// Copyright © 2024-25 The Johns Hopkins Applied Physics Laboratory LLC.
//
// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License,
// version 3, as published by the Free Software Foundation.  If you
// would like to purchase a commercial license for this software, please
// contact APL’s Tech Transfer at 240-592-0817 or
// techtransfer@jhuapl.edu.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program.  If not, see
// <https://www.gnu.org/licenses/>.

//! Far-link channels over Datagram Transport-Layer Security (DTLS)
//! sessions.
//!
//! This module provides a [FarChannel] implementation over DTLS
//! sessions.  DTLS session negotiation occurs when a [Flow] is set up
//! using [borrowed_flows](FarChannelBorrowFlows::borrowed_flows) or
//! [owned_flows](FarChannelOwnedFlows::owned_flows).
//!
//! Communications over the resulting channel will then be protected
//! and authenticated.

use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Condvar;
use std::time::Duration;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Session;
use constellation_common::net::Socket;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_streams::stream::ConcurrentStream;
use log::debug;
use log::info;
use log::trace;
use mio::Registry;
use mio::Token;
use openssl::error::ErrorStack;
use openssl::ssl::SslAcceptor;
use openssl::ssl::SslConnector;
use openssl::ssl::Error;
use openssl::ssl::ErrorCode;
use openssl::ssl::HandshakeError;
use openssl::ssl::MidHandshakeSslStream;
use openssl::ssl::ShutdownResult;
use openssl::ssl::SslStream;

use crate::config::tls::TLSLoadClient;
use crate::config::tls::TLSLoadConfigError;
use crate::config::tls::TLSLoadServer;
use crate::config::tls::TLSPeerConfig;
use crate::config::DTLSFarChannelConfig;
use crate::far::flows::BufferedFlow;
use crate::far::FarChannel;
use crate::far::FarChannelFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::resolve::cache::NSNameCachesCtx;
use crate::tls::TLSShutdownNegotiator;
use crate::tls::TLSStartError;

/// A far-link channel that negotiates Datagram Transport-Layer
/// Security sessions for individual flows.
///
/// This is a [FarChannel] instance that builds on a lower-level
/// `FarChannel` instance, and negotiates DTLS sessions when
/// individual [Flow]s are established.  Communications over the
/// resulting channel will then be protected.  Client authentication
/// is hardwired to enabled, so the connection will also be
/// authenticated.
///
/// Typically, a [UDPFarChannel](crate::far::udp::UDPFarChannel) will
/// be used as the underlying channel; however, this is not required.
/// It is possible, for example, to use a
/// [UnixFarChannel](crate::far::unix::UnixFarChannel) (though this is
/// typically only useful for testing purposes).  It is even possible
/// to use another `DTLSFarChannel` to set up double-layer DTLS
/// sessions.
///
/// # Usage
///
/// The primary use of a `DTLSFarChannel` takes place through its
/// [FarChannel] instance.
///
/// ## Configuration and Creation
///
/// A `DTLSFarChannel` is created using the
/// [create](FarChannelCreate::new) function from its [FarChannel]
/// instance.  This function takes a [DTLSFarChannelConfig] as its
/// principal argument, which supplies all configuration information.
///
/// ### Example
///
/// The following example shows how to create a `DTLSFarChannel`,
/// using a [UDPFarChannel](crate::far::udp::UDPFarChannel) as
/// the underlying channel.
///
/// ```
/// # use std::iter::empty;
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::dtls::DTLSFarChannel;
/// # use constellation_channels::far::udp::UDPFarChannel;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "addr: ::1\n",
///     "port: 8281\n",
///     "trust-root:\n",
///     "  root-certs:\n",
///     "    - test/data/certs/client/ca_cert.pem\n",
///     "  crls: []\n",
///     "cert: test/data/certs/server/certs/test_server_cert.pem\n",
///     "key: test/data/certs/server/private/test_server_key.pem\n",
/// );
/// let dtls_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let mut channel = DTLSFarChannel::<UDPFarChannel>
///     ::create(&mut nscaches, &mut empty(), dtls_config)
///     .expect("Expected success");
/// ```
pub struct DTLSFarChannel<Channel> {
    /// The underlying channel.
    inner: Channel,
    /// The TLS configuration.
    tls: TLSPeerConfig,
    /// Maximum time to spend shutting down.
    shutdown_timeout: Duration,
    /// Retry configuration for shutting down.
    shutdown_retry: Retry
}

/// The [Flow] instance for DTLS sessions.
///
/// This has a [Drop] instance that will attempt to shut down the
/// session when dropped.
pub struct DTLSFlow<Flow: Session + Read + Write> {
    /// The underlying SSL stream.
    ssl: SslStream<Flow>
}

pub struct DTLSOutboundParam<Inner> {
    verify_endpoint: IPEndpointAddr,
    inner: Inner
}

/// [Negotiator] for inbound sessions for [DTLSFarChannel].
#[derive(Clone)]
pub struct DTLSInboundNegotiator<Inner> {
    /// The TLS configuration.
    tls: TLSPeerConfig,
    /// Negotiator for the underlying flow.
    inner: Inner,
}

/// [Negotiator] state for outbound sessions for [DTLSFarChannel].
#[derive(Clone)]
pub struct DTLSOutboundNegotiator<Inner> {
    /// The TLS configuration.
    tls: TLSPeerConfig,
    /// Negotiator for the underlying flow.
    inner: Inner
}

/// [Negotiator] state for inbound sessions for [DTLSFarChannel].
#[derive(Clone)]
pub struct DTLSInboundNegotiatorState<Inner> {
    /// The [SslAcceptor] to use for DTLS negotiations.
    acceptor: SslAcceptor,
    /// Negotiator for the underlying flow.
    inner: Inner,
}

/// [Negotiator] state for outbound sessions for [DTLSFarChannel].
#[derive(Clone)]
pub struct DTLSOutboundNegotiatorState<Inner> {
    /// The [SslConnector] to use for DTLS negotiations.
    connector: SslConnector,
    /// Negotiator for the underlying flow.
    inner: Inner,
    /// Domain name to use for DTLS verification.
    domain: String
}

pub enum DTLSInboundNegoPending<Conn, Inner> {
    Inner {
        acceptor: SslAcceptor,
        pending: Inner,
    },
    DTLS {
        pending: MidHandshakeSslStream<Conn>
    }
}

pub enum DTLSOutboundNegoPending<Conn, Inner> {
    Inner {
        connector: SslConnector,
        pending: Inner,
        domain: String
    },
    DTLS {
        pending: MidHandshakeSslStream<Conn>
    }
}

/// Errors that can occur during DTLS session negotiation.
#[derive(Debug)]
pub enum DTLSNegotiateError<Inner> {
    /// An error occurred on the underlying channel.
    Inner {
        /// The underlying channel error.
        inner: Inner
    },
    /// Error loading TLS configuration.
    TLSLoad {
        /// The error that occurred while loading the TLS
        /// configuration.
        tls: TLSLoadConfigError
    },
    /// Error in OpenSSL prior to handshaking.
    OpenSSL {
        /// The OpenSSL error stack.
        err: ErrorStack
    },
    /// Error during DTLS handshaking.
    Handshake {
        /// The handshake error.
        err: Error
    },
    IO {
        err: std::io::Error
    },
    /// No server name could be established.
    NoName
}

#[derive(Debug)]
pub enum DTLSOutboundNegoError<Inner> {
    Inner {
        err: Inner
    },
    /// Error loading TLS configuration.
    TLSLoad {
        /// The error that occurred while loading the TLS
        /// configuration.
        err: TLSLoadConfigError
    },
    /// No server name could be established.
    NoName
}

#[derive(Debug)]
pub enum DTLSInboundNegoError<Inner> {
    Inner {
        err: Inner
    },
    /// Error loading TLS configuration.
    TLSLoad {
        /// The error that occurred while loading the TLS
        /// configuration.
        err: TLSLoadConfigError
    },
}

impl<Inner> DTLSOutboundParam<Inner> {
    #[inline]
    pub fn new(
        verify_endpoint: IPEndpointAddr,
        inner: Inner
    ) -> Self {
        DTLSOutboundParam {
            verify_endpoint: verify_endpoint,
            inner: inner
        }
    }
}

impl<Inner> ScopedError for DTLSNegotiateError<Inner>
where
    Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            DTLSNegotiateError::IO { err } => err.scope(),
            DTLSNegotiateError::Inner { inner } => inner.scope(),
            DTLSNegotiateError::TLSLoad { tls } => tls.scope(),
            DTLSNegotiateError::OpenSSL { .. } => ErrorScope::Session,
            DTLSNegotiateError::Handshake { .. } => ErrorScope::External,
            DTLSNegotiateError::NoName => ErrorScope::Unrecoverable
        }
    }
}

impl<Inner> ScopedError for DTLSInboundNegoError<Inner>
where Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            DTLSInboundNegoError::Inner { err } => err.scope(),
            DTLSInboundNegoError::TLSLoad { err } => err.scope(),
        }
    }
}

impl<Inner> ScopedError for DTLSOutboundNegoError<Inner>
where Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            DTLSOutboundNegoError::Inner { err } => err.scope(),
            DTLSOutboundNegoError::TLSLoad { err } => err.scope(),
            DTLSOutboundNegoError::NoName => ErrorScope::Unrecoverable
        }
    }
}

impl<Channel> FarChannel for DTLSFarChannel<Channel>
where
    Channel: FarChannel
{
    type Acquired = Channel::Acquired;
    type State = Channel::State;
    type NegotiatePending = Channel::NegotiatePending;
    type AcquireError = Channel::AcquireError;
    type NegotiateError = Channel::NegotiateError;

    #[inline]
    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::State>, Self::AcquireError> {
        self.inner.acquire(registry)
    }

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, std::io::Error> {
        self.inner.socks5_target(val)
    }

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.inner.negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.inner.complete_negotiate(err)
    }
}

impl<Channel> FarChannelSocket for DTLSFarChannel<Channel>
where
    Channel: FarChannelSocket
{
    type Param = Channel::Param;
    type Socket = Channel::Socket;
    type SocketError = Channel::SocketError;

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.inner.socket(param)
    }
}

impl<Channel> FarChannelCreate for DTLSFarChannel<Channel>
where
    Channel: FarChannelCreate
{
    type Config = DTLSFarChannelConfig<Channel::Config>;
    type CreateError = Channel::CreateError;

    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        let tls = config.take();
        let (tls, inner, shutdown_retry, shutdown_timeout) = tls.take();
        let inner = Channel::create(caches, tokens, inner)?;

        Ok(DTLSFarChannel {
            shutdown_timeout: shutdown_timeout,
            shutdown_retry: shutdown_retry,
            inner: inner,
            tls: tls
        })
    }
}

impl<Inner, Xfrm, InnerXfrm> FarChannelXfrm<Xfrm, InnerXfrm>
    for DTLSFarChannel<Inner>
where
    Inner: FarChannelFlows<Xfrm, InnerXfrm>,
    <Inner::Socket as Socket>::Addr: TryFrom<InnerXfrm::LocalAddr>,
    <<Inner::Socket as Socket>::Addr as TryFrom<InnerXfrm::LocalAddr>>::Error:
        Debug + Display,
    InnerXfrm::LocalAddr: From<<Inner::Socket as Socket>::Addr>,
    <Inner::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Inner::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Debug + Display,
    Xfrm::LocalAddr: From<<Inner::Socket as Socket>::Addr>,
    Xfrm: DatagramXfrm,
    InnerXfrm: DatagramXfrm
{
    type XfrmError = Inner::XfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: InnerXfrm
    ) -> Result<Xfrm, Self::XfrmError> {
        self.inner.wrap_xfrm(param, xfrm)
    }
}

impl<Inner, Xfrm, InnerXfrm> FarChannelFlows<Xfrm, InnerXfrm>
    for DTLSFarChannel<Inner>
where
    Inner: FarChannelFlows<Xfrm, InnerXfrm>,
    <Inner::Socket as Socket>::Addr: TryFrom<InnerXfrm::LocalAddr>,
    <<Inner::Socket as Socket>::Addr as TryFrom<InnerXfrm::LocalAddr>>::Error:
        Debug + Display,
    InnerXfrm::LocalAddr: From<<Inner::Socket as Socket>::Addr>,
    <Inner::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Inner::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Debug + Display,
    Xfrm::LocalAddr: From<<Inner::Socket as Socket>::Addr>,
    Xfrm: DatagramXfrm,
    InnerXfrm: DatagramXfrm
{
    type Flow = DTLSFlow<Inner::Flow>;
    type InboundNego = DTLSInboundNegotiator<Inner::InboundNego>;
    type OutboundNego = DTLSOutboundNegotiator<Inner::OutboundNego>;
    type ShutdownNego = TLSShutdownNegotiator<Inner::Flow,
                                              Inner::ShutdownNego>;
    type InboundNegoError = DTLSInboundNegoError<Inner::InboundNegoError>;
    type OutboundNegoError = DTLSOutboundNegoError<Inner::OutboundNegoError>;
    type ShutdownNegoError = Inner::ShutdownNegoError;

    #[inline]
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        let inner = self.inner.inbound_negotiator()
            .map_err(|err| DTLSInboundNegoError::Inner { err: err })?;

        Ok(DTLSInboundNegotiator {
            tls: self.tls.clone(),
            inner: inner
        })
    }

    #[inline]
    fn outbound_negotiator(
        &self,
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        let inner = self.inner.outbound_negotiator()
            .map_err(|err| DTLSOutboundNegoError::Inner { err: err })?;

        Ok(DTLSOutboundNegotiator {
            tls: self.tls.clone(),
            inner: inner
        })
    }

    #[inline]
    fn shutdown_negotiator(
        &self,
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        let inner = self.inner.shutdown_negotiator()?;

        Ok(TLSShutdownNegotiator::new(inner, self.shutdown_retry.clone(),
                                      self.shutdown_timeout))
    }
}

impl <Flow, Inner> Negotiator<DTLSFlow<Flow>> for DTLSInboundNegotiator<Inner>
where
    Flow: Credentials + Session + Read + Write,
    Inner: Negotiator<Flow>
{
    type State = DTLSInboundNegotiatorState<Inner::State>;
    type Pending = DTLSInboundNegoPending<Flow, Inner::Pending>;
    type NegotiateError = DTLSNegotiateError<Inner::NegotiateError>;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<DTLSFlow<Flow>, Self::Pending>,
                Self::NegotiateError> {
        match self.inner
            .negotiate(state.inner)
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })? {
            NegotiatorResult::Complete(flow) => {
                let addr = flow.peer_addr()
                    .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                debug!(target: "far-dtls",
                       "accepting DTLS session from {}", addr);

                match state.acceptor.accept(flow) {
                    Ok(stream) => {
                        info!(target: "far-dtls",
                              "established DTLS session with {}", addr);

                        Ok(NegotiatorResult::Complete(DTLSFlow { ssl: stream }))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(err) => {
                            Err(DTLSNegotiateError::OpenSSL { err: err })
                        }
                        HandshakeError::Failure(err) => {
                            Err(DTLSNegotiateError::Handshake {
                                err: err.into_error()
                            })
                        }
                        HandshakeError::WouldBlock(pending) => {
                            trace!(target: "far-dtls",
                                   "pausing DTLS negotiation with {}",
                                   addr);

                            Ok(NegotiatorResult::Pending(
                                DTLSInboundNegoPending::DTLS {
                                    pending: pending
                                }
                            ))
                        }
                    }
                }
            }
            NegotiatorResult::Pending(pending) => Ok(
                NegotiatorResult::Pending(
                    DTLSInboundNegoPending::Inner {
                        acceptor: state.acceptor,
                        pending: pending,
                    }
                )
            )
        }
    }

    fn complete_negotiate(
        &self,
        pending: DTLSInboundNegoPending<Flow, Inner::Pending>
    ) -> Result<NegotiatorResult<DTLSFlow<Flow>, Self::Pending>,
                Self::NegotiateError> {
        match pending {
            DTLSInboundNegoPending::Inner { acceptor, pending } => match self
                .inner
                .complete_negotiate(pending)
                .map_err(|e| DTLSNegotiateError::Inner { inner: e })? {
                NegotiatorResult::Complete(flow) => {
                    let addr = flow.peer_addr()
                        .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                    debug!(target: "far-dtls",
                           "accepting DTLS session from {}", addr);

                    match acceptor.accept(flow) {
                        Ok(stream) => {
                            info!(target: "far-dtls",
                                  "established DTLS session with {}", addr);

                            Ok(NegotiatorResult::Complete(DTLSFlow {
                                ssl: stream
                            }))
                        }
                        Err(err) => match err {
                            HandshakeError::SetupFailure(err) => {
                                Err(DTLSNegotiateError::OpenSSL { err: err })
                            }
                            HandshakeError::Failure(err) => {
                                Err(DTLSNegotiateError::Handshake {
                                    err: err.into_error()
                                })
                            }
                            HandshakeError::WouldBlock(pending) => {
                                trace!(target: "far-dtls",
                                       "pausing DTLS negotiation with {}",
                                       addr);

                                Ok(NegotiatorResult::Pending(
                                    DTLSInboundNegoPending::DTLS {
                                        pending: pending
                                    }
                                ))
                            }
                        }
                    }
                }
                NegotiatorResult::Pending(pending) => Ok(
                    NegotiatorResult::Pending(
                        DTLSInboundNegoPending::Inner {
                            acceptor: acceptor,
                            pending: pending,
                        }
                    )
                )
            }
            DTLSInboundNegoPending::DTLS { pending } => {
                let addr = pending.get_ref().peer_addr()
                    .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                trace!(target: "far-dtls",
                       "resuming DTLS negotiation with {}",
                       addr);

                match pending .handshake() {
                    Ok(stream) => {
                        info!(target: "far-dtls",
                              "established DTLS session with {}", addr);

                        Ok(NegotiatorResult::Complete(DTLSFlow { ssl: stream }))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(stack) =>
                            Err(DTLSNegotiateError::OpenSSL {
                                err: stack
                            }),
                        HandshakeError::Failure(err) =>
                            Err(DTLSNegotiateError::Handshake {
                                err: err.into_error()
                            }),
                        HandshakeError::WouldBlock(pending) => {
                            Ok(NegotiatorResult::Pending(
                                DTLSInboundNegoPending::DTLS {
                                    pending: pending
                                }
                            ))
                        }
                    }
                }
            }
        }
    }
}

impl <Flow, Inner, Sock, Xfrm>
    NegotiatorStart<DTLSFlow<Flow>, BufferedFlow<Sock, Xfrm>>
    for DTLSInboundNegotiator<Inner>
where
    Flow: Credentials + Session + Read + Write,
    Inner: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    Sock: Socket + Sender + Receiver,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm: DatagramXfrm,
{
    type Param = Inner::Param;
    type StartError = TLSStartError<Inner::StartError, TLSLoadConfigError>;

    fn start(
        &self,
        param: &Inner::Param,
        stream: BufferedFlow<Sock, Xfrm>
    ) -> Result<Self::State, Self::StartError> {
        let inner = self.inner.start(param, stream)
            .map_err(|err| TLSStartError::Inner { err: err })?;
        let acceptor = self
            .tls
            .load_server(None, true)
            .map_err(|err| TLSStartError::TLS { err: err })?;

        Ok(DTLSInboundNegotiatorState {
            acceptor: acceptor,
            inner: inner
        })
    }
}

impl <Flow, Inner> Negotiator<DTLSFlow<Flow>> for DTLSOutboundNegotiator<Inner>
where
    Flow: Credentials + Session + Read + Write,
    Inner: Negotiator<Flow>
{
    type State = DTLSOutboundNegotiatorState<Inner::State>;
    type Pending = DTLSOutboundNegoPending<Flow, Inner::Pending>;
    type NegotiateError = DTLSNegotiateError<Inner::NegotiateError>;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<DTLSFlow<Flow>, Self::Pending>,
                Self::NegotiateError> {
        match self.inner
            .negotiate(state.inner)
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })? {
            NegotiatorResult::Complete(flow) => {
                let addr = flow.peer_addr()
                    .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                debug!(target: "far-dtls",
                       "establishing DTLS session with {}",
                       addr);

                match state.connector.connect(state.domain.as_str(), flow) {
                    Ok(stream) => {
                        info!(target: "far-dtls",
                              "established DTLS session with {}",
                              addr);

                        Ok(NegotiatorResult::Complete(DTLSFlow { ssl: stream }))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(err) => {
                            Err(DTLSNegotiateError::OpenSSL { err: err })
                        }
                        HandshakeError::Failure(err) => {
                            Err(DTLSNegotiateError::Handshake {
                                err: err.into_error()
                            })
                        }
                        HandshakeError::WouldBlock(pending) => {
                            trace!(target: "far-dtls",
                                   "pausing DTLS negotiation with {}",
                                   addr);

                            Ok(NegotiatorResult::Pending(
                                DTLSOutboundNegoPending::DTLS {
                                    pending: pending
                                }
                            ))
                        }
                    }
                }
            }
            NegotiatorResult::Pending(pending) => Ok(
                NegotiatorResult::Pending(
                    DTLSOutboundNegoPending::Inner {
                        connector: state.connector,
                        domain: state.domain,
                        pending: pending
                    }
                )
            )
        }
    }

    fn complete_negotiate(
        &self,
        pending: DTLSOutboundNegoPending<Flow, Inner::Pending>
    ) -> Result<NegotiatorResult<DTLSFlow<Flow>, Self::Pending>,
                Self::NegotiateError> {
        match pending {
            DTLSOutboundNegoPending::Inner {
                connector, domain, pending
            } => match self
                .inner
                .complete_negotiate(pending)
                .map_err(|e| DTLSNegotiateError::Inner { inner: e })? {
                NegotiatorResult::Complete(flow) => {
                    let addr = flow.peer_addr()
                        .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                    debug!(target: "far-dtls",
                           "establishing DTLS session with {}", addr);

                    match connector.connect(domain.as_str(), flow) {
                        Ok(stream) => {
                            info!(target: "far-dtls",
                                  "established DTLS session with {}", addr);

                            Ok(NegotiatorResult::Complete(DTLSFlow {
                                ssl: stream
                            }))
                        }
                        Err(err) => match err {
                            HandshakeError::SetupFailure(err) => {
                                Err(DTLSNegotiateError::OpenSSL { err: err })
                            }
                            HandshakeError::Failure(err) => {
                                Err(DTLSNegotiateError::Handshake {
                                    err: err.into_error()
                                })
                            }
                            HandshakeError::WouldBlock(pending) => {
                                trace!(target: "far-dtls",
                                       "pausing DTLS session with {}", addr);

                                Ok(NegotiatorResult::Pending(
                                    DTLSOutboundNegoPending::DTLS {
                                        pending: pending
                                    }
                                ))
                            }
                        }
                    }
                }
                NegotiatorResult::Pending(pending) => Ok(
                    NegotiatorResult::Pending(
                        DTLSOutboundNegoPending::Inner {
                            connector: connector,
                            domain: domain,
                            pending: pending
                        }
                    )
                )
            }
            DTLSOutboundNegoPending::DTLS { pending } => {
                let addr = pending.get_ref().peer_addr()
                    .map_err(|err| DTLSNegotiateError::IO { err: err })?;

                trace!(target: "far-dtls",
                       "resuming DTLS negotiation with {}",
                       addr);

                match pending.handshake() {
                    Ok(stream) => {
                        info!(target: "far-dtls",
                              "established DTLS session with {}",
                              addr);

                        Ok(NegotiatorResult::Complete(DTLSFlow { ssl: stream }))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(stack) =>
                            Err(DTLSNegotiateError::OpenSSL {
                                err: stack
                            }),
                        HandshakeError::Failure(err) =>
                            Err(DTLSNegotiateError::Handshake {
                                err: err.into_error()
                            }),
                        HandshakeError::WouldBlock(pending) => {
                            trace!(target: "far-dtls",
                                   "pausing DTLS negotiation with {}",
                                   addr);

                            Ok(NegotiatorResult::Pending(
                                DTLSOutboundNegoPending::DTLS {
                            pending: pending
                                }
                            ))
                        }
                    }
                }
            }
        }
    }
}

impl <Flow, Inner, Sock, Xfrm>
    NegotiatorStart<DTLSFlow<Flow>, BufferedFlow<Sock, Xfrm>>
    for DTLSOutboundNegotiator<Inner>
where
    Inner: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    Flow: Credentials + Session + Read + Write,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm: DatagramXfrm,
    Sock: Socket + Sender + Receiver
{
    type Param = DTLSOutboundParam<Inner::Param>;
    type StartError = TLSStartError<Inner::StartError, TLSLoadConfigError>;

    fn start(
        &self,
        param: &DTLSOutboundParam<Inner::Param>,
        stream: BufferedFlow<Sock, Xfrm>
    ) -> Result<Self::State, Self::StartError> {
        let inner = self.inner.start(&param.inner, stream)
            .map_err(|err| TLSStartError::Inner { err: err })?;
        let connector = self
            .tls
            .load_client(None, &param.verify_endpoint, true)
            .map_err(|err| TLSStartError::TLS { err: err })?;
        let domain = match &param.verify_endpoint {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            },
            // XXX This should probably produce an error.
            IPEndpointAddr::Addr(_) => String::new()
        };

        Ok(DTLSOutboundNegotiatorState {
            connector: connector,
            domain: domain,
            inner: inner
        })
    }
}

impl <Stream, Inner> NegotiatorStart<(), DTLSFlow<Stream>>
    for TLSShutdownNegotiator<Stream, Inner>
where
    Inner: NegotiatorStart<(), Stream>,
    Stream: Credentials + Session + Read + Write,
{
    type Param = ();
    type StartError = Inner::StartError;

    #[inline]
    fn start(
        &self,
        param: &(),
        stream: DTLSFlow<Stream>
    ) -> Result<Self::State, Self::StartError> {
        self.start(param, stream.ssl)
    }
}

impl<Inner> Display for DTLSNegotiateError<Inner>
where
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            DTLSNegotiateError::Inner { inner } => write!(f, "{}", inner),
            DTLSNegotiateError::IO { err } => write!(f, "{}", err),
            DTLSNegotiateError::TLSLoad { tls } => write!(f, "{}", tls),
            DTLSNegotiateError::OpenSSL { err } => write!(f, "{}", err),
            DTLSNegotiateError::Handshake { err } => write!(f, "{}", err),
            DTLSNegotiateError::NoName => write!(
                f,
                concat!(
                    "non-IP endpoint for DTLS channel ",
                    "and no verify-endpoint provided"
                )
            )
        }
    }
}

impl<Inner> Display for DTLSInboundNegoError<Inner>
where Inner: Display {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            DTLSInboundNegoError::Inner { err } => err.fmt(f),
            DTLSInboundNegoError::TLSLoad { err } => write!(f, "{}", err),
        }
    }
}

impl<Inner> Display for DTLSOutboundNegoError<Inner>
where Inner: Display {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            DTLSOutboundNegoError::Inner { err } => err.fmt(f),
            DTLSOutboundNegoError::TLSLoad { err } => write!(f, "{}", err),
            DTLSOutboundNegoError::NoName => write!(
                f,
                concat!(
                    "non-IP endpoint for DTLS channel ",
                    "and no verify-endpoint provided"
                )
            )
        }
    }
}

impl<Flow> ConcurrentStream for DTLSFlow<Flow>
where
    Flow: ConcurrentStream + Session + Read + Write
{
    #[inline]
    fn condvar(&self) -> Arc<Condvar> {
        self.ssl.get_ref().condvar()
    }
}

impl<Flow> Credentials for DTLSFlow<Flow>
where
    Flow: Credentials + Session + Read + Write
{
    type Cred = SSLCred<<Flow as Credentials>::Cred>;
    type CredError = <Flow as Credentials>::CredError;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<SSLCred<<Flow as Credentials>::Cred>>,
        <Flow as Credentials>::CredError
    > {
        self.ssl.creds()
    }
}

impl<Flow> Session for DTLSFlow<Flow>
where
    Flow: Session + Read + Write
{
    type LocalAddr = Flow::LocalAddr;
    type PeerAddr = Flow::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, std::io::Error> {
        self.ssl.get_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, std::io::Error> {
        self.ssl.get_ref().peer_addr()
    }
}

impl<Flow> Read for DTLSFlow<Flow>
where
    Flow: Session + Read + Write
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, std::io::Error> {
        self.ssl.read(buf)
    }

    #[inline]
    fn read_vectored(
        &mut self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<usize, std::io::Error> {
        self.ssl.read_vectored(bufs)
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, std::io::Error> {
        self.ssl.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, std::io::Error> {
        self.ssl.read_to_string(buf)
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), std::io::Error> {
        self.ssl.read_exact(buf)
    }
}

impl<Flow> Write for DTLSFlow<Flow>
where
    Flow: Session + Read + Write
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, std::io::Error> {
        self.ssl.write(buf)
    }

    #[inline]
    fn write_vectored(
        &mut self,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, std::io::Error> {
        self.ssl.write_vectored(bufs)
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), std::io::Error> {
        self.ssl.write_all(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.ssl.flush()
    }
}

#[cfg(test)]
use std::iter::empty;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;
#[cfg(test)]
use mio::Interest;
#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::config::FlowsConfig;
#[cfg(test)]
use crate::config::UDPFarChannelConfig;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;
#[cfg(test)]
use crate::far::flows::accept_one;
#[cfg(test)]
use crate::far::flows::connect_one;
#[cfg(test)]
use crate::far::flows::read_one;
#[cfg(test)]
use crate::far::flows::write_one;
#[cfg(test)]
use crate::far::udp::UDPFarChannel;

#[cfg(test)]
const CHANNEL_CONFIG: &'static str = concat!(
    "addr: ::1\n",
    "port: 8281\n",
    "cipher-suites:\n",
    "  - TLS_AES_256_GCM_SHA384\n",
    "  - TLS_CHACHA20_POLY1305_SHA256\n",
    "key-exchange-groups:\n",
    "  - P-384\n",
    "  - X25519\n",
    "  - P-256\n",
    "trust-root:\n",
    "  root-certs:\n",
    "    - test/data/certs/client/ca_cert.pem\n",
    "  crls: []\n",
    "cert: test/data/certs/server/certs/test_server_cert.pem\n",
    "key: test/data/certs/server/private/test_server_key.pem\n",
);

#[cfg(test)]
const CLIENT_CONFIG: &'static str = concat!(
    "addr: ::1\n",
    "port: 8282\n",
    "cipher-suites:\n",
    "  - TLS_AES_256_GCM_SHA384\n",
    "  - TLS_CHACHA20_POLY1305_SHA256\n",
    "key-exchange-groups:\n",
    "  - P-384\n",
    "  - X25519\n",
    "  - P-256\n",
    "trust-root:\n",
    "  root-certs:\n",
    "    - test/data/certs/server/ca_cert.pem\n",
    "  crls: []\n",
    "cert: test/data/certs/client/certs/test_client_cert.pem\n",
    "key: test/data/certs/client/private/test_client_key.pem\n",
);

#[test]
fn test_send_recv() {
    init();

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let server_addr = SocketAddr::new(
        server_config.tls().underlying().addr().clone(),
        server_config.tls().underlying().port()
    );
    let client_addr = SocketAddr::new(
        client_config.tls().underlying().addr().clone(),
        client_config.tls().underlying().port()
    );
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut listener = DTLSFarChannel::<UDPFarChannel>
            ::create(&mut server_nscaches, &mut empty(), server_config)
            .expect("Expected success");
        let config = FlowsConfig::default();
        let param = match listener.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows = listener.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        server_barrier.wait();

        let (mut flow, peer_addr) =
            accept_one(&mut flows, &mut poll, &(), token)
            .expect("Expected success");

        server_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &peer_addr, &(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
            .expect("Expected success");

        server_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let dtlsparam = DTLSOutboundParam {
            verify_endpoint: endpoint,
            inner: ()
        };
        let mut conn = DTLSFarChannel::<UDPFarChannel>
            ::create(&mut client_nscaches, &mut empty(), client_config)
            .expect("expected success");
        let config = FlowsConfig::default();
        let param = match conn.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows = conn.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        client_barrier.wait();

        let mut flow = connect_one(&mut flows, &mut poll, &dtlsparam, &(),
                                   server_addr.clone(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
            .expect("Expected success");

        client_barrier.wait();
        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &server_addr, &(), token)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}
