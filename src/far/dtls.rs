// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
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
//!
//! # Examples
//!
//! The following is an example of negotiating a session, sending, and
//! receiving over DTLS:
//!
//! ```
//! # use constellation_common::net::IPEndpointAddr;
//! # use constellation_common::net::PassthruDatagramXfrm;
//! # use constellation_channels::config::DTLSFarChannelConfig;
//! # use constellation_channels::config::UDPFarChannelConfig;
//! # use constellation_channels::config::tls::TLSClientConfig;
//! # use constellation_channels::config::tls::TLSServerConfig;
//! # use constellation_channels::far::FarChannel;
//! # use constellation_channels::far::FarChannelCreate;
//! # use constellation_channels::far::FarChannelBorrowFlows;
//! # use constellation_channels::far::dtls::DTLSFarChannel;
//! # use constellation_channels::far::dtls::DTLSMultiFlows;
//! # use constellation_channels::far::dtls::DTLSSingleFlow;
//! # use constellation_channels::far::flows::BorrowedFlows;
//! # use constellation_channels::far::udp::UDPFarChannel;
//! # use constellation_channels::far::udp::UDPFarSocket;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use std::net::Shutdown;
//! # use std::net::SocketAddr;
//! # use std::thread::spawn;
//! # use std::io::Read;
//! # use std::io::Write;
//! # use std::sync::Arc;
//! # use std::sync::Barrier;
//! # use std::thread::sleep;
//! # use std::time::Duration;
//! #
//! const CHANNEL_CONFIG: &'static str =
//!     concat!(
//!         "addr: ::1\n",
//!         "port: 8281\n",
//!         "cipher-suites:\n",
//!         "  - TLS_AES_256_GCM_SHA384\n",
//!         "  - TLS_CHACHA20_POLY1305_SHA256\n",
//!         "key-exchange-groups:\n",
//!         "  - P-384\n",
//!         "  - X25519\n",
//!         "  - P-256\n",
//!         "trust-root:\n",
//!         "  root-certs:\n",
//!         "    - test/data/certs/client/ca_cert.pem\n",
//!         "  crls: []\n",
//!         "cert: test/data/certs/server/certs/test_server_cert.pem\n",
//!         "key: test/data/certs/server/private/test_server_key.pem\n",
//!     );
//! const CLIENT_CONFIG: &'static str =
//!     concat!(
//!         "addr: ::1\n",
//!         "port: 8282\n",
//!         "cipher-suites:\n",
//!         "  - TLS_AES_256_GCM_SHA384\n",
//!         "  - TLS_CHACHA20_POLY1305_SHA256\n",
//!         "key-exchange-groups:\n",
//!         "  - P-384\n",
//!         "  - X25519\n",
//!         "  - P-256\n",
//!         "trust-root:\n",
//!         "  root-certs:\n",
//!         "    - test/data/certs/server/ca_cert.pem\n",
//!         "  crls: []\n",
//!         "cert: test/data/certs/client/certs/test_client_cert.pem\n",
//!         "key: test/data/certs/client/private/test_client_key.pem\n",
//!     );
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! let channel_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
//!     serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
//! let client_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
//!     serde_yaml::from_str(CLIENT_CONFIG).unwrap();
//! let channel_addr = SocketAddr::new(channel_config.tls().underlying()
//!                                    .addr().clone(),
//!                                    channel_config.tls()
//!                                    .underlying().port());
//! let client_addr = SocketAddr::new(client_config.tls().underlying()
//!                                   .addr().clone(),
//!                                   client_config.tls()
//!                                   .underlying().port());
//! let nscaches = SharedNSNameCaches::new();
//! # let barrier = Arc::new(Barrier::new(2));
//!
//! let mut client_nscaches = nscaches.clone();
//! let client_barrier = barrier.clone();
//! let listen = spawn(move || {
//!     let mut listener = DTLSFarChannel::<UDPFarChannel>::new(
//!         &mut client_nscaches,
//!         channel_config
//!     )
//!     .expect("Expected success");
//!     let param = listener.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: DTLSMultiFlows<
//!         UDPFarChannel,
//!         PassthruDatagramXfrm<SocketAddr>
//!     > = listener.borrowed_flows(param, xfrm, ()).unwrap();
//!     let mut buf = [0; FIRST_BYTES.len()];
//!
//! #   client_barrier.wait();
//!
//!     let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();
//!
//! #   client_barrier.wait();
//!
//!     let nbytes = flow.read(&mut buf).unwrap();
//!
//!     flow.write_all(&SECOND_BYTES).expect("Expected success");
//!
//! #   client_barrier.wait();
//!
//!     assert_eq!(peer_addr, client_addr);
//!     assert_eq!(FIRST_BYTES.len(), nbytes);
//!     assert_eq!(FIRST_BYTES, buf);
//! });
//! let channel_barrier = barrier;
//! let mut channel_nscaches = nscaches.clone();
//! let send = spawn(move || {
//!     let mut conn = DTLSFarChannel::<UDPFarChannel>::new(
//!         &mut channel_nscaches,
//!         client_config
//!     )
//!     .expect("expected success");
//!     let param = conn.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: DTLSSingleFlow<
//!         UDPFarChannel,
//!         PassthruDatagramXfrm<SocketAddr>
//!     > = conn
//!         .borrowed_flows(param, xfrm, channel_addr.clone())
//!         .unwrap();
//!     let servername = "test-server.nowhere.com";
//!     let endpoint = IPEndpointAddr::name(String::from(servername));
//!
//! #   channel_barrier.wait();
//!
//!     let mut flow = BorrowedFlows::flow(
//!         &mut flows,
//!         channel_addr.clone(),
//!         Some(&endpoint)
//!     )
//!     .unwrap();
//!
//!     flow.write_all(&FIRST_BYTES).expect("Expected success");
//!
//! #   channel_barrier.wait();
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!
//! #   channel_barrier.wait();
//!
//!     flow.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! send.join().unwrap();
//! listen.join().unwrap();
//! ```

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Condvar;
use std::thread::sleep;
use std::time::Instant;

use constellation_auth::authn::SessionAuthN;
use constellation_auth::cred::Credentials;
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Socket;
use constellation_common::nonblock::NonblockResult;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_streams::stream::ConcurrentStream;
use log::debug;
use log::info;
use log::warn;
use openssl::error::ErrorStack;
use openssl::ssl::Error;
use openssl::ssl::HandshakeError;
use openssl::ssl::ShutdownResult;
use openssl::ssl::SslStream;

use crate::config::tls::TLSLoadClient;
use crate::config::tls::TLSLoadConfigError;
use crate::config::tls::TLSLoadServer;
use crate::config::tls::TLSPeerConfig;
use crate::config::DTLSFarChannelConfig;
use crate::far::flows::BorrowedFlows;
use crate::far::flows::CreateBorrowedFlows;
use crate::far::flows::CreateOwnedFlows;
use crate::far::flows::Flow;
use crate::far::flows::Flows;
use crate::far::flows::MultiFlows;
use crate::far::flows::NegotiateRetry;
use crate::far::flows::Negotiator;
use crate::far::flows::OwnedFlows;
use crate::far::flows::SingleFlow;
use crate::far::FarChannel;
use crate::far::FarChannelBorrowFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelOwnedFlows;
use crate::resolve::cache::NSNameCachesCtx;

/// Errors that can occur when creating a [DTLSFarChannel].
#[derive(Debug)]
pub enum DTLSCreateError {
    /// An error occurred while loading the TLS configuration.
    TLS {
        /// The TLS configuration load error.
        error: TLSLoadConfigError
    },
    /// No identity was provided for verification, and none could be
    /// obtained from the underlying connection.
    NoName
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
        error: ErrorStack
    },
    /// Error during DTLS handshaking.
    Handshake {
        /// The handshake error.
        error: Error
    },
    /// No server name could be established.
    NoName
}

/// A [Flows] instance that negotiates DTLS sessions for flows.
///
/// This [Flows] instance will negotiate a DTLS session as part of the
/// creation of a new [Flow].  If the underlying [Flows] instance `F`
/// implements [OwnedFlows], then `DTLSFlows` will also implement
/// `BorrowedFlows`, and the
/// [listen](crate::far::flows::OwnedFlowsListener::listen) and
/// [flow](OwnedFlows::flow) functions will retry DTLS negotiations
/// until they succeed, according to a [Retry] policy provided by the
/// [DTLSFarChannel] that created this instance. Similarly, if the
/// underlying [Flows] instance `F` implements [BorrowedFlows], then
/// `DTLSFlows` will also implement `BorrowedFlows`; however, the
/// [listen](BorrowedFlows::listen) and [flow](BorrowedFlows::flow)
/// functions will only attempt a single DTLS negotiation, and will
/// fail with an error if it fails.
pub struct DTLSFlows<Xfrm: DatagramXfrm, F: Flows<Xfrm = Xfrm>> {
    context: PhantomData<Xfrm>,
    /// The inner [Flows].
    inner: F,
    /// The TLS configuration.
    tls: TLSPeerConfig,
    /// Current number of retries.
    nretries: usize,
    /// The time at which the next retry will take place.
    until: Instant,
    /// Retry policy.
    retry: Retry
}

/// [Negotiator] instance for [DTLSFlows].
#[derive(Clone)]
pub struct DTLSNegotiator<Inner>
where
    Inner: Negotiator {
    /// Negotiator for the underlying flow.
    inner: Inner,
    /// The TLS configuration.
    tls: TLSPeerConfig
}

/// The [Flow] instance for DTLS sessions.
///
/// This has a [Drop] instance that will attempt to shut down the
/// session when dropped.
pub struct DTLSFlow<F: Flow + Read + Write> {
    /// The underlying SSL stream.
    ssl: SslStream<F>
}

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
///     ::new(&mut nscaches, dtls_config).expect("Expected success");
/// ```
pub struct DTLSFarChannel<Channel: FarChannel> {
    /// The underlying channel.
    inner: Channel,
    /// The TLS configuration.
    tls: TLSPeerConfig,
    /// Retry policy for session negotiations.
    retry: Retry
}

/// A [SingleFlow] wrapped in a DTLS channel.
///
/// This is intended to be used as a shorthand for the result of
/// [borrowed_flows](DTLSFarChannel::borrowed_flows) on
/// [DTLSFarChannel], when using [SingleFlow] as the underlying
/// [Flows] type.
///
/// This type implements [BorrowedFlows].  Its
/// [listen](BorrowedFlows::listen) and [flow](BorrowedFlows::flow)
/// implementations will attempt a single DTLS negotiation, and will
/// return an error if it fails.
pub type DTLSSingleFlow<Channel, Xfrm> =
    DTLSFlows<Xfrm, SingleFlow<DTLSFarChannel<Channel>, Xfrm>>;

/// A [MultiFlows] wrapped in a DTLS channel.
///
/// This is intended to be used as a shorthand for the result of
/// [borrowed_flows](DTLSFarChannel::borrowed_flows) on
/// [DTLSFarChannel], when using [MultiFlows] as the underlying
/// [Flows] type.
///
/// This type implements [BorrowedFlows].  Its
/// [listen](BorrowedFlows::listen) and [flow](BorrowedFlows::flow)
/// implementations will attempt a single DTLS negotiation, and will
/// return an error if it fails.
pub type DTLSMultiFlows<Channel, Xfrm> =
    DTLSFlows<Xfrm, MultiFlows<DTLSFarChannel<Channel>, Xfrm>>;

impl<Inner> ScopedError for DTLSNegotiateError<Inner>
where
    Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            DTLSNegotiateError::Inner { inner } => inner.scope(),
            DTLSNegotiateError::TLSLoad { tls } => tls.scope(),
            DTLSNegotiateError::OpenSSL { .. } => ErrorScope::Session,
            DTLSNegotiateError::Handshake { .. } => ErrorScope::External,
            DTLSNegotiateError::NoName => ErrorScope::Unrecoverable
        }
    }
}

impl<Channel> FarChannel for DTLSFarChannel<Channel>
where
    Channel: FarChannel
{
    type AcquireError = Channel::AcquireError;
    type Acquired = Channel::Acquired;
    type Config = DTLSFarChannelConfig<Channel::Config>;
    type Param = Channel::Param;
    type Socket = Channel::Socket;
    type SocketError = Channel::SocketError;

    #[inline]
    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        self.inner.acquire()
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
    type CreateError = Channel::CreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (tls, retry) = config.take();
        let (tls, inner) = tls.take();
        let inner = Channel::new(caches, inner)?;

        Ok(DTLSFarChannel {
            inner: inner,
            tls: tls,
            retry: retry
        })
    }
}

impl<F, Channel, Xfrm> FarChannelBorrowFlows<F, Xfrm>
    for DTLSFarChannel<Channel>
where
    Channel: FarChannelBorrowFlows<F, Xfrm>,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    F: Flows + CreateBorrowedFlows + BorrowedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    F::Xfrm: From<Xfrm>
{
    type Borrowed = DTLSFlows<F::Xfrm, Channel::Borrowed>;
    type BorrowedFlowsError = Channel::BorrowedFlowsError;
    type Xfrm = Channel::Xfrm;
    type XfrmError = Channel::XfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        self.inner.wrap_xfrm(param, xfrm)
    }

    #[inline]
    fn wrap_borrowed_flows(
        &self,
        flows: F
    ) -> Result<Self::Borrowed, Self::BorrowedFlowsError> {
        let inner = self.inner.wrap_borrowed_flows(flows)?;

        Ok(DTLSFlows {
            context: PhantomData,
            tls: self.tls.clone(),
            nretries: 0,
            until: Instant::now(),
            inner: inner,
            retry: self.retry.clone()
        })
    }
}

impl<F, Channel, AuthN, Xfrm> FarChannelOwnedFlows<F, AuthN, Xfrm>
    for DTLSFarChannel<Channel>
where
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm>,
    Channel::Nego: Negotiator<Inner = F::Flow>,
    Xfrm: DatagramXfrm,
    Xfrm::PeerAddr: Send + Sync,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    F: Flows
        + CreateOwnedFlows<DTLSNegotiator<Channel::Nego>, AuthN>
        + CreateOwnedFlows<Channel::Nego, AuthN>
        + OwnedFlows,
    AuthN: SessionAuthN<<DTLSNegotiator<Channel::Nego> as Negotiator>::Flow>,
    AuthN: SessionAuthN<<Channel::Nego as Negotiator>::Flow>,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    F::Xfrm: From<Xfrm>
{
    type Nego = DTLSNegotiator<Channel::Nego>;
    type Owned = DTLSFlows<F::Xfrm, Channel::Owned>;
    type OwnedFlowsError = Channel::OwnedFlowsError;
    type Xfrm = Channel::Xfrm;
    type XfrmError = Channel::XfrmError;

    #[inline]
    fn negotiator(&self) -> Self::Nego {
        DTLSNegotiator {
            inner: self.inner.negotiator(),
            tls: self.tls.clone()
        }
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        self.inner.wrap_xfrm(param, xfrm)
    }

    #[inline]
    fn wrap_owned_flows(
        &self,
        flows: F
    ) -> Result<Self::Owned, Self::OwnedFlowsError> {
        let inner = self.inner.wrap_owned_flows(flows)?;

        Ok(DTLSFlows {
            context: PhantomData,
            tls: self.tls.clone(),
            nretries: 0,
            until: Instant::now(),
            inner: inner,
            retry: self.retry.clone()
        })
    }
}

impl<F, Xfrm> Flows for DTLSFlows<Xfrm, F>
where
    Xfrm: DatagramXfrm,
    F: Flows<Xfrm = Xfrm>
{
    type Socket = F::Socket;
    type Xfrm = Xfrm;

    #[inline]
    fn local_addr(
        &self
    ) -> Result<<Self::Socket as Socket>::Addr, std::io::Error> {
        self.inner.local_addr()
    }
}

impl<F, Xfrm> BorrowedFlows for DTLSFlows<Xfrm, F>
where
    Xfrm: DatagramXfrm,
    F: Flows<Xfrm = Xfrm> + BorrowedFlows<Xfrm = Xfrm>
{
    type Flow<'a> = DTLSFlow<F::Flow<'a>>
    where Xfrm: 'a,
          F: 'a;
    type FlowError = DTLSNegotiateError<F::FlowError>;
    type ListenError = DTLSNegotiateError<F::ListenError>;

    #[inline]
    fn listen(
        &mut self
    ) -> Result<(Xfrm::PeerAddr, DTLSFlow<F::Flow<'_>>), Self::ListenError>
    {
        let (addr, flow) = self
            .inner
            .listen()
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })?;
        let acceptor = self
            .tls
            .load_server(None, true)
            .map_err(|e| DTLSNegotiateError::TLSLoad { tls: e })?;

        debug!(target: "far-dtls",
              "accepting DTLS session from {}", addr);

        let stream = acceptor.accept(flow).map_err(|e| match e {
            HandshakeError::SetupFailure(e) => {
                DTLSNegotiateError::OpenSSL { error: e }
            }
            HandshakeError::Failure(e) => DTLSNegotiateError::Handshake {
                error: e.into_error()
            },
            HandshakeError::WouldBlock(e) => DTLSNegotiateError::Handshake {
                error: e.into_error()
            }
        })?;

        info!(target: "far-dtls",
              "established DTLS session with {}", addr);

        Ok((addr, DTLSFlow { ssl: stream }))
    }

    #[inline]
    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<DTLSFlow<F::Flow<'_>>, Self::FlowError> {
        let flow = self
            .inner
            .flow(addr.clone(), endpoint)
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })?;
        let endpoint = endpoint.ok_or(DTLSNegotiateError::NoName)?;
        let connector = self
            .tls
            .load_client(None, endpoint, true)
            .map_err(|e| DTLSNegotiateError::TLSLoad { tls: e })?;

        debug!(target: "far-dtls",
              "establishing DTLS session with {}", addr);

        let domain = match endpoint {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            },
            IPEndpointAddr::Addr(_) => String::new()
        };
        let stream =
            connector
                .connect(domain.as_str(), flow)
                .map_err(|e| match e {
                    HandshakeError::SetupFailure(e) => {
                        DTLSNegotiateError::OpenSSL { error: e }
                    }
                    HandshakeError::Failure(e) => {
                        DTLSNegotiateError::Handshake {
                            error: e.into_error()
                        }
                    }
                    HandshakeError::WouldBlock(e) => {
                        DTLSNegotiateError::Handshake {
                            error: e.into_error()
                        }
                    }
                })?;

        info!(target: "far-dtls",
              "established DTLS session with {}",
              addr);

        Ok(DTLSFlow { ssl: stream })
    }
}

impl<Inner> Negotiator for DTLSNegotiator<Inner>
where
    Inner: Negotiator
{
    type Flow = DTLSFlow<Inner::Flow>;
    type Inner = Inner::Inner;
    type NegotiateError = DTLSNegotiateError<Inner::NegotiateError>;

    #[inline]
    fn negotiate_outbound_nonblock(
        &mut self,
        inner: Inner::Inner,
    ) -> Result<NonblockResult<Self::Flow, Inner::Inner>, Self::NegotiateError>
    {
        Ok(NonblockResult::Fail(inner))
    }

    fn negotiate_outbound(
        &mut self,
        inner: Inner::Inner,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Inner::Inner>>,
        Self::NegotiateError
    > {
        let verify = endpoint.ok_or(DTLSNegotiateError::NoName)?;
        let connector = self
            .tls
            .load_client(None, verify, true)
            .map_err(|e| DTLSNegotiateError::TLSLoad { tls: e })?;
        let domain = match verify {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            },
            IPEndpointAddr::Addr(_) => String::new()
        };
        let addr = inner.peer_addr();
        let flow = match self
            .inner
            .negotiate_outbound(inner, endpoint)
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })?
        {
            RetryResult::Success(flow) => flow,
            RetryResult::Retry(when) => return Ok(RetryResult::Retry(when))
        };

        debug!(target: "far-dtls",
               "establishing DTLS session with {}",
               addr);

        match connector.connect(domain.as_str(), flow) {
            Ok(stream) => {
                info!(target: "far-dtls",
                      "established DTLS session with {}",
                      addr);

                Ok(RetryResult::Success(DTLSFlow { ssl: stream }))
            }
            Err(err) => match err {
                HandshakeError::SetupFailure(e) => {
                    Err(DTLSNegotiateError::OpenSSL { error: e })
                }
                HandshakeError::Failure(e) => {
                    Err(DTLSNegotiateError::Handshake {
                        error: e.into_error()
                    })
                }
                HandshakeError::WouldBlock(e) => {
                    Err(DTLSNegotiateError::Handshake {
                        error: e.into_error()
                    })
                }
            }
        }
    }

    #[inline]
    fn negotiate_inbound_nonblock(
        &mut self,
        inner: Inner::Inner,
    ) -> Result<NonblockResult<Self::Flow, Inner::Inner>, Self::NegotiateError>
    {
        Ok(NonblockResult::Fail(inner))
    }

    fn negotiate_inbound(
        &mut self,
        inner: Inner::Inner,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Inner::Inner>>,
        Self::NegotiateError
    > {
        let addr = inner.peer_addr();
        let flow = match self
            .inner
            .negotiate_inbound(inner)
            .map_err(|e| DTLSNegotiateError::Inner { inner: e })?
        {
            RetryResult::Success(flow) => flow,
            RetryResult::Retry(when) => return Ok(RetryResult::Retry(when))
        };
        let acceptor = self
            .tls
            .load_server(None, true)
            .map_err(|e| DTLSNegotiateError::TLSLoad { tls: e })?;

        debug!(target: "far-dtls",
               "accepting DTLS session from {}", addr);

        match acceptor.accept(flow) {
            Ok(stream) => {
                info!(target: "far-dtls",
                      "established DTLS session with {}", addr);

                Ok(RetryResult::Success(DTLSFlow { ssl: stream }))
            }
            Err(err) => match err {
                HandshakeError::SetupFailure(e) => {
                    Err(DTLSNegotiateError::OpenSSL { error: e })
                }
                HandshakeError::Failure(e) => {
                    Err(DTLSNegotiateError::Handshake {
                        error: e.into_error()
                    })
                }
                HandshakeError::WouldBlock(e) => {
                    Err(DTLSNegotiateError::Handshake {
                        error: e.into_error()
                    })
                }
            }
        }
    }
}

impl<F, Xfrm> OwnedFlows for DTLSFlows<Xfrm, F>
where
    F: OwnedFlows<Xfrm = Xfrm>,
    Xfrm: DatagramXfrm
{
    type Flow = DTLSFlow<F::Flow>;
    type FlowError = DTLSNegotiateError<F::FlowError>;

    #[inline]
    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<DTLSFlow<F::Flow>, Self::FlowError> {
        let verify = endpoint.ok_or(DTLSNegotiateError::NoName)?;
        let connector = self
            .tls
            .load_client(None, verify, true)
            .map_err(|e| DTLSNegotiateError::TLSLoad { tls: e })?;
        let domain = match verify {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            },
            IPEndpointAddr::Addr(_) => String::new()
        };

        loop {
            let now = Instant::now();

            if now < self.until {
                sleep(self.until - now)
            }

            debug!(target: "far-dtls",
                   "establishing DTLS session with {}", addr);

            let flow = self
                .inner
                .flow(addr.clone(), endpoint)
                .map_err(|e| DTLSNegotiateError::Inner { inner: e })?;

            match connector.connect(domain.as_str(), flow) {
                Ok(stream) => {
                    info!(target: "far-dtls",
                          "established DTLS session with {}", addr);

                    return Ok(DTLSFlow { ssl: stream });
                }
                Err(HandshakeError::SetupFailure(e)) => {
                    info!(target: "far-dtls",
                          "error negotiating DTLS session: {}", e);
                }
                Err(HandshakeError::Failure(e)) => {
                    info!(target: "far-dtls",
                          "error negotiating DTLS session: {}", e.error());
                }
                Err(HandshakeError::WouldBlock(e)) => {
                    warn!(target: "far-dtls",
                          concat!("unexpected would-block error ",
                                  "negotiating DTLS session: {}"),
                          e.error());
                }
            }

            let duration = self.retry.retry_delay(self.nretries);
            let next_retry = Instant::now() + duration;

            info!(target: "far-dtls",
                  "retry DTLS negotiation in {}.{:06}",
                  duration.as_secs(), duration.subsec_micros());

            self.nretries += 1;
            self.until = next_retry;
        }
    }
}

impl Display for DTLSCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            DTLSCreateError::TLS { error } => write!(f, "{}", error),
            DTLSCreateError::NoName => write!(
                f,
                concat!(
                    "non-IP endpoint for DTLS channel ",
                    "and no verify-endpoint provided"
                )
            )
        }
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
            DTLSNegotiateError::TLSLoad { tls } => write!(f, "{}", tls),
            DTLSNegotiateError::OpenSSL { error } => write!(f, "{}", error),
            DTLSNegotiateError::Handshake { error } => write!(f, "{}", error),
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

impl<F> ConcurrentStream for DTLSFlow<F>
where
    F: ConcurrentStream + Flow + Read + Write
{
    #[inline]
    fn condvar(&self) -> Arc<Condvar> {
        self.ssl.get_ref().condvar()
    }
}

impl<F> Credentials for DTLSFlow<F>
where
    F: Credentials + Flow + Read + Write
{
    type Cred<'a> = SSLCred<'a, <F as Credentials>::Cred<'a>>
    where Self: 'a;
    type CredError = <F as Credentials>::CredError;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<SSLCred<<F as Credentials>::Cred<'_>>>,
        <F as Credentials>::CredError
    > {
        self.ssl.creds()
    }
}

impl<F> Drop for DTLSFlow<F>
where
    F: Flow + Read + Write
{
    fn drop(&mut self) {
        loop {
            match self.ssl.shutdown() {
                Ok(ShutdownResult::Sent) => {
                    info!(target: "far-dtls",
                          "shutting down DTLS session with {}",
                          self.peer_addr());
                }
                Ok(ShutdownResult::Received) => {
                    info!(target: "far-dtls",
                          "DTLS session with {} successfully shut down",
                          self.peer_addr());

                    return;
                }
                Err(err) => {
                    warn!(target: "far-dtls",
                          "error shutting down DTLS session with {}: {}",
                          self.peer_addr(), err);

                    return;
                }
            }
        }
    }
}

impl<F> Flow for DTLSFlow<F>
where
    F: Flow + Read + Write
{
    type LocalAddr = F::LocalAddr;
    type PeerAddr = F::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, std::io::Error> {
        self.ssl.get_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.ssl.get_ref().peer_addr()
    }
}

impl<F> Read for DTLSFlow<F>
where
    F: Flow + Read + Write
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

impl<F> Write for DTLSFlow<F>
where
    F: Flow + Read + Write
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
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;

#[cfg(test)]
use crate::config::UDPFarChannelConfig;
#[cfg(test)]
use crate::far::udp::UDPFarChannel;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

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
    let channel_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let channel_addr = SocketAddr::new(
        channel_config.tls().underlying().addr().clone(),
        channel_config.tls().underlying().port()
    );
    let client_addr = SocketAddr::new(
        client_config.tls().underlying().addr().clone(),
        client_config.tls().underlying().port()
    );
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut listener = DTLSFarChannel::<UDPFarChannel>::new(
            &mut client_nscaches,
            channel_config
        )
        .expect("Expected success");
        let param = listener.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: DTLSMultiFlows<
            UDPFarChannel,
            PassthruDatagramXfrm<SocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        client_barrier.wait();

        let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();

        client_barrier.wait();

        let nbytes = flow.read(&mut buf).unwrap();

        flow.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });
    let channel_barrier = barrier;
    let mut channel_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn = DTLSFarChannel::<UDPFarChannel>::new(
            &mut channel_nscaches,
            client_config
        )
        .expect("expected success");
        let param = conn.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: DTLSSingleFlow<
            UDPFarChannel,
            PassthruDatagramXfrm<SocketAddr>
        > = conn
            .borrowed_flows(param, xfrm, channel_addr.clone())
            .unwrap();
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));

        channel_barrier.wait();

        let mut flow = BorrowedFlows::flow(
            &mut flows,
            channel_addr.clone(),
            Some(&endpoint)
        )
        .unwrap();

        flow.write_all(&FIRST_BYTES).expect("Expected success");

        channel_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        channel_barrier.wait();

        flow.read_exact(&mut buf).unwrap();

        // assert_eq!(peer_addr, channel_addr);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}
