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

//! Near-link channels over Transport-Layer Security (TLS) sessions.
//!
//! This module provides a [NearChannel] and [NearConnector]
//! implementation over TLS sessions.  [TLSNearAcceptor]s can be used to
//! listen on another [NearChannel], and then negotiate a TLS session
//! from the server side.  [TLSNearConnector]s can be used to acquire
//! connections using another [NearConnector], then negotiate a TLS
//! session from the client side.
//!
//! Communications over the resulting
//! channel will then be protected.  If client authentication is
//! enabled, the channel will also be authenticated.

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::time::Duration;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use log::info;
use log::warn;
use mio::event::Source;
use mio::Interest;
use mio::Registry;
use mio::Token;
use openssl::error::ErrorStack;
use openssl::ssl::HandshakeError;
use openssl::ssl::MidHandshakeSslStream;
use openssl::ssl::ShutdownResult;
use openssl::ssl::SslAcceptor;
use openssl::ssl::SslConnector;
use openssl::ssl::SslStream;

use crate::config::tls::TLSLoadClient;
use crate::config::tls::TLSLoadConfigError;
use crate::config::tls::TLSLoadServer;
use crate::config::TLSChannelConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;
use crate::tls::SSLStream;
use crate::tls::TLSShutdownNegotiator;

/// Wrapper for TLS sessions.
pub struct TLSConn<S: Source + Read + Write, Endpoint: Display> {
    /// The underlying SSL stream.
    ssl: SslStream<S>,
    peer: Endpoint
}

/// Errors that can occur during TLS channel creation.
#[derive(Debug)]
pub enum TLSCreateError {
    /// An error occurred while loading the TLS configuration.
    TLS {
        /// The TLS configuration load error.
        error: TLSLoadConfigError
    },
    /// No identity was provided for verification, and none could be
    /// obtained from the underlying connection.
    NoName
}

/// Multiplexer for errors that can occur while creating a session on
/// top of an underlying channel.
#[derive(Debug)]
pub enum TLSSessionCreateError<Session, Channel> {
    /// Error creating the session-level parameters.
    Session { error: Session },
    /// Error creating the underlying channel.
    Channel { error: Channel }
}

/// Server side of a Transport-Layer Security (TLS) near-link channel.
///
/// This is a [NearChannel] instance that obtains connections from a
/// lower-level `NearChannel` instance, and then negotiates TLS
/// sessions from the server side.  Communications over the resulting
/// channel will then be protected.  If client authentication is
/// enabled, the connection will also be authenticated.
///
/// Typically, a [TCPNearAcceptor](crate::near::tcp::TCPNearAcceptor) will be
/// used as the underlying channel; however, this is not required.  It
/// is possible, for example, to use a
/// [UnixNearAcceptor](crate::near::unix::UnixNearAcceptor) (though this is
/// typically only useful forz testing purposes).  It is even possible
/// to use another `TLSNearAcceptor` to set up double-layer TLS.
///
/// # Usage
///
/// The primary usage of `TLSNearAcceptor` takes place through its
/// [NearChannel] instance.
///
/// ## Configuration and Creation
///
/// A `TLSNearAcceptor` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [TLSChannelConfig] as its principal argument, which supplies all
/// configuration unformation.  This `TLSChannelConfig`'s first type
/// parameter (the TLS configuration object) must have a
/// [TLSLoadServer] instance.  The type alias
/// [TLSNearAcceptorConfig](crate::config::TLSNearAcceptorConfig)
/// provides the correct type parameter for most near-link use cases.
///
/// ### Example
///
/// The following example shows how to create a `TLSNearAcceptor`.  A
/// [TCPNearAcceptor](crate::near::tcp::TCPNearAcceptor) is used as the
/// underlying channel.
///
/// ```
/// # use constellation_channels::config::tls::TLSServerConfig;
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPNearAcceptor;
/// # use constellation_channels::near::tls::TLSNearAcceptor;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "cert: test/data/certs/server/certs/test_server_cert.pem\n",
///     "key: test/data/certs/server/private/test_server_key.pem\n",
///     "addr: ::0\n",
///     "port: 8008\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let acceptor: TLSNearAcceptor<TCPNearAcceptor, TLSServerConfig> =
///     TLSNearAcceptor::create(&mut nscaches, accept_config).unwrap();
/// ```
///
/// ## Accepting Connections
///
/// Once a `TLSNearAcceptor` has been created, connections can be accepted
/// using the [take_connection](NearChannel::take_connection)
/// function.
pub struct TLSNearAcceptor<A: NearChannel + Source, TLS: TLSLoadServer> {
    tls: PhantomData<TLS>,
    /// The configuration for establishing TLS sessions.
    acceptor: SslAcceptor,
    shutdown_retry: Retry,
    shutdown_timeout: Duration,
    /// The underlying [NearChannel] instance for obtaining
    /// connections.
    inner: A
}

/// Client side of a Transport-Layer Security (TLS) near-link channel.
///
/// This is a [NearChannel] and [NearConnector] instance that attempts
/// to establish a connection on an underlying `NearConnector`-based
/// channel, then attempts to negotiate a TLS session from the client
/// side.  Communications over the resulting channel will then be
/// protected.  If client authentication is enabled, then
/// authentication will be established with the server using the
/// client certificate.
///
/// Typically, a [TCPNearConnector](crate::near::tcp::TCPNearConnector) will
/// be used as the underlying channel; however, this is not required.
/// It is possible, for example, to use a
/// [UnixNearConnector](crate::near::unix::UnixNearConnector) (though this is
/// typically only useful for testing purposes).  It is even possible
/// to use another `TLSNearConnector` to set up double-layer TLS.
///
/// # Usage
///
/// The primary use of a `TLSNearConnector` takes place through its
/// [NearChannel] and [NearConnector] instances.
///
/// ## Configuration and Creation
///
/// A `TLSNearConnector` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [TLSChannelConfig] as its principal argument, which supplies all
/// configuration unformation.  This `TLSChannelConfig`'s first type
/// parameter (the TLS configuration object) must have a
/// [TLSLoadClient] instance.  The type alias
/// [TLSNearConnectorConfig](crate::config::TLSNearConnectorConfig)
/// provides the correct type parameter for most near-link use cases.
///
/// ### Example
///
/// The following example shows how to create a `TLSNearConnector`, using
/// a [TCPNearConnector](crate::near::tcp::TCPNearConnector) as the underlying
/// channel.
///
/// ```
/// # use constellation_channels::config::tls::TLSClientConfig;
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPResolvingNearConnector;
/// # use constellation_channels::near::tls::TLSNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "trust-root:\n",
///     "  root-certs:\n",
///     "    - test/data/certs/server/ca_cert.pem\n",
///     "addr: en.wikipedia.org\n",
///     "port: 443\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector: TLSNearConnector<TCPResolvingNearConnector,
///                                 TLSClientConfig> =
///     TLSNearConnector::create(&mut nscaches, accept_config).unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `TLSNearConnector` has been created, connections can be
/// established using the
/// [take_connection](NearChannel::take_connection) or
/// [connection](NearConnector::connection) functions.  These will
/// block until a connection has been successfully established.  Note
/// that depending on the circumstances, this may involve many retries
/// and/or name resolutions.
///
/// The TLS session negotiation will occur transparently, and the
/// `TLSNearConnector` will also automatically retry if it fails.  Errors
/// occurring during connection will be logged, but will not cause
/// [take_connection](NearChannel::take_connection) or
/// [connection](NearConnector::connection) to fail.
pub struct TLSNearConnector<Conn, TLS> {
    tls: PhantomData<TLS>,
    /// The configuration for establishing TLS sessions.
    connector: SslConnector,
    domain: String,
    shutdown_retry: Retry,
    shutdown_timeout: Duration,
    /// The underlying [NearChannel] instance for obtaining
    /// connections.
    inner: Conn
}

#[derive(Debug)]
pub enum TLSNegotiateError<Inner, Endpoint, Conn> {
    Inner {
        err: Inner,
    },
    TLS {
        endpoint: Endpoint,
        err: MidHandshakeSslStream<Conn>
    },
    SetupError {
        err: ErrorStack
    },
    BadSplit
}

#[derive(Debug)]
pub enum TLSNegotiatePending<Inner, Endpoint, Conn> {
    Inner {
        pending: Inner,
    },
    TLS {
        endpoint: Endpoint,
        pending: MidHandshakeSslStream<Conn>
    }
}

impl<Inner, Endpoint, Conn> ScopedError
    for TLSNegotiateError<Inner, Endpoint, Conn>
where Inner: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            TLSNegotiateError::Inner { err } => err.scope(),
            TLSNegotiateError::TLS { err, .. } => err.error().scope(),
            TLSNegotiateError::SetupError { .. } |
            TLSNegotiateError::BadSplit => ErrorScope::Unrecoverable
        }
    }
}

impl<Inner, Endpoint, Conn> ScopedError
    for Box<TLSNegotiateError<Inner, Endpoint, Conn>>
where Inner: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self.as_ref() {
            TLSNegotiateError::Inner { err } => err.scope(),
            TLSNegotiateError::TLS { err, .. } => err.error().scope(),
            TLSNegotiateError::SetupError { .. } |
            TLSNegotiateError::BadSplit => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for TLSCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            TLSCreateError::TLS { error } => error.scope(),
            TLSCreateError::NoName => ErrorScope::System
        }
    }
}

impl<Stream, Endpoint> From<TLSConn<Stream, Endpoint>> for SslStream<Stream>
where Stream: Source + Session,
      Endpoint: Display {
    #[inline]
    fn from(val: TLSConn<Stream, Endpoint>) -> SslStream<Stream> {
        val.ssl
    }
}

impl<A, TLS> Negotiator<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint)>
    for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannel + Source,
{
    type State = A::State;
    type Pending = TLSNegotiatePending<
        A::Pending,
        A::Endpoint,
        A::Conn
    >;
    type NegotiateError = TLSNegotiateError<
        A::NegotiateError,
        A::Endpoint,
        A::Conn
    >;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        self.inner
            .negotiate(state)
            .map_err(|err| TLSNegotiateError::Inner { err: err })?
            .map_pending(|pending| TLSNegotiatePending::Inner {
                pending: pending
            })
            .flat_map_ok(|(stream, endpoint)| {
                match self.acceptor.accept(stream) {
                    Ok(stream) => {
                        let conn = TLSConn {
                            ssl: stream,
                            peer: endpoint.clone()
                        };

                        Ok(NegotiatorResult::Complete(
                            (conn, endpoint)
                        ))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(stack) =>
                            Err(TLSNegotiateError::SetupError {
                                err: stack
                            }),
                        HandshakeError::Failure(err) =>
                            Err(TLSNegotiateError::TLS {
                                endpoint: endpoint.clone(),
                                err: err
                            }),
                        HandshakeError::WouldBlock(pending) =>
                            Ok(NegotiatorResult::Pending(
                                TLSNegotiatePending::TLS {
                                    endpoint: endpoint.clone(),
                                    pending: pending
                                }
                            )),
                    }
                }
            })
    }

    /// Complete a failed negotiation.
    fn complete_negotiate(
        &self,
        pending: TLSNegotiatePending<A::Pending, A::Endpoint, A::Conn>
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        match pending {
            TLSNegotiatePending::Inner { pending } => self
                .inner
                .complete_negotiate(pending)
                .map_err(|err| TLSNegotiateError::Inner { err: err })?
                .map_pending(|pending| TLSNegotiatePending::Inner {
                    pending: pending
                })
                .flat_map_ok(|(stream, endpoint)| {
                    match self.acceptor.accept(stream) {
                        Ok(stream) => {
                            let conn = TLSConn {
                                ssl: stream,
                                peer: endpoint.clone()
                            };

                            Ok(NegotiatorResult::Complete(
                                (conn, endpoint)
                            ))
                        }
                        Err(err) => match err {
                            HandshakeError::SetupFailure(stack) =>
                                Err(TLSNegotiateError::SetupError {
                                    err: stack
                                }),
                            HandshakeError::Failure(err) =>
                                Err(TLSNegotiateError::TLS {
                                    endpoint: endpoint.clone(),
                                    err: err
                                }),
                            HandshakeError::WouldBlock(pending) =>
                                Ok(NegotiatorResult::Pending(
                                    TLSNegotiatePending::TLS {
                                        endpoint: endpoint.clone(),
                                        pending: pending
                                    }
                                )),
                        }
                    }
                }),
            TLSNegotiatePending::TLS { endpoint, pending } => match pending
                .handshake() {
                Ok(stream) => {
                    let conn = TLSConn {
                        ssl: stream,
                        peer: endpoint.clone()
                    };

                    Ok(NegotiatorResult::Complete(
                        (conn, endpoint)
                    ))
                }
                Err(err) => match err {
                    HandshakeError::SetupFailure(stack) =>
                        Err(TLSNegotiateError::SetupError {
                            err: stack
                        }),
                    HandshakeError::Failure(err) =>
                        Err(TLSNegotiateError::TLS {
                            endpoint: endpoint.clone(),
                            err: err
                        }),
                    HandshakeError::WouldBlock(pending) =>
                        Ok(NegotiatorResult::Pending(
                            TLSNegotiatePending::TLS {
                                endpoint: endpoint.clone(),
                                pending: pending
                            }
                        )),
                }
            }
        }
    }
}

impl<A, TLS> NearChannel for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannel + Source,
    A::Conn: Credentials
{
    type Endpoint = A::Endpoint;
    type Conn = TLSConn<A::Conn, A::Endpoint>;
    type ShutdownNego = TLSShutdownNegotiator<A::Conn, A::ShutdownNego,
                                              A::ShutdownValue>;
    type ShutdownValue = SSLStream<A::Conn>;
    type StartError = A::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.inner.start(registry, token)
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        let inner = self.inner.shutdown_nego();

        TLSShutdownNegotiator::new(inner, self.shutdown_retry.clone(),
                                   self.shutdown_timeout)
    }

    #[inline]
    fn shutdown_param(
        &self
    ) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: TLSNegotiateError<
            A::NegotiateError,
            A::Endpoint,
            A::Conn
        >
    ) -> Result<(), Error> {
        match err {
            TLSNegotiateError::Inner { err } =>
                self.inner.cleanup(registry, err),
            TLSNegotiateError::TLS { mut err, .. } =>
                registry.deregister(err.get_mut()),
            // XXX Figure out if we need to deregister for SetupFailures.
            TLSNegotiateError::SetupError { .. } |
            TLSNegotiateError::BadSplit => Ok(())
        }
    }
}

impl<S, Endpoint> Session for TLSConn<S, Endpoint>
where
    S: Source + Read + Write + Session,
    Endpoint: Display
{
    type LocalAddr = S::LocalAddr;
    type PeerAddr = S::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.ssl.get_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.ssl.get_ref().peer_addr()
    }
}

impl<S, Endpoint> Source for TLSConn<S, Endpoint>
where
    S: Source + Read + Write,
    Endpoint: Display
{
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.ssl.get_mut().register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.ssl.get_mut().reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.ssl.get_mut().deregister(registry)
    }
}

impl<A, TLS> Source for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannel + Source,
{
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.inner.register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.inner.reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.inner.deregister(registry)
    }
}

impl<A, TLS> NearChannelCreate for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannelCreate + Source,
    A::Conn: Credentials
{
    type Config = TLSChannelConfig<TLS, A::Config>;
    type CreateError = TLSSessionCreateError<TLSCreateError, A::CreateError>;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, A::Config>
    ) -> Result<TLSNearAcceptor<A, TLS>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (tls, endpoint, shutdown_retry, shutdown_timeout) = config.take();
        let acceptor = tls.load_server(None, false).map_err(|err| {
            TLSSessionCreateError::Session {
                error: TLSCreateError::TLS { error: err }
            }
        })?;
        let inner = A::create(caches, endpoint)
            .map_err(|err| TLSSessionCreateError::Channel { error: err })?;

        Ok(TLSNearAcceptor {
            tls: PhantomData,
            inner: inner,
            acceptor: acceptor,
            shutdown_retry: shutdown_retry,
            shutdown_timeout: shutdown_timeout,
        })
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        A::verify_endpoint(config.underlying())
    }
}

impl<A, TLS> Negotiator<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint)>
    for TLSNearConnector<A, TLS>
where
    TLS: TLSLoadClient,
    A: NearChannel,
{
    type State = A::State;
    type Pending = TLSNegotiatePending<
        A::Pending,
        A::Endpoint,
        A::Conn
    >;
    type NegotiateError = TLSNegotiateError<
        A::NegotiateError,
        A::Endpoint,
        A::Conn
    >;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        self.inner
            .negotiate(state)
            .map_err(|err| TLSNegotiateError::Inner { err: err })?
            .map_pending(|pending| TLSNegotiatePending::Inner {
                pending: pending
            })
            .flat_map_ok(|(stream, endpoint)| {
                match self.connector.connect(self.domain.as_str(), stream) {
                    Ok(stream) => {
                        let conn = TLSConn {
                            ssl: stream,
                            peer: endpoint.clone()
                        };

                        Ok(NegotiatorResult::Complete(
                            (conn, endpoint)
                        ))
                    }
                    Err(err) => match err {
                        HandshakeError::SetupFailure(stack) =>
                            Err(TLSNegotiateError::SetupError {
                                err: stack
                            }),
                        HandshakeError::Failure(err) =>
                            Err(TLSNegotiateError::TLS {
                                endpoint: endpoint.clone(),
                                err: err
                            }),
                        HandshakeError::WouldBlock(pending) =>
                            Ok(NegotiatorResult::Pending(
                                TLSNegotiatePending::TLS {
                                    endpoint: endpoint.clone(),
                                    pending: pending
                                }
                            )),
                    }
                }
            })
    }

    /// Complete a failed negotiation.
    fn complete_negotiate(
        &self,
        pending: TLSNegotiatePending<A::Pending, A::Endpoint, A::Conn>
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        match pending {
            TLSNegotiatePending::Inner { pending } => self
                .inner
                .complete_negotiate(pending)
                .map_err(|err| TLSNegotiateError::Inner { err: err })?
                .map_pending(|pending| TLSNegotiatePending::Inner {
                    pending: pending
                })
                .flat_map_ok(|(stream, endpoint)| {
                    match self.connector.connect(self.domain.as_str(), stream) {
                        Ok(stream) => {
                            let conn = TLSConn {
                                ssl: stream,
                                peer: endpoint.clone()
                            };

                            Ok(NegotiatorResult::Complete(
                                (conn, endpoint)
                            ))
                        }
                        Err(err) => match err {
                            HandshakeError::SetupFailure(stack) =>
                                Err(TLSNegotiateError::SetupError {
                                    err: stack
                                }),
                            HandshakeError::Failure(err) =>
                                Err(TLSNegotiateError::TLS {
                                    endpoint: endpoint.clone(),
                                    err: err
                                }),
                            HandshakeError::WouldBlock(pending) =>
                                Ok(NegotiatorResult::Pending(
                                    TLSNegotiatePending::TLS {
                                        endpoint: endpoint.clone(),
                                        pending: pending
                                    }
                                )),
                        }
                    }
                }),
            TLSNegotiatePending::TLS { endpoint, pending } => match pending
                .handshake() {
                Ok(stream) => {
                    let conn = TLSConn {
                        ssl: stream,
                        peer: endpoint.clone()
                    };

                    Ok(NegotiatorResult::Complete(
                        (conn, endpoint)
                    ))
                }
                Err(err) => match err {
                    HandshakeError::SetupFailure(stack) =>
                        Err(TLSNegotiateError::SetupError {
                            err: stack
                        }),
                    HandshakeError::Failure(err) =>
                        Err(TLSNegotiateError::TLS {
                            endpoint: endpoint.clone(),
                            err: err
                        }),
                    HandshakeError::WouldBlock(pending) =>
                        Ok(NegotiatorResult::Pending(
                            TLSNegotiatePending::TLS {
                                endpoint: endpoint.clone(),
                                pending: pending
                            }
                        )),
                }
            }
        }
    }
}

impl<Conn, TLS> NearChannel for TLSNearConnector<Conn, TLS>
where
    Conn: NearConnector,
    Conn::Conn: Credentials,
    TLS: TLSLoadClient
{
    type Endpoint = Conn::Endpoint;
    type Conn = TLSConn<Conn::Conn, Conn::Endpoint>;
    type ShutdownNego = TLSShutdownNegotiator<Conn::Conn,
                                              Conn::ShutdownNego,
                                              Conn::ShutdownValue>;
    type ShutdownValue = SSLStream<Conn::Conn>;
    type StartError = Conn::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.inner.start(registry, token)
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        let inner = self.inner.shutdown_nego();

        TLSShutdownNegotiator::new(inner, self.shutdown_retry.clone(),
                                   self.shutdown_timeout)
    }

    #[inline]
    fn shutdown_param(
        &self
    ) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: TLSNegotiateError<
            Conn::NegotiateError,
            Conn::Endpoint,
            Conn::Conn
        >
    ) -> Result<(), Error> {
        match err {
            TLSNegotiateError::Inner { err } =>
                self.inner.cleanup(registry, err),
            TLSNegotiateError::TLS { mut err, .. } =>
                registry.deregister(err.get_mut()),
            // XXX Figure out if we need to deregister for SetupFailures.
            TLSNegotiateError::SetupError { .. } |
            TLSNegotiateError::BadSplit => Ok(())
        }
    }
}

impl<Conn, TLS> NearChannelCreate for TLSNearConnector<Conn, TLS>
where
    TLS: TLSLoadClient,
    Conn: NearChannelCreate + NearConnector,
    Conn::Conn: Credentials,
{
    type Config = TLSChannelConfig<TLS, Conn::Config>;
    type CreateError = TLSSessionCreateError<TLSCreateError, Conn::CreateError>;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, Conn::Config>
    ) -> Result<TLSNearConnector<Conn, TLS>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (tls, endpoint, shutdown_retry, shutdown_timeout) = config.take();
        let verify_endpoint = match tls.verify_endpoint() {
            Some(endpoint) => Ok(endpoint),
            None => match Conn::verify_endpoint(&endpoint) {
                Some(endpoint) => Ok(endpoint),
                None => Err(TLSSessionCreateError::Session {
                    error: TLSCreateError::NoName
                })
            }
        }?;
        let connector = tls.load_client(None, verify_endpoint, false)
            .map_err(|err| {
                TLSSessionCreateError::Session {
                    error: TLSCreateError::TLS { error: err }
                }
            })?;
        let domain = match verify_endpoint {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            }
            // XXX This should probably produce an error.
            IPEndpointAddr::Addr(_) => String::new()
        };
        let inner = Conn::create(caches, endpoint)
            .map_err(|err| TLSSessionCreateError::Channel { error: err })?;

        Ok(TLSNearConnector {
            tls: PhantomData,
            shutdown_timeout: shutdown_timeout,
            shutdown_retry: shutdown_retry,
            connector: connector,
            domain: domain,
            inner: inner
        })
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Conn::verify_endpoint(config.underlying())
    }
}

impl<Conn, TLS> NearChannelCreateWithEndpoint for TLSNearConnector<Conn, TLS>
where
    TLS: TLSLoadClient,
    Conn: NearChannelCreateWithEndpoint + NearConnector,
    Conn::Conn: Credentials,
{
    type Config = TLSChannelConfig<TLS, Conn::Config>;
    type EndpointConfig = Conn::EndpointConfig;
    type CreateError = TLSSessionCreateError<TLSCreateError, Conn::CreateError>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, Conn::Config>,
        endpoint: Conn::EndpointConfig,
        verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<TLSNearConnector<Conn, TLS>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx
    {
        let (tls, config, shutdown_retry, shutdown_timeout) = config.take();
        let verify_endpoint = match tls.verify_endpoint() {
            Some(endpoint) => Ok(endpoint),
            None => match verify_endpoint {
                Some(endpoint) => Ok(endpoint),
                None => Err(TLSSessionCreateError::Session {
                    error: TLSCreateError::NoName
                })
            }
        }?;
        let connector = tls.load_client(None, verify_endpoint, false)
            .map_err(|err| {
                TLSSessionCreateError::Session {
                    error: TLSCreateError::TLS { error: err }
                }
            })?;
        let domain = match verify_endpoint {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            }
            // XXX This should probably produce an error.
            IPEndpointAddr::Addr(_) => String::new()
        };
        let inner = Conn::create_with_endpoint(caches, config, endpoint,
                                               Some(verify_endpoint))
            .map_err(|err| TLSSessionCreateError::Channel { error: err })?;

        Ok(TLSNearConnector {
            tls: PhantomData,
            shutdown_timeout: shutdown_timeout,
            shutdown_retry: shutdown_retry,
            connector: connector,
            domain: domain,
            inner: inner
        })
    }
}

impl<Conn, TLS> NearConnector for TLSNearConnector<Conn, TLS>
where
    Conn: NearConnector,
    Conn::Conn: Credentials,
    TLS: TLSLoadClient
{
    /// Type of endpoint references.
    type EndpointRef<'a> = Conn::EndpointRef<'a>
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.inner.endpoint()
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
}

impl<A, TLS> Negotiator<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint)>
    for Box<TLSNearConnector<A, TLS>>
where
    TLS: TLSLoadClient,
    A: NearChannel,
{
    type State = A::State;
    type Pending = TLSNegotiatePending<
        A::Pending,
        A::Endpoint,
        A::Conn
    >;
    type NegotiateError = TLSNegotiateError<
        A::NegotiateError,
        A::Endpoint,
        A::Conn
    >;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: TLSNegotiatePending<A::Pending, A::Endpoint, A::Conn>
    ) -> Result<NegotiatorResult<(TLSConn<A::Conn, A::Endpoint>, A::Endpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<Conn, TLS> NearChannel for Box<TLSNearConnector<Conn, TLS>>
where
    Conn: NearConnector,
    Conn::Conn: Credentials,
    TLS: TLSLoadClient
{
    type Endpoint = Conn::Endpoint;
    type Conn = TLSConn<Conn::Conn, Conn::Endpoint>;
    type ShutdownNego = TLSShutdownNegotiator<Conn::Conn,
                                              Conn::ShutdownNego,
                                              Conn::ShutdownValue>;
    type ShutdownValue = SSLStream<Conn::Conn>;
    type StartError = Conn::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.as_mut().start(registry, token)
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        let inner = self.inner.shutdown_nego();

        TLSShutdownNegotiator::new(inner, self.shutdown_retry.clone(),
                                   self.shutdown_timeout)
    }

    #[inline]
    fn shutdown_param(
        &self
    ) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: TLSNegotiateError<
            Conn::NegotiateError,
            Conn::Endpoint,
            Conn::Conn
        >
    ) -> Result<(), Error> {
        self.as_mut().cleanup(registry, err)
    }
}

impl<Conn, TLS> NearChannelCreate for Box<TLSNearConnector<Conn, TLS>>
where
    TLS: TLSLoadClient,
    Conn: NearChannelCreate + NearConnector,
    Conn::Conn: Credentials,
{
    type Config = TLSChannelConfig<TLS, Conn::Config>;
    type CreateError = TLSSessionCreateError<TLSCreateError, Conn::CreateError>;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, Conn::Config>
    ) -> Result<Box<TLSNearConnector<Conn, TLS>>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        Ok(Box::new(TLSNearConnector::create(caches, config)?))
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Conn::verify_endpoint(config.underlying())
    }
}

impl<Conn, TLS> NearChannelCreateWithEndpoint
    for Box<TLSNearConnector<Conn, TLS>>
where
    TLS: TLSLoadClient,
    Conn: NearChannelCreateWithEndpoint + NearConnector,
    Conn::Conn: Credentials,
{
    type Config = TLSChannelConfig<TLS, Conn::Config>;
    type EndpointConfig = Conn::EndpointConfig;
    type CreateError = TLSSessionCreateError<TLSCreateError, Conn::CreateError>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, Conn::Config>,
        endpoint: Conn::EndpointConfig,
        verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<Box<TLSNearConnector<Conn, TLS>>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        Ok(Box::new(TLSNearConnector::create_with_endpoint(caches, config,
                                                           endpoint,
                                                           verify_endpoint)?))
    }
}

impl<Conn, TLS> NearConnector for Box<TLSNearConnector<Conn, TLS>>
where
    Conn: NearConnector + Source,
    Conn::Conn: Credentials,
    TLS: TLSLoadClient
{
    /// Type of endpoint references.
    type EndpointRef<'a> = Conn::EndpointRef<'a>
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.as_ref().endpoint()
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.as_mut().shutdown()
    }
}

impl<S, Endpoint> Credentials for TLSConn<S, Endpoint>
where
    S: Credentials + Source + Read + Write,
    Endpoint: Display
{
    type Cred = SSLCred<S::Cred>;
    type CredError = S::CredError;

    #[inline]
    fn creds(&self) -> Result<Option<SSLCred<S::Cred>>, S::CredError> {
        self.ssl.creds()
    }
}

impl<S, Endpoint> CredentialsMut for TLSConn<S, Endpoint>
where
    S: CredentialsMut + Source + Read + Write,
    Endpoint: Display
{
    type Cred = SSLCred<S::Cred>;
    type CredError = S::CredError;

    #[inline]
    fn creds(&mut self) -> Result<Option<SSLCred<S::Cred>>, S::CredError> {
        self.ssl.creds()
    }
}

impl<S, Endpoint> Read for TLSConn<S, Endpoint>
where
    S: Source + Read + Write,
    Endpoint: Display
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

impl<S, Endpoint> Write for TLSConn<S, Endpoint>
where
    S: Source + Read + Write,
    Endpoint: Display
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

impl<S, Endpoint> Debug for TLSConn<S, Endpoint>
where
    S: Source + Read + Write + Debug,
    Endpoint: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "TLSConn {{ ssl: {:?}, peer: {} }}", self.ssl, self.peer)
    }
}

impl Display for TLSCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSCreateError::TLS { error } => write!(f, "{}", error),
            TLSCreateError::NoName => write!(
                f,
                concat!(
                    "non-IP endpoint for TLS connector ",
                    "and no verify-endpoint provided"
                )
            )
        }
    }
}

impl<Inner, Endpoint, TLS> Display for TLSNegotiateError<Inner, Endpoint, TLS>
where Inner: Display {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSNegotiateError::Inner { err } => err.fmt(f),
            TLSNegotiateError::TLS { err, .. } => write!(f, "{}", err.error()),
            TLSNegotiateError::SetupError { err, .. } =>
                write!(f, "{}", err),
            TLSNegotiateError::BadSplit =>
                write!(f, "invalid result from split()")
        }
    }
}

impl<Session, Channel> ScopedError for TLSSessionCreateError<Session, Channel>
where
    Session: ScopedError,
    Channel: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            TLSSessionCreateError::Session { error } => error.scope(),
            TLSSessionCreateError::Channel { error } => error.scope()
        }
    }
}

impl<Session, Channel> Display for TLSSessionCreateError<Session, Channel>
where
    Session: Display,
    Channel: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSSessionCreateError::Session { error } => error.fmt(f),
            TLSSessionCreateError::Channel { error } => error.fmt(f)
        }
    }
}

#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use crate::config::tls::TLSClientConfig;
#[cfg(test)]
use crate::config::tls::TLSServerConfig;
#[cfg(test)]
use crate::config::TLSNearAcceptorConfig;
#[cfg(test)]
use crate::config::TLSNearConnectorConfig;
#[cfg(test)]
use crate::config::UnixNearChannelConfig;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::near::unix::UnixNearAcceptor;
#[cfg(test)]
use crate::near::unix::UnixNearConnector;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[cfg(test)]
fn server_conf(path: &str) -> String {
    format!(
        concat!(
            "cipher-suites:\n",
            "  - TLS_AES_256_GCM_SHA384\n",
            "  - TLS_CHACHA20_POLY1305_SHA256\n",
            "key-exchange-groups:\n",
            "  - X25519\n",
            "  - P-256\n",
            "client-auth:\n",
            "  verify: required\n",
            "  trust-root:\n",
            "    root-certs:\n",
            "      - test/data/certs/client/ca_cert.pem\n",
            "    crls: []\n",
            "cert: test/data/certs/server/certs/test_server_cert.pem\n",
            "key: test/data/certs/server/private/test_server_key.pem\n",
            "path: {}"
        ),
        path
    )
}

#[cfg(test)]
fn client_conf(path: &str) -> String {
    format!(
        concat!(
            "cipher-suites:\n",
            "  - TLS_AES_256_GCM_SHA384\n",
            "  - TLS_CHACHA20_POLY1305_SHA256\n",
            "key-exchange-groups:\n",
            "  - X25519\n",
            "  - P-256\n",
            "trust-root:\n",
            "  root-certs:\n",
            "    - test/data/certs/server/ca_cert.pem\n",
            "  crls: []\n",
            "client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
            "client-key: test/data/certs/client/private/test_client_key.pem\n",
            "verify-endpoint: test-server.nowhere.com\n",
            "path: {}"
        ),
        path
    )
}

#[cfg(test)]
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

#[cfg(test)]
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;

#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::near::accept_one;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::write_one;
#[cfg(test)]
use crate::near::negotiate_one;

#[test]
fn test_negotiate() {
    init();

    const PATH: &'static str = "test-tls-negotiate.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry().register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let _ = negotiate_one(&mut acceptor, &mut poll, start, session)
            .expect("Expected success");
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn.start(poll.registry(), session)
            .expect("expected success") {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };
        let _ = negotiate_one(&mut conn, &mut poll, start, session)
            .expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_send() {
    init();

    const PATH: &'static str = "test-tls-send.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry().register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) = negotiate_one(&mut acceptor, &mut poll,
                                            start, session)
            .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn.start(poll.registry(), session)
            .expect("expected success") {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) = negotiate_one(&mut conn, &mut poll,
                                            start, session)
            .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");

    });

    listen.join().unwrap();
    send.join().unwrap();
}


#[test]
fn test_recv() {
    init();

    const PATH: &'static str = "test-tls-recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
            .expect("Expected success");

        server_barrier.wait();

        poll.registry().register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) = negotiate_one(&mut acceptor, &mut poll,
                                            start, session)
            .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn.start(poll.registry(), session)
            .expect("expected success") {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) = negotiate_one(&mut conn, &mut poll,
                                            start, session)
            .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_send_recv() {
    init();

    const PATH: &'static str = "test-tls-send-recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry().register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) = negotiate_one(&mut acceptor, &mut poll,
                                            start, session)
            .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &SECOND_BYTES)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn.start(poll.registry(), session)
            .expect("expected success") {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) = negotiate_one(&mut conn, &mut poll,
                                            start, session)
            .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}
