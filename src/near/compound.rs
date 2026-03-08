// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! A flexible, configurable [NearChannel] instance.
//!
//! Compound channels support arbitrary nesting of different channel
//! types, which can be constructed according to a configuration.
//! This functionality is provided by [CompoundNearAcceptor] and
//! [CompoundNearConnector] Most applications should use these
//! implementations, unless there is a good reason to impose more
//! stringent restrictions on what types of channels can be
//! configured.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
#[cfg(feature = "tls")]
use constellation_auth::cred::SSLCred;
use constellation_auth::cred::UnixSocketCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::PassthruNegotiator;
use constellation_common::net::PassthruSessionNegotiation;
use constellation_common::net::Session;
use constellation_common::retry::RetryResult;
#[cfg(feature = "unix")]
use constellation_common::unix::UnixSocketAddr;
#[cfg(feature = "unix")]
use constellation_common::unix::UnixSocketPath;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5Stream;
#[cfg(feature = "socks5")]
use constellation_streams::channels::ChannelParam;
use mio::event::Source;
use mio::net::UnixStream;
use mio::Interest;
use mio::Registry;
use mio::Token;

#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadClient;
#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadConfigError;
#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadServer;
use crate::config::CompoundNearAcceptorConfig;
use crate::config::CompoundNearConnectorParam;
use crate::config::CompoundNearConnectorPartialConfig;
use crate::config::CompoundResolvingNearConnectorConfig;
use crate::config::CompoundResolvingNearConnectorPartialConfig;
use crate::config::TLSParam;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NearConnector;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NegotiateError;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NegotiatePending;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5SessionNegotiation;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5ShutdownNegotiator;
use crate::near::tcp::TCPNearAcceptor;
use crate::near::tcp::TCPNearConnector;
use crate::near::tcp::TCPResolvingNearConnector;
use crate::near::tcp::TCPResolvingNearConnectorError;
use crate::near::tcp::TCPStream;
#[cfg(feature = "tls")]
use crate::near::tls::TLSConn;
#[cfg(feature = "tls")]
use crate::near::tls::TLSCreateError;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNearAcceptor;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNearConnector;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNegotiateError;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNegotiatePending;
#[cfg(feature = "tls")]
use crate::near::tls::TLSSessionCreateError;
#[cfg(feature = "unix")]
use crate::near::unix::UnixNearAcceptor;
#[cfg(feature = "unix")]
use crate::near::unix::UnixNearConnector;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;
use crate::tls::SSLStream;
use crate::tls::TLSShutdownError;
use crate::tls::TLSShutdownNegoPending;
use crate::tls::TLSShutdownNegotiator;
use crate::tls::TLSShutdownNegotiatorState;
use crate::tls::TLSStartError;

/// Multiplexer for [Endpoint](NearChannel::Endpoint)s for
/// [CompoundNearAcceptor].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CompoundNearConcreteAddr {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    TCP {
        tcp: SocketAddr
    }
}

/// Multiplexer for [Endpoint](NearChannel::Endpoint)s for
/// [CompoundNearConnector].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CompoundNearNameAddr {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    TCP {
        tcp: SocketAddr
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: IPEndpoint
    }
}

#[derive(Clone, Debug)]
pub enum CompoundResolvingNearConnectorEndpointConfig {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    TCP {
        tcp: IPEndpoint
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: IPEndpoint
    }
}

/// Multiplexer for [EndpointRef](NearConnector::EndpointRef)s for
/// [CompoundNearConnector].
#[derive(Clone)]
pub enum CompoundNearNameAddrRef<'a> {
    #[cfg(feature = "unix")]
    Unix {
        unix: &'a UnixSocketPath
    },
    TCP {
        tcp: &'a SocketAddr
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: &'a IPEndpoint
    }
}

#[derive(Clone)]
pub enum CompoundResolvingNearConnectorEndpointRef<'a> {
    #[cfg(feature = "unix")]
    Unix {
        unix: &'a UnixSocketPath
    },
    TCP {
        tcp: &'a IPEndpoint
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: &'a IPEndpoint
    }
}

/// Multiplexer for [CreateError](NearChannelCreate::CreateError)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearAcceptorCreateError {
    #[cfg(feature = "unix")]
    Unix {
        unix: Error
    },
    TCP {
        tcp: Error
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSSessionCreateError<
                TLSCreateError,
                CompoundNearAcceptorCreateError
            >
        >
    }
}

/// Multiplexer for [CreateError](NearChannelCreate::CreateError)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearConnectorCreateError {
    #[cfg(feature = "unix")]
    Unix {
        unix: Error
    },
    TCP {
        tcp: TCPResolvingNearConnectorError
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSSessionCreateError<
                TLSCreateError,
                CompoundNearConnectorCreateError
            >
        >
    }
}

#[derive(Debug)]
pub enum CompoundNearConnectorCreateWithEndpointError {
    #[cfg(feature = "unix")]
    Unix {
        unix: Error
    },
    TCP {
        tcp: TCPResolvingNearConnectorError
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSSessionCreateError<
                TLSCreateError,
                CompoundNearConnectorCreateWithEndpointError
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: CompoundNearConnectorCreateError
    },
    Mismatch
}

/// Multiplexer for [CreateError](NearChannelCreate::CreateError)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundResolvingNearConnectorCreateError {
    #[cfg(feature = "unix")]
    Unix { unix: Error },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSSessionCreateError<
                TLSCreateError,
                CompoundNearConnectorCreateError
            >
        >
    }
}

#[derive(Debug)]
pub enum CompoundResolvingNearConnectorCreateWithEndpointError {
    #[cfg(feature = "unix")]
    Unix {
        unix: Error
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSSessionCreateError<
                TLSCreateError,
                CompoundNearConnectorCreateWithEndpointError
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: CompoundNearConnectorCreateError
    },
    Mismatch
}

/// Multiplexer for [NegotiateError](NearChannel::NegotiateError)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearAcceptorNegotiateError {
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSNegotiateError<
                CompoundNearAcceptorNegotiateError,
                CompoundNearConcreteAddr,
                CompoundNearServerConn
            >
        >
    },
    Mismatch
}

pub enum CompoundNearAcceptorNegotiatePending {
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSNegotiatePending<
                CompoundNearAcceptorNegotiatePending,
                CompoundNearConcreteAddr,
                CompoundNearServerConn
            >
        >
    }
}

/// Multiplexer for [NegotiateError](NearChannel::NegotiateError)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearConnectorNegotiateError {
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSNegotiateError<
                CompoundNearConnectorNegotiateError,
                CompoundNearNameAddr,
                CompoundNearClientConn
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiateError<
                CompoundNearConnectorNegotiateError,
                CompoundNearClientConn
            >
        >
    },
    Mismatch
}

pub enum CompoundNearConnectorNegotiatePending {
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSNegotiatePending<
                CompoundNearConnectorNegotiatePending,
                CompoundNearNameAddr,
                CompoundNearClientConn
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiatePending<
                CompoundNearConnectorNegotiatePending,
                CompoundNearClientConn
            >
        >
    }
}

/// Errors that can happen while harvesting credentials.
#[derive(Debug)]
pub enum CompoundNearCredentialError {
    Unix { err: Error },
    TCP { err: Error }
}

/// Errors that can happen while starting negotiations.
#[derive(Debug)]
pub enum CompoundNearAcceptorStartError {
    Unix { err: Error },
    TCP { err: Error }
}

#[derive(Debug)]
pub enum CompoundNearConnectorStartError {
    Unix { err: Error },
    TCP { err: Error }
}

#[derive(Debug)]
pub enum CompoundNearAcceptorShutdownValue {
    #[cfg(feature = "unix")]
    Unix {
        unix: <UnixNearAcceptor as NearChannel>::Conn
    },
    TCP {
        tcp: <TCPNearAcceptor as NearChannel>::Conn
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<SSLStream<CompoundNearServerConn>>
    }
}

#[derive(Debug)]
pub enum CompoundNearConnectorShutdownValue {
    #[cfg(feature = "unix")]
    Unix {
        unix: <UnixNearConnector as NearChannel>::Conn
    },
    TCP {
        tcp: <TCPNearConnector as NearChannel>::Conn
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<SSLStream<CompoundNearClientConn>>
    }
}

/// Multiplexer for [Conn](NearChannel::Conn)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearClientConn {
    #[cfg(feature = "unix")]
    Unix {
        unix: <UnixNearConnector as NearChannel>::Conn
    },
    TCP {
        tcp: <TCPNearConnector as NearChannel>::Conn
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<TLSConn<CompoundNearClientConn, CompoundNearNameAddr>>
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5Stream<CompoundNearClientConn>>
    }
}

/// Multiplexer for [Conn](NearChannel::Conn)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearServerConn {
    #[cfg(feature = "unix")]
    Unix {
        unix: <UnixNearAcceptor as NearChannel>::Conn
    },
    TCP {
        tcp: <TCPNearAcceptor as NearChannel>::Conn
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<TLSConn<CompoundNearServerConn, CompoundNearConcreteAddr>>
    }
}

pub enum CompoundNearConnectorState {
    #[cfg(feature = "unix")]
    Unix {
        unix: (UnixStream, UnixSocketAddr)
    },
    TCP {
        tcp: (TCPStream, SocketAddr)
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5SessionNegotiation<CompoundNearConnectorState>>
    }
}

pub enum CompoundNearAcceptorState {
    #[cfg(feature = "unix")]
    Unix {
        unix: (UnixStream, UnixSocketAddr)
    },
    TCP {
        tcp: (TCPStream, SocketAddr)
    }
}

/// Credentials harvested by [Credentials]
pub enum CompoundNearCredential {
    #[cfg(feature = "unix")]
    Unix { unix: UnixSocketCred<()> },
    /// TCP counterparty address (unsafe) "credential".
    ///
    /// This will only be generated on channels where
    /// `unsafe-allow-ip-addr-creds` is set.
    ///
    /// This is unsafe, and its use should be highly discouraged!
    UnsafeTCP {
        /// Counterparty's socket address.
        unsafe_tcp: SocketAddr
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<SSLCred<CompoundNearCredential>>
    }
}

/// Versatile server-side near-link channel.
///
/// This is a [NearChannel] instance that can support arbitrarily
/// complex nested channel configurations consisting of SOCKS5 and TLS
/// layers, with either TCP or Unix domain sockets serving as the base
/// connections.
///
/// See [CompoundNearAcceptorConfig] for example configuratons.
///
/// # Usage
///
/// The primary usage of `CompoundNearAcceptor` takes place through its
/// [NearChannel] instance.
///
/// ## Configuration and Creation
///
/// A `CompoundNearAcceptor` is created using the
/// [new](NearChannelCreate::new) function from its [NearChannel] instance.
/// This function takes a
/// [CompoundNearNearAcceptorConfig](crate::config::CompoundNearAcceptorConfig)
/// as its principal argument, which supplies all configuration
/// unformation.
///
/// ### Example
///
/// The following example shows how to create a `CompoundNearAcceptor`:
///
/// ```
/// # use constellation_channels::config::tls::TLSServerConfig;
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::compound::CompoundNearAcceptor;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "tls:\n",
///     "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
///     "  key: tests/data/certs/server/private/test_server_key.pem\n",
///     "  tcp:\n",
///     "    addr: ::0\n",
///     "    port: 8001\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let acceptor: CompoundNearAcceptor<TLSServerConfig> =
///     CompoundNearAcceptor::create(&mut nscaches, accept_config).unwrap();
/// ```
///
/// ## Accepting Connections
///
/// Once a `CompoundNearAcceptor` has been created, connections can be
/// accepted using the [take_connection](NearChannel::take_connection)
/// function.
pub enum CompoundNearAcceptor<TLS: Clone + Debug + TLSLoadServer> {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixNearAcceptor
    },
    TCP {
        tcp: TCPNearAcceptor
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: TLSNearAcceptor<Box<CompoundNearAcceptor<TLS>>, TLS>
    }
}

/// Versatile client-side near-link channel.
///
/// This is a [NearChannel] instance that can support arbitrarily
/// complex nested channel configurations consisting of SOCKS5 and TLS
/// layers, with either TCP or Unix domain sockets serving as the base
/// connections.
///
/// See [CompoundNearConnectorConfig] for example configuratons.
///
/// # Usage
///
/// The primary use of a `CompoundNearConnector` takes place through its
/// [NearChannel] and [NearConnector] instances.
///
/// ## Configuration and Creation
///
/// A `CompoundNearConnector` is created using the
/// [new](NearChannelCreate::new) function from its [NearChannel] instance.
/// This function takes a [CompoundNearConnectorConfig] as its
/// principal argument, which supplies all configuration unformation.
///
/// ### Example
///
/// The following example shows how to create a `CompoundNearConnector`:
///
/// ```
/// # use constellation_channels::config::tls::TLSClientConfig;
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::compound::CompoundResolvingNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "tls:\n",
///     "  trust-root:\n",
///     "    root-certs:\n",
///     "      - tests/data/certs/server/ca_cert.pem\n",
///     "  tcp:\n",
///     "    addr: en.wikipedia.org\n",
///     "    port: 443\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector: CompoundResolvingNearConnector<TLSClientConfig> =
///     CompoundResolvingNearConnector::create(&mut nscaches, accept_config)
///     .unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `CompoundNearConnector` has been created, connections can be
/// established using the
/// [take_connection](NearChannel::take_connection) or
/// [connection](NearConnector::connection) functions.  These will
/// block until a connection has been successfully established.  Note
/// that depending on the circumstances, this may involve many retries
/// and/or name resolutions.
///
/// Any session negotiations will occur transparently, and the
/// `CompoundNearConnector` will also automatically retry if it fails.
/// Errors occurring during connection will be logged, but will not
/// cause [take_connection](NearChannel::take_connection) or
/// [connection](NearConnector::connection) to fail.
#[allow(clippy::large_enum_variant)]
pub enum CompoundNearConnector<TLS: Clone + Debug + TLSLoadClient> {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixNearConnector
    },
    TCP {
        tcp: TCPNearConnector
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: TLSNearConnector<Box<CompoundNearConnector<TLS>>, TLS>
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: SOCKS5NearConnector<Box<CompoundResolvingNearConnector<TLS>>>
    }
}

#[allow(clippy::large_enum_variant)]
pub enum CompoundResolvingNearConnector<TLS: Clone + Debug + TLSLoadClient> {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixNearConnector
    },
    TCP {
        tcp: TCPResolvingNearConnector
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: TLSNearConnector<Box<CompoundResolvingNearConnector<TLS>>, TLS>
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: SOCKS5NearConnector<Box<CompoundResolvingNearConnector<TLS>>>
    }
}

/// [Negotiator] instance for shutting down sessions for
/// [CompoundFarChannel]s.
pub enum CompoundNearAcceptorShutdownNegotiator {
    #[cfg(feature = "unix")]
    Unix {
        unix: PassthruNegotiator
    },
    TCP {
        tcp: PassthruNegotiator
    },
    TLS {
        tls: Box<
            TLSShutdownNegotiator<
                CompoundNearServerConn,
                CompoundNearAcceptorShutdownNegotiator,
                CompoundNearAcceptorShutdownValue
            >
        >
    }
}

pub enum CompoundNearConnectorShutdownNegotiator {
    #[cfg(feature = "unix")]
    Unix {
        unix: PassthruNegotiator
    },
    TCP {
        tcp: PassthruNegotiator
    },
    TLS {
        tls: Box<
            TLSShutdownNegotiator<
                CompoundNearClientConn,
                CompoundNearConnectorShutdownNegotiator,
                CompoundNearConnectorShutdownValue
            >
        >
    },
    SOCKS5 {
        socks5: Box<
            SOCKS5ShutdownNegotiator<CompoundNearConnectorShutdownNegotiator>
        >
    }
}

pub enum CompoundNearShutdownNegotiatorState<Stream>
where
    Stream: Session {
    #[cfg(feature = "unix")]
    Unix {
        unix: PassthruSessionNegotiation<
            <UnixNearConnector as NearChannel>::Conn
        >
    },
    TCP {
        tcp:
            PassthruSessionNegotiation<<TCPNearConnector as NearChannel>::Conn>
    },
    TLS {
        tls: Box<
            TLSShutdownNegotiatorState<
                Stream,
                CompoundNearShutdownNegotiatorState<Stream>
            >
        >
    }
}

pub enum CompoundNearShutdownNegotiatorPending<Stream>
where
    Stream: Session {
    TLS {
        tls: Box<
            TLSShutdownNegoPending<
                Stream,
                CompoundNearShutdownNegotiatorPending<Stream>
            >
        >
    }
}

#[derive(Debug)]
pub enum CompoundShutdownError {
    TLS {
        tls: Box<TLSShutdownError<CompoundShutdownError>>
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundNegotiatorStartError {
    TLS {
        tls: Box<
            TLSStartError<CompoundNegotiatorStartError, TLSLoadConfigError>
        >
    },
    Mismatch
}

impl<'a> TryFrom<CompoundNearNameAddrRef<'a>> for CompoundNearNameAddr {
    type Error = Error;

    #[inline]
    fn try_from(
        val: CompoundNearNameAddrRef<'a>
    ) -> Result<CompoundNearNameAddr, Error> {
        match val {
            CompoundNearNameAddrRef::Unix { unix } => {
                Ok(CompoundNearNameAddr::Unix {
                    unix: unix.try_into()?
                })
            }
            CompoundNearNameAddrRef::TCP { tcp } => {
                Ok(CompoundNearNameAddr::TCP { tcp: tcp.clone() })
            }
            CompoundNearNameAddrRef::SOCKS5 { socks5 } => {
                Ok(CompoundNearNameAddr::SOCKS5 {
                    socks5: socks5.clone()
                })
            }
        }
    }
}

impl ScopedError for CompoundShutdownError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "tls")]
            CompoundShutdownError::TLS { tls } => tls.scope(),
            CompoundShutdownError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundNearAcceptorCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorCreateError::Unix { unix } => unix.scope(),
            CompoundNearAcceptorCreateError::TCP { tcp } => tcp.scope(),
            #[cfg(feature = "tls")]
            CompoundNearAcceptorCreateError::TLS { tls } => tls.scope()
        }
    }
}

impl ScopedError for CompoundNearConnectorCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorCreateError::Unix { unix } => unix.scope(),
            CompoundNearConnectorCreateError::TCP { tcp } => tcp.scope(),
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateError::TLS { tls } => tls.scope()
        }
    }
}

impl ScopedError for CompoundNearConnectorCreateWithEndpointError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundNearConnectorCreateWithEndpointError::Unix { unix } => {
                unix.scope()
            }
            CompoundNearConnectorCreateWithEndpointError::TCP { tcp } => {
                tcp.scope()
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateWithEndpointError::TLS { tls } => {
                tls.scope()
            }
            CompoundNearConnectorCreateWithEndpointError::SOCKS5 { socks5 } => {
                socks5.scope()
            }
            CompoundNearConnectorCreateWithEndpointError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundResolvingNearConnectorCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundResolvingNearConnectorCreateError::Unix { unix } => {
                unix.scope()
            }
            #[cfg(feature = "tls")]
            CompoundResolvingNearConnectorCreateError::TLS { tls } => {
                tls.scope()
            }
        }
    }
}

impl ScopedError for CompoundResolvingNearConnectorCreateWithEndpointError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundResolvingNearConnectorCreateWithEndpointError::Unix {
                unix
            } => unix.scope(),
            #[cfg(feature = "tls")]
            CompoundResolvingNearConnectorCreateWithEndpointError::TLS {
                tls
            } => tls.scope(),
            CompoundResolvingNearConnectorCreateWithEndpointError::SOCKS5 {
                socks5
            } => socks5.scope(),
            CompoundResolvingNearConnectorCreateWithEndpointError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundNearAcceptorNegotiateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "tls")]
            CompoundNearAcceptorNegotiateError::TLS { tls } => tls.scope(),
            CompoundNearAcceptorNegotiateError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundNearConnectorNegotiateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "tls")]
            CompoundNearConnectorNegotiateError::TLS { tls } => tls.scope(),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorNegotiateError::SOCKS5 { socks5 } => {
                socks5.scope()
            }
            CompoundNearConnectorNegotiateError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundNearCredentialError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearCredentialError::Unix { err } => err.scope(),
            CompoundNearCredentialError::TCP { err } => err.scope()
        }
    }
}

impl ScopedError for CompoundNearAcceptorStartError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorStartError::Unix { err } => err.scope(),
            CompoundNearAcceptorStartError::TCP { err } => err.scope()
        }
    }
}

impl ScopedError for CompoundNearConnectorStartError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorStartError::Unix { err } => err.scope(),
            CompoundNearConnectorStartError::TCP { err } => err.scope()
        }
    }
}

impl ScopedError for CompoundNegotiatorStartError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundNegotiatorStartError::TLS { tls } => tls.scope(),
            CompoundNegotiatorStartError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for Box<CompoundNegotiatorStartError> {
    #[inline]
    fn scope(&self) -> ErrorScope {
        self.as_ref().scope()
    }
}

impl Display for CompoundNegotiatorStartError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundNegotiatorStartError::TLS { tls } => write!(f, "{}", tls),
            CompoundNegotiatorStartError::Mismatch => {
                write!(f, "negotiator and param type mismatch")
            }
        }
    }
}

impl Display for CompoundShutdownError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundShutdownError::TLS { tls } => write!(f, "{}", tls),
            CompoundShutdownError::Mismatch => {
                write!(f, "negotiator and state type mismatch")
            }
        }
    }
}

impl Display for CompoundNearCredentialError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearCredentialError::Unix { err } => {
                write!(f, "{}", err)
            }
            CompoundNearCredentialError::TCP { err } => {
                write!(f, "{}", err)
            }
        }
    }
}

impl Display for CompoundNearAcceptorStartError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorStartError::Unix { err } => {
                write!(f, "{}", err)
            }
            CompoundNearAcceptorStartError::TCP { err } => {
                write!(f, "{}", err)
            }
        }
    }
}

impl Display for CompoundNearConnectorStartError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorStartError::Unix { err } => {
                write!(f, "{}", err)
            }
            CompoundNearConnectorStartError::TCP { err } => {
                write!(f, "{}", err)
            }
        }
    }
}

impl Display for CompoundNearAcceptorCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorCreateError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundNearAcceptorCreateError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearAcceptorCreateError::TLS { tls } => write!(f, "{}", tls)
        }
    }
}

impl Display for CompoundNearConnectorCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorCreateError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundNearConnectorCreateError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateError::TLS { tls } => {
                write!(f, "{}", tls)
            }
        }
    }
}

impl Display for CompoundNearConnectorCreateWithEndpointError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorCreateWithEndpointError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundNearConnectorCreateWithEndpointError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateWithEndpointError::TLS { tls } => {
                write!(f, "{}", tls)
            }
            #[cfg(feature = "socks5")]
            CompoundNearConnectorCreateWithEndpointError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundNearConnectorCreateWithEndpointError::Mismatch => {
                write!(f, "type mismatch")
            }
        }
    }
}

impl Display for CompoundResolvingNearConnectorCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundResolvingNearConnectorCreateError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            #[cfg(feature = "tls")]
            CompoundResolvingNearConnectorCreateError::TLS { tls } => {
                write!(f, "{}", tls)
            }
        }
    }
}

impl Display for CompoundResolvingNearConnectorCreateWithEndpointError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundResolvingNearConnectorCreateWithEndpointError::Unix {
                unix
            } => write!(f, "{}", unix),
            #[cfg(feature = "tls")]
            CompoundResolvingNearConnectorCreateWithEndpointError::TLS {
                tls
            } => write!(f, "{}", tls),
            #[cfg(feature = "socks5")]
            CompoundResolvingNearConnectorCreateWithEndpointError::SOCKS5 {
                socks5
            } => write!(f, "{}", socks5),
            CompoundResolvingNearConnectorCreateWithEndpointError::Mismatch => {
                write!(f, "type mismatch")
            }
        }
    }
}

impl Display for CompoundNearAcceptorNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "tls")]
            CompoundNearAcceptorNegotiateError::TLS { tls } => {
                write!(f, "{}", tls)
            }
            CompoundNearAcceptorNegotiateError::Mismatch => {
                write!(f, "mismatch")
            }
        }
    }
}

impl Display for CompoundNearConnectorNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "tls")]
            CompoundNearConnectorNegotiateError::TLS { tls } => {
                write!(f, "{}", tls)
            }
            #[cfg(feature = "socks5")]
            CompoundNearConnectorNegotiateError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundNearConnectorNegotiateError::Mismatch => {
                write!(f, "mismatch")
            }
        }
    }
}

impl Display for CompoundNearConcreteAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConcreteAddr::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearConcreteAddr::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
        }
    }
}

impl Display for CompoundNearNameAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearNameAddr::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearNameAddr::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
            #[cfg(feature = "socks5")]
            CompoundNearNameAddr::SOCKS5 { socks5 } => write!(f, "{}", socks5)
        }
    }
}

impl Display for CompoundNearNameAddrRef<'_> {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearNameAddrRef::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearNameAddrRef::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
            #[cfg(feature = "socks5")]
            CompoundNearNameAddrRef::SOCKS5 { socks5 } => {
                write!(f, "socks5://{}", socks5)
            }
        }
    }
}

impl Display for CompoundResolvingNearConnectorEndpointRef<'_> {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundResolvingNearConnectorEndpointRef::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundResolvingNearConnectorEndpointRef::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
            #[cfg(feature = "socks5")]
            CompoundResolvingNearConnectorEndpointRef::SOCKS5 { socks5 } => {
                write!(f, "socks5://{}", socks5)
            }
        }
    }
}

impl Session for CompoundNearClientConn {
    type LocalAddr = CompoundNearConcreteAddr;
    type PeerAddr = CompoundNearNameAddr;

    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                unix.local_addr()
                    .map(|addr| CompoundNearConcreteAddr::Unix {
                        unix: UnixSocketAddr::from(addr)
                    })
            }
            CompoundNearClientConn::TCP { tcp } => tcp
                .local_addr()
                .map(|addr| CompoundNearConcreteAddr::TCP { tcp: addr }),
            #[cfg(feature = "tls")]
            CompoundNearClientConn::TLS { tls } => tls.local_addr(),
            #[cfg(feature = "socks5")]
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.local_addr()
        }
    }

    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                unix.peer_addr().map(|addr| CompoundNearNameAddr::Unix {
                    unix: UnixSocketAddr::from(addr)
                })
            }
            CompoundNearClientConn::TCP { tcp } => tcp
                .peer_addr()
                .map(|addr| CompoundNearNameAddr::TCP { tcp: addr }),
            #[cfg(feature = "tls")]
            CompoundNearClientConn::TLS { tls } => tls.peer_addr(),
            #[cfg(feature = "socks5")]
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5
                .peer_addr()
                .map(|addr| CompoundNearNameAddr::SOCKS5 { socks5: addr })
        }
    }
}

impl Session for CompoundNearServerConn {
    type LocalAddr = CompoundNearConcreteAddr;
    type PeerAddr = CompoundNearConcreteAddr;

    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => {
                unix.local_addr()
                    .map(|addr| CompoundNearConcreteAddr::Unix {
                        unix: UnixSocketAddr::from(addr)
                    })
            }
            CompoundNearServerConn::TCP { tcp } => tcp
                .local_addr()
                .map(|addr| CompoundNearConcreteAddr::TCP { tcp: addr }),
            #[cfg(feature = "tls")]
            CompoundNearServerConn::TLS { tls } => tls.local_addr()
        }
    }

    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => {
                unix.peer_addr().map(|addr| CompoundNearConcreteAddr::Unix {
                    unix: UnixSocketAddr::from(addr)
                })
            }
            CompoundNearServerConn::TCP { tcp } => tcp
                .peer_addr()
                .map(|addr| CompoundNearConcreteAddr::TCP { tcp: addr }),
            #[cfg(feature = "tls")]
            CompoundNearServerConn::TLS { tls } => tls.peer_addr()
        }
    }
}

impl Credentials for CompoundNearClientConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &self
    ) -> Result<Option<CompoundNearCredential>, CompoundNearCredentialError>
    {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                let cred = unix.creds().map_err(|err| {
                    CompoundNearCredentialError::Unix { err: err }
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::Unix { unix: cred }))
            }
            CompoundNearClientConn::TCP { tcp } => {
                let cred = tcp.creds().map_err(|err| {
                    CompoundNearCredentialError::Unix { err: err }
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::UnsafeTCP {
                    unsafe_tcp: cred
                }))
            }
            CompoundNearClientConn::TLS { tls } => {
                let cred = tls.creds()?;

                Ok(cred.map(|cred| CompoundNearCredential::TLS {
                    tls: Box::new(cred)
                }))
            }
            _ => Ok(None)
        }
    }
}

impl CredentialsMut for CompoundNearClientConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &mut self
    ) -> Result<Option<CompoundNearCredential>, CompoundNearCredentialError>
    {
        <Self as Credentials>::creds(self)
    }
}

impl Credentials for CompoundNearServerConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &self
    ) -> Result<Option<CompoundNearCredential>, CompoundNearCredentialError>
    {
        match self {
            CompoundNearServerConn::Unix { unix } => {
                let cred = unix.creds().map_err(|err| {
                    CompoundNearCredentialError::Unix { err: err }
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::Unix { unix: cred }))
            }
            CompoundNearServerConn::TLS { tls } => {
                let cred = tls.creds()?;

                Ok(cred.map(|cred| CompoundNearCredential::TLS {
                    tls: Box::new(cred)
                }))
            }
            _ => Ok(None)
        }
    }
}

impl CredentialsMut for CompoundNearServerConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &mut self
    ) -> Result<Option<CompoundNearCredential>, CompoundNearCredentialError>
    {
        <Self as Credentials>::creds(self)
    }
}

impl Read for CompoundNearClientConn {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.read(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.read(buf),
            CompoundNearClientConn::TLS { tls } => tls.read(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.read_vectored(bufs),
            CompoundNearClientConn::TCP { tcp } => tcp.read_vectored(bufs),
            CompoundNearClientConn::TLS { tls } => tls.read_vectored(bufs),
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.read_vectored(bufs)
            }
        }
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.read_to_end(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.read_to_end(buf),
            CompoundNearClientConn::TLS { tls } => tls.read_to_end(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.read_to_end(buf)
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.read_to_string(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.read_to_string(buf),
            CompoundNearClientConn::TLS { tls } => tls.read_to_string(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.read_to_string(buf)
            }
        }
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.read_exact(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.read_exact(buf),
            CompoundNearClientConn::TLS { tls } => tls.read_exact(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.read_exact(buf)
        }
    }
}

impl Read for CompoundNearServerConn {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.read(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.read(buf),
            CompoundNearServerConn::TLS { tls } => tls.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.read_vectored(bufs),
            CompoundNearServerConn::TCP { tcp } => tcp.read_vectored(bufs),
            CompoundNearServerConn::TLS { tls } => tls.read_vectored(bufs)
        }
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.read_to_end(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.read_to_end(buf),
            CompoundNearServerConn::TLS { tls } => tls.read_to_end(buf)
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.read_to_string(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.read_to_string(buf),
            CompoundNearServerConn::TLS { tls } => tls.read_to_string(buf)
        }
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.read_exact(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.read_exact(buf),
            CompoundNearServerConn::TLS { tls } => tls.read_exact(buf)
        }
    }
}

impl Write for CompoundNearClientConn {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.write(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.write(buf),
            CompoundNearClientConn::TLS { tls } => tls.write(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.write_vectored(bufs),
            CompoundNearClientConn::TCP { tcp } => tcp.write_vectored(bufs),
            CompoundNearClientConn::TLS { tls } => tls.write_vectored(bufs),
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.write_vectored(bufs)
            }
        }
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.write_all(buf),
            CompoundNearClientConn::TCP { tcp } => tcp.write_all(buf),
            CompoundNearClientConn::TLS { tls } => tls.write_all(buf),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.write_all(buf)
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.flush(),
            CompoundNearClientConn::TCP { tcp } => tcp.flush(),
            CompoundNearClientConn::TLS { tls } => tls.flush(),
            CompoundNearClientConn::SOCKS5 { socks5 } => socks5.flush()
        }
    }
}

impl Write for CompoundNearServerConn {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.write(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.write(buf),
            CompoundNearServerConn::TLS { tls } => tls.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.write_vectored(bufs),
            CompoundNearServerConn::TCP { tcp } => tcp.write_vectored(bufs),
            CompoundNearServerConn::TLS { tls } => tls.write_vectored(bufs)
        }
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.write_all(buf),
            CompoundNearServerConn::TCP { tcp } => tcp.write_all(buf),
            CompoundNearServerConn::TLS { tls } => tls.write_all(buf)
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.flush(),
            CompoundNearServerConn::TCP { tcp } => tcp.flush(),
            CompoundNearServerConn::TLS { tls } => tls.flush()
        }
    }
}

impl ChannelParam<CompoundNearConcreteAddr> for CompoundNearConcreteAddr {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearConcreteAddr
    ) -> bool {
        matches!(
            (self, addr),
            (
                CompoundNearConcreteAddr::Unix { .. },
                CompoundNearConcreteAddr::Unix { .. }
            ) | (
                CompoundNearConcreteAddr::TCP { .. },
                CompoundNearConcreteAddr::TCP { .. }
            )
        )
    }
}

impl ChannelParam<SocketAddr> for CompoundNearConcreteAddr {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &SocketAddr
    ) -> bool {
        matches!(self, CompoundNearConcreteAddr::TCP { .. })
    }
}

impl ChannelParam<CompoundNearConcreteAddr> for SocketAddr {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearConcreteAddr
    ) -> bool {
        matches!(addr, CompoundNearConcreteAddr::TCP { .. })
    }
}

impl ChannelParam<UnixSocketAddr> for CompoundNearConcreteAddr {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &UnixSocketAddr
    ) -> bool {
        matches!(self, CompoundNearConcreteAddr::Unix { .. })
    }
}

impl ChannelParam<CompoundNearConcreteAddr> for UnixSocketAddr {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearConcreteAddr
    ) -> bool {
        matches!(addr, CompoundNearConcreteAddr::Unix { .. })
    }
}

impl Source for CompoundNearClientConn {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                unix.register(registry, token, interests)
            }
            CompoundNearClientConn::TCP { tcp } => {
                tcp.register(registry, token, interests)
            }
            CompoundNearClientConn::TLS { tls } => {
                tls.register(registry, token, interests)
            }
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.register(registry, token, interests)
            }
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                unix.reregister(registry, token, interests)
            }
            CompoundNearClientConn::TCP { tcp } => {
                tcp.reregister(registry, token, interests)
            }
            CompoundNearClientConn::TLS { tls } => {
                tls.reregister(registry, token, interests)
            }
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.reregister(registry, token, interests)
            }
        }
    }

    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearClientConn::Unix { unix } => unix.deregister(registry),
            CompoundNearClientConn::TCP { tcp } => tcp.deregister(registry),
            CompoundNearClientConn::TLS { tls } => tls.deregister(registry),
            CompoundNearClientConn::SOCKS5 { socks5 } => {
                socks5.deregister(registry)
            }
        }
    }
}

impl Source for CompoundNearServerConn {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => {
                unix.register(registry, token, interests)
            }
            CompoundNearServerConn::TCP { tcp } => {
                tcp.register(registry, token, interests)
            }
            CompoundNearServerConn::TLS { tls } => {
                tls.register(registry, token, interests)
            }
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => {
                unix.reregister(registry, token, interests)
            }
            CompoundNearServerConn::TCP { tcp } => {
                tcp.reregister(registry, token, interests)
            }
            CompoundNearServerConn::TLS { tls } => {
                tls.reregister(registry, token, interests)
            }
        }
    }

    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearServerConn::Unix { unix } => unix.deregister(registry),
            CompoundNearServerConn::TCP { tcp } => tcp.deregister(registry),
            CompoundNearServerConn::TLS { tls } => tls.deregister(registry)
        }
    }
}

impl Source for CompoundNearAcceptorShutdownValue {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptorShutdownValue::Unix { unix } => {
                unix.register(registry, token, interests)
            }
            CompoundNearAcceptorShutdownValue::TCP { tcp } => {
                tcp.register(registry, token, interests)
            }
            CompoundNearAcceptorShutdownValue::TLS { tls } => {
                tls.as_mut().register(registry, token, interests)
            }
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptorShutdownValue::Unix { unix } => {
                unix.reregister(registry, token, interests)
            }
            CompoundNearAcceptorShutdownValue::TCP { tcp } => {
                tcp.reregister(registry, token, interests)
            }
            CompoundNearAcceptorShutdownValue::TLS { tls } => {
                tls.as_mut().reregister(registry, token, interests)
            }
        }
    }

    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptorShutdownValue::Unix { unix } => {
                unix.deregister(registry)
            }
            CompoundNearAcceptorShutdownValue::TCP { tcp } => {
                tcp.deregister(registry)
            }
            CompoundNearAcceptorShutdownValue::TLS { tls } => {
                tls.as_mut().deregister(registry)
            }
        }
    }
}

impl Source for CompoundNearConnectorShutdownValue {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearConnectorShutdownValue::Unix { unix } => {
                unix.register(registry, token, interests)
            }
            CompoundNearConnectorShutdownValue::TCP { tcp } => {
                tcp.register(registry, token, interests)
            }
            CompoundNearConnectorShutdownValue::TLS { tls } => {
                tls.as_mut().register(registry, token, interests)
            }
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearConnectorShutdownValue::Unix { unix } => {
                unix.reregister(registry, token, interests)
            }
            CompoundNearConnectorShutdownValue::TCP { tcp } => {
                tcp.reregister(registry, token, interests)
            }
            CompoundNearConnectorShutdownValue::TLS { tls } => {
                tls.as_mut().reregister(registry, token, interests)
            }
        }
    }

    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearConnectorShutdownValue::Unix { unix } => {
                unix.deregister(registry)
            }
            CompoundNearConnectorShutdownValue::TCP { tcp } => {
                tcp.deregister(registry)
            }
            CompoundNearConnectorShutdownValue::TLS { tls } => {
                tls.as_mut().deregister(registry)
            }
        }
    }
}

impl<TLS> Source for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptor::Unix { unix } => {
                unix.register(registry, token, interests)
            }
            CompoundNearAcceptor::TCP { tcp } => {
                tcp.register(registry, token, interests)
            }
            CompoundNearAcceptor::TLS { tls } => {
                tls.register(registry, token, interests)
            }
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptor::Unix { unix } => {
                unix.reregister(registry, token, interests)
            }
            CompoundNearAcceptor::TCP { tcp } => {
                tcp.reregister(registry, token, interests)
            }
            CompoundNearAcceptor::TLS { tls } => {
                tls.reregister(registry, token, interests)
            }
        }
    }

    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self {
            CompoundNearAcceptor::Unix { unix } => unix.deregister(registry),
            CompoundNearAcceptor::TCP { tcp } => tcp.deregister(registry),
            CompoundNearAcceptor::TLS { tls } => tls.deregister(registry)
        }
    }
}

impl<TLS> Negotiator<(CompoundNearServerConn, CompoundNearConcreteAddr)>
    for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type NegotiateError = CompoundNearAcceptorNegotiateError;
    type Pending = CompoundNearAcceptorNegotiatePending;
    type State = CompoundNearAcceptorState;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearServerConn, CompoundNearConcreteAddr),
            CompoundNearAcceptorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, state) {
            (
                CompoundNearAcceptor::Unix { unix },
                CompoundNearAcceptorState::Unix { unix: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    unix.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearServerConn::Unix { unix: conn },
                    CompoundNearConcreteAddr::Unix { unix: endpoint }
                ));

                Ok(res)
            }
            (
                CompoundNearAcceptor::TCP { tcp },
                CompoundNearAcceptorState::TCP { tcp: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    tcp.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearServerConn::TCP { tcp: conn },
                    CompoundNearConcreteAddr::TCP { tcp: endpoint }
                ));

                Ok(res)
            }
            (CompoundNearAcceptor::TLS { tls }, state) => Ok(tls
                .negotiate(state)
                .map_err(|err| CompoundNearAcceptorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearAcceptorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearServerConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            _ => Err(CompoundNearAcceptorNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearAcceptorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearServerConn, CompoundNearConcreteAddr),
            CompoundNearAcceptorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, pending) {
            (
                CompoundNearAcceptor::TLS { tls },
                CompoundNearAcceptorNegotiatePending::TLS { tls: pending }
            ) => Ok(tls
                .complete_negotiate(*pending)
                .map_err(|err| CompoundNearAcceptorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearAcceptorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearServerConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            _ => Err(CompoundNearAcceptorNegotiateError::Mismatch)
        }
    }
}

impl<TLS> NearChannel for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Conn = CompoundNearServerConn;
    type Endpoint = CompoundNearConcreteAddr;
    type ShutdownNego = CompoundNearAcceptorShutdownNegotiator;
    type ShutdownValue = CompoundNearAcceptorShutdownValue;
    type StartError = CompoundNearAcceptorStartError;

    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        match self {
            CompoundNearAcceptor::Unix { unix } => {
                let out = unix
                    .start(registry, token)
                    .map_err(|err| CompoundNearAcceptorStartError::Unix {
                        err: err
                    })?
                    .map(|unix| CompoundNearAcceptorState::Unix { unix: unix });

                Ok(out)
            }
            CompoundNearAcceptor::TCP { tcp } => {
                let out = tcp
                    .start(registry, token)
                    .map_err(|err| CompoundNearAcceptorStartError::TCP {
                        err: err
                    })?
                    .map(|tcp| CompoundNearAcceptorState::TCP { tcp: tcp });

                Ok(out)
            }
            CompoundNearAcceptor::TLS { tls } => tls.start(registry, token)
        }
    }

    fn shutdown_nego(&self) -> Self::ShutdownNego {
        match self {
            CompoundNearAcceptor::Unix { .. } => {
                CompoundNearAcceptorShutdownNegotiator::Unix {
                    unix: PassthruNegotiator
                }
            }
            CompoundNearAcceptor::TCP { .. } => {
                CompoundNearAcceptorShutdownNegotiator::TCP {
                    tcp: PassthruNegotiator
                }
            }
            CompoundNearAcceptor::TLS { tls } => {
                let nego = tls.shutdown_nego();

                CompoundNearAcceptorShutdownNegotiator::TLS {
                    tls: Box::new(nego)
                }
            }
        }
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        pending: CompoundNearAcceptorNegotiateError
    ) -> Result<(), Error> {
        match (self, pending) {
            (
                CompoundNearAcceptor::TLS { tls },
                CompoundNearAcceptorNegotiateError::TLS { tls: err }
            ) => tls.cleanup(registry, *err),
            _ => Err(Error::new(ErrorKind::Other, "mismatch in cleanup"))
        }
    }
}

impl<TLS> NearChannelCreate for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = CompoundNearAcceptorConfig<TLS>;
    type CreateError = CompoundNearAcceptorCreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: CompoundNearAcceptorConfig<TLS>
    ) -> Result<Self, CompoundNearAcceptorCreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundNearAcceptorConfig::Unix { unix_stream } => {
                let acc = UnixNearAcceptor::create(caches, unix_stream)
                    .map_err(|err| CompoundNearAcceptorCreateError::Unix {
                        unix: err
                    })?;

                Ok(CompoundNearAcceptor::Unix { unix: acc })
            }
            CompoundNearAcceptorConfig::TCP { tcp } => {
                let acc =
                    TCPNearAcceptor::create(caches, tcp).map_err(|err| {
                        CompoundNearAcceptorCreateError::TCP { tcp: err }
                    })?;

                Ok(CompoundNearAcceptor::TCP { tcp: acc })
            }
            CompoundNearAcceptorConfig::TLS { tls } => {
                let acc =
                    TLSNearAcceptor::create(caches, tls).map_err(|err| {
                        CompoundNearAcceptorCreateError::TLS {
                            tls: Box::new(err)
                        }
                    })?;

                Ok(CompoundNearAcceptor::TLS { tls: acc })
            }
        }
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        match conf {
            CompoundNearAcceptorConfig::Unix { unix_stream } => {
                UnixNearAcceptor::verify_endpoint(unix_stream)
            }
            CompoundNearAcceptorConfig::TCP { tcp } => {
                TCPNearAcceptor::verify_endpoint(tcp)
            }
            CompoundNearAcceptorConfig::TLS { tls } => {
                TLSNearAcceptor::<Box<Self>, TLS>::verify_endpoint(tls)
            }
        }
    }
}

impl<TLS> Negotiator<(CompoundNearServerConn, CompoundNearConcreteAddr)>
    for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type NegotiateError = CompoundNearAcceptorNegotiateError;
    type Pending = CompoundNearAcceptorNegotiatePending;
    type State = CompoundNearAcceptorState;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearServerConn, CompoundNearConcreteAddr),
            CompoundNearAcceptorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: CompoundNearAcceptorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearServerConn, CompoundNearConcreteAddr),
            CompoundNearAcceptorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(err)
    }
}

impl<TLS> NearChannel for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Conn = CompoundNearServerConn;
    type Endpoint = CompoundNearConcreteAddr;
    type ShutdownNego = CompoundNearAcceptorShutdownNegotiator;
    type ShutdownValue = CompoundNearAcceptorShutdownValue;
    type StartError = CompoundNearAcceptorStartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.as_mut().start(registry, token)
    }

    #[inline]
    fn shutdown_nego(&self) -> Self::ShutdownNego {
        self.as_ref().shutdown_nego()
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    #[inline]
    fn cleanup(
        &mut self,
        registry: &Registry,
        err: CompoundNearAcceptorNegotiateError
    ) -> Result<(), Error> {
        self.as_mut().cleanup(registry, err)
    }
}

impl<TLS> NearChannelCreate for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = Box<CompoundNearAcceptorConfig<TLS>>;
    type CreateError = CompoundNearAcceptorCreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundNearAcceptorConfig<TLS>>
    ) -> Result<Self, CompoundNearAcceptorCreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundNearAcceptor::create(caches, config.as_ref().clone())
            .map(Box::new)
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        CompoundNearAcceptor::verify_endpoint(conf.as_ref())
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearNameAddr)>
    for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type NegotiateError = CompoundNearConnectorNegotiateError;
    type Pending = CompoundNearConnectorNegotiatePending;
    type State = CompoundNearConnectorState;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, state) {
            (
                CompoundNearConnector::Unix { unix },
                CompoundNearConnectorState::Unix { unix: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    unix.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearClientConn::Unix { unix: conn },
                    CompoundNearNameAddr::Unix { unix: endpoint }
                ));

                Ok(res)
            }
            (
                CompoundNearConnector::TCP { tcp },
                CompoundNearConnectorState::TCP { tcp: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    tcp.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearClientConn::TCP { tcp: conn },
                    CompoundNearNameAddr::TCP { tcp: endpoint }
                ));

                Ok(res)
            }
            (
                CompoundNearConnector::SOCKS5 { socks5 },
                CompoundNearConnectorState::SOCKS5 { socks5: state }
            ) => Ok(socks5
                .negotiate(*state)
                .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                    socks5: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::SOCKS5 {
                        socks5: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::SOCKS5 {
                            socks5: Box::new(conn)
                        },
                        CompoundNearNameAddr::SOCKS5 { socks5: endpoint }
                    )
                })),
            (CompoundNearConnector::TLS { tls }, state) => Ok(tls
                .negotiate(state)
                .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, pending) {
            (
                CompoundNearConnector::TLS { tls },
                CompoundNearConnectorNegotiatePending::TLS { tls: pending }
            ) => Ok(tls
                .complete_negotiate(*pending)
                .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            (
                CompoundNearConnector::SOCKS5 { socks5 },
                CompoundNearConnectorNegotiatePending::SOCKS5 {
                    socks5: pending
                }
            ) => Ok(socks5
                .complete_negotiate(*pending)
                .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                    socks5: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::SOCKS5 {
                        socks5: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::SOCKS5 {
                            socks5: Box::new(conn)
                        },
                        CompoundNearNameAddr::SOCKS5 { socks5: endpoint }
                    )
                })),
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
        }
    }
}

impl<TLS> NearChannel for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
    type Endpoint = CompoundNearNameAddr;
    type ShutdownNego = CompoundNearConnectorShutdownNegotiator;
    type ShutdownValue = CompoundNearConnectorShutdownValue;
    type StartError = CompoundNearConnectorStartError;

    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        match self {
            CompoundNearConnector::Unix { unix } => {
                let out = unix
                    .start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::Unix {
                        err: err
                    })?
                    .map(|unix| CompoundNearConnectorState::Unix {
                        unix: unix
                    });

                Ok(out)
            }
            CompoundNearConnector::TCP { tcp } => {
                let out = tcp
                    .start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::TCP {
                        err: err
                    })?
                    .map(|tcp| CompoundNearConnectorState::TCP { tcp: tcp });

                Ok(out)
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                let out = socks5.start(registry, token)?.map(|socks5| {
                    CompoundNearConnectorState::SOCKS5 {
                        socks5: Box::new(socks5)
                    }
                });

                Ok(out)
            }
            CompoundNearConnector::TLS { tls } => tls.start(registry, token)
        }
    }

    fn shutdown_nego(&self) -> Self::ShutdownNego {
        match self {
            CompoundNearConnector::Unix { .. } => {
                CompoundNearConnectorShutdownNegotiator::Unix {
                    unix: PassthruNegotiator
                }
            }
            CompoundNearConnector::TCP { .. } => {
                CompoundNearConnectorShutdownNegotiator::TCP {
                    tcp: PassthruNegotiator
                }
            }
            CompoundNearConnector::TLS { tls } => {
                let nego = tls.shutdown_nego();

                CompoundNearConnectorShutdownNegotiator::TLS {
                    tls: Box::new(nego)
                }
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                let nego = socks5.shutdown_nego();

                CompoundNearConnectorShutdownNegotiator::SOCKS5 {
                    socks5: Box::new(nego)
                }
            }
        }
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        pending: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        match (self, pending) {
            (
                CompoundNearConnector::TLS { tls },
                CompoundNearConnectorNegotiateError::TLS { tls: err }
            ) => tls.cleanup(registry, *err),
            _ => Err(Error::new(ErrorKind::Other, "mismatch in cleanup"))
        }
    }
}

impl<TLS> NearChannelCreateWithEndpoint for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = CompoundNearConnectorPartialConfig<TLS>;
    type CreateError = CompoundNearConnectorCreateWithEndpointError;
    type EndpointConfig = CompoundNearNameAddr;
    type Param = Option<CompoundNearConnectorParam>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: CompoundNearConnectorPartialConfig<TLS>,
        endpoint: CompoundNearNameAddr,
        param: Option<CompoundNearConnectorParam>
    ) -> Result<Self, CompoundNearConnectorCreateWithEndpointError>
    where
        Ctx: NSNameCachesCtx {
        match (config, endpoint, param) {
            (
                CompoundNearConnectorPartialConfig::Unix { unix_stream },
                CompoundNearNameAddr::Unix { unix: endpoint },
                None
            ) => {
                let unix = UnixNearConnector::create_with_endpoint(
                    caches,
                    unix_stream.unwrap_or_default(),
                    endpoint,
                    ()
                )
                .map_err(|err| {
                    CompoundNearConnectorCreateWithEndpointError::Unix {
                        unix: err
                    }
                })?;

                Ok(CompoundNearConnector::Unix { unix: unix })
            }
            (
                CompoundNearConnectorPartialConfig::TCP { tcp },
                CompoundNearNameAddr::TCP { tcp: endpoint },
                None
            ) => {
                let Ok(acc) = TCPNearConnector::create_with_endpoint(
                    caches,
                    tcp.unwrap_or_default(),
                    endpoint,
                    ()
                );

                Ok(CompoundNearConnector::TCP { tcp: acc })
            }
            (
                CompoundNearConnectorPartialConfig::TLS { tls },
                endpoint,
                param
            ) => {
                let param = match param {
                    Some(CompoundNearConnectorParam::TLS { tls }) => *tls,
                    None => TLSParam::default()
                };
                let acc = TLSNearConnector::create_with_endpoint(
                    caches, tls, endpoint, param
                )
                .map_err(|err| {
                    CompoundNearConnectorCreateWithEndpointError::TLS {
                        tls: Box::new(err)
                    }
                })?;

                Ok(CompoundNearConnector::TLS { tls: acc })
            }
            (
                CompoundNearConnectorPartialConfig::SOCKS5 { socks5_tcp },
                CompoundNearNameAddr::SOCKS5 { socks5: endpoint },
                None
            ) => SOCKS5NearConnector::create_with_endpoint(
                caches,
                socks5_tcp,
                endpoint,
                ()
            )
            .map(|acc| CompoundNearConnector::SOCKS5 { socks5: acc })
            .map_err(|err| {
                CompoundNearConnectorCreateWithEndpointError::SOCKS5 {
                    socks5: err
                }
            }),
            _ => Err(CompoundNearConnectorCreateWithEndpointError::Mismatch)
        }
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearNameAddr)>
    for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type NegotiateError = CompoundNearConnectorNegotiateError;
    type Pending = CompoundNearConnectorNegotiatePending;
    type State = CompoundNearConnectorState;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(err)
    }
}

impl<TLS> NearChannel for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
    type Endpoint = CompoundNearNameAddr;
    type ShutdownNego = CompoundNearConnectorShutdownNegotiator;
    type ShutdownValue = CompoundNearConnectorShutdownValue;
    type StartError = CompoundNearConnectorStartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.as_mut().start(registry, token)
    }

    #[inline]
    fn shutdown_nego(&self) -> Self::ShutdownNego {
        self.as_ref().shutdown_nego()
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    #[inline]
    fn cleanup(
        &mut self,
        registry: &Registry,
        err: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        self.as_mut().cleanup(registry, err)
    }
}

impl<TLS> NearChannelCreateWithEndpoint for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = Box<CompoundNearConnectorPartialConfig<TLS>>;
    type CreateError = CompoundNearConnectorCreateWithEndpointError;
    type EndpointConfig = CompoundNearNameAddr;
    type Param = Option<CompoundNearConnectorParam>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundNearConnectorPartialConfig<TLS>>,
        endpoint: CompoundNearNameAddr,
        param: Option<CompoundNearConnectorParam>
    ) -> Result<Self, CompoundNearConnectorCreateWithEndpointError>
    where
        Ctx: NSNameCachesCtx {
        CompoundNearConnector::create_with_endpoint(
            caches, *config, endpoint, param
        )
        .map(Box::new)
    }
}

impl<TLS> NearConnector for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type EndpointRef<'a>
        = CompoundNearNameAddrRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        match self {
            CompoundNearConnector::Unix { unix } => {
                CompoundNearNameAddrRef::Unix {
                    unix: unix.endpoint()
                }
            }
            CompoundNearConnector::TCP { tcp } => {
                CompoundNearNameAddrRef::TCP {
                    tcp: tcp.endpoint()
                }
            }
            CompoundNearConnector::TLS { tls } => tls.endpoint(),
            CompoundNearConnector::SOCKS5 { socks5 } => {
                CompoundNearNameAddrRef::SOCKS5 {
                    socks5: socks5.endpoint()
                }
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        match self {
            CompoundNearConnector::Unix { unix } => unix.shutdown(),
            CompoundNearConnector::TCP { tcp } => tcp.shutdown(),
            CompoundNearConnector::TLS { tls } => tls.shutdown(),
            CompoundNearConnector::SOCKS5 { socks5 } => socks5.shutdown()
        }
    }
}

impl<TLS> NearConnector for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type EndpointRef<'a>
        = CompoundNearNameAddrRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.as_ref().endpoint()
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.as_mut().shutdown()
    }
}

impl Negotiator<CompoundNearAcceptorShutdownValue>
    for CompoundNearAcceptorShutdownNegotiator
{
    type NegotiateError = CompoundShutdownError;
    type Pending =
        CompoundNearShutdownNegotiatorPending<CompoundNearServerConn>;
    type State = CompoundNearShutdownNegotiatorState<CompoundNearServerConn>;

    fn negotiate(
        &self,
        state: CompoundNearShutdownNegotiatorState<CompoundNearServerConn>
    ) -> Result<
        NegotiatorResult<CompoundNearAcceptorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        match (self, state) {
            (
                CompoundNearAcceptorShutdownNegotiator::Unix { unix },
                CompoundNearShutdownNegotiatorState::Unix { unix: state }
            ) => {
                let Ok(NegotiatorResult::Complete(out)) = unix.negotiate(state);

                Ok(NegotiatorResult::Complete(
                    CompoundNearAcceptorShutdownValue::Unix { unix: out }
                ))
            }
            (
                CompoundNearAcceptorShutdownNegotiator::TCP { tcp },
                CompoundNearShutdownNegotiatorState::TCP { tcp: state }
            ) => {
                let Ok(NegotiatorResult::Complete(out)) = tcp.negotiate(state);

                Ok(NegotiatorResult::Complete(
                    CompoundNearAcceptorShutdownValue::TCP { tcp: out }
                ))
            }
            (
                CompoundNearAcceptorShutdownNegotiator::TLS { tls },
                CompoundNearShutdownNegotiatorState::TLS { tls: state }
            ) => Ok(tls
                .negotiate(*state)
                .map_err(|err| CompoundShutdownError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|pending| {
                    CompoundNearShutdownNegotiatorPending::TLS {
                        tls: Box::new(pending)
                    }
                })
                .map(|out| CompoundNearAcceptorShutdownValue::TLS {
                    tls: Box::new(out)
                })),
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearShutdownNegotiatorPending<CompoundNearServerConn>
    ) -> Result<
        NegotiatorResult<CompoundNearAcceptorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        match (self, pending) {
            (
                CompoundNearAcceptorShutdownNegotiator::TLS { tls },
                CompoundNearShutdownNegotiatorPending::TLS { tls: pending }
            ) => Ok(tls
                .complete_negotiate(*pending)
                .map_err(|err| CompoundShutdownError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|pending| {
                    CompoundNearShutdownNegotiatorPending::TLS {
                        tls: Box::new(pending)
                    }
                })
                .map(|out| CompoundNearAcceptorShutdownValue::TLS {
                    tls: Box::new(out)
                })),
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }
}

impl Negotiator<CompoundNearConnectorShutdownValue>
    for CompoundNearConnectorShutdownNegotiator
{
    type NegotiateError = CompoundShutdownError;
    type Pending =
        CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>;
    type State = CompoundNearShutdownNegotiatorState<CompoundNearClientConn>;

    fn negotiate(
        &self,
        state: CompoundNearShutdownNegotiatorState<CompoundNearClientConn>
    ) -> Result<
        NegotiatorResult<CompoundNearConnectorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        match (self, state) {
            (
                CompoundNearConnectorShutdownNegotiator::Unix { unix },
                CompoundNearShutdownNegotiatorState::Unix { unix: state }
            ) => {
                let Ok(NegotiatorResult::Complete(out)) = unix.negotiate(state);

                Ok(NegotiatorResult::Complete(
                    CompoundNearConnectorShutdownValue::Unix { unix: out }
                ))
            }
            (
                CompoundNearConnectorShutdownNegotiator::TCP { tcp },
                CompoundNearShutdownNegotiatorState::TCP { tcp: state }
            ) => {
                let Ok(NegotiatorResult::Complete(out)) = tcp.negotiate(state);

                Ok(NegotiatorResult::Complete(
                    CompoundNearConnectorShutdownValue::TCP { tcp: out }
                ))
            }
            (
                CompoundNearConnectorShutdownNegotiator::TLS { tls },
                CompoundNearShutdownNegotiatorState::TLS { tls: state }
            ) => Ok(tls
                .negotiate(*state)
                .map_err(|err| CompoundShutdownError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|pending| {
                    CompoundNearShutdownNegotiatorPending::TLS {
                        tls: Box::new(pending)
                    }
                })
                .map(|out| CompoundNearConnectorShutdownValue::TLS {
                    tls: Box::new(out)
                })),
            (
                CompoundNearConnectorShutdownNegotiator::SOCKS5 { socks5 },
                state
            ) => socks5.negotiate(state),
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>
    ) -> Result<
        NegotiatorResult<CompoundNearConnectorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        match (self, pending) {
            (
                CompoundNearConnectorShutdownNegotiator::TLS { tls },
                CompoundNearShutdownNegotiatorPending::TLS { tls: pending }
            ) => Ok(tls
                .complete_negotiate(*pending)
                .map_err(|err| CompoundShutdownError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|pending| {
                    CompoundNearShutdownNegotiatorPending::TLS {
                        tls: Box::new(pending)
                    }
                })
                .map(|out| CompoundNearConnectorShutdownValue::TLS {
                    tls: Box::new(out)
                })),
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }
}

impl NegotiatorStart<CompoundNearAcceptorShutdownValue, CompoundNearServerConn>
    for CompoundNearAcceptorShutdownNegotiator
{
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundNearServerConn
    ) -> Result<Self::State, Self::StartError> {
        match (self, stream) {
            (
                CompoundNearAcceptorShutdownNegotiator::Unix { unix },
                CompoundNearServerConn::Unix { unix: stream }
            ) => {
                let Ok(state) = unix.start(param, stream);

                Ok(CompoundNearShutdownNegotiatorState::Unix { unix: state })
            }
            (
                CompoundNearAcceptorShutdownNegotiator::TCP { tcp },
                CompoundNearServerConn::TCP { tcp: stream }
            ) => {
                let Ok(state) = tcp.start(param, stream);

                Ok(CompoundNearShutdownNegotiatorState::TCP { tcp: state })
            }
            (
                CompoundNearAcceptorShutdownNegotiator::TLS { tls },
                CompoundNearServerConn::TLS { tls: stream }
            ) => tls.start(param, *stream).map(|state| {
                CompoundNearShutdownNegotiatorState::TLS {
                    tls: Box::new(state)
                }
            }),
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl NegotiatorStart<CompoundNearConnectorShutdownValue, CompoundNearClientConn>
    for CompoundNearConnectorShutdownNegotiator
{
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundNearClientConn
    ) -> Result<Self::State, Self::StartError> {
        match (self, stream) {
            (
                CompoundNearConnectorShutdownNegotiator::Unix { unix },
                CompoundNearClientConn::Unix { unix: stream }
            ) => {
                let Ok(state) = unix.start(param, stream);

                Ok(CompoundNearShutdownNegotiatorState::Unix { unix: state })
            }
            (
                CompoundNearConnectorShutdownNegotiator::TCP { tcp },
                CompoundNearClientConn::TCP { tcp: stream }
            ) => {
                let Ok(state) = tcp.start(param, stream);

                Ok(CompoundNearShutdownNegotiatorState::TCP { tcp: state })
            }
            (
                CompoundNearConnectorShutdownNegotiator::TLS { tls },
                CompoundNearClientConn::TLS { tls: stream }
            ) => tls.start(param, *stream).map(|state| {
                CompoundNearShutdownNegotiatorState::TLS {
                    tls: Box::new(state)
                }
            }),
            (
                CompoundNearConnectorShutdownNegotiator::SOCKS5 { socks5 },
                CompoundNearClientConn::SOCKS5 { socks5: stream }
            ) => socks5.start(param, *stream),
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl Negotiator<CompoundNearAcceptorShutdownValue>
    for Box<CompoundNearAcceptorShutdownNegotiator>
{
    type NegotiateError = CompoundShutdownError;
    type Pending =
        CompoundNearShutdownNegotiatorPending<CompoundNearServerConn>;
    type State = CompoundNearShutdownNegotiatorState<CompoundNearServerConn>;

    fn negotiate(
        &self,
        state: CompoundNearShutdownNegotiatorState<CompoundNearServerConn>
    ) -> Result<
        NegotiatorResult<CompoundNearAcceptorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearShutdownNegotiatorPending<CompoundNearServerConn>
    ) -> Result<
        NegotiatorResult<CompoundNearAcceptorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(pending)
    }
}

impl Negotiator<CompoundNearConnectorShutdownValue>
    for Box<CompoundNearConnectorShutdownNegotiator>
{
    type NegotiateError = CompoundShutdownError;
    type Pending =
        CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>;
    type State = CompoundNearShutdownNegotiatorState<CompoundNearClientConn>;

    fn negotiate(
        &self,
        state: CompoundNearShutdownNegotiatorState<CompoundNearClientConn>
    ) -> Result<
        NegotiatorResult<CompoundNearConnectorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>
    ) -> Result<
        NegotiatorResult<CompoundNearConnectorShutdownValue, Self::Pending>,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(pending)
    }
}

impl NegotiatorStart<CompoundNearConnectorShutdownValue, CompoundNearClientConn>
    for Box<CompoundNearConnectorShutdownNegotiator>
{
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundNearClientConn
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl NegotiatorStart<CompoundNearAcceptorShutdownValue, CompoundNearServerConn>
    for Box<CompoundNearAcceptorShutdownNegotiator>
{
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundNearServerConn
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearNameAddr)>
    for CompoundResolvingNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type NegotiateError = CompoundNearConnectorNegotiateError;
    type Pending = CompoundNearConnectorNegotiatePending;
    type State = CompoundNearConnectorState;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, state) {
            (
                CompoundResolvingNearConnector::Unix { unix },
                CompoundNearConnectorState::Unix { unix: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    unix.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearClientConn::Unix { unix: conn },
                    CompoundNearNameAddr::Unix { unix: endpoint }
                ));

                Ok(res)
            }
            (
                CompoundResolvingNearConnector::TCP { tcp },
                CompoundNearConnectorState::TCP { tcp: state }
            ) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    tcp.negotiate(state);
                let res = NegotiatorResult::Complete((
                    CompoundNearClientConn::TCP { tcp: conn },
                    CompoundNearNameAddr::TCP { tcp: endpoint }
                ));

                Ok(res)
            }
            (
                CompoundResolvingNearConnector::SOCKS5 { socks5 },
                CompoundNearConnectorState::SOCKS5 { socks5: state }
            ) => Ok(socks5
                .negotiate(*state)
                .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                    socks5: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::SOCKS5 {
                        socks5: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::SOCKS5 {
                            socks5: Box::new(conn)
                        },
                        CompoundNearNameAddr::SOCKS5 { socks5: endpoint }
                    )
                })),
            (CompoundResolvingNearConnector::TLS { tls }, state) => Ok(tls
                .negotiate(state)
                .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        match (self, pending) {
            (
                CompoundResolvingNearConnector::TLS { tls },
                CompoundNearConnectorNegotiatePending::TLS { tls: pending }
            ) => Ok(tls
                .complete_negotiate(*pending)
                .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                    tls: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::TLS {
                        tls: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::TLS {
                            tls: Box::new(conn)
                        },
                        endpoint
                    )
                })),
            (
                CompoundResolvingNearConnector::SOCKS5 { socks5 },
                CompoundNearConnectorNegotiatePending::SOCKS5 {
                    socks5: pending
                }
            ) => Ok(socks5
                .complete_negotiate(*pending)
                .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                    socks5: Box::new(err)
                })?
                .map_pending(|inner| {
                    CompoundNearConnectorNegotiatePending::SOCKS5 {
                        socks5: Box::new(inner)
                    }
                })
                .map(|(conn, endpoint)| {
                    (
                        CompoundNearClientConn::SOCKS5 {
                            socks5: Box::new(conn)
                        },
                        CompoundNearNameAddr::SOCKS5 { socks5: endpoint }
                    )
                })),
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
        }
    }
}

impl<TLS> NearChannel for CompoundResolvingNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
    type Endpoint = CompoundNearNameAddr;
    type ShutdownNego = CompoundNearConnectorShutdownNegotiator;
    type ShutdownValue = CompoundNearConnectorShutdownValue;
    type StartError = CompoundNearConnectorStartError;

    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        match self {
            CompoundResolvingNearConnector::Unix { unix } => {
                let out = unix
                    .start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::Unix {
                        err: err
                    })?
                    .map(|unix| CompoundNearConnectorState::Unix {
                        unix: unix
                    });

                Ok(out)
            }
            CompoundResolvingNearConnector::TCP { tcp } => {
                let out = tcp
                    .start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::TCP {
                        err: err
                    })?
                    .map(|tcp| CompoundNearConnectorState::TCP { tcp: tcp });

                Ok(out)
            }
            CompoundResolvingNearConnector::SOCKS5 { socks5 } => {
                let out = socks5.start(registry, token)?.map(|socks5| {
                    CompoundNearConnectorState::SOCKS5 {
                        socks5: Box::new(socks5)
                    }
                });

                Ok(out)
            }
            CompoundResolvingNearConnector::TLS { tls } => {
                tls.start(registry, token)
            }
        }
    }

    fn shutdown_nego(&self) -> Self::ShutdownNego {
        match self {
            CompoundResolvingNearConnector::Unix { .. } => {
                CompoundNearConnectorShutdownNegotiator::Unix {
                    unix: PassthruNegotiator
                }
            }
            CompoundResolvingNearConnector::TCP { .. } => {
                CompoundNearConnectorShutdownNegotiator::TCP {
                    tcp: PassthruNegotiator
                }
            }
            CompoundResolvingNearConnector::TLS { tls } => {
                let nego = tls.shutdown_nego();

                CompoundNearConnectorShutdownNegotiator::TLS {
                    tls: Box::new(nego)
                }
            }
            CompoundResolvingNearConnector::SOCKS5 { socks5 } => {
                let nego = socks5.shutdown_nego();

                CompoundNearConnectorShutdownNegotiator::SOCKS5 {
                    socks5: Box::new(nego)
                }
            }
        }
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        pending: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        match (self, pending) {
            (
                CompoundResolvingNearConnector::TLS { tls },
                CompoundNearConnectorNegotiateError::TLS { tls: err }
            ) => tls.cleanup(registry, *err),
            _ => Err(Error::new(ErrorKind::Other, "mismatch in cleanup"))
        }
    }
}

impl<TLS> NearChannelCreate for CompoundResolvingNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = CompoundResolvingNearConnectorConfig<TLS>;
    type CreateError = CompoundNearConnectorCreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: CompoundResolvingNearConnectorConfig<TLS>
    ) -> Result<Self, CompoundNearConnectorCreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundResolvingNearConnectorConfig::Unix { unix_stream } => {
                let acc = UnixNearConnector::create(caches, unix_stream)
                    .map_err(|err| CompoundNearConnectorCreateError::Unix {
                        unix: err
                    })?;

                Ok(CompoundResolvingNearConnector::Unix { unix: acc })
            }
            CompoundResolvingNearConnectorConfig::TCP { tcp } => {
                let acc = TCPResolvingNearConnector::create(caches, tcp)
                    .map_err(|err| CompoundNearConnectorCreateError::TCP {
                        tcp: err
                    })?;

                Ok(CompoundResolvingNearConnector::TCP { tcp: acc })
            }
            CompoundResolvingNearConnectorConfig::TLS { tls } => {
                let acc =
                    TLSNearConnector::create(caches, tls).map_err(|err| {
                        CompoundNearConnectorCreateError::TLS {
                            tls: Box::new(err)
                        }
                    })?;

                Ok(CompoundResolvingNearConnector::TLS { tls: acc })
            }
            CompoundResolvingNearConnectorConfig::SOCKS5 { socks5_tcp } => {
                SOCKS5NearConnector::create(caches, socks5_tcp).map(|acc| {
                    CompoundResolvingNearConnector::SOCKS5 { socks5: acc }
                })
            }
        }
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        match conf {
            CompoundResolvingNearConnectorConfig::Unix { unix_stream } => {
                <UnixNearConnector as NearChannelCreate>
                    ::verify_endpoint(unix_stream)
            }
            CompoundResolvingNearConnectorConfig::TCP { tcp } => {
                <TCPResolvingNearConnector as NearChannelCreate>::verify_endpoint(tcp)
            }
            CompoundResolvingNearConnectorConfig::TLS { tls } => {
                <TLSNearConnector::<Box<Self>, TLS> as NearChannelCreate>
                    ::verify_endpoint(tls)
            }
            CompoundResolvingNearConnectorConfig::SOCKS5 { socks5_tcp } => {
                <SOCKS5NearConnector::<Box<Self>> as NearChannelCreate>
                    ::verify_endpoint(socks5_tcp)
            }
        }
    }
}

impl<TLS> NearChannelCreateWithEndpoint for CompoundResolvingNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = CompoundResolvingNearConnectorPartialConfig<TLS>;
    type CreateError = CompoundNearConnectorCreateWithEndpointError;
    type EndpointConfig = CompoundResolvingNearConnectorEndpointConfig;
    type Param = Option<CompoundNearConnectorParam>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: CompoundResolvingNearConnectorPartialConfig<TLS>,
        endpoint: CompoundResolvingNearConnectorEndpointConfig,
        param: Option<CompoundNearConnectorParam>
    ) -> Result<Self, CompoundNearConnectorCreateWithEndpointError>
    where
        Ctx: NSNameCachesCtx {
        match (config, endpoint, param) {
            (
                CompoundResolvingNearConnectorPartialConfig::Unix {
                    unix_stream
                },
                CompoundResolvingNearConnectorEndpointConfig::Unix {
                    unix: endpoint
                },
                None
            ) => {
                let unix = UnixNearConnector::create_with_endpoint(
                    caches,
                    unix_stream.unwrap_or_default(),
                    endpoint,
                    ()
                )
                .map_err(|err| {
                    CompoundNearConnectorCreateWithEndpointError::Unix {
                        unix: err
                    }
                })?;

                Ok(CompoundResolvingNearConnector::Unix { unix: unix })
            }
            (
                CompoundResolvingNearConnectorPartialConfig::TCP { tcp },
                CompoundResolvingNearConnectorEndpointConfig::TCP {
                    tcp: endpoint
                },
                None
            ) => {
                let acc = TCPResolvingNearConnector::create_with_endpoint(
                    caches,
                    tcp.unwrap_or_default(),
                    endpoint,
                    ()
                )
                .map_err(|err| {
                    CompoundNearConnectorCreateWithEndpointError::TCP {
                        tcp: err
                    }
                })?;

                Ok(CompoundResolvingNearConnector::TCP { tcp: acc })
            }
            (
                CompoundResolvingNearConnectorPartialConfig::TLS { tls },
                endpoint,
                param
            ) => {
                let param = match param {
                    Some(CompoundNearConnectorParam::TLS { tls }) => *tls,
                    None => TLSParam::default()
                };
                let acc = TLSNearConnector::create_with_endpoint(
                    caches, tls, endpoint, param
                )
                .map_err(|err| {
                    CompoundNearConnectorCreateWithEndpointError::TLS {
                        tls: Box::new(err)
                    }
                })?;

                Ok(CompoundResolvingNearConnector::TLS { tls: acc })
            }
            (
                CompoundResolvingNearConnectorPartialConfig::SOCKS5 {
                    socks5_tcp
                },
                CompoundResolvingNearConnectorEndpointConfig::SOCKS5 {
                    socks5: endpoint
                },
                None
            ) => SOCKS5NearConnector::create_with_endpoint(
                caches,
                socks5_tcp,
                endpoint,
                ()
            )
            .map(|acc| CompoundResolvingNearConnector::SOCKS5 { socks5: acc })
            .map_err(|err| {
                CompoundNearConnectorCreateWithEndpointError::SOCKS5 {
                    socks5: err
                }
            }),
            _ => Err(CompoundNearConnectorCreateWithEndpointError::Mismatch)
        }
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearNameAddr)>
    for Box<CompoundResolvingNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type NegotiateError = CompoundNearConnectorNegotiateError;
    type Pending = CompoundNearConnectorNegotiatePending;
    type State = CompoundNearConnectorState;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<
            (CompoundNearClientConn, CompoundNearNameAddr),
            CompoundNearConnectorNegotiatePending
        >,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(err)
    }
}

impl<TLS> NearChannel for Box<CompoundResolvingNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
    type Endpoint = CompoundNearNameAddr;
    type ShutdownNego = CompoundNearConnectorShutdownNegotiator;
    type ShutdownValue = CompoundNearConnectorShutdownValue;
    type StartError = CompoundNearConnectorStartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.as_mut().start(registry, token)
    }

    #[inline]
    fn shutdown_nego(&self) -> Self::ShutdownNego {
        self.as_ref().shutdown_nego()
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
    }

    #[inline]
    fn cleanup(
        &mut self,
        registry: &Registry,
        err: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        self.as_mut().cleanup(registry, err)
    }
}

impl<TLS> NearChannelCreate for Box<CompoundResolvingNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = Box<CompoundResolvingNearConnectorConfig<TLS>>;
    type CreateError = CompoundNearConnectorCreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundResolvingNearConnectorConfig<TLS>>
    ) -> Result<Self, CompoundNearConnectorCreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundResolvingNearConnector::create(caches, *config).map(Box::new)
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        <CompoundResolvingNearConnector<TLS> as NearChannelCreate>
            ::verify_endpoint(conf.as_ref())
    }
}

impl<TLS> NearChannelCreateWithEndpoint
    for Box<CompoundResolvingNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = Box<CompoundResolvingNearConnectorPartialConfig<TLS>>;
    type CreateError = CompoundNearConnectorCreateWithEndpointError;
    type EndpointConfig = CompoundResolvingNearConnectorEndpointConfig;
    type Param = Option<CompoundNearConnectorParam>;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundResolvingNearConnectorPartialConfig<TLS>>,
        endpoint: CompoundResolvingNearConnectorEndpointConfig,
        param: Option<CompoundNearConnectorParam>
    ) -> Result<Self, CompoundNearConnectorCreateWithEndpointError>
    where
        Ctx: NSNameCachesCtx {
        CompoundResolvingNearConnector::create_with_endpoint(
            caches, *config, endpoint, param
        )
        .map(Box::new)
    }
}

impl<TLS> NearConnector for CompoundResolvingNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type EndpointRef<'a>
        = CompoundResolvingNearConnectorEndpointRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        match self {
            CompoundResolvingNearConnector::Unix { unix } => {
                CompoundResolvingNearConnectorEndpointRef::Unix {
                    unix: unix.endpoint()
                }
            }
            CompoundResolvingNearConnector::TCP { tcp } => {
                CompoundResolvingNearConnectorEndpointRef::TCP {
                    tcp: tcp.endpoint()
                }
            }
            CompoundResolvingNearConnector::TLS { tls } => tls.endpoint(),
            CompoundResolvingNearConnector::SOCKS5 { socks5 } => {
                CompoundResolvingNearConnectorEndpointRef::SOCKS5 {
                    socks5: socks5.endpoint()
                }
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        match self {
            CompoundResolvingNearConnector::Unix { unix } => unix.shutdown(),
            CompoundResolvingNearConnector::TCP { tcp } => tcp.shutdown(),
            CompoundResolvingNearConnector::TLS { tls } => tls.shutdown(),
            CompoundResolvingNearConnector::SOCKS5 { socks5 } => {
                socks5.shutdown()
            }
        }
    }
}

impl<TLS> NearConnector for Box<CompoundResolvingNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type EndpointRef<'a>
        = CompoundResolvingNearConnectorEndpointRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.as_ref().endpoint()
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.as_mut().shutdown()
    }
}

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::config::tls::TLSClientConfig;
#[cfg(test)]
use crate::config::tls::TLSServerConfig;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::near::accept_one;
#[cfg(test)]
use crate::near::negotiate_one;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::write_one;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[cfg(test)]
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

#[cfg(test)]
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[cfg(test)]
fn test_compound(
    server_conf: &str,
    client_conf: &str
) {
    let client_conf: CompoundResolvingNearConnectorConfig<TLSClientConfig> =
        serde_yaml::from_str(client_conf).unwrap();
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        serde_yaml::from_str(server_conf).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor =
            CompoundNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) =
            negotiate_one(&mut acceptor, &mut poll, start, session)
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
        let mut conn = CompoundResolvingNearConnector::create(
            &mut client_nscaches,
            client_conf
        )
        .expect("expected success");

        client_barrier.wait();

        let start = match conn
            .start(poll.registry(), session)
            .expect("expected success")
        {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) =
            negotiate_one(&mut conn, &mut poll, start, session)
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

#[test]
fn test_tls_unix() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  client-auth:\n",
        "    verify: required\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  unix-stream:\n",
        "    path: test_compound_tls_unix.sock"
    );

    const CLIENT_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  unix-stream:\n",
        "    path: test_compound_tls_unix.sock"
    );

    test_compound(SERVER_CONF, CLIENT_CONF)
}

#[test]
fn test_compound_tls_tcp() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  client-auth:\n",
        "    verify: required\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  tcp:\n",
        "    addr: ::0\n",
        "    port: 8002\n"
    );

    const CLIENT_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  tcp:\n",
        "    addr: localhost\n",
        "    port: 8002\n"
    );

    test_compound(SERVER_CONF, CLIENT_CONF)
}

#[test]
fn test_compound_double_tls() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  client-auth:\n",
        "    verify: required\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  tls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - X25519\n",
        "      - P-256\n",
        "    client-auth:\n",
        "      verify: required\n",
        "      trust-root:\n",
        "        root-certs:\n",
        "          - tests/data/certs/client/ca_cert.pem\n",
        "        crls: []\n",
        "    cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "    key: tests/data/certs/server/private/test_server_key.pem\n",
        "    tcp:\n",
        "      addr: ::0\n",
        "      port: 8003\n"
    );

    const CLIENT_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  tls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - X25519\n",
        "      - P-256\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/server/ca_cert.pem\n",
        "      crls: []\n",
        "    client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "    client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "    verify-endpoint: test-server.nowhere.com\n",
        "    tcp:\n",
        "      addr: localhost\n",
        "      port: 8003\n"
    );

    test_compound(SERVER_CONF, CLIENT_CONF)
}
