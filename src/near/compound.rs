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

//! A flexible, configurable [NearChannel] instance.
//!
//! Compound channels support arbitrary nesting of different channel
//! types, which can be constructed according to a configuration.
//! This functionality is provided by [CompoundNearAcceptor] and
//! [CompoundNearConnector] Most applications should use these
//! implementations, unless there is a good reason to impose more
//! stringent restrictions on what types of channels can be
//! configured.

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
use constellation_common::retry::RetryResult;
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
use crate::config::tls::TLSLoadServer;
use crate::config::CompoundNearAcceptorConfig;
use crate::config::CompoundNearConnectorConfig;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NearConnector;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NegotiateError;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5NegotiatePending;
#[cfg(feature = "socks5")]
use crate::near::socks5::SOCKS5SessionNegotiation;
use crate::near::tcp::TCPNearAcceptor;
use crate::near::tcp::TCPNearConnector;
use crate::near::tcp::TCPNearConnectorError;
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
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;
#[cfg(feature = "unix")]
use crate::unix::UnixSocketAddr;
#[cfg(feature = "unix")]
use crate::unix::UnixSocketPath;

/// Multiplexer for [Endpoint](NearChannel::Endpoint)s for
/// [CompoundNearAcceptor].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CompoundNearAcceptorEndpoint {
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
#[derive(Clone, Debug)]
pub enum CompoundNearConnectorEndpoint {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    TCP {
        tcp: SocketAddr
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<CompoundNearConnectorEndpoint>
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<CompoundNearConnectorEndpoint>
    }
}

/// Multiplexer for [EndpointRef](NearConnector::EndpointRef)s for
/// [CompoundNearConnector].
#[derive(Clone)]
pub enum CompoundNearConnectorEndpointRef<'a> {
    #[cfg(feature = "unix")]
    Unix {
        unix: &'a UnixSocketPath
    },
    TCP {
        tcp: &'a IPEndpoint
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<CompoundNearConnectorEndpointRef<'a>>
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<CompoundNearConnectorEndpointRef<'a>>
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
        tcp: TCPNearConnectorError
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

/// Multiplexer for [NegotiateError](NearChannel::NegotiateError)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearAcceptorNegotiateError {
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSNegotiateError<
                CompoundNearAcceptorNegotiateError,
                CompoundNearAcceptorEndpoint,
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
                CompoundNearAcceptorEndpoint,
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
                CompoundNearConnectorEndpoint,
                CompoundNearClientConn
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiateError<
                CompoundNearConnectorNegotiateError,
                CompoundNearClientConn,
                CompoundNearConnectorEndpoint,
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
                CompoundNearConnectorEndpoint,
                CompoundNearClientConn
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiatePending<
                CompoundNearConnectorNegotiatePending,
                CompoundNearClientConn,
                CompoundNearConnectorEndpoint,
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
    TCP { err: Error },
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
        tls: Box<TLSConn<CompoundNearClientConn, CompoundNearConnectorEndpoint>>
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
        tls: Box<TLSConn<CompoundNearServerConn, CompoundNearAcceptorEndpoint>>
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
///     "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
///     "  key: test/data/certs/server/private/test_server_key.pem\n",
///     "  tcp:\n",
///     "    addr: ::0\n",
///     "    port: 8001\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let acceptor: CompoundNearAcceptor<TLSServerConfig> =
///     CompoundNearAcceptor::new(&mut nscaches, accept_config).unwrap();
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
/// # use constellation_channels::near::compound::CompoundNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "tls:\n",
///     "  trust-root:\n",
///     "    root-certs:\n",
///     "      - test/data/certs/server/ca_cert.pem\n",
///     "  tcp:\n",
///     "    addr: en.wikipedia.org\n",
///     "    port: 443\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector: CompoundNearConnector<TLSClientConfig> =
///     CompoundNearConnector::new(&mut nscaches, accept_config).unwrap();
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
        socks5: SOCKS5NearConnector<Box<CompoundNearConnector<TLS>>>
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
            CompoundNearConnectorCreateError::TLS { tls } => tls.scope(),
        }
    }
}

impl ScopedError for CompoundNearAcceptorNegotiateError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "tls")]
            CompoundNearAcceptorNegotiateError::TLS { tls } => tls.scope(),
            CompoundNearAcceptorNegotiateError::Mismatch =>
                ErrorScope::Unrecoverable
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
            CompoundNearConnectorNegotiateError::Mismatch =>
                ErrorScope::Unrecoverable
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
            CompoundNearConnectorStartError::TCP { err } => err.scope(),
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
            CompoundNearAcceptorNegotiateError::Mismatch =>
                write!(f, "mismatch")
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
            CompoundNearConnectorNegotiateError::Mismatch =>
                write!(f, "mismatch")
        }
    }
}

impl Display for CompoundNearAcceptorEndpoint {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorEndpoint::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearAcceptorEndpoint::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
        }
    }
}

impl Display for CompoundNearConnectorEndpoint {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorEndpoint::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearConnectorEndpoint::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorEndpoint::TLS { tls } => write!(f, "{}", tls),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorEndpoint::SOCKS5 { socks5 } =>
                write!(f, "{}", socks5),
        }
    }
}

impl Display for CompoundNearConnectorEndpointRef<'_> {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorEndpointRef::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundNearConnectorEndpointRef::TCP { tcp } => {
                write!(f, "tcp://{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorEndpointRef::TLS { tls } => tls.fmt(f),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorEndpointRef::SOCKS5 { socks5 } => socks5.fmt(f)
        }
    }
}

impl Credentials for CompoundNearClientConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<CompoundNearCredential>,
        CompoundNearCredentialError
    > {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                let cred = unix.creds()
                    .map_err(|err| CompoundNearCredentialError::Unix {
                        err: err
                    })?;

                Ok(cred.map(|cred| CompoundNearCredential::Unix { unix: cred }))
            }
            CompoundNearClientConn::TCP { tcp } => {
                let cred = tcp.creds()
                    .map_err(|err| CompoundNearCredentialError::Unix {
                        err: err
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
    ) -> Result<
        Option<CompoundNearCredential>,
        CompoundNearCredentialError
    > {
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

impl ChannelParam<CompoundNearAcceptorEndpoint>
    for CompoundNearAcceptorEndpoint
{
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearAcceptorEndpoint
    ) -> bool {
        matches!(
            (self, addr),
            (
                CompoundNearAcceptorEndpoint::Unix { .. },
                CompoundNearAcceptorEndpoint::Unix { .. }
            ) | (
                CompoundNearAcceptorEndpoint::TCP { .. },
                CompoundNearAcceptorEndpoint::TCP { .. }
            )
        )
    }
}

impl ChannelParam<SocketAddr> for CompoundNearAcceptorEndpoint {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &SocketAddr
    ) -> bool {
        matches!(self, CompoundNearAcceptorEndpoint::TCP { .. })
    }
}

impl ChannelParam<CompoundNearAcceptorEndpoint> for SocketAddr {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearAcceptorEndpoint
    ) -> bool {
        matches!(addr, CompoundNearAcceptorEndpoint::TCP { .. })
    }
}

impl ChannelParam<UnixSocketAddr> for CompoundNearAcceptorEndpoint {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &UnixSocketAddr
    ) -> bool {
        matches!(self, CompoundNearAcceptorEndpoint::Unix { .. })
    }
}

impl ChannelParam<CompoundNearAcceptorEndpoint> for UnixSocketAddr {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundNearAcceptorEndpoint
    ) -> bool {
        matches!(addr, CompoundNearAcceptorEndpoint::Unix { .. })
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

impl<TLS> Negotiator<(CompoundNearServerConn, CompoundNearAcceptorEndpoint)>
    for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type State = CompoundNearAcceptorState;
    type Pending = CompoundNearAcceptorNegotiatePending;
    type NegotiateError = CompoundNearAcceptorNegotiateError;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(CompoundNearServerConn,
                          CompoundNearAcceptorEndpoint),
                         CompoundNearAcceptorNegotiatePending>,
        Self::NegotiateError
    > {
        match (self, state) {
            (CompoundNearAcceptor::Unix { unix },
             CompoundNearAcceptorState::Unix { unix: state }) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    unix.negotiate(state);
                let res = NegotiatorResult::Complete(
                    (CompoundNearServerConn::Unix { unix: conn },
                     CompoundNearAcceptorEndpoint::Unix { unix: endpoint })
                );

                Ok(res)
            }
            (CompoundNearAcceptor::TCP { tcp },
             CompoundNearAcceptorState::TCP { tcp: state }) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    tcp.negotiate(state);
                let res = NegotiatorResult::Complete(
                    (CompoundNearServerConn::TCP { tcp: conn },
                    CompoundNearAcceptorEndpoint::TCP { tcp: endpoint })
                );

                Ok(res)
            }
            (CompoundNearAcceptor::TLS { tls }, state) => {
                Ok(tls.negotiate(state)
                    .map_err(|err| CompoundNearAcceptorNegotiateError::TLS {
                        tls: Box::new(err)
                    })?
                   .map_pending(|inner|
                                CompoundNearAcceptorNegotiatePending::TLS {
                                    tls: Box::new(inner)
                                })
                   .map(|(conn, endpoint)| (CompoundNearServerConn::TLS {
                       tls: Box::new(conn)
                   }, endpoint)))
            }
            _ => Err(CompoundNearAcceptorNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearAcceptorNegotiatePending
    ) -> Result<
        NegotiatorResult<(CompoundNearServerConn,
                          CompoundNearAcceptorEndpoint),
                         CompoundNearAcceptorNegotiatePending>,
        Self::NegotiateError
    > {
        match (self, pending) {
            (CompoundNearAcceptor::TLS { tls },
             CompoundNearAcceptorNegotiatePending::TLS { tls: pending }) => {
                Ok(tls.complete_negotiate(*pending)
                    .map_err(|err| CompoundNearAcceptorNegotiateError::TLS {
                        tls: Box::new(err)
                    })?
                    .map_pending(|inner|
                                 CompoundNearAcceptorNegotiatePending::TLS {
                                     tls: Box::new(inner)
                                 })
                    .map(|(conn, endpoint)| (CompoundNearServerConn::TLS {
                        tls: Box::new(conn)
                    }, endpoint)))
            }
            _ => Err(CompoundNearAcceptorNegotiateError::Mismatch)
        }
    }
}

impl<TLS> NearChannel for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = CompoundNearAcceptorConfig<TLS>;
    type Endpoint = CompoundNearAcceptorEndpoint;
    type Conn = CompoundNearServerConn;
    type StartError = CompoundNearAcceptorStartError;

    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        match self {
            CompoundNearAcceptor::Unix { unix } => {
                let out = unix.start(registry, token)
                    .map_err(|err| CompoundNearAcceptorStartError::Unix {
                        err: err
                    })?
                    .map(|unix| CompoundNearAcceptorState::Unix { unix: unix });

                Ok(out)
            }
            CompoundNearAcceptor::TCP { tcp } => {
                let out = tcp.start(registry, token)
                    .map_err(|err| CompoundNearAcceptorStartError::TCP {
                        err: err
                    })?
                    .map(|tcp| CompoundNearAcceptorState::TCP { tcp: tcp });

                Ok(out)
            }
            CompoundNearAcceptor::TLS { tls } => tls.start(registry, token)
        }
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        pending: CompoundNearAcceptorNegotiateError
    ) -> Result<(), Error> {
        match (self, pending) {
            (CompoundNearAcceptor::TLS { tls },
             CompoundNearAcceptorNegotiateError::TLS { tls: err }) => {
                tls.cleanup(registry, *err)
            }
            _ => Err(Error::new(ErrorKind::Other, "mismatch in cleanup"))
        }
    }
}

impl<TLS> NearChannelCreate for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type CreateError = CompoundNearAcceptorCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: CompoundNearAcceptorConfig<TLS>
    ) -> Result<Self, CompoundNearAcceptorCreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundNearAcceptorConfig::Unix { unix_stream } => {
                let acc = UnixNearAcceptor::new(caches, unix_stream).map_err(
                    |err| CompoundNearAcceptorCreateError::Unix { unix: err }
                )?;

                Ok(CompoundNearAcceptor::Unix { unix: acc })
            }
            CompoundNearAcceptorConfig::TCP { tcp } => {
                let acc = TCPNearAcceptor::new(caches, tcp).map_err(|err| {
                    CompoundNearAcceptorCreateError::TCP { tcp: err }
                })?;

                Ok(CompoundNearAcceptor::TCP { tcp: acc })
            }
            CompoundNearAcceptorConfig::TLS { tls } => {
                let acc = TLSNearAcceptor::new(caches, tls).map_err(|err| {
                    CompoundNearAcceptorCreateError::TLS { tls: Box::new(err) }
                })?;

                Ok(CompoundNearAcceptor::TLS { tls: acc })
            }
        }
    }
}

impl<TLS> Negotiator<(CompoundNearServerConn, CompoundNearAcceptorEndpoint)>
    for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type State = CompoundNearAcceptorState;
    type Pending = CompoundNearAcceptorNegotiatePending;
    type NegotiateError = CompoundNearAcceptorNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(CompoundNearServerConn,
                          CompoundNearAcceptorEndpoint),
                         CompoundNearAcceptorNegotiatePending>,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: CompoundNearAcceptorNegotiatePending
    ) -> Result<
        NegotiatorResult<(CompoundNearServerConn,
                          CompoundNearAcceptorEndpoint),
                         CompoundNearAcceptorNegotiatePending>,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(err)
    }
}

impl<TLS> NearChannel for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = Box<CompoundNearAcceptorConfig<TLS>>;
    type Endpoint = CompoundNearAcceptorEndpoint;
    type Conn = CompoundNearServerConn;
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
    type CreateError = CompoundNearAcceptorCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundNearAcceptorConfig<TLS>>
    ) -> Result<Self, CompoundNearAcceptorCreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundNearAcceptor::new(caches, config.as_ref().clone()).map(Box::new)
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearConnectorEndpoint)>
    for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type State = CompoundNearConnectorState;
    type Pending = CompoundNearConnectorNegotiatePending;
    type NegotiateError = CompoundNearConnectorNegotiateError;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(CompoundNearClientConn,
                          CompoundNearConnectorEndpoint),
                         CompoundNearConnectorNegotiatePending>,
        Self::NegotiateError
    > {
        match (self, state) {
            (CompoundNearConnector::Unix { unix },
             CompoundNearConnectorState::Unix { unix: state }) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    unix.negotiate(state);
                let res = NegotiatorResult::Complete(
                    (CompoundNearClientConn::Unix { unix: conn },
                     CompoundNearConnectorEndpoint::Unix { unix: endpoint })
                );

                Ok(res)
            }
            (CompoundNearConnector::TCP { tcp },
             CompoundNearConnectorState::TCP { tcp: state }) => {
                let Ok(NegotiatorResult::Complete((conn, endpoint))) =
                    tcp.negotiate(state);
                let res = NegotiatorResult::Complete(
                    (CompoundNearClientConn::TCP { tcp: conn },
                    CompoundNearConnectorEndpoint::TCP { tcp: endpoint })
                );

                Ok(res)
            }
            (CompoundNearConnector::SOCKS5 { socks5 },
             CompoundNearConnectorState::SOCKS5 { socks5: state }) => {
                Ok(socks5.negotiate(*state)
                    .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                        socks5: Box::new(err)
                    })?
                   .map_pending(|inner|
                                CompoundNearConnectorNegotiatePending::SOCKS5 {
                                    socks5: Box::new(inner)
                                })
                   .map(|(conn, endpoint)| (CompoundNearClientConn::SOCKS5 {
                       socks5: Box::new(conn)
                   }, endpoint)))
            }
            (CompoundNearConnector::TLS { tls }, state) => {
                Ok(tls.negotiate(state)
                    .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                        tls: Box::new(err)
                    })?
                   .map_pending(|inner|
                                CompoundNearConnectorNegotiatePending::TLS {
                                    tls: Box::new(inner)
                                })
                   .map(|(conn, endpoint)| (CompoundNearClientConn::TLS {
                       tls: Box::new(conn)
                   }, endpoint)))
            }
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<(CompoundNearClientConn,
                          CompoundNearConnectorEndpoint),
                         CompoundNearConnectorNegotiatePending>,
        Self::NegotiateError
    > {
        match (self, pending) {
            (CompoundNearConnector::TLS { tls },
             CompoundNearConnectorNegotiatePending::TLS { tls: pending }) => {
                Ok(tls.complete_negotiate(*pending)
                    .map_err(|err| CompoundNearConnectorNegotiateError::TLS {
                        tls: Box::new(err)
                    })?
                    .map_pending(|inner|
                                 CompoundNearConnectorNegotiatePending::TLS {
                                     tls: Box::new(inner)
                                 })
                    .map(|(conn, endpoint)| (CompoundNearClientConn::TLS {
                        tls: Box::new(conn)
                    }, endpoint)))
            }
            (CompoundNearConnector::SOCKS5 { socks5 },
             CompoundNearConnectorNegotiatePending::SOCKS5 {
                 socks5: pending
             }) => {
                Ok(socks5.complete_negotiate(*pending)
                    .map_err(|err| CompoundNearConnectorNegotiateError::SOCKS5 {
                        socks5: Box::new(err)
                    })?
                    .map_pending(|inner|
                                 CompoundNearConnectorNegotiatePending::SOCKS5 {
                                     socks5: Box::new(inner)
                                 })
                    .map(|(conn, endpoint)| (CompoundNearClientConn::SOCKS5 {
                        socks5: Box::new(conn)
                    }, endpoint)))
            }
            _ => Err(CompoundNearConnectorNegotiateError::Mismatch)
         }
    }
}

impl<TLS> NearChannel for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = CompoundNearConnectorConfig<TLS>;
    type Endpoint = CompoundNearConnectorEndpoint;
    type Conn = CompoundNearClientConn;
    type StartError = CompoundNearConnectorStartError;

    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        match self {
            CompoundNearConnector::Unix { unix } => {
                let out = unix.start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::Unix {
                        err: err
                    })?
                    .map(|unix| CompoundNearConnectorState::Unix {
                        unix: unix
                    });

                Ok(out)
            }
            CompoundNearConnector::TCP { tcp } => {
                let out = tcp.start(registry, token)
                    .map_err(|err| CompoundNearConnectorStartError::TCP {
                        err: err
                    })?
                    .map(|tcp| CompoundNearConnectorState::TCP { tcp: tcp });

                Ok(out)
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                let out = socks5.start(registry, token)?
                    .map(|socks5| CompoundNearConnectorState::SOCKS5 {
                        socks5: Box::new(socks5)
                    });

                Ok(out)
            }
            CompoundNearConnector::TLS { tls } => tls.start(registry, token)
        }
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        pending: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        match (self, pending) {
            (CompoundNearConnector::TLS { tls },
             CompoundNearConnectorNegotiateError::TLS { tls: err }) => {
                tls.cleanup(registry, *err)
            }
            _ => Err(Error::new(ErrorKind::Other, "mismatch in cleanup"))
        }
    }
}

impl<TLS> NearChannelCreate for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type CreateError = CompoundNearConnectorCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: CompoundNearConnectorConfig<TLS>
    ) -> Result<Self, CompoundNearConnectorCreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundNearConnectorConfig::Unix { unix_stream } => {
                let acc = UnixNearConnector::new(caches, unix_stream)
                    .map_err(|err| {
                        CompoundNearConnectorCreateError::Unix { unix: err }
                    })?;

                Ok(CompoundNearConnector::Unix { unix: acc })
            }
            CompoundNearConnectorConfig::TCP { tcp } => {
                let acc =
                    TCPNearConnector::new(caches, tcp).map_err(|err| {
                        CompoundNearConnectorCreateError::TCP { tcp: err }
                    })?;

                Ok(CompoundNearConnector::TCP { tcp: acc })
            }
            CompoundNearConnectorConfig::TLS { tls } => {
                let acc =
                    TLSNearConnector::new(caches, tls).map_err(|err| {
                        CompoundNearConnectorCreateError::TLS {
                            tls: Box::new(err)
                        }
                    })?;

                Ok(CompoundNearConnector::TLS { tls: acc })
            }
            CompoundNearConnectorConfig::SOCKS5 { socks5_tcp } => {
                SOCKS5NearConnector::new(caches, socks5_tcp)
                    .map(|acc| CompoundNearConnector::SOCKS5 { socks5: acc })
            }
        }
    }
}

impl<TLS> Negotiator<(CompoundNearClientConn, CompoundNearConnectorEndpoint)>
    for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type State = CompoundNearConnectorState;
    type Pending = CompoundNearConnectorNegotiatePending;
    type NegotiateError = CompoundNearConnectorNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(CompoundNearClientConn,
                          CompoundNearConnectorEndpoint),
                         CompoundNearConnectorNegotiatePending>,
        Self::NegotiateError
    > {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: CompoundNearConnectorNegotiatePending
    ) -> Result<
        NegotiatorResult<(CompoundNearClientConn,
                          CompoundNearConnectorEndpoint),
                         CompoundNearConnectorNegotiatePending>,
        Self::NegotiateError
    > {
        self.as_ref().complete_negotiate(err)
    }
}

impl<TLS> NearChannel for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = Box<CompoundNearConnectorConfig<TLS>>;
    type Endpoint = CompoundNearConnectorEndpoint;
    type Conn = CompoundNearClientConn;
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
    fn cleanup(
        &mut self,
        registry: &Registry,
        err: CompoundNearConnectorNegotiateError
    ) -> Result<(), Error> {
        self.as_mut().cleanup(registry, err)
    }
}

impl<TLS> NearChannelCreate for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type CreateError = CompoundNearConnectorCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Box<CompoundNearConnectorConfig<TLS>>
    ) -> Result<Self, CompoundNearConnectorCreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundNearConnector::new(caches, *config)
            .map(Box::new)
    }
}

impl<TLS> NearConnector for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type EndpointRef<'a>
        = CompoundNearConnectorEndpointRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        match self {
            CompoundNearConnector::Unix { unix } => {
                CompoundNearConnectorEndpointRef::Unix {
                    unix: unix.endpoint()
                }
            }
            CompoundNearConnector::TCP { tcp } => {
                CompoundNearConnectorEndpointRef::TCP {
                    tcp: tcp.endpoint()
                }
            }
            CompoundNearConnector::TLS { tls } => {
                CompoundNearConnectorEndpointRef::TLS {
                    tls: Box::new(tls.endpoint())
                }
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                CompoundNearConnectorEndpointRef::SOCKS5 {
                    socks5: Box::new(socks5.endpoint())
                }
            }
        }
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        match conf {
            CompoundNearConnectorConfig::Unix { unix_stream } => {
                UnixNearConnector::verify_endpoint(unix_stream)
            }
            CompoundNearConnectorConfig::TCP { tcp } => {
                TCPNearConnector::verify_endpoint(tcp)
            }
            CompoundNearConnectorConfig::TLS { tls } => {
                TLSNearConnector::<Box<Self>, TLS>::verify_endpoint(tls)
            }
            CompoundNearConnectorConfig::SOCKS5 { socks5_tcp } => {
                SOCKS5NearConnector::<Box<Self>>::verify_endpoint(socks5_tcp)
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
        = CompoundNearConnectorEndpointRef<'a>
    where
        TLS: 'a;

    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.as_ref().endpoint()
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        match conf.as_ref() {
            CompoundNearConnectorConfig::Unix { unix_stream } => {
                UnixNearConnector::verify_endpoint(unix_stream)
            }
            CompoundNearConnectorConfig::TCP { tcp } => {
                TCPNearConnector::verify_endpoint(tcp)
            }
            CompoundNearConnectorConfig::TLS { tls } => {
                TLSNearConnector::<Self, TLS>::verify_endpoint(tls)
            }
            CompoundNearConnectorConfig::SOCKS5 { socks5_tcp } => {
                SOCKS5NearConnector::<Self>::verify_endpoint(socks5_tcp)
            }
        }
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
use crate::near::accept_one;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::write_one;
#[cfg(test)]
use crate::near::negotiate_one;
#[cfg(test)]
use crate::config::tls::TLSClientConfig;
#[cfg(test)]
use crate::config::tls::TLSServerConfig;
#[cfg(test)]
use crate::init;
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
    let client_conf: CompoundNearConnectorConfig<TLSClientConfig> =
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
            CompoundNearAcceptor::new(&mut server_nscaches, server_conf)
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
        let mut conn =
            CompoundNearConnector::new(&mut client_nscaches, client_conf)
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
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
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
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: test/data/certs/client/private/test_client_key.pem\n",
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
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
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
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: test/data/certs/client/private/test_client_key.pem\n",
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
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
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
        "          - test/data/certs/client/ca_cert.pem\n",
        "        crls: []\n",
        "    cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "    key: test/data/certs/server/private/test_server_key.pem\n",
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
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: test/data/certs/client/private/test_client_key.pem\n",
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
        "        - test/data/certs/server/ca_cert.pem\n",
        "      crls: []\n",
        "    client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "    client-key: test/data/certs/client/private/test_client_key.pem\n",
        "    verify-endpoint: test-server.nowhere.com\n",
        "    tcp:\n",
        "      addr: localhost\n",
        "      port: 8003\n"
    );

    test_compound(SERVER_CONF, CLIENT_CONF)
}
