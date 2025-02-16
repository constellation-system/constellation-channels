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
//!
//! ### Examples
//!
//! The following shows an example use of [CompoundNearAcceptor] and
//! [CompoundNearConnector] establishing a TLS session over TCP (note
//! that `CLIENT_CONFIG` and `SERVER_CONFIG` can be modified to
//! support any alternate configuration):
//!
//! ```
//! # use constellation_channels::config::CompoundNearAcceptorConfig;
//! # use constellation_channels::config::CompoundNearConnectorConfig;
//! # use constellation_channels::config::tls::TLSClientConfig;
//! # use constellation_channels::config::tls::TLSServerConfig;
//! # use constellation_channels::near::NearChannel;
//! # use constellation_channels::near::NearChannelCreate;
//! # use constellation_channels::near::NearConnector;
//! # use constellation_channels::near::compound::CompoundNearAcceptor;
//! # use constellation_channels::near::compound::CompoundNearConnector;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use std::io::Read;
//! # use std::io::Write;
//! # use std::thread::spawn;
//! #
//! const SERVER_CONF: &'static str = concat!(
//!     "tls:\n",
//!     "  cipher-suites:\n",
//!     "    - TLS_AES_256_GCM_SHA384\n",
//!     "    - TLS_CHACHA20_POLY1305_SHA256\n",
//!     "  key-exchange-groups:\n",
//!     "    - X25519\n",
//!     "    - P-256\n",
//!     "  client-auth:\n",
//!     "    verify: required\n",
//!     "    trust-root:\n",
//!     "      root-certs:\n",
//!     "        - test/data/certs/client/ca_cert.pem\n",
//!     "      crls: []\n",
//!     "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
//!     "  key: test/data/certs/server/private/test_server_key.pem\n",
//!     "  tcp:\n",
//!     "    addr: ::0\n",
//!     "    port: 8000\n"
//! );
//! const CLIENT_CONF: &'static str = concat!(
//!     "tls:\n",
//!     "  cipher-suites:\n",
//!     "    - TLS_AES_256_GCM_SHA384\n",
//!     "    - TLS_CHACHA20_POLY1305_SHA256\n",
//!     "  key-exchange-groups:\n",
//!     "    - X25519\n",
//!     "    - P-256\n",
//!     "  trust-root:\n",
//!     "    root-certs:\n",
//!     "      - test/data/certs/server/ca_cert.pem\n",
//!     "    crls: []\n",
//!     "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
//!     "  client-key: test/data/certs/client/private/test_client_key.pem\n",
//!     "  verify-endpoint: test-server.nowhere.com\n",
//!     "  tcp:\n",
//!     "    addr: localhost\n",
//!     "    port: 8000\n"
//! );
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//!
//! let client_conf: CompoundNearConnectorConfig<TLSClientConfig> =
//!     serde_yaml::from_str(&CLIENT_CONF).unwrap();
//! let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
//!     serde_yaml::from_str(SERVER_CONF).unwrap();
//! let nscaches = SharedNSNameCaches::new();
//!
//! let mut server_nscaches = nscaches.clone();
//! let listen = spawn(move || {
//!     let mut acceptor =
//!         CompoundNearAcceptor::new(&mut server_nscaches, server_conf)
//!             .unwrap();
//!
//!     let (mut stream, _) =
//!         acceptor.take_connection().expect("Expected success");
//!
//!     let mut buf = [0; FIRST_BYTES.len()];
//!
//!     stream.read_exact(&mut buf).unwrap();
//!     stream.flush().unwrap();
//!     stream.write_all(&SECOND_BYTES).unwrap();
//!
//!     assert_eq!(FIRST_BYTES, buf);
//! });
//!
//! let mut client_nscaches = nscaches.clone();
//! let send = spawn(move || {
//!     let mut conn =
//!         CompoundNearConnector::new(&mut client_nscaches, client_conf)
//!             .expect("expected success");
//!     let (mut stream, _) =  conn.connection().expect("expected success");
//!     let n = stream.write(&FIRST_BYTES).expect("Expected success");
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!
//!     stream.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(FIRST_BYTES.len(), n);
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! listen.join().unwrap();
//! send.join().unwrap();
//! ```
use std::convert::Infallible;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
#[cfg(feature = "unix")]
use std::os::unix::net::UCred;
#[cfg(feature = "unix")]
use std::os::unix::net::UnixStream;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
#[cfg(feature = "tls")]
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::error::WithMutexPoison;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5Stream;
use constellation_streams::channels::ChannelParam;

#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadClient;
#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadServer;
use crate::config::CompoundNearAcceptorConfig;
use crate::config::CompoundNearConnectorConfig;
#[cfg(feature = "tls")]
use crate::near::session::NearSessionCreateError;
use crate::near::socks5::SOCKS5NearConnector;
use crate::near::tcp::TCPNearAcceptor;
use crate::near::tcp::TCPNearConnector;
use crate::near::tcp::TCPNearConnectorError;
use crate::near::tcp::TCPStream;
#[cfg(feature = "tls")]
use crate::near::tls::TLSConn;
#[cfg(feature = "tls")]
use crate::near::tls::TLSConnectionError;
#[cfg(feature = "tls")]
use crate::near::tls::TLSCreateError;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNearAcceptor;
#[cfg(feature = "tls")]
use crate::near::tls::TLSNearConnector;
#[cfg(feature = "unix")]
use crate::near::unix::UnixNearAcceptor;
#[cfg(feature = "unix")]
use crate::near::unix::UnixNearConnector;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearConn;
use crate::near::NearConnectError;
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
#[derive(Clone)]
pub enum CompoundNearConnectorEndpoint {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketPath
    },
    TCP {
        tcp: IPEndpoint
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
            NearSessionCreateError<
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
    TCP {
        tcp: TCPNearConnectorError
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            NearSessionCreateError<
                TLSCreateError,
                CompoundNearConnectorCreateError
            >
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            NearSessionCreateError<
                Infallible,
                CompoundNearConnectorCreateError
            >
        >
    }
}

/// Multiplexer for [TakeConnectError](NearChannel::TakeConnectError)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearAcceptorTakeConnectError {
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
            TLSConnectionError<
                CompoundNearAcceptorTakeConnectError,
                CompoundNearServerConn
            >
        >
    }
}

/// Multiplexer for [TakeConnectError](NearChannel::TakeConnectError)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearConnectorTakeConnectError {
    #[cfg(feature = "unix")]
    Unix {
        unix: NearConnectError
    },
    TCP {
        tcp: NearConnectError
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: NearConnectError
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: NearConnectError
    }
}

/// Errors that can happen while harvesting credentials.
pub enum CompoundNearCredentialError {
    Unix { err: Error },
    TCP { err: Error }
}

/// Multiplexer for [OwnedConn](NearChannel::OwnedConn)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearClientOwnedConn {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixStream
    },
    TCP {
        tcp: TCPStream
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<
            TLSConn<CompoundNearClientOwnedConn, CompoundNearConnectorEndpoint>
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5Stream<CompoundNearClientOwnedConn>>
    }
}

/// Multiplexer for [Conn](NearChannel::Conn)s for
/// [CompoundNearConnector].
#[derive(Debug)]
pub enum CompoundNearClientConn {
    #[cfg(feature = "unix")]
    Unix {
        unix: NearConn<UnixStream>
    },
    TCP {
        tcp: NearConn<TCPStream>
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: NearConn<
            TLSConn<CompoundNearClientOwnedConn, CompoundNearConnectorEndpoint>
        >
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: NearConn<SOCKS5Stream<CompoundNearClientOwnedConn>>
    }
}

/// Multiplexer for [Conn](NearChannel::Conn)s for
/// [CompoundNearAcceptor].
#[derive(Debug)]
pub enum CompoundNearServerConn {
    #[cfg(feature = "unix")]
    Unix {
        unix: <UnixNearAcceptor as NearChannel>::OwnedConn
    },
    TCP {
        tcp: <TCPNearAcceptor as NearChannel>::OwnedConn
    },
    #[cfg(feature = "tls")]
    TLS {
        tls: Box<TLSConn<CompoundNearServerConn, CompoundNearAcceptorEndpoint>>
    }
}

/// Credentials harvested by [Credentials]
pub enum CompoundNearCredential {
    #[cfg(feature = "unix")]
    Unix { unix: UCred },
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
            CompoundNearConnectorCreateError::TCP { tcp } => tcp.scope(),
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateError::TLS { tls } => tls.scope(),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorCreateError::SOCKS5 { socks5 } => {
                socks5.scope()
            }
        }
    }
}

impl ScopedError for CompoundNearAcceptorTakeConnectError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorTakeConnectError::Unix { unix } => unix.scope(),
            CompoundNearAcceptorTakeConnectError::TCP { tcp } => tcp.scope(),
            #[cfg(feature = "tls")]
            CompoundNearAcceptorTakeConnectError::TLS { tls } => tls.scope()
        }
    }
}

impl ScopedError for CompoundNearConnectorTakeConnectError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorTakeConnectError::Unix { unix } => {
                unix.scope()
            }
            CompoundNearConnectorTakeConnectError::TCP { tcp } => tcp.scope(),
            #[cfg(feature = "tls")]
            CompoundNearConnectorTakeConnectError::TLS { tls } => tls.scope(),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorTakeConnectError::SOCKS5 { socks5 } => {
                socks5.scope()
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
            CompoundNearConnectorCreateError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorCreateError::TLS { tls } => {
                write!(f, "{}", tls)
            }
            #[cfg(feature = "socks5")]
            CompoundNearConnectorCreateError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
        }
    }
}

impl Display for CompoundNearAcceptorTakeConnectError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearAcceptorTakeConnectError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundNearAcceptorTakeConnectError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearAcceptorTakeConnectError::TLS { tls } => {
                write!(f, "{}", tls)
            }
        }
    }
}

impl Display for CompoundNearConnectorTakeConnectError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            #[cfg(feature = "unix")]
            CompoundNearConnectorTakeConnectError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundNearConnectorTakeConnectError::TCP { tcp } => {
                write!(f, "{}", tcp)
            }
            #[cfg(feature = "tls")]
            CompoundNearConnectorTakeConnectError::TLS { tls } => {
                write!(f, "{}", tls)
            }
            #[cfg(feature = "socks5")]
            CompoundNearConnectorTakeConnectError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
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
            CompoundNearConnectorEndpoint::TLS { tls } => tls.fmt(f),
            #[cfg(feature = "socks5")]
            CompoundNearConnectorEndpoint::SOCKS5 { socks5 } => socks5.fmt(f)
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

impl Credentials for CompoundNearClientOwnedConn {
    type Cred = CompoundNearCredential;
    type CredError = CompoundNearCredentialError;

    #[inline]
    fn creds(
        &self
    ) -> Result<Option<CompoundNearCredential>, CompoundNearCredentialError>
    {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => {
                let cred = unix.creds().map_err(|err| {
                    CompoundNearCredentialError::Unix { err: err }
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::Unix { unix: cred }))
            }
            CompoundNearClientOwnedConn::TCP { tcp } => {
                let cred = tcp.creds().map_err(|err| {
                    CompoundNearCredentialError::TCP { err: err }
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::UnsafeTCP {
                    unsafe_tcp: cred
                }))
            }
            CompoundNearClientOwnedConn::TLS { tls } => {
                let cred = tls.creds()?;

                Ok(cred.map(|cred| CompoundNearCredential::TLS {
                    tls: Box::new(cred)
                }))
            }
            _ => Ok(None)
        }
    }
}

impl CredentialsMut for CompoundNearClientOwnedConn {
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

impl Credentials for CompoundNearClientConn {
    type Cred = CompoundNearCredential;
    type CredError = WithMutexPoison<CompoundNearCredentialError>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<CompoundNearCredential>,
        WithMutexPoison<CompoundNearCredentialError>
    > {
        match self {
            CompoundNearClientConn::Unix { unix } => {
                let cred = unix.creds().map_err(|err| match err {
                    WithMutexPoison::Inner { error } => {
                        WithMutexPoison::Inner {
                            error: CompoundNearCredentialError::Unix {
                                err: error
                            }
                        }
                    }
                    WithMutexPoison::MutexPoison => WithMutexPoison::MutexPoison
                })?;

                Ok(cred.map(|cred| CompoundNearCredential::Unix { unix: cred }))
            }
            CompoundNearClientConn::TCP { tcp } => {
                let cred = tcp.creds().map_err(|err| match err {
                    WithMutexPoison::Inner { error } => {
                        WithMutexPoison::Inner {
                            error: CompoundNearCredentialError::Unix {
                                err: error
                            }
                        }
                    }
                    WithMutexPoison::MutexPoison => WithMutexPoison::MutexPoison
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
    type CredError = WithMutexPoison<CompoundNearCredentialError>;

    #[inline]
    fn creds(
        &mut self
    ) -> Result<
        Option<CompoundNearCredential>,
        WithMutexPoison<CompoundNearCredentialError>
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

impl Read for CompoundNearClientOwnedConn {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => unix.read(buf),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.read(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.read(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => socks5.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => {
                unix.read_vectored(bufs)
            }
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.read_vectored(bufs),
            CompoundNearClientOwnedConn::TLS { tls } => tls.read_vectored(bufs),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
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
            CompoundNearClientOwnedConn::Unix { unix } => unix.read_to_end(buf),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.read_to_end(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.read_to_end(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
                socks5.read_to_end(buf)
            }
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => {
                unix.read_to_string(buf)
            }
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.read_to_string(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.read_to_string(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
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
            CompoundNearClientOwnedConn::Unix { unix } => unix.read_exact(buf),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.read_exact(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.read_exact(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
                socks5.read_exact(buf)
            }
        }
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

impl Write for CompoundNearClientOwnedConn {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => unix.write(buf),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.write(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.write(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => socks5.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => {
                unix.write_vectored(bufs)
            }
            CompoundNearClientOwnedConn::TCP { tcp } => {
                tcp.write_vectored(bufs)
            }
            CompoundNearClientOwnedConn::TLS { tls } => {
                tls.write_vectored(bufs)
            }
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
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
            CompoundNearClientOwnedConn::Unix { unix } => unix.write_all(buf),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.write_all(buf),
            CompoundNearClientOwnedConn::TLS { tls } => tls.write_all(buf),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => {
                socks5.write_all(buf)
            }
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundNearClientOwnedConn::Unix { unix } => unix.flush(),
            CompoundNearClientOwnedConn::TCP { tcp } => tcp.flush(),
            CompoundNearClientOwnedConn::TLS { tls } => tls.flush(),
            CompoundNearClientOwnedConn::SOCKS5 { socks5 } => socks5.flush()
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

impl<TLS> NearChannel for CompoundNearAcceptor<TLS>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = CompoundNearAcceptorConfig<TLS>;
    type Endpoint = CompoundNearAcceptorEndpoint;
    type OwnedConn = CompoundNearServerConn;
    type TakeConnectError = CompoundNearAcceptorTakeConnectError;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<
        (Self::OwnedConn, Self::Endpoint),
        CompoundNearAcceptorTakeConnectError
    > {
        match self {
            CompoundNearAcceptor::Unix { unix } => {
                let (stream, endpoint) =
                    unix.take_connection().map_err(|err| {
                        CompoundNearAcceptorTakeConnectError::Unix { unix: err }
                    })?;

                Ok((
                    CompoundNearServerConn::Unix { unix: stream },
                    CompoundNearAcceptorEndpoint::Unix { unix: endpoint }
                ))
            }
            CompoundNearAcceptor::TCP { tcp } => {
                let (stream, endpoint) =
                    tcp.take_connection().map_err(|err| {
                        CompoundNearAcceptorTakeConnectError::TCP { tcp: err }
                    })?;

                Ok((
                    CompoundNearServerConn::TCP { tcp: stream },
                    CompoundNearAcceptorEndpoint::TCP { tcp: endpoint }
                ))
            }
            CompoundNearAcceptor::TLS { tls } => {
                let (stream, endpoint) =
                    tls.take_connection().map_err(|err| {
                        CompoundNearAcceptorTakeConnectError::TLS {
                            tls: Box::new(err)
                        }
                    })?;

                Ok((
                    CompoundNearServerConn::TLS {
                        tls: Box::new(stream)
                    },
                    endpoint
                ))
            }
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
                let acc =
                    UnixNearAcceptor::new(caches, unix_stream).map_err(|err| {
                        CompoundNearAcceptorCreateError::Unix { unix: err }
                    })?;

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

impl<TLS> NearChannel for Box<CompoundNearAcceptor<TLS>>
where
    TLS: Clone + Debug + TLSLoadServer
{
    type Config = Box<CompoundNearAcceptorConfig<TLS>>;
    type Endpoint = CompoundNearAcceptorEndpoint;
    type OwnedConn = CompoundNearServerConn;
    type TakeConnectError = CompoundNearAcceptorTakeConnectError;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<
        (Self::OwnedConn, Self::Endpoint),
        CompoundNearAcceptorTakeConnectError
    > {
        self.as_mut().take_connection()
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

impl<TLS> NearChannel for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = CompoundNearConnectorConfig<TLS>;
    type Endpoint = CompoundNearConnectorEndpoint;
    type OwnedConn = CompoundNearClientOwnedConn;
    type TakeConnectError = CompoundNearConnectorTakeConnectError;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<
        (Self::OwnedConn, Self::Endpoint),
        CompoundNearConnectorTakeConnectError
    > {
        match self {
            CompoundNearConnector::Unix { unix } => {
                let (stream, endpoint) =
                    unix.take_connection().map_err(|err| {
                        CompoundNearConnectorTakeConnectError::Unix {
                            unix: err
                        }
                    })?;

                Ok((
                    CompoundNearClientOwnedConn::Unix { unix: stream },
                    CompoundNearConnectorEndpoint::Unix { unix: endpoint }
                ))
            }
            CompoundNearConnector::TCP { tcp } => {
                let (stream, endpoint) =
                    tcp.take_connection().map_err(|err| {
                        CompoundNearConnectorTakeConnectError::TCP { tcp: err }
                    })?;

                Ok((
                    CompoundNearClientOwnedConn::TCP { tcp: stream },
                    CompoundNearConnectorEndpoint::TCP { tcp: endpoint }
                ))
            }
            CompoundNearConnector::TLS { tls } => {
                let (stream, endpoint) =
                    tls.take_connection().map_err(|err| {
                        CompoundNearConnectorTakeConnectError::TLS { tls: err }
                    })?;

                Ok((
                    CompoundNearClientOwnedConn::TLS {
                        tls: Box::new(stream)
                    },
                    endpoint
                ))
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                let (stream, endpoint) =
                    socks5.take_connection().map_err(|err| {
                        CompoundNearConnectorTakeConnectError::SOCKS5 {
                            socks5: err
                        }
                    })?;

                Ok((
                    CompoundNearClientOwnedConn::SOCKS5 {
                        socks5: Box::new(stream)
                    },
                    endpoint
                ))
            }
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
                let acc = UnixNearConnector::new(caches, unix_stream).unwrap();

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
                let acc = SOCKS5NearConnector::new(caches, socks5_tcp).map_err(
                    |err| CompoundNearConnectorCreateError::SOCKS5 {
                        socks5: Box::new(err)
                    }
                )?;

                Ok(CompoundNearConnector::SOCKS5 { socks5: acc })
            }
        }
    }
}

impl<TLS> NearChannel for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Config = Box<CompoundNearConnectorConfig<TLS>>;
    type Endpoint = CompoundNearConnectorEndpoint;
    type OwnedConn = CompoundNearClientOwnedConn;
    type TakeConnectError = CompoundNearConnectorTakeConnectError;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<
        (Self::OwnedConn, Self::Endpoint),
        CompoundNearConnectorTakeConnectError
    > {
        self.as_mut().take_connection()
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
        CompoundNearConnector::new(caches, config.as_ref().clone())
            .map(Box::new)
    }
}

impl<TLS> NearConnector for CompoundNearConnector<TLS>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
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

    fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error> {
        match self {
            CompoundNearConnector::Unix { unix } => unix.fail(nretries),
            CompoundNearConnector::TCP { tcp } => tcp.fail(nretries),
            CompoundNearConnector::TLS { tls } => tls.fail(nretries),
            CompoundNearConnector::SOCKS5 { socks5 } => socks5.fail(nretries)
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

    fn connection(
        &mut self
    ) -> Result<(Self::Conn, Self::EndpointRef<'_>), NearConnectError> {
        match self {
            CompoundNearConnector::Unix { unix } => {
                let (stream, endpoint) = unix.connection()?;

                Ok((
                    CompoundNearClientConn::Unix { unix: stream },
                    CompoundNearConnectorEndpointRef::Unix { unix: endpoint }
                ))
            }
            CompoundNearConnector::TCP { tcp } => {
                let (stream, endpoint) = tcp.connection()?;

                Ok((
                    CompoundNearClientConn::TCP { tcp: stream },
                    CompoundNearConnectorEndpointRef::TCP { tcp: endpoint }
                ))
            }
            CompoundNearConnector::TLS { tls } => {
                let (stream, endpoint) = tls.connection()?;

                Ok((
                    CompoundNearClientConn::TLS { tls: stream },
                    CompoundNearConnectorEndpointRef::TLS {
                        tls: Box::new(endpoint)
                    }
                ))
            }
            CompoundNearConnector::SOCKS5 { socks5 } => {
                let (stream, endpoint) = socks5.connection()?;

                Ok((
                    CompoundNearClientConn::SOCKS5 { socks5: stream },
                    CompoundNearConnectorEndpointRef::SOCKS5 {
                        socks5: Box::new(endpoint)
                    }
                ))
            }
        }
    }
}

impl<TLS> NearConnector for Box<CompoundNearConnector<TLS>>
where
    TLS: Clone + Debug + TLSLoadClient
{
    type Conn = CompoundNearClientConn;
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
    fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error> {
        self.as_mut().fail(nretries)
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.as_mut().shutdown()
    }

    #[inline]
    fn connection(
        &mut self
    ) -> Result<(Self::Conn, Self::EndpointRef<'_>), NearConnectError> {
        self.as_mut().connection()
    }
}

#[cfg(test)]
use std::thread::spawn;

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

#[test]
fn test_compound_tls_unix() {
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

    let client_conf: CompoundNearConnectorConfig<TLSClientConfig> =
        serde_yaml::from_str(&CLIENT_CONF).unwrap();
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        serde_yaml::from_str(SERVER_CONF).unwrap();
    let nscaches = SharedNSNameCaches::new();

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            CompoundNearAcceptor::new(&mut server_nscaches, server_conf)
                .unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.flush().unwrap();
        stream.write_all(&SECOND_BYTES).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            CompoundNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut stream, _) = conn.connection().expect("expected success");
        let n = stream.write(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();

        assert_eq!(FIRST_BYTES.len(), n);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
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

    let client_conf: CompoundNearConnectorConfig<TLSClientConfig> =
        serde_yaml::from_str(&CLIENT_CONF).unwrap();
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        serde_yaml::from_str(SERVER_CONF).unwrap();
    let nscaches = SharedNSNameCaches::new();

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            CompoundNearAcceptor::new(&mut server_nscaches, server_conf)
                .unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.flush().unwrap();
        stream.write_all(&SECOND_BYTES).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            CompoundNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut stream, _) = conn.connection().expect("expected success");
        let n = stream.write(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();

        assert_eq!(FIRST_BYTES.len(), n);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
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

    let client_conf: CompoundNearConnectorConfig<TLSClientConfig> =
        serde_yaml::from_str(&CLIENT_CONF).unwrap();
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        serde_yaml::from_str(SERVER_CONF).unwrap();
    let nscaches = SharedNSNameCaches::new();

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            CompoundNearAcceptor::new(&mut server_nscaches, server_conf)
                .unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.flush().unwrap();
        stream.write_all(&SECOND_BYTES).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            CompoundNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut stream, _) = conn.connection().expect("expected success");
        let n = stream.write(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();

        assert_eq!(FIRST_BYTES.len(), n);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}
