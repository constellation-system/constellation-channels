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
//!
//! # Examples
//!
//! The following is an example of connecting, sending, and
//! receiving over TLS:
//!
//! ```
//! # use constellation_channels::config::TCPNearAcceptorConfig;
//! # use constellation_channels::config::TCPNearConnectorConfig;
//! # use constellation_channels::config::TLSNearAcceptorConfig;
//! # use constellation_channels::config::TLSNearConnectorConfig;
//! # use constellation_channels::config::tls::TLSClientConfig;
//! # use constellation_channels::config::tls::TLSServerConfig;
//! # use constellation_channels::near::NearChannel;
//! # use constellation_channels::near::NearChannelCreate;
//! # use constellation_channels::near::NearConnector;
//! # use constellation_channels::near::tcp::TCPNearConnector;
//! # use constellation_channels::near::tcp::TCPNearAcceptor;
//! # use constellation_channels::near::tls::TLSNearConnector;
//! # use constellation_channels::near::tls::TLSNearAcceptor;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use std::net::Shutdown;
//! # use std::thread::spawn;
//! # use std::io::Read;
//! # use std::io::Write;
//! #
//! const CLIENT_CONF: &'static str = concat!(
//!     "trust-root:\n",
//!     "  root-certs:\n",
//!     "    - test/data/certs/server/ca_cert.pem\n",
//!     "  crls: []\n",
//!     "client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
//!     "client-key: test/data/certs/client/private/test_client_key.pem\n",
//!     "verify-endpoint: test-server.nowhere.com\n",
//!     "addr: localhost\n",
//!     "port: 8007\n"
//! );
//! const SERVER_CONF: &'static str = concat!(
//!     "client-auth:\n",
//!     "  verify: required\n",
//!     "  trust-root:\n",
//!     "    root-certs:\n",
//!     "      - test/data/certs/client/ca_cert.pem\n",
//!     "    crls: []\n",
//!     "cert: test/data/certs/server/certs/test_server_cert.pem\n",
//!     "key: test/data/certs/server/private/test_server_key.pem\n",
//!     "addr: ::1\n",
//!     "port: 8007\n"
//! );
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//!
//! let client_conf: TLSNearConnectorConfig<TCPNearConnectorConfig> =
//!     serde_yaml::from_str(CLIENT_CONF).unwrap();
//! let server_conf: TLSNearAcceptorConfig<TCPNearAcceptorConfig> =
//!     serde_yaml::from_str(SERVER_CONF).unwrap();
//! let nscaches = SharedNSNameCaches::new();
//!
//! let mut server_nscaches = nscaches.clone();
//! let listen = spawn(move || {
//!     let mut acceptor: TLSNearAcceptor<TCPNearAcceptor, TLSServerConfig> =
//!         TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();
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
//!     let mut conn: TLSNearConnector<TCPNearConnector, TLSClientConfig> =
//!         TLSNearConnector::new(&mut client_nscaches, client_conf)
//!             .expect("expected success");
//!     let (mut receiver, mut sender, _) =
//!         conn.connection().expect("expected success");
//!     let n = sender.write(&FIRST_BYTES).expect("Expected success");
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!
//!     receiver.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(FIRST_BYTES.len(), n);
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! listen.join().unwrap();
//! send.join().unwrap();
//! ```

#[cfg(feature = "openssl")]
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use log::info;
use log::warn;
#[cfg(feature = "openssl")]
use openssl::ssl::HandshakeError;
#[cfg(feature = "openssl")]
use openssl::ssl::ShutdownResult;
#[cfg(feature = "openssl")]
use openssl::ssl::SslAcceptor;
#[cfg(feature = "openssl")]
use openssl::ssl::SslConnector;
#[cfg(feature = "openssl")]
use openssl::ssl::SslStream;

use crate::config::tls::TLSLoadClient;
use crate::config::tls::TLSLoadConfigError;
use crate::config::tls::TLSLoadServer;
use crate::config::TLSChannelConfig;
use crate::near::session::NearSessionConnector;
use crate::near::session::NearSessionCreateError;
use crate::near::session::NearSessionParams;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

/// Wrapper for TLS sessions.
pub struct TLSStream<S: Read + Write, Endpoint: Display> {
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

#[cfg(feature = "openssl")]
/// Errors that can occur while setting up a TLS connection.
#[derive(Debug)]
pub enum TLSConnectionError<E, S> {
    /// Error during TLS negotations.
    TLS {
        /// TLS-specific error.
        error: HandshakeError<S>
    },
    /// Error obtaining underlying connection.
    Connection {
        /// Error from obtaining the connection.
        error: E
    }
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
/// typically only useful for testing purposes).  It is even possible
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
///     TLSNearAcceptor::new(&mut nscaches, accept_config).unwrap();
/// ```
///
/// ## Accepting Connections
///
/// Once a `TLSNearAcceptor` has been created, connections can be accepted
/// using the [take_connection](NearChannel::take_connection)
/// function.
pub struct TLSNearAcceptor<A: NearChannel, TLS: TLSLoadServer> {
    tls: PhantomData<TLS>,
    /// The configuration for establishing TLS sessions.
    #[cfg(feature = "openssl")]
    acceptor: SslAcceptor,
    /// The underlying [NearChannel] instance for obtaining
    /// connections.
    inner: A
}

/// The [NearSocketParams] instance used by [NearSessionConnector].
#[doc(hidden)]
pub struct TLSNearConnectorParams<TLS: TLSLoadClient> {
    tls: PhantomData<TLS>,
    #[cfg(feature = "openssl")]
    connector: SslConnector,
    #[cfg(feature = "openssl")]
    domain: String
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
/// # use constellation_channels::near::tcp::TCPNearConnector;
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
/// let connector: TLSNearConnector<TCPNearConnector, TLSClientConfig> =
///     TLSNearConnector::new(&mut nscaches, accept_config).unwrap();
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
pub type TLSNearConnector<Conn, TLS> =
    NearSessionConnector<TLSNearConnectorParams<TLS>, Conn>;

impl ScopedError for TLSCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            TLSCreateError::TLS { error } => error.scope(),
            TLSCreateError::NoName => ErrorScope::System
        }
    }
}

impl<E, S> ScopedError for TLSConnectionError<E, S>
where
    E: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            TLSConnectionError::TLS { error } => error.scope(),
            TLSConnectionError::Connection { error } => error.scope()
        }
    }
}

impl<A, TLS> NearChannel for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannel,
    A::Stream: Credentials
{
    type Config = TLSChannelConfig<TLS, A::Config>;
    type Endpoint = A::Endpoint;
    #[cfg(feature = "openssl")]
    type Stream = TLSStream<A::Stream, A::Endpoint>;
    #[cfg(feature = "openssl")]
    type TakeConnectError = TLSConnectionError<A::TakeConnectError, A::Stream>;

    #[cfg(feature = "openssl")]
    fn take_connection(
        &mut self
    ) -> Result<
        (Self::Stream, Self::Endpoint),
        TLSConnectionError<A::TakeConnectError, A::Stream>
    > {
        let (stream, endpoint) = self
            .inner
            .take_connection()
            .map_err(|err| TLSConnectionError::Connection { error: err })?;
        let stream = self
            .acceptor
            .accept(stream)
            .map_err(|err| TLSConnectionError::TLS { error: err })?;

        Ok((
            TLSStream {
                ssl: stream,
                peer: endpoint.clone()
            },
            endpoint
        ))
    }
}

impl<A, TLS> NearChannelCreate for TLSNearAcceptor<A, TLS>
where
    TLS: TLSLoadServer,
    A: NearChannelCreate,
    A::Stream: Credentials
{
    type CreateError = NearSessionCreateError<TLSCreateError, A::CreateError>;

    #[cfg(feature = "openssl")]
    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: TLSChannelConfig<TLS, A::Config>
    ) -> Result<TLSNearAcceptor<A, TLS>, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (tls, endpoint) = config.take();
        let acceptor = tls.load_server(None, false).map_err(|err| {
            NearSessionCreateError::Session {
                error: TLSCreateError::TLS { error: err }
            }
        })?;
        let inner = A::new(caches, endpoint)
            .map_err(|err| NearSessionCreateError::Channel { error: err })?;

        Ok(TLSNearAcceptor {
            tls: PhantomData,
            inner: inner,
            acceptor: acceptor
        })
    }
}

impl<Conn, TLS> NearSessionParams<Conn> for TLSNearConnectorParams<TLS>
where
    Conn: NearConnector,
    TLS: TLSLoadClient
{
    type Config = TLSChannelConfig<TLS, Conn::Config>;
    type CreateError = TLSCreateError;
    #[cfg(feature = "openssl")]
    type NegotiateError = HandshakeError<Conn::Stream>;
    #[cfg(feature = "openssl")]
    type Value = TLSStream<Conn::Stream, Conn::Endpoint>;

    const NAME: &'static str = "TLS";

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Conn::verify_endpoint(config.underlying())
    }

    #[cfg(feature = "openssl")]
    fn create(
        config: Self::Config
    ) -> Result<(Self, Conn::Config), Self::CreateError> {
        let (tls, inner) = config.take();
        // Note: this is not the IP address to which we are
        // connecting, but what we'll use to verify certificates.
        let verify_endpoint = match tls.verify_endpoint() {
            Some(endpoint) => Ok(endpoint),
            None => match Conn::verify_endpoint(&inner) {
                Some(endpoint) => Ok(endpoint),
                None => Err(TLSCreateError::NoName)
            }
        }?;
        let connector = tls
            .load_client(None, verify_endpoint, false)
            .map_err(|err| TLSCreateError::TLS { error: err })?;
        let domain = match verify_endpoint {
            IPEndpointAddr::Name(name) => match name.find('.') {
                Some(idx) => {
                    let (_, domain) = name.split_at(idx);

                    String::from(domain)
                }
                None => String::new()
            },
            IPEndpointAddr::Addr(_) => String::new()
        };

        Ok((
            TLSNearConnectorParams {
                tls: PhantomData,
                domain: domain,
                connector: connector
            },
            inner
        ))
    }

    #[cfg(feature = "openssl")]
    #[inline]
    fn negotiate(
        &mut self,
        stream: Conn::Stream,
        endpoint: &Conn::Endpoint
    ) -> Result<
        TLSStream<Conn::Stream, Conn::Endpoint>,
        HandshakeError<Conn::Stream>
    > {
        let stream = self.connector.connect(self.domain.as_str(), stream)?;

        Ok(TLSStream {
            ssl: stream,
            peer: endpoint.clone()
        })
    }
}

impl<S, Endpoint> Credentials for TLSStream<S, Endpoint>
where
    S: Credentials + Read + Write,
    Endpoint: Display
{
    type Cred<'a> = SSLCred<'a, S::Cred<'a>>
    where Self: 'a;
    type CredError = S::CredError;

    #[inline]
    fn creds(&self) -> Result<Option<SSLCred<S::Cred<'_>>>, S::CredError> {
        self.ssl.creds()
    }
}

impl<S, Endpoint> CredentialsMut for TLSStream<S, Endpoint>
where
    S: Credentials + Read + Write,
    Endpoint: Display
{
    type Cred<'a> = SSLCred<'a, S::Cred<'a>>
    where Self: 'a;
    type CredError = S::CredError;

    #[inline]
    fn creds(&mut self) -> Result<Option<SSLCred<S::Cred<'_>>>, S::CredError> {
        <Self as Credentials>::creds(self)
    }
}

impl<S, Endpoint> Drop for TLSStream<S, Endpoint>
where
    S: Read + Write,
    Endpoint: Display
{
    fn drop(&mut self) {
        loop {
            match self.ssl.shutdown() {
                Ok(ShutdownResult::Sent) => {
                    info!(target: "far-dtls",
                          "shutting down TLS session with {}",
                          self.peer);
                }
                Ok(ShutdownResult::Received) => {
                    info!(target: "far-dtls",
                          "TLS session with {} successfully shut down",
                          self.peer);

                    return;
                }
                Err(err) => {
                    warn!(target: "far-dtls",
                          "error shutting down DTLS session with {}: {}",
                          self.peer, err);

                    return;
                }
            }
        }
    }
}

impl<S, Endpoint> Read for TLSStream<S, Endpoint>
where
    S: Read + Write,
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

impl<S, Endpoint> Write for TLSStream<S, Endpoint>
where
    S: Read + Write,
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

impl<S, Endpoint> Debug for TLSStream<S, Endpoint>
where
    S: Read + Write + Debug,
    Endpoint: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "TLSStream {{ ssl: {:?}, peer: {} }}",
            self.ssl, self.peer
        )
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

#[cfg(feature = "openssl")]
impl<E, S> Display for TLSConnectionError<E, S>
where
    E: Display,
    S: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSConnectionError::Connection { error } => error.fmt(f),
            TLSConnectionError::TLS { error } => write!(f, "{}", error)
        }
    }
}

#[cfg(test)]
use std::fs::metadata;
#[cfg(test)]
use std::thread::sleep;
#[cfg(test)]
use std::thread::spawn;
#[cfg(test)]
use std::time::Duration;

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
use crate::config::UnixNearConnectorConfig;
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

#[test]
fn test_tls_negotiate() {
    init();

    const PATH: &'static str = "test_tls_negotiate.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearConnectorConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(server_conf.underlying().path()).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();

        acceptor.take_connection().expect("Expected success");
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let _ = conn.connection().expect("expected success");
    });
    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_tls_send() {
    init();

    const PATH: &'static str = "test_tls_send.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearConnectorConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(server_conf.underlying().path()).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        server_barrier.wait();

        stream.read_exact(&mut buf).expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (_, mut sender, _) = conn.connection().expect("expected success");
        let n = sender.write(&FIRST_BYTES).expect("Expected success");

        sender.flush().expect("Expected success");

        client_barrier.wait();

        assert_eq!(FIRST_BYTES.len(), n);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_tls_recv() {
    init();

    const PATH: &'static str = "test_tls_recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearConnectorConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(server_conf.underlying().path()).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        stream.write_all(&FIRST_BYTES).unwrap();
        stream.flush().unwrap();
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut receiver, _, _) = conn.connection().expect("expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        receiver.read_exact(&mut buf).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_tls_send_recv() {
    init();

    const PATH: &'static str = "test_tls_send_recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearConnectorConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(server_conf.underlying().path()).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();

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
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");
        let n = sender.write(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        receiver.read_exact(&mut buf).unwrap();

        assert_eq!(FIRST_BYTES.len(), n);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_tls_recv_send() {
    init();

    const PATH: &'static str = "test_tls_recv_send.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearConnectorConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(server_conf.underlying().path()).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::new(&mut server_nscaches, server_conf).unwrap();

        let (mut stream, _) =
            acceptor.take_connection().expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        stream.write_all(&FIRST_BYTES).unwrap();
        stream.flush().unwrap();
        stream.read_exact(&mut buf).unwrap();

        assert_eq!(SECOND_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::new(&mut client_nscaches, client_conf)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        receiver.read_exact(&mut buf).unwrap();

        let n = sender.write(&SECOND_BYTES).expect("Expected success");

        sender.flush().unwrap();

        assert_eq!(SECOND_BYTES.len(), n);
        assert_eq!(FIRST_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}
