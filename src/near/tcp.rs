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

//! Near-link channels over TCP sockets.
//!
//! This module provides a [NearChannel] and
//! [NearConnector](crate::near::NearConnector) implementation over
//! TCP sockets.  [TCPNearAcceptor]s can be used to listen on a TCP
//! port.  [TCPNearConnector]s can be used to connect to remote TCP
//! ports.
//!
//! Note that connections established in this way are neither
//! authenticated nor secure inherently.
//!
//! # Examples
//!
//! The following is an example of connecting, sending, and
//! receiving over TCP:
//!
//! ```
//! # use constellation_channels::near::NearChannel;
//! # use constellation_channels::near::NearChannelCreate;
//! # use constellation_channels::near::NearConnector;
//! # use constellation_channels::near::tcp::TCPNearConnector;
//! # use constellation_channels::near::tcp::TCPNearAcceptor;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use std::net::Shutdown;
//! # use std::thread::spawn;
//! # use std::io::Read;
//! # use std::io::Write;
//! #
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! const SERVER_CONFIG: &'static str = concat!("addr: ::1\n",
//!                                             "port: 8004\n");
//! const CLIENT_CONFIG: &'static str = concat!("addr: localhost\n",
//!                                             "port: 8004\n");
//! let accept_config = serde_yaml::from_str(SERVER_CONFIG).unwrap();
//! let connect_config = serde_yaml::from_str(CLIENT_CONFIG).unwrap();
//! let nscaches = SharedNSNameCaches::new();
//!
//! let mut server_nscaches = nscaches.clone();
//! let listen = spawn(move || {
//!     let mut acceptor =
//!         TCPNearAcceptor::new(&mut server_nscaches, accept_config).unwrap();
//!     let (mut stream, _) = acceptor.take_connection().unwrap();
//!     let mut buf = [0; FIRST_BYTES.len()];
//!
//!     stream.read_exact(&mut buf).unwrap();
//!     stream.write_all(&SECOND_BYTES).expect("Expected success");
//!     stream.shutdown(Shutdown::Both).unwrap();
//!
//!     assert_eq!(FIRST_BYTES, buf);
//! });
//!
//! let mut client_nscaches = nscaches.clone();
//! let send = spawn(move || {
//!     let mut conn =
//!         TCPNearConnector::new(&mut client_nscaches, connect_config)
//!             .expect("expected success");
//!     let (mut receiver, mut sender, _) =
//!         conn.connection().expect("expected success");
//!
//!     sender.write_all(&FIRST_BYTES).expect("Expected success");
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!
//!     receiver.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! listen.join().unwrap();
//! send.join().unwrap();
//! ```

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::iter::repeat;
use std::iter::Repeat;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Instant;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::Retry;
use log::debug;
use log::info;
use log::trace;
use log::warn;

use crate::addrs::AddrMultiplexer;
use crate::addrs::AddrsCreateError;
use crate::config::TCPNearAcceptorConfig;
use crate::config::TCPNearConnectorConfig;
use crate::near::socket::NearSocketConnector;
use crate::near::socket::NearSocketParams;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::resolve::cache::NSNameCachesCtx;

/// Server side of a TCP socket near-link channel.
///
/// This is a [NearChannel] instance that listens for connections on a
/// TCP socket.  Communications over this channel are unauthenticated
/// and unprotected, unless another layer is used to secure the
/// channel.
///
/// # Usage
///
/// The primary usage of `TCPNearAcceptor` takes place through its
/// [NearChannel] instance.
///
/// ## Configuration and Creation
///
/// A `TCPNearAcceptor` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [TCPNearAcceptorConfig] as its principal argument, which supplies
/// all configuration unformation.
///
/// ### Example
///
/// The following example shows how to create a `TCPNearAcceptor`:
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPNearAcceptor;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!("addr: ::0\n",
///                                      "port: 8005\n");
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let mut acceptor = TCPNearAcceptor::new(&mut nscaches,
///                                         accept_config).unwrap();
/// ```
///
/// ## Accepting Connections
///
/// Once a `TCPNearAcceptor` has been created, connections can be accepted
/// using the [take_connection](NearChannel::take_connection)
/// function.
pub struct TCPNearAcceptor {
    unsafe_allow_ip_addr_creds: bool,
    /// The listener used to accept connections.
    listener: TcpListener
}

/// The [NearSocketParams] instance used by [NearSocketConnector].
#[doc(hidden)]
pub struct TCPNearConnectorParams {
    unsafe_allow_ip_addr_creds: bool,
    endpoint: IPEndpoint,
    addrs: AddrMultiplexer<Repeat<()>>
}

/// Client side of a TCP socket near-link channel.
///
/// This is a [NearChannel] and
/// [NearConnector](crate::near::NearConnector) instance that attempts
/// to connect to establish a TCP connection to a given address and
/// port.
///
/// # Usage
///
/// The primary use of a `TCPNearConnector` takes place through its
/// [NearChannel] and [NearConnector](crate::near::NearConnector) instances.
///
/// ## Configuration and Creation
///
/// A `TCPNearConnector` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [TCPNearConnectorConfig] as its principal argument, which supplies
/// all configuration unformation.
///
/// ### Example
///
/// The following example shows how to create a `TCPNearConnector`.
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!("addr: en.wikipedia.org\n",
///                                      "port: 443\n");
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector = TCPNearConnector::new(&mut nscaches,
///                                       accept_config).unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `TCPNearConnector` has been created, connections can be
/// established using the
/// [take_connection](NearChannel::take_connection) or
/// [connection](crate::near::NearConnector::connection) functions.  These will
/// block until a connection has been successfully established.  Note
/// that depending on the circumstances, this may involve many retries
/// and/or name resolutions.
pub type TCPNearConnector = NearSocketConnector<TCPNearConnectorParams>;

/// Errors that can occur when converting a [TCPNearConnectorConfig]
/// to [TCPNearConnectorParams].
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum TCPNearConnectorError {
    /// Error creating the [Addrs] object.
    Addrs(AddrsCreateError)
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TCPConnectError;

#[derive(Debug)]
pub struct TCPStream {
    unsafe_allow_ip_addr_creds: bool,
    inner: TcpStream
}

impl Credentials for TCPStream {
    type Cred<'a> = SocketAddr;
    type CredError = Error;

    #[inline]
    fn creds(&self) -> Result<Option<SocketAddr>, Error> {
        if self.unsafe_allow_ip_addr_creds {
            self.inner.peer_addr().map(Some)
        } else {
            Ok(None)
        }
    }
}

impl CredentialsMut for TCPStream {
    type Cred<'a> = SocketAddr;
    type CredError = Error;

    #[inline]
    fn creds(&mut self) -> Result<Option<SocketAddr>, Error> {
        if self.unsafe_allow_ip_addr_creds {
            self.inner.peer_addr().map(Some)
        } else {
            Ok(None)
        }
    }
}

impl TCPStream {
    #[inline]
    pub fn shutdown(
        &mut self,
        shutdown: Shutdown
    ) -> Result<(), Error> {
        self.inner.shutdown(shutdown)
    }
}

impl Read for TCPStream {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        self.inner.read(buf)
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        self.inner.read_to_end(buf)
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        self.inner.read_to_string(buf)
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        self.inner.read_exact(buf)
    }
}

impl Write for TCPStream {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        self.inner.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush()
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        self.inner.write_all(buf)
    }
}

impl ScopedError for TCPNearConnectorError {
    fn scope(&self) -> ErrorScope {
        match self {
            TCPNearConnectorError::Addrs(err) => err.scope()
        }
    }
}

impl ScopedError for TCPConnectError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Session
    }
}

impl NearChannel for TCPNearAcceptor {
    type Config = TCPNearAcceptorConfig;
    type Endpoint = SocketAddr;
    type Stream = TCPStream;
    type TakeConnectError = Error;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<(Self::Stream, Self::Endpoint), Error> {
        let (stream, addr) = self.listener.accept()?;
        let stream = TCPStream {
            unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
            inner: stream
        };

        Ok((stream, addr))
    }
}

impl NearChannelCreate for TCPNearAcceptor {
    type CreateError = Error;

    #[inline]
    fn new<Ctx>(
        _caches: &mut Ctx,
        config: TCPNearAcceptorConfig
    ) -> Result<Self, Error>
    where
        Ctx: NSNameCachesCtx {
        let listener = TcpListener::bind(config.socket_addr())?;

        if config.unsafe_opts().allow_ip_addr_creds() {
            warn!(target: "udp-far-channel",
                  concat!("unsafe option allow_ip_addr_creds enabled for ",
                          "TCP acceptor on {} (this allows for trivial ",
                          "spoofing of channel credentials)"),
                  config.socket_addr())
        }

        Ok(TCPNearAcceptor {
            unsafe_allow_ip_addr_creds: config
                .unsafe_opts()
                .allow_ip_addr_creds(),
            listener: listener
        })
    }
}

impl TCPNearConnectorParams {
    fn try_addrs(
        &mut self,
        retry: &Retry,
        until: &mut Instant,
        nretries: &mut usize
    ) -> Result<TcpStream, ()> {
        while let Ok(result) = self.addrs.addr() {
            let (addr, endpoint, _) = result.take();

            debug!(target: "tcp-near",
                   "attempting connection to {}",
                   addr);

            match TcpStream::connect(addr) {
                Ok(stream) => {
                    match self.addrs.success(&addr, &endpoint) {
                        Ok(()) => {}
                        Err(err) => {
                            warn!(target: "tcp-near",
                                  "error recording success for {} ({})",
                                  addr, err);
                        }
                    }

                    return Ok(stream);
                }
                Err(err) => {
                    info!(target: "tcp-near",
                          concat!("error connecting to {} ({}): ",
                                  "{}, trying next address"),
                          self.endpoint, addr, err);

                    match self.addrs.failure(&addr, &endpoint) {
                        Ok(()) => {}
                        Err(err) => {
                            warn!(target: "tcp-near",
                                  "error recording failure for {} ({})",
                                  addr, err);
                        }
                    }
                }
            }
        }

        let duration = retry.retry_delay(*nretries);
        let retry = Instant::now() + duration;

        *nretries += 1;
        *until = retry;

        Err(())
    }
}

impl NearSocketParams for TCPNearConnectorParams {
    type Config = TCPNearConnectorConfig;
    type CreateError = TCPNearConnectorError;
    type Endpoint = IPEndpoint;
    type Error = TCPConnectError;
    type Stream = TCPStream;

    const NAME: &'static str = "TCP";

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<(Self, Retry), Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (endpoint, resolve, retry, unsafe_opts) = config.take();
        let addrs = AddrMultiplexer::create(
            caches,
            vec![endpoint.clone()],
            repeat(()),
            resolve
        )
        .map_err(TCPNearConnectorError::Addrs)?;

        if unsafe_opts.allow_ip_addr_creds() {
            warn!(target: "udp-far-channel",
                  concat!("unsafe option allow_ip_addr_creds enabled for ",
                          "TCP acceptor on {} (this allows for trivial ",
                          "spoofing of channel credentials)"),
                  endpoint)
        }

        Ok((
            TCPNearConnectorParams {
                unsafe_allow_ip_addr_creds: unsafe_opts.allow_ip_addr_creds(),
                endpoint: endpoint,
                addrs: addrs
            },
            retry
        ))
    }

    #[inline]
    fn endpoint(&self) -> &Self::Endpoint {
        &self.endpoint
    }

    #[inline]
    fn verify_endpoint(conf: &Self::Config) -> Option<&IPEndpointAddr> {
        Some(conf.endpoint().ip_endpoint())
    }

    fn try_connect(
        &mut self,
        retry: &Retry,
        until: &mut Instant,
        nretries: &mut usize
    ) -> Result<TCPStream, TCPConnectError> {
        let now = Instant::now();

        if now < *until {
            sleep(*until - now)
        }

        trace!(target: "tcp-near",
               "attempting to connect to {}",
               self.endpoint);

        match self.try_addrs(retry, until, nretries) {
            Ok(stream) => {
                let stream = TCPStream {
                    unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
                    inner: stream
                };

                Ok(stream)
            }
            Err(()) => Err(TCPConnectError)
        }
    }

    #[inline]
    fn shutdown(
        &self,
        stream: &Self::Stream
    ) -> Result<(), Error> {
        stream.inner.shutdown(Shutdown::Both)
    }
}

impl Display for TCPNearConnectorError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TCPNearConnectorError::Addrs(err) => err.fmt(f)
        }
    }
}

impl Display for TCPConnectError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        write!(f, "possible connection options exhausted")
    }
}

#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::near::NearConnector;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[test]
fn test_send_recv() {
    init();

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    const SERVER_CONFIG: &'static str = concat!("addr: ::1\n", "port: 8006\n");
    const CLIENT_CONFIG: &'static str =
        concat!("addr: localhost\n", "port: 8006\n");
    let accept_config = serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let connect_config = serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            TCPNearAcceptor::new(&mut server_nscaches, accept_config).unwrap();
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.write_all(&SECOND_BYTES).expect("Expected success");
        stream.shutdown(Shutdown::Both).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            TCPNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        receiver.read_exact(&mut buf).unwrap();

        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}
