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

//! Near-link channels over TCP sockets.
//!
//! This module provides a [NearChannel] and
//! [NearConnector](crate::near::NearConnector) implementation over
//! TCP sockets.  [TCPNearAcceptor]s can be used to listen on a TCP
//! port.  [TCPResolvingNearConnector]s can be used to connect to remote TCP
//! ports.
//!
//! Note that connections established in this way are neither
//! authenticated nor secure inherently.

use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::iter::repeat;
use std::iter::Repeat;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::time::Instant;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::TrivialNegotiator;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use log::debug;
use log::info;
use log::warn;
use mio::event::Source;
use mio::net::TcpListener;
use mio::net::TcpStream;
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::addrs::AddrMultiplexer;
use crate::addrs::AddrsCreateError;
use crate::config::TCPNearAcceptorConfig;
use crate::config::TCPNearConnectorPartialConfig;
use crate::config::TCPResolvingNearConnectorConfig;
use crate::config::TCPResolvingNearConnectorPartialConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
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
/// let mut acceptor = TCPNearAcceptor::create(&mut nscaches,
///                                            accept_config).unwrap();
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

/// Client side of a TCP socket near-link channel.
///
/// This is a [NearChannel] and
/// [NearConnector](crate::near::NearConnector) instance that attempts
/// to connect to establish a TCP connection to a given address and
/// port.
///
/// # Usage
///
/// The primary use of a `TCPResolvingNearConnector` takes place through its
/// [NearChannel] and [NearConnector](crate::near::NearConnector) instances.
///
/// ## Configuration and Creation
///
/// A `TCPResolvingNearConnector` is created using the
/// [new](NearChannelCreate::new) function from its [NearChannel]
/// instance.  This function takes a [TCPResolvingNearConnectorConfig]
/// as its principal argument, which supplies all configuration
/// unformation.
///
/// ### Example
///
/// The following example shows how to create a `TCPResolvingNearConnector`.
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPResolvingNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!("addr: en.wikipedia.org\n",
///                                      "port: 443\n");
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector = TCPResolvingNearConnector::create(&mut nscaches,
///                                          accept_config).unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `TCPResolvingNearConnector` has been created, connections can be
/// established using the
/// [take_connection](NearChannel::take_connection) or
/// [connection](crate::near::NearConnector::connection) functions.  These will
/// block until a connection has been successfully established.  Note
/// that depending on the circumstances, this may involve many retries
/// and/or name resolutions.
pub struct TCPResolvingNearConnector {
    unsafe_allow_ip_addr_creds: bool,
    addrs: AddrMultiplexer<Repeat<()>>,
    endpoint: IPEndpoint,
    nretries: usize,
    when: Instant,
    retry: Retry,
}

pub struct TCPNearConnector {
    unsafe_allow_ip_addr_creds: bool,
    endpoint: SocketAddr,
    nretries: usize,
    when: Instant,
    retry: Retry,
}

/// Errors that can occur when converting a [TCPResolvingNearConnectorConfig]
/// to [TCPResolvingNearConnectorParams].
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum TCPResolvingNearConnectorError {
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
    type Cred = SocketAddr;
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
    type Cred = SocketAddr;
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

impl Session for TCPStream {
    type LocalAddr = SocketAddr;
    type PeerAddr = SocketAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.inner.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.inner.peer_addr()
    }
}

impl Source for TCPStream {
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

impl ScopedError for TCPResolvingNearConnectorError {
    fn scope(&self) -> ErrorScope {
        match self {
            TCPResolvingNearConnectorError::Addrs(err) => err.scope()
        }
    }
}

impl ScopedError for TCPConnectError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Session
    }
}

impl Source for TCPNearAcceptor {
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.listener.register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.listener.reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.listener.deregister(registry)
    }
}

impl Negotiator<(TCPStream, SocketAddr)> for TCPNearAcceptor {
    type State = (TCPStream, SocketAddr);
    type Pending = Infallible;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        panic!("This should never be called!")
    }
}

impl NearChannel for TCPNearAcceptor {
    type Endpoint = SocketAddr;
    type Conn = TCPStream;
    type ShutdownNego = TrivialNegotiator;
    type StartError = Error;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        let (stream, addr) = self.listener.accept()?;
        let mut stream = TCPStream {
            unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
            inner: stream
        };

        registry.register(&mut stream, token,
                          Interest::READABLE | Interest::WRITABLE)?;

        Ok(RetryResult::Success((stream, addr)))
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        TrivialNegotiator
    }

    #[inline]
    fn cleanup(
        &mut self,
        _registry: &Registry,
        _err: Self::NegotiateError
    ) -> Result<(), Error> {
        panic!("This should never be called!")
    }
}

impl NearChannelCreate for TCPNearAcceptor {
    type Config = TCPNearAcceptorConfig;
    type CreateError = Error;

    #[inline]
    fn create<Ctx>(
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

    #[inline]
    fn verify_endpoint(_config: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }
}

impl Negotiator<(TCPStream, SocketAddr)> for TCPResolvingNearConnector {
    type State = (TCPStream, SocketAddr);
    type Pending = Infallible;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        panic!("This should never be called!")
    }
}

impl NearChannel for TCPResolvingNearConnector {
    type Endpoint = SocketAddr;
    type Conn = TCPStream;
    type ShutdownNego = TrivialNegotiator;
    type StartError = Error;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        if self.when < Instant::now() {
            // XXX correctly deal with error scopes here.
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
                        let mut stream = TCPStream {
                            unsafe_allow_ip_addr_creds:
                            self.unsafe_allow_ip_addr_creds,
                            inner: stream
                        };

                        registry.register(&mut stream, token,
                                          Interest::READABLE |
                                          Interest::WRITABLE)?;

                        return Ok(RetryResult::Success((stream, addr)));
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

            let duration = self.retry.retry_delay(self.nretries);
            let when = Instant::now() + duration;

            self.nretries += 1;
            self.when = when;
        }

        Ok(RetryResult::Retry(self.when.clone()))
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        TrivialNegotiator
    }

    #[inline]
    fn cleanup(
        &mut self,
        _registry: &Registry,
        _err: Self::NegotiateError
    ) -> Result<(), Error> {
        panic!("This should never be called!")
    }
}

impl NearChannelCreate for TCPResolvingNearConnector {
    type Config = TCPResolvingNearConnectorConfig;
    type CreateError = TCPResolvingNearConnectorError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: TCPResolvingNearConnectorConfig
    ) -> Result<Self, TCPResolvingNearConnectorError>
    where
        Ctx: NSNameCachesCtx {
        let (endpoint, resolve, retry, unsafe_opts) = config.take();
        let partial =
            TCPResolvingNearConnectorPartialConfig
            ::new_with_unsafe(resolve, retry, unsafe_opts);

        TCPResolvingNearConnector::create_with_endpoint(caches, partial,
                                                        endpoint, None)
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Some(config.endpoint().ip_addr())
    }
}

impl NearChannelCreateWithEndpoint for TCPResolvingNearConnector {
    type Config = TCPResolvingNearConnectorPartialConfig;
    type EndpointConfig = IPEndpoint;
    type CreateError = TCPResolvingNearConnectorError;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: TCPResolvingNearConnectorPartialConfig,
        endpoint: IPEndpoint,
        _verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<Self, TCPResolvingNearConnectorError>
    where
        Ctx: NSNameCachesCtx {
        let (resolve, retry, unsafe_opts) = config.take();
        let addrs = AddrMultiplexer::create(
            caches,
            vec![endpoint.clone()],
            repeat(()),
            resolve
        )
        .map_err(TCPResolvingNearConnectorError::Addrs)?;

        if unsafe_opts.allow_ip_addr_creds() {
            warn!(target: "udp-far-channel",
                  concat!("unsafe option allow_ip_addr_creds enabled for ",
                          "TCP acceptor on {} (this allows for trivial ",
                          "spoofing of channel credentials)"),
                  endpoint)
        }

        Ok(TCPResolvingNearConnector {
            unsafe_allow_ip_addr_creds: unsafe_opts.allow_ip_addr_creds(),
            endpoint: endpoint,
            addrs: addrs,
            retry: retry,
            nretries: 0,
            when: Instant::now(),
        })
    }
}

impl NearConnector for TCPResolvingNearConnector {
    /// Type of endpoint references.
    type EndpointRef<'a> = &'a IPEndpoint
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        &self.endpoint
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl Negotiator<(TCPStream, SocketAddr)> for TCPNearConnector {
    type State = (TCPStream, SocketAddr);
    type Pending = Infallible;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<NegotiatorResult<(TCPStream, SocketAddr), Infallible>,
                Self::NegotiateError> {
        panic!("This should never be called!")
    }
}

impl NearChannel for TCPNearConnector {
    type Endpoint = SocketAddr;
    type Conn = TCPStream;
    type ShutdownNego = TrivialNegotiator;
    type StartError = Error;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        let mut stream = TcpStream::connect(self.endpoint)?;

        registry.register(&mut stream, token,
                          Interest::READABLE |
                          Interest::WRITABLE)?;

        let stream = TCPStream {
            unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
            inner: stream
        };
        let out = (stream, self.endpoint.clone());


        Ok(RetryResult::Success(out))
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        TrivialNegotiator
    }

    #[inline]
    fn cleanup(
        &mut self,
        _registry: &Registry,
        _err: Self::NegotiateError
    ) -> Result<(), Error> {
        panic!("This should never be called!")
    }
}

impl NearChannelCreateWithEndpoint for TCPNearConnector {
    type Config = TCPNearConnectorPartialConfig;
    type EndpointConfig = SocketAddr;
    type CreateError = Infallible;

    #[inline]
    fn create_with_endpoint<Ctx>(
        _caches: &mut Ctx,
        config: TCPNearConnectorPartialConfig,
        endpoint: SocketAddr,
        _verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<Self, Infallible>
    where
        Ctx: NSNameCachesCtx {
        let (retry, unsafe_opts) = config.take();

        if unsafe_opts.allow_ip_addr_creds() {
            warn!(target: "udp-far-channel",
                  concat!("unsafe option allow_ip_addr_creds enabled for ",
                          "TCP acceptor on {} (this allows for trivial ",
                          "spoofing of channel credentials)"),
                  endpoint)
        }

        Ok(TCPNearConnector {
            unsafe_allow_ip_addr_creds: unsafe_opts.allow_ip_addr_creds(),
            endpoint: endpoint,
            retry: retry,
            nretries: 0,
            when: Instant::now(),
        })
    }
}

impl NearConnector for TCPNearConnector {
    /// Type of endpoint references.
    type EndpointRef<'a> = &'a SocketAddr
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        &self.endpoint
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}



impl Display for TCPResolvingNearConnectorError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TCPResolvingNearConnectorError::Addrs(err) => err.fmt(f)
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
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;
#[cfg(test)]
use crate::near::accept_one;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::write_one;
#[cfg(test)]
use crate::near::negotiate_one;

#[test]
fn test_send_recv() {
    init();

    const SERVER_CONFIG: &'static str = concat!("addr: ::1\n", "port: 8006\n");
    const CLIENT_CONFIG: &'static str =
        concat!("addr: localhost\n", "port: 8006\n");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let accept_config = serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let connect_config = serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor =
            TCPNearAcceptor::create(&mut server_nscaches, accept_config)
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

        stream.shutdown(Shutdown::Both).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn =
            TCPResolvingNearConnector::create(&mut client_nscaches,
                                              connect_config)
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
