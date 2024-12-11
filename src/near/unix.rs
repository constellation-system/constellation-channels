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

//! Near-link channels over Unix domain sockets.
//!
//! This module provides a [NearChannel] and
//! [NearConnector](crate::near::NearConnector) implementation over
//! Unix domain stream sockets.  These are an interprocess
//! communication mechanism available on most Unix-type operating
//! systems that resemble TCP-like functionality, but are strictly
//! local to a machine.
//!
//! # Unix Domain Sockets
//!
//! A Unix domain socket is referenced by a filesystem path, and
//! appears as a special file.  It is created by the listening
//! process, and other processes can connect to it using the normal
//! sockets API.  Thereafter, it behaves similarly to a very stable,
//! high-bandwidth TCP socket.  Unix sockets also support additional
//! functionality, such as sending file descriptors and
//! authorizations.  This functionality is not supported by the near
//! channel API.
//!
//! Unix sockets cannot connect across machines; however, they serve
//! as a viable replacement for TCP connections to `localhost`, and
//! offer several advantages.  Notably, it is impossible to
//! misconfigure a Unix socket to allow connections from machines
//! other than `localhost`, thus avoiding a potential security issue.
//!
//! # Near-Links Over Unix Sockets
//!
//! The [UnixNearAcceptor] and [UnixNearConnector] types provide the means to
//! use Unix domain sockets within the near-link framework.
//! [UnixNearAcceptor]s can be used to listen on a Unix socket, creating
//! the socket when the `NearAcceptor` is created, and deleting it
//! when it is dropped.  [UnixNearConnector]s can be used to connect to
//! Unix sockets, and will automatically retry connections if one
//! cannot be established.  In this way, Unix sockets can be easily
//! substituted in place of TCP sockets connecting to or listening on
//! `localhost`.
//!
//! # Examples
//!
//! The following is an example of connecting, sending, and
//! receiving over Unix sockets:
//!
//! ```
//! # use constellation_channels::config::UnixNearChannelConfig;
//! # use constellation_channels::near::NearChannel;
//! # use constellation_channels::near::NearChannelCreate;
//! # use constellation_channels::near::NearConnector;
//! # use constellation_channels::near::unix::UnixNearConnector;
//! # use constellation_channels::near::unix::UnixNearAcceptor;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use std::net::Shutdown;
//! # use std::thread::spawn;
//! # use std::io::Read;
//! # use std::io::Write;
//! #
//! const CONFIG: &'static str = concat!("path: example.sock");
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! let connect_config = serde_yaml::from_str(CONFIG).unwrap();
//! let accept_config: UnixNearChannelConfig =
//!     serde_yaml::from_str(CONFIG).unwrap();
//! let path = accept_config.path().to_path_buf();
//! let nscaches = SharedNSNameCaches::new();
//!
//! let mut server_nscaches = nscaches.clone();
//! let listen = spawn(move || {
//!     let mut acceptor =
//!         UnixNearAcceptor::new(&mut server_nscaches, accept_config)
//!             .expect("Expected success");
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
//!         UnixNearConnector::new(&mut client_nscaches, connect_config)
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

use std::convert::Infallible;
use std::fs::remove_file;
use std::io::Error;
use std::net::Shutdown;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::thread::sleep;
use std::time::Instant;

use constellation_common::retry::Retry;
use log::info;
use log::trace;
use log::warn;

use crate::config::UnixNearChannelConfig;
use crate::config::UnixNearConnectorConfig;
use crate::near::socket::NearSocketConnector;
use crate::near::socket::NearSocketParams;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::resolve::cache::NSNameCachesCtx;
use crate::unix::UnixSocketAddr;
use crate::unix::UnixSocketPath;

/// Server side of a Unix socket near-link channel.
///
/// This is a [NearChannel] instance that listens for connections on a
/// Unix domain socket.  This can be paired with [UnixNearConnector] to
/// serve as an alternative to TCP connections when communications are
/// strictly local to a given machine.
///
/// This expects the socket not to exist initially, and will create
/// the socket and begin listening for connections.  It also has a
/// [Drop] implementation that will delete the socket.
///
/// # Usage
///
/// The primary usage of `UnixNearAcceptor` takes place through its
/// [NearChannel] instance.
///
/// ## Configuration and Creation
///
/// A `UnixNearAcceptor` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [UnixNearChannelConfig] as its principal argument, which supplies
/// all configuration unformation.
///
/// ### Example
///
/// The following example shows how to create a `UnixNearAcceptor`.
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::unix::UnixNearAcceptor;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = "path: acceptor_example.sock";
/// let config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let acceptor = UnixNearAcceptor::new(&mut nscaches, config).unwrap();
/// ```
///
/// ## Accepting Connections
///
/// Once a `UnixNearAcceptor` has been created, connections can be accepted
/// using the [take_connection](NearChannel::take_connection)
/// function.
pub struct UnixNearAcceptor {
    /// The underlying listener.
    listener: UnixListener
}

/// The [NearSocketParams] instance used by [NearSocketConnector].
#[doc(hidden)]
pub struct UnixNearConnectorParams {
    /// The endpoint to which this connector will try to connect.
    path: UnixSocketPath
}

/// Client side of a Unix socket near-link channel.
///
/// This is a [NearChannel] and
/// [NearConnector](crate::near::NearConnector) instance that attempts
/// to connect to a Unix domain socket at a given path.  This can be
/// paired with [UnixNearAcceptor] to serve as an alternative to TCP
/// connections when communications are strictly local to a given
/// machine.
///
/// # Usage
///
/// The primary use of a `UnixNearConnector` takes place through its
/// [NearChannel] and [NearConnector](crate::near::NearConnector)
/// instances.
///
/// ## Configuration and Creation
///
/// A `UnixNearConnector` is created using the [new](NearChannelCreate::new)
/// function from its [NearChannel] instance.  This function takes a
/// [UnixNearConnectorConfig] as its principal argument, which supplies
/// all configuration unformation.
///
/// ### Example
///
/// The following example shows how to create a `UnixNearConnector`.
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::unix::UnixNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = "path: /var/run/test/test.sock\n";
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector = UnixNearConnector::new(&mut nscaches, accept_config)
///     .unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `UnixNearConnector` has been created, connections can be
/// established using the
/// [take_connection](NearChannel::take_connection) or
/// [connection](crate::near::NearConnector::connection) functions.
/// These will block until a connection has been successfully
/// established.
///
/// Note that if the Unix socket does not exist at the specified path,
/// then a `UnixNearConnector` attempting to connect to it will
/// continually retry until the socket is created.
pub type UnixNearConnector = NearSocketConnector<UnixNearConnectorParams>;

impl Drop for UnixNearAcceptor {
    fn drop(&mut self) {
        match self.listener.local_addr() {
            Ok(addr) => match addr.as_pathname() {
                Some(path) => match remove_file(path) {
                    Ok(()) => {
                        // Normal deletion of the socket.
                        info!(target: "unix-near-acceptor",
                              "cleaned up unix socket {}",
                              path.to_string_lossy())
                    }
                    Err(err) => {
                        // An error occurred.  We can't do anything
                        // other than log it.
                        warn!(target: "unix-near-acceptor",
                              "error cleaning up unix socket {} ({})",
                              path.to_string_lossy(), err)
                    }
                },
                None => {
                    // The socket address was anonymous.  This
                    // shouldn't happen, and probably represents an
                    // error somewhere.
                    warn!(target: "unix-near-acceptor",
                      concat!("unix socket listener's address was anonymous ",
                              "(this shouldn't happen)"))
                }
            },
            Err(err) => {
                // Couldn't get the address.  There's nothing for us
                // to do besides log it.
                warn!(target: "unix-near-acceptor",
                      "error getting listener address ({})",
                      err)
            }
        }
    }
}

impl NearChannel for UnixNearAcceptor {
    type Config = UnixNearChannelConfig;
    type Endpoint = UnixSocketAddr;
    type Stream = UnixStream;
    type TakeConnectError = Error;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<(Self::Stream, Self::Endpoint), Error> {
        let (stream, addr) = self.listener.accept()?;

        Ok((stream, UnixSocketAddr::from(addr)))
    }
}

impl NearChannelCreate for UnixNearAcceptor {
    type CreateError = Error;

    #[inline]
    fn new<Ctx>(
        _caches: &mut Ctx,
        config: UnixNearChannelConfig
    ) -> Result<Self, Error>
    where
        Ctx: NSNameCachesCtx {
        let listener = UnixListener::bind(config.path())?;

        Ok(UnixNearAcceptor { listener: listener })
    }
}

impl NearSocketParams for UnixNearConnectorParams {
    type Config = UnixNearConnectorConfig;
    type CreateError = Infallible;
    type Endpoint = UnixSocketPath;
    type Error = Error;
    type Stream = UnixStream;

    const NAME: &'static str = "unix";

    #[inline]
    fn create<Ctx>(
        _caches: &mut Ctx,
        config: Self::Config
    ) -> Result<(Self, Retry), Infallible>
    where
        Ctx: NSNameCachesCtx {
        let (channel, retry) = config.take();

        Ok((
            UnixNearConnectorParams {
                path: UnixSocketPath::from(channel.take())
            },
            retry
        ))
    }

    #[inline]
    fn endpoint(&self) -> &Self::Endpoint {
        &self.path
    }

    fn try_connect(
        &mut self,
        retry: &Retry,
        until: &mut Instant,
        nretries: &mut usize
    ) -> Result<UnixStream, Error> {
        trace!(target: "unix-near",
               "attempting to connect to {}",
               self.path);

        let now = Instant::now();

        if now < *until {
            sleep(*until - now)
        }

        match UnixStream::connect(&self.path) {
            // Connect success.
            Ok(stream) => Ok(stream),
            // Connect failure.  Increment retry and loop.
            Err(err) => {
                let duration = retry.retry_delay(*nretries);
                let next_retry = Instant::now() + duration;

                *nretries += 1;
                *until = next_retry;

                Err(err)
            }
        }
    }

    #[inline]
    fn shutdown(
        &self,
        stream: &Self::Stream
    ) -> Result<(), Error> {
        stream.shutdown(Shutdown::Both)
    }
}

#[cfg(test)]
use std::fs::metadata;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
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

    const CONFIG: &'static str = concat!("path: test_send_recv.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
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
            UnixNearConnector::new(&mut client_nscaches, connect_config)
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

    assert!(metadata(&path).is_err());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_reconnect() {
    init();

    const CONFIG: &'static str = concat!("path: test_reconnect.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf1 = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf1).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        server_barrier.wait();
        server_barrier.wait();

        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf2 = [0; SECOND_BYTES.len()];

        stream.read_exact(&mut buf2).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        assert_eq!(FIRST_BYTES, buf1);
        assert_eq!(SECOND_BYTES, buf2);
    });

    let client_barrier = barrier;
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (_, mut sender, _) = conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        client_barrier.wait();

        let err = sender.write_all(&SECOND_BYTES);

        client_barrier.wait();

        assert!(err.is_err());

        let (_, mut sender, _) = conn.connection().expect("expected success");

        sender.write_all(&SECOND_BYTES).expect("Expected success");
    });

    send.join().unwrap();
    listen.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_send_close() {
    init();

    const CONFIG: &'static str = concat!("path: test_send_close.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];
        let err = receiver.read_exact(&mut buf);

        assert!(err.is_err());

        let err = sender.write_all(&SECOND_BYTES);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_recv_close() {
    init();

    const CONFIG: &'static str = concat!("path: test_recv_close.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        server_barrier.wait();

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        client_barrier.wait();

        let err = sender.write_all(&SECOND_BYTES);

        assert!(err.is_err());

        let mut buf = [0; SECOND_BYTES.len()];
        let err = receiver.read_exact(&mut buf);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_send_shutdown() {
    init();

    const CONFIG: &'static str = concat!("path: test_send_shutdown.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();

        server_barrier.wait();

        let _ = stream.shutdown(Shutdown::Both);

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (_, mut sender, _) = conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        conn.shutdown().expect("Expected success");

        client_barrier.wait();

        let err = sender.write_all(&SECOND_BYTES);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_recv_shutdown() {
    init();

    const CONFIG: &'static str = concat!("path: test_recv_shutdown.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf).unwrap();

        server_barrier.wait();

        let _ = stream.shutdown(Shutdown::Both);

        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (mut receiver, mut sender, _) =
            conn.connection().expect("expected success");

        sender.write_all(&FIRST_BYTES).expect("Expected success");

        conn.shutdown().expect("Expected success");

        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];
        let err = receiver.read_exact(&mut buf);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_send_late_shutdown() {
    init();

    const CONFIG: &'static str = concat!("path: test_send_late_shutdown.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut acceptor =
            UnixNearAcceptor::new(&mut server_nscaches, accept_config)
                .expect("Expected success");
        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf1 = [0; FIRST_BYTES.len()];

        stream.read_exact(&mut buf1).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        let (mut stream, _) = acceptor.take_connection().unwrap();
        let mut buf2 = [0; SECOND_BYTES.len()];

        stream.read_exact(&mut buf2).unwrap();
        stream.shutdown(Shutdown::Both).unwrap();

        server_barrier.wait();

        assert_eq!(FIRST_BYTES, buf1);
        assert_eq!(SECOND_BYTES, buf2);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            UnixNearConnector::new(&mut client_nscaches, connect_config)
                .expect("expected success");
        let (mut receiver1, mut sender1, _) =
            conn.connection().expect("expected success");

        sender1.write_all(&FIRST_BYTES).expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];
        let err = receiver1.read_exact(&mut buf);

        assert!(err.is_err());

        let (_, mut sender2, _) = conn.connection().expect("expected success");

        let err = sender1.write_all(&FIRST_BYTES);

        assert!(err.is_err());

        sender2.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();
    });

    send.join().unwrap();
    listen.join().unwrap();

    assert!(metadata(&path).is_err());
}
