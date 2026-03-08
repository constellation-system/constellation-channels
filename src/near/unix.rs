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

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fs::remove_file;
use std::io::Error;

use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::PassthruNegotiator;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketAddr;
use constellation_common::unix::UnixSocketPath;
use log::debug;
use log::info;
use log::warn;
use mio::event::Source;
use mio::net::UnixListener;
use mio::net::UnixStream;
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::config::UnixNearChannelConfig;
use crate::config::UnixNearConnectorPartialConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

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
/// let acceptor = UnixNearAcceptor::create(&mut nscaches, config).unwrap();
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
/// let connector = UnixNearConnector::create(&mut nscaches, accept_config)
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
pub struct UnixNearConnector {
    path: UnixSocketPath
}

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

impl Source for UnixNearAcceptor {
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

impl Negotiator<(UnixStream, UnixSocketAddr)> for UnixNearAcceptor {
    type NegotiateError = Infallible;
    type Pending = Infallible;
    type State = (UnixStream, UnixSocketAddr);

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(UnixStream, UnixSocketAddr), Infallible>,
        Self::NegotiateError
    > {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<(UnixStream, UnixSocketAddr), Infallible>,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl NearChannel for UnixNearAcceptor {
    type Conn = UnixStream;
    type Endpoint = UnixSocketAddr;
    type ShutdownNego = PassthruNegotiator;
    type ShutdownValue = UnixStream;
    type StartError = Error;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        let (mut stream, addr) = self.listener.accept()?;
        let addr = UnixSocketAddr::from(addr);

        registry.register(
            &mut stream,
            token,
            Interest::READABLE | Interest::WRITABLE
        )?;

        Ok(RetryResult::Success((stream, addr)))
    }

    #[inline]
    fn shutdown_nego(&self) -> Self::ShutdownNego {
        PassthruNegotiator
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
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

impl NearChannelCreate for UnixNearAcceptor {
    type Config = UnixNearChannelConfig;
    type CreateError = Error;

    #[inline]
    fn create<Ctx>(
        _caches: &mut Ctx,
        config: UnixNearChannelConfig
    ) -> Result<Self, Error>
    where
        Ctx: NSNameCachesCtx {
        let listener = UnixListener::bind(config.path())?;

        Ok(UnixNearAcceptor { listener: listener })
    }

    #[inline]
    fn verify_endpoint(_config: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }
}

impl Negotiator<(UnixStream, UnixSocketAddr)> for UnixNearConnector {
    type NegotiateError = Infallible;
    type Pending = Infallible;
    type State = (UnixStream, UnixSocketAddr);

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(UnixStream, UnixSocketAddr), Infallible>,
        Self::NegotiateError
    > {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<(UnixStream, UnixSocketAddr), Infallible>,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl NearChannel for UnixNearConnector {
    type Conn = UnixStream;
    type Endpoint = UnixSocketAddr;
    type ShutdownNego = PassthruNegotiator;
    type ShutdownValue = UnixStream;
    type StartError = Error;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Error> {
        debug!(target: "unix-near",
               "attempting to connect to {}",
               self.path);

        let mut stream = UnixStream::connect(&self.path)?;
        let addr = UnixSocketAddr::try_from(&self.path)?;

        registry.register(
            &mut stream,
            token,
            Interest::READABLE | Interest::WRITABLE
        )?;

        Ok(RetryResult::Success((stream, addr)))
    }

    #[inline]
    fn shutdown_nego(&self) -> Self::ShutdownNego {
        PassthruNegotiator
    }

    #[inline]
    fn shutdown_param(&self) -> () {
        ()
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

impl NearChannelCreate for UnixNearConnector {
    type Config = UnixNearChannelConfig;
    type CreateError = Error;

    #[inline]
    fn create<Ctx>(
        _caches: &mut Ctx,
        config: UnixNearChannelConfig
    ) -> Result<Self, Error>
    where
        Ctx: NSNameCachesCtx {
        let path = config.take();

        Ok(UnixNearConnector {
            path: UnixSocketPath::from(path)
        })
    }

    #[inline]
    fn verify_endpoint(_config: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }
}

impl NearChannelCreateWithEndpoint for UnixNearConnector {
    type Config = UnixNearConnectorPartialConfig;
    type CreateError = Error;
    type EndpointConfig = UnixSocketAddr;
    type Param = ();

    #[inline]
    fn create_with_endpoint<Ctx>(
        _caches: &mut Ctx,
        _config: UnixNearConnectorPartialConfig,
        endpoint: UnixSocketAddr,
        _param: Self::Param
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let path = UnixSocketPath::try_from(&endpoint)?;

        Ok(UnixNearConnector { path: path })
    }
}

impl NearConnector for UnixNearConnector {
    /// Type of endpoint references.
    type EndpointRef<'a>
        = &'a UnixSocketPath
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        &self.path
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
