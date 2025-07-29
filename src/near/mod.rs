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

//! Abstractions for connection-based stream-like channels.
//!
//! Near-link channels are an abstraction for communications over
//! relatively stable, reliable, low-latency, higher-bandwidth
//! channels where a connection-based, stream-like abstraction makes
//! sense.  The TCP protocol is assumed to be an acceptable protocol
//! here.  Protection of these channels is primarily assumed to be
//! focused on confidentiality, not on covertness.
//!
//! # Channel Abstraction
//!
//! "Channels", as they are presented here, are an abstraction that
//! removes the need to worry about connections, endpoints, and
//! session negotiation.  All of these concerns are handled internally
//! within a blocking call that supplies a [Read] and [Write]
//! instance.  Some channels (such as TLS or SOCKS5) can be composed
//! out of other channels, and will automatically handle the session
//! negotiation.
//!
//! Channels are intended to operate as a base layer for the more
//! general reactive streams paradigm.  The intended use pattern is to
//! attach a codec to the underlying bytestreams provided by the
//! channel, which creates a typed stream.  This is then ultimately
//! connected to a protocol state machine, which reads incoming
//! protocol traffic and generates responses.
//!
//! Near-link channels are connection-based and present a stream
//! abstraction, similar to TCP or a Unix domain socket.  The
//! near-link channel abstraction *does* expose the issue of lost or
//! dropped connections, as this has implications at the protocol
//! level.  Near-links typically operate in the client-server
//! paradigm, and will exhibit different behavior based on their
//! roles.
//!
//! ## Programming Interfaces
//!
//! The basic channel interface is given by [NearChannel].  Channels
//! are created using the [new](NearChannelCreate::new) function, which
//! takes a configuration object as its argument.  Examples of these
//! can be found in the [config](crate::config) module.  Once a
//! channel is set up, a connection can be obtained using the
//! [take_connection](NearChannel::take_connection) function, which
//! will block until a connection is successfully established, and
//! will then take full ownership of the resulting stream.  Failed
//! attempts to establish a connection will retry according to a retry
//! policy.  Note that this may cause misconfigured channels to block
//! indefinitely.  As such, channels are more appropriate for server
//! or infrastructure-type applications, and less so for end-user
//! clients.
//!
//! The [NearChannel] interface is sufficient for most server-side
//! applications.  In this use, incoming connections are accepted
//! using [take_connection](NearChannel::take_connection), and then
//! connected to a codec and a state machine that will handle
//! requests.  If a connection is broken in the middle of a request,
//! it will be abandoned.
//!
//! Client-side channels typically establish a connection, then
//! proceed to execute a protocol that makes one or more requests.
//! This requires more functionality, which is provided by the
//! additional [NearConnector] trait.  This trait provides the
//! [fail](NearConnector::fail) function, which allows higher-level
//! protocol layers to report failure down to the lower levels.
//! Additionally, the [connection](NearConnector::connection) function
//! allows a connection to be established, but then split into a
//! [Read] and [Write] half, each of which can be shared.
//!
//! # Channel Types
//!
//! This module provides a number of channel types, for both client
//! and server roles.  Server-side channels are given names ending in
//! "Acceptor", while client-side channels have names ending in
//! "Connector".
//!
//! ## Basic Channel Types
//!
//! The following is a summary of the different channel types provided:
//!
//! - Unix domain sockets: provided by
//!   [UnixNearAcceptor](crate::near::unix::UnixNearAcceptor) and
//!   [UnixNearConnector](crate::near::unix::UnixNearConnector)
//!
//! - TCP sockets: provided by
//!   [TCPNearAcceptor](crate::near::tcp::TCPNearAcceptor) and
//!   [TCPNearConnector](crate::near::tcp::TCPNearConnector)
//!
//! - Transport-Layer Security (TLS) sessions: provided by
//!   [TLSNearAcceptor](crate::near::tls::TLSNearAcceptor) and
//!   [TLSNearConnector](crate::near::tls::TLSNearConnector)
//!
//! - SOCKS5 proxied channels: provided by
//!   [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector) (no
//!   server-side is provided)
//!
//! Each of these channel types has a corresponding configuration
//! structure in [config](crate::config).
//!
//! Some of these channel types (TLS and SOCKS5) are constructed out
//! of other channels.  These channels use type parameters to
//! determine the underlying channel type.  Relatively simple
//! applications can use these directly; applications that need more
//! versatility and support for complex arrangements should use the
//! compound channels provided by this module.
//!
//! ## GSSAPI-Authenticated Channels
//!
//! GSSAPI-based authentication is somewhat unique among
//! authentication methods, as it has implications at the channel
//! level.  Once a GSSAPI session is negotiated, a session key is
//! established, which is then used to encrypt and authenticate
//! messages (note that many installations use encryption that is far
//! too weak by modern standards to establish meaningful security).
//! This means that GSSAPI authentication must be implemented at the
//! channel level.
//!
//! GSSAPI-authenticated channels are provided by
//! [GSSAPIAcceptor](crate::near::gssapi::GSSAPINearAcceptor) and
//! [GSSAPIConnector](crate::near::gssapi::GSSAPINearConnector).  These
//! deviate from the other channel types somewhat, in that they cannot
//! be fully configured by a structure from [config](crate::config).
//! GSSAPI channels require a notion of a service name, which must be
//! provided by the application itself.
//!
//! Additionally GSSAPI channels are deliberately excluded from
//! [CompoundNearAcceptor](crate::near::compound::CompoundNearAcceptor)
//! and
//! [CompoundNearConnector](crate::near::compound::CompoundNearConnector).
//! GSSAPI authentication is supported internally by
//! [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector),
//! and use of a
//! [GSSAPIConnector](crate::near::gssapi::GSSAPINearConnector) in the
//! `proxy` configuration would not function.  More generally, GSSAPI
//! authentication should always be the last layer in any channel
//! configuration, corresponding to the innermost layer of any
//! resulting protocol.  Finally, handling GSSAPI in this way makes it
//! possible to create a more general authentication layer.
#[cfg(feature = "socks5")]
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::error::WithMutexPoison;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::RetryResult;
use log::error;
use mio::event::Source;

use crate::resolve::cache::NSNameCachesCtx;

pub mod compound;
#[cfg(feature = "gssapi")]
pub mod gssapi;
#[cfg(feature = "socks5")]
pub mod socks5;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "unix")]
pub mod unix;

/// Basic interface for near-link channels.
///
/// This trait provides the basic functionality for near-link channels
/// on both the client and server sides.  For server-side channels,
/// this interface functions similar to a typical "listener"
/// interface, with [connection](NearChannel::connection) functioning
/// similar to the "accept" function often found in such interfaces.
///
/// Client-side channels typically also implement the [NearConnector]
/// trait.  The [connection](NearChannel::connection) function is
/// typically used only by higher-level protocols to take exclusive
/// possession of the channel.  The
/// [TLSNearConnector](crate::near::tls::TLSNearConnector) and
/// [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector)
/// instances function in this manner with regard to their underlying
/// channels.
pub trait NearChannel {
    /// Type of connections.
    ///
    /// See [take_connection](NearChannel::connection).
    type Conn: CredentialsMut + Source + Read + Write + Debug + Sized;
    /// Type of negotiation state.
    type State;
    /// Type of connection endpoints.
    ///
    /// See [take_connection](NearChannel::take-connection)
    /// [endpoint](NearConnector::endpoint).
    type Endpoint: Clone + Debug + Display + Sized;
    /// Type of configurations.
    type Config;
    /// Errors that can occur during negotiations.
    type NegotiateError: Debug + Display + RecoverableError;
    /// Type of errors that can occur starting a negotiation.
    type StartError: Display + ScopedError;

    /// Start a session negotiation.
    ///
    /// This is similar in nature to
    /// (Negotiator::start)[constellation_common::net::Negotiator::start],
    /// the underlying stream is supplied by the channel.
    fn start(
        &mut self
    ) -> Result<RetryResult<Self::State>, Self::StartError>;

    /// Perform negotiations.
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<(Self::Conn, Self::Endpoint), Self::NegotiateError>;

    /// Complete a failed negotiation.
    fn complete_negotiate(
        &self,
        err: <Self::NegotiateError as RecoverableError>::Completable
    ) -> Result<(Self::Conn, Self::Endpoint), Self::NegotiateError>;
}

/// Trait for creating instances of near-link channels.
pub trait NearChannelCreate: NearChannel + Sized {
    /// Type of errors that can be returned from [new](NearChannelCreate::new).
    type CreateError: Display + ScopedError + Sized;

    /// Create a new instance from `config`.
    ///
    /// # Type Parameters
    ///
    /// * `Ctx`: Type of [NSNameCachesCtx] instance to use.
    ///
    /// # Parameters
    ///
    /// * `ctx`: Context to use to obtain name caches.
    /// * `config`: Configuration object to use to create the channel.
    fn new<Ctx>(
        ctx: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx;
}

/// Interface for client-side near-link channels.
///
/// This interface provides functionality for near-link channels that
/// is specific to the client side.
pub trait NearConnector: NearChannel {
    /// Type of endpoint references.
    type EndpointRef<'a>: Display
    where
        Self: 'a;

    /// Get the target endpoint.
    ///
    /// The type of this will vary by instance, but it will always
    /// implement [Display].
    fn endpoint(&self) -> Self::EndpointRef<'_>;

    /// Get the IP address to which this `NearConnector` connects, if
    /// applicable.
    ///
    /// The default behavior is to return `None`.  This is used to
    /// configure TLS connectors based on their underlying connectors.
    ///
    /// # Parameters
    ///
    /// * `config`: Configuration object used to create the channel.
    #[inline]
    fn verify_endpoint(_config: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }

    /// Shut down this connector and all lower-level connectors.
    ///
    /// Subsequent attempts to acquire any connection will fail.
    fn shutdown(&mut self) -> Result<(), Error>;
}

/// Errors that can occur for [connection](NearChannel::connection).
#[derive(Debug)]
pub enum NearConnectError {
    /// A low-level IO error occurred.
    IO {
        /// The underlying IO error.
        error: Error
    },
    /// A previous connection was made, and ownership has been
    /// transferred.
    Transferred,
    Shutdown,
    MutexPoison
}

/// Errors that can occur for [session](NearChannel::session).
#[derive(Debug)]
pub enum NearSessionError<Conn, Auth> {
    /// An error occurred establishing the connection.
    Conn {
        /// The error that occurred establishing the connection.
        err: Conn
    },
    /// An error occurred during authentication.
    Auth {
        /// The error that occurred during authentication.
        err: Auth
    },
    /// Authentication failure.
    AuthFail
}

/// Wrapper for near-channel connections.
///
/// An instance can be created using the [From] instance.
#[derive(Clone, Debug)]
pub struct NearConn<Conn> {
    conn: Arc<Mutex<Option<Conn>>>
}

impl ScopedError for NearConnectError {
    fn scope(&self) -> ErrorScope {
        match self {
            NearConnectError::IO { error } => error.scope(),
            NearConnectError::Transferred => ErrorScope::Unrecoverable,
            NearConnectError::Shutdown => ErrorScope::Shutdown,
            NearConnectError::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

impl<Conn, Auth> ScopedError for NearSessionError<Conn, Auth>
where Conn: ScopedError,
      Auth: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            NearSessionError::Conn { err } => err.scope(),
            NearSessionError::Auth { err } => err.scope(),
            NearSessionError::AuthFail => ErrorScope::Session
        }
    }
}

impl<Conn> From<Conn> for NearConn<Conn>
where
    Conn: Read + Write
{
    #[inline]
    fn from(conn: Conn) -> NearConn<Conn> {
        NearConn::from(Some(conn))
    }
}

impl<Conn> From<Option<Conn>> for NearConn<Conn>
where
    Conn: Read + Write
{
    #[inline]
    fn from(conn: Option<Conn>) -> NearConn<Conn> {
        NearConn::from(Arc::new(Mutex::new(conn)))
    }
}

impl<Conn> From<Arc<Mutex<Option<Conn>>>> for NearConn<Conn>
where
    Conn: Read + Write
{
    #[inline]
    fn from(conn: Arc<Mutex<Option<Conn>>>) -> NearConn<Conn> {
        NearConn { conn: conn }
    }
}

impl<Conn> Credentials for NearConn<Conn>
where
    Conn: Credentials
{
    type Cred = Conn::Cred;
    type CredError = WithMutexPoison<Conn::CredError>;

    #[inline]
    fn creds(&self) -> Result<Option<Self::Cred>, Self::CredError> {
        match self
            .conn
            .lock()
            .map_err(|_| WithMutexPoison::MutexPoison)?
            .as_ref()
        {
            Some(conn) => conn
                .creds()
                .map_err(|err| WithMutexPoison::Inner { err: err }),
            None => Ok(None)
        }
    }
}

impl<Conn> CredentialsMut for NearConn<Conn>
where
    Conn: CredentialsMut
{
    type Cred = Conn::Cred;
    type CredError = WithMutexPoison<Conn::CredError>;

    #[inline]
    fn creds(&mut self) -> Result<Option<Self::Cred>, Self::CredError> {
        match self
            .conn
            .lock()
            .map_err(|_| WithMutexPoison::MutexPoison)?
            .as_mut()
        {
            Some(conn) => conn
                .creds()
                .map_err(|err| WithMutexPoison::Inner { err: err }),
            None => Ok(None)
        }
    }
}

impl<Conn> Read for NearConn<Conn>
where
    Conn: Read + Write
{
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.read(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "mutex poisoned, aborting read"
            ))
        }
    }

    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.read_vectored(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "mutex poisoned, aborting read"
            ))
        }
    }

    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.read_to_end(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "mutex poisoned, aborting read"
            ))
        }
    }

    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.read_to_string(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "mutex poisoned, aborting read"
            ))
        }
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.read_exact(buf) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => Err(Error::new(
                ErrorKind::Other,
                "mutex poisoned, aborting read"
            ))
        }
    }
}

impl<Conn> Write for NearConn<Conn>
where
    Conn: Read + Write
{
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.write(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => {
                error!(target: "near-write",
                       "mutex poisoned, aborting write");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting write"
                ))
            }
        }
    }

    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.write_vectored(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => {
                error!(target: "near-write",
                       "mutex poisoned, aborting write");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting write"
                ))
            }
        }
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.write_all(buf) {
                    Ok(out) => Ok(out),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => {
                error!(target: "near-write",
                       "mutex poisoned, aborting write");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting write"
                ))
            }
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        match self.conn.lock() {
            Ok(mut guard) => match &mut *guard {
                Some(stream) => match stream.flush() {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        // Reset the stream dependending on the error kind.
                        match err.kind() {
                            // Don't reset for interrupted.
                            ErrorKind::Interrupted => {}
                            // Reset by default.
                            _ => *guard = None
                        }

                        Err(err)
                    }
                },
                // Connection was already terminated.
                None => Err(Error::new(
                    ErrorKind::NotConnected,
                    "reader connection is already closed"
                ))
            },
            // Mutex poisoned.
            Err(_) => {
                error!(target: "near-write",
                       "mutex poisoned, aborting flush");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting flush"
                ))
            }
        }
    }
}

impl Display for NearConnectError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            NearConnectError::IO { error } => write!(f, "{}", error),
            NearConnectError::Transferred => {
                write!(f, "connection has been transferred")
            }
            NearConnectError::Shutdown => {
                write!(f, "channel has been shut down")
            }
            NearConnectError::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}

impl<Conn, Auth> Display for NearSessionError<Conn, Auth>
where Conn: Display,
      Auth: Display {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            NearSessionError::Conn { err } => err.fmt(f),
            NearSessionError::Auth { err } => err.fmt(f),
            NearSessionError::AuthFail => write!(f, "authentication failed")
        }
    }
}
