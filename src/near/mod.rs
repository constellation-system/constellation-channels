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

use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use log::error;

use crate::resolve::cache::NSNameCachesCtx;

pub mod compound;
#[cfg(feature = "gssapi")]
pub mod gssapi;
pub(crate) mod session;
mod socket;
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
/// interface, with [take_connection](NearChannel::take_connection)
/// functioning similar to the "accept" function often found in such
/// interfaces.
///
/// Client-side channels typically also implement the [NearConnector]
/// trait.  The [take_connection](NearChannel::take_connection)
/// function is typically used only by higher-level protocols to take
/// exclusive possession of the channel, thus eliminating the need for
/// a layer of locking and sharing.  The
/// [TLSNearConnector](crate::near::tls::TLSNearConnector) and
/// [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector)
/// instances function in this manner with regard to their underlying
/// channels.
pub trait NearChannel: Sized {
    /// Type of streams where ownership is transferred.
    ///
    /// See [take_connection](NearChannel::take_connection).
    type Stream: CredentialsMut + Read + Write + Debug + Sized;
    /// Type of connection endpoints.
    ///
    /// See [take_connection](NearChannel::take-connection)
    /// [endpoint](NearConnector::endpoint).
    type Endpoint: Clone + Display + Sized;
    type TakeConnectError: Display + ScopedError + Sized;
    /// Type of configurations.
    type Config;

    /// Acquire a connection and return the exclusively-owned
    /// underlying stream.
    ///
    /// This will block until a connection is successfully acquired.
    /// Failed attempts at connecting will be handled internally.  Any
    /// errors returned by this function represent hard programming
    /// errors, not connection failures or misconfigurations.
    ///
    /// After this call succeeds, subsequent calls to this function
    /// will fail with an error until the underlying connection is
    /// terminated.  For instances that also implement [NearConnector],
    /// calls to [connection](NearConnector::connection) will also
    /// fail with an error after this call succeeds, until
    /// [fail](NearConnector::fail) is called.
    fn take_connection(
        &mut self
    ) -> Result<(Self::Stream, Self::Endpoint), Self::TakeConnectError>;
}

/// Trait for creating instances of near-link channels.
pub trait NearChannelCreate: NearChannel {
    /// Type of errors that can be returned from [new](NearChannelCreate::new).
    type CreateError: Display + ScopedError + Sized;

    /// Create a new instance from `config`.
    fn new<Ctx>(
        caches: &mut Ctx,
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
    /// Type of the write half for the split reader/writer interface.
    ///
    /// See [connection](NearConnector::connection).
    type Writer: Write;
    /// Type of the read half for the split reader/writer interface.
    ///
    /// See [connection](NearConnector::connection).
    type Reader: Read;
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
    #[inline]
    fn verify_endpoint(_conf: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }

    /// Indicate a failure of a higher-level protocol, and reset this
    /// connector.
    ///
    /// The number of failures is given by `nretries`, and will be
    /// used to set the retry count on the lowest-level protocol,
    /// which will in turn affect the retry delay.
    fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error>;

    /// Shut down this connector and all lower-level connectors.
    ///
    /// Subsequent attempts to acquire any connection will fail.
    fn shutdown(&mut self) -> Result<(), Error>;

    /// Acquire a connection and return shared reader/writer references.
    ///
    /// This will block until a connection is successfully acquired.
    /// Failed attempts at connecting will be handled internally.  Any
    /// errors returned by this function represent hard programming
    /// errors, not connection failures or misconfigurations.
    fn connection(
        &mut self
    ) -> Result<
        (Self::Reader, Self::Writer, Self::EndpointRef<'_>),
        NearConnectError
    >;
}

/// Errors that can occur for [connection](NearConnector::connection)
/// or [take_connection](NearChannel::take_connection).
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

/// Wrapper for the read half of shared, split read/write streams.
///
/// This implements [Read] and [Clone] on an underlying stream
/// that does not.  An instance can be created using the [From]
/// instance.
#[derive(Clone)]
pub struct NearReader<Stream: Read> {
    stream: Arc<Mutex<Option<Stream>>>
}

/// Wrapper for the write half of shared, split read/write streams.
///
/// This implements [Write] and [Clone] on an underlying stream
/// that does not.  An instance can be created using the [From]
/// instance.
#[derive(Clone)]
pub struct NearWriter<Stream: Write> {
    stream: Arc<Mutex<Option<Stream>>>
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

impl<Stream> From<Stream> for NearReader<Stream>
where
    Stream: Read
{
    #[inline]
    fn from(stream: Stream) -> NearReader<Stream> {
        NearReader::from(Some(stream))
    }
}

impl<Stream> From<Option<Stream>> for NearReader<Stream>
where
    Stream: Read
{
    #[inline]
    fn from(stream: Option<Stream>) -> NearReader<Stream> {
        NearReader::from(Arc::new(Mutex::new(stream)))
    }
}

impl<Stream> From<Arc<Mutex<Option<Stream>>>> for NearReader<Stream>
where
    Stream: Read
{
    #[inline]
    fn from(stream: Arc<Mutex<Option<Stream>>>) -> NearReader<Stream> {
        NearReader { stream: stream }
    }
}

impl<Stream> From<Stream> for NearWriter<Stream>
where
    Stream: Write
{
    #[inline]
    fn from(stream: Stream) -> NearWriter<Stream> {
        NearWriter::from(Some(stream))
    }
}

impl<Stream> From<Option<Stream>> for NearWriter<Stream>
where
    Stream: Write
{
    #[inline]
    fn from(stream: Option<Stream>) -> NearWriter<Stream> {
        NearWriter::from(Arc::new(Mutex::new(stream)))
    }
}

impl<Stream> From<Arc<Mutex<Option<Stream>>>> for NearWriter<Stream>
where
    Stream: Write
{
    #[inline]
    fn from(stream: Arc<Mutex<Option<Stream>>>) -> NearWriter<Stream> {
        NearWriter { stream: stream }
    }
}

impl<Stream> Read for NearReader<Stream>
where
    Stream: Read
{
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self.stream.lock() {
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
            Err(_) => {
                error!(target: "near-read",
                       "mutex poisoned, aborting read");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting read"
                ))
            }
        }
    }

    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self.stream.lock() {
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
            Err(_) => {
                error!(target: "near-read",
                       "mutex poisoned, aborting read");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting read"
                ))
            }
        }
    }

    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self.stream.lock() {
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
            Err(_) => {
                error!(target: "near-read",
                       "mutex poisoned, aborting read");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting read"
                ))
            }
        }
    }

    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self.stream.lock() {
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
            Err(_) => {
                error!(target: "near-read",
                       "mutex poisoned, aborting read");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting read"
                ))
            }
        }
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self.stream.lock() {
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
            Err(_) => {
                error!(target: "near-read",
                       "mutex poisoned, aborting read");

                Err(Error::new(
                    ErrorKind::Other,
                    "mutex poisoned, aborting read"
                ))
            }
        }
    }
}

impl<Stream> Write for NearWriter<Stream>
where
    Stream: Write
{
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self.stream.lock() {
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
        match self.stream.lock() {
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
        match self.stream.lock() {
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
        match self.stream.lock() {
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
