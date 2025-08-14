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

//! GSSAPI-authenticated [NearChannel]s.
//!
//! This module provides [NearChannel] and [NearConnector] instances
//! that perform GSSAPI negotiation and session establishment.  This
//! provides an authenticated channel.
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
//! GSSAPI channels are deliberately *not* included in
//! [CompoundNearConnector](crate::near::compound::CompoundNearConnector) and
//! [CompoundNearAcceptor](crate::near::compound::CompoundNearAcceptor),
//! as it generally doesn't make sense to include them anywhere but at
//! the top level of a configuration.
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::time::Duration;

use constellation_auth::cred::Credentials;
use constellation_auth::cred::CredentialsMut;
use constellation_auth::cred::GSSAPICred;
use constellation_common::config::authn::ClientGSSAPIConfig;
use constellation_common::config::authn::GSSAPISecurity;
use constellation_common::config::authn::ServerGSSAPIConfig;
use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::retry::RetryResult;
use libgssapi::context::ClientCtx;
use libgssapi::context::CtxFlags;
use libgssapi::context::SecurityContext;
use libgssapi::context::ServerCtx;
use libgssapi::credential::Cred;
use libgssapi::credential::CredUsage;
use libgssapi::name::Name;
use libgssapi::oid::OidSet;
use libgssapi::oid::GSS_MECH_KRB5;
use libgssapi::oid::GSS_NT_HOSTBASED_SERVICE;
use libgssapi::util::Buf;
use log::debug;
use log::trace;
use log::warn;
use mio::event::Source;
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

// This rips off the wire format for SOCKS5 GSSAPI messages.

const GSSAPI_VERSION: u8 = 0x01;
const GSSAPI_CTX_NEGOTIATE: u8 = 0x01;
const GSSAPI_CTX_NEGOTIATE_ERROR: u8 = 0xff;
const GSSAPI_SECLVL_NEGOTIATE: u8 = 0x02;
const GSSAPI_PAYLOAD: u8 = 0x03;

/// Representation of errors that can occur in GSSAPI portions of the
/// protocol.
#[derive(Debug)]
pub enum GSSAPIError {
    /// Low-level IO error.
    IO {
        /// IO error.
        err: Error
    },
    /// GSSAPI error.
    GSSAPI {
        /// GSSAPI error.
        err: libgssapi::error::Error
    },
    /// Security level was not accepted.
    BadSecLvl,
    /// Bad protocol version.
    BadVersion,
    /// Bad operation code.
    BadOpcode
}

/// Errors that can occur when setting up a GSSAPI connection.
#[derive(Debug)]
pub enum GSSAPINegotiationError<E, Stream> {
    /// Error in GSSAPI negotiation.
    GSSAPI {
        stream: Stream,
        /// The error from GSSAPI negotiation.
        err: GSSAPIError,
    },
    /// Error while obtaining the underlying connection.
    Connection {
        /// Error from obtaining the connection.
        err: E
    }
}

pub enum GSSAPINegotiationPending<Inner, Endpoint, Stream, Ctx> {
    GSSAPI {
        endpoint: Endpoint,
        stream: Stream,
        ctx: Ctx
    },
    Inner {
        inner: Inner
    }
}

/// Errors that can occur when obtaining GSSAPI credentials.
#[derive(Debug)]
pub enum GSSAPICredError<Inner> {
    /// Error in GSSAPI.
    GSSAPI {
        /// The error from GSSAPI.
        err: libgssapi::error::Error
    },
    /// Error from the underlying connection.
    Inner {
        /// Error from the connection.
        err: Inner
    }
}

/// GSSAPI-wrapped streams.
///
/// This provides [Read] and [Write] functionality for GSSAPI
/// connections post-negotiation.
#[derive(Debug)]
pub struct GSSAPIStream<Stream, Ctx>
where
    Stream: Source + Read + Write,
    Ctx: SecurityContext {
    /// The GSSAPI context.
    ctx: Ctx,
    /// The underlying stream.
    stream: Stream
}

/// [NearChannel] instance that performs GSSAPI session negotiation.
pub struct GSSAPINearAcceptor<A: Source + NearChannel> {
    config: ServerGSSAPIConfig,
    /// Server credential name.
    inner: A
}

/// [NearConnector] instance that performs GSSAPI session negotiation.
pub struct GSSAPINearConnector<Conn: NearConnector> {
    inner: Conn,
    /// Client credential name.
    name: Option<String>,
    /// Service name.
    service: String,
    time_req: Option<Duration>,
    /// Optional GSSAPI bindings.
    bindings: Option<Vec<u8>>,
    security: GSSAPISecurity
}

/// Configuration object for a [GSSAPINearAcceptor].
#[derive(Clone)]
pub struct GSSAPINearAcceptorConfig<A: NearChannel> {
    config: ServerGSSAPIConfig,
    /// Optional GSSAPI bindings.
    inner: A
}

/// Configuration object for a [GSSAPINearConnector].
#[derive(Clone)]
pub struct GSSAPINearConnectorConfig<Conn: NearChannel> {
    /// Client credential name.
    name: Option<String>,
    /// Service name.
    service: String,
    time_req: Option<Duration>,
    /// Optional GSSAPI bindings.
    bindings: Option<Vec<u8>>,
    /// GSSAPI security level.
    security: GSSAPISecurity,
    /// Configuration for the underlying channel.
    inner: Conn::Config
}

/// Credentials harvested from a [GSSAPIStream].
pub struct GSSAPIStreamCred<Stream> {
    gssapi: Option<GSSAPICred>,
    inner: Option<Stream>
}

impl<A> Source for GSSAPINearAcceptor<A>
where
    A: Source + NearChannel
{
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

impl<Stream, Ctx> Source for GSSAPIStream<Stream, Ctx>
where
    Stream: Source + Read + Write,
    Ctx: SecurityContext
{
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.stream.register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.stream.reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.stream.deregister(registry)
    }
}

impl<Stream> GSSAPIStreamCred<Stream> {
    #[inline]
    pub fn gssapi(&self) -> Option<&GSSAPICred> {
        self.gssapi.as_ref()
    }

    #[inline]
    pub fn stream(&self) -> Option<&Stream> {
        self.inner.as_ref()
    }
}

impl<Conn> GSSAPINearConnectorConfig<Conn>
where
    Conn: NearConnector
{
    #[inline]
    pub fn from_config(
        config: ClientGSSAPIConfig,
        service_default: String,
        bindings: Option<Vec<u8>>,
        inner: Conn::Config
    ) -> Self {
        let (name, service, time_req, security) = config.take();

        GSSAPINearConnectorConfig {
            service: service.unwrap_or(service_default),
            name: name,
            security: security,
            inner: inner,
            time_req: time_req,
            bindings: bindings
        }
    }
}

impl<Stream> CredentialsMut for GSSAPIStream<Stream, ServerCtx>
where
    Stream: Source + CredentialsMut + Read + Write
{
    type Cred = GSSAPIStreamCred<Stream::Cred>;
    type CredError = GSSAPICredError<Stream::CredError>;

    #[inline]
    fn creds(
        &mut self
    ) -> Result<Option<GSSAPIStreamCred<Stream::Cred>>, Self::CredError> {
        let gssapi = self
            .ctx
            .creds()
            .map_err(|err| GSSAPICredError::GSSAPI { err: err })?;
        let inner = self
            .stream
            .creds()
            .map_err(|err| GSSAPICredError::Inner { err: err })?;

        match (gssapi, inner) {
            (None, None) => Ok(None),
            (gssapi, inner) => Ok(Some(GSSAPIStreamCred {
                gssapi: gssapi,
                inner: inner
            }))
        }
    }
}

impl<Stream> CredentialsMut for GSSAPIStream<Stream, ClientCtx>
where
    Stream: Source + CredentialsMut + Read + Write
{
    type Cred = GSSAPIStreamCred<Stream::Cred>;
    type CredError = GSSAPICredError<Stream::CredError>;

    #[inline]
    fn creds(
        &mut self
    ) -> Result<Option<GSSAPIStreamCred<Stream::Cred>>, Self::CredError> {
        let gssapi = self
            .ctx
            .creds()
            .map_err(|err| GSSAPICredError::GSSAPI { err: err })?;
        let inner = self
            .stream
            .creds()
            .map_err(|err| GSSAPICredError::Inner { err: err })?;

        match (gssapi, inner) {
            (None, None) => Ok(None),
            (gssapi, inner) => Ok(Some(GSSAPIStreamCred {
                gssapi: gssapi,
                inner: inner
            }))
        }
    }
}

// ISSUE #8: We may need to check the time on the context and kill the
// connection if it's expired.

impl<Stream, Ctx> Read for GSSAPIStream<Stream, Ctx>
where
    Stream: Source + Read + Write,
    Ctx: SecurityContext
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        let msg = parse_gssapi_payload(&mut self.stream, &mut self.ctx)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
        let len = msg.len();

        buf.clone_from_slice(msg.as_ref());

        Ok(len)
    }
}

impl<Stream, Ctx> Write for GSSAPIStream<Stream, Ctx>
where
    Stream: Source + Read + Write,
    Ctx: SecurityContext
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        let len = buf.len();

        write_gssapi_payload(&mut self.stream, &mut self.ctx, buf)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;

        Ok(len)
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        write_gssapi_payload(&mut self.stream, &mut self.ctx, buf)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.stream.flush()
    }
}

#[inline]
fn write_gssapi_step<W>(
    stream: &mut W,
    msg: &Buf
) -> Result<(), Error>
where
    W: Write {
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_CTX_NEGOTIATE);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    stream.write_all(&buf)
}

fn parse_gssapi_step<R>(stream: &mut R) -> Result<Vec<u8>, Error>
where
    R: Read {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream.read_exact(&mut buf[..])?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Read in the token and return it.
        (GSSAPI_VERSION, GSSAPI_CTX_NEGOTIATE) => {
            let mut buf = [0; 2];

            stream.read_exact(&mut buf[..])?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream.read_exact(&mut buf[..])?;

            Ok(buf)
        }
        // Server rejected the authentication attempt.
        (GSSAPI_VERSION, GSSAPI_CTX_NEGOTIATE_ERROR) =>
            Err(Error::new(ErrorKind::Other, "authentication failed")),
        // Bad reply type.
        (GSSAPI_VERSION, _) =>
            Err(Error::new(ErrorKind::Other, "bad GSSAPI reply type")),
        // Bad version.
        _ => Err(Error::new(ErrorKind::Other, "bad protocol version code"))
    }
}

#[inline]
fn write_gssapi_seclvl<W, Ctx>(
    stream: &mut W,
    ctx: &mut Ctx,
    seclvl: u8
) -> Result<(), GSSAPIError>
where
    Ctx: SecurityContext,
    W: Write {
    let msg = ctx
        .wrap(true, &[seclvl])
        .map_err(|err| GSSAPIError::GSSAPI { err: err })?;
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_SECLVL_NEGOTIATE);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    stream
        .write_all(&buf)
        .map_err(|err| GSSAPIError::IO { err: err })
}

#[inline]
fn parse_gssapi_seclvl<R, Ctx>(
    stream: &mut R,
    ctx: &mut Ctx
) -> Result<u8, GSSAPIError>
where
    Ctx: SecurityContext,
    R: Read {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| GSSAPIError::IO { err: err })?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Unwrap the message and extract the security level.
        (GSSAPI_VERSION, GSSAPI_SECLVL_NEGOTIATE) => {
            let mut buf = [0; 2];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| GSSAPIError::IO { err: err })?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| GSSAPIError::IO { err: err })?;

            let buf = ctx
                .unwrap(&buf)
                .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

            Ok(buf[0])
        }
        // Bad reply type.
        (GSSAPI_VERSION, reply) => {
            warn!(target: "socks5-proto",
                  "bad GSSAPI operation type ({})",
                  reply);

            Err(GSSAPIError::BadOpcode)
        }
        // Bad version.
        (version, _) => {
            warn!(target: "gssapi-near",
                  "bad GSSAPI protocol version ({})",
                  version);

            Err(GSSAPIError::BadVersion)
        }
    }
}

fn write_gssapi_payload<W, Ctx>(
    stream: &mut W,
    ctx: &mut Ctx,
    msg: &[u8]
) -> Result<(), GSSAPIError>
where
    W: Write,
    Ctx: SecurityContext {
    let msg = ctx
        .wrap(true, msg)
        .map_err(|err| GSSAPIError::GSSAPI { err: err })?;
    let len = msg.len();
    let mut buf = Vec::with_capacity(len + 4);
    let len = len as u16;

    buf.push(GSSAPI_VERSION);
    buf.push(GSSAPI_PAYLOAD);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend(msg.as_ref());

    stream
        .write_all(&buf)
        .map_err(|err| GSSAPIError::IO { err: err })
}

fn parse_gssapi_payload<R, Ctx>(
    stream: &mut R,
    ctx: &mut Ctx
) -> Result<Buf, GSSAPIError>
where
    R: Read,
    Ctx: SecurityContext {
    // Read the first two bytes to determine whether there is more.
    let mut buf = [0; 2];

    stream
        .read_exact(&mut buf[..])
        .map_err(|err| GSSAPIError::IO { err: err })?;

    // Check the version and status.
    match (buf[0], buf[1]) {
        // Unwrap the payload.
        (GSSAPI_VERSION, GSSAPI_PAYLOAD) => {
            let mut buf = [0; 2];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| GSSAPIError::IO { err: err })?;

            let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
            let mut buf = vec![0; len];

            stream
                .read_exact(&mut buf[..])
                .map_err(|err| GSSAPIError::IO { err: err })?;

            let buf = ctx
                .unwrap(&buf)
                .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

            Ok(buf)
        }
        // Bad reply type.
        (GSSAPI_VERSION, reply) => {
            warn!(target: "gssapi-near",
                  "bad GSSAPI operation type ({})",
                  reply);

            Err(GSSAPIError::BadOpcode)
        }
        // Bad version.
        (version, _) => {
            warn!(target: "gssapi-near",
                  "bad GSSAPI protocol version ({})",
                  version);

            Err(GSSAPIError::BadVersion)
        }
    }
}

impl<A: Source + NearChannel> GSSAPINearAcceptor<A> {
    /// Prepare a GSSAPI context.
    fn prepare_gssapi(&self) -> Result<ServerCtx, libgssapi::error::Error> {
        // Prepare the mechanisms.
        let mut mechs = OidSet::new()?;

        mechs.add(&GSS_MECH_KRB5)?;

        // Prepare the principal name.
        let cred = match &self.config.name() {
            // A principal name was provided.
            Some(name) => {
                let name = Name::new(
                    name.as_bytes(),
                    Some(&GSS_NT_HOSTBASED_SERVICE)
                )?;
                let name = name.canonicalize(Some(&GSS_MECH_KRB5))?;

                Cred::acquire(
                    Some(&name),
                    self.config.time_req(),
                    CredUsage::Initiate,
                    Some(&mechs)
                )?
            }
            // No principal name was provided.
            None => Cred::acquire(
                None,
                self.config.time_req(),
                CredUsage::Initiate,
                Some(&mechs)
            )?
        };

        Ok(ServerCtx::new(Some(cred)))
    }

    fn gssapi_negotiate(
        &self,
        conn: &mut A::Conn
    ) -> Result<NegotiatorResult<ServerCtx, ServerCtx>, GSSAPIError> {
        let ctx = self
            .prepare_gssapi()
            .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

        debug!(target: "gssapi-near",
               "beginning GSSAPI negotiation");

        self.gssapi_negotiate_with_ctx(conn, ctx)
    }

    fn gssapi_negotiate_with_ctx(
        &self,
        conn: &mut A::Conn,
        mut ctx: ServerCtx
    ) -> Result<NegotiatorResult<ServerCtx, ServerCtx>, GSSAPIError> {
        // Do context negotiation.
        while let Some(msg) = {
            let token = match parse_gssapi_step(conn) {
                Ok(token) => token,
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::Interrupted =>
                        return Ok(NegotiatorResult::Pending(ctx)),
                    _ => return Err(GSSAPIError::IO { err: err })
                }
            };

            ctx.step(&token)
                .map_err(|err| GSSAPIError::GSSAPI { err: err })?
        } {
            trace!(target: "gssapi-near",
                   "continuing GSSAPI authentication");

            if let Err(err) = write_gssapi_step(conn, &msg) {
                match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::Interrupted =>
                        return Ok(NegotiatorResult::Pending(ctx)),
                    _ => return Err(GSSAPIError::IO { err: err })
                }
            }
        }

        // Do security level negotiation.
        debug!(target: "gssapi-near",
               "GSSAPI context established, negotiating security level");

        let _ = parse_gssapi_seclvl(conn, &mut ctx)?;

        // The Rust bindings don't actually supply any means by
        // which to interrogate or set security levels.
        //
        // Since Kerberos uses DES (ick!), we'll just hardwire it to 56.
        write_gssapi_seclvl(conn, &mut ctx, 56)?;

        Ok(NegotiatorResult::Complete(ctx))
    }
}

impl<A> Negotiator<(GSSAPIStream<A::Conn, ServerCtx>, A::Endpoint)>
    for GSSAPINearAcceptor<A>
where
    A: Source + NearChannel,
{
    type State = A::State;
    type Pending = GSSAPINegotiationPending<
        A::Pending,
        A::Endpoint,
        A::Conn,
        ServerCtx
    >;
    type NegotiateError = GSSAPINegotiationError<A::NegotiateError, A::Conn>;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<A::Conn, ServerCtx>, A::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        self.inner
            .negotiate(state)
            .map_err(|err| GSSAPINegotiationError::Connection { err: err })?
            .map_pending(|inner| GSSAPINegotiationPending::Inner {
                inner: inner
            })
            .flat_map_ok(|(mut stream, endpoint)| {
                match self.gssapi_negotiate(&mut stream) {
                    Ok(res) => match res {
                        NegotiatorResult::Complete(ctx) =>
                            Ok(NegotiatorResult::Complete(
                                (GSSAPIStream {
                                    ctx: ctx,
                                    stream: stream
                                },
                                 endpoint)
                            )),
                        NegotiatorResult::Pending(ctx) =>
                            Ok(NegotiatorResult::Pending(
                                GSSAPINegotiationPending::GSSAPI {
                                    endpoint: endpoint,
                                    stream: stream,
                                    ctx: ctx
                                }
                            )),
                    }
                    Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                        stream: stream,
                        err: err
                    })
                }
            })
    }

    fn complete_negotiate(
        &self,
        pending: GSSAPINegotiationPending<
            A::Pending,
            A::Endpoint,
            A::Conn,
            ServerCtx
        >
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<A::Conn, ServerCtx>, A::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        match pending {
            GSSAPINegotiationPending::Inner { inner } => self
                .inner
                .complete_negotiate(inner)
                .map_err(|err| GSSAPINegotiationError::Connection { err: err })?
                .map_pending(|inner| GSSAPINegotiationPending::Inner {
                    inner: inner
                })
                .flat_map_ok(|(mut stream, endpoint)| {
                    match self.gssapi_negotiate(&mut stream) {
                        Ok(res) => match res {
                            NegotiatorResult::Complete(ctx) =>
                                Ok(NegotiatorResult::Complete(
                                    (GSSAPIStream {
                                        ctx: ctx,
                                        stream: stream
                                    },
                                     endpoint)
                                )),
                            NegotiatorResult::Pending(ctx) =>
                                Ok(NegotiatorResult::Pending(
                                    GSSAPINegotiationPending::GSSAPI {
                                        endpoint: endpoint,
                                        stream: stream,
                                        ctx: ctx
                                    }
                                )),
                        }
                        Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                            stream: stream,
                            err: err
                        })
                    }
                }),
            GSSAPINegotiationPending::GSSAPI {
                mut stream, endpoint, ctx
            } => match self.gssapi_negotiate_with_ctx(&mut stream, ctx) {
                Ok(res) => match res {
                    NegotiatorResult::Complete(ctx) =>
                        Ok(NegotiatorResult::Complete(
                            (GSSAPIStream {
                                ctx: ctx,
                                stream: stream
                            },
                             endpoint)
                        )),
                    NegotiatorResult::Pending(ctx) =>
                        Ok(NegotiatorResult::Pending(
                            GSSAPINegotiationPending::GSSAPI {
                                endpoint: endpoint,
                                stream: stream,
                                ctx: ctx
                            }
                        )),
                }
                Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                    stream: stream,
                    err: err
                })
            }
        }
    }
}

impl<A> NearChannel for GSSAPINearAcceptor<A>
where
    A: Source + NearChannel,
{
    type Config = GSSAPINearAcceptorConfig<A>;
    type Endpoint = A::Endpoint;
    type Conn = GSSAPIStream<A::Conn, ServerCtx>;
    type StartError = A::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.inner.start(registry, token)
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: GSSAPINegotiationError<A::NegotiateError, A::Conn>
    ) -> Result<(), Error> {
        match err {
            GSSAPINegotiationError::Connection { err } =>
                self.inner.cleanup(registry, err),
            GSSAPINegotiationError::GSSAPI { mut stream, .. } =>
                registry.deregister(&mut stream),
        }
    }
}

impl<A> NearChannelCreate for GSSAPINearAcceptor<A>
where
    A: Source + NearChannelCreate,
{
    type CreateError = Infallible;

    #[inline]
    fn new<Ctx>(
        _caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        Ok(GSSAPINearAcceptor {
            inner: config.inner,
            config: config.config
        })
    }
}

impl<Conn: NearConnector> GSSAPINearConnector<Conn> {
    /// Prepare a GSSAPI context.
    fn prepare_gssapi(&self) -> Result<ClientCtx, libgssapi::error::Error> {
        // Prepare the mechanisms.
        let mut mechs = OidSet::new()?;

        mechs.add(&GSS_MECH_KRB5)?;

        // Prepare the principal name.
        let cred = match &self.name {
            // A principal name was provided.
            Some(name) => {
                let name = Name::new(
                    name.as_bytes(),
                    Some(&GSS_NT_HOSTBASED_SERVICE)
                )?;
                let name = name.canonicalize(Some(&GSS_MECH_KRB5))?;

                Cred::acquire(
                    Some(&name),
                    self.time_req,
                    CredUsage::Initiate,
                    Some(&mechs)
                )?
            }
            // No principal name was provided.
            None => Cred::acquire(
                None,
                self.time_req,
                CredUsage::Initiate,
                Some(&mechs)
            )?
        };

        // Prepare the service name.
        let service = Name::new(
            self.service.as_bytes(),
            Some(&GSS_NT_HOSTBASED_SERVICE)
        )?;
        let service = service.canonicalize(Some(&GSS_MECH_KRB5))?;

        Ok(ClientCtx::new(
            Some(cred),
            service,
            CtxFlags::GSS_C_MUTUAL_FLAG,
            Some(&GSS_MECH_KRB5)
        ))
    }

    fn gssapi_negotiate(
        &self,
        conn: &mut Conn::Conn
    ) -> Result<NegotiatorResult<ClientCtx, ClientCtx>, GSSAPIError> {
        let ctx = self
            .prepare_gssapi()
            .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

        debug!(target: "gssapi-near",
               "beginning GSSAPI authentication");

        self.gssapi_negotiate_with_ctx(conn, ctx)
    }

    fn gssapi_negotiate_with_ctx(
        &self,
        conn: &mut Conn::Conn,
        mut ctx: ClientCtx
    ) -> Result<NegotiatorResult<ClientCtx, ClientCtx>, GSSAPIError> {
        let bindings = self.bindings.as_ref().map(|b| &b[..]);

        // Do context negotiation.
        let mut res = ctx
            .step(None, bindings)
            .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

        while let Some(msg) = res {
            trace!(target: "gssapi-near",
                   "continuing GSSAPI authentication");

            if let Err(err) = write_gssapi_step(conn, &msg) {
                match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::Interrupted =>
                        return Ok(NegotiatorResult::Pending(ctx)),
                    _ => return Err(GSSAPIError::IO { err: err })
                }
            }

            let token = match parse_gssapi_step(conn) {
                Ok(token) => token,
                Err(err) => match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::Interrupted =>
                        return Ok(NegotiatorResult::Pending(ctx)),
                    _ => return Err(GSSAPIError::IO { err: err })
                }
            };

            res = ctx
                .step(Some(&token), bindings)
                .map_err(|err| GSSAPIError::GSSAPI { err: err })?;
        }

        debug!(target: "gssapi-near",
               "GSSAPI context established, negotiating security level");

        // Do security level negotiation.
        write_gssapi_seclvl(conn, &mut ctx, self.security.seclvl())?;

        let seclvl = parse_gssapi_seclvl(conn, &mut ctx)?;

        trace!(target: "gssapi-near",
               "server replied with security level {}",
               seclvl);

        if !self.security.is_required() || self.security.seclvl() >= seclvl {
            trace!(target: "gssapi-near",
                   "security level {} accepted",
                   seclvl);
            Ok(ctx)
        } else {
            trace!(target: "gssapi-near",
                   "security level {} not accepted",
                   seclvl);

            Err(GSSAPIError::BadSecLvl)
        }
    }
}

impl<C> Negotiator<(GSSAPIStream<C::Conn, ClientCtx>, C::Endpoint)>
    for GSSAPINearConnector<C>
where
    C: Source + NearConnector,
{
    type State = C::State;
    type Pending = GSSAPINegotiationPending<
        C::Pending,
        C::Endpoint,
        C::Conn,
        ClientCtx
    >;
    type NegotiateError = GSSAPINegotiationError<C::NegotiateError, C::Conn>;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<C::Conn, ClientCtx>, C::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        self.inner
            .negotiate(state)
            .map_err(|err| GSSAPINegotiationError::Connection { err: err })?
            .map_pending(|inner| GSSAPINegotiationPending::Inner {
                inner: inner
            })
            .flat_map_ok(|(mut stream, endpoint)| {
                match self.gssapi_negotiate(&mut stream) {
                    Ok(res) => match res {
                        NegotiatorResult::Complete(ctx) =>
                            Ok(NegotiatorResult::Complete(
                                (GSSAPIStream {
                                    ctx: ctx,
                                    stream: stream
                                },
                                 endpoint)
                            )),
                        NegotiatorResult::Pending(ctx) =>
                            Ok(NegotiatorResult::Pending(
                                GSSAPINegotiationPending::GSSAPI {
                                    endpoint: endpoint,
                                    stream: stream,
                                    ctx: ctx
                                }
                            )),
                    }
                    Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                        stream: stream,
                        err: err
                    })
                }
            })
    }

    fn complete_negotiate(
        &self,
        pending: GSSAPINegotiationPending<
            C::Pending,
            C::Endpoint,
            C::Conn,
            ClientCtx
        >
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<C::Conn, ClientCtx>, C::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        match pending {
            GSSAPINegotiationPending::Inner { inner } => self
                .inner
                .complete_negotiate(inner)
                .map_err(|err| GSSAPINegotiationError::Connection { err: err })?
                .map_pending(|inner| GSSAPINegotiationPending::Inner {
                    inner: inner
                })
                .flat_map_ok(|(mut stream, endpoint)| {
                    match self.gssapi_negotiate(&mut stream) {
                        Ok(res) => match res {
                            NegotiatorResult::Complete(ctx) =>
                                Ok(NegotiatorResult::Complete(
                                    (GSSAPIStream {
                                        ctx: ctx,
                                        stream: stream
                                    },
                                     endpoint)
                                )),
                            NegotiatorResult::Pending(ctx) =>
                                Ok(NegotiatorResult::Pending(
                                    GSSAPINegotiationPending::GSSAPI {
                                        endpoint: endpoint,
                                        stream: stream,
                                        ctx: ctx
                                    }
                                )),
                        }
                        Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                            stream: stream,
                            err: err
                        })
                    }
                }),
            GSSAPINegotiationPending::GSSAPI {
                mut stream, endpoint, ctx
            } => match self.gssapi_negotiate_with_ctx(&mut stream, ctx) {
                Ok(res) => match res {
                    NegotiatorResult::Complete(ctx) =>
                        Ok(NegotiatorResult::Complete(
                            (GSSAPIStream {
                                ctx: ctx,
                                stream: stream
                            },
                             endpoint)
                        )),
                    NegotiatorResult::Pending(ctx) =>
                        Ok(NegotiatorResult::Pending(
                            GSSAPINegotiationPending::GSSAPI {
                                endpoint: endpoint,
                                stream: stream,
                                ctx: ctx
                            }
                        )),
                }
                Err(err) => Err(GSSAPINegotiationError::GSSAPI {
                    stream: stream,
                    err: err
                })
            }
        }
    }
}

impl<C> NearChannel for GSSAPINearConnector<C>
where
    C: Source + NearConnector,
{
    type Config = GSSAPINearConnectorConfig<C>;
    type Endpoint = C::Endpoint;
    type Conn = GSSAPIStream<C::Conn, ClientCtx>;
    type StartError = C::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        self.inner.start(registry, token)
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: GSSAPINegotiationError<C::NegotiateError, C::Conn>
    ) -> Result<(), Error> {
        match err {
            GSSAPINegotiationError::Connection { err } =>
                self.inner.cleanup(registry, err),
            GSSAPINegotiationError::GSSAPI { mut stream, .. } =>
                registry.deregister(&mut stream),
        }
    }
}

impl<Conn> NearConnector for GSSAPINearConnector<Conn>
where
    Conn: Source + NearConnector,
    Conn::Conn: Source + Credentials + Read + Write
{
    /// Type of endpoint references.
    type EndpointRef<'a> = Conn::EndpointRef<'a>
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.inner.endpoint()
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Conn::verify_endpoint(&config.inner)
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
}

impl ScopedError for GSSAPIError {
    fn scope(&self) -> ErrorScope {
        match self {
            GSSAPIError::IO { err } => err.scope(),
            GSSAPIError::GSSAPI { .. } => ErrorScope::Session,
            GSSAPIError::BadSecLvl | GSSAPIError::BadVersion => {
                ErrorScope::External
            }
            GSSAPIError::BadOpcode => ErrorScope::Session
        }
    }
}

impl<E, S> ScopedError for GSSAPINegotiationError<E, S>
where
    E: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            GSSAPINegotiationError::Connection { err } => err.scope(),
            GSSAPINegotiationError::GSSAPI { err, .. } => err.scope()
        }
    }
}

impl<E> ScopedError for GSSAPICredError<E>
where
    E: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            GSSAPICredError::Inner { err } => err.scope(),
            GSSAPICredError::GSSAPI { .. } => ErrorScope::Session
        }
    }
}

impl Display for GSSAPIError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            GSSAPIError::IO { err } => err.fmt(f),
            GSSAPIError::GSSAPI { err } => err.fmt(f),
            GSSAPIError::BadSecLvl => {
                write!(f, concat!("security level ", "was not accepted"))
            }
            GSSAPIError::BadVersion => write!(f, "bad protocol version code"),
            GSSAPIError::BadOpcode => write!(f, "bad protocol operation code")
        }
    }
}

impl<E, S> Display for GSSAPINegotiationError<E, S>
where
    E: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            GSSAPINegotiationError::Connection { err } => err.fmt(f),
            GSSAPINegotiationError::GSSAPI { err, .. } => err.fmt(f)
        }
    }
}

impl<E> Display for GSSAPICredError<E>
where
    E: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            GSSAPICredError::Inner { err } => err.fmt(f),
            GSSAPICredError::GSSAPI { err } => err.fmt(f)
        }
    }
}
