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
use constellation_streams::state_machine::OnceMachineAction;
use constellation_streams::state_machine::RawMachineState;
use constellation_streams::state_machine::RawOnceMachineState;
use constellation_streams::state_machine::RawStateMachine;
use constellation_streams::state_machine::RawStateMachineError;
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
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

// This rips off the wire format for SOCKS5 GSSAPI messages.

const GSSAPI_VERSION: u8 = 0x01;
const GSSAPI_CTX_NEGOTIATE: u8 = 0x01;
const GSSAPI_CTX_NEGOTIATE_ERROR: u8 = 0xff;
const GSSAPI_SECLVL_NEGOTIATE: u8 = 0x02;
const GSSAPI_PAYLOAD: u8 = 0x03;

pub enum GSSAPIClientState {
    GSSAPIStart,
    /// GSSAPI auhentication.
    GSSAPIAuthN {
        /// GSSAPI context.
        ctx: ClientCtx,
        /// Buffered message to write.
        msg: Buf
    },
    /// GSSAPI security level negotiation.
    GSSAPISecLvl {
        /// GSSAPI context.
        ctx: ClientCtx
    },
    /// Success end-state.
    Success {
        /// Protocol result.
        result: ClientCtx
    },
    /// Error end-state.
    Error {
        /// The protocol error.
        error: GSSAPIError
    }
}

pub enum GSSAPIServerState {
    GSSAPIStart,
    /// GSSAPI auhentication.
    GSSAPIAuthN {
        /// GSSAPI context.
        ctx: ServerCtx,
        /// Buffered message to write.
        msg: Buf
    },
    /// GSSAPI security level negotiation.
    GSSAPISecLvlWait {
        /// GSSAPI context.
        ctx: ServerCtx
    },
    /// GSSAPI security level negotiation.
    GSSAPISecLvlSend {
        /// GSSAPI context.
        ctx: ServerCtx
    },
    /// Success end-state.
    Success {
        /// Protocol result.
        result: ServerCtx
    },
    /// Error end-state.
    Error {
        /// The protocol error.
        error: GSSAPIError
    }
}

#[derive(Clone)]
pub struct ClientGSSAPIParams {
    bindings: Option<Vec<u8>>,
    /// Name of the principal to acquire and use in authentication.
    name: Option<String>,
    /// Name of the service principal to expect.
    service: String,
    /// Duration for which to request credentials.
    time_req: Option<Duration>,
    /// GSSAPI security level (see [GSSAPISecurity]).
    security: GSSAPISecurity
}

pub struct GSSAPIClientNegotiation<Inner> {
    params: ClientGSSAPIParams,
    inner: Inner
}

pub struct GSSAPIServerNegotiation<Inner> {
    params: ServerGSSAPIConfig,
    inner: Inner
}

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
    BadSecLvl {
        seclvl: u8
    },
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
    Inner {
        /// Error from obtaining the connection.
        err: E
    },
    BadSplit
}

pub enum GSSAPINegotiationPending<Inner, Endpoint, Stream, Pending> {
    GSSAPI {
        endpoint: Endpoint,
        stream: Stream,
        pending: Pending
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
    params: ServerGSSAPIConfig,
    /// Server credential name.
    inner: A
}

/// [NearConnector] instance that performs GSSAPI session negotiation.
pub struct GSSAPINearConnector<Conn: NearConnector> {
    params: ClientGSSAPIParams,
    inner: Conn
}

/// Configuration object for a [GSSAPINearAcceptor].
#[derive(Clone)]
pub struct GSSAPINearAcceptorConfig<Inner> {
    config: ServerGSSAPIConfig,
    /// Optional GSSAPI bindings.
    inner: Inner
}

/// Configuration object for a [GSSAPINearConnector].
#[derive(Clone)]
pub struct GSSAPINearConnectorConfig<Inner> {
    gssapi: ClientGSSAPIParams,
    /// Configuration for the underlying channel.
    inner: Inner
}

/// Credentials harvested from a [GSSAPIStream].
pub struct GSSAPIStreamCred<Stream> {
    gssapi: Option<GSSAPICred>,
    inner: Option<Stream>
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

    // XXX this will most likely break.  We need to buffer and parse
    // input into packets.
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

impl GSSAPIClientState {
    fn prepare_gssapi(
        params: &ClientGSSAPIParams,
    ) -> Result<ClientCtx, libgssapi::error::Error> {
        // Prepare the mechanisms.
        let mut mechs = OidSet::new()?;

        mechs.add(&GSS_MECH_KRB5)?;

        // Prepare the principal name.
        let cred = match &params.name {
            // A principal name was provided.
            Some(name) => {
                let name = Name::new(
                    name.as_bytes(),
                    Some(&GSS_NT_HOSTBASED_SERVICE)
                )?;
                let name = name.canonicalize(Some(&GSS_MECH_KRB5))?;

                Cred::acquire(
                    Some(&name),
                    params.time_req,
                    CredUsage::Initiate,
                    Some(&mechs)
                )?
            }
            // No principal name was provided.
            None => Cred::acquire(
                None,
                params.time_req,
                CredUsage::Initiate,
                Some(&mechs)
            )?
        };

        // Prepare the service name.
        let service = Name::new(
            params.service.as_bytes(),
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
}

impl RawMachineState for GSSAPIClientState {
    type Error = GSSAPIError;
    type Params = ClientGSSAPIParams;
    type Value = ClientCtx;

    #[inline]
    fn start(_params: &ClientGSSAPIParams) -> GSSAPIClientState {
        GSSAPIClientState::GSSAPIStart
    }

    #[inline]
    fn error(
        _params: &ClientGSSAPIParams,
        error: GSSAPIError
    ) -> GSSAPIClientState {
        GSSAPIClientState::Error { error: error }
    }

    #[inline]
    fn write<W>(
        &mut self,
        params: &ClientGSSAPIParams,
        stream: &mut W
    ) -> Result<(), GSSAPIError>
    where
        W: Write {
        match self {
            // Send GSSAPI authentication step.
            GSSAPIClientState::GSSAPIAuthN { msg, .. } => {
                write_gssapi_step(stream, msg)
                    .map_err(|err| GSSAPIError::IO { err: err })
            }
            // Send GSSAPI security level request.
            GSSAPIClientState::GSSAPISecLvl { ctx } =>
                write_gssapi_seclvl(
                    stream,
                    ctx,
                    params.security.seclvl()
                ),
            _ => Ok(())
        }
    }

    fn read_select<R>(
        self,
        params: &ClientGSSAPIParams,
        stream: &mut R
    ) -> Result<Self, GSSAPIError>
    where
        R: Read {
        match self {
            GSSAPIClientState::GSSAPIStart => {
                // Prepare a GSSAPI state.
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "beginning GSSAPI authentication");
                let mut ctx = Self::prepare_gssapi(params)
                    .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

                // Do the first step.
                match ctx.step(None, params.bindings.as_deref()) {
                    // The step returned a message.  Continue
                    // authnenticating.
                    Ok(Some(msg)) => {
                        #[cfg(feature = "log")]
                        trace!(target: "gssapi-near-client",
                               "continuing GSSAPI authentication");

                        Ok(GSSAPIClientState::GSSAPIAuthN {
                            msg: msg,
                            ctx: ctx
                        })
                    }
                    // The step returned no message.  We're
                    // authenticated.
                    Ok(None) => {
                        #[cfg(feature = "log")]
                        debug!(target: "gssapi-near-client",
                               "GSSAPI authentication succeeded");

                        Ok(GSSAPIClientState::GSSAPISecLvl { ctx: ctx })
                    }
                    // The step returned an error.
                    Err(err) => {
                        Err(GSSAPIError::GSSAPI { err: err })
                    }
                }
            }
            GSSAPIClientState::GSSAPIAuthN { mut ctx, .. } => {
                // Read in the server message.
                let token = parse_gssapi_step(stream)
                    .map_err(|err| GSSAPIError::IO { err: err })?;

                match ctx.step(Some(&token), params.bindings.as_deref()) {
                    // The step returned a message.  Continue
                    // authnenticating.
                    Ok(Some(msg)) => {
                        #[cfg(feature = "log")]
                        trace!(target: "gssapi-near-client",
                               "continuing GSSAPI authentication");

                        Ok(GSSAPIClientState::GSSAPIAuthN {
                            msg: msg,
                            ctx: ctx
                        })
                    }
                    // The step returned no message.  We're
                    // authenticated.
                    Ok(None) => {
                        #[cfg(feature = "log")]
                        debug!(target: "gssapi-near-client",
                               "GSSAPI authentication succeeded");

                        Ok(GSSAPIClientState::GSSAPISecLvl { ctx: ctx })
                    }
                    // The step returned an error.
                    Err(err) => {
                        Err(GSSAPIError::GSSAPI { err: err })
                    }
                }
            }
            // Send GSSAPI security level request.
            GSSAPIClientState::GSSAPISecLvl {
                mut ctx
            } => {
                let seclvl = parse_gssapi_seclvl(stream, &mut ctx)?;

                if !params.security.is_required() ||
                    params.security.seclvl() >= seclvl
                {
                    #[cfg(feature = "log")]
                    debug!(target: "gssapi-near-client",
                           "GSSAPI negotiation succeeded");

                    Ok(GSSAPIClientState::Success { result: ctx })
                } else {
                    Err(GSSAPIError::BadSecLvl { seclvl: seclvl })
                }
            }
            // End states.
            end => Ok(end)
        }
    }
}

impl RawOnceMachineState for GSSAPIClientState {
    #[inline]
    fn end(
        self,
        _params: &ClientGSSAPIParams
    ) -> OnceMachineAction<Self, Result<ClientCtx, GSSAPIError>> {
        match self {
            GSSAPIClientState::Success { result } => {
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "GSSAPI protocol has reached an end state");

                OnceMachineAction::Stop(Ok(result))
            }
            GSSAPIClientState::Error { error } => {
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "terminating GSSAPI protocol with error ({})",
                       error);

                OnceMachineAction::Stop(Err(error))
            }
            out => OnceMachineAction::Continue(out)
        }
    }
}

impl GSSAPIServerState {
    /// Prepare a GSSAPI context.
    fn prepare_gssapi(
        params: &ServerGSSAPIConfig,
    ) -> Result<ServerCtx, libgssapi::error::Error> {
        // Prepare the mechanisms.
        let mut mechs = OidSet::new()?;

        mechs.add(&GSS_MECH_KRB5)?;

        // Prepare the principal name.
        let cred = match params.name() {
            // A principal name was provided.
            Some(name) => {
                let name = Name::new(
                    name.as_bytes(),
                    Some(&GSS_NT_HOSTBASED_SERVICE)
                )?;
                let name = name.canonicalize(Some(&GSS_MECH_KRB5))?;

                Cred::acquire(
                    Some(&name),
                    params.time_req(),
                    CredUsage::Initiate,
                    Some(&mechs)
                )?
            }
            // No principal name was provided.
            None => Cred::acquire(
                None,
                params.time_req(),
                CredUsage::Initiate,
                Some(&mechs)
            )?
        };

        Ok(ServerCtx::new(Some(cred)))
    }
}

impl RawMachineState for GSSAPIServerState {
    type Error = GSSAPIError;
    type Params = ServerGSSAPIConfig;
    type Value = ServerCtx;

    #[inline]
    fn start(_params: &ServerGSSAPIConfig) -> GSSAPIServerState {
        GSSAPIServerState::GSSAPIStart
    }

    #[inline]
    fn error(
        _params: &ServerGSSAPIConfig,
        error: GSSAPIError
    ) -> GSSAPIServerState {
        GSSAPIServerState::Error { error: error }
    }

    #[inline]
    fn write<W>(
        &mut self,
        _params: &ServerGSSAPIConfig,
        stream: &mut W
    ) -> Result<(), GSSAPIError>
    where
        W: Write {
        match self {
            // Send GSSAPI authentication step.
            GSSAPIServerState::GSSAPIAuthN { msg, .. } => {
                write_gssapi_step(stream, msg)
                    .map_err(|err| GSSAPIError::IO { err: err })
            }
            // Send GSSAPI security level request.
            GSSAPIServerState::GSSAPISecLvlSend { ctx } =>
            // The Rust bindings don't actually supply any means by
            // which to interrogate or set security levels.
            //
            // Since Kerberos uses DES (ick!), we'll just hardwire it to 56.
                write_gssapi_seclvl(stream, ctx, 56),
            _ => Ok(())
        }
    }

    fn read_select<R>(
        self,
        params: &ServerGSSAPIConfig,
        stream: &mut R
    ) -> Result<Self, GSSAPIError>
    where
        R: Read {
        match self {
            GSSAPIServerState::GSSAPIStart => {
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "beginning GSSAPI authentication");
                let mut ctx = Self::prepare_gssapi(params)
                    .map_err(|err| GSSAPIError::GSSAPI { err: err })?;

                // Read in the server message.
                let token = parse_gssapi_step(stream)
                    .map_err(|err| GSSAPIError::IO { err: err })?;

                match ctx.step(&token) {
                    // The step returned a message.  Continue
                    // authnenticating.
                    Ok(Some(msg)) => {
                        #[cfg(feature = "log")]
                        trace!(target: "gssapi-near-client",
                               "continuing GSSAPI authentication");

                        Ok(GSSAPIServerState::GSSAPIAuthN {
                            msg: msg,
                            ctx: ctx
                        })
                    }
                    // The step returned no message.  We're
                    // authenticated.
                    Ok(None) => {
                        #[cfg(feature = "log")]
                        debug!(target: "gssapi-near-client",
                               "GSSAPI authentication succeeded");

                        Ok(GSSAPIServerState::GSSAPISecLvlWait { ctx: ctx })
                    }
                    // The step returned an error.
                    Err(err) => {
                        Err(GSSAPIError::GSSAPI { err: err })
                    }
                }
            }
            GSSAPIServerState::GSSAPIAuthN { mut ctx, .. } => {
                // Read in the server message.
                let token = parse_gssapi_step(stream)
                    .map_err(|err| GSSAPIError::IO { err: err })?;

                match ctx.step(&token) {
                    // The step returned a message.  Continue
                    // authnenticating.
                    Ok(Some(msg)) => {
                        #[cfg(feature = "log")]
                        trace!(target: "gssapi-near-client",
                               "continuing GSSAPI authentication");

                        Ok(GSSAPIServerState::GSSAPIAuthN {
                            msg: msg,
                            ctx: ctx
                        })
                    }
                    // The step returned no message.  We're
                    // authenticated.
                    Ok(None) => {
                        #[cfg(feature = "log")]
                        debug!(target: "gssapi-near-client",
                               "GSSAPI authentication succeeded");

                        Ok(GSSAPIServerState::GSSAPISecLvlWait { ctx: ctx })
                    }
                    // The step returned an error.
                    Err(err) => {
                        Err(GSSAPIError::GSSAPI { err: err })
                    }
                }
            }
            // Send GSSAPI security level request.
            GSSAPIServerState::GSSAPISecLvlWait { mut ctx } => {
                let _ = parse_gssapi_seclvl(stream, &mut ctx)?;

                Ok(GSSAPIServerState::GSSAPISecLvlSend { ctx: ctx })
            }
            GSSAPIServerState::GSSAPISecLvlSend { ctx } =>
                Ok(GSSAPIServerState::Success { result: ctx }),
            // End states.
            end => Ok(end)
        }
    }
}

impl RawOnceMachineState for GSSAPIServerState {
    #[inline]
    fn end(
        self,
        _params: &ServerGSSAPIConfig
    ) -> OnceMachineAction<Self, Result<ServerCtx, GSSAPIError>> {
        match self {
            GSSAPIServerState::Success { result } => {
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "GSSAPI protocol has reached an end state");

                OnceMachineAction::Stop(Ok(result))
            }
            GSSAPIServerState::Error { error } => {
                #[cfg(feature = "log")]
                debug!(target: "gssapi-near-client",
                       "terminating GSSAPI protocol with error ({})",
                       error);

                OnceMachineAction::Stop(Err(error))
            }
            out => OnceMachineAction::Continue(out)
        }
    }
}

impl<A> Negotiator<(GSSAPIStream<A::Conn, ServerCtx>, A::Endpoint)>
    for GSSAPINearAcceptor<A>
where
    A: Source + NearChannel,
{
    type State = GSSAPIServerNegotiation<A::State>;
    type Pending = GSSAPINegotiationPending<
        A::Pending,
        A::Endpoint,
        A::Conn,
        <RawStateMachineError<GSSAPIServerState> as RecoverableError>::Completable
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
        self.inner.negotiate(state.inner)
            .map_err(|err| GSSAPINegotiationError::Inner { err: err })?
            .map_pending(|pending| GSSAPINegotiationPending::Inner {
                inner: pending
            })
            .flat_map_ok(|(mut stream, endpoint)| {
                let machine: RawStateMachine<GSSAPIServerState> =
                    RawStateMachine::new(self.params.clone());

                match machine.run(&mut stream) {
                    Ok(ctx) => Ok(NegotiatorResult::Complete(
                        (GSSAPIStream {
                            ctx: ctx,
                            stream: stream
                        },
                         endpoint)
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) => Ok(NegotiatorResult::Pending(
                            GSSAPINegotiationPending::GSSAPI {
                                endpoint: endpoint.clone(),
                                stream: stream,
                                pending: pending
                            }
                        )),
                        (None, Some(err)) =>
                            Err(GSSAPINegotiationError::GSSAPI {
                                stream: stream,
                                err: err
                            }),
                        _ => Err(GSSAPINegotiationError::BadSplit)
                    }
                }
            })
    }

    fn complete_negotiate(
        &self,
        pending: GSSAPINegotiationPending<
            A::Pending,
            A::Endpoint,
            A::Conn,
            <RawStateMachineError<GSSAPIServerState> as RecoverableError>::Completable
        >
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<A::Conn, ServerCtx>, A::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        match pending {
            GSSAPINegotiationPending::Inner { inner } => self.inner
                .complete_negotiate(inner)
                .map_err(|err| GSSAPINegotiationError::Inner { err: err })?
                .map_pending(|pending| GSSAPINegotiationPending::Inner {
                    inner: pending
                })
                .flat_map_ok(|(mut stream, endpoint)| {
                    let machine: RawStateMachine<GSSAPIServerState> =
                        RawStateMachine::new(self.params.clone());

                    match machine.run(&mut stream) {
                        Ok(ctx) => Ok(NegotiatorResult::Complete(
                            (GSSAPIStream {
                                ctx: ctx,
                                stream: stream
                            },
                             endpoint)
                        )),
                        Err(err) => match err.split() {
                            (Some(pending), None) =>
                                Ok(NegotiatorResult::Pending(
                                    GSSAPINegotiationPending::GSSAPI {
                                        endpoint: endpoint.clone(),
                                        stream: stream,
                                        pending: pending
                                    }
                                )),
                            (None, Some(err)) =>
                                Err(GSSAPINegotiationError::GSSAPI {
                                    stream: stream,
                                    err: err
                                }),
                            _ => Err(GSSAPINegotiationError::BadSplit)
                        }
                    }
                }),
            GSSAPINegotiationPending::GSSAPI {
                endpoint, mut stream, pending
            } => {
                let machine: RawStateMachine<GSSAPIServerState> =
                    RawStateMachine::complete(pending);

                match machine.run(&mut stream) {
                    Ok(ctx) => Ok(NegotiatorResult::Complete(
                        (GSSAPIStream {
                            ctx: ctx,
                            stream: stream
                        },
                         endpoint)
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) =>
                            Ok(NegotiatorResult::Pending(
                                GSSAPINegotiationPending::GSSAPI {
                                    endpoint: endpoint.clone(),
                                    stream: stream,
                                    pending: pending
                                }
                            )),
                        (None, Some(err)) =>
                            Err(GSSAPINegotiationError::GSSAPI {
                                stream: stream,
                                err: err
                            }),
                        _ => Err(GSSAPINegotiationError::BadSplit)
                    }
                }
            }
        }
    }
}

impl<A> NearChannel for GSSAPINearAcceptor<A>
where
    A: Source + NearChannel,
{
    type Endpoint = A::Endpoint;
    type Conn = GSSAPIStream<A::Conn, ServerCtx>;
    type StartError = A::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        Ok(self.inner.start(registry, token)?.map(|inner| {
            GSSAPIServerNegotiation {
                params: self.params.clone(),
                inner: inner
            }
        }))
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: GSSAPINegotiationError<A::NegotiateError, A::Conn>
    ) -> Result<(), Error> {
        match err {
            GSSAPINegotiationError::Inner { err } =>
                self.inner.cleanup(registry, err),
            GSSAPINegotiationError::GSSAPI { mut stream, .. } =>
                registry.deregister(&mut stream),
            GSSAPINegotiationError::BadSplit => Ok(())
        }
    }
}

impl<A> NearChannelCreate for GSSAPINearAcceptor<A>
where
    A: Source + NearChannelCreate,
{
    type Config = GSSAPINearAcceptorConfig<A::Config>;
    type CreateError = A::CreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let inner = A::create(caches, config.inner)?;

        Ok(GSSAPINearAcceptor {
            inner: inner,
            params: config.config
        })
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        A::verify_endpoint(&config.inner)
    }
}

impl<C> Negotiator<(GSSAPIStream<C::Conn, ClientCtx>, C::Endpoint)>
    for GSSAPINearConnector<C>
where
    C: Source + NearConnector,
{
    type State = GSSAPIClientNegotiation<C::State>;
    type Pending = GSSAPINegotiationPending<
        C::Pending,
        C::Endpoint,
        C::Conn,
        <RawStateMachineError<GSSAPIClientState> as RecoverableError>::Completable
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
        self.inner.negotiate(state.inner)
            .map_err(|err| GSSAPINegotiationError::Inner { err: err })?
            .map_pending(|pending| GSSAPINegotiationPending::Inner {
                inner: pending
            })
            .flat_map_ok(|(mut stream, endpoint)| {
                let machine: RawStateMachine<GSSAPIClientState> =
                    RawStateMachine::new(self.params.clone());

                match machine.run(&mut stream) {
                    Ok(ctx) => Ok(NegotiatorResult::Complete(
                        (GSSAPIStream {
                            ctx: ctx,
                            stream: stream
                        },
                         endpoint)
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) => Ok(NegotiatorResult::Pending(
                            GSSAPINegotiationPending::GSSAPI {
                                endpoint: endpoint.clone(),
                                stream: stream,
                                pending: pending
                            }
                        )),
                        (None, Some(err)) =>
                            Err(GSSAPINegotiationError::GSSAPI {
                                stream: stream,
                                err: err
                            }),
                        _ => Err(GSSAPINegotiationError::BadSplit)
                    }
                }
            })
    }

    fn complete_negotiate(
        &self,
        pending: GSSAPINegotiationPending<
            C::Pending,
            C::Endpoint,
            C::Conn,
            <RawStateMachineError<GSSAPIClientState> as RecoverableError>::Completable
        >
    ) -> Result<
        NegotiatorResult<(GSSAPIStream<C::Conn, ClientCtx>, C::Endpoint),
                         Self::Pending>,
        Self::NegotiateError
    > {
        match pending {
            GSSAPINegotiationPending::Inner { inner } => self.inner
                .complete_negotiate(inner)
                .map_err(|err| GSSAPINegotiationError::Inner { err: err })?
                .map_pending(|pending| GSSAPINegotiationPending::Inner {
                    inner: pending
                })
                .flat_map_ok(|(mut stream, endpoint)| {
                    let machine: RawStateMachine<GSSAPIClientState> =
                        RawStateMachine::new(self.params.clone());

                    match machine.run(&mut stream) {
                        Ok(ctx) => Ok(NegotiatorResult::Complete(
                            (GSSAPIStream {
                                ctx: ctx,
                                stream: stream
                            },
                             endpoint)
                        )),
                        Err(err) => match err.split() {
                            (Some(pending), None) =>
                                Ok(NegotiatorResult::Pending(
                                    GSSAPINegotiationPending::GSSAPI {
                                        endpoint: endpoint.clone(),
                                        stream: stream,
                                        pending: pending
                                    }
                                )),
                            (None, Some(err)) =>
                                Err(GSSAPINegotiationError::GSSAPI {
                                    stream: stream,
                                    err: err
                                }),
                            _ => Err(GSSAPINegotiationError::BadSplit)
                        }
                    }
                }),
            GSSAPINegotiationPending::GSSAPI {
                endpoint, mut stream, pending
            } => {
                let machine: RawStateMachine<GSSAPIClientState> =
                    RawStateMachine::complete(pending);

                match machine.run(&mut stream) {
                    Ok(ctx) => Ok(NegotiatorResult::Complete(
                        (GSSAPIStream {
                            ctx: ctx,
                            stream: stream
                        },
                         endpoint)
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) =>
                            Ok(NegotiatorResult::Pending(
                                GSSAPINegotiationPending::GSSAPI {
                                    endpoint: endpoint.clone(),
                                    stream: stream,
                                    pending: pending
                                }
                            )),
                        (None, Some(err)) =>
                            Err(GSSAPINegotiationError::GSSAPI {
                                stream: stream,
                                err: err
                            }),
                        _ => Err(GSSAPINegotiationError::BadSplit)
                    }
                }
            }
        }
    }
}

impl<C> NearChannel for GSSAPINearConnector<C>
where
    C: Source + NearConnector,
{
    type Endpoint = C::Endpoint;
    type Conn = GSSAPIStream<C::Conn, ClientCtx>;
    type StartError = C::StartError;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        Ok(self.inner.start(registry, token)?.map(|inner| {
            GSSAPIClientNegotiation {
                params: self.params.clone(),
                inner: inner
            }
        }))
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: GSSAPINegotiationError<C::NegotiateError, C::Conn>
    ) -> Result<(), Error> {
        match err {
            GSSAPINegotiationError::Inner { err } =>
                self.inner.cleanup(registry, err),
            GSSAPINegotiationError::GSSAPI { mut stream, .. } =>
                registry.deregister(&mut stream),
            GSSAPINegotiationError::BadSplit => Ok(())
        }
    }
}

impl<C> NearChannelCreate for GSSAPINearConnector<C>
where
    C: Source + NearConnector + NearChannelCreate,
{
    type Config = GSSAPINearConnectorConfig<C::Config>;
    type CreateError = C::CreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let inner = C::create(caches, config.inner)?;

        Ok(GSSAPINearConnector {
            inner: inner,
            params: config.gssapi
        })
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        C::verify_endpoint(&config.inner)
    }
}

impl<C> NearChannelCreateWithEndpoint for GSSAPINearConnector<C>
where
    C: Source + NearConnector + NearChannelCreateWithEndpoint,
{
    type Config = GSSAPINearConnectorConfig<C::Config>;
    type EndpointConfig = C::EndpointConfig;
    type CreateError = C::CreateError;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: Self::Config,
        endpoint: C::EndpointConfig,
        verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let inner = C::create_with_endpoint(caches, config.inner, endpoint,
                                            verify_endpoint)?;

        Ok(GSSAPINearConnector {
            inner: inner,
            params: config.gssapi
        })
    }
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
        inner: Conn
    ) -> Self {
        let (name, service, time_req, security) = config.take();
        let params = ClientGSSAPIParams {
            service: service.unwrap_or(service_default),
            name: name,
            security: security,
            time_req: time_req,
            bindings: bindings
        };

        GSSAPINearConnectorConfig {
            gssapi: params,
            inner: inner
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
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
}

impl RecoverableError for GSSAPIError {
    type Permanent = GSSAPIError;
    type Completable = ();

    fn split(self) -> (Option<Self::Completable>, Option<Self::Permanent>) {
        match self {
            GSSAPIError::IO { err } => {
                let (completable, permanent) = err.split();

                if let Some(permanent) = permanent {
                    (completable, Some(GSSAPIError::IO { err: permanent }))
                } else {
                    (completable, None)
                }
            },
            err => (None, Some(err))
        }
    }
}

impl ScopedError for GSSAPIError {
    fn scope(&self) -> ErrorScope {
        match self {
            GSSAPIError::IO { err } => err.scope(),
            GSSAPIError::GSSAPI { .. } => ErrorScope::Session,
            GSSAPIError::BadSecLvl { .. } | GSSAPIError::BadVersion => {
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
            GSSAPINegotiationError::Inner { err } => err.scope(),
            GSSAPINegotiationError::GSSAPI { err, .. } => err.scope(),
            GSSAPINegotiationError::BadSplit => ErrorScope::Unrecoverable
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
            GSSAPIError::BadSecLvl { seclvl } => {
                write!(f, "security level {} was not accepted", seclvl)
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
            GSSAPINegotiationError::Inner { err } => err.fmt(f),
            GSSAPINegotiationError::GSSAPI { err, .. } => err.fmt(f),
            GSSAPINegotiationError::BadSplit =>
                write!(f, "split() returned no result")
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
