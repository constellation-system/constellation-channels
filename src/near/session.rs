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

use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use log::debug;
use log::error;
use log::info;
use log::warn;

use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearConnectError;
use crate::near::NearConnector;
use crate::near::NearReader;
use crate::near::NearWriter;
use crate::resolve::cache::NSNameCachesCtx;

pub trait NearSessionParams<Conn: NearConnector>: Sized {
    /// Name of the type of session.
    ///
    /// This is used in logging.
    const NAME: &'static str;

    type Value: Debug;
    type CreateError: Display + ScopedError;
    type NegotiateError: Display + ScopedError;
    type Config;

    fn create(
        config: Self::Config
    ) -> Result<(Self, Conn::Config), Self::CreateError>;

    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr>;

    fn negotiate(
        &mut self,
        stream: Conn::Stream,
        endpoint: &Conn::Endpoint
    ) -> Result<Self::Value, Self::NegotiateError>;
}

/// Multiplexer for errors that can occur while creating a session on
/// top of an underlying channel.
#[derive(Debug)]
pub enum NearSessionCreateError<Session, Channel> {
    /// Error creating the session-level parameters.
    Session { error: Session },
    /// Error creating the underlying channel.
    Channel { error: Channel }
}

/// Session states for near connectors.
enum NearSession<Stream> {
    /// Session is live, and was not transferred.
    Live {
        /// The underlying stream.
        stream: Arc<Mutex<Option<Stream>>>
    },
    /// Session is dead, with `nretries` prior retries having happened.
    Dead {
        /// Number of retries that previously happened.
        nretries: usize
    },
    /// Session is live, but was transferred.
    Transferred,
    /// Connector has been shut down.
    Shutdown
}

pub struct NearSessionConnector<
    Params: NearSessionParams<Conn>,
    Conn: NearConnector
> {
    session: NearSession<Params::Value>,
    params: Params,
    inner: Conn
}

impl<Session, Channel> ScopedError for NearSessionCreateError<Session, Channel>
where
    Session: ScopedError,
    Channel: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            NearSessionCreateError::Session { error } => error.scope(),
            NearSessionCreateError::Channel { error } => error.scope()
        }
    }
}

impl<Params, Conn> NearSessionConnector<Params, Conn>
where
    Params: NearSessionParams<Conn>,
    Conn: NearConnector
{
    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Params::Config
    ) -> Result<
        Self,
        NearSessionCreateError<Params::CreateError, Conn::CreateError>
    >
    where
        Ctx: NSNameCachesCtx,
        Conn: NearChannelCreate {
        let (params, inner_config) = Params::create(config)
            .map_err(|err| NearSessionCreateError::Session { error: err })?;
        let inner = Conn::new(caches, inner_config)
            .map_err(|err| NearSessionCreateError::Channel { error: err })?;
        let session = NearSession::Dead { nretries: 0 };

        Ok(NearSessionConnector {
            params: params,
            inner: inner,
            session: session
        })
    }

    #[inline]
    fn reset_state(
        &self,
        nretries: usize
    ) -> NearSession<Params::Value> {
        NearSession::Dead { nretries: nretries }
    }

    fn try_connect(
        &mut self,
        nretries: usize
    ) -> Result<(Params::Value, Conn::Endpoint), usize> {
        match self.inner.take_connection() {
            Ok((stream, endpoint)) => {
                debug!(target: "near-session",
                       "obtained connection, beginning {} negotiation",
                       Params::NAME);

                // Negotiate client connection.
                match self.params.negotiate(stream, &endpoint) {
                    // Do session negotiation.
                    Ok(stream) => {
                        info!(target: "near-session",
                              "established {} connection to {}",
                              Params::NAME, endpoint);

                        return Ok((stream, endpoint));
                    }
                    // Error during negotiation.
                    Err(err) => {
                        warn!(target: "near-session",
                              "error in {} negotiation ({})",
                              Params::NAME, err);
                    }
                };

                // Reset the lower-level connection.
                match self.inner.fail(nretries) {
                    Ok(()) => Err(nretries + 1),
                    Err(err) => {
                        error!(target: "near-session",
                               "error resetting connection ({})",
                               err);

                        Err(nretries + 1)
                    }
                }
            }
            Err(err) => {
                warn!(target: "near-session",
                      concat!("failed to obtain underlying connection ",
                              "for {} session to {} ({})"),
                      Params::NAME, self.inner.endpoint(), err);

                Err(nretries + 1)
            }
        }
    }

    pub(crate) fn connect_owned(
        &mut self
    ) -> Result<(Params::Value, Conn::Endpoint), NearConnectError> {
        // Try until we succeed, or encounter a hard error.
        loop {
            let reset = match &self.session {
                // Connection is live; return the underlying stream.
                NearSession::Live { stream, .. } => {
                    let guard = match stream.lock() {
                        Ok(guard) => Ok(guard),
                        Err(_) => Err(NearConnectError::MutexPoison)
                    }?;

                    // Check to see if one of the readers or writers
                    // closed the connection.
                    if guard.is_some() {
                        return Err(NearConnectError::Transferred);
                    } else {
                        Some(1)
                    }
                }
                // Session is dead; try to make a connection.
                NearSession::Dead { nretries } => {
                    match self.try_connect(*nretries) {
                        Ok(res) => {
                            self.session = NearSession::Transferred;

                            return Ok(res);
                        }
                        Err(nretries) => Some(nretries)
                    }
                }
                // Session was transferred; this is a hard error.
                //
                // This can only happen if someone used the API wrong,
                // transferring the connection via take_connection
                // multiple times.
                NearSession::Transferred => {
                    return Err(NearConnectError::Transferred)
                }
                // Channel was shut down; this is a hard error.
                //
                // This can only happen if someone used the API wrong,
                // shutting down a connector, then trying to get a
                // connection.
                NearSession::Shutdown { .. } => {
                    return Err(NearConnectError::Shutdown)
                }
            };

            if let Some(nretries) = reset {
                self.session = self.reset_state(nretries);
            }
        }
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), Error> {
        match &self.session {
            NearSession::Live { stream, .. } => {
                info!(target: "near-session",
                      "shutting down {} session to {}",
                      Params::NAME, self.inner.endpoint());

                let newstate = match stream.lock() {
                    // Figure out whether we need to shut down the stream.
                    Ok(mut guard) => match &*guard {
                        // Shut it down.
                        Some(_) => {
                            *guard = None;

                            Ok(NearSession::Shutdown)
                        }
                        // Already shut down.
                        None => Ok(NearSession::Shutdown)
                    },
                    // Mutex poisoned.
                    Err(_) => {
                        error!(target: "near-session",
                               "mutex poisoned, aborting shutdown");

                        Err(Error::new(
                            ErrorKind::Other,
                            "mutex poisoned, aborting shutdown"
                        ))
                    }
                }?;

                self.session = newstate;
            }
            // Shutting down a transferred state.
            NearSession::Transferred => {
                info!(target: "near-session",
                      "shutting down {} connection to {}",
                      Params::NAME, self.inner.endpoint());

                self.session = NearSession::Shutdown;
            }
            // Shutting down a dead state.
            NearSession::Dead { .. } => {
                info!(target: "near-session",
                      "shutting down {} connection to {}",
                      Params::NAME, self.inner.endpoint());

                self.session = NearSession::Shutdown;
            }
            // Socket was already shut down.
            NearSession::Shutdown => {
                warn!(target: "near-session",
                      "{} connection with {} is already shut down",
                      Params::NAME, self.inner.endpoint());
            }
        };

        self.inner.shutdown()
    }

    pub(crate) fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error> {
        let state = match &mut self.session {
            NearSession::Live { stream, .. } => match stream.lock() {
                Ok(mut guard) => {
                    debug!(target: "near-session",
                           "resetting connection to {}, with {} retries",
                           self.inner.endpoint(), nretries);

                    *guard = None;

                    Ok(NearSession::Dead { nretries: nretries })
                }
                Err(_) => {
                    error!(target: "near-session",
                           "mutex poisoned, aborting reset");

                    Err(Error::new(
                        ErrorKind::Other,
                        "mutex poisoned, aborting connect"
                    ))
                }
            },
            NearSession::Dead {
                nretries: curr_nretries
            } => {
                debug!(target: "near-session",
                       "resetting dead {}, connection to {}, with {} retries",
                       Params::NAME, self.inner.endpoint(), nretries);

                // Check if the higher-level protocol's number of
                // retries is greater than the current.
                if *curr_nretries >= nretries {
                    debug!(target: "near-session",
                           "current retries on {} ({}) exceeds new value of {}",
                           self.inner.endpoint(), curr_nretries, nretries);

                    return Ok(());
                } else {
                    Ok(NearSession::Dead { nretries: nretries })
                }
            }
            // Connection was transferred
            NearSession::Transferred => {
                debug!(target: "near-session",
                       "resetting {} connection to {}, with {} retries",
                       Params::NAME, self.inner.endpoint(), nretries);

                Ok(NearSession::Dead { nretries: nretries })
            }
            // Connection was already shut down.
            NearSession::Shutdown { .. } => {
                warn!(target: "near-session",
                      concat!("attempting to reset {} connection to ",
                              "{}, which is shut down"),
                      Params::NAME, self.inner.endpoint());

                return Err(Error::new(
                    ErrorKind::Other,
                    "connection is shut down"
                ));
            }
        }?;

        self.session = state;

        self.inner.fail(nretries)
    }
}

impl<Params, Conn> NearChannel for NearSessionConnector<Params, Conn>
where
    Params: NearSessionParams<Conn>,
    Params::Value: CredentialsMut + Read + Write,
    Conn: NearConnector
{
    type Config = Params::Config;
    type Endpoint = Conn::Endpoint;
    type Stream = Params::Value;
    type TakeConnectError = NearConnectError;

    #[inline]
    fn take_connection(
        &mut self
    ) -> Result<(Self::Stream, Conn::Endpoint), NearConnectError> {
        self.connect_owned()
    }
}

impl<Params, Conn> NearChannelCreate for NearSessionConnector<Params, Conn>
where
    Params: NearSessionParams<Conn>,
    Params::Value: CredentialsMut + Read + Write,
    Conn: NearConnector + NearChannelCreate
{
    type CreateError =
        NearSessionCreateError<Params::CreateError, Conn::CreateError>;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Params::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        Self::create(caches, config)
    }
}

impl<Params, Conn> NearConnector for NearSessionConnector<Params, Conn>
where
    Params: NearSessionParams<Conn>,
    Params::Value: CredentialsMut + Read + Write,
    Conn: NearConnector
{
    type EndpointRef<'a> = Conn::EndpointRef<'a>
    where Conn::Endpoint: 'a,
          Params: 'a,
          Conn: 'a;
    type Reader = NearReader<Params::Value>;
    type Writer = NearWriter<Params::Value>;

    #[inline]
    fn endpoint(&self) -> Conn::EndpointRef<'_> {
        self.inner.endpoint()
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Params::verify_endpoint(config)
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown()
    }

    #[inline]
    fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error> {
        self.fail(nretries)
    }

    fn connection(
        &mut self
    ) -> Result<
        (Self::Reader, Self::Writer, Conn::EndpointRef<'_>),
        NearConnectError
    > {
        loop {
            let reset = match &self.session {
                NearSession::Live { stream } => {
                    let guard = match stream.lock() {
                        Ok(guard) => Ok(guard),
                        Err(_) => {
                            error!(target: "near-session",
                                   "mutex poisoned, aborting shutdown");

                            Err(Error::new(
                                ErrorKind::Other,
                                "mutex poisoned, aborting connect"
                            ))
                        }
                    }
                    .map_err(|err| NearConnectError::IO { error: err })?;

                    // Check to see if one of the readers or writers
                    // closed the connection.
                    if guard.is_some() {
                        // We're good, we can return.
                        let reader = NearReader::from(stream.clone());
                        let writer = NearWriter::from(stream.clone());

                        return Ok((reader, writer, self.inner.endpoint()));
                    } else {
                        Some(1)
                    }
                }
                NearSession::Dead { nretries } => {
                    match self.try_connect(*nretries) {
                        Ok((stream, _)) => {
                            let stream = Some(stream);
                            let stream = Arc::new(Mutex::new(stream));

                            self.session = NearSession::Live {
                                stream: stream.clone()
                            };

                            return Ok((
                                NearReader::from(stream.clone()),
                                NearWriter::from(stream),
                                self.inner.endpoint()
                            ));
                        }
                        Err(nretries) => Some(nretries)
                    }
                }
                NearSession::Transferred => {
                    return Err(NearConnectError::Transferred)
                }
                NearSession::Shutdown { .. } => {
                    return Err(NearConnectError::Shutdown)
                }
            };

            if let Some(nretries) = reset {
                self.session = self.reset_state(nretries);
            }
        }
    }
}

impl<Session, Channel> Display for NearSessionCreateError<Session, Channel>
where
    Session: Display,
    Channel: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            NearSessionCreateError::Session { error } => error.fmt(f),
            NearSessionCreateError::Channel { error } => error.fmt(f)
        }
    }
}
