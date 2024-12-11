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
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use constellation_auth::cred::CredentialsMut;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::Retry;
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

pub trait NearSocketParams: Sized {
    const NAME: &'static str;

    type Config;
    type CreateError: Display + ScopedError;
    type Endpoint: Clone + Display;
    type Error: Display + ScopedError;
    type Stream: CredentialsMut + Debug + Read + Write;

    fn create<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<(Self, Retry), Self::CreateError>
    where
        Ctx: NSNameCachesCtx;

    fn endpoint(&self) -> &Self::Endpoint;

    fn verify_endpoint(_conf: &Self::Config) -> Option<&IPEndpointAddr> {
        None
    }

    fn try_connect(
        &mut self,
        retry: &Retry,
        until: &mut Instant,
        nretries: &mut usize
    ) -> Result<Self::Stream, Self::Error>;

    fn shutdown(
        &self,
        stream: &Self::Stream
    ) -> Result<(), Error>;
}

enum NearSocketConnection<Stream> {
    Live { stream: Arc<Mutex<Option<Stream>>> },
    Dead { retry: Instant, nretries: usize },
    Transferred,
    Shutdown
}

pub struct NearSocketConnector<Params: NearSocketParams> {
    /// The connection state.
    state: NearSocketConnection<Params::Stream>,
    params: Params,
    /// The retry configuration.
    retry: Retry
}

impl<Params> NearSocketConnector<Params>
where
    Params: NearSocketParams
{
    #[inline]
    fn reset_state(&self) -> NearSocketConnection<Params::Stream> {
        let duration = self.retry.retry_delay(0);
        let now = Instant::now();
        let retry = now + duration;

        info!(target: "near-socket",
              "retrying {} connection to {} in {}.{:06}s",
              Params::NAME, self.params.endpoint(),
              duration.as_secs(), duration.subsec_micros());

        NearSocketConnection::Dead {
            retry: retry,
            nretries: 0
        }
    }
}

impl<Params> NearChannel for NearSocketConnector<Params>
where
    Params: NearSocketParams
{
    type Config = Params::Config;
    type Endpoint = Params::Endpoint;
    type Stream = Params::Stream;
    type TakeConnectError = NearConnectError;

    fn take_connection(
        &mut self
    ) -> Result<(Self::Stream, Self::Endpoint), Self::TakeConnectError> {
        loop {
            let reset = match &mut self.state {
                NearSocketConnection::Live { stream } => {
                    let guard = match stream.lock() {
                        Ok(guard) => Ok(guard),
                        Err(_) => {
                            error!(target: "near-socket",
                                   "mutex poisoned, aborting connect");

                            Err(NearConnectError::MutexPoison)
                        }
                    }?;

                    // Check to see if one of the readers or writers
                    // closed the connection.
                    if guard.is_some() {
                        return Err(NearConnectError::Transferred);
                    } else {
                        true
                    }
                }
                NearSocketConnection::Dead { retry, nretries } => {
                    match self.params.try_connect(&self.retry, retry, nretries)
                    {
                        // Connection successful.
                        Ok(stream) => {
                            info!(target: "near-socket",
                                  "established {} connection to {}",
                                  Params::NAME, self.params.endpoint());
                            self.state = NearSocketConnection::Transferred;

                            return Ok((
                                stream,
                                self.params.endpoint().clone()
                            ));
                        }
                        // Connection failed, try again.
                        Err(err) => {
                            warn!(target: "near-socket",
                                  "error connecting to {}: {}",
                                  self.params.endpoint(), err);

                            false
                        }
                    }
                }
                // Connection is transferred.
                NearSocketConnection::Transferred => {
                    return Err(NearConnectError::Transferred);
                }
                // Connection was already shut down.
                NearSocketConnection::Shutdown { .. } => {
                    return Err(NearConnectError::Shutdown);
                }
            };

            if reset {
                self.state = self.reset_state();
            }
        }
    }
}

impl<Params> NearChannelCreate for NearSocketConnector<Params>
where
    Params: NearSocketParams
{
    type CreateError = Params::CreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let state = NearSocketConnection::Dead {
            retry: Instant::now(),
            nretries: 0
        };
        let (params, retry) = Params::create(caches, config)?;

        Ok(NearSocketConnector {
            params: params,
            state: state,
            retry: retry
        })
    }
}

impl<Params> NearConnector for NearSocketConnector<Params>
where
    Params: NearSocketParams
{
    type EndpointRef<'a> = &'a Params::Endpoint
    where Params::Endpoint: 'a,
          Params: 'a;
    type Reader = NearReader<Params::Stream>;
    type Writer = NearWriter<Params::Stream>;

    #[inline]
    fn endpoint(&self) -> &'_ Params::Endpoint {
        self.params.endpoint()
    }

    #[inline]
    fn verify_endpoint(conf: &Params::Config) -> Option<&IPEndpointAddr> {
        Params::verify_endpoint(conf)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        match &self.state {
            NearSocketConnection::Live { stream } => {
                info!(target: "near-socket",
                      "shutting down {} socket connecting to {}",
                      Params::NAME, self.params.endpoint());

                let newstate = match stream.lock() {
                    // Figure out whether we need to shut down the stream.
                    Ok(mut guard) => match &*guard {
                        // Shut it down.
                        Some(stream) => match self.params.shutdown(stream) {
                            Ok(()) => {
                                *guard = None;

                                Ok(NearSocketConnection::Shutdown)
                            }
                            Err(err) => Err(err)
                        },
                        // Already shut down.
                        None => Ok(NearSocketConnection::Shutdown)
                    },
                    // Mutex poisoned.
                    Err(_) => {
                        error!(target: "near-socket",
                               "mutex poisoned, aborting shutdown");

                        Err(Error::new(
                            ErrorKind::Other,
                            "mutex poisoned, aborting shutdown"
                        ))
                    }
                }?;

                self.state = newstate;

                Ok(())
            }
            // Shutting down a dead state.
            NearSocketConnection::Dead { .. } => {
                info!(target: "near-socket",
                      "shutting down {} socket connecting to {}",
                      Params::NAME, self.params.endpoint());

                self.state = NearSocketConnection::Shutdown;

                Ok(())
            }
            // Shutting down a transferred state.
            NearSocketConnection::Transferred => {
                info!(target: "near-socket",
                      "shutting down {} socket connecting to {}",
                      Params::NAME, self.params.endpoint());

                self.state = NearSocketConnection::Shutdown;

                Ok(())
            }
            // Socket was already shut down.
            NearSocketConnection::Shutdown => {
                warn!(target: "near-socket",
                      "{} socket to {} is already shut down",
                      Params::NAME, self.params.endpoint());

                Ok(())
            }
        }
    }

    fn fail(
        &mut self,
        nretries: usize
    ) -> Result<(), Error> {
        let state = match &mut self.state {
            NearSocketConnection::Live { stream } => match stream.lock() {
                Ok(mut guard) => {
                    debug!(target: "unix-near",
                           concat!("resetting {} socket connection ",
                                   "to {}, with {} retries"),
                           Params::NAME, self.params.endpoint(), nretries);

                    let duration = self.retry.retry_delay(nretries);
                    let retry = Instant::now() + duration;

                    *guard = None;

                    Ok(NearSocketConnection::Dead {
                        nretries: nretries,
                        retry: retry
                    })
                }
                Err(_) => {
                    error!(target: "near-socket",
                           "mutex poisoned, aborting reset");

                    Err(Error::new(
                        ErrorKind::Other,
                        "mutex poisoned, aborting connect"
                    ))
                }
            },
            NearSocketConnection::Transferred => {
                debug!(target: "near-socket",
                       "resetting {} socket connection to {}, with {} retries",
                       Params::NAME, self.params.endpoint(), nretries);

                let duration = self.retry.retry_delay(nretries);
                let retry = Instant::now() + duration;

                Ok(NearSocketConnection::Dead {
                    nretries: nretries,
                    retry: retry
                })
            }
            NearSocketConnection::Dead {
                nretries: curr_nretries,
                ..
            } => {
                debug!(target: "near-socket",
                       concat!("resetting dead {} socket connection to {},",
                               " with {} retries"),
                       Params::NAME, self.params.endpoint(), nretries);

                // Check if the higher-level protocol's number of
                // retries is greater than the current.
                if *curr_nretries >= nretries {
                    debug!(target: "near-socket",
                           "current retries on {} ({}) exceeds new value of {}",
                           self.params.endpoint(), curr_nretries, nretries);

                    return Ok(());
                } else {
                    let duration = self.retry.retry_delay(nretries);
                    let retry = Instant::now() + duration;

                    Ok(NearSocketConnection::Dead {
                        nretries: nretries,
                        retry: retry
                    })
                }
            }
            // Connection was already shut down.
            NearSocketConnection::Shutdown { .. } => {
                warn!(target: "unix-near",
                      concat!("attempting to reset {} socket connection to ",
                              "{}, which is shut down"),
                      Params::NAME, self.params.endpoint());

                return Err(Error::new(
                    ErrorKind::Other,
                    "connection is shut down"
                ));
            }
        }?;

        self.state = state;

        Ok(())
    }

    fn connection(
        &mut self
    ) -> Result<
        (
            NearReader<Params::Stream>,
            NearWriter<Params::Stream>,
            &'_ Params::Endpoint
        ),
        NearConnectError
    > {
        loop {
            let reset = match &mut self.state {
                NearSocketConnection::Live { stream } => {
                    let guard = match stream.lock() {
                        Ok(guard) => Ok(guard),
                        Err(_) => {
                            error!(target: "near-socket",
                                   "mutex poisoned, aborting connect");

                            Err(NearConnectError::MutexPoison)
                        }
                    }?;

                    // Check to see if one of the readers or writers
                    // closed the connection.
                    if guard.is_some() {
                        // We're good, we can return.
                        let reader = NearReader::from(stream.clone());
                        let writer = NearWriter::from(stream.clone());

                        return Ok((reader, writer, self.params.endpoint()));
                    } else {
                        true
                    }
                }
                NearSocketConnection::Dead { retry, nretries } => {
                    match self.params.try_connect(&self.retry, retry, nretries)
                    {
                        // Connection successful.
                        Ok(stream) => {
                            info!(target: "near-socket",
                                  "established {} connection to {}",
                                  Params::NAME, self.params.endpoint());

                            let stream = Arc::new(Mutex::new(Some(stream)));
                            let reader = NearReader::from(stream.clone());
                            let writer = NearWriter::from(stream.clone());

                            self.state =
                                NearSocketConnection::Live { stream: stream };

                            return Ok((
                                reader,
                                writer,
                                self.params.endpoint()
                            ));
                        }
                        // Connection failed, try again.
                        Err(err) => {
                            warn!(target: "near-socket",
                                  "error connecting {} socket to {}: {}",
                                  Params::NAME, self.params.endpoint(), err);

                            let now = Instant::now();

                            if now < *retry {
                                let duration = *retry - now;

                                info!(target: "near-socket",
                                      concat!("retrying {} connection to ",
                                              "{} in {}.{:03}s"),
                                      Params::NAME, self.params.endpoint(),
                                      duration.as_secs(),
                                      duration.subsec_millis());
                            } else {
                                warn!(target: "near-socket",
                                      concat!("retry time is before present ",
                                              "time, possible busy-wait"));
                            }

                            false
                        }
                    }
                }
                // Connection is transferred.
                NearSocketConnection::Transferred => {
                    return Err(NearConnectError::Transferred)
                }
                // Connection was already shut down.
                NearSocketConnection::Shutdown { .. } => {
                    return Err(NearConnectError::Shutdown)
                }
            };

            if reset {
                self.state = self.reset_state();
            }
        }
    }
}
