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

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::iter::Peekable;
use std::time::Instant;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::SessionAuthN;
use constellation_common::config::Create;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use mio::event::Source;
use mio::Registry;
use mio::Token;

use crate::channels::ShutdownError;
use crate::channels::WithShutdownError;
use crate::config::NearChannelsEntryConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

/// Newtype wrapper for IDs created to refer to specific channels.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NearChannelID(Token);

enum DuplexValue<Accept, Conn> {
    Accept {
        accept: Accept
    },
    Conn {
        conn: Conn
    }
}

enum SessionNegoEntry<Channel, AuthN>
where
    Channel: NearChannel,
    Channel::NegotiateError: ScopedError,
    AuthN: Clone + Create + SessionAuthN<Channel::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    /// Session negotiation is pending.
    Session {
        /// Pending negotiation state.
        pending: Channel::Pending
    },
    /// Authentication negotiation is pending.
    AuthN {
        /// Endpoint for this negotiation.
        endpoint: Channel::Endpoint,
        /// Pending negotiation state.
        pending: AuthN::Pending,
    },
    Active {
        /// Endpoint for this session.
        endpoint: Channel::Endpoint,
    },
    /// Shutdown negotiation is pending.
    Shutdown {
        /// Endpoint for this session.
        endpoint: Channel::Endpoint,
        /// Pending negotiation state.
        pending: <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::Pending
    }
}

struct AcceptorEntry<Channel, AuthN>
where
    Channel: NearChannel,
    Channel::NegotiateError: ScopedError,
    AuthN: Clone + Create + SessionAuthN<Channel::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    state: Option<SessionNegoEntry<Channel, AuthN>>,
    /// When to retry next.
    when: Option<Instant>
}

struct ConnectorEntry<Channel, AuthN>
where
    Channel: NearChannel,
    Channel::NegotiateError: ScopedError,
    AuthN: Clone + Create + SessionAuthN<Channel::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    channel: Channel,
    shutdown: Channel::ShutdownNego,
    state: Option<SessionNegoEntry<Channel, AuthN>>,
    /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Option<Instant>
}

enum ChannelMode<Accept, Conn, AcceptAuthN, ConnAuthN>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Endpoint: Clone + Eq + Hash,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    Accept: NearChannel + NearChannelCreate,
    Accept::Endpoint: Clone + Eq + Hash,
    Accept::Conn: Session,
    Accept::NegotiateError: ScopedError,
    ConnAuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    ConnAuthN::NegotiateError: ScopedError,
    AcceptAuthN: Clone + Create + SessionAuthN<Accept::Conn, Param = ()>,
    AcceptAuthN::NegotiateError: ScopedError
{
    /// Full-duplex channels, which can establish outbound as well as
    /// inbound connections.
    Duplex {
        config: Conn::Config,
        in_authn: AcceptAuthN,
        out_authn: ConnAuthN,
        /// Acceptor for incoming sessions.
        acceptor: Accept,
        shutdown: Accept::ShutdownNego,
        /// Token for acceptor.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint.
        accept_tokens: HashMap<Accept::Endpoint, Token>,
        conn_tokens: HashMap<Conn::Endpoint, Token>,
        negos: HashMap<
            Token,
            DuplexValue<
                Option<SessionNegoEntry<Accept, AcceptAuthN>>,
                ConnectorEntry<Conn, ConnAuthN>
            >
        >
    },
    /// Outbound-only channels, which can only establish connections.
    Outbound {
        config: Conn::Config,
        authn: ConnAuthN,
        /// Session information for each endpoint.
        tokens: HashMap<Conn::Endpoint, Token>,
        negos: HashMap<
            Token,
            ConnectorEntry<Conn, ConnAuthN>,
        >,
    },
    /// Inbound-only channels, which can only listen for connections.
    Inbound {
        authn: AcceptAuthN,
        /// Acceptor for incoming sessions.
        acceptor: Accept,
        shutdown: Accept::ShutdownNego,
        /// Token for acceptor.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint.
        tokens: HashMap<Accept::Endpoint, Token>,
        negos: HashMap<
            Token,
            Option<SessionNegoEntry<Accept, AcceptAuthN>>,
        >
    }
}

struct ChannelEntry<Accept, Conn, AcceptAuthN, ConnAuthN>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Endpoint: Clone + Eq + Hash,
    Conn::Conn: Session,
    Conn::Config: Clone,
    Conn::NegotiateError: ScopedError,
    Accept: NearChannel + NearChannelCreate,
    Accept::Endpoint: Clone + Eq + Hash,
    Accept::Conn: Session,
    Accept::NegotiateError: ScopedError,
    ConnAuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    ConnAuthN::NegotiateError: ScopedError,
    AcceptAuthN: Clone + Create + SessionAuthN<Accept::Conn, Param = ()>,
    AcceptAuthN::NegotiateError: ScopedError
{
    mode: ChannelMode<Accept, Conn, AcceptAuthN, ConnAuthN>,
    /// Retry configuration to use.
    retry: Retry,
}

pub struct NearChannels<Accept, Conn, AcceptAuthN, ConnAuthN>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Endpoint: Clone + Eq + Hash,
    Conn::Conn: Session,
    Conn::Config: Clone,
    Conn::NegotiateError: ScopedError,
    Accept: NearChannel + NearChannelCreate,
    Accept::Endpoint: Clone + Eq + Hash,
    Accept::Conn: Session,
    Accept::NegotiateError: ScopedError,
    ConnAuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    ConnAuthN::NegotiateError: ScopedError,
    AcceptAuthN: Clone + Create + SessionAuthN<Accept::Conn, Param = ()>,
    AcceptAuthN::NegotiateError: ScopedError
{
    /// Map from names to `NearChannelID`s.
    ids: HashMap<String, NearChannelID>,
    tokens: HashMap<Token, NearChannelID>,
    /// Reverse map from `NearChannelID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Accept, Conn, AcceptAuthN, ConnAuthN>>
}

#[derive(Debug)]
pub enum NearChannelsEntryCreateError<Accept, AuthN> {
    Accept {
        err: Accept
    },
    AuthN {
        err: AuthN
    }
}

#[derive(Debug)]
pub enum NearChannelsEntrySessionError<Conn, Req> {
    /// Error occurred creating a new session entry.
    Conn {
        /// Error that occurred creating the new session entry.
        err: Conn
    },
    /// Error occurred requesting a session from an existing entry.
    Req {
        /// The error that occurred requesting the session.
        err: Req
    },
    /// The token iterator was exhausted.
    NoTokens
}

#[derive(Debug)]
pub enum SessionEntryStepError<Session, AuthN, Shutdown> {
    Session {
        err: Session
    },
    AuthN {
        err: AuthN
    },
    Shutdown {
        err: Shutdown
    },
    IO {
        err: std::io::Error
    }
}

#[derive(Debug)]
pub enum SessionEntryAuthNError<Start, Auth> {
    /// Error occurred starting session negotiations.
    Start {
        /// The error that occurred starting session negotiations.
        err: Start
    },
    /// Error occurred during session negotiations.
    AuthN {
        /// The error that occurred during session negotiations.
        err: Auth
    },
}

#[derive(Debug)]
pub enum NegoEntrySessionError<Nego, AuthN> {
    Nego {
        err: Nego
    },
    AuthN {
        err: AuthN
    }
}

#[derive(Debug)]
pub enum SessionEntryCreateError<Session, Shutdown> {
    Session {
        err: Session
    },
    Shutdown {
        err: Shutdown
    },
    IO {
        err: std::io::Error
    }
}

#[derive(Debug)]
pub enum SessionEntryShutdownError<Start, Shutdown> {
    Shutdown {
        err: ShutdownError<Start, Shutdown>
    },
    IO {
        err: std::io::Error
    },
    NotActive
}

#[derive(Debug)]
pub enum SessionCreateError<Session, Shutdown> {
    Session {
        err: Session
    },
    Shutdown {
        err: Shutdown
    },
    IO {
        err: std::io::Error
    }
}

#[derive(Debug)]
pub enum ConnectorEntryCreateError<Start, Nego> {
    Start {
        err: Start
    },
    Nego {
        err: Nego
    }
}

#[derive(Debug)]
pub enum ConnectorEntryStepError<Start, Connect, Step> {
    Start {
        err: Start
    },
    Connect {
        err: Connect
    },
    Step {
        err: Step
    }
}



impl<Channel, AuthN> SessionNegoEntry<Channel, AuthN>
where
    Channel: NearChannel,
    Channel::Endpoint: Clone + Eq + Hash,
    Channel::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError: ScopedError,
    AuthN: Clone + Create + SessionAuthN<Channel::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    /// Create a new `SessionNegoEntry`.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of failing to create the `SessionNegoEntry` due
    /// to authentication failures.
    ///
    /// # Parameters
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
    ///
    /// - `param`: The parameter to use to begin shutdown.
    ///
    /// - `state`: The initial state to use for session negotiations.
    ///
    /// # Return Values
    ///
    /// - `Some(self, Some(session))`: If a session was successfully
    ///   negotiated.
    ///
    /// - `Some(self, None)`: If negotiations could not be concluded.
    ///
    /// - `None`: If negotiations concluded, but did not yield a session.
    fn create(
        registry: &Registry,
        channel: &Channel,
        authn: &AuthN,
        shutdown: &Channel::ShutdownNego,
        state: Channel::State,
    ) -> Result<
        Option<(Self, Option<AuthN::AuthNSession>)>,
        SessionEntryCreateError<
            NegoEntrySessionError<
                Channel::NegotiateError,
                SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
            >,
            ShutdownError<
                <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
            >
        >
    > {
        match SessionNegoEntry::session(channel, authn, state) {
            Ok(NegotiatorResult::Complete((AuthNResult::Accept((out, session)),
                                           endpoint))) => {
                info!(target: "session-nego-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                Ok(Some((out, Some(session))))
            },
            Ok(NegotiatorResult::Complete((AuthNResult::Reject(stream),
                                          endpoint))) => {
                info!(target: "session-nego-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let res = Self::do_shutdown(shutdown, &channel.shutdown_param(),
                                            endpoint.clone(), stream)
                    .map_err(|err| SessionEntryCreateError::Shutdown {
                        err: err
                    })?;
                let out = Self::handle_shutdown_result(registry, res, endpoint)
                    .map_err(|err| SessionEntryCreateError::IO { err: err })?;

                Ok(out.map(|out| (out, None)))
            },
            Ok(NegotiatorResult::Pending(pending)) => Ok(Some((pending, None))),
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System =>
                    Err(SessionEntryCreateError::Session { err: err }),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "session-nego-entry",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    warn!(target: "session-nego-entry",
                          "session negotiation failed: {}",
                          err);

                    // See if we need to shut down the stream.
                    let stream = match err {
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr()
                            .map_err(|err| SessionEntryCreateError::IO {
                                err: err
                            })?;
                        let res = Self::do_shutdown(shutdown,
                                                    &channel.shutdown_param(),
                                                    endpoint.clone(),
                                                    stream)
                            .map_err(|err| SessionEntryCreateError::Shutdown {
                                err: err
                            })?;
                        let out = Self::handle_shutdown_result(registry, res,
                                                               endpoint)
                            .map_err(|err| SessionEntryCreateError::IO {
                                err: err
                            })?;

                        Ok(out.map(|out| (out, None)))
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    fn session(
        channel: &Channel,
        authn: &AuthN,
        state: Channel::State,
    ) -> Result<
        NegotiatorResult<
            (AuthNResult<(Self, AuthN::AuthNSession), Channel::Conn>,
             Channel::Endpoint),
            Self
        >,
        NegoEntrySessionError<
            Channel::NegotiateError,
            SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
        >
    > {
        channel.negotiate(state)
            .map_err(|err| NegoEntrySessionError::Nego { err: err })?
            .map_pending(|pending| SessionNegoEntry::Session {
                pending: pending
            })
            .flat_map_ok(|(stream, endpoint)|
                         Self::authn(authn, endpoint.clone(), stream)
                         .map(|res| res.map(|res| (res, endpoint)))
                         .map_err(|err| NegoEntrySessionError::AuthN {
                             err: err
                         }))
    }

    fn authn(
        authn: &AuthN,
        endpoint: Channel::Endpoint,
        stream: Channel::Conn
    ) -> Result<
        NegotiatorResult<
            AuthNResult<(Self, AuthN::AuthNSession), Channel::Conn>,
            Self
        >,
        SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
    > {
        debug!(target: "session-nego-entry",
               "starting session authentication over {}",
               endpoint);

        let state = authn
            .start(&(), stream)
            .map_err(|err| SessionEntryAuthNError::Start {
                err: err
            })?;

        Ok(authn
           .negotiate(state)
           .map_err(|err| SessionEntryAuthNError::AuthN { err: err })?
           .map_pending(|pending| {
               debug!(target: "session-nego-entry",
                      "continuing session authentication over {}",
                      endpoint);

               SessionNegoEntry::AuthN {
                   endpoint: endpoint.clone(),
                   pending: pending
               }
           })
           .map(|res| {
               debug!(target: "session-nego-entry",
                      "completed session authentication over {}",
                      endpoint);

               res.map(|session| (SessionNegoEntry::Active {
                   endpoint: endpoint
               }, session))
           }))
    }

    /// Create a `SessionNegoEntry` for shutdown negotiations.
    fn do_shutdown(
        shutdown: &Channel::ShutdownNego,
        param: &<Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::Param,
        endpoint: Channel::Endpoint,
        stream: Channel::Conn,
    ) -> Result<
        NegotiatorResult<Channel::ShutdownValue, Self>,
        ShutdownError<
            <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
            <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
        >
    > {
        let state = shutdown.start(param, stream)
            .map_err(|err| ShutdownError::Start { err: err })?;

        Ok(shutdown.negotiate(state)
           .map_err(|err| ShutdownError::Negotiate {
               err: err
           })?
           .map_pending(|pending| SessionNegoEntry::Shutdown {
               endpoint: endpoint,
               pending: pending
           }))
    }

    fn do_step(
        self,
        endpoints: &mut HashSet<Channel::Endpoint>,
        registry: &Registry,
        channel: &Channel,
        authn: &AuthN,
        shutdown: &Channel::ShutdownNego,
    ) -> Result<
        NegotiatorResult<
            (Option<AuthNResult<(Self, AuthN::AuthNSession), Channel::Conn>>,
             Channel::Endpoint),
            Self
        >,
        SessionEntryStepError<
            Channel::NegotiateError,
            SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>,
            <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
        >
    > {
        match self {
            SessionNegoEntry::Session { pending } => channel
                .complete_negotiate(pending)
                .map_err(|err| SessionEntryStepError::Session { err: err })?
                .map_pending(|pending| SessionNegoEntry::Session {
                    pending: pending
                })
                .flat_map_ok(|(stream, endpoint)|
                             Self::authn(authn, endpoint.clone(), stream)
                             .map(|res| res.map(|res| (Some(res), endpoint)))
                             .map_err(|err| SessionEntryStepError::AuthN {
                                 err: err
                             })),
            SessionNegoEntry::AuthN { pending, endpoint } =>
                Ok(authn
                   .complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::AuthN {
                       err: SessionEntryAuthNError::AuthN {
                           err: err
                       }
                   })?
                   .map_pending(|pending| SessionNegoEntry::AuthN {
                       endpoint: endpoint.clone(),
                       pending: pending
                   })
                   .map(|res| (Some(res.map(|session|
                                            (SessionNegoEntry::Active {
                                                endpoint: endpoint.clone()
                                            }, session))),
                                    endpoint))),
            SessionNegoEntry::Active { endpoint } => {
                endpoints.insert(endpoint.clone());

                Ok(NegotiatorResult::Pending(SessionNegoEntry::Active {
                    endpoint: endpoint
                }))
            }
            SessionNegoEntry::Shutdown { pending, endpoint } =>
                Ok(shutdown.complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::Shutdown { err: err })?
                   .map_pending(|pending| SessionNegoEntry::Shutdown {
                       endpoint: endpoint.clone(),
                       pending: pending
                   })
                   .map(|mut val| {
                       info!(target: "session-nego-entry",
                             "shutdown session with {}",
                             endpoint);

                       val.deregister(registry);

                       (None, endpoint)
                   }))
        }
    }

    fn handle_shutdown_result<Addr>(
        registry: &Registry,
        res: NegotiatorResult<Channel::ShutdownValue, Self>,
        endpoint: Addr
    ) -> Result<Option<Self>, std::io::Error>
    where Addr: Display {
        match res {
            NegotiatorResult::Complete(mut val) => {
                info!(target: "session-nego-entry",
                      "shutdown session with {}",
                      endpoint);

                val.deregister(registry);

                Ok(None)
            }
            NegotiatorResult::Pending(pending) => {
                debug!(target: "session-nego-entry",
                       "continuing shutdown negotiation with {}",
                       endpoint);

                Ok(Some(pending))
            }
        }
    }

    /// Consume this `SessionNegoEntry` and step negotiations forward.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of completion.  It will create a new
    /// `SessionNegoEntry` if the session is still going.
    ///
    /// # Parameters
    ///
    /// - `endpoints`: A [HashSet] into which the endpoints for any
    ///   active sessions will be placed.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
    ///
    /// - `param`: The parameter to use to begin shutdown.
    ///
    /// # Return Values
    ///
    /// - `Some(self, Some(session))`: If a session was successfully
    ///   negotiated.
    ///
    /// - `Some(self, None)`: If the session still exists, but did not
    ///   produce a new session.
    ///
    /// - `None`: If negotiations concluded, but did not yield a session.
    fn step(
        self,
        endpoints: &mut HashSet<Channel::Endpoint>,
        registry: &Registry,
        channel: &Channel,
        authn: &AuthN,
        shutdown: &Channel::ShutdownNego,
    ) -> Result<
        Option<(Self, Option<AuthN::AuthNSession>)>,
        SessionEntryStepError<
            Channel::NegotiateError,
            SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>,
            ShutdownError<
                <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
            >
        >
    > {
        match self.do_step(endpoints, registry, channel, authn, shutdown) {
            // Negotiations completed and yielded a session.
            Ok(NegotiatorResult::Complete(
                (Some(AuthNResult::Accept((out, session))), endpoint)
            )) => {
                info!(target: "session-nego-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                Ok(Some((out, Some(session))))
            }
            // Negotiations completed and yielded an
            // authentication failure.
            Ok(NegotiatorResult::Complete(
                (Some(AuthNResult::Reject(stream)), endpoint)
            )) => {
                info!(target: "session-nego-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let res = Self::do_shutdown(shutdown, &channel.shutdown_param(),
                                            endpoint.clone(), stream)
                    .map_err(|err| SessionEntryStepError::Shutdown {
                        err: err
                    })?;
                let out = Self::handle_shutdown_result(registry, res, endpoint)
                    .map_err(|err| SessionEntryStepError::IO { err: err })?;

                Ok(out.map(|out| (out, None)))
            },
            // Negotiations completed and yielrded a session.
            Ok(NegotiatorResult::Complete((None, endpoint))) => {
                info!(target: "session-nego-entry",
                      "shutdown session with {}",
                      endpoint);

                Ok(None)
            }
            Ok(NegotiatorResult::Pending(pending)) => Ok(Some((pending, None))),
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => match err {
                    SessionEntryStepError::Session { err } =>
                        Err(SessionEntryStepError::Session { err: err }),
                    SessionEntryStepError::AuthN { err } =>
                        Err(SessionEntryStepError::AuthN { err: err }),
                    SessionEntryStepError::Shutdown { err } =>
                        Err(SessionEntryStepError::Shutdown {
                            err: ShutdownError::Negotiate {
                                err: err
                            }
                        }),
                    SessionEntryStepError::IO { err } =>
                        Err(SessionEntryStepError::IO { err: err }),
                }
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "session-nego-entry",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    warn!(target: "session-nego-entry",
                          "session negotiation failed: {}",
                          err);

                    // See if we need to shut down the stream.
                    let stream = match err {
                        SessionEntryStepError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        SessionEntryStepError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr()
                            .map_err(|err| SessionEntryStepError::IO {
                                err: err
                            })?;
                        let res = Self::do_shutdown(shutdown,
                                                    &channel.shutdown_param(),
                                                    endpoint.clone(),
                                                    stream)
                            .map_err(|err| SessionEntryStepError::Shutdown {
                                err: err
                            })?;
                        let out = Self::handle_shutdown_result(registry, res,
                                                               endpoint)
                            .map_err(|err| SessionEntryStepError::IO {
                                err: err
                            })?;

                        Ok(out.map(|out| (out, None)))
                    } else {
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Shut down an active session.
    ///
    /// This will consume the `SessionNegoEntry` and attempt shutdown
    /// negotiations.  If negotiations cannot be concluded
    /// immediately, a new `SessionNegoEntry` representing the pending
    /// negotiations will be returned.
    ///
    /// # Parameters
    ///
    /// - `shutdown`: The [Negotiator] to use for shutdown.
    ///
    /// - `param`: The parameter to use to begin the shutdown.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// - `Some(..)` if shutdown negotiations are still pending.
    ///
    /// - `None` if the session was shut down successfully.
    fn shutdown(
        self,
        registry: &Registry,
        shutdown: &Channel::ShutdownNego,
        param: &<Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::Param,
        stream: Channel::Conn,
    ) -> Result<
        Option<Self>,
        SessionEntryShutdownError<
            <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
            <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
        >
    > {
        if let SessionNegoEntry::Active { endpoint } = self {
            let res = SessionNegoEntry::do_shutdown(shutdown, param,
                                                    endpoint.clone(), stream)
                .map_err(|err| SessionEntryShutdownError::Shutdown {
                    err: err
                })?;

            Self::handle_shutdown_result(registry, res, endpoint)
                .map_err(|err| SessionEntryShutdownError::IO { err: err })
        } else {
            Err(SessionEntryShutdownError::NotActive)
        }
    }
}

impl<Channel, AuthN> ConnectorEntry<Channel, AuthN>
where
    Channel: NearConnector,
    Channel::Endpoint: Clone + Eq + Hash,
    Channel::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError: ScopedError,
    AuthN: Clone + Create + SessionAuthN<Channel::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
{
    fn create(
        registry: &Registry,
        mut channel: Channel,
        authn: &AuthN,
        retry: &Retry,
        token: Token
    ) -> Result<
        RetryResult<(Self, Option<AuthN::AuthNSession>)>,
        ConnectorEntryCreateError<
            Channel::StartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Channel::NegotiateError,
                    SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
                >,
                SessionEntryShutdownError<
                    <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                    <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
                >
            >
        >
    > {
        channel.start(registry, token)
            .map_err(|err| ConnectorEntryCreateError::Start { err: err })?
            .map_ok(|state| {
                let shutdown = channel.shutdown_nego();
                let mut entry = ConnectorEntry {
                    channel: channel,
                    shutdown: shutdown,
                    state: None,
                    nretries: 0,
                    when: None
                };
                let session = entry.do_connect(registry, authn, retry, state)
                    .map_err(|err| ConnectorEntryCreateError::Nego {
                        err: err
                    })?;

                Ok((entry, session))
            })
    }

    fn step(
        &mut self,
        endpoints: &mut HashSet<Channel::Endpoint>,
        registry: &Registry,
        authn: &AuthN,
        retry: &Retry,
        token: Token
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        ConnectorEntryStepError<
            Channel::StartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Channel::NegotiateError,
                    SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
                >,
                SessionEntryShutdownError<
                    <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                    <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
                >
            >,
            SessionEntryStepError<
                Channel::NegotiateError,
                SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>,
                SessionEntryShutdownError<
                    <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                    <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
                >
            >
        >
    > {
        let state = self.state.take();

        match state {
            Some(state) => self.do_step(endpoints, registry,
                                        authn, retry, state)
                .map_err(|err| ConnectorEntryStepError::Step { err: err })
                .map(RetryResult::Success),
            None => {
                let now = Instant::now();
                let when = self.when.take().and_then(|when| if when < now {
                    Some(when)
                } else {
                    None
                });

                if let Some(when) = when {
                    Ok(RetryResult::Retry(when))
                } else {
                    match self.channel.start(registry, token)
                        .map_err(|err| ConnectorEntryStepError::Start {
                            err: err
                        })? {
                        RetryResult::Success(state) => self
                            .do_connect(registry, authn, retry, state)
                            .map_err(|err| ConnectorEntryStepError::Connect {
                                err: err
                            })
                            .map(RetryResult::Success),
                        RetryResult::Retry(when) => {
                            self.when = Some(when);

                            Ok(RetryResult::Retry(when))
                        }
                    }
                }
            }
        }
    }

    fn shutdown(
        &mut self,
        registry: &Registry,
        stream: Channel::Conn,
    ) -> Result<
        bool,
        SessionEntryShutdownError<
            <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
            <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
        >
    > {
        let state = self.state.take()
            .ok_or(SessionEntryShutdownError::NotActive)?;
        let newstate = state
            .shutdown(registry, &self.shutdown, &self.channel.shutdown_param(),
                      stream)?;
        let out = newstate.is_none();

        self.state = newstate;

        Ok(out)
    }

    fn do_shutdown(
        &mut self,
        registry: &Registry,
        endpoint: Channel::Endpoint,
        stream: Channel::Conn,
    ) -> Result<
        (),
        SessionEntryShutdownError<
            <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
            <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
        >
    > {
        let res = SessionNegoEntry::do_shutdown(&self.shutdown,
                                                &self.channel.shutdown_param(),
                                                endpoint.clone(), stream)
            .map_err(|err| SessionEntryShutdownError::Shutdown { err: err })?;

        self.state = SessionNegoEntry::handle_shutdown_result(registry, res,
                                                              endpoint)
            .map_err(|err| SessionEntryShutdownError::IO { err: err })?;

        Ok(())
    }

    fn do_connect(
        &mut self,
        registry: &Registry,
        authn: &AuthN,
        retry: &Retry,
        state: Channel::State,
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionCreateError<
            NegoEntrySessionError<
                Channel::NegotiateError,
                SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
            >,
            SessionEntryShutdownError<
                <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
            >
        >
    > {
        match SessionNegoEntry::session(&self.channel, authn, state) {
            Ok(NegotiatorResult::Complete((AuthNResult::Accept((out, session)),
                                           endpoint))) => {
                info!(target: "connector-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                self.state = Some(out);

                Ok(Some(session))
            },
            Ok(NegotiatorResult::Complete((AuthNResult::Reject(stream),
                                           endpoint))) => {
                info!(target: "connector-entry",
                      "authentication rejected for session with {}",
                      self.channel.endpoint());

                let delay = retry.retry_delay(self.nretries);

                self.when = Some(Instant::now() + delay);
                self.nretries += 1;

                self.do_shutdown(registry, endpoint, stream)
                    .map_err(|err| SessionCreateError::Shutdown { err: err })?;

                Ok(None)
            },
            Ok(NegotiatorResult::Pending(pending)) => {
                self.state = Some(pending);

                Ok(None)
            }
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System =>
                    Err(SessionCreateError::Session { err: err }),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "connector-entry",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    warn!(target: "connector-entry",
                          "session authentication with {} failed: {}",
                          self.channel.endpoint(), err);

                    let delay = retry.retry_delay(0);

                    debug!(target: "connector-entry",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.nretries = self.nretries + 1;
                    self.when = Some(Instant::now() + delay);
                    self.state = None;

                    // See if we need to shut down the stream.
                    let stream = match err {
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr()
                            .map_err(|err| SessionCreateError::IO {
                                err: err
                            })?;

                        self.do_shutdown(registry, endpoint, stream)
                            .map_err(|err| SessionCreateError::Shutdown {
                                err: err
                            })?;
                    }

                    Ok(None)
                }
            }
        }
    }

    fn do_step(
        &mut self,
        endpoints: &mut HashSet<Channel::Endpoint>,
        registry: &Registry,
        authn: &AuthN,
        retry: &Retry,
        state: SessionNegoEntry<Channel, AuthN>
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionEntryStepError<
            Channel::NegotiateError,
            SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>,
            SessionEntryShutdownError<
                <Channel::ShutdownNego as NegotiatorStart<Channel::ShutdownValue, Channel::Conn>>::StartError,
                <Channel::ShutdownNego as Negotiator<Channel::ShutdownValue>>::NegotiateError
            >
        >
    > {
        match state.do_step(endpoints, registry, &self.channel,
                            authn, &self.shutdown) {
            // Negotiations completed and yielded a session.
            Ok(NegotiatorResult::Complete(
                (Some(AuthNResult::Accept((out, session))), endpoint)
            )) => {
                info!(target: "connector-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                self.state = Some(out);

                Ok(Some(session))
            }
            // Negotiations completed and yielded an
            // authentication failure.
            Ok(NegotiatorResult::Complete(
                (Some(AuthNResult::Reject(stream)), endpoint)
            )) => {
                info!(target: "connector-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let delay = retry.retry_delay(self.nretries);

                self.when = Some(Instant::now() + delay);
                self.nretries += 1;

                self.do_shutdown(registry, endpoint, stream)
                    .map_err(|err| SessionEntryStepError::Shutdown {
                        err: err
                    })?;

                Ok(None)
            },
            // Negotiations completed and yielrded a session.
            Ok(NegotiatorResult::Complete((None, endpoint))) => {
                info!(target: "connector-entry",
                      "shutdown session with {}",
                      endpoint);

                Ok(None)
            }
            Ok(NegotiatorResult::Pending(pending)) => {
                self.state = Some(pending);

                Ok(None)
            }
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => match err {
                    SessionEntryStepError::Session { err } =>
                        Err(SessionEntryStepError::Session { err: err }),
                    SessionEntryStepError::AuthN { err } =>
                        Err(SessionEntryStepError::AuthN { err: err }),
                    SessionEntryStepError::Shutdown { err } =>
                        Err(SessionEntryStepError::Shutdown {
                            err: SessionEntryShutdownError::Shutdown {
                                err: ShutdownError::Negotiate {
                                    err: err
                                }
                            }
                        }),
                    SessionEntryStepError::IO { err } =>
                        Err(SessionEntryStepError::IO { err: err }),
                }
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "connector-entry",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    warn!(target: "connector-entry",
                          "session authentication with {} failed: {}",
                          self.channel.endpoint(), err);

                    let delay = retry.retry_delay(0);

                    debug!(target: "connector-entry",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.nretries = self.nretries + 1;
                    self.when = Some(Instant::now() + delay);
                    self.state = None;

                    // See if we need to shut down the stream.
                    let stream = match err {
                        SessionEntryStepError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        SessionEntryStepError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr()
                            .map_err(|err| SessionEntryStepError::IO {
                                err: err
                            })?;

                        self.do_shutdown(registry, endpoint, stream)
                            .map_err(|err| SessionEntryStepError::Shutdown {
                                err: err
                            })?;
                    }

                    Ok(None)
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum ChannelEntryReqError<Channel, Entry> {
    /// Error creating the channel instance.
    Channel {
        /// Error that occurred creating the channel instance.
        err: Channel
    },
    /// Error creating the [ConnectorEntry].
    Entry {
    /// The error that occurred creating the [ConnectorEntry].
        err: Entry
    },
    /// The given endpoint was already requested.
    Collision,
    /// Token generator was exhausted.
    NoTokens,
    /// Trying to request a stream from an inbound-only channel.
    Inbound
}

#[derive(Debug)]
pub enum ChannelEntryShutdownError<Shutdown, Endpoint> {
    Shutdown {
        err: Shutdown
    },
    IO {
        err: std::io::Error
    },
    NotFound {
        endpoint: Endpoint
    },
    Inconsistent,
    Mismatch
}

#[derive(Debug)]
pub enum ChannelEntryListenError<Start> {
    Start {
        err: Start
    },
    NoTokens
}

impl<Accept, Conn, AcceptAuthN, ConnAuthN>
    ChannelEntry<Accept, Conn, AcceptAuthN, ConnAuthN>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Endpoint: Clone + Eq + Hash,
    Conn::Conn: Session,
    Conn::Config: Clone,
    Conn::NegotiateError: ScopedError,
    <Conn::ShutdownNego as Negotiator<Conn::ShutdownValue>>::NegotiateError: ScopedError,
    Accept: NearChannel + NearChannelCreate,
    Accept::Endpoint: Clone + Eq + Hash,
    Accept::Conn: Session,
    Accept::NegotiateError: ScopedError,
    <Accept::ShutdownNego as Negotiator<Accept::ShutdownValue>>::NegotiateError: ScopedError,
    ConnAuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    ConnAuthN::NegotiateError: ScopedError,
    AcceptAuthN: Clone + Create + SessionAuthN<Accept::Conn, Param = ()>,
    AcceptAuthN::NegotiateError: ScopedError
{
    fn shutdown_conn(
        &mut self,
        registry: &Registry,
        stream: Conn::Conn,
    ) -> Result<
        (),
        ChannelEntryShutdownError<
            SessionEntryShutdownError<
                <Conn::ShutdownNego as NegotiatorStart<Conn::ShutdownValue, Conn::Conn>>::StartError,
                <Conn::ShutdownNego as Negotiator<Conn::ShutdownValue>>::NegotiateError
            >,
            Conn::Endpoint
        >
    > {
        let endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        match &mut self.mode {
            ChannelMode::Duplex {
                conn_tokens, negos, ..
            } => if let Entry::Occupied(ent) =
                conn_tokens.entry(endpoint.clone()) {
                if let DuplexValue::Conn { conn } = negos
                    .get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)? {
                    let delete = conn.shutdown(registry, stream)
                        .map_err(|err| ChannelEntryShutdownError::Shutdown {
                            err: err
                        })?;

                    if delete {
                        if negos.remove(ent.get()).is_none() {
                            error!(target: "connector-entry",
                                   "entry for token {:?} missing",
                                   ent.get());
                        }

                        ent.remove();
                    }

                    Ok(())
                } else {
                    Err(ChannelEntryShutdownError::Mismatch)
                }
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Outbound {
                tokens, negos, ..
            } =>  if let Entry::Occupied(ent) = tokens.entry(endpoint.clone()) {
                let conn = negos.get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)?;
                let delete = conn.shutdown(registry, stream)
                    .map_err(|err| ChannelEntryShutdownError::Shutdown {
                        err: err
                    })?;

                if delete {
                    if negos.remove(ent.get()).is_none() {
                        error!(target: "connector-entry",
                               "entry for token {:?} missing",
                               ent.get());
                    }

                    ent.remove();
                }

                Ok(())
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Inbound { .. } =>
                Err(ChannelEntryShutdownError::Mismatch)
        }
    }

    fn shutdown_accept(
        &mut self,
        registry: &Registry,
        stream: Accept::Conn,
    ) -> Result<
        (),
        ChannelEntryShutdownError<
            SessionEntryShutdownError<
                <Accept::ShutdownNego as NegotiatorStart<Accept::ShutdownValue, Accept::Conn>>::StartError,
                <Accept::ShutdownNego as Negotiator<Accept::ShutdownValue>>::NegotiateError
            >,
            Accept::Endpoint
        >
    > {
        let endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        match &mut self.mode {
            ChannelMode::Duplex {
                accept_tokens, negos, shutdown, acceptor, ..
            } => if let Entry::Occupied(ent) = accept_tokens
                .entry(endpoint.clone()) {
                if let DuplexValue::Accept { accept } = negos
                    .get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)? {
                    let newaccept = accept.take()
                        .ok_or(ChannelEntryShutdownError::NotFound {
                            endpoint: endpoint
                        })?
                        .shutdown(
                            registry, shutdown, &acceptor.shutdown_param(),
                            stream
                        )
                        .map_err(|err| ChannelEntryShutdownError::Shutdown {
                            err: err
                        })?;

                    if newaccept.is_some() {
                        *accept = newaccept
                    } else {
                        if negos.remove(ent.get()).is_none() {
                            error!(target: "connector-entry",
                                   "entry for token {:?} missing",
                                   ent.get());
                        }

                        ent.remove();
                    }

                    Ok(())
                } else {
                    Err(ChannelEntryShutdownError::Mismatch)
                }
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Inbound {
                tokens, negos, shutdown, acceptor, ..
            } =>  if let Entry::Occupied(ent) = tokens.entry(endpoint.clone()) {
                let accept = negos.get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)?;
                let newaccept = accept.take()
                    .ok_or(ChannelEntryShutdownError::NotFound {
                        endpoint: endpoint
                    })?
                    .shutdown(
                        registry, shutdown, &acceptor.shutdown_param(),
                        stream
                    )
                    .map_err(|err| ChannelEntryShutdownError::Shutdown {
                        err: err
                    })?;

                if newaccept.is_some() {
                    *accept = newaccept
                } else {
                    if negos.remove(ent.get()).is_none() {
                        error!(target: "connector-entry",
                               "entry for token {:?} missing",
                               ent.get());
                    }

                    ent.remove();
                }

                Ok(())
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Outbound { .. } =>
                Err(ChannelEntryShutdownError::Mismatch)
        }
    }

    fn req_stream<Ctx, I>(
        &mut self,
        ctx: &mut Ctx,
        gentok: &mut Peekable<I>,
        registry: &Registry,
        endpoint: Conn::Endpoint,
        verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Option<ConnAuthN::AuthNSession>>,
        ChannelEntryReqError<
            Conn::CreateError,
            ConnectorEntryCreateError<
                Conn::StartError,
                SessionCreateError<
                    NegoEntrySessionError<
                        Conn::NegotiateError,
                        SessionEntryAuthNError<ConnAuthN::StartError, ConnAuthN::NegotiateError>
                    >,
                    SessionEntryShutdownError<
                        <Conn::ShutdownNego as NegotiatorStart<Conn::ShutdownValue, Conn::Conn>>::StartError,
                        <Conn::ShutdownNego as Negotiator<Conn::ShutdownValue>>::NegotiateError
                    >
                >
            >
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx
    {
        match &mut self.mode {
            ChannelMode::Duplex {
                config, conn_tokens, negos, out_authn, ..
            } => if !conn_tokens.contains_key(&endpoint) {
                let token = gentok.peek()
                    .ok_or(ChannelEntryReqError::NoTokens)?;
                let conn = Conn::create_with_endpoint(ctx, config.clone(),
                                                      endpoint, verify_endpoint)
                    .map_err(|err| ChannelEntryReqError::Channel { err: err })?;

                Ok(ConnectorEntry::create(registry, conn, out_authn,
                                          &self.retry, *token)
                   .map_err(|err| ChannelEntryReqError::Entry { err: err })?
                   .map(|(ent, out)| {
                       let ent = DuplexValue::Conn { conn: ent };
                       let _ = gentok.next();

                       if conn_tokens.insert(endpoint, *token).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       if negos.insert(*token, ent).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       out
                   }))
            } else {
                Err(ChannelEntryReqError::Collision)
            }
            ChannelMode::Outbound {
                config, tokens, negos, authn, ..
            } => if !tokens.contains_key(&endpoint) {
                let token = gentok.peek()
                    .ok_or(ChannelEntryReqError::NoTokens)?;
                let conn = Conn::create_with_endpoint(ctx, config.clone(),
                                                      endpoint, verify_endpoint)
                    .map_err(|err| ChannelEntryReqError::Channel { err: err })?;

                Ok(ConnectorEntry::create(registry, conn, authn,
                                          &self.retry, *token)
                   .map_err(|err| ChannelEntryReqError::Entry { err: err })?
                   .map(|(ent, out)| {
                       let _ = gentok.next();

                       if tokens.insert(endpoint, *token).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       if negos.insert(*token, ent).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       out
                   }))
            } else {
                Err(ChannelEntryReqError::Collision)
            }
            ChannelMode::Inbound { .. } => Err(ChannelEntryReqError::Inbound)
        }
    }

    fn start_incoming<I>(
        gentok: &mut Peekable<I>,
        sessions: &mut Vec<AcceptAuthN::AuthNSession>,
        when: &mut Option<Instant>,
        read: &mut bool,
        registry: &Registry,
        accept: &mut Accept,
        shutdown: &Accept::ShutdownNego,
        authn: &AcceptAuthN,
    ) -> Result<
        Option<Vec<(Token, SessionNegoEntry<Accept, AcceptAuthN>)>>,
        ChannelEntryListenError<Accept::StartError>
    >
    where
        I: Iterator<Item = Token>,
    {
        if when.map_or(true, |when| when <= Instant::now()) {
            let mut incoming = Vec::new();

            *when = None;

            loop {
                let token = gentok.peek()
                    .ok_or(ChannelEntryListenError::NoTokens)?;
                let token = *token;

                match accept.start(registry, token) {
                    Ok(RetryResult::Success(state)) => {
                        // Normal listen result.
                        *read = true;
                        gentok.next();
                        incoming.push((token, state));
                    }
                    // If we get a retry delay, record it and return
                    // what we have.
                    Ok(RetryResult::Retry(retry)) => {
                        *when = Some(retry);

                        break;
                    }
                    // Error; see if it's WouldBlock.
                    Err(err) => {
                        // Report errors other than WouldBlock.
                        if err.scope() != ErrorScope::WouldBlock {
                            error!(target: "channel-entry",
                                   "error listening for incoming sessions: {}",
                                   err);

                            if err.scope() >= ErrorScope::System {
                                return Err(ChannelEntryListenError::Start {
                                    err: err
                                })
                            }
                        }

                        break;
                    }
                }
            }

            let mut out = Vec::with_capacity(incoming.len());

            for (token, state) in incoming.drain(..) {
                match SessionNegoEntry::create(registry, accept, authn,
                                               shutdown, state) {
                    Ok(Some((ent, session))) => {
                        out.push((token, ent));

                        if let Some(session) = session {
                            sessions.push(session)
                        }
                    }
                    Ok(None) => {
                    }
                    Err(err) => {
                        error!(target: "channel-entry",
                               "error stepping pending negotiation: {}",
                               err);
                    }
                }
            }

            let out = if out.len() != 0 {
                Some(out)
            } else {
                None
            };

            Ok(out)
        } else {
            Ok(None)
        }
    }

    fn listen<Ctx, I>(
        &mut self,
        gentok: &mut Peekable<I>,
        out_sessions: &mut Vec<ConnAuthN::AuthNSession>,
        in_sessions: &mut Vec<AcceptAuthN::AuthNSession>,
        out_endpoints: &mut HashSet<Conn::Endpoint>,
        in_endpoints: &mut HashSet<Accept::Endpoint>,
        registry: &Registry,
        live: &HashSet<Token>,
    ) -> Result<
        (),
        ChannelEntryListenError<Accept::StartError>
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx
    {
        match &mut self.mode {
            ChannelMode::Duplex {
                negos, out_authn, retry_when, acceptor, shutdown,
                in_authn, accept_tokens, token, ..
            } => while {
                let mut read = false;

                // Pick up all incoming sessions.
                let incoming = if live.contains(token) {
                    let incoming = Self::start_incoming(gentok, in_sessions,
                                                        retry_when, &mut read,
                                                        registry, acceptor,
                                                        shutdown, in_authn)?;

                    incoming
                } else {
                    None
                };

                let mut deletes = Vec::with_capacity(negos.len());

                // Process all live existing sessions.
                for (token, ent) in negos.iter_mut() {
                    let now = Instant::now();

                    match ent {
                        DuplexValue::Conn { conn: ent } => if ent
                            .when.map_or(false, |when| when < now) ||
                            live.contains(token) {
                                match ent.step(out_endpoints, registry,
                                               out_authn, &self.retry,
                                               *token) {
                                    // Session was produced; record it.
                                    Ok(RetryResult::Success(Some(session))) => {
                                        out_sessions.push(session);
                                    }
                                    // Record a deferral.
                                    Ok(RetryResult::Retry(when)) => if ent.when
                                        .map_or(true, |curr| curr < when) {
                                            ent.when = Some(when);
                                        }
                                    // We don't delete outgoing
                                    // entries that fail to connect.
                                    Ok(RetryResult::Success(None)) => {}
                                    Err(err) => {
                                        error!(target: "channel-entry",
                                               "negotiation step error: {}",
                                               err);
                                    }
                                }
                            },
                        DuplexValue::Accept { accept: ent } => if live
                            .contains(token) {
                                if let Some(state) = ent.take() {
                                    match state.step(in_endpoints, registry,
                                                     acceptor, in_authn,
                                                     shutdown) {
                                        // Session was produced; record it.
                                        Ok(Some((state, session))) => {
                                            *ent = Some(state);

                                            if let Some(session) = session {
                                                in_sessions.push(session);
                                            }
                                        }
                                        Ok(None) => {
                                            deletes.push(*token)
                                        }
                                        Err(err) => {
                                            error!(target: "channel-entry",
                                                   "negotiation step error: {}",
                                                   err);

                                            deletes.push(*token)
                                        }
                                    }
                                } else {
                                    error!(target: "channel-entry",
                                           "empty entry state for token {:?}",
                                           token);
                                }
                            }
                    }
                }

                // Delete expired entries.
                for token in deletes {
                    if negos.remove(&token).is_none() {
                        error!(target: "channel-entry",
                               "deleted token {:?} was not present",
                               token);
                    }
                }

                // Add the incoming sessions if we have them.
                if let Some(incoming) = incoming {
                    for (token, ent) in incoming {
                        let endpoint: Option<&Accept::Endpoint> =
                            match &ent {
                                SessionNegoEntry::AuthN { endpoint, .. } |
                                SessionNegoEntry::Active { endpoint } |
                                SessionNegoEntry::Shutdown {
                                    endpoint, ..
                                } => Some(endpoint),
                                SessionNegoEntry::Session { .. } => None
                            };

                        if let Some(endpoint) = endpoint {
                            if accept_tokens.insert(endpoint.clone(),
                                                    token.clone())
                                .is_some() {
                                error!(target: "channel-entry",
                                       "tokens contains entry for {}",
                                       endpoint);
                            }
                        }

                        let ent = DuplexValue::Accept { accept: Some(ent) };

                        if negos.insert(token, ent).is_some() {
                            error!(target: "channel-entry",
                                   "sessions contains entry for {:?}",
                                   token);
                        }
                    }
                }

                read
            } {}
            ChannelMode::Outbound { negos, authn, .. } =>
                for (token, ent) in negos.iter_mut() {
                    let now = Instant::now();

                    if ent.when.map_or(false, |when| when < now) ||
                        live.contains(token) {
                        match ent.step(out_endpoints, registry, authn,
                                       &self.retry, *token) {
                            // Session was produced; record it.
                            Ok(RetryResult::Success(Some(session))) => {
                                out_sessions.push(session);
                            }
                            // Record a deferral.
                            Ok(RetryResult::Retry(when)) => if ent.when
                                .map_or(true, |curr| curr < when) {
                                ent.when = Some(when);
                            }
                            // We don't delete outgoing entries that fail
                            // to connect.
                            Ok(RetryResult::Success(None)) => {}
                            Err(err) => {
                                error!(target: "channel-entry",
                                       "negotiation step error: {}",
                                       err);
                            }
                        }
                    }
                }
            ChannelMode::Inbound {
                tokens, negos, shutdown, acceptor, authn, retry_when, token
            } => while {
                let mut read = false;

                // Pick up all incoming sessions.
                let incoming = if live.contains(token) {
                    let incoming = Self::start_incoming(gentok, in_sessions,
                                                        retry_when, &mut read,
                                                        registry, acceptor,
                                                        shutdown, authn)?;

                    incoming
                } else {
                    None
                };

                let mut deletes = Vec::with_capacity(negos.len());

                // Process all live existing sessions.
                for (token, ent) in negos.iter_mut() {
                    if live.contains(token) {
                        if let Some(state) = ent.take() {
                            match state.step(in_endpoints, registry, acceptor,
                                             authn, shutdown) {
                                // Session was produced; record it.
                                Ok(Some((state, session))) => {
                                    *ent = Some(state);

                                    if let Some(session) = session {
                                        in_sessions.push(session);
                                    }
                                }
                                Ok(None) => {
                                    deletes.push(*token)
                                }
                                Err(err) => {
                                    error!(target: "channel-entry",
                                           "negotiation step error: {}",
                                           err);
                                }
                            }
                        } else {
                            error!(target: "channel-entry",
                                   "empty entry state for token {:?}",
                                   token);
                        }
                    }
                }

                // Delete expired entries.
                for token in deletes {
                    if negos.remove(&token).is_none() {
                        error!(target: "channel-entry",
                               "deleted token {:?} was not present",
                               token);
                    }
                }

                // Add the incoming sessions if we have them.
                if let Some(incoming) = incoming {
                    for (token, ent) in incoming {
                        let endpoint: Option<&Accept::Endpoint> =
                            match &ent {
                                SessionNegoEntry::AuthN { endpoint, .. } |
                                SessionNegoEntry::Active { endpoint } |
                                SessionNegoEntry::Shutdown {
                                    endpoint, ..
                                } => Some(endpoint),
                                SessionNegoEntry::Session { .. } => None
                            };

                        if let Some(endpoint) = endpoint {
                            if tokens.insert(endpoint.clone(),
                                             token.clone())
                                .is_some() {
                                error!(target: "channel-entry",
                                       "tokens contains entry for {}",
                                       endpoint);
                            }
                        }

                        if negos.insert(token, Some(ent)).is_some() {
                            error!(target: "channel-entry",
                                   "sessions contains entry for {:?}",
                                   token);
                        }
                    }
                }

                read
            } {}
        }

        Ok(())
    }
}

impl<Accept, Conn> Read for DuplexValue<Accept, Conn>
where Conn: Read,
      Accept: Read {
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.read(buf),
            DuplexValue::Accept { accept } => accept.read(buf),
        }
    }

    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.read_vectored(buf),
            DuplexValue::Accept { accept } => accept.read_vectored(buf),
        }
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.read_exact(buf),
            DuplexValue::Accept { accept } => accept.read_exact(buf),
        }
    }
}

impl<Accept, Conn> Write for DuplexValue<Accept, Conn>
where Conn: Write,
      Accept: Write {
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.write(buf),
            DuplexValue::Accept { accept } => accept.write(buf),
        }
    }

    fn flush(
        &mut self,
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.flush(),
            DuplexValue::Accept { accept } => accept.flush()
        }
    }

    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.write_vectored(buf),
            DuplexValue::Accept { accept } => accept.write_vectored(buf),
        }
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn { conn } => conn.write_all(buf),
            DuplexValue::Accept { accept } => accept.write_all(buf),
        }
    }
}

impl<Start, Auth> ScopedError for SessionEntryAuthNError<Start, Auth>
where Start: ScopedError,
      Auth: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            SessionEntryAuthNError::Start { err } => err.scope(),
            SessionEntryAuthNError::AuthN { err } => err.scope(),
        }
    }
}

impl<Nego, AuthN> ScopedError for NegoEntrySessionError<Nego, AuthN>
where Nego: ScopedError,
      AuthN: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            NegoEntrySessionError::Nego { err } => err.scope(),
            NegoEntrySessionError::AuthN { err } => err.scope(),
        }
    }
}

impl<Session, AuthN, Shutdown> ScopedError
    for SessionEntryStepError<Session, AuthN, Shutdown>
where Session: ScopedError,
      AuthN: ScopedError,
      Shutdown: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            SessionEntryStepError::Session { err } => err.scope(),
            SessionEntryStepError::AuthN { err } => err.scope(),
            SessionEntryStepError::Shutdown { err } => err.scope(),
            SessionEntryStepError::IO { err } => err.scope()
        }
    }
}

impl Display for NearChannelID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}", self.0.0)
    }
}

impl<Accept, AuthN> Display for NearChannelsEntryCreateError<Accept, AuthN>
where Accept: Display,
      AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsEntryCreateError::Accept { err } => err.fmt(f),
            NearChannelsEntryCreateError::AuthN { err } => err.fmt(f),
        }
    }
}

impl<Conn, Req> Display for NearChannelsEntrySessionError<Conn, Req>
where Conn: Display,
      Req: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsEntrySessionError::Req { err } => err.fmt(f),
            NearChannelsEntrySessionError::Conn { err } => err.fmt(f),
            NearChannelsEntrySessionError::NoTokens =>
                write!(f, "tokens exhausted")
        }
    }
}

impl<Session, AuthN, Shutdown> Display
    for SessionEntryStepError<Session, AuthN, Shutdown>
where Session: Display,
      AuthN: Display,
      Shutdown: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryStepError::Session { err } => err.fmt(f),
            SessionEntryStepError::AuthN { err } => err.fmt(f),
            SessionEntryStepError::Shutdown { err } => err.fmt(f),
            SessionEntryStepError::IO { err } => err.fmt(f)
        }
    }
}

impl<Start, Auth> Display for SessionEntryAuthNError<Start, Auth>
where Start: Display,
      Auth: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryAuthNError::Start { err } => err.fmt(f),
            SessionEntryAuthNError::AuthN { err } => err.fmt(f),
        }
    }
}

impl<Session, Shutdown> Display for SessionEntryCreateError<Session, Shutdown>
where Session: Display,
      Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryCreateError::IO { err } => err.fmt(f),
            SessionEntryCreateError::Session { err } => err.fmt(f),
            SessionEntryCreateError::Shutdown { err } => err.fmt(f),
        }
    }
}

impl<Start, Shutdown> Display for SessionEntryShutdownError<Start, Shutdown>
where Start: Display,
      Shutdown: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryShutdownError::Shutdown { err } => err.fmt(f),
            SessionEntryShutdownError::IO { err } => err.fmt(f),
            SessionEntryShutdownError::NotActive =>
                write!(f, "session is not active")
        }
    }
}

impl<Nego, AuthN> Display for NegoEntrySessionError<Nego, AuthN>
where Nego: Display,
      AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NegoEntrySessionError::Nego { err } => err.fmt(f),
            NegoEntrySessionError::AuthN { err } => err.fmt(f),
        }
    }
}

impl<Session, Shutdown> Display for SessionCreateError<Session, Shutdown>
where Session: Display,
      Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionCreateError::IO { err } => err.fmt(f),
            SessionCreateError::Session { err } => err.fmt(f),
            SessionCreateError::Shutdown { err } => err.fmt(f),
        }
    }
}

impl<Create, Nego> Display for ConnectorEntryCreateError<Create, Nego>
where
    Create: Display,
    Nego: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConnectorEntryCreateError::Start { err } => err.fmt(f),
            ConnectorEntryCreateError::Nego { err } => err.fmt(f),
        }
    }
}

impl<Start, Connect, Step> Display
    for ConnectorEntryStepError<Start, Connect, Step>
where
    Start: Display,
    Connect: Display,
    Step: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ConnectorEntryStepError::Start { err } => err.fmt(f),
            ConnectorEntryStepError::Connect { err } => err.fmt(f),
            ConnectorEntryStepError::Step { err } => err.fmt(f),
        }
    }
}

impl<Shutdown, Endpoint> Display
    for ChannelEntryShutdownError<Shutdown, Endpoint>
where Shutdown: Display,
      Endpoint: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ChannelEntryShutdownError::Shutdown { err } => err.fmt(f),
            ChannelEntryShutdownError::IO { err } => err.fmt(f),
            ChannelEntryShutdownError::NotFound { endpoint } =>
                write!(f, "no entry for {}", endpoint),
            ChannelEntryShutdownError::Inconsistent =>
                write!(f, "inconsistent token and session tables"),
            ChannelEntryShutdownError::Mismatch =>
                write!(f, "wrong type of stream for this channel entry")
        }
    }
}
