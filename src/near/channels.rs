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
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::near::types::NearDuplexNegoTypes;
use crate::near::types::NearSessionNegoTypes;
use crate::resolve::cache::NSNameCachesCtx;

/// Newtype wrapper for IDs created to refer to specific channels.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NearChannelID(Token);

/// Generic type used in duplex channels.
///
/// This is necessary as unlike [FarChannel](crate::far::FarChannel)s,
/// [NearChannel]s have distinct types for inbound and outbound
/// sessions.
enum DuplexValue<Accept, Conn> {
    /// Value associated with the inbound (accepting) channel.
    Accept(Accept),
    /// Value associated with the outbound (connecting) channel.
    Conn(Conn)
}

/// Negotiation state for a given channel.
///
/// This is usable for both incoming and outgoing channels.
enum SessionNegoState<Types>
where
    Types: NearSessionNegoTypes
{
    /// Session negotiation is pending.
    Session {
        /// Pending negotiation state.
        pending: Types::ConnPending
    },
    /// Authentication negotiation is pending.
    AuthN {
        /// Endpoint for this negotiation.
        endpoint: Types::Endpoint,
        /// Pending negotiation state.
        pending: Types::AuthNPending,
    },
    Active {
        /// Endpoint for this session.
        endpoint: Types::Endpoint,
    },
    /// Shutdown negotiation is pending.
    Shutdown {
        /// Endpoint for this session.
        endpoint: Types::Endpoint,
        /// Pending negotiation state.
        pending: Types::ShutdownPending
    }
}

/// Session entry for an incoming (accepting) channel.
///
/// This holds the negotiation state for sessions through an acceptor
/// with a single endpoint..
struct AcceptorEntry<Types>
where
    Types: NearSessionNegoTypes
{
    /// State of negotiations.
    ///
    /// This should generally never be `None`.  [Option] is only used
    /// here to implement a state machine (this is a limitation of the
    /// Rust standard API).
    state: Option<SessionNegoState<Types>>,
    /// When to retry next.
    when: Option<Instant>
}

/// Session entry for an outgoing (connecting) channel.
///
/// This holds the negotiation state for sessions through a connector
/// for a single endpoint.
struct ConnectorEntry<Types>
where
    Types: NearSessionNegoTypes
{
    /// The [NearConnector] used to establish sessions.
    channel: Types::Channel,
    /// The [Negotiator] used to shut down sessions.
    shutdown: Types::ShutdownNego,
    /// The current state of negotiations.
    ///
    /// This is allowed to be `None`, if no session currently exists.
    state: Option<SessionNegoState<Types>>,
    // XXX Replace this retry information with a standard type in
    // common.
    /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Option<Instant>
}

/// Representation of a mode in which a given channel operates.
///
/// This effectively acts as most of the state of the [ChannelEntry].
///
/// Unlike [FarChannel](crate::far::FarChannel)s, [NearChannel]s have
/// differing incoming and outgoing types.  This means that the
/// incoming and outgoing channels are logically associated with each
/// other in duplex mode as opposed to being the same type.  Also,
/// there is not necessarily an incoming or outgoing channel in all
/// cases.  This type exists to manage that.
enum ChannelMode<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Full-duplex channels, which can establish outbound as well as
    /// inbound connections.
    Duplex {
        /// Base configuration used to create connectors.
        config: Types::OutConfig,
        /// [SessionAuthN] used to authenticate incoming sessions.
        in_authn: Types::InAuthN,
        /// [SessionAuthN] used to authenticate outgoing sessions.
        out_authn: Types::OutAuthN,
        /// Acceptor for incoming sessions.
        acceptor: Types::InChannel,
        /// [Negotiator] used to shut down incoming sessions.
        shutdown: Types::InShutdownNego,
        /// [Token] associated with `acceptor`.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint, for incoming sessions.
        accept_tokens: HashMap<Types::InEndpoint, Token>,
        /// Session information for each endpoint, for outgoing sessions.
        conn_tokens: HashMap<Types::OutEndpoint, Token>,
        /// Negotiation states corresponding to each [Token].
        ///
        /// Each `Token` in this table must have exactly one entry in
        /// either `accept_tokens` or `conn_tokens`.
        negos: HashMap<
            Token,
            DuplexValue<
                Option<SessionNegoState<Types::Inbound>>,
                ConnectorEntry<Types::Outbound>
            >
        >
    },
    /// Outbound-only channels, which can only establish connections.
    Outbound {
        /// Base configuration used to create connectors.
        config: Types::OutConfig,
        /// [SessionAuthN] used to authenticate sessions.
        authn: Types::OutAuthN,
        /// Session information for each endpoint.
        tokens: HashMap<Types::OutEndpoint, Token>,
        /// Negotiation states corresponding to each [Token].
        ///
        /// Each `Token` in this table must have exactly one entry in
        /// `tokens`.
        negos: HashMap<Token, ConnectorEntry<Types::Outbound>>,
    },
    /// Inbound-only channels, which can only listen for connections.
    Inbound {
        /// [SessionAuthN] used to authenticate sessions.
        authn: Types::InAuthN,
        /// Acceptor for incoming sessions.
        acceptor: Types::InChannel,
        /// [Negotiator] used to shut down sessions.
        shutdown: Types::InShutdownNego,
        /// Token for acceptor.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint.
        tokens: HashMap<Types::InEndpoint, Token>,
        /// Negotiation states corresponding to each [Token].
        ///
        /// Each `Token` in this table must have exactly one entry in
        /// `tokens`.
        negos: HashMap<Token, Option<SessionNegoState<Types::Inbound>>>
    }
}

/// Information about a given logical channel configuration.
///
/// Unlike [FarChannel](crate::far::FarChannel)s, [NearChannel]s have
/// differing incoming and outgoing types.  This means that incoming
/// and outgoing channels are managed separately, and are only
/// associated together logically.
///
/// There are three configurations that a given logical channel may take:
///
/// - **Duplex**: Both incoming and outgoing sessions.  In a duplex
///   channel, an incoming and outgoing connection to the same
///   principal will be considered equivalent for the purposes of
///   deduplication.
///
/// - **Accept-only**: Only incoming sessions.
///
/// - **Connect-only**: Only outgoing sessions.
///
/// Since the endpoints for all incoming sessions will be unique
/// (unique port numbers will be assigned to TCP-type connections,
/// which will differ from the port to which outgoing sessions
/// connect), we cannot deduplicate sessions based on endpoints.  The
/// only correct way to deduplicate sessions is through
/// principals. However, we do also need to associate sessions with
/// the same logical channel ID, so that incoming and outgoing
/// sessions can be deduplicated in this fashion.
pub(crate) struct ChannelEntry<Types>
where
    Types: NearDuplexNegoTypes
{
    /// The per-mode channel state.
    mode: ChannelMode<Types>,
    /// Retry configuration to use.
    retry: Retry,
}

pub struct NearChannels<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Map from names to `NearChannelID`s.
    ids: HashMap<String, NearChannelID>,
    tokens: HashMap<Token, NearChannelID>,
    /// Reverse map from `NearChannelID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Types>>
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



impl<Types> SessionNegoState<Types>
where
    Types: NearSessionNegoTypes
{
    /// Create a new `SessionNegoState`.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of failing to create the `SessionNegoState` due
    /// to authentication failures.  If they succeed, then the
    /// authenticated session will be returned as well.  If they fail,
    /// then the session will be shut down, and retried later.
    /// Regardless, the `SessionNegoState` will be returned.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
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
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego,
        state: Types::ConnState,
    ) -> Result<
        Option<(Self, Option<Types::AuthNSession>)>,
        SessionEntryCreateError<
            NegoEntrySessionError<
                Types::SessionNegoError,
                SessionEntryAuthNError<Types::AuthStartError,
                                       Types::AuthNegoError>
            >,
            ShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
            >
        >
    > {
        match SessionNegoState::session(channel, authn, state) {
            Ok(NegotiatorResult::Complete((AuthNResult::Accept((out, session)),
                                           endpoint))) => {
                let session: Types::AuthNSession = session;

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

    /// Attempt to negotiate a new session and create a `SessionNegoState`.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of failing to create the `SessionNegoState` due
    /// to authentication failures.  If they succeed, then the
    /// authenticated session will be returned as well.
    ///
    /// This will not initiate shutdown if authentication fails.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
    ///
    /// - `state`: The initial state to use for session negotiations.
    ///
    /// # Return Values
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Accept((self,
    ///   session)))`: Negotiations were completed and authentication
    ///   succeeded.
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Reject(conn))`:
    ///   Negotiations were completed and authentication failed.
    ///
    /// - `NegotiatorResult::Pending(self)`: Negotiations are still
    ///   pending.
    fn session(
        channel: &Types::Channel,
        authn: &Types::AuthN,
        state: Types::ConnState,
    ) -> Result<
        NegotiatorResult<
            (AuthNResult<(Self, Types::AuthNSession), Types::Conn>,
             Types::Endpoint),
            Self
        >,
        NegoEntrySessionError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError,
                                   Types::AuthNegoError>
        >
    > {
        channel.negotiate(state)
            .map_err(|err| NegoEntrySessionError::Nego { err: err })?
            .map_pending(|pending| SessionNegoState::Session {
                pending: pending
            })
            .flat_map_ok(|(stream, endpoint)|
                         Self::authn(authn, endpoint.clone(), stream)
                         .map(|res| res.map(|res| (res, endpoint)))
                         .map_err(|err| NegoEntrySessionError::AuthN {
                             err: err
                         }))
    }

    /// Attempt to authenticate session and create a
    /// `SessionNegoState`.
    ///
    /// This will advance authentication negotiations as far as they
    /// can go, possibly to the point of failing to create the
    /// `SessionNegoState` due to authentication failures.  If they
    /// succeed, then the authenticated session will be returned as
    /// well.
    ///
    /// This will not initiate shutdown if authentication fails.
    ///
    /// # Parameters
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `endpoint`: The counterparty's address.
    ///
    /// - `state`: The initial state to use for session negotiations.
    ///
    /// # Return Values
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Accept((self,
    ///   session)))`: Negotiations were completed and authentication
    ///   succeeded.
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Reject(conn))`:
    ///   Negotiations were completed and authentication failed.
    ///
    /// - `NegotiatorResult::Pending(self)`: Negotiations are still
    ///   pending.
    fn authn(
        authn: &Types::AuthN,
        endpoint: Types::Endpoint,
        stream: Types::Conn
    ) -> Result<
        NegotiatorResult<
            AuthNResult<(Self, Types::AuthNSession), Types::Conn>,
            Self
        >,
        SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>
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

               SessionNegoState::AuthN {
                   endpoint: endpoint.clone(),
                   pending: pending
               }
           })
           .map(|res| {
               debug!(target: "session-nego-entry",
                      "completed session authentication over {}",
                      endpoint);

               res.map(|session| (SessionNegoState::Active {
                   endpoint: endpoint
               }, session))
           }))
    }

    /// Consume this `SessionNegoState` and step negotiations forward.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of completion.  It will create a new
    /// `SessionNegoState` if the session is still going.
    ///
    /// # Parameters
    ///
    /// - `endpoints`: A [HashSet] into which the endpoints for any
    ///   active sessions will be placed.
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
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
        endpoints: &mut HashSet<Types::Endpoint>,
        registry: &Registry,
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego,
    ) -> Result<
        Option<(Self, Option<Types::AuthNSession>)>,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError,
                                   Types::AuthNegoError>,
            ShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
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
                      "shut down session with {}",
                      endpoint);

                Ok(None)
            }
            Ok(NegotiatorResult::Pending(pending)) => {
                debug!(target: "session-nego-entry",
                       "continuing session negotiations");

                Ok(Some((pending, None)))
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
    /// This will consume the `SessionNegoState` and attempt shutdown
    /// negotiations.  If negotiations cannot be concluded
    /// immediately, a new `SessionNegoState` representing the pending
    /// negotiations will be returned.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutdown.
    ///
    /// - `param`: The parameter to use to begin the shutdown.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// - `Some(self)` if shutdown negotiations are still pending.
    ///
    /// - `None` if the session was shut down successfully.
    fn shutdown(
        self,
        registry: &Registry,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        stream: Types::Conn,
    ) -> Result<
        Option<Self>,
        SessionEntryShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError,
        >
    > {
        if let SessionNegoState::Active { endpoint } = self {
            let res = SessionNegoState::do_shutdown(shutdown, param,
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

    fn do_shutdown(
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        endpoint: Types::Endpoint,
        stream: Types::Conn,
    ) -> Result<
        NegotiatorResult<Types::ShutdownValue, Self>,
        ShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError,
        >
    > {
        let state = shutdown.start(param, stream)
            .map_err(|err| ShutdownError::Start { err: err })?;

        Ok(shutdown.negotiate(state)
           .map_err(|err| ShutdownError::Negotiate {
               err: err
           })?
           .map_pending(|pending| SessionNegoState::Shutdown {
               endpoint: endpoint,
               pending: pending
           }))
    }

    fn do_step(
        self,
        endpoints: &mut HashSet<Types::Endpoint>,
        registry: &Registry,
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego,
    ) -> Result<
        NegotiatorResult<
            (Option<AuthNResult<(Self, Types::AuthNSession), Types::Conn>>,
             Types::Endpoint),
            Self
        >,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>,
            Types::ShutdownNegoError
        >
    > {
        match self {
            SessionNegoState::Session { pending } => channel
                .complete_negotiate(pending)
                .map_err(|err| SessionEntryStepError::Session { err: err })?
                .map_pending(|pending| SessionNegoState::Session {
                    pending: pending
                })
                .flat_map_ok(|(stream, endpoint)|
                             Self::authn(authn, endpoint.clone(), stream)
                             .map(|res| res.map(|res| (Some(res), endpoint)))
                             .map_err(|err| SessionEntryStepError::AuthN {
                                 err: err
                             })),
            SessionNegoState::AuthN { pending, endpoint } =>
                Ok(authn
                   .complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::AuthN {
                       err: SessionEntryAuthNError::AuthN {
                           err: err
                       }
                   })?
                   .map_pending(|pending| SessionNegoState::AuthN {
                       endpoint: endpoint.clone(),
                       pending: pending
                   })
                   .map(|res| (Some(res.map(|session|
                                            (SessionNegoState::Active {
                                                endpoint: endpoint.clone()
                                            }, session))),
                                    endpoint))),
            SessionNegoState::Active { endpoint } => {
                endpoints.insert(endpoint.clone());

                Ok(NegotiatorResult::Pending(SessionNegoState::Active {
                    endpoint: endpoint
                }))
            }
            SessionNegoState::Shutdown { pending, endpoint } =>
                shutdown.complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::Shutdown { err: err })?
                   .map_pending(|pending| SessionNegoState::Shutdown {
                       endpoint: endpoint.clone(),
                       pending: pending
                   })
                   .map_ok(|mut val| {
                       info!(target: "session-nego-entry",
                             "shut down session with {}",
                             endpoint);

                       val.deregister(registry)
                           .map_err(|err| SessionEntryStepError::IO {
                               err: err
                           })?;

                       Ok((None, endpoint))
                   })
        }
    }

    fn handle_shutdown_result<Addr>(
        registry: &Registry,
        res: NegotiatorResult<Types::ShutdownValue, Self>,
        endpoint: Addr
    ) -> Result<Option<Self>, std::io::Error>
    where Addr: Display {
        match res {
            NegotiatorResult::Complete(mut val) => {
                info!(target: "session-nego-entry",
                      "shutdown session with {}",
                      endpoint);

                val.deregister(registry)?;

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
}

impl<Types> ConnectorEntry<Types>
where
    Types: NearSessionNegoTypes,
    Types::Channel: NearConnector
{
    /// Create a new `ConnectorEntry`.
    ///
    /// This will attempt to negotiate and authenticate a new session.
    /// If negotiations succeed immediately, then the authenticated
    /// session will be returned immediately as well.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `retry`: The [Retry] configuration to use if negotiations fail.
    ///
    /// - `token`: The [Token] associated with this `ConnectorEntry`.
    ///
    /// # Return Values
    ///
    /// - `RetryResult::Success((self, Some(session)))`: If a session
    ///   was successfully negotiated.
    ///
    /// - `RetryResult::Success((self, None))`: If negotiations could
    ///   not be concluded, or concluded but did not yield a session.
    fn create(
        registry: &Registry,
        mut channel: Types::Channel,
        authn: &Types::AuthN,
        retry: &Retry,
        token: Token
    ) -> Result<
        RetryResult<(Self, Option<Types::AuthNSession>)>,
        ConnectorEntryCreateError<
            Types::SessionStartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Types::SessionNegoError,
                    SessionEntryAuthNError<Types::AuthStartError,
                                           Types::AuthNegoError>
                >,
                SessionEntryShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >
        >
    > {
        trace!(target: "connector-entry",
               "creating connector entry with {}",
               channel.endpoint());

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

    /// Listen for input and step negotiations forward as far as
    /// possible.
    ///
    /// This will advance negotiations as far as they can go, possibly
    /// to the point of completion.  It will create a new
    /// `SessionNegoState` if the session is still going.
    ///
    /// If the session was already active, the counterparty address
    /// will be added to `endpoints`.
    ///
    /// # Parameters
    ///
    /// - `endpoints`: A [HashSet] into which the endpoints for any
    ///   active sessions will be placed.
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `retry`: The [Retry] configuration to use if negotiations fail.
    ///
    /// - `token`: The [Token] associated with this `ConnectorEntry`.
    ///
    /// # Return Values
    ///
    /// - `RetryResult::Success(Some(session))`: If a session
    ///   was successfully negotiated.
    ///
    /// - `RetryResult::Success(None)`: If negotiations could not be
    ///   concluded, or concluded but did not yield a session, or the
    ///   session was already active.
    fn step(
        &mut self,
        endpoints: &mut HashSet<Types::Endpoint>,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        token: Token
    ) -> Result<
        RetryResult<Option<Types::AuthNSession>>,
        ConnectorEntryStepError<
            Types::SessionStartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Types::SessionNegoError,
                    SessionEntryAuthNError<Types::AuthStartError,
                                           Types::AuthNegoError>
                >,
                SessionEntryShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >,
            SessionEntryStepError<
                Types::SessionNegoError,
                SessionEntryAuthNError<Types::AuthStartError,
                                       Types::AuthNegoError>,
                SessionEntryShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >
        >
    > {
        let state = self.state.take();

        trace!(target: "connector-entry",
               "stepping negotiations with {}",
               self.channel.endpoint());

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

    /// Shut down an active session.
    ///
    /// This will attempt to run shutdown negotiations as far as
    /// possible.  It will return a `bool` indicating whether the
    /// shutdown was completed.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// - `true`: Shutdown negotiations are finished.
    ///
    /// - `false`: Shutdown negotiations are still pending.
    fn shutdown(
        &mut self,
        registry: &Registry,
        stream: Types::Conn,
    ) -> Result<
        bool,
        SessionEntryShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    > {
        trace!(target: "connector-entry",
               "shutting down connector entry with {}",
               self.channel.endpoint());

        let state = self.state.take()
            .ok_or(SessionEntryShutdownError::NotActive)?;
        let newstate = state
            .shutdown(registry, &self.shutdown, &self.channel.shutdown_param(),
                      stream)?;
        let out = newstate.is_none();

        self.state = newstate;

        Ok(out)
    }

    // XXX Get rid of this variant if possible.
    fn do_shutdown(
        &mut self,
        registry: &Registry,
        endpoint: Types::Endpoint,
        stream: Types::Conn,
    ) -> Result<
        (),
        SessionEntryShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    > {
        let res = SessionNegoState::do_shutdown(&self.shutdown,
                                                &self.channel.shutdown_param(),
                                                endpoint.clone(), stream)
            .map_err(|err| SessionEntryShutdownError::Shutdown { err: err })?;

        self.state = SessionNegoState::handle_shutdown_result(registry, res,
                                                              endpoint)
            .map_err(|err| SessionEntryShutdownError::IO { err: err })?;

        Ok(())
    }

    fn do_connect(
        &mut self,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        state: Types::ConnState,
    ) -> Result<
        Option<Types::AuthNSession>,
        SessionCreateError<
            NegoEntrySessionError<
                Types::SessionNegoError,
                SessionEntryAuthNError<Types::AuthStartError,
                                       Types::AuthNegoError>,
            >,
            SessionEntryShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
            >
        >
    > {
        match SessionNegoState::session(&self.channel, authn, state) {
            Ok(NegotiatorResult::Complete((AuthNResult::Accept((out, session)),
                                           endpoint))) => {
                let session: Types::AuthNSession = session;

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
                debug!(target: "connector-entry",
                      "continuing session negotiations with {}",
                      self.channel.endpoint());

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
        endpoints: &mut HashSet<Types::Endpoint>,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        state: SessionNegoState<Types>
    ) -> Result<
        Option<Types::AuthNSession>,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError,
                                   Types::AuthNegoError>,
            SessionEntryShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
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
                debug!(target: "connector-entry",
                      "continuing session negotiations with");

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

impl<Types> ChannelEntry<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Create a `ChannelEntry` for outbound connections only.
    ///
    /// Calls to [listen](ChannelEntry::listen) on this `ChannelEntry`
    /// will only complete pending session negotiations; it will not
    /// generate incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `config`: Base configuration for outbound channels.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration for retrying connections.
    pub(crate) fn outbound(
        config: Types::OutConfig,
        authn: Types::OutAuthN,
        retry: Retry
    ) -> Self {
        let tokens = HashMap::new();
        let negos = HashMap::new();
        let mode = ChannelMode::Outbound {
            config: config,
            authn: authn,
            tokens: tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Create a `ChannelEntry` for outbound connections only with a
    /// size hint.
    ///
    /// Calls to [listen](ChannelEntry::listen) on this `ChannelEntry`
    /// will only complete pending session negotiations; it will not
    /// generate incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `config`: Base configuration for outbound channels.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration for retrying connections.
    ///
    /// - `size`: Expected maximum number of sessions; this will not
    ///   cause an errer if it is too low.
    pub(crate) fn outbound_with_capacity(
        config: Types::OutConfig,
        authn: Types::OutAuthN,
        retry: Retry,
        size: usize
    ) -> Self {
        let tokens = HashMap::with_capacity(size);
        let negos = HashMap::with_capacity(size);
        let mode = ChannelMode::Outbound {
            config: config,
            authn: authn,
            tokens: tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Create a `ChannelEntry` for inbound connections only.
    ///
    /// Calls to [req_stream](ChannelEntry::req_stream) on this
    /// `ChannelEntry` will fail, and [listen](ChannelEntry::listen)
    /// will only produce incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening
    ///   for new sessions.
    pub(crate) fn inbound(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        retry: Retry,
        token: Token
    ) -> Self {
        let tokens = HashMap::new();
        let negos = HashMap::new();
        let shutdown = acceptor.shutdown_nego();
        let mode = ChannelMode::Inbound {
            acceptor: acceptor,
            shutdown: shutdown,
            authn: authn,
            token: token,
            retry_when: None,
            tokens: tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Create a `ChannelEntry` for inbound connections only, with a
    /// size hint.
    ///
    /// Calls to [req_stream](ChannelEntry::req_stream) on this
    /// `ChannelEntry` will fail, and [listen](ChannelEntry::listen)
    /// will only produce incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening
    ///   for new sessions.
    ///
    /// - `size`: Expected maximum number of sessions; this will not
    ///   cause an errer if it is too low.
    pub(crate) fn inbound_with_capacity(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        retry: Retry,
        token: Token,
        size: usize
    ) -> Self {
        let tokens = HashMap::with_capacity(size);
        let negos = HashMap::with_capacity(size);
        let shutdown = acceptor.shutdown_nego();
        let mode = ChannelMode::Inbound {
            acceptor: acceptor,
            shutdown: shutdown,
            authn: authn,
            token: token,
            retry_when: None,
            tokens: tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Create a `ChannelEntry` for both inbound and outbound
    /// connections.
    ///
    /// # Parameters
    ///
    /// - `out_config`: Base configuration for outbound channels.
    ///
    /// - `out_authn`: [SessionAuthN] to use for authenticating
    ///   outbound sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound
    ///   sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening
    ///   for new sessions.
    pub(crate) fn duplex(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        retry: Retry,
        token: Token,
    ) -> Self {
        let out_tokens = HashMap::new();
        let in_tokens = HashMap::new();
        let negos = HashMap::new();
        let in_shutdown = acceptor.shutdown_nego();
        let mode = ChannelMode::Duplex {
            config: out_config,
            out_authn: out_authn,
            in_authn: in_authn,
            shutdown: in_shutdown,
            acceptor: acceptor,
            token: token,
            retry_when: None,
            accept_tokens: in_tokens,
            conn_tokens: out_tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Create a `ChannelEntry` for both inbound and outbound
    /// connections, with a size hint.
    ///
    /// # Parameters
    ///
    /// - `out_config`: Base configuration for outbound channels.
    ///
    /// - `out_authn`: [SessionAuthN] to use for authenticating
    ///   outbound sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound
    ///   sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening
    ///   for new sessions.
    ///
    /// - `nins`: Expected maximum number of inbound sessions; this
    ///   will not cause an errer if it is too low.
    ///
    /// - `nouts`: Expected maximum number of outbound sessions; this
    ///   will not cause an errer if it is too low.
    pub(crate) fn duplex_with_capacity(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        retry: Retry,
        token: Token,
        nins: usize,
        nouts: usize,
    ) -> Self {
        let out_tokens = HashMap::with_capacity(nouts);
        let in_tokens = HashMap::with_capacity(nins);
        let negos = HashMap::with_capacity(nins + nouts);
        let in_shutdown = acceptor.shutdown_nego();
        let mode = ChannelMode::Duplex {
            config: out_config,
            out_authn: out_authn,
            in_authn: in_authn,
            shutdown: in_shutdown,
            acceptor: acceptor,
            token: token,
            retry_when: None,
            accept_tokens: in_tokens,
            conn_tokens: out_tokens,
            negos: negos
        };

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Check if this `ChannelEntry` contains any active sessions.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        match &self.mode {
            ChannelMode::Duplex {
                accept_tokens, conn_tokens, negos, ..
            } => match (accept_tokens.is_empty(), conn_tokens.is_empty(),
                        negos.is_empty()) {
                (true, true, true)  => true,
                (false, false, _) | (false, _, false) => false,
                _ => {
                    error!(target: "channel-entry",
                           "inconsistent token and negotiation tables");

                    false
                }
            },
            ChannelMode::Outbound {
                tokens, negos, ..
            } => match (tokens.is_empty(), negos.is_empty()) {
                (true, true) => true,
                (false, false) => false,
                _ => {
                    error!(target: "channel-entry",
                           "inconsistent token and negotiation tables");

                    false
                }
            },
            ChannelMode::Inbound {
                tokens, negos, ..
            } => match (tokens.is_empty(), negos.is_empty()) {
                (true, true) => true,
                (false, false) => false,
                _ => {
                    error!(target: "channel-entry",
                           "inconsistent token and negotiation tables");

                    false
                }
            }
        }
    }

    /// Request a stream for a given endpoint.
    ///
    /// This will attempt to negotiate and authenticate a session with
    /// the given endpoint.  If negotiations can be concluded
    /// immediately, then the authenticated session will be returned.
    /// Otherwise, the request will remain active and will eventually
    /// be returned by [listen](ChannelEntry::listen).  Subsequent calls
    /// to this function with the same `endpoint` will return an
    /// error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_conn](FlowsEntry::shutdown_conn)
    /// to properly handle shutdown negotiations and cleanup.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution
    ///   caches.
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `gentok`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to register nonblocking I/O.
    ///
    /// - `endpoint`: Counterparty's address.
    ///
    /// - `verify_endpoint`: Override to use for SSL verification.
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success(Some(session))`: The session was fully
    ///   negotiated.
    ///
    /// - `RetryResult::Success(None))`: Session negotiations are
    ///   still pending and the session will eventually be reported by
    ///   [listen](ChannelEntry::listen).
    pub(crate) fn req_stream<Ctx, I>(
        &mut self,
        ctx: &mut Ctx,
        gentok: &mut Peekable<I>,
        registry: &Registry,
        endpoint: Types::OutEndpoint,
        param: Types::OutParam
    ) -> Result<
        RetryResult<(Token, Option<Types::OutAuthNSession>)>,
        ChannelEntryReqError<
            Types::OutCreateError,
            ConnectorEntryCreateError<
                Types::OutSessionStartError,
                SessionCreateError<
                    NegoEntrySessionError<
                        Types::OutSessionNegoError,
                        SessionEntryAuthNError<Types::OutAuthStartError,
                                               Types::OutAuthNegoError>
                    >,
                    SessionEntryShutdownError<
                        Types::OutShutdownStartError,
                        Types::OutShutdownNegoError,
                    >
                >
            >
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx
    {
        debug!(target: "channel-entry",
               "requesting flow with {}",
               endpoint);

        match &mut self.mode {
            ChannelMode::Duplex {
                config, conn_tokens, negos, out_authn, ..
            } => if !conn_tokens.contains_key(&endpoint) {
                trace!(target: "channel-entry",
                       "creating outbound channel to {}",
                       endpoint);

                let token = *gentok.peek()
                    .ok_or(ChannelEntryReqError::NoTokens)?;
                let conn = Types::OutChannel
                    ::create_with_endpoint(ctx, config.clone(),
                                           endpoint.clone(), param)
                    .map_err(|err| ChannelEntryReqError::Channel { err: err })?;

                trace!(target: "channel-entry",
                       "creating connector entry for {}, token {:?}",
                       endpoint, token);

                Ok(ConnectorEntry::create(registry, conn, out_authn,
                                          &self.retry, token)
                   .map_err(|err| ChannelEntryReqError::Entry { err: err })?
                   .map(|(ent, out)| {
                       let ent = DuplexValue::Conn(ent);
                       let _ = gentok.next();

                       trace!(target: "channel-entry",
                              "connector entry created for {}",
                              endpoint);

                       if conn_tokens.insert(endpoint, token).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       if negos.insert(token, ent).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       (token, out)
                   }))
            } else {
                Err(ChannelEntryReqError::Collision)
            }
            ChannelMode::Outbound {
                config, tokens, negos, authn, ..
            } => if !tokens.contains_key(&endpoint) {
                trace!(target: "channel-entry",
                       "creating outbound channel to {}",
                       endpoint);

                let token = *gentok.peek()
                    .ok_or(ChannelEntryReqError::NoTokens)?;
                let conn = Types::OutChannel
                    ::create_with_endpoint(ctx, config.clone(),
                                           endpoint.clone(), param)
                    .map_err(|err| ChannelEntryReqError::Channel { err: err })?;

                trace!(target: "channel-entry",
                       "creating connector entry for {}, token {:?}",
                       endpoint, token);

                Ok(ConnectorEntry::create(registry, conn, authn,
                                          &self.retry, token)
                   .map_err(|err| ChannelEntryReqError::Entry { err: err })?
                   .map(|(ent, out)| {
                       let _ = gentok.next();

                       trace!(target: "channel-entry",
                              "connector entry created for {}",
                              endpoint);

                       if tokens.insert(endpoint, token).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       if negos.insert(token, ent).is_some() {
                           error!(target: "channel-entry",
                                  "tokens table should not contain an entry");
                       }

                       (token, out)
                   }))
            } else {
                Err(ChannelEntryReqError::Collision)
            }
            ChannelMode::Inbound { .. } => Err(ChannelEntryReqError::Inbound)
        }
    }

    /// Listen for incoming traffic and new sessions for this channel.
    ///
    /// This will fully exhaust all incoming traffic corresponding to
    /// any [Token] in `tokens`.  All pending negotiations will be
    /// updated, and any new sessions will be reported.  If any new
    /// connections are found, then negotiations will begin for them.
    ///
    /// New authenticated sessions will be reported in `in_sessions`
    /// and `out_sessions`.  Traffic on existing active sessions will
    /// be reported in `in_endpoints` and `out_endpoints`.  Any
    /// sessions that are shut down will be unregistered.
    ///
    /// # Type Parameters
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `gentok`: Generator for [Token]s.
    ///
    /// - `out_sessions`: Buffer for new authenticated outbound sessions.
    ///
    /// - `in_sessions`: Buffer for new authenticated inbound sessions.
    ///
    /// - `out_endpoints`: Set of all active outbound sessions that
    ///   have pending traffic.
    ///
    /// - `in_endpoints`: Set of all active inbound sessions that have
    ///   pending traffic.
    ///
    /// - `registry`: [Registry] to use to register nonblocking I/O.
    ///
    /// - `live`: All [Token]s that have pending read traffic.
    fn listen<I>(
        &mut self,
        gentok: &mut Peekable<I>,
        out_sessions: &mut Vec<Types::OutAuthNSession>,
        in_sessions: &mut Vec<Types::InAuthNSession>,
        out_endpoints: &mut HashSet<Types::OutEndpoint>,
        in_endpoints: &mut HashSet<Types::InEndpoint>,
        registry: &Registry,
        live: &HashSet<Token>,
    ) -> Result<
        (),
        ChannelEntryListenError<Types::InSessionStartError>
    >
    where
        I: Iterator<Item = Token>
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
                        DuplexValue::Conn(ent) => if ent
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
                        DuplexValue::Accept(ent) => if live.contains(token) {
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
                for token in deletes.iter() {
                    if negos.remove(token).is_none() {
                        error!(target: "channel-entry",
                               "deleted token {:?} was not present",
                               token);
                    }
                }

                // Add the incoming sessions if we have them.
                if let Some(incoming) = incoming {
                    for (token, ent) in incoming {
                        let endpoint: Option<&Types::InEndpoint> =
                            match &ent {
                                SessionNegoState::AuthN { endpoint, .. } |
                                SessionNegoState::Active { endpoint } |
                                SessionNegoState::Shutdown {
                                    endpoint, ..
                                } => Some(endpoint),
                                SessionNegoState::Session { .. } => None
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

                        let ent = DuplexValue::Accept(Some(ent));

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
                    Self::start_incoming(gentok, in_sessions,
                                         retry_when, &mut read,
                                         registry, acceptor,
                                         shutdown, authn)?
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
                        let endpoint: Option<&Types::InEndpoint> =
                            match &ent {
                                SessionNegoState::AuthN { endpoint, .. } |
                                SessionNegoState::Active { endpoint } |
                                SessionNegoState::Shutdown {
                                    endpoint, ..
                                } => Some(endpoint),
                                SessionNegoState::Session { .. } => None
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

    /// Shut down an outbound (connected) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    fn shutdown_conn(
        &mut self,
        registry: &Registry,
        stream: Types::OutConn,
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            SessionEntryShutdownError<
                Types::OutShutdownStartError,
                Types::OutShutdownNegoError,
            >,
            Types::OutEndpoint
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
                if let DuplexValue::Conn(conn) = negos
                    .get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)? {
                    let delete = conn.shutdown(registry, stream)
                        .map_err(|err| ChannelEntryShutdownError::Shutdown {
                            err: err
                        })?;

                    if delete {
                        let token = *ent.get();

                        if negos.remove(&token).is_none() {
                            error!(target: "connector-entry",
                                   "entry for token {:?} missing",
                                   ent.get());
                        }

                        ent.remove();

                        Ok(Some(token))
                    } else {
                        Ok(None)
                    }
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
                    let token = *ent.get();

                    if negos.remove(&token).is_none() {
                        error!(target: "connector-entry",
                               "entry for token {:?} missing",
                               ent.get());
                    }

                    ent.remove();

                    Ok(Some(token))
                } else {
                    Ok(None)
                }
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Inbound { .. } =>
                Err(ChannelEntryShutdownError::Mismatch)
        }
    }

    /// Shut down an inbound (accepted) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down
    ///   sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    fn shutdown_accept(
        &mut self,
        registry: &Registry,
        stream: Types::InConn,
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            SessionEntryShutdownError<
                Types::InShutdownStartError,
                Types::InShutdownNegoError,
            >,
            Types::InEndpoint
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
                if let DuplexValue::Accept(accept) = negos
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
                        *accept = newaccept;

                        Ok(None)
                    } else {
                        let token = *ent.get();

                        if negos.remove(&token).is_none() {
                            error!(target: "connector-entry",
                                   "entry for token {:?} missing",
                                   ent.get());
                        }

                        ent.remove();

                        Ok(Some(token))
                    }
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
                    *accept = newaccept;

                    Ok(None)
                } else {
                    let token = *ent.get();

                    if negos.remove(&token).is_none() {
                        error!(target: "connector-entry",
                               "entry for token {:?} missing",
                               ent.get());
                    }

                    ent.remove();

                    Ok(Some(token))
                }
            } else {
                Err(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint
                })
            }
            ChannelMode::Outbound { .. } =>
                Err(ChannelEntryShutdownError::Mismatch)
        }
    }

    fn start_incoming<I>(
        gentok: &mut Peekable<I>,
        sessions: &mut Vec<Types::InAuthNSession>,
        when: &mut Option<Instant>,
        read: &mut bool,
        registry: &Registry,
        accept: &mut Types::InChannel,
        shutdown: &Types::InShutdownNego,
        authn: &Types::InAuthN,
    ) -> Result<
        Option<Vec<(Token, SessionNegoState<Types::Inbound>)>>,
        ChannelEntryListenError<Types::InSessionStartError>
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
                match SessionNegoState::create(registry, accept, authn,
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
}

impl<Accept, Conn> Read for DuplexValue<Accept, Conn>
where Conn: Read,
      Accept: Read {
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read(buf),
            DuplexValue::Accept(accept) => accept.read(buf),
        }
    }

    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read_vectored(buf),
            DuplexValue::Accept(accept) => accept.read_vectored(buf),
        }
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read_exact(buf),
            DuplexValue::Accept(accept) => accept.read_exact(buf),
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
            DuplexValue::Conn(conn) => conn.write(buf),
            DuplexValue::Accept(accept) => accept.write(buf),
        }
    }

    fn flush(
        &mut self,
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.flush(),
            DuplexValue::Accept(accept) => accept.flush()
        }
    }

    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.write_vectored(buf),
            DuplexValue::Accept(accept) => accept.write_vectored(buf),
        }
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.write_all(buf),
            DuplexValue::Accept(accept) => accept.write_all(buf),
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

#[cfg(test)]
use std::convert::TryFrom;
#[cfg(test)]
use std::iter::once;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::thread::spawn;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use constellation_auth::authn::TrivialAuthN;
#[cfg(test)]
use constellation_common::unix::UnixSocketAddr;
#[cfg(test)]
use mio::Events;
#[cfg(test)]
use mio::Interest;
#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::config::CompoundNearAcceptorConfig;
#[cfg(test)]
use crate::config::CompoundNearConnectorParam;
#[cfg(test)]
use crate::config::CompoundNearConnectorPartialConfig;
#[cfg(test)]
use crate::config::tls::TLSClientConfig;
#[cfg(test)]
use crate::config::tls::TLSServerConfig;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::write_one;
#[cfg(test)]
use crate::near::compound::CompoundNearAcceptor;
#[cfg(test)]
use crate::near::compound::CompoundNearClientConn;
#[cfg(test)]
use crate::near::compound::CompoundNearCredential;
#[cfg(test)]
use crate::near::compound::CompoundNearNameAddr;
#[cfg(test)]
use crate::near::compound::CompoundNearServerConn;
#[cfg(test)]
use crate::near::types::SimpleNearDuplexNegoTypes;
#[cfg(test)]
use crate::near::types::CompoundAcceptorNegoTypes;
#[cfg(test)]
use crate::near::types::CompoundConnectorNegoTypes;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[cfg(test)]
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

#[cfg(test)]
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
struct TestPrin;

#[cfg(test)]
type TestAcceptorNegoTypes =
    CompoundAcceptorNegoTypes<TrivialAuthN<TestPrin, CompoundNearServerConn>,
                              TLSServerConfig>;

#[cfg(test)]
type TestConnectorNegoTypes =
    CompoundConnectorNegoTypes<TrivialAuthN<TestPrin, CompoundNearClientConn>,
                               TLSClientConfig>;

#[cfg(test)]
type TestDuplexNegoTypes = SimpleNearDuplexNegoTypes<TestAcceptorNegoTypes,
                                                     TestConnectorNegoTypes>;

#[cfg(test)]
impl From<CompoundNearCredential> for TestPrin {
    #[inline]
    fn from(_val: CompoundNearCredential) -> TestPrin {
        TestPrin
    }
}

#[cfg(test)]
impl Display for TestPrin {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "test principal")
    }
}

#[cfg(test)]
fn get_out_session<Types, Ctx>(
    ctx: &mut Ctx,
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    endpoint: Types::OutEndpoint,
    param: Types::OutParam,
    token: Token
) -> Types::OutAuthNSession
where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes,
{
    let mut gentok = once(token).peekable();

    match entry.req_stream(ctx, &mut gentok, poll.registry(), endpoint, param)
        .expect("Expected success") {
            RetryResult::Success((newtok, Some(out))) => {
                trace!(target: "get-in-session",
                       "got outbound session immediately");

                assert_eq!(newtok, token);

                out
            },
        RetryResult::Success((newtok, None)) => {
            let mut events = Events::with_capacity(2);
            let mut out_sessions = Vec::new();
            let mut in_sessions = Vec::new();
            let mut out_endpoints = HashSet::new();
            let mut in_endpoints = HashSet::new();
            let mut live = HashSet::new();
            let mut count = 0;

            assert_eq!(newtok, token);

            while out_sessions.is_empty() {
                trace!(target: "get-out-session",
                       "polling");

                if count > 5 {
                    panic!("Timeout")
                }

                poll.poll(&mut events, Some(Duration::from_secs(1)))
                    .expect("Expected success");

                count += 1;

                trace!(target: "get-out-session",
                       "polling returned");

                for event in events.iter() {
                    trace!(target: "get-out-session",
                           "event for token {:?}", event.token());

                    live.insert(event.token());
                }

                trace!(target: "get-out-session",
                       "listening");

                entry.listen(&mut gentok, &mut out_sessions, &mut in_sessions,
                             &mut out_endpoints, &mut in_endpoints,
                             poll.registry(), &live)
                    .expect("Expected success");

                live.clear();
            }

            trace!(target: "get-in-session",
                   "got outbound session");

            out_sessions.pop().expect("Expected some")
        }
        _ => panic!("Should not see retry delay here")
    }
}

#[cfg(test)]
fn get_in_session<Types>(
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    token: Token
) -> Types::InAuthNSession
where
    Types: NearDuplexNegoTypes,
{
    let mut gentok = vec![token, Token(7777)].into_iter().peekable();
    let mut events = Events::with_capacity(2);
    let mut out_sessions = Vec::new();
    let mut in_sessions = Vec::new();
    let mut out_endpoints = HashSet::new();
    let mut in_endpoints = HashSet::new();
    let mut live = HashSet::new();
    let mut count = 0;

    while in_sessions.is_empty() {
        trace!(target: "get-in-session",
               "polling");

        if count > 5 {
            panic!("Timeout")
        }

        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .expect("Expected success");

        count += 1;

        trace!(target: "get-in-session",
               "polling returned");

        for event in events.iter() {
            trace!(target: "get-in-session",
                   "event for token {:?}", event.token());

            live.insert(event.token());
        }

        trace!(target: "get-in-session",
               "listening");

        entry.listen(&mut gentok, &mut out_sessions, &mut in_sessions,
                     &mut out_endpoints, &mut in_endpoints, poll.registry(),
                     &live)
            .expect("Expected success");

        live.clear();
    }

    trace!(target: "get-in-session",
           "got inbound session");

    in_sessions.pop().expect("Expected some")
}
/*
#[cfg(test)]
fn shutdown_out_session<Types, Ctx>(
    ctx: &mut Ctx,
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    endpoint: Types::OutEndpoint,
    param: Types::OutParam,
    token: Token
) -> Types::OutAuthNSession
where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes,
{
}
*/
#[cfg(test)]
fn entry_test<Types, Ctx>(
    mut nscaches: Ctx,
    mut acceptor: Types::InChannel,
    out_config: Types::OutConfig,
    in_authn: Types::InAuthN,
    out_authn: Types::OutAuthN,
    endpoint: Types::OutEndpoint,
    param: Types::OutParam,
    listen: Token,
    in_session: Token,
    out_session: Token
)
where
    Ctx: 'static + NSNameCachesCtx + Send,
    Types: NearDuplexNegoTypes,
    Types::InChannel: 'static + Send,
    Types::InAuthN: 'static + Send,
    Types::OutConfig: 'static + Send,
    Types::OutAuthN: 'static + Send,
    Types::OutParam: 'static + Send,
    Types::OutEndpoint: 'static + Send
{
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");

        poll.registry().register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let mut entry: ChannelEntry<Types> =
            ChannelEntry::inbound(acceptor, in_authn,
                                  Retry::default(), listen);

        assert!(entry.is_empty());

        let mut session: Types::InAuthNSession =
            get_in_session(&mut entry, &mut poll, in_session);

        assert!(!entry.is_empty());

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(session.get_mut(), &mut poll, in_session, &mut buf)
            .expect("Expected success");

        write_one(session.get_mut(), &mut poll, in_session, &SECOND_BYTES)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let send = spawn(move || {
        let mut entry: ChannelEntry<Types> =
            ChannelEntry::outbound(out_config, out_authn, Retry::default());

        assert!(entry.is_empty());

        let mut poll = Poll::new().expect("Expected success");
        let mut session: Types::OutAuthNSession =
            get_out_session(&mut nscaches, &mut entry, &mut poll,
                            endpoint, param, out_session);

        assert!(!entry.is_empty());

        write_one(session.get_mut(), &mut poll, out_session, &FIRST_BYTES)
            .expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        read_one(session.get_mut(), &mut poll, out_session, &mut buf)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();

}

#[cfg(test)]
fn compound_entry_test(
    server_conf: &str,
    client_conf: &str,
    endpoint: CompoundNearNameAddr,
    param_conf: Option<&str>
) {
    init();

    let mut nscaches = SharedNSNameCaches::new();
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        serde_yaml::from_str(server_conf).unwrap();
    let param: Option<CompoundNearConnectorParam> =
        param_conf.map(|param_conf| serde_yaml::from_str(param_conf).unwrap());
    let client_conf: CompoundNearConnectorPartialConfig<TLSClientConfig> =
        serde_yaml::from_str(client_conf).unwrap();
    let acceptor =
        CompoundNearAcceptor::create(&mut nscaches, server_conf)
        .expect("Expected success");
    let listen = Token(0);
    let in_session = Token(1);
    let out_session = Token(0);

    entry_test::<TestDuplexNegoTypes, _>(
        nscaches, acceptor, client_conf, TrivialAuthN::default(),
        TrivialAuthN::default(), endpoint, param, listen,
        in_session, out_session
    )
}

#[test]
fn test_unix() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "unix-stream:\n",
        "  path: test_near_channels_unix.sock"
    );
    const CLIENT_CONF: &'static str = concat!(
        "unix-stream:"
    );
    let endpoint = CompoundNearNameAddr::Unix {
        unix: UnixSocketAddr::try_from("test_near_channels_unix.sock")
            .expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, None)
}

#[test]
fn test_tcp() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tcp:\n",
        "  addr: ::0\n",
        "  port: 8100\n"
    );
    const CLIENT_CONF: &'static str = concat!(
        "tcp:",
    );
    let endpoint = CompoundNearNameAddr::TCP {
        tcp: "[::0]:8100".parse()
            .expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, None)
}

#[test]
fn test_tls_unix() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  client-auth:\n",
        "    verify: required\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
        "  unix-stream:\n",
        "    path: test_near_channels_tls_unix.sock"
    );
    const CLIENT_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: test/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  unix-stream:",
    );
    const PARAM_CONF: &'static str = concat!(
        "tls:\n",
        "  verify-endpoint: test-server.nowhere.com",
    );
    let endpoint = CompoundNearNameAddr::Unix {
        unix: UnixSocketAddr::try_from("test_near_channels_tls_unix.sock")
            .expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, Some(PARAM_CONF))
}


#[test]
fn test_tls_tcp() {
    init();

    const SERVER_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  client-auth:\n",
        "    verify: required\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
        "  tcp:\n",
        "    addr: ::0\n",
        "    port: 8101\n"
    );
    const CLIENT_CONF: &'static str = concat!(
        "tls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: test/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  tcp:",
    );
    const PARAM_CONF: &'static str = concat!(
        "tls:\n",
        "  verify-endpoint: test-server.nowhere.com",
    );
    let endpoint = CompoundNearNameAddr::TCP {
        tcp: "[::0]:8101".parse()
            .expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, Some(PARAM_CONF))
}
