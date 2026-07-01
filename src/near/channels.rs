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

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::iter::FusedIterator;
use std::rc::Rc;
use std::time::Instant;
use std::vec::IntoIter;

use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_streams::channels::ChannelParam;
use constellation_streams::channels::Channels;
use constellation_streams::channels::ChannelsListen;
use constellation_streams::channels::ChannelsShutdown;
use constellation_streams::threads::RegistryCtx;
use constellation_streams::threads::TokensCtx;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use mio::event::Source;
use mio::Registry;
use mio::Token;

use crate::channels::ShutdownError;
use crate::config::NearChannelEntryConfig;
use crate::config::NearChannelsConfig;
use crate::near::types::NearDuplexNegoTypes;
use crate::near::types::NearSessionNegoTypes;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

/// Newtype wrapper for IDs created to refer to specific channels.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NearChannelID(usize);

/// Generic type used in duplex channels.
///
/// This is necessary as unlike [FarChannel](crate::far::FarChannel)s,
/// [NearChannel]s have distinct types for inbound and outbound
/// sessions.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DuplexValue<Accept, Conn> {
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
    Types: NearSessionNegoTypes {
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
        pending: Types::AuthNPending
    },
    Active {
        /// Endpoint for this session.
        endpoint: Types::Endpoint
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
    Types: NearSessionNegoTypes {
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
    Types: NearSessionNegoTypes {
    /// The [NearConnector] used to establish sessions.
    channel: Types::Channel,
    /// The request endpoint.
    ///
    /// This may differ from the session's endpoint.
    req_endpoint: Types::Endpoint,
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
    when: Option<Instant>,
    /// Whether to preserve this entry if state ever gets set to None.
    keepalive: bool
}

/// Full-duplex channels, which can establish outbound as well as
/// inbound connections.
struct DuplexChannelMode<Types>
where
    Types: NearDuplexNegoTypes {
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
    accept_tokens: HashMap<Types::Endpoint, Token>,
    /// Session information for each endpoint, for outgoing sessions.
    conn_tokens: HashMap<Types::Endpoint, Token>,
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
}

/// Outbound-only channels, which can only establish connections.
struct OutboundChannelMode<Types>
where
    Types: NearDuplexNegoTypes {
    /// Base configuration used to create connectors.
    config: Types::OutConfig,
    /// [SessionAuthN] used to authenticate sessions.
    authn: Types::OutAuthN,
    /// Session information for each endpoint.
    tokens: HashMap<Types::Endpoint, Token>,
    /// Negotiation states corresponding to each [Token].
    ///
    /// Each `Token` in this table must have exactly one entry in
    /// `tokens`.
    negos: HashMap<Token, ConnectorEntry<Types::Outbound>>
}

/// Inbound-only channels, which can only listen for connections.
struct InboundChannelMode<Types>
where
    Types: NearDuplexNegoTypes {
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
    tokens: HashMap<Types::Endpoint, Token>,
    /// Negotiation states corresponding to each [Token].
    ///
    /// Each `Token` in this table must have exactly one entry in
    /// `tokens`.
    negos: HashMap<Token, Option<SessionNegoState<Types::Inbound>>>
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
    Types: NearDuplexNegoTypes {
    /// Full-duplex channels, which can establish outbound as well as
    /// inbound connections.
    Duplex(DuplexChannelMode<Types>),
    /// Outbound-only channels, which can only establish connections.
    Outbound(OutboundChannelMode<Types>),
    /// Inbound-only channels, which can only listen for connections.
    Inbound(InboundChannelMode<Types>)
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
/// - **Duplex**: Both incoming and outgoing sessions.  In a duplex channel, an
///   incoming and outgoing connection to the same principal will be considered
///   equivalent for the purposes of deduplication.
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
    Types: NearDuplexNegoTypes {
    /// The per-mode channel state.
    mode: ChannelMode<Types>,
    /// Retry configuration to use.
    retry: Retry
}

pub struct NearChannels<Types>
where
    Types: NearDuplexNegoTypes {
    /// Map from names to `NearChannelID`s.
    ids: HashMap<String, NearChannelID>,
    /// Reverse map from `NearChannelID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Types>>,
    tokens: HashMap<Token, NearChannelID>
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NearChannelParam;

/// Result of a step.
enum StepResult<Session, Endpoint, Internal> {
    /// A new session was created.
    Create {
        /// The new session.
        session: Session
    },
    /// A session was shut down.
    Shutdown {
        /// The endpoint of the session that was shut down.
        endpoint: Endpoint
    },
    /// The step did not create or shut down a session.
    Internal { internal: Internal }
}

pub struct NearChannelsParamsIter<I>
where I: Iterator<Item = NearChannelID> {
    ids: I,
}

#[derive(Debug)]
pub enum NearChannelsEntryCreateError<Accept, AuthN> {
    Accept { err: Accept },
    AuthN { err: AuthN }
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
}

#[derive(Debug)]
pub enum SessionEntryStepError<Session, AuthN, Shutdown> {
    Session { err: Session },
    AuthN { err: AuthN },
    Shutdown { err: Shutdown },
    IO { err: std::io::Error }
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
    }
}

#[derive(Debug)]
pub enum NegoEntrySessionError<Nego, AuthN> {
    Nego { err: Nego },
    AuthN { err: AuthN }
}

#[derive(Debug)]
pub enum SessionEntryCreateError<Session, Shutdown> {
    Session { err: Session },
    Shutdown { err: Shutdown },
    IO { err: std::io::Error }
}

#[derive(Debug)]
pub enum SessionEntryShutdownError<Start, Shutdown> {
    Shutdown { err: ShutdownError<Start, Shutdown> },
    IO { err: std::io::Error },
    NotActive
}

#[derive(Debug)]
pub enum SessionCreateError<Session, Shutdown> {
    Session { err: Session },
    Shutdown { err: Shutdown },
    IO { err: std::io::Error }
}

#[derive(Debug)]
pub enum ConnectorEntryCreateError<Start, Nego> {
    Start { err: Start },
    Nego { err: Nego }
}

#[derive(Debug)]
pub enum ConnectorEntryStepError<Start, Connect, Step> {
    Start { err: Start },
    Connect { err: Connect },
    Step { err: Step }
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
    IO {
        err: std::io::Error
    },
    /// The given endpoint was already requested.
    Collision,
    /// Trying to request a stream from an inbound-only channel.
    Inbound
}

#[derive(Debug)]
pub enum ChannelEntryShutdownError<Shutdown, Endpoint> {
    /// An error occurred shutting down the channel.
    Shutdown {
        /// The error that occurred shutting down the channel.
        err: Shutdown
    },
    /// A low-level IO error occurred.
    IO {
        /// The low-level IO error that occurred.
        err: std::io::Error
    },
    /// No channel exists for the given endpoint.
    NotFound {
        /// The endpoint.
        endpoint: Endpoint
    },
    /// The channel was not exclusively owned.
    Nonexclusive,
    /// The negotiation state was not in a state that can be shut down.
    Inconsistent,
    /// The channel type does not match the stream type.
    Mismatch
}

/// Errors that can occur for a [ChannelEntry] when listening.
#[derive(Debug)]
pub enum ChannelEntryListenError<Start> {
    /// An error occurred starting a new session.
    Start {
        /// The error that occurred starting the session.
        err: Start
    },
    /// A low-level I/O error occurred.
    IO {
        /// The low-level I/O error.
        err: std::io::Error
    },
}

#[derive(Debug)]
pub enum ChannelEntryShutdownListenError<Start, Shutdown, Endpoint> {
    Listen {
        err: ChannelEntryListenError<Start>
    },
    Shutdown {
        err: ChannelEntryShutdownError<Shutdown, Endpoint>
    },
    Finish {
        errs: Vec<(NearChannelID, std::io::Error)>
    }
}

#[derive(Debug)]
pub enum NearChannelsCreateError<InAuth, OutAuth, Inbound> {
    OutAuth {
        err: OutAuth
    },
    InAuth {
        err: InAuth
    },
    Inbound {
        err: Inbound
    },
    Collision {
        name: String
    }
}

impl<Addr> ChannelParam<Addr> for NearChannelParam {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &Addr
    ) -> bool {
        true
    }
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
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
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
    /// - `Some(self, Some(session))`: If a session was successfully negotiated.
    ///
    /// - `Some(self, None)`: If negotiations could not be concluded.
    ///
    /// - `None`: If negotiations concluded, but did not yield a session.
    fn create(
        registry: &Registry,
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego,
        state: Types::ConnState
    ) -> Result<
        Option<(Self, Option<Types::AuthNSession>)>,
        SessionEntryCreateError<
            NegoEntrySessionError<
                Types::SessionNegoError,
                SessionEntryAuthNError<
                    Types::AuthStartError,
                    Types::AuthNegoError
                >
            >,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    > {
        match SessionNegoState::session(channel, authn, state) {
            Ok(NegotiatorResult::Complete((
                AuthNResult::Accept((out, session)),
                endpoint
            ))) => {
                let session: Types::AuthNSession = session;

                info!(target: "session-nego-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                Ok(Some((out, Some(session))))
            }
            Ok(NegotiatorResult::Complete((
                AuthNResult::Reject(stream),
                endpoint
            ))) => {
                info!(target: "session-nego-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let res = Self::do_shutdown(
                    shutdown,
                    &channel.shutdown_param(),
                    endpoint.clone(),
                    stream
                )
                .map_err(|err| {
                    SessionEntryCreateError::Shutdown { err: err }
                })?;
                let out = Self::handle_shutdown_result(registry, res, endpoint)
                    .map_err(|err| SessionEntryCreateError::IO { err: err })?;

                Ok(out.map(|out| (out, None)))
            }
            Ok(NegotiatorResult::Pending(pending)) => Ok(Some((pending, None))),
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => {
                    Err(SessionEntryCreateError::Session { err: err })
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
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr().map_err(|err| {
                            SessionEntryCreateError::IO { err: err }
                        })?;
                        let res = Self::do_shutdown(
                            shutdown,
                            &channel.shutdown_param(),
                            endpoint.clone(),
                            stream
                        )
                        .map_err(|err| {
                            SessionEntryCreateError::Shutdown { err: err }
                        })?;
                        let out = Self::handle_shutdown_result(
                            registry, res, endpoint
                        )
                        .map_err(|err| {
                            SessionEntryCreateError::IO { err: err }
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
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
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
    /// - `NegotiatorResult::Complete(AuthNResult::Accept((self, session)))`:
    ///   Negotiations were completed and authentication succeeded.
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Reject(conn))`: Negotiations
    ///   were completed and authentication failed.
    ///
    /// - `NegotiatorResult::Pending(self)`: Negotiations are still pending.
    fn session(
        channel: &Types::Channel,
        authn: &Types::AuthN,
        state: Types::ConnState
    ) -> Result<
        NegotiatorResult<
            (
                AuthNResult<(Self, Types::AuthNSession), Types::Conn>,
                Types::Endpoint
            ),
            Self
        >,
        NegoEntrySessionError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>
        >
    > {
        trace!(target: "session-nego-entry",
               "starting session negotiation");

        channel
            .negotiate(state)
            .map_err(|err| NegoEntrySessionError::Nego { err: err })?
            .map_pending(|pending| SessionNegoState::Session {
                pending: pending
            })
            .flat_map_ok(|(stream, endpoint)| {
                Self::authn(authn, endpoint.clone(), stream)
                    .map(|res| res.map(|res| (res, endpoint)))
                    .map_err(|err| NegoEntrySessionError::AuthN { err: err })
            })
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
    /// - `NegotiatorResult::Complete(AuthNResult::Accept((self, session)))`:
    ///   Negotiations were completed and authentication succeeded.
    ///
    /// - `NegotiatorResult::Complete(AuthNResult::Reject(conn))`: Negotiations
    ///   were completed and authentication failed.
    ///
    /// - `NegotiatorResult::Pending(self)`: Negotiations are still pending.
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
            .map_err(|err| SessionEntryAuthNError::Start { err: err })?;

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

                res.map(|session| {
                    (SessionNegoState::Active { endpoint: endpoint }, session)
                })
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
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `channel`: The [NearChannel] definition to use.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `shutdown`: The [Negotiator] to use for shutting down sessions.
    ///
    /// # Return Values
    ///
    /// - `Some(self, Some(session))`: If a session was successfully negotiated.
    ///
    /// - `Some(self, None)`: If the session still exists, but did not produce a
    ///   new session.
    ///
    /// - `None`: If negotiations concluded, but did not yield a session.
    fn step<F>(
        self,
        report_endpoint: F,
        registry: &Registry,
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego
    ) -> Result<
        StepResult<(Self, Types::AuthNSession), Option<Types::Endpoint>, Self>,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where F: FnOnce(Types::Endpoint) {
        trace!(target: "session-nego-entry",
               "stepping negotiations");

        match self.do_step(report_endpoint, registry,
                           channel, authn, shutdown) {
            // Negotiations completed and yielded a session.
            Ok(NegotiatorResult::Complete((
                Some(AuthNResult::Accept((out, session))),
                endpoint
            ))) => {
                info!(target: "session-nego-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                Ok(StepResult::Create {
                    session: (out, session)
                })
            }
            // Negotiations completed and yielded an
            // authentication failure.
            Ok(NegotiatorResult::Complete((
                Some(AuthNResult::Reject(stream)),
                endpoint
            ))) => {
                info!(target: "session-nego-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let res = Self::do_shutdown(
                    shutdown,
                    &channel.shutdown_param(),
                    endpoint.clone(),
                    stream
                )
                .map_err(|err| SessionEntryStepError::Shutdown { err: err })?;

                match Self::handle_shutdown_result(
                    registry,
                    res,
                    endpoint.clone()
                )
                .map_err(|err| SessionEntryStepError::IO { err: err })?
                {
                    // Shutdown negotiations are still pending.
                    Some(out) => Ok(StepResult::Internal { internal: out }),
                    // Shutdown negotiations completed.
                    None => Ok(StepResult::Shutdown {
                        endpoint: Some(endpoint)
                    })
                }
            }
            // Negotiations completed and shut down the session.
            Ok(NegotiatorResult::Complete((None, endpoint))) => {
                info!(target: "session-nego-entry",
                      "shut down session with {}",
                      endpoint);

                Ok(StepResult::Shutdown {
                    endpoint: Some(endpoint)
                })
            }
            Ok(NegotiatorResult::Pending(pending)) => {
                debug!(target: "session-nego-entry",
                       "continuing session negotiations");

                Ok(StepResult::Internal { internal: pending })
            }
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => match err {
                    SessionEntryStepError::Session { err } => {
                        Err(SessionEntryStepError::Session { err: err })
                    }
                    SessionEntryStepError::AuthN { err } => {
                        Err(SessionEntryStepError::AuthN { err: err })
                    }
                    SessionEntryStepError::Shutdown { err } => {
                        Err(SessionEntryStepError::Shutdown {
                            err: ShutdownError::Negotiate { err: err }
                        })
                    }
                    SessionEntryStepError::IO { err } => {
                        Err(SessionEntryStepError::IO { err: err })
                    }
                },
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
                        let endpoint = stream.peer_addr().map_err(|err| {
                            SessionEntryStepError::IO { err: err }
                        })?;

                        debug!(target: "session-nego-entry",
                               "shutting down failed negotiation with {}",
                               endpoint);

                        let res = Self::do_shutdown(
                            shutdown,
                            &channel.shutdown_param(),
                            endpoint.clone(),
                            stream
                        )
                        .map_err(|err| {
                            SessionEntryStepError::Shutdown { err: err }
                        })?;

                        match Self::handle_shutdown_result(
                            registry,
                            res,
                            endpoint.clone()
                        )
                        .map_err(|err| SessionEntryStepError::IO { err: err })?
                        {
                            // Shutdown negotiations are still pending.
                            Some(out) => {
                                Ok(StepResult::Internal { internal: out })
                            }
                            // Shutdown negotiations completed.
                            None => Ok(StepResult::Shutdown {
                                endpoint: Some(endpoint)
                            })
                        }
                    } else {
                        Ok(StepResult::Shutdown { endpoint: None })
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
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
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
        stream: Types::Conn
    ) -> Result<
        Option<Self>,
        SessionEntryShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    > {
        trace!(target: "session-nego-entry",
               "shutting down session");

        if let SessionNegoState::Active { endpoint } = self {
            let res = SessionNegoState::do_shutdown(
                shutdown,
                param,
                endpoint.clone(),
                stream
            )
            .map_err(|err| SessionEntryShutdownError::Shutdown { err: err })?;

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
        stream: Types::Conn
    ) -> Result<
        NegotiatorResult<Types::ShutdownValue, Self>,
        ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
    > {
        let state = shutdown
            .start(param, stream)
            .map_err(|err| ShutdownError::Start { err: err })?;

        Ok(shutdown
            .negotiate(state)
            .map_err(|err| ShutdownError::Negotiate { err: err })?
            .map_pending(|pending| SessionNegoState::Shutdown {
                endpoint: endpoint,
                pending: pending
            }))
    }

    fn do_step<F>(
        self,
        report_endpoint: F,
        registry: &Registry,
        channel: &Types::Channel,
        authn: &Types::AuthN,
        shutdown: &Types::ShutdownNego
    ) -> Result<
        NegotiatorResult<
            (
                Option<AuthNResult<(Self, Types::AuthNSession), Types::Conn>>,
                Types::Endpoint
            ),
            Self
        >,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>,
            Types::ShutdownNegoError
        >
    >
    where F: FnOnce(Types::Endpoint) {
        match self {
            SessionNegoState::Session { pending } => channel
                .complete_negotiate(pending)
                .map_err(|err| SessionEntryStepError::Session { err: err })?
                .map_pending(|pending| SessionNegoState::Session {
                    pending: pending
                })
                .flat_map_ok(|(stream, endpoint)| {
                    Self::authn(authn, endpoint.clone(), stream)
                        .map(|res| res.map(|res| (Some(res), endpoint)))
                        .map_err(|err| SessionEntryStepError::AuthN {
                            err: err
                        })
                }),
            SessionNegoState::AuthN { pending, endpoint } => Ok(authn
                .complete_negotiate(pending)
                .map_err(|err| SessionEntryStepError::AuthN {
                    err: SessionEntryAuthNError::AuthN { err: err }
                })?
                .map_pending(|pending| SessionNegoState::AuthN {
                    endpoint: endpoint.clone(),
                    pending: pending
                })
                .map(|res| {
                    (
                        Some(res.map(|session| {
                            (
                                SessionNegoState::Active {
                                    endpoint: endpoint.clone()
                                },
                                session
                            )
                        })),
                        endpoint
                    )
                })),
            SessionNegoState::Active { endpoint } => {
                report_endpoint(endpoint.clone());

                Ok(NegotiatorResult::Pending(SessionNegoState::Active {
                    endpoint: endpoint
                }))
            }
            SessionNegoState::Shutdown { pending, endpoint } => shutdown
                .complete_negotiate(pending)
                .map_err(|err| SessionEntryStepError::Shutdown { err: err })?
                .map_pending(|pending| SessionNegoState::Shutdown {
                    endpoint: endpoint.clone(),
                    pending: pending
                })
                .map_ok(|mut val| {
                    info!(target: "session-nego-entry",
                             "shut down session with {}",
                             endpoint);

                    val.deregister(registry).map_err(|err| {
                        SessionEntryStepError::IO { err: err }
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
    where
        Addr: Display {
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
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
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
    /// - `RetryResult::Success((self, Some(session)))`: If a session was
    ///   successfully negotiated.
    ///
    /// - `RetryResult::Success((self, None))`: If negotiations could not be
    ///   concluded, or concluded but did not yield a session.
    fn create(
        registry: &Registry,
        mut channel: Types::Channel,
        authn: &Types::AuthN,
        retry: &Retry,
        req_endpoint: Types::Endpoint,
        token: Token
    ) -> Result<
        RetryResult<(Self, Option<Types::AuthNSession>)>,
        ConnectorEntryCreateError<
            Types::SessionStartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Types::SessionNegoError,
                    SessionEntryAuthNError<
                        Types::AuthStartError,
                        Types::AuthNegoError
                    >
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

        channel
            .start(registry, token)
            .map_err(|err| ConnectorEntryCreateError::Start { err: err })?
            .map_ok(|state| {
                let shutdown = channel.shutdown_nego();
                let mut entry = ConnectorEntry {
                    req_endpoint: req_endpoint,
                    shutdown: shutdown,
                    channel: channel,
                    keepalive: true,
                    state: None,
                    nretries: 0,
                    when: None
                };
                let session =
                    entry.do_connect(registry, authn, retry, state).map_err(
                        |err| ConnectorEntryCreateError::Nego { err: err }
                    )?;

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
    /// - `report_endpoints`: A function used to report endpoints.
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `authn`: The [SessionAuthN] to use for authentication.
    ///
    /// - `retry`: The [Retry] configuration to use if negotiations fail.
    ///
    /// - `token`: The [Token] associated with this `ConnectorEntry`.
    ///
    /// # Return Values
    ///
    /// - `RetryResult::Success(Some(session))`: If a session was successfully
    ///   negotiated.
    ///
    /// - `RetryResult::Success(None)`: If negotiations could not be concluded,
    ///   or concluded but did not yield a session, or the session was already
    ///   active.
    fn step<F>(
        &mut self,
        report_endpoint: F,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        token: Token
    ) -> Result<
        RetryResult<
            StepResult<Types::AuthNSession, Option<Types::Endpoint>, ()>
        >,
        ConnectorEntryStepError<
            Types::SessionStartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Types::SessionNegoError,
                    SessionEntryAuthNError<
                        Types::AuthStartError,
                        Types::AuthNegoError
                    >
                >,
                SessionEntryShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >,
            SessionEntryStepError<
                Types::SessionNegoError,
                SessionEntryAuthNError<
                    Types::AuthStartError,
                    Types::AuthNegoError
                >,
                SessionEntryShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >
        >
    >
    where F: FnOnce(Types::Endpoint) {
        let state = self.state.take();

        trace!(target: "connector-entry",
               "stepping negotiations with {}",
               self.channel.endpoint());

        match state {
            // There's an existing state; step it.
            Some(state) => self
                .do_step(report_endpoint, registry, authn, retry, state)
                .map_err(|err| ConnectorEntryStepError::Step { err: err })
                .map(RetryResult::Success),
            // There is no existing state.
            None => {
                trace!(target: "connector-entry",
                       "no existing negotiation state with {}",
                       self.channel.endpoint());

                // See if it's time to try to reconnect.
                let now = Instant::now();
                let when = self.when.take().and_then(|when| {
                    if when < now {
                        Some(when)
                    } else {
                        None
                    }
                });

                if let Some(when) = when {
                    Ok(RetryResult::Retry(when))
                } else {
                    // Try to connect.
                    match self.channel.start(registry, token).map_err(
                        |err| ConnectorEntryStepError::Start { err: err }
                    )? {
                        // We don't return a shutdown result here,
                        // because no one downstream would have seen
                        // the endpoint.
                        RetryResult::Success(state) => {
                            let out = self
                                .do_connect(registry, authn, retry, state)
                                .map_err(|err| {
                                    ConnectorEntryStepError::Connect {
                                        err: err
                                    }
                                })?
                                .map_or(
                                    StepResult::Internal { internal: () },
                                    |session| StepResult::Create {
                                        session: session
                                    }
                                );

                            Ok(RetryResult::Success(out))
                        }
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
    /// This will also cause [is_live](ConnectorEntry::is_live) to
    /// return `false` once the session is shut down.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
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
        stream: Types::Conn
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

        let state = self
            .state
            .take()
            .ok_or(SessionEntryShutdownError::NotActive)?;
        let newstate = state.shutdown(
            registry,
            &self.shutdown,
            &self.channel.shutdown_param(),
            stream
        )?;
        let out = newstate.is_none();

        self.keepalive = false;
        self.state = newstate;

        Ok(out)
    }

    /// Check if this entry should be preserved.
    #[inline]
    fn is_live(&self) -> bool {
        self.keepalive || self.state.is_some()
    }

    fn do_shutdown(
        &mut self,
        registry: &Registry,
        endpoint: Types::Endpoint,
        stream: Types::Conn
    ) -> Result<
        (),
        SessionEntryShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    > {
        let res = SessionNegoState::do_shutdown(
            &self.shutdown,
            &self.channel.shutdown_param(),
            endpoint.clone(),
            stream
        )
        .map_err(|err| SessionEntryShutdownError::Shutdown { err: err })?;

        self.state =
            SessionNegoState::handle_shutdown_result(registry, res, endpoint)
                .map_err(|err| SessionEntryShutdownError::IO { err: err })?;

        Ok(())
    }

    fn do_connect(
        &mut self,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        state: Types::ConnState
    ) -> Result<
        Option<Types::AuthNSession>,
        SessionCreateError<
            NegoEntrySessionError<
                Types::SessionNegoError,
                SessionEntryAuthNError<
                    Types::AuthStartError,
                    Types::AuthNegoError
                >
            >,
            SessionEntryShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
            >
        >
    > {
        match SessionNegoState::session(&self.channel, authn, state) {
            Ok(NegotiatorResult::Complete((
                AuthNResult::Accept((out, session)),
                endpoint
            ))) => {
                let session: Types::AuthNSession = session;

                info!(target: "connector-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                self.state = Some(out);

                Ok(Some(session))
            }
            Ok(NegotiatorResult::Complete((
                AuthNResult::Reject(stream),
                endpoint
            ))) => {
                info!(target: "connector-entry",
                      "authentication rejected for session with {}",
                      self.channel.endpoint());

                let delay = retry.retry_delay(self.nretries);

                self.when = Some(Instant::now() + delay);
                self.nretries += 1;

                self.do_shutdown(registry, endpoint, stream)
                    .map_err(|err| SessionCreateError::Shutdown { err: err })?;

                Ok(None)
            }
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
                ErrorScope::System => {
                    Err(SessionCreateError::Session { err: err })
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
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::Start { err }
                        } => authn.start_err_stream(err),
                        NegoEntrySessionError::AuthN {
                            err: SessionEntryAuthNError::AuthN { err }
                        } => authn.err_stream(err),
                        _ => None
                    };

                    if let Some(stream) = stream {
                        let endpoint = stream.peer_addr().map_err(|err| {
                            SessionCreateError::IO { err: err }
                        })?;

                        self.do_shutdown(registry, endpoint, stream).map_err(
                            |err| SessionCreateError::Shutdown { err: err }
                        )?;
                    }

                    Ok(None)
                }
            }
        }
    }

    fn do_step<F>(
        &mut self,
        report_endpoint: F,
        registry: &Registry,
        authn: &Types::AuthN,
        retry: &Retry,
        state: SessionNegoState<Types>
    ) -> Result<
        StepResult<Types::AuthNSession, Option<Types::Endpoint>, ()>,
        SessionEntryStepError<
            Types::SessionNegoError,
            SessionEntryAuthNError<Types::AuthStartError, Types::AuthNegoError>,
            SessionEntryShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
            >
        >
    >
    where F: FnOnce(Types::Endpoint) {
        match state.do_step(
            report_endpoint,
            registry,
            &self.channel,
            authn,
            &self.shutdown
        ) {
            // Negotiations completed and yielded a session.
            Ok(NegotiatorResult::Complete((
                Some(AuthNResult::Accept((out, session))),
                endpoint
            ))) => {
                info!(target: "connector-entry",
                      "authenticated new session with {} over {}",
                      session.prin(), endpoint);

                self.nretries = 0;
                self.state = Some(out);

                Ok(StepResult::Create { session: session })
            }
            // Negotiations completed and yielded an
            // authentication failure.
            Ok(NegotiatorResult::Complete((
                Some(AuthNResult::Reject(stream)),
                endpoint
            ))) => {
                info!(target: "connector-entry",
                      "authentication rejected for session with {}",
                      endpoint);

                let delay = retry.retry_delay(self.nretries);

                self.when = Some(Instant::now() + delay);
                self.nretries += 1;

                self.do_shutdown(registry, endpoint.clone(), stream)
                    .map_err(|err| SessionEntryStepError::Shutdown {
                        err: err
                    })?;

                if self.state.is_some() {
                    Ok(StepResult::Internal { internal: () })
                } else {
                    Ok(StepResult::Shutdown {
                        endpoint: Some(endpoint)
                    })
                }
            }
            // Negotiations completed and yielrded a session.
            Ok(NegotiatorResult::Complete((None, endpoint))) => {
                info!(target: "connector-entry",
                      "shutdown session with {}",
                      endpoint);

                Ok(StepResult::Shutdown {
                    endpoint: Some(endpoint)
                })
            }
            Ok(NegotiatorResult::Pending(pending)) => {
                debug!(target: "connector-entry",
                      "continuing session negotiations with");

                self.state = Some(pending);

                Ok(StepResult::Internal { internal: () })
            }
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => match err {
                    SessionEntryStepError::Session { err } => {
                        Err(SessionEntryStepError::Session { err: err })
                    }
                    SessionEntryStepError::AuthN { err } => {
                        Err(SessionEntryStepError::AuthN { err: err })
                    }
                    SessionEntryStepError::Shutdown { err } => {
                        Err(SessionEntryStepError::Shutdown {
                            err: SessionEntryShutdownError::Shutdown {
                                err: ShutdownError::Negotiate { err: err }
                            }
                        })
                    }
                    SessionEntryStepError::IO { err } => {
                        Err(SessionEntryStepError::IO { err: err })
                    }
                },
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
                        let endpoint = stream.peer_addr().map_err(|err| {
                            SessionEntryStepError::IO { err: err }
                        })?;

                        self.do_shutdown(registry, endpoint, stream).map_err(
                            |err| SessionEntryStepError::Shutdown { err: err }
                        )?;
                    }

                    if self.state.is_some() {
                        Ok(StepResult::Internal { internal: () })
                    } else {
                        Ok(StepResult::Shutdown { endpoint: None })
                    }
                }
            }
        }
    }
}

/// Exhaust all incoming sessions, negotiate them as far as possible,
/// and return all the resulting negotiation states.
fn start_incoming<Ctx, S, Types>(
    ctx: &mut Ctx,
    mut report_session: S,
    when: &mut Option<Instant>,
    read: &mut bool,
    accept: &mut Types::InChannel,
    shutdown: &Types::InShutdownNego,
    authn: &Types::InAuthN
) -> Result<
    Option<Vec<(Token, SessionNegoState<Types::Inbound>)>>,
    ChannelEntryListenError<Types::InSessionStartError>
>
where
    S: FnMut(
        DuplexValue<Types::InAuthNSession, Types::OutAuthNSession>
    ) -> Result<(), std::io::Error>,
    Types: NearDuplexNegoTypes,
    Ctx: RegistryCtx + TokensCtx {
    if when.map_or(true, |when| when <= Instant::now()) {
        let mut incoming = Vec::new();

        *when = None;

        loop {
            let token = ctx.token();

            match accept.start(ctx.registry(), token) {
                Ok(RetryResult::Success(state)) => {
                    // Normal listen result.
                    *read = true;
                    incoming.push((token, state));
                }
                // If we get a retry delay, record it and return
                // what we have.
                Ok(RetryResult::Retry(retry)) => {
                    *when = Some(retry);
                    ctx.free_token(token);

                    break;
                }
                // Error; see if it's WouldBlock.
                Err(err) => {
                    ctx.free_token(token);

                    // Report errors other than WouldBlock.
                    if err.scope() != ErrorScope::WouldBlock {
                        error!(target: "channel-entry",
                               "error listening for incoming sessions: {}",
                               err);

                        if err.scope() >= ErrorScope::System {
                            return Err(ChannelEntryListenError::Start {
                                err: err
                            });
                        }
                    }

                    break;
                }
            }
        }

        let mut out = Vec::with_capacity(incoming.len());

        for (token, state) in incoming.drain(..) {
            match SessionNegoState::create(
                ctx.registry(), accept, authn, shutdown, state
            ) {
                Ok(Some((ent, session))) => {
                    out.push((token, ent));

                    if let Some(session) = session {
                        let session = DuplexValue::Accept(session);

                        report_session(session)
                            .map_err(|err| ChannelEntryListenError::IO {
                                err: err
                            })?
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    error!(target: "channel-entry",
                           "error stepping pending negotiation: {}",
                           err);
                }
            }
        }

        let out = if out.len() != 0 { Some(out) } else { None };

        Ok(out)
    } else {
        Ok(None)
    }
}

impl<Types> DuplexChannelMode<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Create a `DuplexChannelMode` for both inbound and outbound
    /// connections.
    ///
    /// # Parameters
    ///
    /// - `out_config`: Base configuration for outbound channels.
    ///
    /// - `out_authn`: [SessionAuthN] to use for authenticating outbound
    ///   sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    pub(crate) fn new(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        token: Token
    ) -> Self {
        let out_tokens = HashMap::new();
        let in_tokens = HashMap::new();
        let negos = HashMap::new();
        let in_shutdown = acceptor.shutdown_nego();

        DuplexChannelMode {
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
        }
    }

    /// Create a `DuplexChannelMode` for both inbound and outbound
    /// connections, with a size hint.
    ///
    /// # Parameters
    ///
    /// - `out_config`: Base configuration for outbound channels.
    ///
    /// - `out_authn`: [SessionAuthN] to use for authenticating outbound
    ///   sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    ///
    /// - `nins`: Expected maximum number of inbound sessions; this will not
    ///   cause an errer if it is too low.
    ///
    /// - `nouts`: Expected maximum number of outbound sessions; this will not
    ///   cause an errer if it is too low.
    pub(crate) fn with_capacity(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        token: Token,
        nins: usize,
        nouts: usize
    ) -> Self {
        let out_tokens = HashMap::with_capacity(nouts);
        let in_tokens = HashMap::with_capacity(nins);
        let negos = HashMap::with_capacity(nins + nouts);
        let in_shutdown = acceptor.shutdown_nego();

        DuplexChannelMode {
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
        }
    }

    /// Check if this `DuplexChannelMode` contains any active sessions.
    #[inline]
    fn is_empty(&self) -> bool {
        match (
            self.accept_tokens.is_empty(),
            self.conn_tokens.is_empty(),
            self.negos.is_empty()
        ) {
            (true, true, true) => true,
            (false, false, _) | (false, _, false) => false,
            _ => {
                error!(target: "duplex-channel-mode",
                       "inconsistent token and negotiation tables");

                false
            }
        }
    }

    #[inline]
    fn shutdown(
        mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        self.acceptor.deregister(registry)
    }

    /// Request a stream for a given endpoint.
    ///
    /// This will attempt to negotiate and authenticate a session with
    /// the given endpoint.  If negotiations can be concluded
    /// immediately, then the authenticated session will be returned.
    /// Otherwise, the request will remain active and will eventually
    /// be returned by [listen](DuplexChannelMode::listen).  Subsequent calls
    /// to this function with the same `endpoint` will return an
    /// error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_conn](FlowsEntry::shutdown_conn)
    /// to properly handle shutdown negotiations and cleanup.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `gentok`: Generator for [Token]s.
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
    /// - `RetryResult::Success(None))`: Session negotiations are still pending
    ///   and the session will eventually be reported by
    ///   [listen](DuplexChannelMode::listen).
    pub(crate) fn req_stream<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        retry: &Retry,
        endpoint: Types::Endpoint,
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
                        SessionEntryAuthNError<
                            Types::OutAuthStartError,
                            Types::OutAuthNegoError
                        >
                    >,
                    SessionEntryShutdownError<
                        Types::OutShutdownStartError,
                        Types::OutShutdownNegoError
                    >
                >
            >
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        if !self.conn_tokens.contains_key(&endpoint) {
            trace!(target: "duplex-channel-mode",
                   "creating outbound channel to {}",
                   endpoint);

            let token = ctx.token();
            let conn = Types::OutChannel::create_with_endpoint(
                ctx,
                self.config.clone(),
                endpoint.clone(),
                param
            )
            .map_err(|err| {
                ctx.free_token(token);

                ChannelEntryReqError::Channel { err: err }
            })?;

            trace!(target: "duplex-channel-mode",
                   "creating connector entry for {}, token {:?}",
                   endpoint, token);

            ConnectorEntry::create(
                ctx.registry(),
                conn,
                &self.out_authn,
                retry,
                endpoint.clone(),
                token
            )
            .map_err(|err| {
                ctx.free_token(token);

                ChannelEntryReqError::Entry { err: err }
            })?
            .map_ok(|(ent, out)| {
                let out: Option<Types::OutAuthNSession> = out;

                trace!(target: "duplex-channel-mode",
                          "connector entry created for {}",
                          endpoint);

                self.insert_out_ent(&out, ent, endpoint, token)
                    .map_err(|err| ChannelEntryReqError::IO { err: err })?;

                Ok((token, out))
            })
        } else {
            Err(ChannelEntryReqError::Collision)
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
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `report_session`: A function used to report authenticated sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `live`: All [Token]s that have pending read traffic.
    ///
    /// - `shutdown_only`: Whether to allow new incoming sessions.
    fn listen<Ctx, E, S>(
        &mut self,
        ctx: &mut Ctx,
        mut report_session: S,
        mut report_endpoint: E,
        retry: &Retry,
        live: &HashSet<Token>,
        shutdown_only: bool
    ) -> Result<
        (Option<Vec<Token>>, Option<Vec<Token>>),
        ChannelEntryListenError<Types::InSessionStartError>
    >
    where
        S: FnMut(
            DuplexValue<Types::InAuthNSession, Types::OutAuthNSession>
        ) -> Result<(), std::io::Error>,
        E: FnMut(Types::Endpoint),
        Ctx: RegistryCtx + TokensCtx {
        let mut creates = HashSet::with_capacity(self.negos.len());
        let mut deletes = HashSet::with_capacity(self.negos.len());

        while {
            let mut read = false;
            let mut round_deletes = Vec::with_capacity(self.negos.len());

            // Process all live existing sessions.
            for (token, ent) in self.negos.iter_mut() {
                let now = Instant::now();

                match ent {
                    DuplexValue::Conn(ent) => {
                        if ent.when.map_or(false, |when| when < now) ||
                            live.contains(token)
                        {
                            match ent.step(
                                &mut report_endpoint,
                                ctx.registry(),
                                &self.out_authn,
                                retry,
                                *token
                            ) {
                                // Session was produced; record it.
                                Ok(RetryResult::Success(res)) => match res {
                                    StepResult::Create { session } => {
                                        // Need to insert the extra token
                                        // entry.
                                        Self::insert_out_ent_extra(
                                            &mut self.conn_tokens,
                                            &session,
                                            &ent.req_endpoint,
                                            *token
                                        )
                                        .map_err(|err| {
                                            ChannelEntryListenError::IO {
                                                err: err
                                            }
                                        })?;

                                        let session =
                                            DuplexValue::Conn(session);

                                        report_session(session)
                                            .map_err(|err| {
                                                ChannelEntryListenError::IO {
                                                    err: err
                                                }
                                            })?;
                                    }
                                    // Session shut down; clean up after it.
                                    StepResult::Shutdown { endpoint } => {
                                        round_deletes.push(*token);

                                        Self::remove_out_ent_token(
                                            &mut self.conn_tokens,
                                            endpoint,
                                            &ent.req_endpoint
                                        )
                                    }
                                    StepResult::Internal { internal: () } => {}
                                },
                                // Record a deferral.
                                Ok(RetryResult::Retry(when)) => {
                                    if ent.when.map_or(true, |curr| curr < when)
                                    {
                                        ent.when = Some(when);
                                    }
                                }
                                Err(err) => {
                                    error!(target: "duplex-channel-mode",
                                       "negotiation step error: {}",
                                       err);
                                }
                            }
                        }
                    }
                    DuplexValue::Accept(ent) => {
                        if live.contains(token) {
                            if let Some(state) = ent.take() {
                                match state.step(
                                    &mut report_endpoint,
                                    ctx.registry(),
                                    &self.acceptor,
                                    &self.in_authn,
                                    &self.shutdown
                                ) {
                                    // Session was produced; record it.
                                    Ok(StepResult::Create {
                                        session: (state, session)
                                    }) => {
                                        // Need to insert the token entry.
                                        let endpoint = session
                                            .get()
                                            .peer_addr()
                                            .map_err(|err| {
                                                ChannelEntryListenError::IO {
                                                    err: err
                                                }
                                            })?;
                                        let session =
                                            DuplexValue::Accept(session);

                                        Self::insert_in_ent_token(
                                            &mut self.accept_tokens,
                                            &endpoint,
                                            *token
                                        );
                                        *ent = Some(state);
                                        report_session(session)
                                            .map_err(|err| {
                                                ChannelEntryListenError::IO {
                                                    err: err
                                                }
                                            })?;
                                    }
                                    // Session shut down; clean up after it.
                                    Ok(StepResult::Shutdown { endpoint }) => {
                                        round_deletes.push(*token);

                                        // Remove the token entry if we need to.
                                        if let Some(endpoint) = endpoint {
                                            Self::remove_in_ent_token(
                                                &mut self.accept_tokens,
                                                &endpoint
                                            );
                                        }
                                    }
                                    // Internl traffic
                                    Ok(StepResult::Internal { internal }) => {
                                        *ent = Some(internal);
                                    }
                                    Err(err) => {
                                        error!(target: "duplex-channel-mode",
                                           "negotiation step error: {}",
                                           err);
                                    }
                                }
                            } else {
                                error!(target: "duplex-channel-mode",
                                   "empty entry state for token {:?}",
                                   token);
                            }
                        }
                    }
                }
            }

            // Delete expired entries.
            for token in round_deletes.iter() {
                trace!(target: "duplex-channel-mode",
                       "removing session entry for {:?}",
                       token);

                if self.negos.remove(token).is_none() {
                    error!(target: "duplex-channel-mode",
                           "deleted token {:?} was not present",
                           token);
                }

                creates.remove(token);
                deletes.insert(*token);
            }

            // Pick up all incoming sessions.
            if !shutdown_only {
                let incoming = if live.contains(&self.token) {
                    let incoming = start_incoming::<Ctx, _, Types>(
                        ctx,
                        &mut report_session,
                        &mut self.retry_when,
                        &mut read,
                        &mut self.acceptor,
                        &self.shutdown,
                        &self.in_authn
                    )?;

                    incoming
                } else {
                    None
                };

                // Add the incoming sessions if we have them.
                if let Some(incoming) = incoming {
                    for (token, ent) in incoming {
                        self.insert_in_ent(ent, token);
                        deletes.remove(&token);
                        creates.insert(token);
                    }
                }
            }

            read
        } {}

        let creates = if !creates.is_empty() {
            Some(creates.into_iter().collect())
        } else {
            None
        };
        let deletes = if !deletes.is_empty() {
            Some(deletes.into_iter().collect())
        } else {
            None
        };

        Ok((creates, deletes))
    }

    /// Shut down an outbound (connected) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// If the stream was shut down, `Some(token)` where `token` is
    /// the [Token] for the stream.
    fn shutdown_conn(
        &mut self,
        registry: &Registry,
        stream: Types::OutConn
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    > {
        let session_endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        trace!(target: "duplex-channel-mode",
               "shutting down connected session with {}",
               session_endpoint);

        let res = if let Entry::Occupied(ent) =
            self.conn_tokens.entry(session_endpoint.clone())
        {
            if let DuplexValue::Conn(conn) = self
                .negos
                .get_mut(ent.get())
                .ok_or(ChannelEntryShutdownError::Inconsistent)?
            {
                let delete =
                    conn.shutdown(registry, stream).map_err(|err| {
                        ChannelEntryShutdownError::Shutdown {
                            err: DuplexValue::Conn(err)
                        }
                    })?;

                if delete {
                    let token = *ent.get();

                    trace!(target: "duplex-channel-mode",
                           "removing session entry for {:?}",
                           token);

                    let conn_endpoint = match self.negos.remove(&token) {
                        Some(DuplexValue::Conn(ent)) => Ok(ent.req_endpoint),
                        Some(_) => Err(ChannelEntryShutdownError::Mismatch),
                        None => Err(ChannelEntryShutdownError::Inconsistent)
                    }?;

                    trace!(target: "duplex-channel-mode",
                           "removing tokens entry for {} to token {:?}",
                           session_endpoint, token);

                    ent.remove();

                    Ok(Some((conn_endpoint, token)))
                } else {
                    Ok(None)
                }
            } else {
                Err(ChannelEntryShutdownError::Mismatch)
            }
        } else {
            Err(ChannelEntryShutdownError::NotFound {
                endpoint: session_endpoint.clone()
            })
        }?;

        Ok(res.map(|(endpoint, token)| {
            if endpoint != session_endpoint {
                if let Some(token) = self.conn_tokens.remove(&endpoint) {
                    trace!(target: "duplex-channel-mode",
                           "removing tokens entry for {} to token {:?}",
                           endpoint, token);
                } else {
                    error!(target: "duplex-channel-mode",
                           "address {} not present",
                           endpoint);
                }
            }

            token
        }))
    }

    /// Shut down an inbound (accepted) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// If the stream was shut down, `Some(token)` where `token` is
    /// the [Token] for the stream.
    fn shutdown_accept(
        &mut self,
        registry: &Registry,
        stream: Types::InConn
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    > {
        let endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        trace!(target: "duplex-channel-mode",
               "shutting down accepted session with {}",
               endpoint);

        if let Entry::Occupied(ent) = self.accept_tokens.entry(endpoint.clone())
        {
            if let DuplexValue::Accept(accept) =
                self.negos
                    .get_mut(ent.get())
                    .ok_or(ChannelEntryShutdownError::Inconsistent)?
            {
                let newaccept = accept
                    .take()
                    .ok_or(ChannelEntryShutdownError::NotFound {
                        endpoint: endpoint.clone()
                    })?
                    .shutdown(
                        registry,
                        &self.shutdown,
                        &self.acceptor.shutdown_param(),
                        stream
                    )
                    .map_err(|err| ChannelEntryShutdownError::Shutdown {
                        err: DuplexValue::Accept(err)
                    })?;

                if newaccept.is_some() {
                    *accept = newaccept;

                    Ok(None)
                } else {
                    let token = *ent.get();

                    trace!(target: "duplex-channel-mode",
                           "removing session entry for {:?}",
                           token);

                    if self.negos.remove(&token).is_none() {
                        error!(target: "duplex-channel-mode",
                               "entry for token {:?} missing",
                               ent.get());
                    }

                    trace!(target: "duplex-channel-mode",
                           "removing tokens entry for {} to token {:?}",
                           endpoint, token);

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
    }

    fn insert_out_ent(
        &mut self,
        session: &Option<Types::OutAuthNSession>,
        ent: ConnectorEntry<Types::Outbound>,
        endpoint: Types::Endpoint,
        token: Token
    ) -> Result<(), std::io::Error> {
        let ent = DuplexValue::Conn(ent);

        trace!(target: "duplex-channel-mode",
               "adding tokens entry for {} to token {:?}",
               endpoint, token);

        if let Some(token) = self.conn_tokens.insert(endpoint.clone(), token) {
            error!(target: "duplex-channel-mode",
                   "tokens table contains {} (token {:?})",
                   endpoint, token);
        }

        // We also need to check to see if the address reported by the
        // session differs from the one used to connect.
        if let Some(session) = &session {
            Self::insert_out_ent_extra(
                &mut self.conn_tokens,
                session,
                &endpoint,
                token
            )?
        }

        trace!(target: "duplex-channel-mode",
               "adding connector entry for token {:?}",
               token);

        if self.negos.insert(token, ent).is_some() {
            error!(target: "duplex-channel-mode",
                   "sessions table contains {:?}",
                   token);
        }

        Ok(())
    }

    fn insert_out_ent_extra(
        conn_tokens: &mut HashMap<Types::Endpoint, Token>,
        session: &Types::OutAuthNSession,
        endpoint: &Types::Endpoint,
        token: Token
    ) -> Result<(), std::io::Error> {
        let session_endpoint = session.get().peer_addr()?;

        if &session_endpoint != endpoint {
            trace!(target: "duplex-channel-mode",
                   "adding extra tokens entry for {} to token {:?}",
                   session_endpoint, token);

            if let Some(token) =
                conn_tokens.insert(session_endpoint.clone(), token)
            {
                error!(target: "duplex-channel-mode",
                       "tokens already contains entry for {} (token {:?})",
                       endpoint, token);
            }
        }

        Ok(())
    }

    fn remove_out_ent_token(
        conn_tokens: &mut HashMap<Types::Endpoint, Token>,
        session_endpoint: Option<Types::Endpoint>,
        endpoint: &Types::Endpoint
    ) {
        if let Some(token) = conn_tokens.remove(endpoint) {
            trace!(target: "duplex-channel-mode",
                   "removing tokens entry for {} to token {:?}",
                   endpoint, token);
        } else {
            error!(target: "duplex-channel-mode",
                   "address {} not present",
                   endpoint);
        }

        if let Some(session_endpoint) = session_endpoint {
            if &session_endpoint != endpoint {
                if let Some(token) = conn_tokens.remove(&session_endpoint) {
                    trace!(target: "duplex-channel-mode",
                           "removing extra tokens entry for {} to token {:?}",
                           endpoint, token);
                } else {
                    error!(target: "duplex-channel-mode",
                           "address {} not present",
                           endpoint);
                }
            }
        }
    }

    fn insert_in_ent(
        &mut self,
        ent: SessionNegoState<Types::Inbound>,
        token: Token
    ) {
        let endpoint: Option<&Types::Endpoint> = match &ent {
            SessionNegoState::AuthN { endpoint, .. } |
            SessionNegoState::Active { endpoint } |
            SessionNegoState::Shutdown { endpoint, .. } => Some(endpoint),
            SessionNegoState::Session { .. } => None
        };

        if let Some(endpoint) = endpoint {
            Self::insert_in_ent_token(&mut self.accept_tokens, endpoint, token)
        }

        let ent = DuplexValue::Accept(Some(ent));

        trace!(target: "duplex-channel-mode",
               "adding connector entry for token {:?}",
               token);

        if self.negos.insert(token, ent).is_some() {
            error!(target: "duplex-channel-mode",
                   "sessions contains entry for {:?}",
                   token);
        }
    }

    fn insert_in_ent_token(
        accept_tokens: &mut HashMap<Types::Endpoint, Token>,
        endpoint: &Types::Endpoint,
        token: Token
    ) {
        trace!(target: "duplex-channel-mode",
               "adding tokens entry for {} to token {:?}",
               endpoint, token);

        if let Some(token) = accept_tokens.insert(endpoint.clone(), token) {
            error!(target: "duplex-channel-mode",
                   "tokens already contains entry for {} (token {:?})",
                   endpoint, token);
        }
    }

    fn remove_in_ent_token(
        accept_tokens: &mut HashMap<Types::Endpoint, Token>,
        endpoint: &Types::Endpoint
    ) {
        if let Some(token) = accept_tokens.remove(endpoint) {
            trace!(target: "duplex-channel-mode",
                   "removing tokens entry for {} to token {:?}",
                   endpoint, token);
        } else {
            error!(target: "duplex-channel-mode",
                   "address {} not present",
                   endpoint);
        }
    }
}

impl<Types> OutboundChannelMode<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Create a `OutboundChannelMode` for outbound connections only.
    ///
    /// Calls to [listen](OutboundChannelMode::listen) on this
    /// `OutboundChannelMode` will only complete pending session
    /// negotiations; it will not generate incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `config`: Base configuration for outbound channels.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration for retrying connections.
    pub(crate) fn new(
        config: Types::OutConfig,
        authn: Types::OutAuthN
    ) -> Self {
        let tokens = HashMap::new();
        let negos = HashMap::new();

        OutboundChannelMode {
            config: config,
            authn: authn,
            tokens: tokens,
            negos: negos
        }
    }

    /// Create a `OutboundChannelMode` for outbound connections only with a
    /// size hint.
    ///
    /// Calls to [listen](OutboundChannelMode::listen) on this
    /// `OutboundChannelMode` will only complete pending session
    /// negotiations; it will not generate incoming sessions.
    ///
    /// # Parameters
    ///
    /// - `config`: Base configuration for outbound channels.
    ///
    /// - `authn`: [SessionAuthN] to use for authenticating sessions.
    ///
    /// - `retry`: [Retry] configuration for retrying connections.
    ///
    /// - `size`: Expected maximum number of sessions; this will not cause an
    ///   errer if it is too low.
    pub(crate) fn with_capacity(
        config: Types::OutConfig,
        authn: Types::OutAuthN,
        size: usize
    ) -> Self {
        let tokens = HashMap::with_capacity(size);
        let negos = HashMap::with_capacity(size);

        OutboundChannelMode {
            config: config,
            authn: authn,
            tokens: tokens,
            negos: negos
        }
    }

    /// Check if this `OutboundChannelMode` contains any active sessions.
    #[inline]
    fn is_empty(&self) -> bool {
        match (self.tokens.is_empty(), self.negos.is_empty()) {
            (true, true) => true,
            (false, false) => false,
            _ => {
                error!(target: "outbound-channel-mode",
                       "inconsistent token and negotiation tables");

                false
            }
        }
    }

    #[inline]
    fn shutdown(
        self,
        _registry: &Registry
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    /// Request a stream for a given endpoint.
    ///
    /// This will attempt to negotiate and authenticate a session with
    /// the given endpoint.  If negotiations can be concluded
    /// immediately, then the authenticated session will be returned.
    /// Otherwise, the request will remain active and will eventually
    /// be returned by [listen](OutboundChannelMode::listen).  Subsequent calls
    /// to this function with the same `endpoint` will return an
    /// error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_conn](FlowsEntry::shutdown_conn)
    /// to properly handle shutdown negotiations and cleanup.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
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
    /// - `RetryResult::Success(None))`: Session negotiations are still pending
    ///   and the session will eventually be reported by
    ///   [listen](OutboundChannelMode::listen).
    pub(crate) fn req_stream<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        retry: &Retry,
        endpoint: Types::Endpoint,
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
                        SessionEntryAuthNError<
                            Types::OutAuthStartError,
                            Types::OutAuthNegoError
                        >
                    >,
                    SessionEntryShutdownError<
                        Types::OutShutdownStartError,
                        Types::OutShutdownNegoError
                    >
                >
            >
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        debug!(target: "outbound-channel-mode",
               "requesting flow with {}",
               endpoint);

        if !self.tokens.contains_key(&endpoint) {
            trace!(target: "outbound-channel-mode",
                   "creating outbound channel to {}",
                   endpoint);

            let token = ctx.token();
            let conn = Types::OutChannel::create_with_endpoint(
                ctx,
                self.config.clone(),
                endpoint.clone(),
                param
            )
            .map_err(|err| {
                ctx.free_token(token);

                ChannelEntryReqError::Channel { err: err }
            })?;

            trace!(target: "outbound-channel-mode",
                   "creating connector entry for {}, token {:?}",
                   endpoint, token);

            ConnectorEntry::create(
                ctx.registry(),
                conn,
                &self.authn,
                retry,
                endpoint.clone(),
                token
            )
            .map_err(|err| {
                ctx.free_token(token);

                ChannelEntryReqError::Entry { err: err }
            })?
            .map_ok(|(ent, out)| {
                let out: Option<Types::OutAuthNSession> = out;

                trace!(target: "outbound-channel-mode",
                          "connector entry created for {}",
                          endpoint);

                self.insert_out_ent(&out, ent, endpoint, token)
                    .map_err(|err| ChannelEntryReqError::IO { err: err })?;

                Ok((token, out))
            })
        } else {
            Err(ChannelEntryReqError::Collision)
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
    /// # Parameters
    ///
    /// - `report_session`: A function used to report new authenticated
    ///   sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `registry`: [Registry] to use to register nonblocking I/O.
    ///
    /// - `live`: All [Token]s that have pending read traffic.
    fn listen<E, S>(
        &mut self,
        mut report_session: S,
        mut report_endpoint: E,
        registry: &Registry,
        retry: &Retry,
        live: &HashSet<Token>
    ) -> Result<
        Option<Vec<Token>>,
        ChannelEntryListenError<Types::InSessionStartError>
    >
    where
        S: FnMut(
            DuplexValue<Types::InAuthNSession, Types::OutAuthNSession>
        ) -> Result<(), std::io::Error>,
        E: FnMut(Types::Endpoint)
    {
        let mut deletes: Option<Vec<Token>> = None;
        let len = self.negos.len();

        for (token, ent) in self.negos.iter_mut() {
            let now = Instant::now();

            if ent.when.map_or(false, |when| when < now) || live.contains(token)
            {
                match ent.step(
                    &mut report_endpoint,
                    registry,
                    &self.authn,
                    retry,
                    *token
                ) {
                    // Session was produced; record it.
                    Ok(RetryResult::Success(res)) => match res {
                        StepResult::Create { session } => {
                            // Need to insert the extra token
                            // entry.
                            Self::insert_out_ent_extra(
                                &mut self.tokens,
                                &session,
                                &ent.req_endpoint,
                                *token
                            )
                            .map_err(|err| {
                                ChannelEntryListenError::IO { err: err }
                            })?;

                            let session = DuplexValue::Conn(session);

                            report_session(session)
                                .map_err(|err| ChannelEntryListenError::IO {
                                    err: err
                                })?;
                        }
                        // Session shut down; clean up after it.
                        StepResult::Shutdown { endpoint } => {
                            if let Some(deletes) = &mut deletes {
                                deletes.push(*token);
                            } else {
                                let mut vec = Vec::with_capacity(len);

                                vec.push(*token);
                                deletes = Some(vec);
                            }

                            Self::remove_out_ent_token(
                                &mut self.tokens,
                                endpoint,
                                &ent.req_endpoint
                            )
                        }
                        StepResult::Internal { internal: () } => {}
                    },
                    // Record a deferral.
                    Ok(RetryResult::Retry(when)) => {
                        if ent.when.map_or(true, |curr| curr < when) {
                            ent.when = Some(when);
                        }
                    }
                    Err(err) => {
                        error!(target: "outbound-channel-mode",
                               "negotiation step error: {}",
                               err);
                    }
                }
            }
        }

        if let Some(deletes) = &deletes {
            // Delete expired entries.
            for token in deletes.iter() {
                trace!(target: "outbound-channel-mode",
                       "removing session entry for {:?}",
                       token);

                if self.negos.remove(token).is_none() {
                    error!(target: "outbound-channel-mode",
                           "deleted token {:?} was not present",
                           token);
                }
            }
        }

        Ok(deletes)
    }

    /// Shut down an outbound (connected) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// If the stream was shut down, `Some(token)` where `token` is
    /// the [Token] for the stream.
    fn shutdown_conn(
        &mut self,
        registry: &Registry,
        stream: Types::OutConn
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    > {
        let session_endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        trace!(target: "outbound-channel-mode",
               "shutting down connected session with {}",
               session_endpoint);

        let res = if let Entry::Occupied(ent) =
            self.tokens.entry(session_endpoint.clone())
        {
            let conn = self
                .negos
                .get_mut(ent.get())
                .ok_or(ChannelEntryShutdownError::Inconsistent)?;
            let delete = conn.shutdown(registry, stream).map_err(|err| {
                ChannelEntryShutdownError::Shutdown {
                    err: DuplexValue::Conn(err)
                }
            })?;

            if delete {
                let token = *ent.get();

                trace!(target: "outbound-channel-mode",
                       "removing session entry for {:?}",
                       token);

                let conn_endpoint = self
                    .negos
                    .remove(&token)
                    .ok_or(ChannelEntryShutdownError::Inconsistent)?
                    .req_endpoint;

                trace!(target: "outbound-channel-mode",
                       "removing tokens entry for {} to token {:?}",
                       session_endpoint, token);

                ent.remove();

                Ok(Some((conn_endpoint, token)))
            } else {
                Ok(None)
            }
        } else {
            Err(ChannelEntryShutdownError::NotFound {
                endpoint: session_endpoint.clone()
            })
        }?;

        Ok(res.map(|(endpoint, token)| {
            if endpoint != session_endpoint {
                if let Some(token) = self.tokens.remove(&endpoint) {
                    trace!(target: "outbound-channel-mode",
                           "removing tokens entry for {} to token {:?}",
                           endpoint, token);
                } else {
                    error!(target: "outbound-channel-mode",
                           "address {} not present",
                           endpoint);
                }
            }

            token
        }))
    }

    fn insert_out_ent(
        &mut self,
        session: &Option<Types::OutAuthNSession>,
        ent: ConnectorEntry<Types::Outbound>,
        endpoint: Types::Endpoint,
        token: Token
    ) -> Result<(), std::io::Error> {
        trace!(target: "outbound-channel-mode",
               "adding tokens entry for {} to token {:?}",
               endpoint, token);

        if let Some(token) = self.tokens.insert(endpoint.clone(), token) {
            error!(target: "outbound-channel-mode",
                   "tokens table contains {} (token {:?})",
                   endpoint, token);
        }

        // We also need to check to see if the address reported by the
        // session differs from the one used to connect.
        if let Some(session) = &session {
            Self::insert_out_ent_extra(
                &mut self.tokens,
                session,
                &endpoint,
                token
            )?
        }

        trace!(target: "outbound-channel-mode",
               "adding connector entry for token {:?}",
               token);

        if self.negos.insert(token, ent).is_some() {
            error!(target: "outbound-channel-mode",
                   "sessions table contains {:?}",
                   token);
        }

        Ok(())
    }

    fn insert_out_ent_extra(
        conn_tokens: &mut HashMap<Types::Endpoint, Token>,
        session: &Types::OutAuthNSession,
        endpoint: &Types::Endpoint,
        token: Token
    ) -> Result<(), std::io::Error> {
        let session_endpoint = session.get().peer_addr()?;

        if &session_endpoint != endpoint {
            trace!(target: "outbound-channel-mode",
                   "adding session tokens entry for {} to token {:?}",
                   session_endpoint, token);

            if let Some(token) =
                conn_tokens.insert(session_endpoint.clone(), token)
            {
                error!(target: "outbound-channel-mode",
                       "tokens already contains entry for {} (token {:?})",
                       endpoint, token);
            }
        }

        Ok(())
    }

    fn remove_out_ent_token(
        conn_tokens: &mut HashMap<Types::Endpoint, Token>,
        session_endpoint: Option<Types::Endpoint>,
        endpoint: &Types::Endpoint
    ) {
        if let Some(token) = conn_tokens.remove(endpoint) {
            trace!(target: "outbound-channel-mode",
                   "removing tokens entry for {} to token {:?}",
                   endpoint, token);
        } else {
            error!(target: "outbound-channel-mode",
                   "address {} not present",
                   endpoint);
        }

        if let Some(session_endpoint) = session_endpoint {
            if &session_endpoint != endpoint {
                if let Some(token) = conn_tokens.remove(&session_endpoint) {
                    trace!(target: "outbound-channel-mode",
                           "removing extra tokens entry for {} to token {:?}",
                           session_endpoint, token);
                } else {
                    error!(target: "outbound-channel-mode",
                           "address {} not present",
                           session_endpoint);
                }
            }
        }
    }
}

impl<Types> InboundChannelMode<Types>
where
    Types: NearDuplexNegoTypes
{
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
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    pub(crate) fn new(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        token: Token
    ) -> Self {
        let tokens = HashMap::new();
        let negos = HashMap::new();
        let shutdown = acceptor.shutdown_nego();

        InboundChannelMode {
            acceptor: acceptor,
            shutdown: shutdown,
            authn: authn,
            token: token,
            retry_when: None,
            tokens: tokens,
            negos: negos
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
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    ///
    /// - `size`: Expected maximum number of sessions; this will not cause an
    ///   errer if it is too low.
    pub(crate) fn with_capacity(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        token: Token,
        size: usize
    ) -> Self {
        let tokens = HashMap::with_capacity(size);
        let negos = HashMap::with_capacity(size);
        let shutdown = acceptor.shutdown_nego();

        InboundChannelMode {
            acceptor: acceptor,
            shutdown: shutdown,
            authn: authn,
            token: token,
            retry_when: None,
            tokens: tokens,
            negos: negos
        }
    }

    /// Check if this `ChannelEntry` contains any active sessions.
    #[inline]
    fn is_empty(&self) -> bool {
        match (self.tokens.is_empty(), self.negos.is_empty()) {
            (true, true) => true,
            (false, false) => false,
            _ => {
                error!(target: "inbound-channel-mode",
                       "inconsistent token and negotiation tables");

                false
            }
        }
    }

    #[inline]
    fn shutdown(
        mut self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
            self.acceptor.deregister(registry)
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
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `report_session`: A function used to report authenticated
    ///   sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `live`: All [Token]s that have pending read traffic.
    ///
    /// - `shutdown_only`: Whether to allow new incoming sessions.
    fn listen<Ctx, E, S>(
        &mut self,
        ctx: &mut Ctx,
        mut report_session: S,
        mut report_endpoint: E,
        live: &HashSet<Token>,
        shutdown_only: bool
    ) -> Result<
        (Option<Vec<Token>>, Option<Vec<Token>>),
        ChannelEntryListenError<Types::InSessionStartError>
    >
    where
        S: FnMut(
            DuplexValue<Types::InAuthNSession, Types::OutAuthNSession>
        ) -> Result<(), std::io::Error>,
        E: FnMut(Types::Endpoint),
        Ctx: RegistryCtx + TokensCtx {
        let mut creates = HashSet::with_capacity(self.negos.len());
        let mut deletes = HashSet::with_capacity(self.negos.len());

        while {
            let mut read = false;
            let mut round_deletes = Vec::with_capacity(self.negos.len());

            // Process all live existing sessions.
            for (token, ent) in self.negos.iter_mut() {
                if live.contains(token) {
                    if let Some(state) = ent.take() {
                        match state.step(
                            &mut report_endpoint,
                            ctx.registry(),
                            &self.acceptor,
                            &self.authn,
                            &self.shutdown
                        ) {
                            // Session was produced; record it.
                            Ok(StepResult::Create {
                                session: (state, session)
                            }) => {
                                // Need to insert the token entry.
                                let endpoint = session
                                    .get()
                                    .peer_addr()
                                    .map_err(|err| {
                                        ChannelEntryListenError::IO { err: err }
                                    })?;
                                let session = DuplexValue::Accept(session);

                                Self::insert_in_ent_token(
                                    &mut self.tokens,
                                    &endpoint,
                                    *token
                                );
                                *ent = Some(state);
                                report_session(session)
                                    .map_err(|err| ChannelEntryListenError::IO {
                                        err: err
                                    })?;
                            }
                            // Session shut down; clean up after it.
                            Ok(StepResult::Shutdown { endpoint }) => {
                                round_deletes.push(*token);

                                // Remove the token entry if we need to.
                                if let Some(endpoint) = endpoint {
                                    Self::remove_in_ent_token(
                                        &mut self.tokens,
                                        &endpoint
                                    );
                                }
                            }
                            // Internal traffic
                            Ok(StepResult::Internal { internal }) => {
                                *ent = Some(internal);
                            }
                            Err(err) => {
                                error!(target: "inbound-channel-mode",
                                       "negotiation step error: {}",
                                       err);
                            }
                        }
                    } else {
                        error!(target: "inbound-channel-mode",
                               "empty entry state for token {:?}",
                               token);
                    }
                }
            }

            // Delete expired entries.
            for token in round_deletes {
                trace!(target: "inbound-channel-mode",
                       "removing session entry for {:?}",
                       token);

                if self.negos.remove(&token).is_none() {
                    error!(target: "inbound-channel-mode",
                           "deleted token {:?} was not present",
                           token);
                }

                creates.remove(&token);
                deletes.insert(token);
            }

            // Pick up all incoming sessions.
            if !shutdown_only {
                let incoming = if live.contains(&self.token) {
                    start_incoming::<Ctx, _, Types>(
                        ctx,
                        &mut report_session,
                        &mut self.retry_when,
                        &mut read,
                        &mut self.acceptor,
                        &self.shutdown,
                        &self.authn
                    )?
                } else {
                    None
                };

                // Add the incoming sessions if we have them.
                if let Some(incoming) = incoming {
                    for (token, ent) in incoming {
                        self.insert_in_ent(ent, token);
                        deletes.remove(&token);
                        creates.insert(token);
                    }
                }
            }

            read
        } {}

        let creates = if !creates.is_empty() {
            Some(creates.into_iter().collect())
        } else {
            None
        };
        let deletes = if !deletes.is_empty() {
            Some(deletes.into_iter().collect())
        } else {
            None
        };

        Ok((creates, deletes))
    }

    /// Shut down an inbound (accepted) session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// If the stream was shut down, `Some(token)` where `token` is
    /// the [Token] for the stream.
    fn shutdown_accept(
        &mut self,
        registry: &Registry,
        stream: Types::InConn
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    > {
        let endpoint = stream
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownError::IO { err: err })?;

        trace!(target: "inbound-channel-mode",
               "shutting down accepted session with {}",
               endpoint);

        if let Entry::Occupied(ent) = self.tokens.entry(endpoint.clone()) {
            let accept = self
                .negos
                .get_mut(ent.get())
                .ok_or(ChannelEntryShutdownError::Inconsistent)?;
            let newaccept = accept
                .take()
                .ok_or(ChannelEntryShutdownError::NotFound {
                    endpoint: endpoint.clone()
                })?
                .shutdown(
                    registry,
                    &self.shutdown,
                    &self.acceptor.shutdown_param(),
                    stream
                )
                .map_err(|err| ChannelEntryShutdownError::Shutdown {
                    err: DuplexValue::Accept(err)
                })?;

            if newaccept.is_some() {
                *accept = newaccept;

                Ok(None)
            } else {
                let token = *ent.get();

                trace!(target: "inbound-channel-mode",
                       "removing session entry for {:?}",
                       token);

                if self.negos.remove(&token).is_none() {
                    error!(target: "connector-entry",
                           "entry for token {:?} missing",
                           ent.get());
                }

                trace!(target: "inbound-channel-mode",
                       "removing tokens entry for {} to token {:?}",
                       endpoint, token);

                ent.remove();

                Ok(Some(token))
            }
        } else {
            Err(ChannelEntryShutdownError::NotFound {
                endpoint: endpoint
            })
        }
    }

    fn insert_in_ent(
        &mut self,
        ent: SessionNegoState<Types::Inbound>,
        token: Token
    ) {
        let endpoint: Option<&Types::Endpoint> = match &ent {
            SessionNegoState::AuthN { endpoint, .. } |
            SessionNegoState::Active { endpoint } |
            SessionNegoState::Shutdown { endpoint, .. } => Some(endpoint),
            SessionNegoState::Session { .. } => None
        };

        if let Some(endpoint) = endpoint {
            Self::insert_in_ent_token(&mut self.tokens, endpoint, token)
        }

        trace!(target: "inbound-channel-mode",
               "adding connector entry for token {:?}",
               token);

        if self.negos.insert(token, Some(ent)).is_some() {
            error!(target: "inbound-channel-mode",
                   "sessions contains entry for {:?}",
                   token);
        }
    }

    fn insert_in_ent_token(
        accept_tokens: &mut HashMap<Types::Endpoint, Token>,
        endpoint: &Types::Endpoint,
        token: Token
    ) {
        trace!(target: "inbound-channel-mode",
               "adding tokens entry for {} to token {:?}",
               endpoint, token);

        if let Some(token) = accept_tokens.insert(endpoint.clone(), token) {
            error!(target: "inbound-channel-mode",
                   "tokens already contains entry for {} (token {:?})",
                   endpoint, token);
        }
    }

    fn remove_in_ent_token(
        accept_tokens: &mut HashMap<Types::Endpoint, Token>,
        endpoint: &Types::Endpoint
    ) {
        if let Some(token) = accept_tokens.remove(endpoint) {
            trace!(target: "inbound-channel-mode",
                   "removing tokens entry for {} to token {:?}",
                   endpoint, token);
        } else {
            error!(target: "inbound-channel-mode",
                   "address {} not present",
                   endpoint);
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
        let mode = OutboundChannelMode::new(config, authn);
        let mode = ChannelMode::Outbound(mode);

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
    /// - `size`: Expected maximum number of sessions; this will not cause an
    ///   error if it is too low.
    pub(crate) fn outbound_with_capacity(
        config: Types::OutConfig,
        authn: Types::OutAuthN,
        retry: Retry,
        size: usize
    ) -> Self {
        let mode = OutboundChannelMode::with_capacity(config, authn, size);
        let mode = ChannelMode::Outbound(mode);

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
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    pub(crate) fn inbound(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        retry: Retry,
        token: Token
    ) -> Self {
        let mode = InboundChannelMode::new(acceptor, authn, token);
        let mode = ChannelMode::Inbound(mode);

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
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    ///
    /// - `size`: Expected maximum number of sessions; this will not cause an
    ///   error if it is too low.
    pub(crate) fn inbound_with_capacity(
        acceptor: Types::InChannel,
        authn: Types::InAuthN,
        retry: Retry,
        token: Token,
        size: usize
    ) -> Self {
        let mode =
            InboundChannelMode::with_capacity(acceptor, authn, token, size);
        let mode = ChannelMode::Inbound(mode);

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
    /// - `out_authn`: [SessionAuthN] to use for authenticating outbound
    ///   sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    pub(crate) fn duplex(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        retry: Retry,
        token: Token
    ) -> Self {
        let mode = DuplexChannelMode::new(
            out_config, out_authn, acceptor, in_authn, token
        );
        let mode = ChannelMode::Duplex(mode);

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
    /// - `out_authn`: [SessionAuthN] to use for authenticating outbound
    ///   sessions.
    ///
    /// - `acceptor`: [NearChannel] to use for accepting connections.
    ///
    /// - `in_authn`: [SessionAuthN] to use for authenticating inbound sessions.
    ///
    /// - `retry`: [Retry] configuration to use.
    ///
    /// - `token`: [Token] associated with `acceptor` for listening for new
    ///   sessions.
    ///
    /// - `nins`: Expected maximum number of inbound sessions; this will not
    ///   cause an error if it is too low.
    ///
    /// - `nouts`: Expected maximum number of outbound sessions; this will not
    ///   cause an error if it is too low.
    pub(crate) fn duplex_with_capacity(
        out_config: Types::OutConfig,
        out_authn: Types::OutAuthN,
        acceptor: Types::InChannel,
        in_authn: Types::InAuthN,
        retry: Retry,
        token: Token,
        nins: usize,
        nouts: usize
    ) -> Self {
        let mode = DuplexChannelMode::with_capacity(
            out_config, out_authn, acceptor, in_authn, token, nins, nouts
        );
        let mode = ChannelMode::Duplex(mode);

        ChannelEntry {
            retry: retry,
            mode: mode
        }
    }

    /// Check if this `ChannelEntry` contains any active sessions.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        match &self.mode {
            ChannelMode::Duplex(ent) => ent.is_empty(),
            ChannelMode::Outbound(ent) => ent.is_empty(),
            ChannelMode::Inbound(ent) => ent.is_empty()
        }
    }

    pub(crate) fn shutdown(
        self,
        registry: &Registry
    ) -> Result<(), std::io::Error> {
        match self.mode {
            ChannelMode::Duplex(ent) => ent.shutdown(&registry),
            ChannelMode::Outbound(ent) => ent.shutdown(&registry),
            ChannelMode::Inbound(ent) => ent.shutdown(&registry)
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
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
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
    /// - `RetryResult::Success(None))`: Session negotiations are still pending
    ///   and the session will eventually be reported by
    ///   [listen](ChannelEntry::listen).
    pub(crate) fn req_stream<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        endpoint: Types::Endpoint,
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
                        SessionEntryAuthNError<
                            Types::OutAuthStartError,
                            Types::OutAuthNegoError
                        >
                    >,
                    SessionEntryShutdownError<
                        Types::OutShutdownStartError,
                        Types::OutShutdownNegoError
                    >
                >
            >
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        debug!(target: "channel-entry",
               "requesting flow with {}",
               endpoint);

        match &mut self.mode {
            ChannelMode::Duplex(ent) => ent.req_stream(
                ctx,
                &self.retry,
                endpoint,
                param
            ),
            ChannelMode::Outbound(ent) => ent.req_stream(
                ctx,
                &self.retry,
                endpoint,
                param
            ),
            ChannelMode::Inbound(_) => Err(ChannelEntryReqError::Inbound)
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
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `report_session`: A function used to report authenticated
    ///   sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `live`: All [Token]s that have pending read traffic.
    ///
    /// - `shutdown_only`: Whether to allow new incoming sessions.
    ///
    /// # Return Value
    ///
    /// A pair of `Vec`s, the first containing [Token]s that were
    /// registered, and the second containing `Token`s that were
    /// deregistered.
    fn listen<Ctx, E, S>(
        &mut self,
        ctx: &mut Ctx,
        report_session: S,
        report_endpoint: E,
        live: &HashSet<Token>
    ) -> Result<
        (Option<Vec<Token>>, Option<Vec<Token>>),
        ChannelEntryListenError<Types::InSessionStartError>
    >
    where
        S: FnMut(
            DuplexValue<Types::InAuthNSession, Types::OutAuthNSession>
        ) -> Result<(), std::io::Error>,
        E: FnMut(Types::Endpoint),
        Ctx: RegistryCtx + TokensCtx {
        match &mut self.mode {
            ChannelMode::Duplex(ent) => ent.listen(
                ctx,
                report_session,
                report_endpoint,
                &self.retry,
                live,
                false
            ),
            ChannelMode::Outbound(ent) => ent.listen(
                    report_session,
                    report_endpoint,
                    ctx.registry(),
                    &self.retry,
                    live
                )
                .map(|deletes| (None, deletes)),
            ChannelMode::Inbound(ent) => {
                ent.listen(ctx, report_session, report_endpoint, live, false)
            }
        }
    }

    fn shutdown_listen<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        live: &HashSet<Token>,
    ) -> Result<
        (Option<Vec<Token>>, Option<Vec<Token>>),
        ChannelEntryShutdownListenError<
            Types::InSessionStartError,
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        let mut sessions: Option<
                Vec<DuplexValue<
                    Rc<RefCell<Types::InAuthNSession>>,
                    Rc<RefCell<Types::OutAuthNSession>>
                >>
        > = None;

        let (creates, deletes) = match &mut self.mode {
            ChannelMode::Duplex(ent) => {
                let nnegos = ent.negos.len();

                ent.listen(
                    ctx,
                    |session| {
                        let session = match session {
                            DuplexValue::Accept(accept) => {
                                let accept = Rc::new(RefCell::new(accept));
                                let accept = DuplexValue::Accept(accept);

                                accept
                            }
                            DuplexValue::Conn(conn) => {
                                let conn = Rc::new(RefCell::new(conn));
                                let conn = DuplexValue::Conn(conn);

                                conn
                            }
                        };

                        match &mut sessions {
                            Some(sessions) => {
                                sessions.push(session);
                            }
                            None => {
                                let mut vec = Vec::with_capacity(nnegos);

                                vec.push(session);
                                sessions = Some(vec);
                            }
                        }

                        Ok(())
                    },
                    |endpoint| {
                        trace!(target: "channel-entry",
                               "ignoring inbound traffic from {}",
                               endpoint);
                    },
                    &self.retry,
                    live,
                    true
                )
                    .map_err(|err| ChannelEntryShutdownListenError::Listen {
                        err: err
                    })?
            }
            ChannelMode::Outbound(ent) => {
                let nnegos = ent.negos.len();

                let deletes = ent.listen(
                    |session| {
                        let session = match session {
                            DuplexValue::Accept(accept) => {
                                let accept = Rc::new(RefCell::new(accept));
                                let accept = DuplexValue::Accept(accept);

                                accept
                            }
                            DuplexValue::Conn(conn) => {
                                let conn = Rc::new(RefCell::new(conn));
                                let conn = DuplexValue::Conn(conn);

                                conn
                            }
                        };

                        match &mut sessions {
                            Some(sessions) => {
                                sessions.push(session);
                            }
                            None => {
                                let mut vec = Vec::with_capacity(nnegos);

                                vec.push(session);
                                sessions = Some(vec);
                            }
                        }

                        Ok(())
                    },
                    |endpoint| {
                        trace!(target: "channel-entry",
                               "ignoring inbound traffic from {}",
                               endpoint);
                    },
                    ctx.registry(),
                    &self.retry,
                    live
                )
                    .map_err(|err| ChannelEntryShutdownListenError::Listen {
                        err: err
                    })?;

                (None, deletes)
            },
            ChannelMode::Inbound(ent) => {
                let nnegos = ent.negos.len();

                ent.listen(
                    ctx,
                    |session| {
                        let session = match session {
                            DuplexValue::Accept(accept) => {
                                let accept = Rc::new(RefCell::new(accept));
                                let accept = DuplexValue::Accept(accept);

                                accept
                            }
                            DuplexValue::Conn(conn) => {
                                let conn = Rc::new(RefCell::new(conn));
                                let conn = DuplexValue::Conn(conn);

                                conn
                            }
                        };

                        match &mut sessions {
                            Some(sessions) => {
                                sessions.push(session)
                            }
                            None => {
                                let mut vec = Vec::with_capacity(nnegos);

                                vec.push(session);
                                sessions = Some(vec)
                            }
                        }

                        Ok(())
                    },
                    |endpoint| {
                        trace!(target: "channel-entry",
                               "ignoring inbound traffic from {}",
                               endpoint);
                    },
                    live,
                    true
                )
                    .map_err(|err| ChannelEntryShutdownListenError::Listen {
                        err: err
                    })?
            }
        };

        let creates = if let Some(sessions) = sessions {
            let nshutdowns = sessions.len();
            let mut shutdowns: Option<HashSet<Token>> = None;

            for session in sessions.into_iter() {
                if let Some(token) = self
                    .shutdown_stream(ctx.registry(), session)
                    .map_err(|err| ChannelEntryShutdownListenError::Shutdown {
                        err: err
                    })? {
                    match &mut shutdowns {
                        Some(shutdowns) => {
                            shutdowns.insert(token);
                        }
                        None => {
                            let mut set = HashSet::with_capacity(nshutdowns);

                            set.insert(token);

                            shutdowns = Some(set)
                        }
                    }
                }
            }

            if let Some(shutdowns) = shutdowns {
                if let Some(creates) = creates {
                    Some(creates
                         .into_iter()
                         .filter(|token| shutdowns.contains(token))
                         .collect())
                } else {
                    error!(target: "channel-entry",
                           "creates should not be None if shutdowns is Some");

                    None
                }
            } else {
                creates
            }
        } else {
            creates
        };

        Ok((creates, deletes))
    }

    /// Shut down a session.
    ///
    /// This will consume `stream` and attempt to run shutdown
    /// negotiations as far as possible.  Once `stream` is shut down,
    /// it will be deregistered.
    ///
    /// # Parameters
    ///
    /// - `registry`: The [Registry] to use to unregister shut down sessions.
    ///
    /// - `stream`: The [Session] to shut down.
    ///
    /// # Return Value
    ///
    /// If the stream was shut down, `Some(token)` where `token` is
    /// the [Token] for the stream.
    fn shutdown_stream(
        &mut self,
        registry: &Registry,
        stream: DuplexValue<Rc<RefCell<Types::InAuthNSession>>,
                            Rc<RefCell<Types::OutAuthNSession>>>
    ) -> Result<
        Option<Token>,
        ChannelEntryShutdownError<
            DuplexValue<
                SessionEntryShutdownError<
                    Types::InShutdownStartError,
                    Types::InShutdownNegoError
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >,
            Types::Endpoint
        >
    > {
        match (&mut self.mode, stream) {
            (ChannelMode::Duplex(ent), DuplexValue::Conn(stream)) => {
                let stream = Rc::into_inner(stream)
                    .ok_or(ChannelEntryShutdownError::Nonexclusive)?;
                let stream = stream.into_inner();
                let (_, stream) = stream.take();

                ent.shutdown_conn(registry, stream)
            }
            (ChannelMode::Duplex(ent), DuplexValue::Accept(stream)) => {
                let stream = Rc::into_inner(stream)
                    .ok_or(ChannelEntryShutdownError::Nonexclusive)?;
                let stream = stream.into_inner();
                let (_, stream) = stream.take();

                ent.shutdown_accept(registry, stream)
            }
            (ChannelMode::Outbound(ent), DuplexValue::Conn(stream)) => {
                let stream = Rc::into_inner(stream)
                    .ok_or(ChannelEntryShutdownError::Nonexclusive)?;
                let stream = stream.into_inner();
                let (_, stream) = stream.take();

                ent.shutdown_conn(registry, stream)
            }
            (ChannelMode::Inbound(ent), DuplexValue::Accept(stream)) => {
                let stream = Rc::into_inner(stream)
                    .ok_or(ChannelEntryShutdownError::Nonexclusive)?;
                let stream = stream.into_inner();
                let (_, stream) = stream.take();

                ent.shutdown_accept(registry, stream)
            }
            _ => Err(ChannelEntryShutdownError::Mismatch)
        }
    }
}

impl<Types> NearChannels<Types>
where
    Types: NearDuplexNegoTypes
{
    /// Get the [NearChannelID] for a given channel name.
    ///
    /// # Parameters
    ///
    /// - `name`: Name of the channel.
    #[inline]
    pub fn id(
        &self,
        name: &str
    ) -> Option<NearChannelID> {
        self.ids.get(name).cloned()
    }

    /// Get an iterator over all names and channel IDs.
    #[inline]
    pub fn ids(&self) -> Iter<'_, String, NearChannelID> {
        self.ids.iter()
    }

    /// Get the name associated with a [FarChannelID].
    ///
    /// # Parameters
    ///
    /// - `id`: [NearChannelID] for which to get the channel name.
    #[inline]
    pub fn name(
        &self,
        id: &NearChannelID
    ) -> &str {
        let idx: usize = id.0;

        &self.names[idx]
    }

    /// Get all the channel names.
    #[inline]
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

impl<Ctx, Types> Channels<Ctx> for NearChannels<Types>
where
    Types: NearDuplexNegoTypes,
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
    type ChannelID = NearChannelID;
    type Param = NearChannelParam;
    type Addr = Types::Endpoint;
    type Stream = DuplexValue<
        Rc<RefCell<Types::InAuthNSession>>,
        Rc<RefCell<Types::OutAuthNSession>>
    >;
    type OutNegoParam = Types::OutParam;
    type ParamsIter<I> = NearChannelsParamsIter<I>
    where
        I: Iterator<Item = Self::ChannelID>;
    type ParamsError = Infallible;
    type ReqStreamError = ChannelEntryReqError<
        Types::OutCreateError,
        ConnectorEntryCreateError<
            Types::OutSessionStartError,
            SessionCreateError<
                NegoEntrySessionError<
                    Types::OutSessionNegoError,
                    SessionEntryAuthNError<
                        Types::OutAuthStartError,
                        Types::OutAuthNegoError
                    >
                >,
                SessionEntryShutdownError<
                    Types::OutShutdownStartError,
                    Types::OutShutdownNegoError
                >
            >
        >
    >;

    #[inline]
    fn params<I>(
        &mut self,
        _ctx: &mut Ctx,
        channels: I
    ) -> Result<Self::ParamsIter<I>, Self::ParamsError>
    where I: Iterator<Item = Self::ChannelID> {
        Ok(NearChannelsParamsIter {
            ids: channels
        })
    }

    fn req_stream(
        &mut self,
        ctx: &mut Ctx,
        channel: &Self::ChannelID,
        _param: &Self::Param,
        endpoint: &Self::Addr,
        nego_param: &Self::OutNegoParam
    ) -> Result<
        RetryResult<(Option<Self::Stream>,
                     Option<Vec<NearChannelParam>>,
                     Option<Instant>)>,
        Self::ReqStreamError
    > {
        Ok(self.channels[channel.0]
            .req_stream(ctx, endpoint.clone(), nego_param.clone())?
            .map(|(token, out)| {
                if let Some(curr) = self.tokens.insert(token, *channel) {
                    error!(target: "near-channels",
                          "tokens table contains entry for {:?} ({})",
                          token, curr);
                }

                let out = out.map(|out| {
                    DuplexValue::Conn(Rc::new(RefCell::new(out)))
                });

                (out, None, None)
            }))
    }

    #[inline]
    fn channel_id(
        &self,
        name: &str
    ) -> Option<Self::ChannelID> {
        self.ids.get(name).cloned()
    }
}

impl<Ctx, Types> ChannelsListen<Ctx> for NearChannels<Types>
where
    Types: NearDuplexNegoTypes,
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
    type StreamIter = IntoIter<
        (Self::Addr, Self::ChannelID, Self::Param, Self::Stream)
    >;
    type EndpointIter = IntoIter<
        (Self::Addr, Self::ChannelID, Self::Param)
    >;
    type ListenError = ChannelEntryListenError<Types::InSessionStartError>;

    fn listen(
        &mut self,
        ctx: &mut Ctx,
        live: &HashSet<Token>
    ) -> Result<
        RetryResult<(
            Self::StreamIter,
            Self::EndpointIter,
            Option<Vec<(
                NearChannelID,
                Option<Vec<NearChannelParam>>,
            )>>,
            Option<Instant>
        )>,
        Self::ListenError
    > {
        let mut sessions = Vec::with_capacity(self.channels.len());
        let mut endpoints = Vec::with_capacity(self.tokens.len());

        // First, figure out which channels to visit.
        let lives: Vec<NearChannelID> = self
            .tokens
            .iter()
            .flat_map(|(token, id)| {
                if live.contains(token) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for id in lives {
            let (creates, deletes) = self.channels[id.0].listen(
                ctx,
                |session| {
                    let (peer_addr, session) = match session {
                        DuplexValue::Accept(accept) => {
                            let peer_addr = accept.get().peer_addr()?;
                            let accept = Rc::new(RefCell::new(accept));
                            let accept = DuplexValue::Accept(accept);

                            (peer_addr, accept)
                        }
                        DuplexValue::Conn(conn) => {
                            let peer_addr = conn.get().peer_addr()?;
                            let conn = Rc::new(RefCell::new(conn));
                            let conn = DuplexValue::Conn(conn);

                            (peer_addr, conn)
                        }
                    };

                    sessions.push((peer_addr, id, NearChannelParam, session));

                    Ok(())
                },
                |endpoint| endpoints.push((endpoint, id, NearChannelParam)),
                live,
            )?;

            if let Some(deletes) = deletes {
                for token in deletes {
                    if self.tokens.remove(&token).is_none() {
                        error!(target: "near-channels",
                               "token {:?} was not present in tokens table",
                               token);
                    }

                    ctx.free_token(token);
                }
            }

            if let Some(creates) = creates {
                for token in creates {
                    if let Some(curr) = self.tokens.insert(token, id.clone()) {
                        error!(target: "near-channels",
                               "tokens table contains entry for {:?} ({})",
                               token, curr);
                    }
                }
            }
        }

        Ok(RetryResult::Success(
            (sessions.into_iter(), endpoints.into_iter(), None, None)
        ))
    }
}

impl<Ctx, Types> ChannelsShutdown<Ctx> for NearChannels<Types>
where
    Types: NearDuplexNegoTypes,
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
    type ShutdownStreamError = ChannelEntryShutdownError<
        DuplexValue<
            SessionEntryShutdownError<
                Types::InShutdownStartError,
                Types::InShutdownNegoError
            >,
            SessionEntryShutdownError<
                Types::OutShutdownStartError,
                Types::OutShutdownNegoError
            >
        >,
        Types::Endpoint
    >;
    type ShutdownListenError = ChannelEntryShutdownListenError<
        Types::InSessionStartError,
        DuplexValue<
            SessionEntryShutdownError<
                Types::InShutdownStartError,
                Types::InShutdownNegoError
            >,
            SessionEntryShutdownError<
                Types::OutShutdownStartError,
                Types::OutShutdownNegoError
            >
        >,
        Types::Endpoint
    >;

    fn shutdown_stream(
        &mut self,
        ctx: &mut Ctx,
        channel: &NearChannelID,
        _param: &Self::Param,
        stream: DuplexValue<Rc<RefCell<Types::InAuthNSession>>,
                            Rc<RefCell<Types::OutAuthNSession>>>
    ) -> Result<
        RetryResult<(
            Option<Vec<Self::Param>>,
            Option<Instant>
        )>,
        Self::ShutdownStreamError
    > {
        if let Some(token) = self
            .channels[channel.0]
            .shutdown_stream(ctx.registry(), stream)? {
            if self.tokens.remove(&token).is_none() {
                error!(target: "near-channels",
                       "token {:?} was not present in tokens table",
                       token);
            }

            ctx.free_token(token);
        }

        Ok(RetryResult::Success((None, None)))
    }

    fn shutdown_listen(
        mut self,
        ctx: &mut Ctx,
        live: &HashSet<Token>
    ) -> Result<Option<(Self, Option<Instant>)>, Self::ShutdownListenError> {
        debug!(target: "near-channels",
               "listening for shutdown");

        // First, figure out which channels to visit.
        let lives: Vec<NearChannelID> = self
            .tokens
            .iter()
            .flat_map(|(token, id)| {
                if live.contains(token) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Visit all live channels and listen for shutdown.
        for id in lives {
            let (creates, deletes) = self
                .channels[id.0]
                .shutdown_listen(ctx, live)?;

            if let Some(creates) = creates {
                for token in creates {
                    if let Some(curr) = self.tokens.insert(token, id.clone()) {
                        error!(target: "near-channels",
                               "tokens table contains entry for {:?} ({})",
                               token, curr);
                    }
                }
            }

            if let Some(deletes) = deletes {
                for token in deletes {
                    if self.tokens.remove(&token).is_none() {
                        error!(target: "near-channels",
                               "token {:?} was not present in tokens table",
                               token);
                    }

                    ctx.free_token(token);
                }
            }
        }

        // See if we can shut down all channels.
        if self.channels.iter().all(|ent| ent.is_empty()) {
            // We can; we should be able to shut down now.
            debug!(target: "near-channels",
                   "shutting down near channels");

            let mut errs: Option<Vec<(NearChannelID, std::io::Error)>> = None;
            let nchannels = self.channels.len();

            for (id, ent) in self.channels.into_iter().enumerate() {
                if let Err(err) = ent.shutdown(ctx.registry()) {
                    let id = NearChannelID(id);

                    match &mut errs {
                        Some(errs) => {
                            errs.push((id, err))
                        }
                        None => {
                            let mut vec = Vec::with_capacity(nchannels);

                            vec.push((id, err));
                            errs = Some(vec)
                        }
                    }
                }
            }

            if let Some(errs) = errs {
                Err(ChannelEntryShutdownListenError::Finish { errs: errs })
            } else {
                Ok(None)
            }
        } else {
            // There are still live channels.
            trace!(target: "near-channels",
                   "live channels still exist");

            Ok(Some((self, None)))
        }
    }
}

impl<I> Iterator for NearChannelsParamsIter<I>
where I: Iterator<Item = NearChannelID> {
    type Item = (NearChannelID,
                 RetryResult<(Vec<NearChannelParam>, Option<Instant>)>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.ids.next()
            .map(|id| (id, RetryResult::Success((vec![NearChannelParam],
                                                 None))))
    }
}

impl<I> FusedIterator for NearChannelsParamsIter<I>
where
    I: Iterator<Item = NearChannelID> {
}

impl<'a, Ctx, Types> CreateWithParam<&'a mut Ctx> for NearChannels<Types>
where
    Types: NearDuplexNegoTypes,
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
    type Config = NearChannelsConfig<
        Types::InConfig,
        Types::OutConfig,
        Types::InAuthNConfig,
        Types::OutAuthNConfig
    >;
    type CreateError = NearChannelsCreateError<
        Types::InAuthCreateError,
        Types::OutAuthCreateError,
        Types::InChannelCreateError
    >;

    fn create(
        config: Self::Config,
        ctx: &'a mut Ctx,
    ) -> Result<Self, Self::CreateError> {
        let (channel_configs, default_inbound_authn, default_outbound_authn,
             default_retry, default_nsessions) = config.take();

        // Ensure no id collisions.
        let mut names = HashSet::with_capacity(channel_configs.len());

        for config in channel_configs.iter() {
            if !names.insert(config.name()) {
                return Err(NearChannelsCreateError::Collision {
                    name: config.name().to_string()
                })
            }
        }

        let mut ids = HashMap::with_capacity(channel_configs.len());
        let mut tokens = HashMap::with_capacity(channel_configs.len());
        let mut names = Vec::with_capacity(channel_configs.len());
        let mut channels = Vec::with_capacity(channel_configs.len());

        // Create each channel.
        for config in channel_configs.into_iter() {
            match config {
                NearChannelEntryConfig::Outbound { outbound } => {
                    let (name, connect, authn, retry, nsessions) =
                        outbound.take();
                    let authn = authn.unwrap_or(default_outbound_authn.clone());
                    let retry = retry.unwrap_or(default_retry.clone());
                    let nsessions = nsessions.or(default_nsessions);

                    info!(target: "near-channels",
                          "creating outbound near channel \"{}\"",
                          name);

                    let authn = Types::OutAuthN::create(authn)
                        .map_err(|err| NearChannelsCreateError::OutAuth {
                            err: err
                        })?;
                    let channel = match nsessions {
                        Some(nsessions) => ChannelEntry::outbound_with_capacity(
                            connect,
                            authn,
                            retry,
                            nsessions
                        ),
                        None => ChannelEntry::outbound(connect, authn, retry)
                    };
                    let id = NearChannelID(channels.len());

                    channels.push(channel);
                    names.push(name.clone());

                    if let Some(curr) = ids.insert(name.clone(), id) {
                        error!(target: "near-channels",
                               "entry for name \"{}\" already existed: {}",
                               name, curr);
                    }

                }
                NearChannelEntryConfig::Inbound { inbound } => {
                    let (name, listen, authn, retry, nsessions) =
                        inbound.take();
                    let authn = authn.unwrap_or(default_inbound_authn.clone());
                    let retry = retry.unwrap_or(default_retry.clone());
                    let nsessions = nsessions.or(default_nsessions);

                    info!(target: "near-channels",
                          "creating inbound near channel \"{}\"",
                          name);

                    let authn = Types::InAuthN::create(authn)
                        .map_err(|err| NearChannelsCreateError::InAuth {
                            err: err
                        })?;
                    let acceptor = Types::InChannel::create(ctx, listen)
                        .map_err(|err| NearChannelsCreateError::Inbound {
                            err: err
                        })?;
                    let token = ctx.token();
                    let channel = match nsessions {
                        Some(nsessions) => ChannelEntry::inbound_with_capacity(
                            acceptor,
                            authn,
                            retry,
                            token,
                            nsessions
                        ),
                        None => ChannelEntry::inbound(
                            acceptor,
                            authn,
                            retry,
                            token
                        )
                    };
                    let id = NearChannelID(channels.len());

                    channels.push(channel);
                    names.push(name.clone());

                    if let Some(curr) = ids.insert(name.clone(), id) {
                        error!(target: "near-channels",
                               "entry for name \"{}\" already existed: {}",
                               name, curr);
                    }

                    if let Some(curr) = tokens.insert(token, id) {
                        error!(target: "near-channels",
                               "entry for token {:?} already existed: {}",
                               token, curr);
                    }
                }
                NearChannelEntryConfig::Duplex { duplex } => {
                    let (name, listen, connect, in_authn, out_authn,
                         retry, nsessions) = duplex.take();
                    let out_authn = out_authn
                        .unwrap_or(default_outbound_authn.clone());
                    let in_authn = in_authn
                        .unwrap_or(default_inbound_authn.clone());
                    let retry = retry.unwrap_or(default_retry.clone());
                    let nsessions = nsessions.or(default_nsessions);

                    info!(target: "near-channels",
                          "creating duplex near channel \"{}\"",
                          name);

                    let out_authn = Types::OutAuthN::create(out_authn)
                        .map_err(|err| NearChannelsCreateError::OutAuth {
                            err: err
                        })?;
                    let in_authn = Types::InAuthN::create(in_authn)
                        .map_err(|err| NearChannelsCreateError::InAuth {
                            err: err
                        })?;
                    let acceptor = Types::InChannel::create(ctx, listen)
                        .map_err(|err| NearChannelsCreateError::Inbound {
                            err: err
                        })?;
                    let token = ctx.token();
                    let channel = match nsessions {
                        Some(nsessions) => ChannelEntry::duplex_with_capacity(
                            connect,
                            out_authn,
                            acceptor,
                            in_authn,
                            retry,
                            token,
                            nsessions,
                            nsessions
                        ),
                        None => ChannelEntry::duplex(
                            connect,
                            out_authn,
                            acceptor,
                            in_authn,
                            retry,
                            token,
                        )
                    };
                    let id = NearChannelID(channels.len());

                    channels.push(channel);
                    names.push(name.clone());

                    if let Some(curr) = ids.insert(name.clone(), id) {
                        error!(target: "near-channels",
                               "entry for name \"{}\" already existed: {}",
                               name, curr);
                    }

                    if let Some(curr) = tokens.insert(token, id) {
                        error!(target: "near-channels",
                               "entry for token {:?} already existed: {}",
                               token, curr);
                    }
                }
            }
        }

        Ok(NearChannels {
            ids: ids,
            names: names,
            channels: channels,
            tokens: tokens
        })
    }
}

impl<Accept, Conn> Read for DuplexValue<Accept, Conn>
where
    Conn: Read,
    Accept: Read
{
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read(buf),
            DuplexValue::Accept(accept) => accept.read(buf)
        }
    }

    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read_vectored(buf),
            DuplexValue::Accept(accept) => accept.read_vectored(buf)
        }
    }

    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.read_exact(buf),
            DuplexValue::Accept(accept) => accept.read_exact(buf)
        }
    }
}

impl<Accept, Conn> Write for DuplexValue<Accept, Conn>
where
    Conn: Write,
    Accept: Write
{
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.write(buf),
            DuplexValue::Accept(accept) => accept.write(buf)
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
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
            DuplexValue::Accept(accept) => accept.write_vectored(buf)
        }
    }

    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), std::io::Error> {
        match self {
            DuplexValue::Conn(conn) => conn.write_all(buf),
            DuplexValue::Accept(accept) => accept.write_all(buf)
        }
    }
}

impl<Accept, Conn> Session for DuplexValue<Accept, Conn>
where Accept: Session<LocalAddr = Conn::LocalAddr, PeerAddr = Conn::PeerAddr>,
      Conn: Session
{
    type LocalAddr = Accept::LocalAddr;
    type PeerAddr = Accept::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, std::io::Error> {
        match self {
            DuplexValue::Accept(accept) => accept.local_addr(),
            DuplexValue::Conn(accept) => accept.local_addr()
        }
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, std::io::Error> {
        match self {
            DuplexValue::Accept(accept) => accept.peer_addr(),
            DuplexValue::Conn(accept) => accept.peer_addr()
        }
    }
}

impl<Conn, Accept> ScopedError for DuplexValue<Conn, Accept>
where
    Conn: ScopedError,
    Accept: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            DuplexValue::Accept(accept) => accept.scope(),
            DuplexValue::Conn(conn) => conn.scope(),
        }
    }
}

impl<Start, Auth> ScopedError for SessionEntryAuthNError<Start, Auth>
where
    Start: ScopedError,
    Auth: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionEntryAuthNError::Start { err } => err.scope(),
            SessionEntryAuthNError::AuthN { err } => err.scope()
        }
    }
}

impl<Nego, AuthN> ScopedError for NegoEntrySessionError<Nego, AuthN>
where
    Nego: ScopedError,
    AuthN: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            NegoEntrySessionError::Nego { err } => err.scope(),
            NegoEntrySessionError::AuthN { err } => err.scope()
        }
    }
}

impl<Session, AuthN, Shutdown> ScopedError
    for SessionEntryStepError<Session, AuthN, Shutdown>
where
    Session: ScopedError,
    AuthN: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionEntryStepError::Session { err } => err.scope(),
            SessionEntryStepError::AuthN { err } => err.scope(),
            SessionEntryStepError::Shutdown { err } => err.scope(),
            SessionEntryStepError::IO { err } => err.scope()
        }
    }
}

impl<Start, Shutdown> ScopedError
    for SessionEntryShutdownError<Start, Shutdown>
where Start: ScopedError,
      Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionEntryShutdownError::Shutdown { err } => err.scope(),
            SessionEntryShutdownError::IO { err } => err.scope(),
            SessionEntryShutdownError::NotActive => ErrorScope::Unrecoverable
        }
    }
}

impl<Session, Shutdown> ScopedError for SessionCreateError<Session, Shutdown>
where Session: ScopedError,
      Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionCreateError::Shutdown { err } => err.scope(),
            SessionCreateError::Session { err } => err.scope(),
            SessionCreateError::IO { err } => err.scope()
        }
    }
}

impl<Create, Nego> ScopedError for ConnectorEntryCreateError<Create, Nego>
where
    Create: ScopedError,
    Nego: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ConnectorEntryCreateError::Start { err } => err.scope(),
            ConnectorEntryCreateError::Nego { err } => err.scope()
        }
    }
}

impl<Start> ScopedError for ChannelEntryListenError<Start>
where Start: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryListenError::Start { err } => err.scope(),
            ChannelEntryListenError::IO { err } => err.scope(),
        }
    }
}

impl<Start, Shutdown, Endpoint> ScopedError
    for ChannelEntryShutdownListenError<Start, Shutdown, Endpoint>
where Start: ScopedError,
      Shutdown: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryShutdownListenError::Listen { err } => err.scope(),
            ChannelEntryShutdownListenError::Shutdown { err } => err.scope(),
            ChannelEntryShutdownListenError::Finish { .. } =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Channel, Entry> ScopedError for ChannelEntryReqError<Channel, Entry>
where Channel: ScopedError,
      Entry: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryReqError::Channel { err } => err.scope(),
            ChannelEntryReqError::Entry { err } => err.scope(),
            ChannelEntryReqError::IO { err } => err.scope(),
            ChannelEntryReqError::Collision => ErrorScope::Session,
            ChannelEntryReqError::Inbound => ErrorScope::Unrecoverable
        }
    }
}

impl<Shutdown, Endpoint> ScopedError
    for ChannelEntryShutdownError<Shutdown, Endpoint>
where
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryShutdownError::Shutdown { err } => err.scope(),
            ChannelEntryShutdownError::IO { err } => err.scope(),
            ChannelEntryShutdownError::NotFound { .. } |
            ChannelEntryShutdownError::Inconsistent |
            ChannelEntryShutdownError::Mismatch |
            ChannelEntryShutdownError::Nonexclusive =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Conn, Accept> Display for DuplexValue<Conn, Accept>
where Conn: Display,
      Accept: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            DuplexValue::Conn(conn) => conn.fmt(f),
            DuplexValue::Accept(accept) => accept.fmt(f),
        }
    }
}

impl Display for NearChannelParam {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "near channel param")
    }
}

impl Display for NearChannelID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "near channel {}", self.0)
    }
}

impl<Accept, AuthN> Display for NearChannelsEntryCreateError<Accept, AuthN>
where
    Accept: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsEntryCreateError::Accept { err } => err.fmt(f),
            NearChannelsEntryCreateError::AuthN { err } => err.fmt(f)
        }
    }
}

impl<Conn, Req> Display for NearChannelsEntrySessionError<Conn, Req>
where
    Conn: Display,
    Req: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsEntrySessionError::Req { err } => err.fmt(f),
            NearChannelsEntrySessionError::Conn { err } => err.fmt(f),
        }
    }
}

impl<Session, AuthN, Shutdown> Display
    for SessionEntryStepError<Session, AuthN, Shutdown>
where
    Session: Display,
    AuthN: Display,
    Shutdown: Display
{
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
where
    Start: Display,
    Auth: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryAuthNError::Start { err } => err.fmt(f),
            SessionEntryAuthNError::AuthN { err } => err.fmt(f)
        }
    }
}

impl<Session, Shutdown> Display for SessionEntryCreateError<Session, Shutdown>
where
    Session: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryCreateError::IO { err } => err.fmt(f),
            SessionEntryCreateError::Session { err } => err.fmt(f),
            SessionEntryCreateError::Shutdown { err } => err.fmt(f)
        }
    }
}

impl<Start, Shutdown> Display for SessionEntryShutdownError<Start, Shutdown>
where
    Start: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryShutdownError::Shutdown { err } => err.fmt(f),
            SessionEntryShutdownError::IO { err } => err.fmt(f),
            SessionEntryShutdownError::NotActive => {
                write!(f, "session is not active")
            }
        }
    }
}

impl<Nego, AuthN> Display for NegoEntrySessionError<Nego, AuthN>
where
    Nego: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NegoEntrySessionError::Nego { err } => err.fmt(f),
            NegoEntrySessionError::AuthN { err } => err.fmt(f)
        }
    }
}

impl<Session, Shutdown> Display for SessionCreateError<Session, Shutdown>
where
    Session: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionCreateError::IO { err } => err.fmt(f),
            SessionCreateError::Session { err } => err.fmt(f),
            SessionCreateError::Shutdown { err } => err.fmt(f)
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
            ConnectorEntryCreateError::Nego { err } => err.fmt(f)
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
            ConnectorEntryStepError::Step { err } => err.fmt(f)
        }
    }
}

impl<Start> Display for ChannelEntryListenError<Start>
where Start: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ChannelEntryListenError::Start { err } => err.fmt(f),
            ChannelEntryListenError::IO { err } => err.fmt(f),
        }
    }
}

impl<Start, Shutdown, Endpoint> Display
    for ChannelEntryShutdownListenError<Start, Shutdown, Endpoint>
where
    Start: Display,
    Shutdown: Display,
    Endpoint: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ChannelEntryShutdownListenError::Listen { err } => err.fmt(f),
            ChannelEntryShutdownListenError::Shutdown { err } => err.fmt(f),
            ChannelEntryShutdownListenError::Finish { errs } => {
                writeln!(f, "errors shutting down channels:")?;

                for (id, err) in errs.into_iter() {
                    writeln!(f, "{}: {}", id, err)?;
                }

                Ok(())
            }
        }
    }
}

impl<Shutdown, Endpoint> Display
    for ChannelEntryShutdownError<Shutdown, Endpoint>
where
    Shutdown: Display,
    Endpoint: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ChannelEntryShutdownError::Shutdown { err } => err.fmt(f),
            ChannelEntryShutdownError::IO { err } => err.fmt(f),
            ChannelEntryShutdownError::NotFound { endpoint } => {
                write!(f, "no entry for {}", endpoint)
            }
            ChannelEntryShutdownError::Inconsistent => {
                write!(f, "inconsistent token and session tables")
            }
            ChannelEntryShutdownError::Mismatch => {
                write!(f, "wrong type of stream for this channel entry")
            }
            ChannelEntryShutdownError::Nonexclusive => {
                write!(f, "shutdown channel was not owned exclusively")
            }
        }
    }
}

impl<Channel, Entry> Display for ChannelEntryReqError<Channel, Entry>
where Channel: Display,
      Entry: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            ChannelEntryReqError::Channel { err } => err.fmt(f),
            ChannelEntryReqError::Entry { err } => err.fmt(f),
            ChannelEntryReqError::IO { err } => err.fmt(f),
            ChannelEntryReqError::Collision =>
                write!(f, "endpoint was already registered"),
            ChannelEntryReqError::Inbound =>
                write!(f, "requesting stream from inbound-only channel"),
        }
    }
}

impl<InAuth, OutAuth, Inbound> Display
    for NearChannelsCreateError<InAuth, OutAuth, Inbound>
where OutAuth: Display,
      InAuth: Display,
      Inbound: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsCreateError::OutAuth { err } => err.fmt(f),
            NearChannelsCreateError::InAuth { err } => err.fmt(f),
            NearChannelsCreateError::Inbound { err } => err.fmt(f),
            NearChannelsCreateError::Collision { name } =>
                write!(f, "multiple channels with id \"{}\"", name)
        }
    }
}

#[cfg(test)]
use std::convert::TryFrom;
#[cfg(test)]
use std::iter::empty;
#[cfg(test)]
use std::iter::once;
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
use crate::config::tls::TLSClientConfig;
#[cfg(test)]
use crate::config::tls::TLSServerConfig;
#[cfg(test)]
use crate::config::CompoundNearAcceptorConfig;
#[cfg(test)]
use crate::config::CompoundNearConnectorParam;
#[cfg(test)]
use crate::config::CompoundNearConnectorPartialConfig;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::near::compound::CompoundNearAcceptor;
#[cfg(test)]
use crate::near::compound::CompoundNearClientConn;
#[cfg(test)]
use crate::near::compound::CompoundNearCredential;
#[cfg(test)]
use crate::near::compound::CompoundNearConcreteAddr;
#[cfg(test)]
use crate::near::compound::CompoundNearServerConn;
#[cfg(test)]
use crate::near::read_one;
#[cfg(test)]
use crate::near::types::CompoundAcceptorNegoTypes;
#[cfg(test)]
use crate::near::types::CompoundConnectorNegoTypes;
#[cfg(test)]
use crate::near::types::SimpleNearDuplexNegoTypes;
#[cfg(test)]
use crate::near::write_one;
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
type TestAcceptorNegoTypes = CompoundAcceptorNegoTypes<
    TrivialAuthN<TestPrin, CompoundNearServerConn>,
    TLSServerConfig
>;

#[cfg(test)]
type TestConnectorNegoTypes = CompoundConnectorNegoTypes<
    TrivialAuthN<TestPrin, CompoundNearClientConn>,
    TLSClientConfig
>;

#[cfg(test)]
type TestDuplexNegoTypes =
    SimpleNearDuplexNegoTypes<TestAcceptorNegoTypes, TestConnectorNegoTypes>;

#[cfg(test)]
struct TestCtx<'a, Ctx, I>
where Ctx: NSNameCachesCtx,
      I: Iterator<Item = Token>
{
    registry: &'a Registry,
    inner: &'a mut Ctx,
    freed: Vec<Token>,
    tokens: I
}

#[cfg(test)]
impl<'a, Ctx, I> NSNameCachesCtx for TestCtx<'a, Ctx, I>
where Ctx: NSNameCachesCtx,
      I: Iterator<Item = Token>
{
    type NameCaches = Ctx::NameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut Self::NameCaches {
        self.inner.name_caches()
    }
}

#[cfg(test)]
impl<'a, Ctx, I> RegistryCtx for TestCtx<'a, Ctx, I>
where Ctx: NSNameCachesCtx,
      I: Iterator<Item = Token>
{
    #[inline]
    fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(test)]
impl<'a, Ctx, I> TokensCtx for TestCtx<'a, Ctx, I>
where Ctx: NSNameCachesCtx,
      I: Iterator<Item = Token>
{
    #[inline]
    fn token(&mut self) -> Token {
        self.tokens.next()
            .expect("Expected token")
    }

    #[inline]
    fn free_token(
        &mut self,
        token: Token
    ) {
        self.freed.push(token)
    }
}

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
    endpoint: Types::Endpoint,
    param: Types::OutParam,
    token: Token
) -> Types::OutAuthNSession
where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes {
    let mut gentok = once(token).peekable();

    match entry
        .req_stream(
            &mut TestCtx {
                registry: poll.registry(),
                inner: ctx,
                freed: Vec::new(),
                tokens: empty()
            },
            endpoint,
            param
        )
        .expect("Expected success")
    {
        RetryResult::Success((newtok, Some(out))) => {
            trace!(target: "get-out-session",
                       "got outbound session immediately");

            assert_eq!(newtok, token);

            out
        }
        RetryResult::Success((newtok, None)) => {
            let mut events = Events::with_capacity(2);
            let mut sessions = Vec::new();
            let mut endpoints = HashSet::new();
            let mut live = HashSet::new();
            let mut count = 0;

            assert_eq!(newtok, token);

            while sessions.is_empty() {
                trace!(target: "get-out-session",
                       "polling");

                if count > 10 {
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

                let (creates, deletes) = entry
                    .listen(
                        &mut TestCtx {
                            registry: poll.registry(),
                            inner: ctx,
                            freed: Vec::new(),
                            tokens: &mut gentok
                        },
                        |session| {
                            sessions.push(session);

                            Ok(())
                        },
                        |endpoint| {
                            endpoints.insert(endpoint);
                        },
                        &live
                    )
                    .expect("Expected success");

                assert!(deletes.is_none());

                if let Some(mut creates) = creates {
                    let newtok = creates.pop().expect("Expected some");

                    assert_eq!(token, newtok);
                }

                live.clear();
            }

            trace!(target: "get-out-session",
                   "got outbound session");

            assert!(endpoints.is_empty());

            if let DuplexValue::Conn(out) = sessions
                .pop()
                .expect("Expected some") {
                out
            } else {
                panic!("expected outbound sesssion")
            }
        }
        _ => panic!("Should not see retry delay here")
    }
}

#[cfg(test)]
fn get_in_session<Types, Ctx>(
    ctx: &mut Ctx,
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    token: Token
) -> Types::InAuthNSession
where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes {
    let mut gentok = vec![token, Token(7777)].into_iter().peekable();
    let mut events = Events::with_capacity(2);
    let mut sessions = Vec::new();
    let mut endpoints = HashSet::new();
    let mut live = HashSet::new();
    let mut count = 0;

    while sessions.is_empty() {
        trace!(target: "get-in-session",
               "polling");

        if count > 10 {
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

        let (creates, deletes) = entry
            .listen(
                &mut TestCtx {
                    registry: poll.registry(),
                    inner: ctx,
                    freed: Vec::new(),
                    tokens: &mut gentok
                },
                |session| {
                    sessions.push(session);

                    Ok(())
                },
                |endpoint| {
                    endpoints.insert(endpoint);
                },
                &live
            )
            .expect("Expected success");

        assert!(deletes.is_none());

        if let Some(mut creates) = creates {
            let newtok = creates.pop().expect("Expected some");

            assert_eq!(token, newtok);
        }

        live.clear();
    }

    trace!(target: "get-in-session",
           "got inbound session");

    assert!(endpoints.is_empty());

    if let DuplexValue::Accept(out) = sessions
        .pop()
        .expect("Expected some") {
        out
    } else {
        panic!("expected outbound sesssion")
    }
}

#[cfg(test)]
fn shutdown_out_session<Types, Ctx>(
    ctx: &mut Ctx,
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    stream: Types::OutAuthNSession,
    token: Token
) where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes {
    let mut gentok = once(token).peekable();
    let (_, stream) = stream.take();

    match entry
        .shutdown_stream(poll.registry(), DuplexValue::Conn(stream))
        .expect("Expected success")
    {
        Some(deadtok) => {
            trace!(target: "shutdown-out-session",
                       "shut down outbound session immediately");

            assert_eq!(deadtok, token);
        }
        None => {
            let mut events = Events::with_capacity(2);
            let mut sessions = Vec::new();
            let mut endpoints = HashSet::new();
            let mut live = HashSet::new();
            let mut count = 0;

            loop {
                trace!(target: "shutdown-out-session",
                       "polling");

                if count > 10 {
                    panic!("Timeout")
                }

                poll.poll(&mut events, Some(Duration::from_secs(1)))
                    .expect("Expected success");

                count += 1;

                trace!(target: "shutdown-out-session",
                       "polling returned");

                for event in events.iter() {
                    trace!(target: "shutdown-out-session",
                           "event for token {:?}", event.token());

                    live.insert(event.token());
                }

                trace!(target: "shutdown-out-session",
                       "listening");

                let (creates, deletes) = entry
                    .listen(
                        &mut TestCtx {
                            registry: poll.registry(),
                            inner: ctx,
                            freed: Vec::new(),
                            tokens: &mut gentok
                        },
                        |session| {
                            sessions.push(session);

                            Ok(())
                        },
                        |endpoint| {
                            endpoints.insert(endpoint);
                        },
                        &live
                    )
                    .expect("Expected success");

                assert!(creates.is_none());

                if let Some(mut deletes) = deletes {
                    let newtok = deletes.pop().expect("Expected some");

                    assert_eq!(token, newtok);

                    break;
                }

                live.clear();
            }

            trace!(target: "shutdown-out-session",
                   "got outbound session");

            assert!(sessions.is_empty());
            assert!(endpoints.is_empty());
        }
    }
}

#[cfg(test)]
fn shutdown_in_session<Types, Ctx>(
    ctx: &mut Ctx,
    entry: &mut ChannelEntry<Types>,
    poll: &mut Poll,
    stream: Types::InAuthNSession,
    token: Token
) where
    Ctx: NSNameCachesCtx,
    Types: NearDuplexNegoTypes {
    let mut gentok = once(token).peekable();
    let (_, stream) = stream.take();

    match entry
        .shutdown_stream(poll.registry(), DuplexValue::Accept(stream))
        .expect("Expected success")
    {
        Some(deadtok) => {
            trace!(target: "shutdown-in-session",
                       "shut down outbound session immediately");

            assert_eq!(deadtok, token);
        }
        None => {
            let mut events = Events::with_capacity(2);
            let mut sessions = Vec::new();
            let mut endpoints = HashSet::new();
            let mut live = HashSet::new();
            let mut count = 0;

            loop {
                trace!(target: "shutdown-in-session",
                       "polling");

                if count > 10 {
                    panic!("Timeout")
                }

                poll.poll(&mut events, Some(Duration::from_secs(1)))
                    .expect("Expected success");

                count += 1;

                trace!(target: "shutdown-in-session",
                       "polling returned");

                for event in events.iter() {
                    trace!(target: "get-out-session",
                           "event for token {:?}", event.token());

                    live.insert(event.token());
                }

                trace!(target: "shutdown-in-session",
                       "listening");

                let (creates, deletes) = entry
                    .listen(
                        &mut TestCtx {
                            registry: poll.registry(),
                            inner: ctx,
                            freed: Vec::new(),
                            tokens: &mut gentok
                        },
                        |session| {
                            sessions.push(session);

                            Ok(())
                        },
                        |endpoint| {
                            endpoints.insert(endpoint);
                        },
                        &live
                    )
                    .expect("Expected success");

                assert!(creates.is_none());

                if let Some(mut deletes) = deletes {
                    let newtok = deletes.pop().expect("Expected some");

                    assert_eq!(token, newtok);

                    break;
                }

                live.clear();
            }

            trace!(target: "shutdown-in-session",
                   "got outbound session");

            assert!(sessions.is_empty());
            assert!(endpoints.is_empty());
        }
    }
}

#[cfg(test)]
fn entry_test<Types>(
    mut nscaches: SharedNSNameCaches,
    mut acceptor: Types::InChannel,
    out_config: Types::OutConfig,
    in_authn: Types::InAuthN,
    out_authn: Types::OutAuthN,
    endpoint: Types::Endpoint,
    param: Types::OutParam,
    listen: Token,
    in_session: Token,
    out_session: Token
) where
    Types: NearDuplexNegoTypes,
    Types::InChannel: 'static + Send,
    Types::InAuthN: 'static + Send,
    Types::OutConfig: 'static + Send,
    Types::OutAuthN: 'static + Send,
    Types::OutParam: 'static + Send,
    Types::Endpoint: 'static + Send {
    let mut listen_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let mut entry: ChannelEntry<Types> =
            ChannelEntry::inbound(acceptor, in_authn, Retry::default(), listen);

        assert!(entry.is_empty());

        trace!(target: "entry-test-server",
               "listening");

        let mut session: Types::InAuthNSession =
            get_in_session(&mut listen_nscaches, &mut entry,
                           &mut poll, in_session);

        assert!(!entry.is_empty());

        let mut buf = [0; FIRST_BYTES.len()];

        trace!(target: "entry-test-server",
               "reading message");

        read_one(session.get_mut(), &mut poll, in_session, &mut buf)
            .expect("Expected success");

        trace!(target: "entry-test-server",
               "writing message");

        write_one(session.get_mut(), &mut poll, in_session, &SECOND_BYTES)
            .expect("Expected success");

        trace!(target: "entry-test-server",
               "shutting down");

        shutdown_in_session(&mut listen_nscaches, &mut entry, &mut poll,
                            session, in_session);

        assert!(entry.is_empty());

        assert_eq!(FIRST_BYTES, buf);
    });

    let send = spawn(move || {
        let mut entry: ChannelEntry<Types> =
            ChannelEntry::outbound(out_config, out_authn, Retry::default());

        assert!(entry.is_empty());

        trace!(target: "entry-test-client",
               "connecting");

        let mut poll = Poll::new().expect("Expected success");
        let mut session: Types::OutAuthNSession = get_out_session(
            &mut nscaches,
            &mut entry,
            &mut poll,
            endpoint,
            param,
            out_session
        );

        assert!(!entry.is_empty());

        trace!(target: "entry-test-client",
               "writing message");

        write_one(session.get_mut(), &mut poll, out_session, &FIRST_BYTES)
            .expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        trace!(target: "entry-test-client",
               "reading message");

        read_one(session.get_mut(), &mut poll, out_session, &mut buf)
            .expect("Expected success");

        trace!(target: "entry-test-client",
               "shutting down");

        shutdown_out_session(&mut nscaches, &mut entry,
                             &mut poll, session, out_session);

        assert!(entry.is_empty());
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[cfg(test)]
fn compound_entry_test(
    server_conf: &str,
    client_conf: &str,
    endpoint: CompoundNearConcreteAddr,
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
    let acceptor = CompoundNearAcceptor::create(&mut nscaches, server_conf)
        .expect("Expected success");
    let listen = Token(0);
    let in_session = Token(1);
    let out_session = Token(0);

    entry_test::<TestDuplexNegoTypes>(
        nscaches,
        acceptor,
        client_conf,
        TrivialAuthN::default(),
        TrivialAuthN::default(),
        endpoint,
        param,
        listen,
        in_session,
        out_session
    )
}

#[test]
fn test_unix() {
    init();

    const SERVER_CONF: &'static str =
        concat!("unix-stream:\n", "  path: test_near_channels_unix.sock");
    const CLIENT_CONF: &'static str = concat!("unix-stream:");
    let endpoint = CompoundNearConcreteAddr::Unix {
        unix: UnixSocketAddr::try_from("test_near_channels_unix.sock")
            .expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, None)
}

#[test]
fn test_tcp() {
    init();

    const SERVER_CONF: &'static str =
        concat!("tcp:\n", "  addr: ::0\n", "  port: 8100\n");
    const CLIENT_CONF: &'static str = concat!("tcp:",);
    let endpoint = CompoundNearConcreteAddr::TCP {
        tcp: "[::1]:8100".parse().expect("Expected success")
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
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
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
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  unix-stream:",
    );
    const PARAM_CONF: &'static str =
        concat!("tls:\n", "  verify-endpoint: test-server.nowhere.com",);
    let endpoint = CompoundNearConcreteAddr::Unix {
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
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
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
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  client-key: tests/data/certs/client/private/test_client_key.pem\n",
        "  verify-endpoint: test-server.nowhere.com\n",
        "  tcp:",
    );
    const PARAM_CONF: &'static str =
        concat!("tls:\n", "  verify-endpoint: test-server.nowhere.com",);
    let endpoint = CompoundNearConcreteAddr::TCP {
        tcp: "[::1]:8101".parse().expect("Expected success")
    };

    compound_entry_test(SERVER_CONF, CLIENT_CONF, endpoint, Some(PARAM_CONF))
}
