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

use std::collections::hash_map::Entry;
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Instant;
use std::vec::IntoIter;

use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_common::config::Create;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpoint;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use constellation_common::retry::next_retry;
use constellation_common::retry::next_retry_definite;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_common::retry::WithRetryWhen;
use constellation_common::sched::Policy;
use constellation_streams::addrs::Addrs;
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
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::addrs::SocketAddrPolicy;
use crate::channels::ShutdownError;
use crate::channels::WithShutdownError;
use crate::config::AddrsConfig;
use crate::config::FarChannelsConfig;
use crate::config::FlowsConfig;
use crate::config::ResolverConfig;
use crate::far::flows::Flows;
use crate::far::flows::FlowsFlowError;
use crate::far::flows::FlowsListenError;
use crate::far::flows::ListenResult;
use crate::far::types::FarChannelsTypes;
use crate::far::types::FlowAuthNShutdownTypes;
use crate::far::types::FlowsEntryTypes;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelFlowsError;
use crate::resolve::cache::NSNameCacheError;
use crate::resolve::cache::NSNameCachesCtx;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FarChannelID(usize);

/// Negotiation state for session and authentication negotiations.
///
/// This is used to store current negotiation states, and advance
/// them.  This differs slightly from the near channel version,
/// because session negotiations happen internally in [Flows].
// XXX Collapse this into SessionState
enum SessionNegoState<AuthPending> {
    /// Session negotiation is pending.
    ///
    /// Session negotiation takes place internally in [Flows], so this
    /// is just a placeholder to guarantee that we don't attempt to
    /// obtain a given flow multiple times with [Flows::flow].
    Session,
    /// Session authentication is pending.
    AuthN {
        /// State of pending authentication.
        pending: AuthPending
    }
}

/// Current state of sessions.
///
/// This is used to store whether a session is in negotiations, or is
/// active and has already been returned.
enum SessionState<Stream, Types>
where
    Stream: Session,
    Types: FlowAuthNShutdownTypes<Stream> {
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        pending: SessionNegoState<Types::AuthPending>
    },
    /// A session has already been established.
    Active,
    /// Session shutdown is pending.
    Shutdown {
        /// The pending shutdown negotiation state.
        pending: Types::ShutdownPending
    }
}

/// Retry information for a given possible [Flows] instance.
// XXX Move this out to common.
struct FlowsRetry {
    /// Current number of failures.
    nfailures: usize,
    /// When to retry next.
    retry_when: Instant
}

/// Negotiation state for an individual flow.
struct FlowNegoState<Flow, Types>
where
    Flow: Session,
    Types: FlowAuthNShutdownTypes<Flow> {
    /// Current session negotiation state, if there are active
    /// negotiations.
    state: Option<SessionState<Flow, Types>>,
    /// Retry information for establishing this flow.
    retry: FlowsRetry,
    /// Whether to delete this once it shuts down.
    live: bool
}

/// Representation of a [Flows], and all of its [Flow] sessions and
/// negotiations.
struct FlowsEntry<Flow, Types>
where
    Flow: Session,
    Types: FlowsEntryTypes<Flow> {
    /// All sessions either active or in negotiation.
    sessions: HashMap<Types::PeerAddr, FlowNegoState<Flow, Types>>,
    /// The [Flows] to which all sessions correspond.
    flows: Flows<
        Flow,
        Types::Sock,
        Types::InboundNego,
        Types::OutboundNego,
        Types::Xfrm
    >,
    /// Retry information for listening for new sessions.
    retry: FlowsRetry,
    param: Types::ChannelParam
}

/// Entry associated with an acquired value on a channel.
///
/// This will hold all [FlowsEntry]s corresponding to the channel
/// parameters associated with the acquired value.  It will
/// periodically refresh these values and update states as necessary.
struct AcquiredEntry<Types>
where
    Types: FarChannelsTypes {
    xfrm: PhantomData<Types::Xfrm>,
    auth: PhantomData<Types::AuthN>,
    /// Acquired value from the channel.
    acquired: Types::Acquired,
    /// Resolver generated by the acquired value.
    resolver: AcquiredResolver<Types::ChannelParam>,
    /// Current set of [Flows] for the various
    /// [Param](FarChannelSocket::Param)s.
    ///
    /// An acquired far channel allows sockets to be created, but
    /// there may be multiple possible configurations that can be set
    /// up.
    tokens: HashMap<Types::ChannelParam, Token>,
    /// Map from tokens to flows entries
    flows: HashMap<Token, FlowsEntry<Types::Flow, Types>>,
    /// Configuration information used to create new [Flows].
    flows_config: FlowsConfig,
    /// Parameter used to create new [DatagramXfrm]s.
    xfrm_param: Types::InnerXfrmCreateParam,
    /// Size hint for the number of flows.
    nflows_hint: Option<usize>
}

/// Acquisition negotiation information.
///
/// This will ultimately create an [AcquiredEntry] when negotiations
/// succeed, and will manage any shutdown associated with the
/// underlying channel.
enum AcquireState<Types>
where
    Types: FarChannelsTypes {
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        state: Types::AcquirePending
    },
    /// The acquisition negotiations are complete, but resolution was
    /// delayed.
    Acquired {
        /// The acquired value.
        acquired: Types::Acquired,
        /// When to retry.
        when: Instant
    },
    /// A session has already been established.
    Active {
        /// The associated
        acquired: AcquiredEntry<Types>
    },
    /// Shutdown negotiations are pending.
    Shutdown {
        /// State of pending shutdown negotiations.
        pending: Types::AcquireShutdownPending
    }
}

pub(crate) struct ChannelEntry<Types>
where
    Types: FarChannelsTypes {
    /// Authenticator to use for session authentication.
    authn: Types::AuthN,
    /// Base [FarChannel](crate::far::FarChannel) object.
    channel: Types::Channel,
    /// Shutdown negotiator for channels.
    shutdown: Types::ShutdownNego,
    /// Shutdown negotiator parameter.
    shutdown_param: Types::ShutdownParam,
    /// Configuration used to create [Flows].
    flows_config: FlowsConfig,
    /// Configuration used to create [Resolver]s.
    resolve_config: ResolverConfig,
    /// Address policy.
    addr_policy: SocketAddrPolicy,
    in_param: Types::InParam,
    /// Parameter used to create the basic [DatagramXfrm].
    xfrm_param: Types::InnerXfrmCreateParam,
    /// Retry configuration.
    retry: Retry,
    /// Size hint for flows tables.
    nflows_hint: Option<usize>,
    /// Acquired value and flows, if a value has been acquired.
    ///
    /// This is used to store when to retry, if
    /// [Retry](RetryResult::Retry) is present.
    acquired: Option<RetryResult<AcquireState<Types>>>
}

pub struct FarChannels<Types>
where
    Types: FarChannelsTypes {
    /// Map from names to [FarChannelID]s.
    ids: HashMap<String, FarChannelID>,
    /// Reverse map from [FarChannelID]s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Types>>,
    tokens: HashMap<Token, FarChannelID>
}

pub struct FarChannelsParamsIter<'a, I, Types>
where I: 'a + Iterator<Item = FarChannelID>,
    Types: FarChannelsTypes {
    ids: I,
    channels: &'a mut [ChannelEntry<Types>],
}

/// Errors that can occur refreshing name caches and updating entries.
#[derive(Debug)]
pub enum FarChannelsRefreshError<Flows, Wrap> {
    /// Error refreshing name cache entries.
    NameCaches {
        /// The error that occurred refreshing the name caches.
        err: NSNameCacheError
    },
    /// Error obtaining a new [Flows].
    Flows {
        /// The error that occurred obtaining the new [Flows].
        err: Flows
    },
    /// Error wrapping a [SocketAddr].
    Wrap {
        /// Error that occurred wrapping the address.
        err: Wrap
    },
    /// Low-level I/O error occurred.
    IO {
        /// The low-level I/O error that occurred.
        err: Error
    },
    /// Token and flows tables were inconsistent.
    Inconsistent,
    /// No valid addresses were produced.
    NoValidAddrs,
}

#[derive(Debug)]
pub enum AuthNegoStepError<AuthN> {
    /// An error occurred during authentication negotiations.
    AuthN {
        /// The error that occurred during authentication negotiations.
        err: AuthN
    },
    /// An error occurred clearing the backlog.
    IO {
        /// The error that occurred clearing the backlog.
        err: Error
    },
    /// The state is still in session negotiation.
    Session
}

#[derive(Debug)]
pub enum SessionNegoToAuthError<AuthN, Start> {
    /// An error occurred during authentication negotiations.
    AuthN {
        /// The error that occurred during authentication negotiations.
        err: AuthN
    },
    /// An error occurred starting authentication negotiation.
    Start {
        /// The error that occurred starting authentication negotiations.
        err: Start
    },
    /// An error occurred clearing the backlog.
    IO {
        /// The error that occurred clearing the backlog.
        err: Error
    },
    /// The state is not in session negotiation.
    NotSession
}

#[derive(Debug)]
pub enum FlowStateGetFlowError<AuthN, Start, Flow, Shutdown> {
    /// Error occurred shutting down the stream
    Shutdown { err: Shutdown },
    /// Error occurred transitioning to authentication stage.
    ToAuth {
        /// Error that occurred transitioning to authentication stage.
        err: SessionNegoToAuthError<AuthN, Start>
    },
    /// Error occurred obtaining a [Flow] instance.
    Flow {
        /// The error that occurred obtaining the [Flow] instance.
        err: Flow
    },
    /// The session is already active.
    Active,
    /// Impossible case occurred.
    Impossible
}

#[derive(Debug)]
pub enum SessionStateBacklogError {
    Active
}

#[derive(Debug)]
pub enum SessionNegoStepError<AuthN, Shutdown> {
    /// Error occurred stepping session negotiations
    Auth {
        /// The error that occurred stepping session negotiations.
        err: AuthNegoStepError<AuthN>
    },
    /// An error occurred during shutdown negotiations.
    Shutdown {
        /// The error that occurred during shutdown negotiations.
        err: Shutdown
    }
}

#[derive(Debug)]
pub enum SessionListenError<Flows, Start, AuthN, Shutdown> {
    /// Error occurred listening for flows.
    Flows {
        /// Error that occurred listening for flows.
        err: Flows
    },
    /// Error occurred starting negotiations.
    Start {
        /// Error that occurred starting negotiations.
        err: SessionNegoToAuthError<AuthN, Start>
    },
    /// Error occurred stepping session negotiations
    Step {
        /// The error that occurred stepping session negotiations.
        err: SessionNegoStepError<AuthN, Shutdown>
    },
    IO {
        err: Error
    }
}

#[derive(Debug)]
pub enum SessionShutdownStepError<Flows, Shutdown> {
    /// Error occurred listening for flows.
    Flows {
        /// Error that occurred listening for flows.
        err: Flows
    },
    /// Error occurred stepping session negotiations
    Step {
        /// The error that occurred stepping session negotiations.
        err: Shutdown
    }
}

#[derive(Debug)]
pub enum SessionFlowsError<Flows, Listen, Start, AuthN, Shutdown> {
    /// Error orrucred listening for input after requesting.
    Listen {
        /// The error that occurred listening for input.
        err: SessionListenError<Listen, Start, AuthN, Shutdown>
    },
    /// Error occurred requesting the flow.
    Flows {
        /// The error that occurred requesting the flow.
        err: Flows
    }
}

/// Errors that can occur shutting down a session.
#[derive(Debug)]
pub enum SessionShutdownError<Start, Negotiate> {
    /// Error occurred starting negotiations.
    Session {
        err: ShutdownError<Start, Negotiate>
    },
    /// The session was in a shutdown state.
    Shutdown,
    /// A pending session negotiation exists.
    Pending,
    /// The session has no existing state.
    None
}

#[derive(Debug)]
pub enum AcquiredEntryCreateError<Resolve, Flows, Wrap> {
    /// Error refreshing name cache entries.
    NameCaches {
        /// The error that occurred refreshing the name caches.
        err: NSNameCacheError
    },
    /// Error wrapping a [SocketAddr].
    Wrap {
        /// Error that occurred wrapping the address.
        err: Wrap
    },
    /// Error obtaining a new [Flows].
    Flows {
        /// The error that occurred obtaining the new [Flows].
        err: Flows
    },
    Resolve {
        err: Resolve
    },
    IO {
        err: Error
    },
    /// No valid addresses were produced.
    NoValidAddrs,
}

#[derive(Debug)]
pub enum AcquiredEntryListenError<Refresh, Flows, Start, AuthN, Shutdown> {
    /// Error occurred refreshing addresses.
    Refresh {
        /// Error that occurred while refreshing addresses.
        err: Refresh
    },
    /// Error occurred listening for flows.
    Listen {
        /// Error that occurred listening for flows.
        err: SessionListenError<Flows, Start, AuthN, Shutdown>
    }
}

#[derive(Debug)]
pub enum AcquiredEntryFlowsError<Flows, Wrap> {
    /// Error occurred while refreshing addresses.
    Refresh {
        /// Error that occurred while refreshing addresses.
        err: FarChannelsRefreshError<Flows, Wrap>
    },
    /// No flow exists for the requested address.
    ParamNotFound,
    /// The token and flows tables were inconsistent.
    Inconsistent
}

#[derive(Debug)]
pub enum AcquiredEntryFlowError<Flows, Wrap, Flow> {
    /// Error occurred while obtaining the flows entry.
    Flows {
        /// Error that occurred obtaining the flows entry.
        err: AcquiredEntryFlowsError<Flows, Wrap>
    },
    /// Error occurred requesting the flow.
    Flow { err: Flow }
}

#[derive(Debug)]
pub enum AcquiredEntryShutdownError<Flows, Wrap> {
    /// Error occurred while refreshing addresses.
    Refresh {
        /// Error that occurred while refreshing addresses.
        err: FarChannelsRefreshError<Flows, Wrap>
    },
    /// The token and flows tables were inconsistent.
    Inconsistent
}

#[derive(Debug)]
pub enum ChannelEntryAcquireError<Acquire, Nego, Entry> {
    Acquire { err: Acquire },
    Nego { err: Nego },
    Entry { err: Entry }
}

#[derive(Debug)]
pub enum ChannelEntryCreateError<Acquire, Shutdown, Nego, Entry> {
    Acquire {
        err: ChannelEntryAcquireError<Acquire, Nego, Entry>
    },
    /// Error occurred creating the shutdown [Negotiator].
    Shutdown {
        /// The error that occurred creating the shutdown
        /// [Negotiator].
        err: Shutdown
    }
}

/// Errors that can occur shutting down a flow on an `AcquireState`.
#[derive(Debug)]
pub enum ChannelEntryShutdownFlowError<Flow> {
    /// Error occurred while shutting down the flow.
    Flow {
        /// Error that occurred while shutting down the flow.
        err: Flow
    },
    IO {
        err: Error
    },
    /// Acquire negotiations are still pending.
    Pending,
    /// The `AcquireState` is in shutdown negotiations.
    Shutdown,
    /// There is no acquire state.
    None
}

/// Errors that can occur obtaining addresses on an `AcquireState`.
#[derive(Debug)]
pub enum FarChannelsAddrsError<Flow> {
    Flow {
        err: Flow
    },
    /// Acquire negotiations are still pending.
    Pending,
    /// The `AcquireState` is in shutdown negotiations.
    Shutdown,
    /// There is no acquire state.
    None
}

/// Errors that can occur requesting a flow on an `AcquireState`.
#[derive(Debug)]
pub enum ChannelEntryReqFlowError<Flow> {
    Flow {
        err: Flow
    },
    /// Acquire negotiations are still pending.
    Pending,
    /// The `AcquireState` is in shutdown negotiations.
    Shutdown,
    /// There is no current `AcquireState`.
    None
}

#[derive(Debug)]
pub enum ChannelEntryListenError<Listen, Entry, Nego, Shutdown> {
    Listen { err: Listen },
    Entry { err: Entry },
    Nego { err: Nego },
    Shutdown { err: Shutdown },
    None
}

#[derive(Debug)]
pub enum FarChannelsCreateError<Auth, Channel, Entry> {
    Auth {
        err: Auth
    },
    Channel {
        err: Channel
    },
    Entry {
        err: Entry
    },
    Collision {
        name: String
    }
}

impl<AuthPending> SessionNegoState<AuthPending> {
    /// Create a state denoting session negotiations.
    ///
    /// This will not perform any negotiations.
    #[inline]
    fn session() -> Self {
        SessionNegoState::Session
    }

    /// Create a state denoting authentication negotiations.
    ///
    /// This will attempt to step the authentication negotiations.  If
    /// they succeed, then an authenticated session will be returned
    /// immediately, otherwise, a state will be returned.
    ///
    /// # Parameters
    ///
    /// - `authn`: Authenticator to use.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// # Return Value
    ///
    /// - `NegotiatorResult::Complete(session)`: If authentication succeeded
    ///   immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are still pending.
    fn auth<Flow, AuthN>(
        authn: &AuthN,
        flow: Flow
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        SessionNegoToAuthError<AuthN::NegotiateError, AuthN::StartError>
    >
    where
        Flow: Session + Read + Write,
        AuthN: SessionAuthN<Flow>
            + NegotiatorStart<
                AuthNResult<AuthN::AuthNSession, Flow>,
                Flow,
                Param = ()
            > + Negotiator<
                AuthNResult<AuthN::AuthNSession, Flow>,
                Pending = AuthPending
            > {
        // Start authentication negotiations.
        let state = authn
            .start(&(), flow)
            .map_err(|err| SessionNegoToAuthError::Start { err: err })?;

        Ok(authn
            .negotiate(state)
            .map_err(|err| SessionNegoToAuthError::AuthN { err: err })?
            .map_pending(|pending| SessionNegoState::AuthN {
                pending: pending
            }))
    }

    /// Transition into the authentication phase.
    ///
    /// This will attempt to step the authentication negotiations.  If
    /// they succeed, then an authenticated session will be returned
    /// immediately, otherwise, a state will be returned.
    ///
    /// # Parameters
    ///
    /// - `authn`: Authenticator to use.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// # Return Value
    ///
    /// - `NegotiatorResult::Complete(session)`: If authentication succeeded
    ///   immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are still pending.
    fn to_auth<Flow, AuthN>(
        self,
        authn: &AuthN,
        flow: Flow
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        SessionNegoToAuthError<AuthN::NegotiateError, AuthN::StartError>
    >
    where
        Flow: Session + Read + Write,
        AuthN: SessionAuthN<Flow>
            + NegotiatorStart<
                AuthNResult<AuthN::AuthNSession, Flow>,
                Flow,
                Param = ()
            > + Negotiator<
                AuthNResult<AuthN::AuthNSession, Flow>,
                Pending = AuthPending
            > {
        if let SessionNegoState::Session = self {
            // Start authentication negotiations.
            let state = authn
                .start(&(), flow)
                .map_err(|err| SessionNegoToAuthError::Start { err: err })?;

            Ok(authn
                .negotiate(state)
                .map_err(|err| SessionNegoToAuthError::AuthN { err: err })?
                .map_pending(|pending| SessionNegoState::AuthN {
                    pending: pending
                }))
        } else {
            Err(SessionNegoToAuthError::NotSession)
        }
    }

    /// Step negotitions forward in the authentication phase.
    ///
    /// If they succeed, then an authenticated session will be
    /// returned immediately, otherwise, a state will be returned.
    ///
    /// # Parameters
    ///
    /// - `authn`: Authenticator to use.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// # Return Value
    ///
    /// - `NegotiatorResult::Complete(session)`: If authentication succeeded
    ///   immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are still pending.
    fn step_auth<Flow, AuthN>(
        self,
        authn: &AuthN
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        AuthNegoStepError<AuthN::NegotiateError>
    >
    where
        Flow: Session + Read + Write,
        AuthN: SessionAuthN<Flow, Pending = AuthPending, Param = ()> {
        match self {
            // Resuming session negotiations.
            SessionNegoState::Session { .. } => Err(AuthNegoStepError::Session),
            // Resuming authentication negotiations.
            SessionNegoState::AuthN { pending } => Ok(authn
                .complete_negotiate(pending)
                .map_err(|err| AuthNegoStepError::AuthN { err: err })?
                .map_pending(|pending| SessionNegoState::AuthN {
                    pending: pending
                }))
        }
    }
}

impl<Flow, Types> FlowNegoState<Flow, Types>
where
    Flow: Session + Read + Write,
    Types: FlowAuthNShutdownTypes<Flow>
{
    /// Take an incoming negotiated session and create a state in the
    /// authentication phase.
    ///
    /// This will attempt to step authentication negotiations forward.
    /// If they succeed, then the authenticated session will be
    /// returned as well.  If they fail, then the [Flow] will be shut
    /// down, and retried later.  Regardless, the `FlowNegoState` will
    /// be returned.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `peer`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `(self, Some(session))`: If authentication negotiations succeeded.
    ///
    /// - `(self, None)`: If authentication negotiations are pending, or failed
    ///   and will be retried later.
    fn create<Addr>(
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        flow: Flow,
        peer: Addr
    ) -> Result<
        (Self, Option<Types::AuthNSession>),
        WithShutdownError<
            SessionNegoToAuthError<Types::AuthNegoError, Types::AuthStartError>,
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    >
    where
        Addr: Display {
        let mut new = FlowNegoState {
            state: None,
            retry: FlowsRetry::new(),
            live: true
        };
        let res = new.recv_flow(shutdown, param, authn, retry, flow, peer)?;

        Ok((new, res))
    }

    /// Check if this session is shut down.
    #[inline]
    fn is_shutdown(&self) -> bool {
        self.state.is_none()
    }

    #[inline]
    fn is_live(&self) -> bool {
        self.live || !self.is_shutdown()
    }

    /// Step the state forward as indicated by an authentication result.
    ///
    /// This will return an authenticated session if the authenticated
    /// result produces one.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// - `Err`: Type of errors in the authentication result.
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// - `res`: Authentication negotiation result to process.
    ///
    /// - `err_stream`: Function to possibly recover a [Flow] from an error in
    ///   `res`.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If the result denotes an authentication success.
    ///
    /// - `None`: If the result does not produce an authenticated session.
    fn handle_to_auth_result<Addr, Err, F>(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        retry: &Retry,
        addr: &Addr,
        res: Result<
            NegotiatorResult<
                AuthNResult<Types::AuthNSession, Flow>,
                SessionNegoState<Types::AuthPending>
            >,
            Err
        >,
        err_stream: F
    ) -> Result<
        Option<Types::AuthNSession>,
        WithShutdownError<
            Err,
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    >
    where
        F: FnOnce(Err) -> Option<Flow>,
        Addr: Display,
        Err: Display + ScopedError {
        match res {
            // Negotiations completed immediately; set the state
            // to active and return.
            Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                info!(target: "flows-nego-state",
                      "authenticated new session with {} over {}",
                      out.prin(), addr);

                self.state = Some(SessionState::Active);
                self.retry.nfailures = 0;

                Ok(Some(out))
            }
            // Authentication failed.
            Ok(NegotiatorResult::Complete(AuthNResult::Reject(flow))) => {
                info!(target: "flows-nego-state",
                      "authentication rejected for session with {}",
                      addr);

                let delay = retry.retry_delay(self.retry.nfailures);

                debug!(target: "flows-nego-state",
                       "authentication failed, delay for {}.{:03}s",
                       delay.as_secs(), delay.subsec_millis());

                self.state = None;
                self.retry.nfailures = self.retry.nfailures + 1;
                self.retry.retry_when = Instant::now() + delay;

                self.do_shutdown_session(shutdown, param, addr, flow)
                    .map_err(|err| WithShutdownError::Shutdown { err: err })?;

                Ok(None)
            }
            // Negotiations stopped in a pending state.
            Ok(NegotiatorResult::Pending(pending)) => {
                debug!(target: "flows-nego-state",
                       "continuing negotiations with {}",
                       addr);

                self.state = Some(SessionState::Pending { pending: pending });

                Ok(None)
            }
            // Error occurred; check its scope.
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => {
                    Err(WithShutdownError::Inner { err: err })
                }
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "flows-nego-state",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    warn!(target: "flows-nego-state",
                          "session authentication with {} failed: {}",
                          addr, err);

                    let delay = retry.retry_delay(self.retry.nfailures);

                    debug!(target: "flows-nego-state",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.retry.nfailures = self.retry.nfailures + 1;
                    self.retry.retry_when = Instant::now() + delay;
                    self.state = None;

                    if let Some(flow) = err_stream(err) {
                        self.do_shutdown_session(shutdown, param, addr, flow)
                            .map_err(|err| WithShutdownError::Shutdown {
                            err: err
                        })?;
                    }

                    Ok(None)
                }
            }
        }
    }

    /// Step the state forward as indicated by a shutdown result.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// - `res`: Shutdown negotiation result to process.
    fn handle_shutdown_result<Addr>(
        &mut self,
        addr: Addr,
        res: NegotiatorResult<(), Types::ShutdownPending>
    ) where
        Addr: Display {
        match res {
            NegotiatorResult::Complete(()) => {
                info!(target: "flows-nego-state",
                      "shut down session with {}",
                      addr);

                self.state = None;
            }
            NegotiatorResult::Pending(pending) => {
                debug!(target: "flows-nego-state",
                       "continuing shutdown negotiation with {}",
                       addr);

                self.state = Some(SessionState::Shutdown { pending: pending });
            }
        }
    }

    /// Try to start a new session.
    ///
    /// This will attempt to step session and authentication
    /// negotiations forward as far as possible.  If they succeed,
    /// then the authenticated session will be returned as well.  If
    /// they fail, then the [Flow] will be shut down, and retried
    /// later.  Regardless, the `FlowNegoState` will be returned.
    ///
    /// This should never be called if a session already exists.
    ///
    /// # Parameters
    ///
    /// - `flows`: [Flows] to use to obtain the new session.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `param`: Parameter used by the outbound negotiator.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If authentication negotiations succeeded.
    ///
    /// - `None`: If authentication negotiations are pending, or failed and will
    ///   be retried later.
    fn create_flow(
        &mut self,
        flows: &mut Flows<
            Flow,
            Types::Sock,
            Types::InboundNego,
            Types::OutboundNego,
            Types::Xfrm
        >,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        param: &Types::OutParam,
        addr: &Types::PeerAddr
    ) -> Result<
        RetryResult<Option<Types::AuthNSession>>,
        FlowStateGetFlowError<
            Types::AuthNegoError,
            Types::AuthStartError,
            FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where
        Types: FlowsEntryTypes<Flow> {
        trace!(target: "flows-nego-state",
               "creating new flow with {}",
               addr);

        // Check if we're still delayed
        let now = Instant::now();

        if self.retry.retry_when <= now {
            // Good to go. Try creating a flow
            if let Some(flow) = flows
                .flow(param, addr.clone())
                .map_err(|err| FlowStateGetFlowError::Flow { err: err })?
            {
                trace!(target: "flows-nego-state",
                       "session negotiated immediately with {}",
                       addr);

                // The session negotiation returned immediately.
                // Start authentication.
                let res = SessionNegoState::auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown,
                    shutdown_param,
                    retry,
                    addr,
                    res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } => {
                            authn.start_err_stream(err)
                        }
                        SessionNegoToAuthError::AuthN { err } => {
                            authn.err_stream(err)
                        }
                        _ => None
                    }
                )
                .map(RetryResult::Success)
                .map_err(|err| match err {
                    WithShutdownError::Shutdown { err } => {
                        FlowStateGetFlowError::Shutdown { err: err }
                    }
                    WithShutdownError::Inner { err } => {
                        FlowStateGetFlowError::ToAuth { err: err }
                    }
                })
            } else {
                trace!(target: "flows-nego-state",
                       "continuing session negotiation with {}",
                       addr);

                // Session negotiations are pending.
                let pending = SessionNegoState::session();

                self.state = Some(SessionState::Pending { pending: pending });

                Ok(RetryResult::Success(None))
            }
        } else {
            // Still delayed.
            Ok(RetryResult::Retry(self.retry.retry_when))
        }
    }

    /// Try to start a new session.
    ///
    /// This will attempt to step session and authentication
    /// negotiations forward as far as possible.  If they succeed,
    /// then the authenticated session will be returned as well.  If
    /// they fail, then the [Flow] will be shut down, and retried
    /// later.  Regardless, the `FlowNegoState` will be returned.
    ///
    /// This is a safe wrapper around
    /// [create_flow](FlowNegoState::create_flow) that can be called
    /// whether or not a state already exists, and will return an
    /// error if one does.
    ///
    /// # Parameters
    ///
    /// - `flows`: [Flows] to use to obtain the new session.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `param`: Parameter used by the outbound negotiator.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If authentication negotiations succeeded.
    ///
    /// - `None`: If authentication negotiations are pending, or failed and will
    ///   be retried later.
    fn get_flow(
        &mut self,
        flows: &mut Flows<
            Flow,
            Types::Sock,
            Types::InboundNego,
            Types::OutboundNego,
            Types::Xfrm
        >,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        param: &Types::OutParam,
        addr: &Types::PeerAddr
    ) -> Result<
        RetryResult<Option<Types::AuthNSession>>,
        FlowStateGetFlowError<
            Types::AuthNegoError,
            Types::AuthStartError,
            FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where
        Types: FlowsEntryTypes<Flow> {
        debug!(target: "flows-nego-state",
               "obtaining flow with {}",
               addr);

        if let Some(state) = &self.state {
            match state {
                // Negotiations are pending, there is no session.
                SessionState::Pending { .. } |
                SessionState::Shutdown { .. } => Ok(RetryResult::Success(None)),
                // There's already an active session.
                SessionState::Active => Err(FlowStateGetFlowError::Active)
            }
        } else {
            // No session exists; we need to start one.
            self.create_flow(
                flows,
                shutdown,
                shutdown_param,
                authn,
                retry,
                param,
                addr
            )
        }
    }

    /// Take an incoming negotiated session and transition this state
    /// into the authentication phase.
    ///
    /// This will attempt to step authentication negotiations forward.
    /// If they succeed, then the authenticated session will be
    /// returned as well.  If they fail, then the [Flow] will be shut
    /// down, and retried later.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `peer`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If authentication negotiations succeeded.
    ///
    /// - `None`: If authentication negotiations are pending, or failed and will
    ///   be retried later.
    fn recv_flow<Addr>(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        flow: Flow,
        peer: Addr
    ) -> Result<
        Option<Types::AuthNSession>,
        WithShutdownError<
            SessionNegoToAuthError<Types::AuthNegoError, Types::AuthStartError>,
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    >
    where
        Addr: Display {
        debug!(target: "flows-nego-state",
               "receiving incoming flow with {}",
               peer);

        let state = self.state.take();

        match state {
            // There's already an active session, but this isn't an error.
            Some(SessionState::Active) => {
                info!(target: "flows-nego-state",
                      "discarding session from {}, active session exists",
                      peer);

                self.state = Some(SessionState::Active);

                Ok(None)
            }
            // A pending negotiation exists; advance it to the
            // authentication stage.
            Some(SessionState::Pending { pending }) => {
                trace!(target: "flows-nego-state",
                       "pending negotiation exists");

                let res = pending.to_auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown,
                    param,
                    retry,
                    &peer,
                    res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } => {
                            authn.start_err_stream(err)
                        }
                        SessionNegoToAuthError::AuthN { err } => {
                            authn.err_stream(err)
                        }
                        _ => None
                    }
                )
            }
            // No existing state at all; start fresh in the
            // authentication state.
            //
            // Alternatively, shutdown negotiations were pending, and
            // this discards them.

            // XXX Possibly rate-limit incoming connections to
            // avoid DoS?
            Some(SessionState::Shutdown { .. }) | None => {
                trace!(target: "flows-nego-state",
                       "no pending negotiation exists");

                let res = SessionNegoState::auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown,
                    param,
                    retry,
                    &peer,
                    res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } => {
                            authn.start_err_stream(err)
                        }
                        SessionNegoToAuthError::AuthN { err } => {
                            authn.err_stream(err)
                        }
                        _ => None
                    }
                )
            }
        }
    }

    /// Try to shut down a session and update state accordingly.
    ///
    /// This will attempt to step shutdown negotiations forward as far
    /// as possible.
    ///
    /// This must never be called with a [Flow] other than the current
    /// active session.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// - `session`: The session to shut down.  This must be the same
    ///   authenticated session returned by [create](FlowNegoState::create),
    ///   [get_flow](FlowNegoState::get_flow), or [step](FlowNegoState::step).
    fn do_shutdown_session<Addr>(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        addr: Addr,
        session: Flow
    ) -> Result<
        (),
        ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
    >
    where
        Addr: Display {
        let state = shutdown
            .start(param, session)
            .map_err(|err| ShutdownError::Start { err: err })?;
        let res = shutdown
            .negotiate(state)
            .map_err(|err| ShutdownError::Negotiate { err: err })?;

        self.handle_shutdown_result(addr, res);

        Ok(())
    }

    /// Try to shut down a session and update state accordingly.
    ///
    /// This will attempt to step shutdown negotiations forward as far
    /// as possible.
    ///
    /// This is a wrapper around [do_shutdown_session] that will
    /// return an error if there is not a current session.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// - `session`: The session to shut down.  This must be the same
    ///   authenticated session returned by [create](FlowNegoState::create),
    ///   [get_flow](FlowNegoState::get_flow), or [step](FlowNegoState::step).
    fn shutdown_session<Addr>(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        addr: Addr,
        session: Types::AuthNSession
    ) -> Result<
        (),
        SessionShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    >
    where
        Addr: Display {
        debug!(target: "flows-nego-state",
               "shutting down session with {}",
               addr);

        match &self.state {
            // This is what we expect.
            Some(SessionState::Active) => {
                error!(target: "flows-nego-state",
                       "shutting down active session with {}",
                       addr);

                let (_, session) = session.take();

                self.live = false;

                self.do_shutdown_session(shutdown, param, addr, session)
                    .map_err(|err| SessionShutdownError::Session { err: err })
            }
            // None of these should ever happen, but they're not
            // fatal.
            Some(SessionState::Pending { .. }) => {
                Err(SessionShutdownError::Pending)
            }
            Some(SessionState::Shutdown { .. }) => {
                Err(SessionShutdownError::Shutdown)
            }
            None => Err(SessionShutdownError::None)
        }
    }

    /// Step shutdown negotiations forward as far as possible.
    ///
    /// This should never be called except in the shutdown state.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    fn shutdown_step<Addr>(
        &mut self,
        shutdown: &Types::ShutdownNego,
        addr: Addr
    ) -> Result<
        (),
        ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
    >
    where
        Addr: Display + Eq + Hash {
        let state = self.state.take();

        match state {
            Some(SessionState::Shutdown { pending }) => {
                let res = shutdown
                    .complete_negotiate(pending)
                    .map_err(|err| ShutdownError::Negotiate { err: err })?;

                self.handle_shutdown_result(addr, res);
            }
            // We shouldn't see any other state than shutdown.
            Some(SessionState::Pending { .. }) => {
                error!(target: "flows-nego-state",
                      "should not see pending session with {}",
                      addr);
            }
            Some(SessionState::Active) => {
                error!(target: "flows-nego-state",
                      "should not see active session with {}",
                      addr);
            }
            None => {
                debug!(target: "flows-nego-state",
                      "attempting to step inactive session with {}",
                      addr);
            }
        }

        Ok(())
    }

    /// Step the ongoing negotiations forward as far as possible.
    ///
    /// If the session is currently active and negotiations succeed,
    /// then the authenticated session will be returned as well.  If
    /// they fail, then the [Flow] will be shut down, and retried
    /// later.
    ///
    /// If the session is already fully-authenticated and active, then
    /// this will deliver any pending messages, and add `addr` to
    /// `ext_endpoints`.
    ///
    /// This will not attempt to restart inactive negotiations.
    ///
    /// # Type Parameters
    ///
    /// - `Addr`: Type of counterparty addresses (used for logging only).
    ///
    /// # Parameters
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `addr`: Counterparty's address.
    fn step<Addr, E>(
        &mut self,
        report_endpoint: E,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        addr: Addr
    ) -> Result<
        Option<Types::AuthNSession>,
        SessionNegoStepError<
            Types::AuthNegoError,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where
        E: FnOnce(Addr),
        Addr: Clone + Display + Eq + Hash {
        debug!(target: "flows-nego-state",
               "stepping session with {}",
               addr);

        let state = self.state.take();

        match state {
            // A pending negotiation exists; step it.
            Some(SessionState::Pending { pending }) => {
                trace!(target: "flows-nego-state",
                       "session is pending");

                let res = pending.step_auth(authn);

                self.handle_to_auth_result(
                    shutdown,
                    param,
                    retry,
                    &addr,
                    res,
                    |err| match err {
                        AuthNegoStepError::AuthN { err } => {
                            authn.err_stream(err)
                        }
                        _ => None
                    }
                )
                .map_err(|err| match err {
                    WithShutdownError::Shutdown { err } => {
                        SessionNegoStepError::Shutdown { err: err }
                    }
                    WithShutdownError::Inner { err } => {
                        SessionNegoStepError::Auth { err: err }
                    }
                })
            }
            // There's already an active session, but this isn't an error.
            Some(SessionState::Active) => {
                trace!(target: "flows-nego-state",
                       "session is active, recording endpoint");

                report_endpoint(addr.clone());
                self.state = Some(SessionState::Active);

                Ok(None)
            }
            Some(SessionState::Shutdown { pending }) => {
                trace!(target: "flows-nego-state",
                       "session is shutting down");

                let res =
                    shutdown.complete_negotiate(pending).map_err(|err| {
                        SessionNegoStepError::Shutdown {
                            err: ShutdownError::Negotiate { err: err }
                        }
                    })?;

                self.handle_shutdown_result(addr, res);

                Ok(None)
            }
            // No existing state at all; ignore this.
            None => {
                trace!(target: "flows-nego-state",
                      "attempting to step inactive session with {}",
                      addr);

                Ok(None)
            }
        }
    }
}

impl FlowsRetry {
    /// Create a new `FlowsRetry`.
    #[inline]
    fn new() -> Self {
        FlowsRetry {
            nfailures: 0,
            retry_when: Instant::now()
        }
    }
}

impl<Flow, Types> FlowsEntry<Flow, Types>
where
    Flow: Session + Read + Write,
    Types: FlowsEntryTypes<Flow>
{
    /// Create a new `FlowsEntry` from a [Flows].
    ///
    /// # Parameters
    ///
    /// - `flows`: The [Flows] to use.
    #[inline]
    fn new(
        registry: &Registry,
        mut flows: Flows<
            Flow,
            Types::Sock,
            Types::InboundNego,
            Types::OutboundNego,
            Types::Xfrm
        >,
        token: Token,
        param: Types::ChannelParam
    ) -> Result<Self, Error> {
        registry.register(
            &mut flows,
            token,
            Interest::READABLE | Interest::WRITABLE
        )?;

        let sessions = HashMap::new();

        Ok(FlowsEntry {
            retry: FlowsRetry::new(),
            sessions: sessions,
            flows: flows,
            param: param
        })
    }

    /// Create a new `FlowsEntry` from a [Flows] with a size hint.
    ///
    /// # Parameters
    ///
    /// - `flows`: The [Flows] to use.
    ///
    /// - `nsessions`: Size hint for the sessions table.
    #[inline]
    fn with_capacity(
        registry: &Registry,
        mut flows: Flows<
            Flow,
            Types::Sock,
            Types::InboundNego,
            Types::OutboundNego,
            Types::Xfrm
        >,
        token: Token,
        param: Types::ChannelParam,
        nsessions: usize
    ) -> Result<Self, Error> {
        registry.register(
            &mut flows,
            token,
            Interest::READABLE | Interest::WRITABLE
        )?;

        let sessions = HashMap::with_capacity(nsessions);

        Ok(FlowsEntry {
            retry: FlowsRetry::new(),
            sessions: sessions,
            flows: flows,
            param: param
        })
    }

    /// Check if this `FlowsEntry` is safe to shut down.
    ///
    /// This checks whether there are any remaining sessions.
    #[inline]
    fn is_shutdown_safe(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Request a flow for a given endpoint.
    ///
    /// This will attempt to negotiate and authenticate a session with
    /// the given endpoint.  If negotiations can be concluded
    /// immediately, then the authenticated session will be returned.
    /// Otherwise, the request will remain active and will eventually
    /// be returned by [listen](FlowsEntry::listen).  Subsequent calls
    /// to this function with the same `endpoint` will return an
    /// error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_flow](FlowsEntry::shutdown_flow)
    /// to properly handle shutdown negotiations and cleanup.
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `out_param`: Parameter used by the outbound negotiator.
    ///
    /// - `endpoint`: The counterparty's address.
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success(Some(session))`: If authentication negotiations
    ///   succeeded.
    ///
    /// - `RetryResult::Success(None)`: If authentication negotiations are
    ///   pending, or failed and will be retried later.
    fn req_flow(
        &mut self,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        out_param: &Types::OutParam,
        endpoint: &Types::PeerAddr
    ) -> Result<
        RetryResult<Option<Types::AuthNSession>>,
        FlowStateGetFlowError<
            Types::AuthNegoError,
            Types::AuthStartError,
            FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    > {
        let now = Instant::now();

        match self.sessions.entry(endpoint.clone()) {
            Entry::Occupied(mut ent) => {
                let ent = ent.get_mut();

                if ent.retry.retry_when <= now {
                    let out = ent.get_flow(
                        &mut self.flows,
                        shutdown,
                        shutdown_param,
                        authn,
                        retry,
                        out_param,
                        endpoint
                    )?;

                    Ok(out)
                } else {
                    Ok(RetryResult::Retry(ent.retry.retry_when))
                }
            }
            Entry::Vacant(ent) => {
                let ent = ent.insert(FlowNegoState {
                    state: None,
                    retry: FlowsRetry::new(),
                    live: true
                });

                let out = ent.get_flow(
                    &mut self.flows,
                    shutdown,
                    shutdown_param,
                    authn,
                    retry,
                    out_param,
                    endpoint
                )?;

                Ok(out)
            }
        }
    }

    /// Return a session obtained from this `FlowsEntry` and shut it
    /// down.
    ///
    /// This will perform shutdown negotiations on `session` and
    /// handle any cleanup.
    ///
    /// # Parameters
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `session`: The session to shut down.
    ///
    /// - `endpoint`: The counterparty's address.
    fn shutdown_flow(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        session: Types::AuthNSession,
        endpoint: Types::PeerAddr
    ) -> Result<
        (),
        SessionShutdownError<
            Types::ShutdownStartError,
            Types::ShutdownNegoError
        >
    > {
        let endpoint = Types::PeerAddr::from(endpoint);

        match self.sessions.entry(endpoint.clone()) {
            Entry::Vacant(_) => Err(SessionShutdownError::None),
            Entry::Occupied(mut ent) => {
                let state = ent.get_mut();

                state.shutdown_session(shutdown, param, &endpoint, session)?;

                if state.state.is_none() {
                    ent.remove();
                }

                Ok(())
            }
        }
    }

    /// Listen for incoming traffic and new sessions for the [Flows]
    /// for this `FlowsEntry`.
    ///
    /// This will fully exhaust all incoming traffic corresponding to
    /// any [Token] in `tokens`.  All pending negotiations will be
    /// updated, and any new sessions will be reported.  If any new
    /// [Flow]s are obtained, then negotiations will begin for them.
    ///
    /// New authenticated sessions will be reported in `sessions`.
    /// Traffic on existing active sessions will be reported in
    /// `ext_endpoints`.
    ///
    /// # Parameters
    ///
    /// - `report_session`: A function used to report authenticated
    ///   sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `param`: Parameter used by the inbound negotiator.
    fn listen<S, E>(
        &mut self,
        mut report_session: S,
        mut report_endpoint: E,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        param: &Types::InParam
    ) -> Result<
        (),
        SessionListenError<
            FlowsListenError<
                Types::XfrmError,
                Types::InStartError,
                Types::InNegoError,
                Types::OutNegoError
            >,
            Types::AuthStartError,
            Types::AuthNegoError,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where
        S: FnMut(Types::ChannelParam,
                 Types::AuthNSession) -> Result<(), Error>,
        E: FnMut(Types::PeerAddr, Types::ChannelParam),
    {
        let mut endpoints = HashSet::new();
        let mut flows = Vec::new();

        while {
            let mut read = false;

            // Pick up all incoming flows.
            loop {
                match self.flows.listen(param) {
                    Ok(res) => {
                        // Normal listen result.
                        read = true;

                        // See if it was internal-only.
                        if let Some(res) = res {
                            match res {
                                // New flow was created.
                                ListenResult::New { endpoint, flow } => {
                                    trace!(target: "flows-nego-state",
                                           "got new flow from {}",
                                           endpoint);

                                    flows.push((endpoint, flow));
                                }
                                // Update to an existing flow.
                                ListenResult::Existing { endpoint } => {
                                    if self.sessions.contains_key(&endpoint) {
                                        trace!(target: "flows-nego-state",
                                           "traffic on pending session {}",
                                           endpoint);

                                        endpoints.insert(endpoint);
                                    } else {
                                        // This shouldn't happen; we're
                                        // missing a session.

                                        error!(target: "flows-nego-state",
                                           "traffic on nonexistent session {}",
                                           endpoint);
                                    }
                                }
                            }
                        }
                    }
                    // Error; see if it's WouldBlock.
                    Err(err) => {
                        if err.scope() == ErrorScope::WouldBlock {
                            // Non-blocking I/O exhausted.
                            break;
                        } else {
                            // A real error occurred.
                            return Err(SessionListenError::Flows { err: err });
                        }
                    }
                }
            }

            // Process all new sessions.
            for (endpoint, flow) in flows.drain(..) {
                debug!(target: "flows-nego-state",
                       "handling incoming flow {}",
                       endpoint);

                match self.sessions.entry(endpoint.clone()) {
                    Entry::Occupied(mut ent) => {
                        trace!(target: "flows-nego-state",
                               "entry for flow {} already exists",
                               ent.key());

                        read = true;

                        if let Some(session) = ent
                            .get_mut()
                            .recv_flow(
                                shutdown,
                                shutdown_param,
                                authn,
                                retry,
                                flow,
                                endpoint
                            )
                            .map_err(|err| match err {
                                WithShutdownError::Inner { err } => {
                                    SessionListenError::Start { err: err }
                                }
                                WithShutdownError::Shutdown { err } => {
                                    SessionListenError::Step {
                                        err: SessionNegoStepError::Shutdown {
                                            err: err
                                        }
                                    }
                                }
                            })?
                        {
                            debug!(target: "flows-nego-state",
                                   "reporting completed session");

                            // Session negotiations complete; report it out.
                            report_session(self.param.clone(), session)
                                .map_err(|err| SessionListenError::IO {
                                    err: err
                                })?;
                        }
                    }
                    Entry::Vacant(ent) => {
                        trace!(target: "flows-nego-state",
                               "no entry for flow {}",
                               ent.key());

                        let (state, session) = FlowNegoState::create(
                            shutdown,
                            shutdown_param,
                            authn,
                            retry,
                            flow,
                            endpoint
                        )
                        .map_err(|err| match err {
                            WithShutdownError::Inner { err } => {
                                SessionListenError::Start { err: err }
                            }
                            WithShutdownError::Shutdown { err } => {
                                SessionListenError::Step {
                                    err: SessionNegoStepError::Shutdown {
                                        err: err
                                    }
                                }
                            }
                        })?;

                        ent.insert(state);

                        if let Some(session) = session {
                            debug!(target: "flows-nego-state",
                                   "reporting completed session");

                            // Session negotiations complete; report it out.
                            report_session(self.param.clone(), session)
                                .map_err(|err| SessionListenError::IO {
                                    err: err
                                })?;
                        }
                    }
                }
            }

            // Process all negotiation steps.
            for endpoint in endpoints.drain() {
                trace!(target: "flows-nego-state",
                       "traffic on flow {}",
                       endpoint);

                let param = self.param.clone();

                // Look up the session.
                if let Entry::Occupied(mut ent) =
                    self.sessions.entry(endpoint.clone())
                {
                    read = true;

                    // Step negotiations.
                    if let Some(session) = ent
                        .get_mut()
                        .step(
                            |endpoint| report_endpoint(endpoint, param),
                            shutdown,
                            shutdown_param,
                            authn,
                            retry,
                            endpoint.clone()
                        )
                        .map_err(|err| SessionListenError::Step { err: err })?
                    {
                        debug!(target: "flows-nego-state",
                               "reporting completed session");

                        // Session negotiations complete; report it out.
                        report_session(self.param.clone(), session)
                            .map_err(|err| SessionListenError::IO {
                                err: err
                            })?;
                    }

                    if !ent.get().is_live() {
                        trace!(target: "flows-nego-state",
                               "removing entry for {}",
                               endpoint);

                        ent.remove();
                    }
                } else {
                    error!(target: "flows-nego-state",
                           "no session entry for {}",
                           endpoint);
                }
            }

            read
        } {}

        Ok(())
    }

    fn shutdown_step(
        &mut self,
        shutdown: &Types::ShutdownNego,
        param: &Types::InParam
    ) -> Result<
        (),
        SessionShutdownStepError<
            FlowsListenError<
                Types::XfrmError,
                Types::InStartError,
                Types::InNegoError,
                Types::OutNegoError
            >,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    > {
        let mut endpoints = HashSet::new();

        while {
            let mut read = false;

            loop {
                match self.flows.listen(param) {
                    Ok(res) => {
                        // Normal listen result.
                        read = true;

                        // See if it was internal-only.
                        if let Some(res) = res {
                            match res {
                                // New flow was created, but we're
                                // shutting down.  Ignore it.
                                ListenResult::New { endpoint, .. } => {
                                    info!(target: "flows-nego-state",
                                          "ignoring new flow from {}",
                                          endpoint);
                                }
                                // Update to an existing flow.
                                ListenResult::Existing { endpoint } => {
                                    if self.sessions.contains_key(&endpoint) {
                                        trace!(target: "flows-nego-state",
                                           "traffic on pending session {}",
                                           endpoint);

                                        endpoints.insert(endpoint);
                                    } else {
                                        // This shouldn't happen; we're
                                        // missing a session.

                                        error!(target: "flows-nego-state",
                                           "traffic on nonexistent session {}",
                                           endpoint);
                                    }
                                }
                            }
                        }
                    }
                    // Error; see if it's WouldBlock.
                    Err(err) => {
                        if err.scope() == ErrorScope::WouldBlock {
                            // Non-blocking I/O exhausted.
                            break;
                        } else {
                            // A real error occurred.
                            return Err(SessionShutdownStepError::Flows {
                                err: err
                            });
                        }
                    }
                }
            }

            // Process all negotiation steps.
            for endpoint in endpoints.drain() {
                trace!(target: "flows-nego-state",
                       "traffic on flow {}",
                       endpoint);

                // Look up the session.
                if let Some(ent) = self.sessions.get_mut(&endpoint) {
                    read = true;

                    // Step negotiations.
                    ent.shutdown_step(shutdown, endpoint).map_err(|err| {
                        SessionShutdownStepError::Step { err: err }
                    })?
                } else {
                    error!(target: "flows-nego-state",
                           "no session entry for {}",
                           endpoint);
                }
            }

            read
        } {}

        Ok(())
    }
}

impl<Flow, Types> Source for FlowsEntry<Flow, Types>
where
    Flow: Session,
    Types: FlowsEntryTypes<Flow>
{
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.flows.register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.flows.reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.flows.deregister(registry)
    }
}

impl<Types> AcquiredEntry<Types>
where
    Types: FarChannelsTypes
{
    /// Create a new `AcquiredEntry`.
    ///
    /// This creates a new `AcquiredEntry` from its configurations,
    /// and the `acquired` value.  The `acquired` value will be used
    /// to create a resolver.  The resolver will then immediately
    /// attempt to obtain a set of addresses, which will be used to
    /// create [Flows] and corresponding entries.
    ///
    /// The time to the next refresh will be returned along with the
    /// `AcquiredEntry`, if there is one.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `channel`: [FarChannel] that provided `acquired`.
    ///
    /// - `created`: [Vec] into which to store created [Token]s.
    ///
    /// - `flows_config`: Configuration object to use to create a [Flows].
    ///
    /// - `resolve_config`: Configuration object for the resolver.
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// - `xfrm_param`: Configuration object to use to create the
    ///   [DatagramXfrm].
    ///
    /// - `acquired`: The acquired value to use to create the resolver.
    ///
    /// - `retry`: Retry configuration for name resolution.
    ///
    /// - `nflows_hint`: Size hint for the number of [Flows].
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success((self, Some(when)))`: Resolution was successful,
    ///   and will need to be refreshed again at `when`.`
    ///
    /// - `RetryResult::Success((self, None))`: Resolution was successful, and
    ///   will not ever need to be refreshed.
    ///
    /// - `RetryResult::Retry(when)`: Resolution was delayed, and can be retried
    ///   at `when`.
    fn create<Ctx>(
        ctx: &mut Ctx,
        channel: &mut Types::Channel,
        created: &mut Vec<Token>,
        flows_config: &FlowsConfig,
        resolve_config: &ResolverConfig,
        policy: &SocketAddrPolicy,
        xfrm_param: &Types::InnerXfrmCreateParam,
        acquired: Types::Acquired,
        nflows_hint: Option<usize>
    ) -> Result<
        RetryResult<(Self, Option<Instant>), WithRetryWhen<Types::Acquired>>,
        AcquiredEntryCreateError<
            Types::ResolverError,
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        let mut resolver = acquired
            .resolver(ctx, policy, resolve_config)
            .map_err(|err| AcquiredEntryCreateError::Resolve { err: err })?;
        let res = match &mut resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver } => resolver
                .addrs()
                .map_err(|err| AcquiredEntryCreateError::NameCaches {
                    err: err
                })?
                .map_ok(|(resolved, time)| {
                    trace!(target: "acquired-entry",
                           "refreshing addresses for registry entry");

                    let mut flows = HashMap::with_capacity(resolved.len());
                    let mut tokens = HashMap::with_capacity(resolved.len());

                    // Filter out all the addresses we're keeping.
                    for (addr, _, _) in resolved {
                        if policy.check_ip(&addr.ip()) {
                            trace!(target: "acquired-entry",
                                   "keeping address: {}",
                                   addr);

                            let addr = acquired.wrap(addr).map_err(|err| {
                                AcquiredEntryCreateError::Wrap { err: err }
                            })?;

                            debug!(target: "acquired-entry",
                                   "establishing flows for {}",
                                   addr);

                            let xfrm =
                                Types::InnerXfrm::create(&addr, xfrm_param);
                            let session = channel
                                .flows(flows_config.clone(), addr.clone(), xfrm)
                                .map_err(|err| {
                                    AcquiredEntryCreateError::Flows { err: err }
                                })?;
                            let token = ctx.token();
                            let registry = ctx.registry();
                            let ent = match nflows_hint {
                                Some(hint) => FlowsEntry::with_capacity(
                                    registry, session, token, addr.clone(), hint
                                )
                                .map_err(|err| AcquiredEntryCreateError::IO {
                                    err: err
                                }),
                                None => FlowsEntry::new(
                                    registry, session, token, addr.clone()
                                )
                                .map_err(|err| {
                                    AcquiredEntryCreateError::IO {
                                        err: err
                                    }
                                })
                            }?;

                            if let Some(curr) = tokens
                                .insert(addr.clone(), token.clone()) {
                                error!(target: "acquired-entry",
                                       "entry exists for address {}: token {}",
                                       addr, curr.0);

                            }

                            created.push(token.clone());

                            if flows.insert(token.clone(), ent).is_some() {
                                error!(target: "acquired-entry",
                                       "entry exists for token {}",
                                       token.0);
                            }
                        } else {
                            debug!(target: "acquired-entry",
                                   "discarding address {}",
                                   addr);
                        }
                    }

                    if tokens.is_empty() {
                        Err(AcquiredEntryCreateError::NoValidAddrs)
                    } else {
                        // Replace the flows.
                        tokens.shrink_to_fit();
                        flows.shrink_to_fit();

                        Ok((tokens, flows, time))
                    }
                }),
            AcquiredResolver::StaticMulti { params } => {
                let mut tokens = HashMap::with_capacity(params.len());
                let mut flows = HashMap::with_capacity(params.len());

                for addr in params {
                    debug!(target: "acquired-entry",
                           "establishing flows for {}",
                               addr);

                    let xfrm = Types::InnerXfrm::create(addr, xfrm_param);
                    let session = channel
                        .flows(flows_config.clone(), addr.clone(), xfrm)
                        .map_err(|err| AcquiredEntryCreateError::Flows {
                            err: err
                        })?;
                    let token = ctx.token();
                    let registry = ctx.registry();
                    let ent = match nflows_hint {
                        Some(hint) => FlowsEntry::with_capacity(
                            registry, session, token, addr.clone(), hint
                        )
                        .map_err(|err| {
                            AcquiredEntryCreateError::IO { err: err }
                        }),
                        None => FlowsEntry::new(
                            registry, session, token, addr.clone()
                        )
                        .map_err(|err| AcquiredEntryCreateError::IO {
                            err: err
                        })
                    }?;

                    if let Some(curr) = tokens
                        .insert(addr.clone(), token.clone()) {
                        error!(target: "acquired-entry",
                               "entry exists for address {}: token {}",
                               addr, curr.0);

                    }

                    created.push(token.clone());

                    if flows.insert(token.clone(), ent).is_some() {
                        error!(target: "acquired-entry",
                               "entry exists for token {}",
                               token.0);
                    }
                }

                Ok(RetryResult::Success((tokens, flows, None)))
            }
            AcquiredResolver::StaticSingle { param } => {
                let mut tokens = HashMap::with_capacity(1);
                let mut flows = HashMap::with_capacity(1);

                debug!(target: "acquired-entry",
                       "establishing flows for {}",
                       param);

                let xfrm = Types::InnerXfrm::create(param, xfrm_param);
                let session = channel
                    .flows(flows_config.clone(), param.clone(), xfrm)
                    .map_err(|err| AcquiredEntryCreateError::Flows {
                        err: err
                    })?;
                let token = ctx.token();
                let registry = ctx.registry();
                let ent = match nflows_hint {
                    Some(hint) => FlowsEntry::with_capacity(
                        registry, session, token, param.clone(), hint
                    )
                    .map_err(|err| AcquiredEntryCreateError::IO { err: err }),
                    None => FlowsEntry::new(
                        registry, session, token, param.clone()
                    ).map_err(
                        |err| AcquiredEntryCreateError::IO { err: err }
                    )
                }?;

                if let Some(curr) = tokens
                    .insert(param.clone(), token.clone()) {
                    error!(target: "acquired-entry",
                           "entry exists for address {}: token {}",
                           param, curr.0);

                }

                created.push(token.clone());

                if flows.insert(token.clone(), ent).is_some() {
                    error!(target: "acquired-entry",
                           "entry exists for token {}",
                           token.0);
                }

                Ok(RetryResult::Success((tokens, flows, None)))
            }
        }?;

        match res {
            RetryResult::Success((tokens, flows, time)) => {
                let ent = AcquiredEntry {
                    xfrm: PhantomData,
                    auth: PhantomData,
                    flows_config: flows_config.clone(),
                    xfrm_param: xfrm_param.clone(),
                    nflows_hint: nflows_hint,
                    acquired: acquired,
                    resolver: resolver,
                    tokens: tokens,
                    flows: flows
                };

                Ok(RetryResult::Success((ent, time)))
            }
            RetryResult::Retry(when) => {
                let out = WithRetryWhen::new(acquired, when);

                Ok(RetryResult::Retry(out))
            }
        }
    }

    /// Check if this `AcquiredEntry` is safe to shut down.
    ///
    /// This checks whether there are any remaining sessions.
    fn is_shutdown_safe(&self) -> bool {
        self.flows.values().all(|ent| ent.is_shutdown_safe())
    }

    /// Indicate when the next refresh is needed, if ever.
    ///
    /// # Return Value
    ///
    /// - `Some(when)`: The next refresh is needed at `when`.
    ///
    /// - `None`: This entry never needs a refresh.
    fn next_refresh(&self) -> Option<Instant> {
        if let AcquiredResolver::Resolve { resolver } = &self.resolver {
            resolver.refresh_when()
        } else {
            None
        }
    }

    /// Request a flow for a given endpoint.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then attempt to negotiate and authenticate a
    /// session with the given endpoint.  If negotiations can be
    /// concluded immediately, then the authenticated session will be
    /// returned.  Otherwise, the request will remain active and will
    /// eventually be returned by [listen](FlowsEntry::listen).
    /// Subsequent calls to this function with the same `endpoint`
    /// will return an error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_flow](FlowsEntry::shutdown_flow)
    /// to properly handle shutdown negotiations and cleanup.
    /// Information from the call to `refresh` will also be returned.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context object.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context to use to manage [Token]s.
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// - `channel_param`: Channel parameter indicating the specific [Flows]
    ///   from which `session` was obtained.
    ///
    /// - `nego_param`: Parameter used by the outbound negotiator.
    ///
    /// - `endpoint`: The counterparty'ss address.
    fn req_flow<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        policy: &SocketAddrPolicy,
        retry: &Retry,
        channel_param: &Types::ChannelParam,
        nego_param: &Types::OutParam,
        endpoint: &Types::PeerAddr
    ) -> Result<
        RetryResult<(
            Option<Types::AuthNSession>,
            Option<Vec<Types::ChannelParam>>,
            Option<Instant>
        )>,
        AcquiredEntryFlowError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError,
            FlowStateGetFlowError<
                Types::AuthNegoError,
                Types::AuthStartError,
                FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
                ShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        self.flows(ctx, channel, policy, channel_param)
            .map_err(|err| AcquiredEntryFlowError::Flows { err: err })?
            .flat_map_ok(|(ent, addrs, refresh_when)| {
                Ok(ent
                    .req_flow(
                        shutdown,
                        shutdown_param,
                        authn,
                        &retry,
                        nego_param,
                        endpoint
                    )
                    .map_err(|err| AcquiredEntryFlowError::Flow { err: err })?
                    .map(|session| (session, addrs, refresh_when)))
            })
    }

    /// Refresh name resolution on this `AcquiredEntry` and
    /// reconstitute the downstream entries.
    ///
    /// This will obtain a new set of channel parameters, which may
    /// delete some of the old [Flows] and/or create new ones.
    ///
    /// There is in general no way to cleanly shut down any sessions
    /// on a [Flows] that is deleted in this way as they are presumed
    /// to be out of contact.  However, these session do not have
    /// separate I/O objects, so only the socket corresponding to the
    /// [Flows] needs to be unregistered.
    ///
    /// If the set of [Flows] changes, then the new set will be
    /// reported.  The time of the next refresh will also be reported.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context object.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context to use to manage [Token]s.
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success((Some(params), Some(when)))`: The set of [Flows]
    ///   changed to `params`, and the channel needs to be refreshed at `when`
    ///
    /// - `RetryResult::Success((None, Some(when)))`: The set of [Flows] is
    ///   unchanged, and the channel needs to be refreshed at `when`
    ///
    /// - `RetryResult::Success((Some(params), None))`: This case should never
    ///   happen.
    ///
    /// - `RetryResult::Success((None, None))`: Should be returned by any entry
    ///   with a static address set.
    ///
    /// - `RetryResult::Retry(when)`: A refresh is needed, but was delayed until
    ///   `when`.
    // XXX change the return type to eliminate the impossible case.
    fn refresh<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy
    ) -> Result<
        RetryResult<(Option<Vec<Types::ChannelParam>>, Option<Instant>)>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        match &mut self.resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver }
                if resolver.needs_refresh() =>
            {
                resolver
                    .addrs()
                    .map_err(|err| FarChannelsRefreshError::NameCaches {
                        err: err
                    })?
                    .map_ok(|(resolved, next_refresh)| {
                        trace!(target: "acquired-entry",
                           "refreshing addresses for registry entry");

                        let out = self.update_refreshed(
                            ctx,
                            channel,
                            policy,
                            resolved.into_iter()
                        )?;

                        Ok((Some(out), next_refresh))
                    })
            }
            // Only a resolver can refresh.  Everything else is trivial.
            _ => Ok(RetryResult::Success((None, self.next_refresh())))
        }
    }

    /// Shut down a session obtained from this `AcquriedEntry`.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then perform shutdown negotiations on
    /// `session` and handle any cleanup.
    ///
    /// Previous calls to `refresh` (including the one performed by
    /// this call) may result in `session` becoming stale.  No error
    /// is returned in this case.
    ///
    /// The return value is the same as for the call to `refresh`.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context object.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context to use to manage [Token]s.
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// - `channel_param`: Channel parameter indicating the specific [Flows]
    ///   from which `session` was obtained.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `session`: The session to shut down.
    ///
    /// - `peer`: The counterparty'ss address.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    fn shutdown_flow<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy,
        shutdown: &Types::ShutdownNego,
        param: &Types::ShutdownParam,
        channel_param: &Types::ChannelParam,
        session: Types::AuthNSession,
        peer: Types::PeerAddr
    ) -> Result<
        RetryResult<(Option<Vec<Types::ChannelParam>>, Option<Instant>)>,
        AcquiredEntryShutdownError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        self.refresh(ctx, channel, policy)
            .map_err(|err| AcquiredEntryShutdownError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                // The token might have gotten deleted in the refresh;
                // don't throw a hard error here.
                if let Some(token) = self.tokens.get(channel_param) {
                    // The flows tables should always be consistent.
                    let flows = self
                        .flows
                        .get_mut(&token)
                        .ok_or(AcquiredEntryShutdownError::Inconsistent)?;

                    // Try to shut down the flow.  Errors here aren't
                    // fatal, and should not be reported.
                    if let Err(err) =
                        flows.shutdown_flow(shutdown, param, session, peer)
                    {
                        warn!(target: "acquired-entry",
                              "error shutting down channel {}: {}",
                              channel_param, err)
                    }
                }

                Ok((addrs, refresh_when))
            })
    }

    /// Obtain a snapshot of the current set of addresses.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then return the same value as the last
    /// `refresh`.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context to use to manage [Token]s.
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    fn addrs<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy
    ) -> Result<
        RetryResult<(Vec<Types::ChannelParam>, Option<Instant>)>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        Ok(self.refresh(ctx, channel, policy)?.map(
            |(out, refresh_when)| match out {
                // No refresh was necessary, generate the addresses directly.
                None => (self.tokens.keys().cloned().collect(), refresh_when),
                // The refresh generated the address list for us.
                Some(out) => (out, refresh_when)
            }
        ))
    }

    /// Listen for incoming traffic and new sessions for all [Flows]
    /// for this `AcquiredEntry`.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then fully exhaust all incoming traffic
    /// corresponding to any [Token] in `tokens`.  All pending
    /// negotiations will be updated, and any new sessions will be
    /// reported.  If any new [Flow]s are obtained, then negotiations
    /// will begin for them.
    ///
    /// New authenticated sessions will be reported in `sessions`.
    /// Traffic on existing active sessions will be reported in
    /// `ext_endpoints`.
    ///
    /// The return value is the same as for the call to `refresh`.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context to use to manage [Token]s.
    ///
    /// - `report_session`: A function used to report authenticated
    ///   sessions.
    ///
    /// - `report_endpoint`: A function used to report endpoints.
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to be retried
    ///   later.
    ///
    /// - `param`: Parameter used by the inbound negotiator.
    ///
    /// - `tokens`: All [Token]s that have pending read traffic.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    fn listen<Ctx, S, E>(
        &mut self,
        ctx: &mut Ctx,
        mut report_session: S,
        mut report_endpoint: E,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy,
        shutdown: &Types::ShutdownNego,
        shutdown_param: &Types::ShutdownParam,
        authn: &Types::AuthN,
        retry: &Retry,
        nego_param: &Types::InParam,
        tokens: &HashSet<Token>
    ) -> Result<
        RetryResult<(Option<Vec<Types::ChannelParam>>, Option<Instant>)>,
        AcquiredEntryListenError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >,
            FlowsListenError<
                Types::XfrmError,
                Types::InStartError,
                Types::InNegoError,
                Types::OutNegoError
            >,
            Types::AuthStartError,
            Types::AuthNegoError,
            ShutdownError<Types::ShutdownStartError, Types::ShutdownNegoError>
        >
    >
    where
        S: FnMut(Types::ChannelParam,
                 Types::AuthNSession) -> Result<(), Error>,
        E: FnMut(Types::PeerAddr, Types::ChannelParam),
        Ctx: RegistryCtx + TokensCtx {
        self.refresh(ctx, channel, policy)
            .map_err(|err| AcquiredEntryListenError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                for (_, ent) in self
                    .flows
                    .iter_mut()
                    .filter(|(token, _)| tokens.contains(token))
                {
                    ent.listen(
                        &mut report_session,
                        &mut report_endpoint,
                        shutdown,
                        shutdown_param,
                        authn,
                        retry,
                        nego_param
                    )
                    .map_err(|err| {
                        AcquiredEntryListenError::Listen { err: err }
                    })?
                }

                Ok((addrs, refresh_when))
            })
    }

    fn update_refreshed<Ctx, I>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy,
        resolved: I
    ) -> Result<
        Vec<Types::ChannelParam>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        I: Iterator<Item = (SocketAddr, IPEndpoint, Instant)>,
        Ctx: RegistryCtx + TokensCtx {
        let mut new_tokens = HashMap::with_capacity(self.flows.len());
        let mut new_flows = HashMap::with_capacity(self.flows.len());
        let mut retained = HashSet::with_capacity(self.flows.len());

        for (addr, _, _) in resolved {
            if policy.check(&addr) {
                trace!(target: "acquired-entry",
                       "keeping address: {}",
                       addr);

                let addr = self.acquired.wrap(addr).map_err(|err| {
                    FarChannelsRefreshError::Wrap { err: err }
                })?;

                // Only create a new flows if there isn't one already
                // in existence.
                match self.tokens.remove(&addr) {
                    Some(token) => {
                        trace!(target: "acquired-entry",
                               "retaining flows for {}",
                               addr);

                        let flows = self
                            .flows
                            .remove(&token)
                            .ok_or(FarChannelsRefreshError::Inconsistent)?;

                        retained.insert(token.clone());
                        new_flows.insert(token.clone(), flows);
                        new_tokens.insert(addr, token);
                    }
                    None => {
                        debug!(target: "acquired-entry",
                               "establishing flows for {}",
                               addr);

                        let token = ctx.token();
                        let xfrm =
                            Types::InnerXfrm::create(&addr, &self.xfrm_param);
                        let flows = channel
                            .flows(
                                self.flows_config.clone(),
                                addr.clone(),
                                xfrm
                            )
                            .map_err(|err| FarChannelsRefreshError::Flows {
                                err: err
                            })?;
                        let registry = ctx.registry();
                        let ent = match self.nflows_hint {
                            Some(hint) => FlowsEntry::with_capacity(
                                registry, flows, token, addr.clone(), hint
                            )
                            .map_err(|err| FarChannelsRefreshError::IO {
                                err: err
                            }),
                            None => FlowsEntry::new(
                                registry, flows, token, addr.clone()
                            )
                            .map_err(|err| FarChannelsRefreshError::IO {
                                err: err
                            })
                        }?;

                        new_flows.insert(token.clone(), ent);
                        new_tokens.insert(addr, token);
                    }
                };
            } else {
                debug!(target: "acquired-entry",
                       "discarding address {} of unknown type",
                       addr);
            }
        }

        if new_tokens.is_empty() {
            Err(FarChannelsRefreshError::NoValidAddrs)
        } else {
            let out = new_tokens.keys().cloned().collect();

            // Replace the flows.
            new_tokens.shrink_to_fit();
            new_flows.shrink_to_fit();
            self.tokens = new_tokens;
            self.flows = new_flows;

            // Filter out the flows that weren't retained.
            let deletes: Vec<Token> = self
                .flows
                .keys()
                .cloned()
                .filter(|tok| !retained.contains(tok))
                .collect();

            for tok in deletes {
                if let Some(mut flows) = self.flows.remove(&tok) {
                    let addr = flows.flows.local_addr().map_err(|err| {
                        FarChannelsRefreshError::IO { err: err }
                    })?;

                    debug!(target: "acquired-entry",
                           "deregistering flows for {}, token {}",
                           addr, tok.0);

                    flows.flows.deregister(ctx.registry()).map_err(|err| {
                        FarChannelsRefreshError::IO { err: err }
                    })?;
                    ctx.free_token(tok);
                } else {
                    error!(target: "acquired-entry",
                           "entry should not be missing for token {}",
                           tok.0);
                }
            }

            Ok(out)
        }
    }

    fn flows<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel: &Types::Channel,
        policy: &SocketAddrPolicy,
        param: &Types::ChannelParam
    ) -> Result<
        RetryResult<(
            &mut FlowsEntry<Types::Flow, Types>,
            Option<Vec<Types::ChannelParam>>,
            Option<Instant>
        )>,
        AcquiredEntryFlowsError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        self.refresh(ctx, channel, policy)
            .map_err(|err| AcquiredEntryFlowsError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                let token = self
                    .tokens
                    .get(param)
                    .ok_or(AcquiredEntryFlowsError::ParamNotFound)?;
                let flows = self
                    .flows
                    .get_mut(&token)
                    .ok_or(AcquiredEntryFlowsError::Inconsistent)?;

                Ok((flows, addrs, refresh_when))
            })
    }
}

#[derive(Debug)]
pub enum ChannelEntryShutdownError<Start, Nego> {
    Start { err: Start },
    Nego { err: Nego },
    Active
}

impl<Types> ChannelEntry<Types>
where
    Types: FarChannelsTypes
{
    /// Create a new `ChannelEntry`.
    ///
    /// This will attempt to perform acquire negotiations on
    /// `channel`.  If negotiations can be concluded immediately, then
    /// an `AcquiredEntry` will be created if possible.
    ///
    /// The time of the next refresh or update will be returned along
    /// with the `AcquiredEntry`, if there is one.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `channel`: [FarChannel] that provided `acquired`.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `flows_config`: Configuration object to use to create a [Flows].
    ///
    /// - `resolve_config`: Configuration object for the resolver.
    ///
    /// - `addr_policy`: Address policy to filter resolved names.
    ///
    /// - `xfrm_param`: Configuration object to use to create the
    ///   [DatagramXfrm].
    ///
    /// - `retry`: Retry configuration for name resolution.
    ///
    /// - `nflows_hint`: Size hint for the number of [Flows].
    ///
    /// # Return Value
    ///
    /// - `(self, Some(when))`: The next refresh or retry occurs at
    /// `when`.
    ///
    /// - `(self, None)`: There is no next refresh or update.
    pub(crate) fn create<Ctx>(
        ctx: &mut Ctx,
        channel: Types::Channel,
        authn: Types::AuthN,
        flows_config: FlowsConfig,
        addrs_config: AddrsConfig,
        xfrm_param: Types::InnerXfrmCreateParam,
        retry: Retry,
        nflows_hint: Option<usize>
    ) -> Result<
        (Self, Vec<Token>, Option<Instant>),
        ChannelEntryCreateError<
            Types::AcquireError,
            Types::ShutdownNegoCreateError,
            Types::AcquireNegoError,
            AcquiredEntryCreateError<
                Types::ResolverError,
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        let shutdown = channel
            .shutdown_negotiator()
            .map_err(|err| ChannelEntryCreateError::Shutdown { err: err })?;
        let in_param = channel.inbound_nego_param();
        let shutdown_param = channel.shutdown_nego_param();
        let (addrs_config, resolve_config) = addrs_config.take();
        let addr_policy = SocketAddrPolicy::create(&addrs_config);
        let mut out = ChannelEntry {
            authn: authn,
            channel: channel,
            flows_config: flows_config,
            resolve_config: resolve_config,
            addr_policy: addr_policy,
            in_param: in_param,
            xfrm_param: xfrm_param,
            shutdown: shutdown,
            shutdown_param: shutdown_param,
            retry: retry,
            nflows_hint: nflows_hint,
            acquired: None
        };
        // XXX size hint by depth of the channel.
        let mut tokens = Vec::new();
        let when = out
            .try_acquire(ctx, &mut tokens)
            .map_err(|err| ChannelEntryCreateError::Acquire { err: err })?;

        Ok((out, tokens, when))
    }

    /// Indicate whether this `ChannelEntry` has finished acquisition.
    #[inline]
    fn is_active(&self) -> RetryResult<bool> {
        match &self.acquired {
            Some(RetryResult::Success(AcquireState::Active { .. })) => {
                RetryResult::Success(true)
            }
            Some(RetryResult::Success(AcquireState::Acquired {
                when, ..
            })) |
            Some(RetryResult::Retry(when)) => RetryResult::Retry(*when),
            _ => RetryResult::Success(false)
        }
    }

    #[inline]
    fn is_shutdown(&self) -> bool {
        self.acquired.is_none()
    }

    #[inline]
    fn is_shutdown_safe(&self) -> bool {
        match &self.acquired {
            Some(RetryResult::Success(AcquireState::Active { acquired })) => {
                acquired.is_shutdown_safe()
            }
            None | Some(RetryResult::Retry(_)) => true,
            _ => false
        }
    }

    /// Obtain a snapshot of the current set of addresses.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then return the same value as the last
    /// `refresh`.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](ChannelEntry::refresh).
    fn addrs<Ctx>(
        &mut self,
        ctx: &mut Ctx,
    ) -> Result<
        RetryResult<(Vec<Types::ChannelParam>, Option<Instant>)>,
        FarChannelsAddrsError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        match self.acquired.as_mut().ok_or(FarChannelsAddrsError::None)? {
            RetryResult::Success(AcquireState::Active { acquired }) => acquired
                .addrs(ctx, &self.channel, &self.addr_policy)
                .map_err(|err| FarChannelsAddrsError::Flow { err: err }),
            RetryResult::Success(AcquireState::Pending { .. }) |
            RetryResult::Success(AcquireState::Acquired { .. }) => {
                Err(FarChannelsAddrsError::Pending)
            }
            RetryResult::Success(AcquireState::Shutdown { .. }) => {
                Err(FarChannelsAddrsError::Shutdown)
            }
            // If we are delayed, pass the delay along.
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        }
    }

    /// Request a flow for a given endpoint.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then attempt to negotiate and authenticate a
    /// session with the given endpoint.  If negotiations can be
    /// concluded immediately, then the authenticated session will be
    /// returned.  Otherwise, the request will remain active and will
    /// eventually be returned by [listen](ChannelEntry::listen).
    /// Subsequent calls to this function with the same `endpoint`
    /// will return an error.
    ///
    /// If a session is obtained from a call to this function, it must
    /// be shut down with [shutdown_flow](ChannelEntry::shutdown_flow)
    /// to properly handle shutdown negotiations and cleanup.
    /// Information from the call to `refresh` will also be returned.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `channel_param`: Resolved channel parameter for which to request a
    ///   [Flow]
    ///
    /// - `nego_param`: Parameter used by the outbound negotiator.
    ///
    /// - `endpoint`: The counterparty'ss address.
    ///
    /// # Return Value
    ///
    /// A triple containing three values in order:
    ///
    /// 1. The authenticated session, if there is one.
    ///
    /// 1. If a refresh occurred, the new set of channel parameters.
    ///
    /// 1. When the next refresh occurs.
    pub(crate) fn req_flow<Ctx>(
        &mut self,
        tokens: &mut Ctx,
        param: &Types::ChannelParam,
        endpoint: &Types::PeerAddr,
        out_param: &Types::OutParam
    ) -> Result<
        RetryResult<(
            Option<Types::AuthNSession>,
            Option<Vec<Types::ChannelParam>>,
            Option<Instant>
        )>,
        ChannelEntryReqFlowError<
            AcquiredEntryFlowError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError,
                FlowStateGetFlowError<
                    Types::AuthNegoError,
                    Types::AuthStartError,
                    FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
                    ShutdownError<
                        Types::ShutdownStartError,
                        Types::ShutdownNegoError
                    >
                >
            >
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        match self
            .acquired
            .as_mut()
            .ok_or(ChannelEntryReqFlowError::None)?
        {
            // The channel is active; directly request the flow.
            RetryResult::Success(AcquireState::Active { acquired, .. }) => {
                acquired
                    .req_flow(
                        tokens,
                        &self.channel,
                        &self.shutdown,
                        &self.shutdown_param,
                        &self.authn,
                        &self.addr_policy,
                        &self.retry,
                        param,
                        &out_param,
                        endpoint
                    )
                    .map_err(|err| ChannelEntryReqFlowError::Flow { err: err })
            }
            // Acquisition is pending.
            RetryResult::Success(
                AcquireState::Pending { .. } | AcquireState::Acquired { .. }
            ) => Err(ChannelEntryReqFlowError::Pending),
            // The channel is shutting down.
            RetryResult::Success(AcquireState::Shutdown { .. }) => {
                Err(ChannelEntryReqFlowError::Shutdown)
            }
            // If we are delayed, pass the delay along.
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        }
    }

    /// Shut down a session obtained from this `ChannelEntry`.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then perform shutdown negotiations on
    /// `session` and handle any cleanup.
    ///
    /// Previous calls to `refresh` (including the one performed by
    /// this call) may result in `session` becoming stale.  No error
    /// is returned in this case.
    ///
    /// The return value is the same as for the call to `refresh`.
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `channel_param`: Channel parameter indicating the specific [Flows]
    ///   from which `session` was obtained.
    ///
    /// - `session`: The session to shut down.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    pub(crate) fn shutdown_flow<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        channel_param: &Types::ChannelParam,
        session: Types::AuthNSession
    ) -> Result<
        RetryResult<(Option<Vec<Types::ChannelParam>>, Option<Instant>)>,
        ChannelEntryShutdownFlowError<
            AcquiredEntryShutdownError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        let addr = session
            .get()
            .peer_addr()
            .map_err(|err| ChannelEntryShutdownFlowError::IO { err: err })?;

        match self
            .acquired
            .as_mut()
            .ok_or(ChannelEntryShutdownFlowError::None)?
        {
            RetryResult::Success(AcquireState::Active { acquired, .. }) => {
                acquired
                    .shutdown_flow(
                        ctx,
                        &self.channel,
                        &self.addr_policy,
                        &self.shutdown,
                        &self.shutdown_param,
                        channel_param,
                        session,
                        addr
                    )
                    .map_err(|err| ChannelEntryShutdownFlowError::Flow {
                        err: err
                    })
            }
            // None of these should ever happen.
            RetryResult::Success(AcquireState::Pending { .. }) |
            RetryResult::Success(AcquireState::Acquired { .. }) => {
                Err(ChannelEntryShutdownFlowError::Pending)
            }
            RetryResult::Success(AcquireState::Shutdown { .. }) => {
                Err(ChannelEntryShutdownFlowError::Shutdown)
            }
            // If we are delayed, pass the delay along.
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        }
    }

    fn shutdown(
        &mut self,
        deletes: &mut Vec<Token>,
        registry: &Registry
    ) -> Result<
        bool,
        ChannelEntryShutdownError<
            Types::AcquireShutdownError,
            Types::AcquireShutdownNegoError
        >
    > {
        match self.acquired.take() {
            Some(RetryResult::Success(AcquireState::Active { acquired }))
                if acquired.is_shutdown_safe() =>
            {
                let state = self.channel.shutdown(acquired.acquired).map_err(
                    |err| ChannelEntryShutdownError::Start { err: err }
                )?;

                match self
                    .channel
                    .shutdown_negotiate(deletes, registry, state)
                    .map_err(|err| ChannelEntryShutdownError::Nego {
                        err: err
                    })? {
                    // Shutdown completed immediately.
                    NegotiatorResult::Complete(()) => Ok(true),
                    NegotiatorResult::Pending(pending) => {
                        let state = AcquireState::Shutdown { pending: pending };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(false)
                    }
                }
            }
            // We were already shut down.
            None | Some(RetryResult::Retry(_)) => Ok(true),
            // It's not safe to shut down yet.
            _ => Err(ChannelEntryShutdownError::Active)
        }
    }

    fn listen<Ctx, E, S>(
        &mut self,
        ctx: &mut Ctx,
        report_session: S,
        report_endpoint: E,
        tokens: &HashSet<Token>
    ) -> Result<
        RetryResult<(
            Option<Vec<Token>>,
            Option<Vec<Token>>,
            Option<Vec<Types::ChannelParam>>,
            Option<Instant>
        )>,
        ChannelEntryListenError<
            AcquiredEntryListenError<
                FarChannelsRefreshError<
                    FarChannelFlowsError<
                        Types::SocketError,
                        Types::XfrmCreateError,
                        Types::InboundNegoCreateError,
                        Types::OutboundNegoCreateError
                    >,
                    Types::WrapError
                >,
                FlowsListenError<
                    Types::XfrmError,
                    Types::InStartError,
                    Types::InNegoError,
                    Types::OutNegoError
                >,
                Types::AuthStartError,
                Types::AuthNegoError,
                ShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >,
            AcquiredEntryCreateError<
                Types::ResolverError,
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >,
            Types::AcquireNegoError,
            Types::AcquireShutdownNegoError
        >
    >
    where
        S: FnMut(Types::ChannelParam,
                 Types::AuthNSession) -> Result<(), Error>,
        E: FnMut(Types::PeerAddr, Types::ChannelParam),
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        match self.acquired.take().ok_or(ChannelEntryListenError::None)? {
            RetryResult::Success(AcquireState::Pending { state }) => match self
                .channel
                .complete_negotiate(state)
            {
                Ok(NegotiatorResult::Pending(state)) => {
                    let state = AcquireState::Pending { state: state };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(RetryResult::Success((None, None, None, None)))
                }
                Ok(NegotiatorResult::Complete(acquired)) => {
                    // XXX size hint by depth of the channel.
                    let mut created = Vec::new();

                    self.handle_acquired(
                        ctx,
                        &mut created,
                        acquired
                    )
                    .map_err(|err| ChannelEntryListenError::Entry { err: err })
                    .map(|when| {
                        RetryResult::Success((Some(created), None, None, when))
                    })
                }
                Err(err) => {
                    error!(target: "channel-entry",
                           "error completing negotiations: {}",
                           err);

                    Ok(RetryResult::Success((None, None, None, None)))
                }
            },
            RetryResult::Success(AcquireState::Acquired { acquired, when }) => {
                if when <= Instant::now() {
                    // XXX size hint by depth of the channel.
                    let mut created = Vec::new();

                    self.handle_acquired(
                        ctx,
                        &mut created,
                        acquired
                    )
                    .map_err(|err| ChannelEntryListenError::Entry { err: err })
                    .map(|when| {
                        RetryResult::Success((Some(created), None, None, when))
                    })
                } else {
                    let state = AcquireState::Acquired {
                        acquired: acquired,
                        when: when
                    };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(RetryResult::Success((None, None, None, Some(when))))
                }
            }
            RetryResult::Success(AcquireState::Active { mut acquired }) => {
                match acquired.listen(
                    ctx,
                    report_session,
                    report_endpoint,
                    &self.channel,
                    &self.addr_policy,
                    &self.shutdown,
                    &self.shutdown_param,
                    &self.authn,
                    &self.retry,
                    &self.in_param,
                    tokens
                ) {
                    Ok(RetryResult::Success((refreshed, when))) => {
                        let state = AcquireState::Active { acquired: acquired };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Success((None, None, refreshed, when)))
                    }
                    Ok(RetryResult::Retry(when)) => {
                        let state = AcquireState::Active { acquired: acquired };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Retry(when))
                    }
                    Err(err) => {
                        error!(target: "channel-entry",
                               "error listening: {}",
                               err);

                        Ok(RetryResult::Success((None, None, None, None)))
                    }
                }
            }
            RetryResult::Success(AcquireState::Shutdown { pending }) => {
                // XXX size hint by depth of the channel.
                let mut deleted = Vec::new();

                match self.channel.complete_shutdown_negotiate(
                    &mut deleted,
                    ctx.registry(),
                    pending
                ) {
                    // Shutdown is complete; there's nothing more to return.
                    Ok(NegotiatorResult::Complete(())) => Ok(
                        RetryResult::Success((None, Some(deleted), None, None))
                    ),
                    // Shutdown is still pending.
                    Ok(NegotiatorResult::Pending(pending)) => {
                        let state = AcquireState::Shutdown { pending: pending };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Success((
                            None,
                            Some(deleted),
                            None,
                            None
                        )))
                    }
                    Err(err) => {
                        error!(target: "channel-entry",
                               "error completing shutdown negotiations: {}",
                               err);

                        Ok(RetryResult::Success((
                            None,
                            Some(deleted),
                            None,
                            None
                        )))
                    }
                }
            }
            // Pass through any delay.
            RetryResult::Retry(when) => {
                self.acquired = Some(RetryResult::Retry(when));

                Ok(RetryResult::Retry(when))
            }
        }
    }

    fn try_acquire<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        tokens: &mut Vec<Token>,
    ) -> Result<
        Option<Instant>,
        ChannelEntryAcquireError<
            Types::AcquireError,
            Types::AcquireNegoError,
            AcquiredEntryCreateError<
                Types::ResolverError,
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        match self
            .channel
            .acquire(tokens, ctx.registry())
            .map_err(|err| ChannelEntryAcquireError::Acquire { err: err })?
        {
            RetryResult::Success(state) => match self
                .channel
                .negotiate(state)
                .map_err(|err| {
                ChannelEntryAcquireError::Nego { err: err }
            })? {
                // Negotiations are still pending.
                NegotiatorResult::Pending(state) => {
                    let state = AcquireState::Pending { state: state };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(None)
                }
                // Acquisition negotiations completed.
                NegotiatorResult::Complete(acquired) =>
                // Create the AcquiredEntry, retry delays at this
                // point are due to resolution, not acquisition.
                {
                    match AcquiredEntry::create(
                        ctx,
                        &mut self.channel,
                        tokens,
                        &self.flows_config,
                        &self.resolve_config,
                        &self.addr_policy,
                        &self.xfrm_param,
                        acquired,
                        self.nflows_hint
                    )
                    .map_err(|err| {
                        ChannelEntryAcquireError::Entry { err: err }
                    })? {
                        RetryResult::Success((acquired, when)) => {
                            let state =
                                AcquireState::Active { acquired: acquired };

                            self.acquired = Some(RetryResult::Success(state));

                            Ok(when)
                        }
                        RetryResult::Retry(retry) => {
                            let (acquired, when) = retry.take();
                            let state = AcquireState::Acquired {
                                acquired: acquired,
                                when: when.clone()
                            };

                            self.acquired = Some(RetryResult::Success(state));

                            Ok(Some(when))
                        }
                    }
                }
            },
            // Retry delay starting acquisition.
            RetryResult::Retry(when) => {
                self.acquired = Some(RetryResult::Retry(when));

                Ok(Some(when))
            }
        }
    }

    fn handle_acquired<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        tokens: &mut Vec<Token>,
        acquired: Types::Acquired
    ) -> Result<
        Option<Instant>,
        AcquiredEntryCreateError<
            Types::ResolverError,
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >
    where
        Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx {
        // XXX possibly transition to shutdown on error?
        match AcquiredEntry::create(
            ctx,
            &mut self.channel,
            tokens,
            &self.flows_config,
            &self.resolve_config,
            &self.addr_policy,
            &self.xfrm_param,
            acquired,
            self.nflows_hint
        )? {
            RetryResult::Success((acquired, refresh_when)) => {
                let state = AcquireState::Active { acquired: acquired };

                self.acquired = Some(RetryResult::Success(state));

                Ok(refresh_when)
            }
            RetryResult::Retry(retry) => {
                let (acquired, when) = retry.take();
                let state = AcquireState::Acquired {
                    acquired: acquired,
                    when: when.clone()
                };

                self.acquired = Some(RetryResult::Success(state));

                Ok(Some(when))
            }
        }
    }
}

impl<Types> FarChannels<Types>
where
    Types: FarChannelsTypes
{
    /// Get an iterator over all names and channel IDs.
    #[inline]
    pub fn ids(&self) -> Iter<'_, String, FarChannelID> {
        self.ids.iter()
    }

    /// Get the name associated with a [FarChannelID].
    ///
    /// # Parameters
    ///
    /// - `id`: [FarChannelID] for which to get the channel name.
    #[inline]
    pub fn name(
        &self,
        id: &FarChannelID
    ) -> &str {
        let idx: usize = id.0;

        &self.names[idx]
    }

    /// Get all the channel names.
    #[inline]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    #[inline]
    pub fn is_shutdown(&self) -> bool {
        self.channels.iter().all(|channel| channel.is_shutdown())
    }

    #[inline]
    pub fn is_shutdown_safe(&self) -> bool {
        self.channels
            .iter()
            .all(|channel| channel.is_shutdown_safe())
    }

    /// Obtain a snapshot of the current set of addresses for one channel.
    ///
    /// This will first check to see if the channel needs to be
    /// refreshed.  It will then return a snapshot of the current set
    /// of addresses.  If the channel is not currently active, `None`
    /// will be returned.`
    ///
    /// # Type Parameters
    ///
    /// - `Ctx`: Type of context from which to obtain name resolution caches.
    ///
    /// # Parameters
    ///
    /// - `ctx`: Context from which to obtain name resolution caches.
    ///
    /// - `id`: ID of the channel for which to get addresses.
    ///
    /// # Return Value
    ///
    /// - `Some((addrs, Some(when)))`: The channel is active, and has `addrs` as
    ///   its current address set.  This will we refreshed at `when`.
    ///
    /// - `Some((addrs, None))`: The channel is active, and has `addrs` as its
    ///   current address set.  This set is permanent.
    ///
    /// - `None`: The channel is not active, and has no resolved addresses.
    pub fn channel_addrs<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        id: &FarChannelID
    ) -> Result<
        RetryResult<Option<(Vec<Types::ChannelParam>, Option<Instant>)>>,
        FarChannelsAddrsError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >
    where
        Ctx: RegistryCtx + TokensCtx {
        let channel = &mut self.channels[id.0];

        channel.is_active().flat_map_ok(|active| {
            if active {
                Ok(channel.addrs(ctx)?.map(Some))
            } else {
                Ok(RetryResult::Success(None))
            }
        })
    }
}

impl<Ctx, Types> Channels<Ctx> for FarChannels<Types>
where
    Types: FarChannelsTypes,
    Ctx: RegistryCtx + TokensCtx
{
    type ChannelID = FarChannelID;
    type Addr = Types::PeerAddr;
    type Param = Types::ChannelParam;
    type Stream = Types::AuthNSession;
    type OutNegoParam = Types::OutParam;
    type ReqStreamError = ChannelEntryReqFlowError<
        AcquiredEntryFlowError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError,
            FlowStateGetFlowError<
                Types::AuthNegoError,
                Types::AuthStartError,
                FlowsFlowError<Types::OutStartError, Types::OutNegoError>,
                ShutdownError<
                    Types::ShutdownStartError,
                    Types::ShutdownNegoError
                >
            >
        >
    >;
    type ParamsIter<I> =
        IntoIter<(FarChannelID,
                  RetryResult<(Vec<Types::ChannelParam>, Option<Instant>)>)>
    where
        I: Iterator<Item = Self::ChannelID>;
    type ParamsError = FarChannelsAddrsError<
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >;

    #[inline]
    fn channel_id(
        &self,
        name: &str
    ) -> Option<FarChannelID> {
        self.ids.get(name).cloned()
    }

    #[inline]
    fn req_stream(
        &mut self,
        ctx: &mut Ctx,
        channel: &Self::ChannelID,
        param: &Self::Param,
        endpoint: &Self::Addr,
        nego_param: &Self::OutNegoParam
    ) -> Result<
        RetryResult<(Option<Types::AuthNSession>,
                     Option<Vec<Types::ChannelParam>>,
                     Option<Instant>)>,
        Self::ReqStreamError
    > {
        self.channels[channel.0].req_flow(ctx, param, endpoint, nego_param)
    }

    #[inline]
    fn params<I>(
        &mut self,
        ctx: &mut Ctx,
        channels: I
    ) -> Result<Self::ParamsIter<I>, Self::ParamsError>
    where I: Iterator<Item = Self::ChannelID> {
        let vec: Result<Vec<(FarChannelID,
                             RetryResult<(Vec<Types::ChannelParam>,
                                          Option<Instant>)>)>,
                        Self::ParamsError> = channels
            .map(|channel| self.channels[channel.0].addrs(ctx)
                 .map(|addrs| (channel, addrs)))
            .collect();

        Ok(vec?.into_iter())
    }
}

impl<Ctx, Types> ChannelsListen<Ctx> for FarChannels<Types>
where
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx,
    Types: FarChannelsTypes {
    type StreamIter = std::vec::IntoIter<
        (Self::Addr, Self::ChannelID, Self::Param, Self::Stream)
    >;
    type EndpointIter = IntoIter<
        (Self::Addr, Self::ChannelID, Self::Param)
    >;
    type ListenError = ChannelEntryListenError<
        AcquiredEntryListenError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >,
            FlowsListenError<
                Types::XfrmError,
                Types::InStartError,
                Types::InNegoError,
                Types::OutNegoError
            >,
            Types::AuthStartError,
            Types::AuthNegoError,
            ShutdownError<
                Types::ShutdownStartError,
                Types::ShutdownNegoError
            >
        >,
        AcquiredEntryCreateError<
            Types::ResolverError,
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >,
        Types::AcquireNegoError,
        Types::AcquireShutdownNegoError
    >;

    fn listen(
        &mut self,
        ctx: &mut Ctx,
        tokens: &HashSet<Token>
    ) -> Result<
        RetryResult<(
            Self::StreamIter,
            Self::EndpointIter,
            Option<Vec<(
                FarChannelID,
                Option<Vec<Types::ChannelParam>>,
            )>>,
            Option<Instant>
        )>,
        Self::ListenError
    > {
        let lives: Vec<FarChannelID> = self
            .tokens
            .iter()
            .flat_map(|(token, id)| {
                if tokens.contains(token) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        let mut sessions = Vec::with_capacity(self.channels.len());
        let mut endpoints = Vec::with_capacity(self.tokens.len());
        let mut updates: Option<Vec<(
            FarChannelID,
            Option<Vec<Types::ChannelParam>>,
        )>> = None;
        let mut next: Option<Instant> = None;
        let mut all_retries = true;
        let nlives = lives.len();

        for id in lives {
            match self.channels[id.0].listen(
                ctx,
                |param, stream| {
                    let endpoint = stream.get().peer_addr()?;

                    sessions.push(
                        (endpoint, id.clone(), param.clone(), stream)
                    );

                    Ok(())
                },
                |endpoint, param| {
                    endpoints.push(
                        (endpoint.clone(), id.clone(), param.clone())
                    );
                },
                tokens
            )? {
                RetryResult::Success((creates, deletes, params, when)) => {
                    if let Some(creates) = creates {
                        for token in creates {
                            if let Some(curr) =
                                self.tokens.insert(token, id.clone())
                            {
                                error!(target: "far-channels",
                                       "tokens contains entry for {:?} ({})",
                                       token, curr);
                            }
                        }
                    }

                    if let Some(deletes) = deletes {
                        for token in deletes {
                            if self.tokens.remove(&token).is_none() {
                                error!(target: "far-channels",
                                       "token {:?} was not in tokens table",
                                       token);
                            }
                        }
                    }

                    if params.is_some() || when.is_some() {
                        match &mut updates {
                            Some(updates) => {
                                updates.push((id, params));
                            }
                            None => {
                                let mut vec = Vec::with_capacity(nlives);

                                vec.push((id, params));

                                updates = Some(vec)
                            }
                        }
                    }

                    next = next_retry(&next, &when);
                    all_retries = false;
                }
                RetryResult::Retry(when) => {
                    next = Some(next_retry_definite(&next, &when));
                }
            }
        }

        if let Some(when) = next {
            if all_retries {
                Ok(RetryResult::Retry(when))
            } else {
                Ok(RetryResult::Success(
                    (sessions.into_iter(), endpoints.into_iter(),
                     updates, Some(when))
                ))
            }
        } else {
            Ok(RetryResult::Success(
                (sessions.into_iter(), endpoints.into_iter(), updates, None)
            ))
        }
    }
}

impl<Ctx, Types> ChannelsShutdown<Ctx> for FarChannels<Types>
where
    Ctx: RegistryCtx,
    Types: FarChannelsTypes {
    type ShutdownStreamError = ChannelEntryShutdownFlowError<
        AcquiredEntryShutdownError<
            FarChannelFlowsError<
                Types::SocketError,
                Types::XfrmCreateError,
                Types::InboundNegoCreateError,
                Types::OutboundNegoCreateError
            >,
            Types::WrapError
        >
    >;

    #[inline]
    fn shutdown_stream(
        &mut self,
        ctx: &mut Ctx,
        channel: &FarChannelID,
        param: &Types::ChannelParam,
        session: Types::AuthNSession
    ) -> Result<
        RetryResult<()>,
        Self::ShutdownStreamError
    > {
        self.channels[channel.0].shutdown_flow(ctx, channel_param, session)
    }

    fn shutdown(
        self,
        ctx: &mut Ctx
    ) -> Result<(), Self::ShutdownError> {
        let registry = ctx.registry();
        let mut out = true;
        let mut errs: Option<Vec<FarChannelID>> = None;
        let mut deletes = Vec::new();
        let nchans = self.channels.len();

        for (id, chan) in self.channels.iter_mut().enumerate() {
            match chan.shutdown(&mut deletes, registry) {
                Ok(shutdown) => out = out && shutdown,
                Err(err) => {
                    error!(target: "far-channels",
                           "error shutting down channel {}: {}",
                           self.names[id], err);

                    let id = FarChannelID(id);

                    match &mut errs {
                        Some(errs) => errs.push(id),
                        None => {
                            let mut vec = Vec::with_capacity(nchans);

                            vec.push(id);

                            errs = Some(vec);
                        }
                    }
                }
            }
        }

        if let Some(errs) = errs.take() {
            Err(errs)
        } else {
            Ok(())
        }
    }
}

impl<'a, Ctx, Types> CreateWithParam<&'a mut Ctx> for FarChannels<Types>
where
    Ctx: NSNameCachesCtx + RegistryCtx + TokensCtx,
    Types: FarChannelsTypes {
    type Config = FarChannelsConfig<
        Types::Config,
        Types::AuthConfig,
        Types::ShutdownParam,
        Types::InnerXfrmCreateParam
    >;
    type CreateError = FarChannelsCreateError<
        Types::AuthCreateError,
        Types::CreateError,
        ChannelEntryCreateError<
            Types::AcquireError,
            Types::ShutdownNegoCreateError,
            Types::AcquireNegoError,
            AcquiredEntryCreateError<
                Types::ResolverError,
                FarChannelFlowsError<
                    Types::SocketError,
                    Types::XfrmCreateError,
                    Types::InboundNegoCreateError,
                    Types::OutboundNegoCreateError
                >,
                Types::WrapError
            >
        >
    >;

    /// Create an instance of this `Channels`.
    fn create(
        config: Self::Config,
        ctx: &'a mut Ctx,
    ) -> Result<Self, Self::CreateError> {
        let (channel_configs, default_resolve, default_authn,
             default_flows_params, default_xfrm_params,
             default_shutdown_params, default_retry,
             default_nflows) = config.take();

        // Ensure no id collisions.
        let mut names = HashSet::with_capacity(channel_configs.len());

        for config in channel_configs.iter() {
            if !names.insert(config.name()) {
                return Err(FarChannelsCreateError::Collision {
                    name: config.name().to_string()
                })
            }
        }

        let mut ids = HashMap::with_capacity(channel_configs.len());
        let mut token_map = HashMap::with_capacity(channel_configs.len());
        let mut names = Vec::with_capacity(channel_configs.len());
        let mut channels = Vec::with_capacity(channel_configs.len());

        for config in channel_configs {
            let (name, channel, resolve, authn_config, flows_params,
                 xfrm_params, shutdown_params, retry, nflows) = config.take();
            let authn_config = authn_config.unwrap_or(default_authn.clone());
            let resolve = resolve.unwrap_or(default_resolve.clone());
            let xfrm_params = xfrm_params
                .unwrap_or(default_xfrm_params.clone());
            let flows_params = flows_params
                .unwrap_or(default_flows_params.clone());
            let shutdown_params = shutdown_params
                .unwrap_or(default_shutdown_params.clone());
            let retry = retry.unwrap_or(default_retry.clone());
            let nflows = nflows.or(default_nflows);

            info!(target: "far-channels",
                  "creating far channel \"{}\"",
                  name);

            let authn = Types::AuthN::create(authn_config)
                .map_err(|err| FarChannelsCreateError::Auth {
                    err: err
                })?;
            let channel = Types::Channel::create(ctx, channel)
                .map_err(|err| FarChannelsCreateError::Channel {
                    err: err
                })?;
            let (channel, tokens, when) = ChannelEntry::create(
                ctx,
                channel,
                authn,
                flows_params,
                resolve,
                xfrm_params,
                retry,
                nflows
            ).map_err(|err| FarChannelsCreateError::Entry {
                err: err
            })?;
            let id = FarChannelID(channels.len());

            channels.push(channel);
            names.push(name.clone());

            for token in tokens {
                if let Some(curr) = token_map.insert(token, id.clone()) {
                    error!(target: "far-channels",
                           "entry for token {} already existed: {}",
                           token.0, curr);
                }
            }

            if let Some(curr) = ids.insert(name.clone(), id) {
                error!(target: "far-channels",
                       "entry for name \"{}\" already existed: {}",
                       name, curr);
            }
        }

        Ok(FarChannels {
            ids: ids,
            names: names,
            channels: channels,
            tokens: token_map
        })
    }
}

impl<Flows, Wrap> ScopedError for FarChannelsRefreshError<Flows, Wrap>
where
    Flows: ScopedError,
    Wrap: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelsRefreshError::NameCaches { err } => err.scope(),
            FarChannelsRefreshError::Flows { err } => err.scope(),
            FarChannelsRefreshError::Wrap { err } => err.scope(),
            FarChannelsRefreshError::IO { err } => err.scope(),
            FarChannelsRefreshError::Inconsistent => ErrorScope::Unrecoverable,
            FarChannelsRefreshError::NoValidAddrs => ErrorScope::External
        }
    }
}

impl<AuthN> ScopedError for AuthNegoStepError<AuthN>
where
    AuthN: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AuthNegoStepError::AuthN { err } => err.scope(),
            AuthNegoStepError::IO { err } => err.scope(),
            AuthNegoStepError::Session => ErrorScope::Unrecoverable
        }
    }
}

impl<AuthN, Shutdown> ScopedError for SessionNegoStepError<AuthN, Shutdown>
where
    AuthN: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionNegoStepError::Auth { err } => err.scope(),
            SessionNegoStepError::Shutdown { err } => err.scope()
        }
    }
}

impl<AuthN, Start> ScopedError for SessionNegoToAuthError<AuthN, Start>
where
    AuthN: ScopedError,
    Start: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionNegoToAuthError::AuthN { err } => err.scope(),
            SessionNegoToAuthError::Start { err } => err.scope(),
            SessionNegoToAuthError::IO { err } => err.scope(),
            SessionNegoToAuthError::NotSession => ErrorScope::Unrecoverable
        }
    }
}

impl<Start, Negotiate> ScopedError for SessionShutdownError<Start, Negotiate>
where
    Negotiate: ScopedError,
    Start: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionShutdownError::Session { err } => err.scope(),
            SessionShutdownError::Shutdown |
            SessionShutdownError::Pending |
            SessionShutdownError::None => ErrorScope::Unrecoverable
        }
    }
}

impl<AuthN, Start, Flow, Shutdown> ScopedError
    for FlowStateGetFlowError<AuthN, Start, Flow, Shutdown>
where
    AuthN: ScopedError,
    Flow: ScopedError,
    Start: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FlowStateGetFlowError::Shutdown { err } => err.scope(),
            FlowStateGetFlowError::ToAuth { err } => err.scope(),
            FlowStateGetFlowError::Flow { err } => err.scope(),
            FlowStateGetFlowError::Impossible |
            FlowStateGetFlowError::Active => ErrorScope::Unrecoverable
        }
    }
}

impl<Acquire, Shutdown, Nego, Entry> ScopedError
    for ChannelEntryCreateError<Acquire, Shutdown, Nego, Entry>
where
    Acquire: ScopedError,
    Shutdown: ScopedError,
    Nego: ScopedError,
    Entry: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryCreateError::Acquire { err } => err.scope(),
            ChannelEntryCreateError::Shutdown { err } => err.scope()
        }
    }
}

impl<Acquire, Nego, Entry> ScopedError
    for ChannelEntryAcquireError<Acquire, Nego, Entry>
where
    Acquire: ScopedError,
    Nego: ScopedError,
    Entry: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryAcquireError::Acquire { err } => err.scope(),
            ChannelEntryAcquireError::Nego { err } => err.scope(),
            ChannelEntryAcquireError::Entry { err } => err.scope()
        }
    }
}

impl<Flow> ScopedError for ChannelEntryShutdownFlowError<Flow>
where
    Flow: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryShutdownFlowError::Flow { err } => err.scope(),
            ChannelEntryShutdownFlowError::IO { err } => err.scope(),
            ChannelEntryShutdownFlowError::Shutdown |
            ChannelEntryShutdownFlowError::Pending |
            ChannelEntryShutdownFlowError::None => ErrorScope::Session
        }
    }
}

impl<Flow> ScopedError for ChannelEntryReqFlowError<Flow>
where
    Flow: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryReqFlowError::Flow { err } => err.scope(),
            ChannelEntryReqFlowError::Shutdown |
            ChannelEntryReqFlowError::Pending |
            ChannelEntryReqFlowError::None => ErrorScope::Session
        }
    }
}

impl<Flow> ScopedError for FarChannelsAddrsError<Flow>
where
    Flow: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelsAddrsError::Flow { err } => err.scope(),
            FarChannelsAddrsError::Shutdown |
            FarChannelsAddrsError::Pending |
            FarChannelsAddrsError::None => ErrorScope::Session
        }
    }
}

impl<Listen, Entry, Nego, Shutdown> ScopedError
    for ChannelEntryListenError<Listen, Entry, Nego, Shutdown>
where
    Listen: ScopedError,
    Entry: ScopedError,
    Nego: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryListenError::Listen { err } => err.scope(),
            ChannelEntryListenError::Entry { err } => err.scope(),
            ChannelEntryListenError::Nego { err } => err.scope(),
            ChannelEntryListenError::Shutdown { err } => err.scope(),
            ChannelEntryListenError::None => ErrorScope::Session
        }
    }
}

impl<Resolve, Flows, Wrap> ScopedError
    for AcquiredEntryCreateError<Resolve, Flows, Wrap>
where
    Resolve: ScopedError,
    Flows: ScopedError,
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryCreateError::NameCaches { err } => err.scope(),
            AcquiredEntryCreateError::Resolve { err } => err.scope(),
            AcquiredEntryCreateError::Flows { err } => err.scope(),
            AcquiredEntryCreateError::Wrap { err } => err.scope(),
            AcquiredEntryCreateError::IO { err } => err.scope(),
            AcquiredEntryCreateError::NoValidAddrs => ErrorScope::External
        }
    }
}

impl<Flows, Start, AuthN, Shutdown> ScopedError
    for SessionListenError<Flows, Start, AuthN, Shutdown>
where
    Flows: ScopedError,
    Start: ScopedError,
    AuthN: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionListenError::Flows { err } => err.scope(),
            SessionListenError::Start { err } => err.scope(),
            SessionListenError::Step { err } => err.scope(),
            SessionListenError::IO { err } => err.scope()
        }
    }
}

impl<Refresh, Flows, Start, AuthN, Shutdown> ScopedError
    for AcquiredEntryListenError<Refresh, Flows, Start, AuthN, Shutdown>
where
    Refresh: ScopedError,
    Flows: ScopedError,
    Start: ScopedError,
    AuthN: ScopedError,
    Shutdown: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryListenError::Refresh { err } => err.scope(),
            AcquiredEntryListenError::Listen { err } => err.scope()
        }
    }
}

impl<Flows, Wrap> ScopedError for AcquiredEntryFlowsError<Flows, Wrap>
where
    Flows: ScopedError,
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryFlowsError::Refresh { err } => err.scope(),
            AcquiredEntryFlowsError::ParamNotFound |
            AcquiredEntryFlowsError::Inconsistent => ErrorScope::Unrecoverable
        }
    }
}

impl<Flows, Wrap> ScopedError for AcquiredEntryShutdownError<Flows, Wrap>
where
    Flows: ScopedError,
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryShutdownError::Refresh { err } => err.scope(),
            AcquiredEntryShutdownError::Inconsistent => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Flows, Wrap, Flow> ScopedError
    for AcquiredEntryFlowError<Flows, Wrap, Flow>
where
    Flows: ScopedError,
    Wrap: ScopedError,
    Flow: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryFlowError::Flows { err } => err.scope(),
            AcquiredEntryFlowError::Flow { err } => err.scope()
        }
    }
}

impl Display for FarChannelID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "far channel {}", self.0)
    }
}

impl<Flows, Wrap> Display for FarChannelsRefreshError<Flows, Wrap>
where
    Flows: Display,
    Wrap: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            FarChannelsRefreshError::NameCaches { err } => err.fmt(f),
            FarChannelsRefreshError::Flows { err } => err.fmt(f),
            FarChannelsRefreshError::Wrap { err } => err.fmt(f),
            FarChannelsRefreshError::IO { err } => err.fmt(f),
            FarChannelsRefreshError::Inconsistent => {
                write!(f, "inconsistent flow tables")
            }
            FarChannelsRefreshError::NoValidAddrs => {
                write!(f, "no valid addresses")
            }
        }
    }
}

impl<AuthN> Display for AuthNegoStepError<AuthN>
where
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AuthNegoStepError::AuthN { err } => err.fmt(f),
            AuthNegoStepError::IO { err } => err.fmt(f),
            AuthNegoStepError::Session => {
                write!(f, "negotiations are still in session phase")
            }
        }
    }
}

impl<AuthN, Shutdown> Display for SessionNegoStepError<AuthN, Shutdown>
where
    AuthN: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoStepError::Auth { err } => err.fmt(f),
            SessionNegoStepError::Shutdown { err } => err.fmt(f)
        }
    }
}

impl<AuthN, Start> Display for SessionNegoToAuthError<AuthN, Start>
where
    Start: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoToAuthError::AuthN { err } => err.fmt(f),
            SessionNegoToAuthError::Start { err } => err.fmt(f),
            SessionNegoToAuthError::IO { err } => err.fmt(f),
            SessionNegoToAuthError::NotSession => {
                write!(f, "negotiations are not in session phase")
            }
        }
    }
}

impl<Flows, Start, AuthN, Shutdown> Display
    for SessionListenError<Flows, Start, AuthN, Shutdown>
where
    Flows: Display,
    Start: Display,
    AuthN: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionListenError::Flows { err } => err.fmt(f),
            SessionListenError::Start { err } => err.fmt(f),
            SessionListenError::Step { err } => err.fmt(f),
            SessionListenError::IO { err } => err.fmt(f)
        }
    }
}

impl<Flows, Shutdown> Display for SessionShutdownStepError<Flows, Shutdown>
where
    Flows: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionShutdownStepError::Flows { err } => err.fmt(f),
            SessionShutdownStepError::Step { err } => err.fmt(f)
        }
    }
}

impl<Start, Negotiate> Display for SessionShutdownError<Start, Negotiate>
where
    Negotiate: Display,
    Start: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionShutdownError::Session { err } => err.fmt(f),
            SessionShutdownError::Shutdown => {
                write!(f, "session has shutdown state")
            }
            SessionShutdownError::Pending => {
                write!(f, "session has pending state")
            }
            SessionShutdownError::None => {
                write!(f, "session has no active state")
            }
        }
    }
}

impl<AuthN, Start, Flow, Shutdown> Display
    for FlowStateGetFlowError<AuthN, Start, Flow, Shutdown>
where
    Shutdown: Display,
    Start: Display,
    Flow: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            FlowStateGetFlowError::Shutdown { err } => err.fmt(f),
            FlowStateGetFlowError::ToAuth { err } => err.fmt(f),
            FlowStateGetFlowError::Flow { err } => err.fmt(f),
            FlowStateGetFlowError::Active => {
                write!(f, "session is already active")
            }
            FlowStateGetFlowError::Impossible => write!(f, "impossible case")
        }
    }
}

impl<Resolve, Flows, Wrap> Display
    for AcquiredEntryCreateError<Resolve, Flows, Wrap>
where
    Resolve: Display,
    Flows: Display,
    Wrap: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryCreateError::NameCaches { err } => err.fmt(f),
            AcquiredEntryCreateError::Resolve { err } => err.fmt(f),
            AcquiredEntryCreateError::Flows { err } => err.fmt(f),
            AcquiredEntryCreateError::Wrap { err } => err.fmt(f),
            AcquiredEntryCreateError::IO { err } => err.fmt(f),
            AcquiredEntryCreateError::NoValidAddrs => {
                write!(f, "no valid addresses")
            }
        }
    }
}

impl<Refresh, Flows, Start, AuthN, Shutdown> Display
    for AcquiredEntryListenError<Refresh, Flows, Start, AuthN, Shutdown>
where
    Refresh: Display,
    Flows: Display,
    Start: Display,
    AuthN: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryListenError::Refresh { err } => err.fmt(f),
            AcquiredEntryListenError::Listen { err } => err.fmt(f)
        }
    }
}

impl<Acquire, Shutdown, Nego, Entry> Display
    for ChannelEntryCreateError<Acquire, Shutdown, Nego, Entry>
where
    Acquire: Display,
    Shutdown: Display,
    Nego: Display,
    Entry: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryCreateError::Acquire { err } => err.fmt(f),
            ChannelEntryCreateError::Shutdown { err } => err.fmt(f)
        }
    }
}

impl<Acquire, Nego, Entry> Display
    for ChannelEntryAcquireError<Acquire, Nego, Entry>
where
    Acquire: Display,
    Nego: Display,
    Entry: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryAcquireError::Acquire { err } => err.fmt(f),
            ChannelEntryAcquireError::Nego { err } => err.fmt(f),
            ChannelEntryAcquireError::Entry { err } => err.fmt(f)
        }
    }
}

impl<Listen, Entry, Nego, Shutdown> Display
    for ChannelEntryListenError<Listen, Entry, Nego, Shutdown>
where
    Listen: Display,
    Entry: Display,
    Nego: Display,
    Shutdown: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryListenError::Listen { err } => err.fmt(f),
            ChannelEntryListenError::Entry { err } => err.fmt(f),
            ChannelEntryListenError::Nego { err } => err.fmt(f),
            ChannelEntryListenError::Shutdown { err } => err.fmt(f),
            ChannelEntryListenError::None => write!(f, "no acquire state")
        }
    }
}

impl<Flows, Wrap> Display for AcquiredEntryFlowsError<Flows, Wrap>
where
    Flows: Display,
    Wrap: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryFlowsError::Refresh { err } => err.fmt(f),
            AcquiredEntryFlowsError::ParamNotFound => {
                write!(f, "no token for requested channel parameter")
            }
            AcquiredEntryFlowsError::Inconsistent => {
                write!(f, "no flows for given token")
            }
        }
    }
}

impl<Flows, Wrap, Flow> Display for AcquiredEntryFlowError<Flows, Wrap, Flow>
where
    Flows: Display,
    Wrap: Display,
    Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryFlowError::Flows { err } => err.fmt(f),
            AcquiredEntryFlowError::Flow { err } => err.fmt(f)
        }
    }
}

impl<Flows, Wrap> Display for AcquiredEntryShutdownError<Flows, Wrap>
where
    Flows: Display,
    Wrap: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryShutdownError::Refresh { err } => err.fmt(f),
            AcquiredEntryShutdownError::Inconsistent => {
                write!(f, "no flows for given token")
            }
        }
    }
}

impl<Flow> Display for ChannelEntryShutdownFlowError<Flow>
where
    Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryShutdownFlowError::Flow { err } => err.fmt(f),
            ChannelEntryShutdownFlowError::IO { err } => err.fmt(f),
            ChannelEntryShutdownFlowError::Shutdown => {
                write!(f, "shutdown negotiations are pending")
            }
            ChannelEntryShutdownFlowError::Pending => {
                write!(f, "session negotiations are pending")
            }
            ChannelEntryShutdownFlowError::None => write!(f, "no acquire state")
        }
    }
}

impl<Flow> Display for FarChannelsAddrsError<Flow>
where
    Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            FarChannelsAddrsError::Flow { err } => err.fmt(f),
            FarChannelsAddrsError::Shutdown => {
                write!(f, "shutdown negotiations are pending")
            }
            FarChannelsAddrsError::Pending => {
                write!(f, "session negotiations are pending")
            }
            FarChannelsAddrsError::None => write!(f, "no acquire state")
        }
    }
}

impl<Flow> Display for ChannelEntryReqFlowError<Flow>
where
    Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryReqFlowError::Flow { err } => err.fmt(f),
            ChannelEntryReqFlowError::Pending => {
                write!(f, "session negotiations are pending")
            }
            ChannelEntryReqFlowError::Shutdown => {
                write!(f, "shutdown negotiations are pending")
            }
            ChannelEntryReqFlowError::None => {
                write!(f, "no current acquire state")
            }
        }
    }
}

impl<Start, Nego> Display for ChannelEntryShutdownError<Start, Nego>
where
    Start: Display,
    Nego: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryShutdownError::Start { err } => err.fmt(f),
            ChannelEntryShutdownError::Nego { err } => err.fmt(f),
            ChannelEntryShutdownError::Active => {
                write!(f, "channel is still active")
            }
        }
    }
}

impl<Auth, Channel, Entry> Display
    for FarChannelsCreateError<Auth, Channel, Entry>
where Auth: Display,
      Channel: Display,
      Entry: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            FarChannelsCreateError::Auth { err } => err.fmt(f),
            FarChannelsCreateError::Channel { err } => err.fmt(f),
            FarChannelsCreateError::Entry { err } => err.fmt(f),
            FarChannelsCreateError::Collision { name } =>
                write!(f, "multiple channels with id \"{}\"", name)
        }
    }
}

#[cfg(test)]
use std::convert::TryFrom;
#[cfg(test)]
use std::io::ErrorKind;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::iter::empty;
#[cfg(test)]
use std::iter::once;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::sleep;
#[cfg(test)]
use std::thread::spawn;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use constellation_auth::authn::TrivialAuthN;
#[cfg(test)]
use constellation_common::net::IPEndpointAddr;
#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;
#[cfg(test)]
use constellation_common::unix::UnixSocketPath;
#[cfg(test)]
use mio::Events;
#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::config::AddrKind;
#[cfg(test)]
use crate::config::CompoundFarChannelConfig;
#[cfg(test)]
use crate::config::CompoundXfrmCreateParam;
#[cfg(test)]
use crate::far::compound::CompoundFarChannelSessionCred;
#[cfg(test)]
use crate::far::compound::CompoundFarChannelXfrmPeerAddr;
#[cfg(test)]
use crate::far::compound::CompoundFlow;
#[cfg(test)]
use crate::far::compound::CompoundOutboundNegotiatorParam;
#[cfg(test)]
use crate::far::dtls::DTLSOutboundParam;
#[cfg(test)]
use crate::far::types::CompoundFarChannelsTypes;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd)]
struct TestPrin;

#[cfg(test)]
type TestFarChannelsTypes = CompoundFarChannelsTypes<
    TrivialAuthN<
        TestPrin,
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >
    >,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>
>;

#[cfg(test)]
impl From<CompoundFarChannelSessionCred> for TestPrin {
    #[inline]
    fn from(_val: CompoundFarChannelSessionCred) -> TestPrin {
        TestPrin
    }
}

#[cfg(test)]
impl Display for TestPrin {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        write!(f, "test principal")
    }
}

#[cfg(test)]
fn get_acquired<Types, Ctx>(
    ctx: &mut Ctx,
    poll: &mut Poll,
    endpoints: &mut HashSet<Types::PeerAddr>,
    sessions: &mut Vec<Types::AuthNSession>,
    channel: Types::Channel,
    authn: Types::AuthN,
    flows_config: FlowsConfig,
    resolve_config: ResolverConfig,
    addr_policy: SocketAddrPolicy,
    xfrm_param: Types::InnerXfrmCreateParam,
    token: Token
) -> (
    ChannelEntry<Types>,
    Vec<Types::ChannelParam>,
    Option<Instant>
)
where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    let (mut ent, creates, _) = ChannelEntry::create(
        &mut once(token),
        ctx,
        poll.registry(),
        channel,
        authn,
        flows_config,
        resolve_config,
        addr_policy,
        xfrm_param,
        Retry::default(),
        None
    )
    .expect("Expected success");

    assert_eq!(creates, vec![token]);

    let is_acquired = match ent.is_active() {
        RetryResult::Success(is_acquired) => is_acquired,
        _ => panic!("Should not see retry result here")
    };

    if is_acquired {
        loop {
            match ent
                .addrs(&mut empty(), poll.registry())
                .expect("Expected success")
            {
                RetryResult::Success((params, when)) => {
                    return (ent, params, when);
                }
                RetryResult::Retry(when) => {
                    let now = Instant::now();

                    if now < when {
                        sleep(when - now)
                    }
                }
            }
        }
    } else {
        let mut events = Events::with_capacity(2);
        let mut count = 0;
        let mut live = HashSet::new();

        loop {
            trace!(target: "get-acquired",
                   "polling");

            if count > 10 {
                panic!("Timeout")
            }

            poll.poll(&mut events, Some(Duration::from_secs(1)))
                .expect("Expected success");

            count += 1;

            trace!(target: "get-acquired",
                   "polling returned");

            for event in events.iter() {
                trace!(target: "get-acquired",
                       "event for token {:?}", event.token());

                live.insert(event.token());
            }

            trace!(target: "get-acquired",
                   "listening");

            match ent
                .listen(
                    ctx,
                    &mut empty(),
                    endpoints,
                    sessions,
                    poll.registry(),
                    &live
                )
                .expect("Expected success")
            {
                RetryResult::Success((None, None, Some(params), when)) => {
                    return (ent, params, when)
                }
                RetryResult::Success((Some(_), _, _, _)) |
                RetryResult::Success((_, Some(_), _, _)) => {
                    panic!("Creates/deletes should be empty!")
                }
                _ => {}
            }

            live.clear();
            assert!(endpoints.is_empty());
            assert!(sessions.is_empty());
        }
    }
}

#[cfg(test)]
fn get_in_session<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll,
    endpoints: &mut HashSet<Types::PeerAddr>
) -> Types::AuthNSession
where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    let mut sessions = Vec::new();
    let mut events = Events::with_capacity(2);
    let mut count = 0;
    let mut live = HashSet::new();

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

        ent.listen(
            ctx,
            &mut empty(),
            endpoints,
            &mut sessions,
            poll.registry(),
            &live
        )
        .expect("");

        live.clear();

        assert!(endpoints.is_empty());
    }

    sessions.pop().expect("Expected some")
}

#[cfg(test)]
fn get_out_session<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll,
    endpoints: &mut HashSet<Types::PeerAddr>,
    endpoint: &Types::PeerAddr,
    channel_param: &Types::ChannelParam,
    out_param: &Types::OutParam
) -> Types::AuthNSession
where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    match ent
        .req_flow(
            &mut empty(),
            poll.registry(),
            channel_param,
            endpoint,
            out_param
        )
        .expect("Expected success")
    {
        RetryResult::Success((Some(out), params, _)) => {
            trace!(target: "get-out-session",
                   "got outbound session immediately");

            assert!(params.is_none());

            out
        }
        RetryResult::Success((None, params, _)) => {
            let mut sessions = Vec::new();
            let mut events = Events::with_capacity(2);
            let mut count = 0;
            let mut live = HashSet::new();

            assert!(params.is_none());

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

                let _ = ent.listen(
                    ctx,
                    &mut empty(),
                    endpoints,
                    &mut sessions,
                    poll.registry(),
                    &live
                );

                live.clear();
                assert!(endpoints.is_empty());
            }

            sessions.pop().expect("Expected some")
        }
        _ => panic!("Should not see retry delay here")
    }
}

#[cfg(test)]
fn read_one<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll,
    flow: &mut Types::Flow,
    buf: &mut [u8],
    endpoint: &Types::PeerAddr
) -> Result<usize, Error>
where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    trace!(target: "read-one",
           "trying to read without polling");

    match flow.read(buf) {
        Ok(len) => {
            trace!(target: "read-one",
                   "successfully read");

            Ok(len)
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock => {
                let mut sessions = Vec::new();
                let mut endpoints = HashSet::new();
                let mut events = Events::with_capacity(2);
                let mut count = 0;
                let mut live = HashSet::new();

                loop {
                    trace!(target: "read-one",
                           "polling");

                    if count > 10 {
                        panic!("Timeout")
                    }

                    poll.poll(&mut events, Some(Duration::from_secs(1)))
                        .expect("Expected success");

                    count += 1;

                    trace!(target: "read-one",
                           "polling returned");

                    for event in events.iter() {
                        trace!(target: "read-one",
                               "event for token {:?}", event.token());

                        live.insert(event.token());
                    }

                    trace!(target: "read-one",
                           "listening");

                    ent.listen(
                        ctx,
                        &mut empty(),
                        &mut endpoints,
                        &mut sessions,
                        poll.registry(),
                        &live
                    )
                    .expect("");

                    live.clear();

                    assert!(sessions.is_empty());

                    if endpoints.contains(endpoint) {
                        break;
                    }
                }

                flow.read(buf)
            }
            _ => Err(err)
        }
    }
}

#[cfg(test)]
fn write_one<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll,
    flow: &mut Types::Flow,
    buf: &[u8],
    endpoint: &Types::PeerAddr
) -> Result<usize, Error>
where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    trace!(target: "write-one",
           "trying to write without polling");

    match flow.write(buf) {
        Ok(len) => {
            trace!(target: "write-one",
                   "successfully wrote");

            Ok(len)
        }
        Err(err) => match err.kind() {
            ErrorKind::WouldBlock => {
                let mut sessions = Vec::new();
                let mut endpoints = HashSet::new();
                let mut events = Events::with_capacity(2);
                let mut count = 0;
                let mut live = HashSet::new();

                loop {
                    trace!(target: "write-one",
                           "polling");

                    if count > 10 {
                        panic!("Timeout")
                    }

                    poll.poll(&mut events, Some(Duration::from_secs(1)))
                        .expect("Expected success");

                    count += 1;

                    trace!(target: "write-one",
                           "polling returned");

                    for event in events.iter() {
                        trace!(target: "write-one",
                               "event for token {:?}", event.token());

                        live.insert(event.token());
                    }

                    trace!(target: "write-one",
                           "listening");

                    ent.listen(
                        ctx,
                        &mut empty(),
                        &mut endpoints,
                        &mut sessions,
                        poll.registry(),
                        &live
                    )
                    .expect("");

                    live.clear();

                    assert!(sessions.is_empty());

                    if endpoints.contains(endpoint) {
                        break;
                    }
                }

                flow.write(buf)
            }
            _ => Err(err)
        }
    }
}

#[cfg(test)]
fn shutdown_session<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll,
    channel_param: &Types::ChannelParam,
    session: Types::AuthNSession
) where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    match ent
        .shutdown_flow(&mut empty(), poll.registry(), channel_param, session)
        .expect("Expected success")
    {
        RetryResult::Success((params, _)) => {
            assert!(params.is_none());
        }
        _ => panic!("Should not see retry delay here")
    }

    let mut sessions = Vec::new();
    let mut events = Events::with_capacity(2);
    let mut count = 0;
    let mut live = HashSet::new();
    let mut endpoints = HashSet::new();

    while !ent.is_shutdown_safe() {
        trace!(target: "shutdown-session",
               "polling");

        if count > 10 {
            panic!("Timeout")
        }

        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .expect("Expected success");

        count += 1;

        trace!(target: "shutdown-session",
               "polling returned");

        for event in events.iter() {
            trace!(target: "shutdown-session",
                   "event for token {:?}", event.token());

            live.insert(event.token());
        }

        trace!(target: "shutdown-session",
               "listening");

        ent.listen(
            ctx,
            &mut empty(),
            &mut endpoints,
            &mut sessions,
            poll.registry(),
            &live
        )
        .expect("");

        live.clear();
        assert!(endpoints.is_empty());
        assert!(sessions.is_empty());
    }
}

#[cfg(test)]
fn shutdown_entry<Ctx, Types>(
    ent: &mut ChannelEntry<Types>,
    ctx: &mut Ctx,
    poll: &mut Poll
) where
    Types: FarChannelsTypes,
    Ctx: NSNameCachesCtx {
    let mut deletes = Vec::new();

    if !ent
        .shutdown(&mut deletes, poll.registry())
        .expect("Expected success")
    {
        let mut sessions = Vec::new();
        let mut events = Events::with_capacity(2);
        let mut count = 0;
        let mut live = HashSet::new();
        let mut endpoints = HashSet::new();

        while !ent.is_shutdown() {
            trace!(target: "shutdown-entry",
                   "polling");

            if count > 10 {
                panic!("Timeout")
            }

            poll.poll(&mut events, Some(Duration::from_secs(1)))
                .expect("Expected success");

            count += 1;

            trace!(target: "shutdown-entry",
                   "polling returned");

            for event in events.iter() {
                trace!(target: "shutdown-entry",
                       "event for token {:?}", event.token());

                live.insert(event.token());
            }

            trace!(target: "shutdown-entry",
                   "listening");

            ent.listen(
                ctx,
                &mut empty(),
                &mut endpoints,
                &mut sessions,
                poll.registry(),
                &live
            )
            .expect("");

            live.clear();
            assert!(endpoints.is_empty());
            assert!(sessions.is_empty());
        }
    }
}

#[cfg(test)]
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

#[cfg(test)]
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[cfg(test)]
fn entry_test<Types, Ctx>(
    nscaches: &mut Ctx,
    server_config: Types::Config,
    client_config: Types::Config,
    server_authn: Types::AuthN,
    client_authn: Types::AuthN,
    flows_config: FlowsConfig,
    resolve_config: ResolverConfig,
    xfrm_param: Types::InnerXfrmCreateParam,
    server_endpoint: Types::PeerAddr,
    out_param: Types::OutParam
) where
    Types: FarChannelsTypes,
    Ctx: 'static + Clone + NSNameCachesCtx + Send,
    Types::AuthN: 'static + Send,
    Types::Config: 'static + Send,
    Types::ChannelParam: 'static + Send,
    Types::InnerXfrmCreateParam: 'static + Send,
    Types::OutParam: 'static + Send,
    Types::PeerAddr: 'static + Send {
    let addr_kinds = &[AddrKind::IPv6, AddrKind::IPv4];
    let barrier = Arc::new(Barrier::new(2));

    let mut server_nscaches = nscaches.clone();
    let server_flows_config = flows_config.clone();
    let server_resolve_config = resolve_config.clone();
    let server_xfrm_param = xfrm_param.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let policy = SocketAddrPolicy::create(addr_kinds);
        let mut poll = Poll::new().expect("Expected success");
        let listener = Types::Channel::create(
            &mut server_nscaches,
            &mut empty(),
            server_config
        )
        .expect("Expected success");
        let mut endpoints: HashSet<Types::PeerAddr> = HashSet::new();
        let mut sessions: Vec<Types::AuthNSession> = Vec::new();
        let (mut entry, params, _) = get_acquired::<Types, _>(
            &mut server_nscaches,
            &mut poll,
            &mut endpoints,
            &mut sessions,
            listener,
            server_authn,
            server_flows_config,
            server_resolve_config,
            policy,
            server_xfrm_param,
            Token(0)
        );

        assert!(endpoints.is_empty());
        assert!(!entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        server_barrier.wait();

        let param = match &params[..] {
            [param] => param,
            _ => panic!("Expected exactly one param")
        };

        let mut session = if let Some(session) = sessions.pop() {
            assert!(sessions.is_empty());

            session
        } else {
            get_in_session(
                &mut entry,
                &mut server_nscaches,
                &mut poll,
                &mut endpoints
            )
        };

        let peer_addr = session.get().peer_addr().expect("Expected success");

        assert!(!entry.is_shutdown());
        assert!(!entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(
            &mut entry,
            &mut server_nscaches,
            &mut poll,
            session.get_mut(),
            &mut buf,
            &peer_addr
        )
        .expect("Expected success");

        write_one(
            &mut entry,
            &mut server_nscaches,
            &mut poll,
            session.get_mut(),
            &SECOND_BYTES,
            &peer_addr
        )
        .expect("Expected success");

        server_barrier.wait();

        shutdown_session(
            &mut entry,
            &mut server_nscaches,
            &mut poll,
            &param,
            session
        );

        assert!(!entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        server_barrier.wait();

        shutdown_entry(&mut entry, &mut server_nscaches, &mut poll);

        assert!(entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(false));

        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let policy = SocketAddrPolicy::create(addr_kinds);
        let mut poll = Poll::new().expect("Expected success");
        let conn = Types::Channel::create(
            &mut client_nscaches,
            &mut empty(),
            client_config
        )
        .expect("Expected success");
        let mut endpoints: HashSet<Types::PeerAddr> = HashSet::new();
        let mut sessions: Vec<Types::AuthNSession> = Vec::new();
        let (mut entry, params, _) = get_acquired::<Types, _>(
            &mut client_nscaches,
            &mut poll,
            &mut endpoints,
            &mut sessions,
            conn,
            client_authn,
            flows_config,
            resolve_config,
            policy,
            xfrm_param,
            Token(0)
        );

        assert!(endpoints.is_empty());
        assert!(sessions.is_empty());
        assert!(!entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        client_barrier.wait();

        let param = match &params[..] {
            [param] => param,
            _ => panic!("Expected exactly one param")
        };
        let mut session: Types::AuthNSession = get_out_session(
            &mut entry,
            &mut client_nscaches,
            &mut poll,
            &mut endpoints,
            &server_endpoint,
            &param,
            &out_param
        );
        let peer_addr = session.get().peer_addr().expect("Expected success");

        assert!(!entry.is_shutdown());
        assert!(!entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        write_one(
            &mut entry,
            &mut client_nscaches,
            &mut poll,
            session.get_mut(),
            &FIRST_BYTES,
            &peer_addr
        )
        .expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];
        let nbytes = read_one(
            &mut entry,
            &mut client_nscaches,
            &mut poll,
            session.get_mut(),
            &mut buf,
            &peer_addr
        )
        .expect("Expected success");

        client_barrier.wait();

        shutdown_session(
            &mut entry,
            &mut client_nscaches,
            &mut poll,
            &param,
            session
        );

        assert!(!entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(true));

        client_barrier.wait();

        shutdown_entry(&mut entry, &mut client_nscaches, &mut poll);

        assert!(entry.is_shutdown());
        assert!(entry.is_shutdown_safe());
        assert_eq!(entry.is_active(), RetryResult::Success(false));

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}

#[cfg(test)]
fn compound_entry_test(
    server_conf: &str,
    client_conf: &str,
    server_endpoint: CompoundFarChannelXfrmPeerAddr,
    out_param: CompoundOutboundNegotiatorParam
) {
    init();

    let mut nscaches = SharedNSNameCaches::new();
    let server_config: CompoundFarChannelConfig =
        serde_yaml::from_str(server_conf).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(client_conf).unwrap();
    let flows_config = FlowsConfig::default();
    let resolver_config = ResolverConfig::default();
    let server_authn = TrivialAuthN::default();
    let client_authn = TrivialAuthN::default();
    let xfrm_param = CompoundXfrmCreateParam::default();

    entry_test::<TestFarChannelsTypes, _>(
        &mut nscaches,
        server_config,
        client_config,
        server_authn,
        client_authn,
        flows_config,
        resolver_config,
        xfrm_param,
        server_endpoint,
        out_param
    )
}

#[test]
fn test_compound_unix() {
    init();

    const SERVER_PATH: &'static str = "test_far_channels_unix_server.sock";
    const SERVER_CONFIG: &'static str = concat!(
        "unix-datagram:\n",
        "  path: test_far_channels_unix_server.sock\n",
    );
    const CLIENT_CONFIG: &'static str = concat!(
        "unix-datagram:\n",
        "  path: test_far_channels_unix_client.sock\n",
    );
    let server_endpoint = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(SERVER_PATH).unwrap()
    );
    let out_param = CompoundOutboundNegotiatorParam::Basic;

    compound_entry_test(
        SERVER_CONFIG,
        CLIENT_CONFIG,
        server_endpoint,
        out_param
    )
}

#[test]
fn test_compound_udp() {
    init();

    const SERVER_CONFIG: &'static str =
        concat!("udp:\n", "  addr: ::0\n", "  port: 8200\n");
    const CLIENT_CONFIG: &'static str =
        concat!("udp:\n", "  addr: ::0\n", "  port: 8201\n");
    let server_endpoint = CompoundFarChannelXfrmPeerAddr::udp(
        "[::1]:8200".parse().expect("Expected success")
    );
    let out_param = CompoundOutboundNegotiatorParam::Basic;

    compound_entry_test(
        SERVER_CONFIG,
        CLIENT_CONFIG,
        server_endpoint,
        out_param
    )
}

#[test]
fn test_compound_dtls_unix() {
    init();

    const SERVER_PATH: &'static str = "test_far_channels_dtls_unix_server.sock";
    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_far_channels_dtls_unix_server.sock\n",
    );
    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  key: tests/data/certs/client/private/test_client_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_far_channels_dtls_unix_client.sock\n",
    );
    let server_endpoint = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(SERVER_PATH).unwrap()
    );
    let servername = "test-server.nowhere.com";
    let endpoint = IPEndpointAddr::name(String::from(servername));
    let out_param = CompoundOutboundNegotiatorParam::DTLS {
        dtls: Box::new(DTLSOutboundParam::new(
            endpoint,
            CompoundOutboundNegotiatorParam::Basic
        ))
    };

    compound_entry_test(
        SERVER_CONFIG,
        CLIENT_CONFIG,
        server_endpoint,
        out_param
    )
}

#[test]
fn test_compound_dtls_udp() {
    init();

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  udp:\n",
        "    addr: ::0\n",
        "    port: 8210\n"
    );
    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  key: tests/data/certs/client/private/test_client_key.pem\n",
        "  udp:\n",
        "    addr: ::0\n",
        "    port: 8211\n"
    );
    let server_endpoint = CompoundFarChannelXfrmPeerAddr::udp(
        "[::1]:8210".parse().expect("Expected success")
    );
    let servername = "test-server.nowhere.com";
    let endpoint = IPEndpointAddr::name(String::from(servername));
    let out_param = CompoundOutboundNegotiatorParam::DTLS {
        dtls: Box::new(DTLSOutboundParam::new(
            endpoint,
            CompoundOutboundNegotiatorParam::Basic
        ))
    };

    compound_entry_test(
        SERVER_CONFIG,
        CLIENT_CONFIG,
        server_endpoint,
        out_param
    )
}
