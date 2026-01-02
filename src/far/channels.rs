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
use std::collections::hash_map::Iter;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Instant;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::SessionAuthN;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpoint;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Negotiator;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_common::retry::RetryWhen;
use constellation_common::retry::WithRetryWhen;
use constellation_common::sched::Policy;
use constellation_streams::addrs::Addrs;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use mio::event::Source;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Registry;
use mio::Token;

use crate::addrs::SocketAddrPolicy;
use crate::channels::ShutdownError;
use crate::channels::WithShutdownError;
use crate::config::AddrsConfig;
use crate::config::AddrKind;
use crate::config::FlowsConfig;
use crate::config::ResolverConfig;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelFlowsError;
use crate::far::flows::BufferedFlow;
use crate::far::flows::Flows;
use crate::far::flows::FlowsFlowError;
use crate::far::flows::FlowsListenError;
use crate::far::flows::ListenResult;
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
enum SessionState<Stream, AuthN, ShutdownNego>
where Stream: Session,
      AuthN: SessionAuthN<Stream>,
      ShutdownNego: NegotiatorStart<(), Stream>,
      ShutdownNego::NegotiateError: ScopedError
{
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        pending: SessionNegoState<AuthN::Pending>
    },
    /// A session has already been established.
    Active,
    /// Session shutdown is pending.
    Shutdown {
        /// The pending shutdown negotiation state.
        pending: ShutdownNego::Pending
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
struct FlowNegoState<Flow, AuthN, ShutdownNego>
where Flow: Session,
      AuthN: SessionAuthN<Flow>,
      ShutdownNego: NegotiatorStart<(), Flow>,
      ShutdownNego::NegotiateError: ScopedError
{
    /// Current session negotiation state, if there are active
    /// negotiations.
    state: Option<SessionState<Flow, AuthN, ShutdownNego>>,
    /// Retry information for establishing this flow.
    retry: FlowsRetry
}

/// Representation of a [Flows], and all of its [Flow] sessions and
/// negotiations.
struct FlowsEntry<Flow, Sock, InboundNego, OutboundNego,
                  ShutdownNego, AuthN, Xfrm>
where
    Flow: Session,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), Flow>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError
{
    /// All sessions either active or in negotiation.
    sessions: HashMap<Xfrm::PeerAddr, FlowNegoState<Flow, AuthN, ShutdownNego>>,
    /// The [Flows] to which all sessions correspond.
    flows: Flows<Flow, Sock, InboundNego, OutboundNego, Xfrm>,
    /// Retry information for listening for new sessions.
    retry: FlowsRetry
}

/// Entry associated with an acquired value on a channel.
///
/// This will hold all [FlowsEntry]s corresponding to the channel
/// parameters associated with the acquired value.  It will
/// periodically refresh these values and update states as necessary.
struct AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    AuthN: Clone + SessionAuthN<Channel::Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError
{
    xfrm: PhantomData<Xfrm>,
    auth: PhantomData<AuthN>,
    /// Acquired value from the channel.
    acquired: Channel::Acquired,
    /// Resolver generated by the acquired value.
    resolver: AcquiredResolver<Channel::Param>,
    /// Current set of [Flows] for the various
    /// [Param](FarChannelSocket::Param)s.
    ///
    /// An acquired far channel allows sockets to be created, but
    /// there may be multiple possible configurations that can be set
    /// up.
    tokens: HashMap<Channel::Param, Token>,
    /// Map from tokens to flows entries
    flows: HashMap<
        Token,
        FlowsEntry<Channel::Flow, Channel::Socket, Channel::InboundNego,
                   Channel::OutboundNego, Channel::ShutdownNego, AuthN, Xfrm>
    >,
    /// Configuration information used to create new [Flows].
    flows_config: FlowsConfig,
    /// Parameter used to create new [DatagramXfrm]s.
    xfrm_param: InnerXfrm::CreateParam,
    /// Size hint for the number of flows.
    nflows_hint: Option<usize>
}

/// Acquisition negotiation information.
///
/// This will ultimately create an [AcquiredEntry] when negotiations
/// succeed, and will manage any shutdown associated with the
/// underlying channel.
enum AcquireState<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    AuthN: Clone + SessionAuthN<Channel::Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError
{
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        state: Channel::AcquirePending,
    },
    /// The acquisition negotiations are complete, but resolution was
    /// delayed.
    Acquired {
        /// The acquired value.
        acquired: Channel::Acquired,
        /// When to retry.
        when: Instant,
    },
    /// A session has already been established.
    Active {
        /// The associated
        acquired: AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>
    },
    /// Shutdown negotiations are pending.
    Shutdown {
        /// State of pending shutdown negotiations.
        pending: Channel::ShutdownPending
    }
}

pub(crate) struct ChannelEntry<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    AuthN: Clone + SessionAuthN<Channel::Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError
{
    /// Authenticator to use for session authentication.
    authn: AuthN,
    /// Base [FarChannel](crate::far::FarChannel) object.
    channel: Channel,
    /// Shutdown negotiator for channels.
    shutdown: Channel::ShutdownNego,
    /// Shutdown negotiator parameter.
    shutdown_param: <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::Param,
    /// Configuration used to create [Flows].
    flows_config: FlowsConfig,
    /// Configuration used to create [Resolver]s.
    resolve_config: ResolverConfig,
    /// Address policy.
    addr_policy: SocketAddrPolicy,
    /// Parameter used to create the basic [DatagramXfrm].
    xfrm_param: InnerXfrm::CreateParam,
    /// Retry configuration.
    retry: Retry,
    /// Size hint for flows tables.
    nflows_hint: Option<usize>,
    /// Acquired value and flows, if a value has been acquired.
    ///
    /// This is used to store when to retry, if
    /// [Retry](RetryResult::Retry) is present.
    acquired: Option<RetryResult<AcquireState<Channel, AuthN, Xfrm, InnerXfrm>>>,
}

pub struct FarChannels<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError,
    AuthN: Clone + SessionAuthN<Channel::Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
    /// Map from names to [FarChannelID]s.
    ids: HashMap<String, FarChannelID>,
    /// Reverse map from [FarChannelID]s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Channel, AuthN, Xfrm, InnerXfrm>>

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
    /// Token iterator exhausted.
    NoTokens
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

pub enum FlowStateGetFlowError<AuthN, Start, Flow, Shutdown> {
    /// Error occurred shutting down the stream
    Shutdown {
        err: Shutdown
    },
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
        err: ShutdownError<Start, Negotiate>,
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
    /// No valid addresses were produced.
    NoValidAddrs,
    /// Token iterator exhausted.
    NoTokens
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
    },
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
    Flow {
        err: Flow
    }
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
    Acquire {
        err: Acquire
    },
    Nego {
        err: Nego
    },
    Entry {
        err: Entry
    }
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
    },
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
pub enum ChannelEntryAddrsError<Flow> {
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
    Listen {
        err: Listen
    },
    Entry {
        err: Entry
    },
    Nego {
        err: Nego
    },
    Shutdown {
        err: Shutdown
    },
    None
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
    /// - `NegotiatorResult::Complete(session)`: If authentication
    ///   succeeded immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are
    ///   still pending.
    fn auth<Flow, AuthN>(
        authn: &AuthN,
        flow: Flow,
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        Flow: Session,
        AuthN: SessionAuthN<Flow>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, Flow>, Flow,
                          Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, Flow>,
                     Pending = AuthPending>,
    {
        // Start authentication negotiations.
        let state = authn
            .start(&(), flow)
            .map_err(|err| SessionNegoToAuthError::Start {
                err: err
            })?;

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
    /// - `NegotiatorResult::Complete(session)`: If authentication
    ///   succeeded immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are
    ///   still pending.
    fn to_auth<Flow, AuthN>(
        self,
        authn: &AuthN,
        flow: Flow
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        Flow: Session,
        AuthN: SessionAuthN<Flow>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, Flow>,
                          Flow, Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, Flow>,
                     Pending = AuthPending>,
    {
        if let SessionNegoState::Session = self {
            // Start authentication negotiations.
            let state = authn
                .start(&(), flow)
                .map_err(|err| SessionNegoToAuthError::Start {
                    err: err
                })?;

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
    /// - `NegotiatorResult::Complete(session)`: If authentication
    ///   succeeded immediately
    ///
    /// - `NegotiationResult::Pending(self)`: If negotiations are
    ///   still pending.
    fn step_auth<Flow, AuthN>(
        self,
        authn: &AuthN
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>, Self>,
        AuthNegoStepError<AuthN::NegotiateError>
    >
    where
        Flow: Session,
        AuthN: SessionAuthN<Flow, Pending = AuthPending, Param = ()> {
        match self {
            // Resuming session negotiations.
            SessionNegoState::Session { .. } => Err(AuthNegoStepError::Session),
            // Resuming authentication negotiations.
            SessionNegoState::AuthN { pending } =>
                Ok(authn
                   .complete_negotiate(pending)
                   .map_err(|err| AuthNegoStepError::AuthN { err: err })?
                   .map_pending(|pending| SessionNegoState::AuthN {
                       pending: pending
                   }))
        }
    }
}

impl<Flow, AuthN, ShutdownNego> FlowNegoState<Flow, AuthN, ShutdownNego>
where
    Flow: Session,
    AuthN: SessionAuthN<Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Flow>,
    ShutdownNego::NegotiateError: ScopedError
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `peer`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `(self, Some(session))`: If authentication negotiations succeeded.
    ///
    /// - `(self, None)`: If authentication negotiations are pending,
    ///   or failed and will be retried later.
    fn create<Addr>(
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        flow: Flow,
        peer: Addr
    ) -> Result<
        (Self, Option<AuthN::AuthNSession>),
        WithShutdownError<
            SessionNegoToAuthError<
                AuthN::NegotiateError,
                AuthN::StartError,
            >,
            ShutdownNego::StartError,
            ShutdownNego::NegotiateError
        >
    >
    where Addr: Display
    {
        let mut new = FlowNegoState {
            state: None,
            retry: FlowsRetry::new()
        };
        let res = new.recv_flow(shutdown, param, authn, retry, flow, peer)?;

        Ok((new, res))
    }

    /// Check if this session is shut down.
    #[inline]
    fn is_shutdown(&self) -> bool {
        self.state.is_none()
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `addr`: Counterparty's address, used for logging.
    ///
    /// - `res`: Authentication negotiation result to process.
    ///
    /// - `err_stream`: Function to possibly recover a [Flow] from an
    ///   error in `res`.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If the result denotes an authentication success.
    ///
    /// - `None`: If the result does not produce an authenticated session.
    fn handle_to_auth_result<Addr, Err, F>(
        &mut self,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        retry: &Retry,
        addr: &Addr,
        res: Result<
            NegotiatorResult<AuthNResult<AuthN::AuthNSession, Flow>,
                             SessionNegoState<AuthN::Pending>>,
            Err
        >,
        err_stream: F
    ) -> Result<
        Option<AuthN::AuthNSession>,
        WithShutdownError<Err, ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
    >
    where
        F: FnOnce(Err) -> Option<Flow>,
        Addr: Display,
        Err: Display + ScopedError
    {
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
            },
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
                self.state = Some(SessionState::Pending {
                    pending: pending
                });

                Ok(None)
            }
            // Error occurred; check its scope.
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System =>
                    Err(WithShutdownError::Inner { err: err }),
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
        res: NegotiatorResult<(), ShutdownNego::Pending>
    )
    where Addr: Display
    {
        match res {
            NegotiatorResult::Complete(()) => {
                info!(target: "flows-nego-state",
                      "shutdown session with {}",
                      addr);

                self.state = None;
            }
            NegotiatorResult::Pending(pending) => {
                debug!(target: "flows-nego-state",
                       "continuing shutdown negotiation with {}",
                       addr);

                self.state = Some(SessionState::Shutdown {
                    pending: pending
                });
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
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
    /// - `None`: If authentication negotiations are pending, or
    ///   failed and will be retried later.
    fn create_flow<Sock, InboundNego, OutboundNego, Xfrm>(
        &mut self,
        flows: &mut Flows<Flow, Sock, InboundNego, OutboundNego, Xfrm>,
        shutdown: &ShutdownNego,
        shutdown_param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        param: &OutboundNego::Param,
        addr: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        FlowStateGetFlowError<
            AuthN::NegotiateError,
            AuthN::StartError,
            FlowsFlowError<OutboundNego::StartError,
                           OutboundNego::NegotiateError>,
            ShutdownError<ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
        >
    >
    where
          Sock: Socket + Sender + Receiver + Source,
          OutboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
          InboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
          Xfrm: DatagramXfrm,
          Xfrm::LocalAddr: From<Sock::Addr>,
          Sock::Addr: TryFrom<Xfrm::LocalAddr>,
          <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
          Xfrm::PeerAddr: Clone + Display + Eq + Hash
    {
        // Check if we're still delayed
        let now = Instant::now();

        if self.retry.retry_when <= now {
            // Good to go. Try creating a flow
            if let Some(flow) = flows.flow(param, addr.clone())
                .map_err(|err| FlowStateGetFlowError::Flow { err: err })? {
                // The session negotiation returned immediately.
                // Start authentication.
                let res = SessionNegoState::auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown, shutdown_param, retry, addr, res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } =>
                            authn.start_err_stream(err),
                        SessionNegoToAuthError::AuthN { err } =>
                            authn.err_stream(err),
                        _ => None
                    })
                    .map(RetryResult::Success)
                    .map_err(|err| match err {
                        WithShutdownError::Shutdown { err } =>
                            FlowStateGetFlowError::Shutdown { err: err },
                        WithShutdownError::Inner { err } =>
                            FlowStateGetFlowError::ToAuth { err: err },
                    })
            } else {
                // Session negotiations are pending.
                let pending = SessionNegoState::session();

                self.state = Some(SessionState::Pending {
                    pending: pending
                });

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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
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
    /// - `None`: If authentication negotiations are pending, or
    ///   failed and will be retried later.
    fn get_flow<Sock, InboundNego, OutboundNego, Xfrm>(
        &mut self,
        flows: &mut Flows<Flow, Sock, InboundNego, OutboundNego, Xfrm>,
        shutdown: &ShutdownNego,
        shutdown_param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        param: &OutboundNego::Param,
        addr: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        FlowStateGetFlowError<
            AuthN::NegotiateError,
            AuthN::StartError,
            FlowsFlowError<OutboundNego::StartError,
                           OutboundNego::NegotiateError>,
            ShutdownError<ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
        >
    >
    where
          Sock: Socket + Sender + Receiver + Source,
          OutboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
          InboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
          Xfrm: DatagramXfrm,
          Xfrm::LocalAddr: From<Sock::Addr>,
          Sock::Addr: TryFrom<Xfrm::LocalAddr>,
          <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
          Xfrm::PeerAddr: Clone + Display + Eq + Hash
    {
        if let Some(state) = &self.state {
            match state {
                // Negotiations are pending, there is no session.
                SessionState::Pending { .. } |
                SessionState::Shutdown { .. } => Ok(RetryResult::Success(None)),
                // There's already an active session.
                SessionState::Active => Err(FlowStateGetFlowError::Active),
            }
        } else {
            // No session exists; we need to start one.
            self.create_flow(flows, shutdown, shutdown_param,
                             authn, retry, param, addr)
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `flow`: Negotiated session to use.
    ///
    /// - `peer`: Counterparty's address, used for logging.
    ///
    /// # Return Value
    ///
    /// - `Some(session)`: If authentication negotiations succeeded.
    ///
    /// - `None`: If authentication negotiations are pending, or
    ///   failed and will be retried later.
    fn recv_flow<Addr>(
        &mut self,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        flow: Flow,
        peer: Addr
    ) -> Result<
        Option<AuthN::AuthNSession>,
        WithShutdownError<
            SessionNegoToAuthError<
                AuthN::NegotiateError,
                AuthN::StartError,
            >,
            ShutdownNego::StartError,
            ShutdownNego::NegotiateError
        >
    >
    where Addr: Display
    {
        let state = self.state.take();

        match state {
            // There's already an active session, but this isn't an error.
            Some(SessionState::Active) => {
                info!(target: "flows-nego-state",
                      "discarding session from {}, active session exists",
                      peer);

                Ok(None)
            }
            // A pending negotiation exists; advance it to the
            // authentication stage.
            Some(SessionState::Pending { pending }) => {
                let res = pending.to_auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown, param, retry, &peer, res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } =>
                            authn.start_err_stream(err),
                        SessionNegoToAuthError::AuthN { err } =>
                            authn.err_stream(err),
                        _ => None
                    })
            }
            // No existing state at all; start fresh in the
            // authentication state.
            //
            // Alternatively, shutdown negotiations were pending, and
            // this discards them.

            // XXX Possibly rate-limit incoming connections to
            // avoid DoS?
            Some(SessionState::Shutdown { .. }) | None => {
                let res = SessionNegoState::auth(authn, flow);

                self.handle_to_auth_result(
                    shutdown, param, retry, &peer, res,
                    |err| match err {
                        SessionNegoToAuthError::Start { err } =>
                            authn.start_err_stream(err),
                        SessionNegoToAuthError::AuthN { err } =>
                            authn.err_stream(err),
                        _ => None
                    })
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
    ///   authenticated session returned by
    ///   [create](FlowNegoState::create),
    ///   [get_flow](FlowNegoState::get_flow), or
    ///   [step](FlowNegoState::step).
    fn do_shutdown_session<Addr>(
        &mut self,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        addr: Addr,
        session: Flow
    ) -> Result<
        (),
        ShutdownError<ShutdownNego::StartError,
                      ShutdownNego::NegotiateError>
    >
    where Addr: Display
    {
        let state = shutdown.start(param, session)
            .map_err(|err| ShutdownError::Start { err: err })?;
        let res = shutdown.negotiate(state)
            .map_err(|err| ShutdownError::Negotiate {
                err: err
            })?;

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
    ///   authenticated session returned by
    ///   [create](FlowNegoState::create),
    ///   [get_flow](FlowNegoState::get_flow), or
    ///   [step](FlowNegoState::step).
    fn shutdown_session<Addr>(
        &mut self,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        addr: Addr,
        session: AuthN::AuthNSession
    ) -> Result<
        (),
        SessionShutdownError<ShutdownNego::StartError,
                             ShutdownNego::NegotiateError>
    >
    where Addr: Display
    {
        match &self.state {
            // This is what we expect.
            Some(SessionState::Active) => {
                error!(target: "flows-nego-state",
                       "shutting down active session with {}",
                       addr);

                let (_, session) = session.take();

                self.do_shutdown_session(shutdown, param, addr, session)
                    .map_err(|err| SessionShutdownError::Session {
                        err: err
                    })
            }
            // None of these should ever happen, but they're not
            // fatal.
            Some(SessionState::Pending { .. }) =>
                Err(SessionShutdownError::Pending),
            Some(SessionState::Shutdown { .. }) =>
                Err(SessionShutdownError::Shutdown),
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
        shutdown: &ShutdownNego,
        addr: Addr,
    ) -> Result<
        (),
        ShutdownError<ShutdownNego::StartError, ShutdownNego::NegotiateError>
    >
    where Addr: Display + Eq + Hash
    {
        let state = self.state.take();

        match state {
            Some(SessionState::Shutdown { pending }) => {
                let res = shutdown
                    .complete_negotiate(pending)
                    .map_err(|err| ShutdownError::Negotiate {
                        err: err
                    })?;

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
    /// - `ext_endpoints`: Set of endpoints that have received
    ///   messages.  If the session is fully-authenticated and receives
    ///   messages, then `addr` will be added to this.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `addr`: Counterparty's address.
    fn step<Addr>(
        &mut self,
        ext_endpoints: &mut HashSet<Addr>,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        addr: Addr,
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoStepError<AuthN::NegotiateError,
                             ShutdownError<ShutdownNego::StartError,
                                           ShutdownNego::NegotiateError>>
    >
    where Addr: Display + Eq + Hash
    {
        let state = self.state.take();

        match state {
            // A pending negotiation exists; step it.
            Some(SessionState::Pending { pending }) => {
                let res = pending.step_auth(authn);

                self.handle_to_auth_result(
                    shutdown, param, retry, &addr, res,
                    |err| match err {
                        AuthNegoStepError::AuthN { err } =>
                            authn.err_stream(err),
                        _ => None
                    })
                    .map_err(|err| match err {
                        WithShutdownError::Shutdown { err } =>
                            SessionNegoStepError::Shutdown { err: err },
                        WithShutdownError::Inner { err } =>
                            SessionNegoStepError::Auth { err: err }
                    })
            }
            // There's already an active session, but this isn't an error.
            Some(SessionState::Active) => {
                ext_endpoints.insert(addr);

                Ok(None)
            }
            Some(SessionState::Shutdown { pending }) => {
                let res = shutdown
                    .complete_negotiate(pending)
                    .map_err(|err| SessionNegoStepError::Shutdown {
                        err: ShutdownError::Negotiate {
                            err: err
                        }
                    })?;

                self.handle_shutdown_result(addr, res);

                Ok(None)
            }
            // No existing state at all; ignore this.
            None => {
                debug!(target: "flows-nego-state",
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

impl<Flow, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm>
    FlowsEntry<Flow, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm>
where
    Flow: Session,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), Flow>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::PeerAddr: From<Flow::PeerAddr>,
    Xfrm::Error: ScopedError
{
    /// Create a new `FlowsEntry` from a [Flows].
    ///
    /// # Parameters
    ///
    /// - `flows`: The [Flows] to use.
    #[inline]
    fn new(
        flows: Flows<Flow, Sock, InboundNego, OutboundNego, Xfrm>,
    ) -> Self {
        let sessions = HashMap::new();

        FlowsEntry {
            retry: FlowsRetry::new(),
            sessions: sessions,
            flows: flows,
        }
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
        flows: Flows<Flow, Sock, InboundNego, OutboundNego, Xfrm>,
        nsessions: usize
    ) -> Self {
        let sessions = HashMap::with_capacity(nsessions);

        FlowsEntry {
            retry: FlowsRetry::new(),
            sessions: sessions,
            flows: flows,
        }
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `out_param`: Parameter used by the outbound negotiator.
    ///
    /// - `endpoint`: The counterparty's address.
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success(Some(session))`: If authentication
    ///   negotiations succeeded.
    ///
    /// - `RetryResult::Success(None)`: If authentication negotiations
    ///   are pending, or failed and will be retried later.
    fn req_flow(
        &mut self,
        shutdown: &ShutdownNego,
        shutdown_param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        out_param: &OutboundNego::Param,
        endpoint: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        FlowStateGetFlowError<
            AuthN::NegotiateError,
            AuthN::StartError,
            FlowsFlowError<
                OutboundNego::StartError,
                OutboundNego::NegotiateError
            >,
            ShutdownError<ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
        >
    > {
        let now = Instant::now();

        match self.sessions.entry(endpoint.clone()) {
            Entry::Occupied(mut ent) => {
                let ent = ent.get_mut();

                if ent.retry.retry_when <= now {
                    let out = ent.get_flow(&mut self.flows,
                                           shutdown, shutdown_param,
                                           authn, retry, out_param, endpoint)?;

                    Ok(out)
                } else {
                    Ok(RetryResult::Retry(ent.retry.retry_when))
                }
            },
            Entry::Vacant(ent) => {
                let ent = ent.insert(FlowNegoState {
                    state: None,
                    retry: FlowsRetry::new()
                });

                let out = ent.get_flow(&mut self.flows,
                                       shutdown, shutdown_param,
                                       authn, retry, out_param, endpoint)?;

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
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        session: AuthN::AuthNSession,
        endpoint: Flow::PeerAddr
    ) -> Result<
        (),
        SessionShutdownError<ShutdownNego::StartError,
                             ShutdownNego::NegotiateError>
    > {
        let endpoint = Xfrm::PeerAddr::from(endpoint);

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
    /// - `ext_endpoints`: Set of all endpoints that have pending
    ///   traffic.
    ///
    /// - `sessions`: Buffer for new authenticated sessions.
    ///
    /// - `shutdown`: [Negotiator] to use to shut down sessions.
    ///
    /// - `shutdown_param`: Parameter for beginning shutdown negotiations.
    ///
    /// - `authn`: [SessionAuthN] instance to use for authentication.
    ///
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `param`: Parameter used by the inbound negotiator.
    fn listen(
        &mut self,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>,
        shutdown: &ShutdownNego,
        shutdown_param: &ShutdownNego::Param,
        authn: &AuthN,
        retry: &Retry,
        param: &InboundNego::Param,
    ) -> Result<
        (),
        SessionListenError<
            FlowsListenError<Xfrm::Error, InboundNego::StartError,
                             InboundNego::NegotiateError,
                             OutboundNego::NegotiateError>,
            AuthN::StartError,
            AuthN::NegotiateError,
            ShutdownError<ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
        >
    > {
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
                                ListenResult::Existing { endpoint } => if self
                                    .sessions.contains_key(&endpoint) {
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
                    // Error; see if it's WouldBlock.
                    Err(err) => if err.scope() == ErrorScope::WouldBlock {
                        // Non-blocking I/O exhausted.
                        break;
                    } else {
                        // A real error occurred.
                        return Err(SessionListenError::Flows { err: err });
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
                            .recv_flow(shutdown, shutdown_param,
                                       authn, retry, flow, endpoint)
                            .map_err(|err| match err {
                                WithShutdownError::Inner { err } =>
                                    SessionListenError::Start {
                                        err: err
                                    },
                                WithShutdownError::Shutdown { err } =>
                                    SessionListenError::Step {
                                        err: SessionNegoStepError::Shutdown {
                                            err: err
                                        }
                                    }
                            })? {
                            debug!(target: "flows-nego-state",
                                   "reporting completed session");

                            // Session negotiations complete; report it out.
                            sessions.push(session)
                        }
                    },
                    Entry::Vacant(ent) => {
                        trace!(target: "flows-nego-state",
                               "no entry for flow {}",
                               ent.key());

                        let (state, session) =
                            FlowNegoState::create(shutdown, shutdown_param,
                                                  authn, retry, flow, endpoint)
                            .map_err(|err| match err {
                                WithShutdownError::Inner { err } =>
                                    SessionListenError::Start {
                                        err: err
                                    },
                                WithShutdownError::Shutdown { err } =>
                                    SessionListenError::Step {
                                        err: SessionNegoStepError::Shutdown {
                                            err: err
                                        }
                                    }
                            })?;

                        ent.insert(state);

                        if let Some(session) = session {
                            debug!(target: "flows-nego-state",
                                   "reporting completed session");

                            // Session negotiations complete; report it out.
                            sessions.push(session)
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
                    if let Some(session) = ent
                        .step(ext_endpoints, shutdown, shutdown_param,
                              authn, retry, endpoint)
                        .map_err(|err| SessionListenError::Step {
                            err: err
                        })? {
                        debug!(target: "flows-nego-state",
                               "reporting completed session");

                        // Session negotiations complete; report it out.
                        sessions.push(session);
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
        shutdown: &ShutdownNego,
        param: &InboundNego::Param,
    ) -> Result<
        (),
        SessionShutdownStepError<
            FlowsListenError<Xfrm::Error, InboundNego::StartError,
                             InboundNego::NegotiateError,
                             OutboundNego::NegotiateError>,
            ShutdownError<ShutdownNego::StartError,
                          ShutdownNego::NegotiateError>
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
                                ListenResult::Existing { endpoint } => if self
                                    .sessions.contains_key(&endpoint) {
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
                    // Error; see if it's WouldBlock.
                    Err(err) => if err.scope() == ErrorScope::WouldBlock {
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

            // Process all negotiation steps.
            for endpoint in endpoints.drain() {
                trace!(target: "flows-nego-state",
                       "traffic on flow {}",
                       endpoint);

                // Look up the session.
                if let Some(ent) = self.sessions.get_mut(&endpoint) {
                    read = true;

                    // Step negotiations.
                    ent.shutdown_step(shutdown, endpoint)
                        .map_err(|err| SessionShutdownStepError::Step {
                            err: err
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

impl<Flow, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm> Source
    for FlowsEntry<Flow, Sock, InboundNego, OutboundNego,
                   ShutdownNego, AuthN, Xfrm>
where
    Flow: Session,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<Flow, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), Flow>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::PeerAddr: From<Flow::PeerAddr>,
    Xfrm::Error: ScopedError
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

impl<Channel, AuthN, Xfrm, InnerXfrm>
    AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError,
    AuthN: Clone + SessionAuthN<Channel::Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::PeerAddr: From<<Channel::Flow as Session>::PeerAddr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    InnerXfrm::CreateParam: Clone,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
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
    /// - `Ctx`: Type of context from which to obtain name resolution
    ///   caches.
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokgen`: Generator for [Token]s.
    ///
    /// - `caches`: Context from which to obtain name resolution caches.
    ///
    /// - `channel`: [FarChannel] that provided `acquired`.
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
    /// - `RetryResult::Success((self, Some(when)))`: Resolution was
    ///   successful, and will need to be refreshed again at `when`.`
    ///
    /// - `RetryResult::Success((self, None))`: Resolution was
    ///   successful, and will not ever need to be refreshed.
    ///
    /// - `RetryResult::Retry(when)`: Resolution was delayed, and can
    ///   be retried at `when`.
    fn create<Ctx, I>(
        tokgen: &mut I,
        caches: &mut Ctx,
        channel: &mut Channel,
        flows_config: &FlowsConfig,
        resolve_config: &ResolverConfig,
        policy: &SocketAddrPolicy,
        xfrm_param: &InnerXfrm::CreateParam,
        acquired: Channel::Acquired,
        nflows_hint: Option<usize>,
    ) -> Result<
        RetryResult<(Self, Option<Instant>), WithRetryWhen<Channel::Acquired>>,
        AcquiredEntryCreateError<
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx {
        let mut resolver = acquired
            .resolver(caches, policy, resolve_config)
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
                    trace!(target: "far-channel-registry",
                           "refreshing addresses for registry entry");

                    let mut flows = HashMap::with_capacity(resolved.len());
                    let mut tokens = HashMap::with_capacity(resolved.len());

                    // Filter out all the addresses we're keeping.
                    for (addr, _, _) in resolved {
                        if policy.check_ip(&addr.ip()) {
                            trace!(target: "far-channel-registry",
                                   "keeping address: {}",
                                   addr);

                            let addr = acquired.wrap(addr).map_err(|err| {
                                AcquiredEntryCreateError::Wrap {
                                    err: err
                                }
                            })?;

                            debug!(target: "far-channel-registry",
                                   "establishing flows for {}",
                                   addr);

                            let xfrm = InnerXfrm::create(&addr, xfrm_param);
                            let session = channel
                                .flows(flows_config.clone(), addr.clone(), xfrm)
                                .map_err(|err| AcquiredEntryCreateError::Flows {
                                    err: err
                                })?;
                            let ent = match nflows_hint {
                                Some(hint) => FlowsEntry::with_capacity(session,
                                                                        hint),
                                None => FlowsEntry::new(session)
                            };
                            let token = tokgen.next()
                                .ok_or(AcquiredEntryCreateError::NoTokens)?;

                            tokens.insert(addr, token.clone());
                            flows.insert(token, ent);
                        } else {
                            debug!(target: "far-channel-registry",
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
                    debug!(target: "far-channel-registry",
                           "establishing flows for {}",
                               addr);

                    let xfrm = InnerXfrm::create(addr, xfrm_param);
                    let session = channel
                        .flows(flows_config.clone(), addr.clone(), xfrm)
                        .map_err(|err| AcquiredEntryCreateError::Flows {
                            err: err
                        })?;
                    let ent = match nflows_hint {
                        Some(hint) => FlowsEntry::with_capacity(session, hint),
                        None => FlowsEntry::new(session)
                    };
                    let token = tokgen.next()
                        .ok_or(AcquiredEntryCreateError::NoTokens)?;

                    tokens.insert(addr.clone(), token.clone());
                    flows.insert(token, ent);
                }

                Ok(RetryResult::Success((tokens, flows, None)))
            }
            AcquiredResolver::StaticSingle { param } => {
                let mut tokens = HashMap::with_capacity(1);
                let mut flows = HashMap::with_capacity(1);

                debug!(target: "far-channel-registry",
                       "establishing flows for {}",
                       param);

                let xfrm = InnerXfrm::create(param, xfrm_param);
                let session = channel
                    .flows(flows_config.clone(), param.clone(), xfrm)
                    .map_err(|err| AcquiredEntryCreateError::Flows {
                        err: err
                    })?;
                let ent = match nflows_hint {
                    Some(hint) => FlowsEntry::with_capacity(session, hint),
                    None => FlowsEntry::new(session)
                };
                let token = tokgen.next()
                    .ok_or(AcquiredEntryCreateError::NoTokens)?;

                tokens.insert(param.clone(), token.clone());
                flows.insert(token, ent);

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
                    flows: flows,
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

    /// Check to see if a refresh is needed.
    fn needs_refresh(&self) -> bool {
        if let AcquiredResolver::Resolve { resolver } = &self.resolver {
            resolver.needs_refresh()
        } else {
            false
        }
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
    /// # Type Parameters
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokens`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
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
    /// - `channel_param`: Channel parameter indicating the specific
    ///   [Flows] from which `session` was obtained.
    ///
    /// - `nego_param`: Parameter used by the outbound negotiator.
    ///
    /// - `endpoint`: The counterparty'ss address.
    fn req_flow<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel: &Channel,
        shutdown: &Channel::ShutdownNego,
        shutdown_param: &<Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::Param,
        authn: &AuthN,
        policy: &SocketAddrPolicy,
        retry: &Retry,
        channel_param: &Channel::Param,
        nego_param: &<Channel::OutboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::Param,
        endpoint: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<(
            Option<AuthN::AuthNSession>,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        AcquiredEntryFlowError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError,
            FlowStateGetFlowError<
                AuthN::NegotiateError,
                AuthN::StartError,
                FlowsFlowError<
                    <Channel::OutboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::StartError,
                    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError
                >,
                ShutdownError<
                    <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::StartError,
                    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError
                >
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        self.flows(tokens, registry, channel, policy, channel_param)
            .map_err(|err| AcquiredEntryFlowError::Flows { err: err })?
            .flat_map_ok(|(ent, addrs, refresh_when)| {
                Ok(ent.req_flow(shutdown, shutdown_param, authn,
                                &retry, nego_param, endpoint)
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
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokens`:  Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// # Return Value
    ///
    /// - `RetryResult::Success((Some(params), Some(when)))`: The set
    ///   of [Flows] changed to `params`, and the channel needs to be
    ///   refreshed at `when`
    ///
    /// - `RetryResult::Success((None, Some(when)))`: The set of
    ///   [Flows] is unchanged, and the channel needs to be refreshed at
    ///   `when`
    ///
    /// - `RetryResult::Success((Some(params), None))`: This case
    ///   should never happen.
    ///
    /// - `RetryResult::Success((None, None))`: Should be returned by
    ///   any entry with a static address set.
    ///
    /// - `RetryResult::Retry(when)`: A refresh is needed, but was
    ///   delayed until `when`.
    // XXX change the return type to eliminate the impossible case.
    fn refresh<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy
    ) -> Result<
        RetryResult<(Option<Vec<Channel::Param>>, Option<Instant>)>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where I: Iterator<Item = Token>
    {
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
                        trace!(target: "far-channel-registry",
                           "refreshing addresses for registry entry");

                        let out = self.update_refreshed(tokens, registry,
                                                        channel, policy,
                                                        resolved.into_iter())?;

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
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokens`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// - `channel_param`: Channel parameter indicating the specific
    ///   [Flows] from which `session` was obtained.
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
    fn shutdown_flow<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        shutdown: &Channel::ShutdownNego,
        param: &<Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::Param,
        channel_param: &Channel::Param,
        session: AuthN::AuthNSession,
        peer: <Channel::Flow as Session>::PeerAddr
    ) -> Result<
        RetryResult<(
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        AcquiredEntryShutdownError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError,
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError,
        >
    >
    where I: Iterator<Item = Token>
    {
        self.refresh(tokens, registry, channel, policy)
            .map_err(|err| AcquiredEntryShutdownError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                // The token might have gotten deleted in the refresh;
                // don't throw a hard error here.
                if let Some(token) = self
                    .tokens
                    .get(channel_param) {
                    // The flows tables should always be consistent.
                    let flows = self
                        .flows
                        .get_mut(&token)
                        .ok_or(AcquiredEntryShutdownError::Inconsistent)?;

                    // Try to shut down the flow.  Errors here aren't
                    // fatal, and should not be reported.
                    if let Err(err) = flows
                        .shutdown_flow(shutdown, param, session, peer) {
                        warn!(target: "",
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
    /// - `tokens`:  Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// - `channel`: [FarChannel] to use to create [Flows].
    ///
    /// - `policy`: Address policy to filter resolved names.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    fn addrs<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where I: Iterator<Item = Token>
    {
        Ok(self
           .refresh(
               tokens,
               registry,
               channel,
               policy,
            )?
            .map(|(out, refresh_when)| match out {
                // No refresh was necessary, generate the addresses directly.
                None => (self.tokens.keys().cloned().collect(), refresh_when),
                // The refresh generated the address list for us.
                Some(out) => (out, refresh_when)
            }))
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
    /// - `ext_endpoints`: Set of all endpoints that have pending
    ///   traffic.
    ///
    /// - `sessions`: Buffer for new authenticated sessions.
    ///
    /// - `tokgen`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to register nonblocking I/O.
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
    /// - `retry`: [Retry] information to use if negotiations need to
    ///   be retried later.
    ///
    /// - `param`: Parameter used by the inbound negotiator.
    ///
    /// - `tokens`: All [Token]s that have pending read traffic.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    fn listen<I>(
        &mut self,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>,
        tokgen: &mut I,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        shutdown: &Channel::ShutdownNego,
        shutdown_param: &<Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::Param,
        authn: &AuthN,
        retry: &Retry,
        param: &<Channel::InboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::Param,
        tokens: &HashSet<Token>,
    ) -> Result<
        RetryResult<(Option<Vec<Channel::Param>>, Option<Instant>)>,
        AcquiredEntryListenError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >,
            FlowsListenError<
                Xfrm::Error,
                <Channel::InboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::StartError,
                <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError,
                <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError
            >,
            AuthN::StartError,
            AuthN::NegotiateError,
            ShutdownError<
                <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::StartError,
                <Channel::ShutdownNego as Negotiator<()>>::NegotiateError
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        self.refresh(tokgen, registry, channel, policy)
            .map_err(|err| AcquiredEntryListenError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                for (_, ent) in self.flows
                    .iter_mut()
                    .filter(|(token, _)| tokens.contains(token)) {
                        ent.listen(ext_endpoints, sessions, shutdown,
                                   shutdown_param, authn, retry, param)
                        .map_err(|err| AcquiredEntryListenError::Listen {
                            err: err
                        })?
                }

                Ok((addrs, refresh_when))
            })
    }

    fn update_refreshed<I, T>(
        &mut self,
        tokens: &mut T,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        resolved: I,
    ) -> Result<
        Vec<Channel::Param>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        I: Iterator<Item = (SocketAddr, IPEndpoint, Instant)>,
        T: Iterator<Item = Token>
    {
        let mut new_tokens = HashMap::with_capacity(self.flows.len());
        let mut new_flows = HashMap::with_capacity(self.flows.len());
        let mut retained = HashSet::with_capacity(self.flows.len());

        for (addr, _, _) in resolved {
            if policy.check(&addr) {
                trace!(target: "far-channel-registry",
                       "keeping address: {}",
                       addr);

                let addr = self.acquired.wrap(addr).map_err(
                    |err| FarChannelsRefreshError::Wrap {
                        err: err
                    }
                )?;

                // Only create a new flows if there isn't one already
                // in existence.
                match self.tokens.remove(&addr) {
                    Some(token) => {
                        trace!(target: "far-channel-registry",
                               "retaining flows for {}",
                               addr);

                        let flows = self.flows.remove(&token)
                            .ok_or(FarChannelsRefreshError::Inconsistent)?;

                        retained.insert(token.clone());
                        new_flows.insert(token.clone(), flows);
                        new_tokens.insert(addr, token);
                    }
                    None => {
                        debug!(target: "far-channel-registry",
                               "establishing flows for {}",
                               addr);

                        let token = tokens.next()
                            .ok_or(FarChannelsRefreshError::NoTokens)?;
                        let xfrm = InnerXfrm::create(&addr, &self.xfrm_param);
                        let flows = channel
                            .flows(self.flows_config.clone(),
                                   addr.clone(),
                                   xfrm)
                            .map_err(|err| {
                                FarChannelsRefreshError::Flows {
                                    err: err
                                }
                            })?;
                        let ent = match self.nflows_hint {
                            Some(hint) => FlowsEntry::with_capacity(flows,
                                                                    hint),
                            None => FlowsEntry::new(flows)
                        };

                        new_flows.insert(token.clone(), ent);
                        new_tokens.insert(addr, token);
                    }
                };
            } else {
                debug!(target: "far-channel-registry",
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
            let deletes: Vec<Token> = self.flows.keys().cloned()
                .filter(|tok| !retained.contains(tok))
                .collect();

            for tok in deletes {
                if let Some(mut flows) = self.flows.remove(&tok) {
                    let addr = flows.flows.local_addr()
                        .map_err(|err| FarChannelsRefreshError::IO {
                            err: err
                        })?;

                    debug!(target: "far-channel-registry",
                           "deregistering flows for {}, token {}",
                           addr, tok.0);

                    flows.flows.deregister(registry)
                        .map_err(|err| FarChannelsRefreshError::IO {
                            err: err
                        })?;
                } else {
                    error!(target: "far-channel-registry",
                           "entry should not be missing for token {}",
                           tok.0);
                }
            }

            Ok(out)
        }
    }

    fn flows<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        param: &Channel::Param,
    ) -> Result<
        RetryResult<(
            &mut FlowsEntry<Channel::Flow, Channel::Socket,
                            Channel::InboundNego, Channel::OutboundNego,
                            Channel::ShutdownNego, AuthN, Xfrm>,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        AcquiredEntryFlowsError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError,
        >
    >
    where I: Iterator<Item = Token>
    {
        self.refresh(tokens, registry, channel, policy)
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

impl<Channel, AuthN, Xfrm, InnerXfrm>
    ChannelEntry<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError: ScopedError,
    AuthN: Clone + SessionAuthN<Channel::Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::PeerAddr: From<<Channel::Flow as Session>::PeerAddr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    InnerXfrm::CreateParam: Clone,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
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
    /// - `Ctx`: Type of context from which to obtain name resolution
    ///   caches.
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `gentok`: Generator for [Token]s.
    ///
    /// - `namectx`: Context from which to obtain name resolution caches.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
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
    pub(crate) fn create<Ctx, I>(
        gentok: &mut I,
        namectx: &mut Ctx,
        registry: &Registry,
        channel: Channel,
        shutdown_param: <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::Param,
        authn: AuthN,
        flows_config: FlowsConfig,
        resolve_config: ResolverConfig,
        addr_policy: SocketAddrPolicy,
        xfrm_param: InnerXfrm::CreateParam,
        retry: Retry,
        nflows_hint: Option<usize>
    ) -> Result<
        (Self, Option<Instant>),
        ChannelEntryCreateError<
            Channel::AcquireError,
            Channel::ShutdownNegoError,
            Channel::NegotiateError,
            AcquiredEntryCreateError<
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx {
        let shutdown = channel.shutdown_negotiator()
            .map_err(|err| ChannelEntryCreateError::Shutdown { err: err })?;
        let mut out = ChannelEntry {
            authn: authn,
            channel: channel,
            flows_config: flows_config,
            resolve_config: resolve_config,
            addr_policy: addr_policy,
            xfrm_param: xfrm_param,
            shutdown: shutdown,
            shutdown_param: shutdown_param,
            retry: retry,
            nflows_hint: nflows_hint,
            acquired: None
        };
        let when = out.try_acquire(gentok, namectx, registry)
            .map_err(|err| ChannelEntryCreateError::Acquire { err: err })?;

        Ok((out, when))
    }

    /// Obtain a snapshot of the current set of addresses.
    ///
    /// This will first do a [refresh](AcquiredEntry::refresh) if
    /// needed.  It will then return the same value as the last
    /// `refresh`.
    ///
    /// # Parameters
    ///
    /// - `tokens`:  Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](ChannelEntry::refresh).
    fn addrs<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        ChannelEntryAddrsError<
            FarChannelsRefreshError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        match self.acquired.as_mut().ok_or(ChannelEntryAddrsError::None)? {
            RetryResult::Success(AcquireState::Active { acquired }) =>
                acquired.addrs(tokens, registry,
                               &self.channel, &self.addr_policy)
                .map_err(|err| ChannelEntryAddrsError::Flow {
                    err: err
                }),
            RetryResult::Success(AcquireState::Pending { .. }) |
            RetryResult::Success(AcquireState::Acquired { .. }) =>
                Err(ChannelEntryAddrsError::Pending),
            RetryResult::Success(AcquireState::Shutdown { .. }) =>
                Err(ChannelEntryAddrsError::Shutdown),
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
    /// # Type Parameters
    ///
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokens`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// - `channel_param`: Resolved channel parameter for which to
    ///   request a [Flow]
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
    pub(crate) fn req_flow<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel_param: &Channel::Param,
        nego_param: &<Channel::OutboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::Param,
        endpoint: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<(
            Option<AuthN::AuthNSession>,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        ChannelEntryReqFlowError<
            AcquiredEntryFlowError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError,
                FlowStateGetFlowError<
                    AuthN::NegotiateError,
                    AuthN::StartError,
                    FlowsFlowError<
                        <Channel::OutboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::StartError,
                        <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError
                    >,
                    ShutdownError<
                        <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::StartError,
                        <Channel::ShutdownNego as Negotiator<()>>::NegotiateError
                    >
                >
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        match self.acquired.as_mut().ok_or(ChannelEntryReqFlowError::None)? {
            // The channel is active; directly request the flow.
            RetryResult::Success(AcquireState::Active { acquired, .. }) =>
                acquired.req_flow(tokens, registry, &self.channel,
                                  &self.shutdown, &self.shutdown_param,
                                  &self.authn, &self.addr_policy, &self.retry,
                                  channel_param, nego_param, endpoint)
                .map_err(|err| ChannelEntryReqFlowError::Flow {
                    err: err
                }),
            // Acquisition is pending.
            RetryResult::Success(AcquireState::Pending { .. } |
                                 AcquireState::Acquired { .. }) =>
                Err(ChannelEntryReqFlowError::Pending),
            // The channel is shutting down.
            RetryResult::Success(AcquireState::Shutdown { .. }) =>
                Err(ChannelEntryReqFlowError::Shutdown),
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
    /// - `I`: Type of generator for [Token]s.
    ///
    /// # Parameters
    ///
    /// - `tokens`: Generator for [Token]s.
    ///
    /// - `registry`: [Registry] to use to deregister expired [Flows].
    ///
    /// - `channel_param`: Channel parameter indicating the specific
    ///   [Flows] from which `session` was obtained.
    ///
    /// - `session`: The session to shut down.
    ///
    /// # Return Value
    ///
    /// Same as for a call to [refresh](AcquiredEntry::refresh).
    pub(crate) fn shutdown_flow<I>(
        &mut self,
        tokens: &mut I,
        registry: &Registry,
        channel_param: &Channel::Param,
        session: AuthN::AuthNSession,
    ) -> Result<
        RetryResult<(
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        ChannelEntryShutdownFlowError<
            AcquiredEntryShutdownError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError,
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError,
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        let addr = session.get().peer_addr()
            .map_err(|err| ChannelEntryShutdownFlowError::IO {
                err: err
            })?;

        match self.acquired.as_mut()
            .ok_or(ChannelEntryShutdownFlowError::None)? {
            RetryResult::Success(AcquireState::Active { acquired, .. }) =>
                acquired.shutdown_flow(tokens, registry, &self.channel,
                                       &self.addr_policy, &self.shutdown,
                                       &self.shutdown_param,
                                       channel_param, session, addr)
                .map_err(|err| ChannelEntryShutdownFlowError::Flow {
                    err: err
                }),
            // None of these should ever happen.
            RetryResult::Success(AcquireState::Pending { .. }) |
            RetryResult::Success(AcquireState::Acquired { .. }) =>
                Err(ChannelEntryShutdownFlowError::Pending),
            RetryResult::Success(AcquireState::Shutdown { .. }) =>
                Err(ChannelEntryShutdownFlowError::Shutdown),
            // If we are delayed, pass the delay along.
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        }
    }

    fn listen<Ctx, I>(
        &mut self,
        namectx: &mut Ctx,
        gentok: &mut I,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>,
        registry: &Registry,
        param: &<Channel::InboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::Param,
        tokens: &HashSet<Token>,
    ) -> Result<
        RetryResult<(Option<Vec<Channel::Param>>, Option<Instant>)>,
        ChannelEntryListenError<
            AcquiredEntryListenError<
                FarChannelsRefreshError<
                    FarChannelFlowsError<
                        Channel::SocketError,
                        Channel::XfrmError,
                        Channel::InboundNegoError,
                        Channel::OutboundNegoError
                    >,
                    <Channel::Acquired as FarChannelAcquired>::WrapError
                >,
                FlowsListenError<
                    Xfrm::Error,
                    <Channel::InboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::StartError,
                    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError,
                    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError
                >,
                AuthN::StartError,
                AuthN::NegotiateError,
                ShutdownError<
                    <Channel::ShutdownNego as NegotiatorStart<(), Channel::Flow>>::StartError,
                    <Channel::ShutdownNego as Negotiator<()>>::NegotiateError
                >
            >,
            AcquiredEntryCreateError<
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >,
            Channel::NegotiateError,
            Channel::ShutdownNegotiateError
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx {
        match self.acquired.take()
            .ok_or(ChannelEntryListenError::None)? {
            RetryResult::Success(AcquireState::Pending { state }) => match self
                .channel.complete_negotiate(state)
                .map_err(|err| ChannelEntryListenError::Nego {
                    err: err
                })? {
                NegotiatorResult::Pending(state) => {
                    let state = AcquireState::Pending { state: state };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(RetryResult::Success((None, None)))
                }
                NegotiatorResult::Complete(acquired) =>
                    self.handle_acquired(gentok, namectx, acquired)
                        .map_err(|err| ChannelEntryListenError::Entry {
                            err: err
                        })
                        .map(|when| RetryResult::Success((None, when))),
            }
            RetryResult::Success(AcquireState::Acquired { acquired, when }) =>
                if when <= Instant::now() {
                    self.handle_acquired(gentok, namectx, acquired)
                        .map_err(|err| ChannelEntryListenError::Entry {
                            err: err
                        })
                        .map(|when| RetryResult::Success((None, when)))
                } else {
                    let state = AcquireState::Acquired {
                        acquired: acquired,
                        when: when
                    };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(RetryResult::Success((None, Some(when))))
                }
            RetryResult::Success(AcquireState::Active { mut acquired }) =>
                match acquired
                    .listen(ext_endpoints, sessions, gentok, registry,
                            &self.channel, &self.addr_policy, &self.shutdown,
                            &self.shutdown_param, &self.authn, &self.retry,
                            param, tokens)
                    .map_err(|err| ChannelEntryListenError::Listen {
                        err: err
                    })? {
                    RetryResult::Success((refreshed, when)) => {
                        let state = AcquireState::Active { acquired: acquired };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Success((refreshed, when)))
                    }
                    RetryResult::Retry(when) => {
                        let state = AcquireState::Active { acquired: acquired };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Retry(when))
                    }
                }
            RetryResult::Success(AcquireState::Shutdown { pending }) =>
                match self.channel
                    .complete_shutdown_negotiate(registry, pending)
                    .map_err(|err| ChannelEntryListenError::Shutdown {
                        err: err
                    })? {
                    // Shutdown is complete; there's nothing more to return.
                    NegotiatorResult::Complete(()) =>
                        Ok(RetryResult::Success((None, None))),
                    // Shutdown is still pending.
                    NegotiatorResult::Pending(pending) => {
                        let state = AcquireState::Shutdown { pending: pending };

                        self.acquired = Some(RetryResult::Success(state));

                        Ok(RetryResult::Success((None, None)))
                    }
                }
            // Pass through any delay.
            RetryResult::Retry(when) => {
                self.acquired = Some(RetryResult::Retry(when));

                Ok(RetryResult::Retry(when))
            }
        }
    }

    fn try_acquire<Ctx, I>(
        &mut self,
        gentok: &mut I,
        namectx: &mut Ctx,
        registry: &Registry,
    ) -> Result<
        Option<Instant>,
        ChannelEntryAcquireError<
            Channel::AcquireError,
            Channel::NegotiateError,
            AcquiredEntryCreateError<
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    Channel::XfrmError,
                    Channel::InboundNegoError,
                    Channel::OutboundNegoError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx {
        match self.channel.acquire(registry)
            .map_err(|err| ChannelEntryAcquireError::Acquire { err: err })? {
            RetryResult::Success(state) => match self.channel.negotiate(state)
                .map_err(|err| ChannelEntryAcquireError::Nego {
                    err: err
                })? {
                // Negotiations are still pending.
                NegotiatorResult::Pending(state) => {
                    let state = AcquireState::Pending {
                        state: state
                    };

                    self.acquired = Some(RetryResult::Success(state));

                    Ok(None)
                }
                // Acquisition negotiations completed.
                NegotiatorResult::Complete(acquired) =>
                    // Create the AcquiredEntry, retry delays at this
                    // point are due to resolution, not acquisition.
                    match AcquiredEntry::create(gentok, namectx,
                                                &mut self.channel,
                                                &self.flows_config,
                                                &self.resolve_config,
                                                &self.addr_policy,
                                                &self.xfrm_param, acquired,
                                                self.nflows_hint)
                        .map_err(|err| ChannelEntryAcquireError::Entry {
                            err: err
                        })? {
                        RetryResult::Success((acquired, when)) => {
                            let state = AcquireState::Active {
                                acquired: acquired
                            };

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
            // Retry delay starting acquisition.
            RetryResult::Retry(when) => {
                self.acquired = Some(RetryResult::Retry(when));

                Ok(Some(when))
            }
        }
    }

    fn handle_acquired<Ctx, I>(
        &mut self,
        gentok: &mut I,
        namectx: &mut Ctx,
        acquired: Channel::Acquired
    ) -> Result<
        Option<Instant>,
        AcquiredEntryCreateError<
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        I: Iterator<Item = Token>,
        Ctx: NSNameCachesCtx {
        // XXX possibly transition to shutdown on error?
        match AcquiredEntry::create(gentok, namectx, &mut self.channel,
                                    &self.flows_config, &self.resolve_config,
                                    &self.addr_policy, &self.xfrm_param,
                                    acquired, self.nflows_hint)? {
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
/*
impl<Channel, AuthN, Xfrm, InnerXfrm>
    FarChannels<Channel, AuthN, Xfrm, InnerXfrm>
where
    Channel: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelCreate,
    <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    AuthN: Clone + SessionAuthN<Channel::Flow>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {

    #[inline]
    fn addrs_id<NameCtx, I>(
        &self,
        caches: &mut NameCtx,
        registry: &Registry,
        tokens: &mut I,
        id: &FarChannelID
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        FarChannelsRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        NameCtx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        let idx: usize = id.0;

        self.channels[idx].
            addrs(
                registry,
                tokens,
                channel: &Channel,
                policy: &SocketAddrPolicy
            )
        // Fall back to write mode.
        match self.channels[idx].write() {
            Ok(mut guard) => guard
                .snapshot_addrs_nonblock(
                    id,
                    caches,
                    &self.policy,
                    &self.resolve_config,
                    &self.authn,
                    &self.reporter,
                    &self.flows_param,
                    &self.xfrm_param
                )
                .map_err(|err| FarChannelRegistryAcquireError::Acquire {
                    err: err
                }),
            Err(_) => Err(FarChannelRegistryAcquireError::MutexPoison)
        }
    }

    /// Get the [FarChannelID] for a given channel name.
    #[inline]
    pub fn id(
        &self,
        name: &str
    ) -> Option<FarChannelID> {
        self.ids.get(name).cloned()
    }

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
}
*/

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
            FarChannelsRefreshError::Inconsistent |
            FarChannelsRefreshError::NoValidAddrs |
            FarChannelsRefreshError::NoTokens => ErrorScope::Unrecoverable
        }
    }
}

impl<AuthN> ScopedError for AuthNegoStepError<AuthN>
where AuthN: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            AuthNegoStepError::AuthN { err } => err.scope(),
            AuthNegoStepError::IO { err } => err.scope(),
            AuthNegoStepError::Session => ErrorScope::Unrecoverable
        }
    }
}

impl<AuthN, Shutdown> ScopedError for SessionNegoStepError<AuthN, Shutdown>
where AuthN: ScopedError,
      Shutdown: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            SessionNegoStepError::Auth { err } => err.scope(),
            SessionNegoStepError::Shutdown { err } => err.scope(),
        }
    }
}

impl<AuthN, Start> ScopedError for SessionNegoToAuthError<AuthN, Start>
where AuthN: ScopedError,
      Start: ScopedError {
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
    Start: ScopedError {
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
where AuthN: ScopedError,
      Flow: ScopedError,
      Start: ScopedError,
      Shutdown: ScopedError {
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
where Acquire: ScopedError,
      Shutdown: ScopedError,
      Nego: ScopedError,
      Entry: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryCreateError::Acquire { err } => err.scope(),
            ChannelEntryCreateError::Shutdown { err } => err.scope(),
        }
    }
}

impl<Acquire, Nego, Entry> ScopedError
    for ChannelEntryAcquireError<Acquire, Nego, Entry>
where Acquire: ScopedError,
      Nego: ScopedError,
      Entry: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryAcquireError::Acquire { err } => err.scope(),
            ChannelEntryAcquireError::Nego { err } => err.scope(),
            ChannelEntryAcquireError::Entry { err } => err.scope(),
        }
    }
}

impl<Flow> ScopedError for ChannelEntryShutdownFlowError<Flow>
where Flow: ScopedError,
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
where Flow: ScopedError,
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

impl<Flow> ScopedError for ChannelEntryAddrsError<Flow>
where Flow: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            ChannelEntryAddrsError::Flow { err } => err.scope(),
            ChannelEntryAddrsError::Shutdown |
            ChannelEntryAddrsError::Pending |
            ChannelEntryAddrsError::None => ErrorScope::Session
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
where Resolve: ScopedError,
      Flows: ScopedError,
      Wrap: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryCreateError::NameCaches { err } => err.scope(),
            AcquiredEntryCreateError::Resolve { err } => err.scope(),
            AcquiredEntryCreateError::Flows { err } => err.scope(),
            AcquiredEntryCreateError::Wrap { err } => err.scope(),
            AcquiredEntryCreateError::NoValidAddrs |
            AcquiredEntryCreateError::NoTokens => ErrorScope::Unrecoverable
        }
    }
}

impl<Flows, Start, AuthN, Shutdown> ScopedError
    for SessionListenError<Flows, Start, AuthN, Shutdown>
where Flows: ScopedError,
      Start: ScopedError,
      AuthN: ScopedError,
      Shutdown: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionListenError::Flows { err } => err.scope(),
            SessionListenError::Start { err } => err.scope(),
            SessionListenError::Step { err } => err.scope()
        }
    }
}

impl<Refresh, Flows, Start, AuthN, Shutdown> ScopedError
    for AcquiredEntryListenError<Refresh, Flows, Start, AuthN, Shutdown>
where Refresh: ScopedError,
      Flows: ScopedError,
      Start: ScopedError,
      AuthN: ScopedError,
      Shutdown: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryListenError::Refresh { err } => err.scope(),
            AcquiredEntryListenError::Listen { err } => err.scope(),
        }
    }
}

impl<Flows, Wrap> ScopedError for AcquiredEntryFlowsError<Flows, Wrap>
where Flows: ScopedError,
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
where Flows: ScopedError,
      Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryShutdownError::Refresh { err } => err.scope(),
            AcquiredEntryShutdownError::Inconsistent =>
                ErrorScope::Unrecoverable
        }
    }
}

impl<Flows, Wrap, Flow> ScopedError
    for AcquiredEntryFlowError<Flows, Wrap, Flow>
where Flows: ScopedError,
      Wrap: ScopedError,
      Flow: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredEntryFlowError::Flows { err } => err.scope(),
            AcquiredEntryFlowError::Flow { err } => err.scope(),
        }
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
            },
            FarChannelsRefreshError::NoValidAddrs => {
                write!(f, "no valid addresses")
            },
            FarChannelsRefreshError::NoTokens => {
                write!(f, "tokens exhausted")
            }
        }
    }
}

impl<AuthN> Display for AuthNegoStepError<AuthN>
where
    AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AuthNegoStepError::AuthN { err } => err.fmt(f),
            AuthNegoStepError::IO { err } => err.fmt(f),
            AuthNegoStepError::Session =>
                write!(f, "negotiations are still in session phase"),
        }
    }
}

impl<AuthN, Shutdown> Display for SessionNegoStepError<AuthN, Shutdown>
where AuthN: Display,
      Shutdown: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoStepError::Auth { err } => err.fmt(f),
            SessionNegoStepError::Shutdown { err } => err.fmt(f),
        }
    }
}

impl<AuthN, Start> Display for SessionNegoToAuthError<AuthN, Start>
where
    Start: Display,
    AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoToAuthError::AuthN { err } => err.fmt(f),
            SessionNegoToAuthError::Start { err } => err.fmt(f),
            SessionNegoToAuthError::IO { err } => err.fmt(f),
            SessionNegoToAuthError::NotSession =>
                write!(f, "negotiations are not in session phase"),
        }
    }
}

impl<Flows, Start, AuthN, Shutdown> Display
    for SessionListenError<Flows, Start, AuthN, Shutdown>
where Flows: Display,
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
            SessionListenError::Step { err } => err.fmt(f)
        }
    }
}

impl<Flows, Shutdown> Display
    for SessionShutdownStepError<Flows, Shutdown>
where Flows: Display,
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
    Start: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionShutdownError::Session { err } => err.fmt(f),
            SessionShutdownError::Shutdown =>
                write!(f, "session has shutdown state"),
            SessionShutdownError::Pending =>
                write!(f, "session has pending state"),
            SessionShutdownError::None =>
                write!(f, "session has no active state")
        }
    }
}

impl<AuthN, Start, Flow, Shutdown> Display
    for FlowStateGetFlowError<AuthN, Start, Flow, Shutdown>
where
    Shutdown: Display,
    Start: Display,
    Flow: Display,
    AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            FlowStateGetFlowError::Shutdown { err } => err.fmt(f),
            FlowStateGetFlowError::ToAuth { err } => err.fmt(f),
            FlowStateGetFlowError::Flow { err } => err.fmt(f),
            FlowStateGetFlowError::Active =>
                write!(f, "session is already active"),
            FlowStateGetFlowError::Impossible =>
                write!(f, "impossible case"),
        }
    }
}

impl<Resolve, Flows, Wrap> Display
    for AcquiredEntryCreateError<Resolve, Flows, Wrap>
where Resolve: Display,
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
            AcquiredEntryCreateError::NoValidAddrs => {
                write!(f, "no valid addresses")
            }
            AcquiredEntryCreateError::NoTokens => {
                write!(f, "tokens exhausted")
            }
        }
    }
}

impl<Refresh, Flows, Start, AuthN, Shutdown> Display
    for AcquiredEntryListenError<Refresh, Flows, Start, AuthN, Shutdown>
where Refresh: Display,
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
            AcquiredEntryListenError::Listen { err } => err.fmt(f),
        }
    }
}

impl<Acquire, Shutdown, Nego, Entry> Display
    for ChannelEntryCreateError<Acquire, Shutdown, Nego, Entry>
where Acquire: Display,
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
            ChannelEntryCreateError::Shutdown { err } => err.fmt(f),
        }
    }
}

impl<Acquire, Nego, Entry> Display
    for ChannelEntryAcquireError<Acquire, Nego, Entry>
where Acquire: Display,
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
            ChannelEntryAcquireError::Entry { err } => err.fmt(f),
        }
    }
}

impl<Listen, Entry, Nego, Shutdown> Display
    for ChannelEntryListenError<Listen, Entry, Nego, Shutdown>
where Listen: Display,
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
            ChannelEntryListenError::None => write!(f, "no acquire state"),
        }
    }
}

impl<Flows, Wrap> Display for AcquiredEntryFlowsError<Flows, Wrap>
where Flows: Display,
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
where Flows: Display,
      Wrap: Display,
      Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredEntryFlowError::Flows { err } => err.fmt(f),
            AcquiredEntryFlowError::Flow { err } => err.fmt(f),
        }
    }
}

impl<Flows, Wrap> Display for AcquiredEntryShutdownError<Flows, Wrap>
where Flows: Display,
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
where Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryShutdownFlowError::Flow { err } => err.fmt(f),
            ChannelEntryShutdownFlowError::IO { err } => err.fmt(f),
            ChannelEntryShutdownFlowError::Shutdown =>
                write!(f, "shutdown negotiations are pending"),
            ChannelEntryShutdownFlowError::Pending =>
                write!(f, "session negotiations are pending"),
            ChannelEntryShutdownFlowError::None =>
                write!(f, "no acquire state"),
        }
    }
}

impl<Flow> Display for ChannelEntryAddrsError<Flow>
where Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryAddrsError::Flow { err } => err.fmt(f),
            ChannelEntryAddrsError::Shutdown =>
                write!(f, "shutdown negotiations are pending"),
            ChannelEntryAddrsError::Pending =>
                write!(f, "session negotiations are pending"),
            ChannelEntryAddrsError::None =>
                write!(f, "no acquire state"),
        }
    }
}

impl<Flow> Display for ChannelEntryReqFlowError<Flow>
where Flow: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ChannelEntryReqFlowError::Flow { err } => err.fmt(f),
            ChannelEntryReqFlowError::Pending =>
                write!(f, "session negotiations are pending"),
            ChannelEntryReqFlowError::Shutdown =>
                write!(f, "shutdown negotiations are pending"),
            ChannelEntryReqFlowError::None =>
                write!(f, "no current acquire state"),
        }
    }
}
