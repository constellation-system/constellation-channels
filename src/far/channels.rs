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
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_common::sched::Policy;
use constellation_streams::addrs::Addrs;
use log::debug;
use log::error;
use log::info;
use log::trace;
use mio::event::Source;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Registry;
use mio::Token;

use crate::addrs::SocketAddrPolicy;
use crate::channels::SessionResult;
use crate::config::AddrsConfig;
use crate::config::AddrKind;
use crate::config::FlowsConfig;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelFlowsError;
use crate::far::flows::BufferedFlow;
use crate::far::flows::Flow;
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
enum SessionNegoState<AuthPending> {
    /// Session negotiation is pending.
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
enum SessionState<F, AuthN, ShutdownNego>
where F: Flow,
      AuthN: SessionAuthN<F>,
      ShutdownNego: NegotiatorStart<(), F>,
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
struct FlowsRetry {
    nfailures: usize,
    retry_when: Instant
}

struct FlowNegoState<F, AuthN, ShutdownNego>
where F: Flow,
      AuthN: SessionAuthN<F>,
      ShutdownNego: NegotiatorStart<(), F>,
      ShutdownNego::NegotiateError: ScopedError
{
    state: Option<SessionState<F, AuthN, ShutdownNego>>,
     /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Instant
}

struct FlowsEntry<F, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), F>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<F>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError
{
    sessions: HashMap<Xfrm::PeerAddr, FlowNegoState<F, AuthN, ShutdownNego>>,
    flows: Flows<F, Sock, InboundNego, OutboundNego, Xfrm>,
    retry: FlowsRetry
}

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
    flows_config: FlowsConfig,
    xfrm_param: InnerXfrm::CreateParam,
    nflows_hint: Option<usize>,
    retry: Retry
}

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
        pending: Channel::State
    },
    /// A session has already been established.
    Acquired {
        acquired: AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>
    }
}

struct ChannelEntry<Channel, AuthN, Xfrm, InnerXfrm>
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
    /// Base [FarChannel](crate::far::FarChannel) object.
    channel: Channel,
    /// Acquired value and flows, if a value has been acquired.
    ///
    /// This is used to store when to retry, if
    /// [Retry](RetryResult::Retry) is present.
    acquired: RetryResult<AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>>,
    /// Retry configuration.
    retry: Retry,
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
    /// Authenticator to use for session authentication.
    authn: AuthN,
    policy: SocketAddrPolicy,
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

pub enum FlowStateGetFlowError<AuthN, Start, Flow> {
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
pub enum AcquireStateCreateError<Acquire, Nego, Flows> {
    Acquire {
        err: Acquire
    },
    Nego {
        err: Nego
    },
    Flows {
        err: Flows
    }
}

impl<AuthPending> SessionNegoState<AuthPending> {
    /// Create a state denoting session negotiations.
    #[inline]
    fn session() -> Self {
        SessionNegoState::Session
    }

    /// Create a state denoting authentication negotiations.
    fn auth<F, AuthN>(
        authn: &AuthN,
        flow: F,
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, ()>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        F: Flow,
        AuthN: SessionAuthN<F>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, ()>, F, Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, ()>,
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

    /// Go into the authentication phase.
    fn to_auth<F, AuthN>(
        self,
        authn: &AuthN,
        flow: F
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, ()>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        F: Flow,
        AuthN: SessionAuthN<F>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, ()>, F, Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, ()>,
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
    fn step_auth<F, AuthN>(
        self,
        authn: &AuthN
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthN::AuthNSession, ()>, Self>,
        AuthNegoStepError<AuthN::NegotiateError>
    >
    where
        F: Flow,
        AuthN: SessionAuthN<F, Pending = AuthPending, Param = ()> {
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

impl<F, AuthN, ShutdownNego> FlowNegoState<F, AuthN, ShutdownNego>
where
    F: Flow,
    AuthN: SessionAuthN<F, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    ShutdownNego: NegotiatorStart<(), F>,
    ShutdownNego::NegotiateError: ScopedError
{
    /// Take an incoming negotiated session and create a state in the
    /// authentication phase.
    fn create(
        authn: &AuthN,
        retry: &Retry,
        flow: F,
    ) -> Result<
        (Self, Option<AuthN::AuthNSession>),
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    > {
        let peer = flow.peer_addr();

        // Try to do authentication negotiations.
        match SessionNegoState::auth(authn, flow) {
            // Negotiations completed immediately; set the state
            // to active and return.
            Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                info!(target: "flows-nego-state",
                      "authenticated new session with {} over {}",
                      out.prin(), peer);

                let new = FlowNegoState {
                    state: Some(SessionState::Active),
                    when: Instant::now(),
                    nretries: 0,
                };

                Ok((new, Some(out)))
            },
            // Authentication failed.
            Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                info!(target: "flows-nego-state",
                      "authentication failed for session with {}",
                      peer);

                let delay = retry.retry_delay(0);

                debug!(target: "flows-nego-state",
                       "authentication failed, delay for {}.{:03}s",
                       delay.as_secs(), delay.subsec_millis());

                let new = FlowNegoState {
                    when: Instant::now() + delay,
                    nretries: 1,
                    state: None
                };

                Ok((new, None))
            }
            // Negotiations stopped in a pending state.
            Ok(NegotiatorResult::Pending(pending)) => {
                let new = FlowNegoState {
                    state: Some(SessionState::Pending {
                        pending: pending
                    }),
                    when: Instant::now(),
                    nretries: 0,
                };

                Ok((new, None))
            }
            // Error occurred; check its scope.
            Err(err) => match err.scope() {
                // Pass these errors through.
                ErrorScope::Unrecoverable |
                ErrorScope::Shutdown |
                ErrorScope::External |
                ErrorScope::System => Err(err),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "flows-nego-state",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    info!(target: "flows-nego-state",
                          "session with {} failed: {}",
                          peer, err);

                    let delay = retry.retry_delay(0);

                    debug!(target: "flows-nego-state",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    let new = FlowNegoState {
                        when: Instant::now() + delay,
                        nretries: 1,
                        state: None
                    };

                    Ok((new, None))
                }
            }
        }
    }

    fn handle_to_auth_result(
        &mut self,
        retry: &Retry,
        peer: &F::PeerAddr,
        res: Result<
            NegotiatorResult<AuthNResult<AuthN::AuthNSession, ()>,
                             SessionNegoState<AuthN::Pending>>,
            SessionNegoToAuthError<
                AuthN::NegotiateError,
                AuthN::StartError,
            >
        >
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    > {
        match res {
            // Negotiations completed immediately; set the state
            // to active and return.
            Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                info!(target: "flows-nego-state",
                      "authenticated new session with {} over {}",
                      out.prin(), peer);

                self.state = Some(SessionState::Active);
                self.nretries = 0;

                Ok(Some(out))
            },
            // Authentication failed.
            Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                info!(target: "flows-nego-state",
                      "authentication failed for session with {}",
                      peer);

                let delay = retry.retry_delay(self.nretries);

                debug!(target: "flows-nego-state",
                       "authentication failed, delay for {}.{:03}s",
                       delay.as_secs(), delay.subsec_millis());

                self.state = None;
                self.nretries += 1;
                self.when = Instant::now() + delay;

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
                ErrorScope::System => Err(err),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "flows-nego-state",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    info!(target: "flows-nego-state",
                          "session with {} failed: {}",
                          peer, err);

                    let delay = retry.retry_delay(self.nretries);

                    debug!(target: "flows-nego-state",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.state = None;
                    self.nretries += 1;
                    self.when = Instant::now() + delay;

                    Ok(None)
                }
            }
        }
    }

    fn create_flow<Sock, InboundNego, OutboundNego, Xfrm>(
        &mut self,
        flows: &mut Flows<F, Sock, InboundNego, OutboundNego, Xfrm>,
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
                           OutboundNego::NegotiateError>
        >
    >
    where
          Sock: Socket + Sender + Receiver + Source,
          OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
          InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
          Xfrm: DatagramXfrm,
          Xfrm::LocalAddr: From<Sock::Addr>,
          Sock::Addr: TryFrom<Xfrm::LocalAddr>,
          <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
          Xfrm::PeerAddr: Clone + Display + Eq + Hash
    {
        // Check if we're still delayed
        let now = Instant::now();

        if self.when < now {
            // Good to go. Try creating a flow
            if let Some(flow) = flows.flow(param, addr.clone())
                .map_err(|err| FlowStateGetFlowError::Flow { err: err })? {
                // The session negotiation returned
                // immediately.  Start authentication.

                match SessionNegoState::auth(authn, flow) {
                    // Negotiations completed immediately; set the state
                    // to active and return.
                    Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                        info!(target: "flows-nego-state",
                              "authenticated new session with {} over {}",
                              out.prin(), addr);

                        self.state = Some(SessionState::Active);
                        self.nretries = 0;

                        Ok(RetryResult::Success(Some(out)))
                    },
                    // Authentication failed.
                    Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                        info!(target: "flows-nego-state",
                              "authentication failed for session with {}",
                              addr);

                        let delay = retry.retry_delay(self.nretries);

                        debug!(target: "flows-nego-state",
                               "authentication failed, delay for {}.{:03}s",
                               delay.as_secs(), delay.subsec_millis());

                        self.state = None;
                        self.nretries += 1;
                        self.when = Instant::now() + delay;

                        Ok(RetryResult::Retry(self.when))
                    }
                    // Negotiations stopped in a pending state.
                    Ok(NegotiatorResult::Pending(pending)) => {
                        self.state = Some(SessionState::Pending {
                            pending: pending
                        });

                        Ok(RetryResult::Success(None))
                    }
                    // Error occurred; check its scope.
                    Err(err) => match err.scope() {
                        // Pass these errors through.
                        ErrorScope::Unrecoverable |
                        ErrorScope::Shutdown |
                        ErrorScope::External |
                        ErrorScope::System =>
                            Err(FlowStateGetFlowError::ToAuth {
                                err: err
                            }),
                        // Retry after a delay
                        scope => {
                            if !matches![scope, ErrorScope::Session] {
                                error!(target: "flows-nego-state",
                                       "shouldn't see error with scope {} here",
                                       scope);
                            }

                            info!(target: "flows-nego-state",
                                  "session with {} failed: {}",
                                  addr, err);

                            let delay = retry.retry_delay(self.nretries);

                            debug!(target: "flows-nego-state",
                                   "negotiation failed, delay for {}.{:03}s",
                                   delay.as_secs(), delay.subsec_millis());

                            self.state = None;
                            self.nretries += 1;
                            self.when = Instant::now() + delay;

                            Ok(RetryResult::Retry(self.when))
                        }
                    }
                }
            } else {
                // Session negotiations are pending; return
                // the backlog.
                let pending = SessionNegoState::session();

                self.state = Some(SessionState::Pending {
                    pending: pending
                });

                Ok(RetryResult::Success(None))
            }
        } else {
            // Still delayed.
            Ok(RetryResult::Retry(self.when))
        }
    }

    fn get_flow<Sock, InboundNego, OutboundNego, Xfrm>(
        &mut self,
        flows: &mut Flows<F, Sock, InboundNego, OutboundNego, Xfrm>,
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
                           OutboundNego::NegotiateError>
        >
    >
    where
          Sock: Socket + Sender + Receiver + Source,
          OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
          InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
          Xfrm: DatagramXfrm,
          Xfrm::LocalAddr: From<Sock::Addr>,
          Sock::Addr: TryFrom<Xfrm::LocalAddr>,
          <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
          Xfrm::PeerAddr: Clone + Display + Eq + Hash
    {
        if self.state.is_some() {
            match &mut self.state {
                // There's already an active session.
                Some(SessionState::Active) =>
                    Err(FlowStateGetFlowError::Active),
                // Negotiations are pending, there is no session.
                Some(SessionState::Pending { .. } |
                     SessionState::Shutdown { .. }) =>
                    Ok(RetryResult::Success(None)),
                // Impossible case.
                None => Err(FlowStateGetFlowError::Impossible)
            }
        } else {
            // No session exists; we need to start one.
            self.create_flow(flows, authn, retry, param, addr)
        }
    }

    /// Take an incoming negotiated session and transition this state
    /// into the authentication phase.
    fn recv_flow(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        flow: F,
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    > {
        let peer = flow.peer_addr();
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

                self.handle_to_auth_result(retry, &peer, res)
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

                self.handle_to_auth_result(retry, &peer, res)
            }
        }
    }

    /// Take an incoming negotiated session and transition this state
    /// into the authentication phase.
    fn step<Addr>(
        &mut self,
        authn: &AuthN,
        shutdown: &ShutdownNego,
        retry: &Retry,
        addr: Addr,
        ext_endpoints: &mut HashSet<Addr>
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoStepError<AuthN::NegotiateError,
                             ShutdownNego::NegotiateError>
    >
    where Addr: Display + Eq + Hash
    {
        let state = self.state.take();

        match state {
            // A pending negotiation exists; step it.
            Some(SessionState::Pending { pending }) => match pending
                .step_auth(authn) {
                // Negotiations completed immediately; set the state
                // to active and return.
                Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                    info!(target: "flows-nego-state",
                          "authenticated new session with {} over {}",
                          out.prin(), addr);

                    self.state = Some(SessionState::Active);
                    self.nretries = 0;

                    Ok(Some(out))
                },
                // Authentication failed.
                Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                    info!(target: "flows-nego-state",
                          "authentication failed for session with {}",
                          addr);

                    let delay = retry.retry_delay(self.nretries);

                    debug!(target: "flows-nego-state",
                           "authentication failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.state = None;
                    self.nretries += 1;
                    self.when = Instant::now() + delay;

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
                    ErrorScope::System => Err(SessionNegoStepError::Auth {
                        err: err
                    }),
                    // Retry after a delay
                    scope => {
                        if !matches![scope, ErrorScope::Session] {
                            error!(target: "flows-nego-state",
                                   "shouldn't see error with scope {} here",
                                   scope);
                        }

                        info!(target: "flows-nego-state",
                              "session with {} failed: {}",
                              addr, err);

                        let delay = retry.retry_delay(self.nretries);

                        debug!(target: "flows-nego-state",
                               "negotiation failed, delay for {}.{:03}s",
                               delay.as_secs(), delay.subsec_millis());

                        self.state = None;
                        self.nretries += 1;
                        self.when = Instant::now() + delay;

                        Ok(None)
                    }
                }
            }
            // There's already an active session, but this isn't an error.
            Some(SessionState::Active) => {
                ext_endpoints.insert(addr);

                Ok(None)
            }
            Some(SessionState::Shutdown { pending }) => match shutdown
                .complete_negotiate(pending)
                .map_err(|err| SessionNegoStepError::Shutdown { err: err })? {
                NegotiatorResult::Complete(()) => {
                    info!(target: "flows-nego-state",
                           "successfully shutdown session with {}",
                          addr);

                    Ok(None)
                }
                NegotiatorResult::Pending(pending) => {
                    debug!(target: "flows-nego-state",
                           "continuing session shutdown negotiation with {}",
                           addr);

                    self.state = Some(SessionState::Shutdown {
                        pending: pending
                    });

                    Ok(None)
                }
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
    #[inline]
    fn new() -> Self {
        FlowsRetry {
            nfailures: 0,
            retry_when: Instant::now()
        }
    }
}

impl<F, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm>
    FlowsEntry<F, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), F>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<F, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError
{
    #[inline]
    fn new(
        flows: Flows<F, Sock, InboundNego, OutboundNego, Xfrm>,
        nsessions: Option<usize>
    ) -> Self {
        let sessions = match nsessions {
            Some(nsessions) => HashMap::with_capacity(nsessions),
            None => HashMap::new()
        };

        FlowsEntry {
            retry: FlowsRetry::new(),
            sessions: sessions,
            flows: flows,
        }
    }

    fn req_flow(
        &mut self,
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
            >
        >
    > {
        let now = Instant::now();

        match self.sessions.entry(endpoint.clone()) {
            Entry::Occupied(mut ent) => {
                let ent = ent.get_mut();

                if ent.when <= now {
                    let out = ent.get_flow(&mut self.flows, authn, retry,
                                           out_param, endpoint)?;

                    Ok(out)
                } else {
                    Ok(RetryResult::Retry(ent.when))
                }
            },
            Entry::Vacant(ent) => {
                let ent = ent.insert(FlowNegoState {
                    state: None,
                    nretries: 0,
                    when: now
                });

                let out = ent.get_flow(&mut self.flows, authn, retry,
                                       out_param, endpoint)?;

                Ok(out)
            }
        }
    }

    fn listen(
        &mut self,
        authn: &AuthN,
        shutdown: &ShutdownNego,
        retry: &Retry,
        param: &InboundNego::Param,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>
    ) -> Result<
        (),
        SessionListenError<
            FlowsListenError<Xfrm::Error, InboundNego::StartError,
                             InboundNego::NegotiateError,
                             OutboundNego::NegotiateError>,
            AuthN::StartError,
            AuthN::NegotiateError,
            ShutdownNego::NegotiateError
        >
    > {
        let mut endpoints = HashSet::new();
        let mut flows = Vec::new();

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

                match self.sessions.entry(endpoint) {
                    Entry::Occupied(mut ent) => {
                        trace!(target: "flows-nego-state",
                               "entry for flow {} already exists",
                               ent.key());

                        if let Some(session) = ent
                            .get_mut()
                            .recv_flow(authn, retry, flow)
                            .map_err(|err| SessionListenError::Start {
                                err: err
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
                            FlowNegoState::create(authn, retry, flow)
                            .map_err(|err| SessionListenError::Start {
                                err: err
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

            // Process all negotiation steps
            for endpoint in endpoints.drain() {
                trace!(target: "flows-nego-state",
                       "traffic on flow {}",
                       endpoint);

                // Look up the session.
                if let Some(ent) = self.sessions.get_mut(&endpoint) {
                    // Step negotiations.
                    if let Some(session) = ent
                        .step(authn, shutdown, retry, endpoint, ext_endpoints)
                        .map_err(|err| SessionListenError::Step {
                            err: err
                        })? {
                        debug!(target: "flows-nego-state",
                               "reporting completed session");

                        // Session negotiations complete; report it out.
                        sessions.push(session)
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
}

impl<F, Sock, InboundNego, OutboundNego, ShutdownNego, AuthN, Xfrm> Source
    for FlowsEntry<F, Sock, InboundNego, OutboundNego,
                   ShutdownNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    ShutdownNego: NegotiatorStart<(), F>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    ShutdownNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<F, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
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
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    InnerXfrm::CreateParam: Clone,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {

    /// Create a new entry where one does not already exist.
    fn create<NameCtx, I>(
        tokgen: &mut I,
        caches: &mut NameCtx,
        channel: &mut Channel,
        flows_config: &FlowsConfig,
        resolve_config: &AddrsConfig,
        policy: &SocketAddrPolicy,
        xfrm_param: &InnerXfrm::CreateParam,
        acquired: Channel::Acquired,
        retry: Retry,
        nflows_hint: Option<usize>,
    ) -> Result<
        RetryResult<(Self, Option<Instant>)>,
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
        NameCtx: NSNameCachesCtx {
        let mut resolver = acquired
            .resolver(caches, policy, resolve_config.resolver())
            .map_err(|err| AcquiredEntryCreateError::Resolve { err: err })?;

        // Decide what kinds of addresses to keep.
        let mut keep_ipv4 = false;
        let mut keep_ipv6 = false;

        for kind in resolve_config.addr_policy().iter() {
            match kind {
                AddrKind::IPv6 => {
                    trace!(target: "far-channel-registry",
                           "retaining IPv6 addresses");

                    keep_ipv6 = true;
                }
                AddrKind::IPv4 => {
                    trace!(target: "far-channel-registry",
                           "retaining IPv4 addresses");

                    keep_ipv4 = true;
                }
            }
        }

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
                        if (addr.is_ipv6() && keep_ipv6) ||
                            (addr.is_ipv4() || keep_ipv4)
                        {
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
                            let ent = FlowsEntry::new(session, nflows_hint);
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
                    let ent = FlowsEntry::new(session, nflows_hint);
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
                let ent = FlowsEntry::new(session, nflows_hint);
                    let token = tokgen.next()
                        .ok_or(AcquiredEntryCreateError::NoTokens)?;

                tokens.insert(param.clone(), token.clone());
                flows.insert(token, ent);

                Ok(RetryResult::Success((tokens, flows, None)))
            }
        }?;

        Ok(res.map(|(tokens, flows, time)| {
            (
                AcquiredEntry {
                    xfrm: PhantomData,
                    auth: PhantomData,
                    flows_config: flows_config.clone(),
                    xfrm_param: xfrm_param.clone(),
                    nflows_hint: nflows_hint,
                    acquired: acquired,
                    resolver: resolver,
                    tokens: tokens,
                    flows: flows,
                    retry: retry
                },
                time
            )
        }))
    }

    /// Check to see if a refresh is needed.
    fn needs_refresh(&self) -> bool {
        if let AcquiredResolver::Resolve { resolver } = &self.resolver {
            resolver.needs_refresh()
        } else {
            false
        }
    }

    fn next_refresh(&self) -> Option<Instant> {
        if let AcquiredResolver::Resolve { resolver } = &self.resolver {
            resolver.refresh_when()
        } else {
            None
        }
    }

    fn update_refreshed<I, T>(
        &mut self,
        registry: &mut Registry,
        tokens: &mut T,
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

                // Only create a new flows if there
                // isn't one already in existence.
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
                        let ent = FlowsEntry::new(flows, self.nflows_hint);

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

    /// Refresh the addresses and update all [Flows], if needed.
    ///
    /// The [RefreshResult] reports all new addresses, if a refresh
    /// happens.
    fn refresh<I>(
        &mut self,
        registry: &mut Registry,
        tokens: &mut I,
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

                        let out = self.update_refreshed(registry,tokens,
                                                        channel, policy,
                                                        resolved.into_iter())?;

                        Ok((Some(out), next_refresh))
                    })
            }
            // Only a resolver can refresh.  Everything else is trivial.
            _ => Ok(RetryResult::Success((None, self.next_refresh())))
        }
    }

    /// Listen and respond on all [Flows] with available I/O.
    ///
    /// This will listen and respond on all flows whose tokens are in
    /// `tokens`, until I/O yields
    /// [WouldBlock](ErrorScope::WouldBlock).
    ///
    /// # Parameters
    ///
    /// - `authn`: Session authenticator to use.
    /// - `retry`: [Retry] configuration to use.
    /// - `param`: Parameter to use for starting inbound negotiations.
    /// - `tokens`: Tokens with available I/O.
    /// - `ext_endpoints`: [HashSet] into which to insert all
    ///   [PeerAddr](DatagramXfrm::PeerAddr)s for flows that had new
    ///   messages delivered.
    /// - `sessions`: [Vec] into which to place any new sessions.
    fn listen<I>(
        &mut self,
        registry: &mut Registry,
        tokgen: &mut I,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        authn: &AuthN,
        shutdown: &Channel::ShutdownNego,
        retry: &Retry,
        param: &<Channel::InboundNego as NegotiatorStart<Channel::Flow, BufferedFlow<Channel::Socket, Xfrm>>>::Param,
        tokens: &HashSet<Token>,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>,
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
            <Channel::ShutdownNego as Negotiator<()>>::NegotiateError
        >
    >
    where I: Iterator<Item = Token>
    {
        self.refresh(registry, tokgen, channel, policy)
            .map_err(|err| AcquiredEntryListenError::Refresh { err: err })?
            .map_ok(move |(addrs, refresh_when)| {
                for (_, ent) in self.flows
                    .iter_mut()
                    .filter(|(token, _)| tokens.contains(token)) {
                        ent.listen(authn, shutdown, retry, param,
                                   ext_endpoints, sessions)
                        .map_err(|err| AcquiredEntryListenError::Listen {
                            err: err
                        })?
                }

                Ok((addrs, refresh_when))
            })
    }

    fn flows<I>(
        &mut self,
        registry: &mut Registry,
        tokens: &mut I,
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
        self.refresh(registry, tokens, channel, policy)
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

    fn req_flow<I>(
        &mut self,
        registry: &mut Registry,
        tokens: &mut I,
        channel: &Channel,
        authn: &AuthN,
        policy: &SocketAddrPolicy,
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
                >
            >
        >
    >
    where I: Iterator<Item = Token>
    {
        let retry = self.retry.clone();

        self.flows(registry, tokens, channel, policy, channel_param)
            .map_err(|err| AcquiredEntryFlowError::Flows { err: err })?
            .flat_map_ok(|(ent, addrs, refresh_when)| {
                Ok(ent.req_flow(authn, &retry, nego_param, endpoint)
                   .map_err(|err| AcquiredEntryFlowError::Flow { err: err })?
                   .map(|session| (session, addrs, refresh_when)))
            })
    }

    /// Obtain a snapshot of the current address set.
    ///
    /// The result will also indicate whether a refresh occurred.
    fn addrs<I>(
        &mut self,
        registry: &mut Registry,
        tokens: &mut I,
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
               registry,
               tokens,
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

}
/*
impl<Pending, Acquired> AcquireState<Pending, Acquired> {
    fn create<F, Channel, AuthN, Xfrm, InnerXfrm>(
        channel: &mut Channel,
        registry: &Registry,
        config: &FlowsConfig,
        channel_param: &Channel::Param,
        xfrm_param: &InnerXfrm::CreateParam,
        addr: &InnerXfrm::Addr,
        nsessions: Option<usize>
    ) -> Result<
        RetryResult<Self>,
        AcquireStateCreateError<
            Channel::AcquireError,
            Channel::NegotiateError,
            FarChannelFlowsError<
                Channel::SocketError,
                Channel::XfrmError,
                Channel::InboundNegoError,
                Channel::OutboundNegoError
            >
        >
    >
    where
        F: Flow,
        Channel: FarChannelFlows<Xfrm, InnerXfrm>
        + FarChannel<
            Acquired = FlowsEntry<F, Channel::Socket,
                                  Channel::InboundNego,
                                  Channel::OutboundNego,
                                  AuthN, Xfrm>,
            NegotiatePending = Pending,
        >
        + FarChannelCreate,
        <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
        <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
            Display,
        AuthN: SessionAuthN<F, Param = ()>,
        AuthN::NegotiateError: ScopedError,
        AuthN::StartError: ScopedError,
        Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
        Xfrm::CreateParam: Clone + Default,
        Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
        Xfrm::Error: ScopedError,
        InnerXfrm: DatagramXfrmCreate,
        Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
        Channel::Param: Clone + Display + Eq + Hash + PartialEq {
        channel
            .acquire(registry)
            .map_err(|err| AcquireStateCreateError::Acquire { err: err })?
            .map_ok(|state| match channel.negotiate(state)
                    .map_err(|err| AcquireStateCreateError::Nego {
                        err: err
                    })? {
                NegotiatorResult::Pending(pending) =>
                    Ok(AcquireState::Pending {
                        pending: pending
                    }),
                NegotiatorResult::Complete(acquired) => {
                    let xfrm = InnerXfrm::create(xfrm_param, addr);
                    let flows = channel.flows(
                        config.clone(),
                        channel_param.clone(),
                        xfrm
                    ).map_err(|err| AcquireStateCreateError::Flows {
                        err: err
                    })?;

                    Ok(AcquireState::Acquired {
                        acquired: acquired
                    })
                }
            })
    }

    fn step<Channel, Xfrm, InnerXfrm>(
        self,
        channel: &mut Channel,
        nsessions: Option<usize>
    ) -> Result<
        Self,
        AcquireStateCreateError<
            Channel::AcquireError,
            Channel::NegotiateError
        >
    >
    where
        Channel: FarChannelFlows<Xfrm, InnerXfrm>
        + FarChannel<
            Acquired = Flows<Channel::Flow, Channel::Socket,
                             Channel::InboundNego,
                             Channel::OutboundNego,
                             Xfrm>,
            NegotiatePending = Pending,
        >
        + FarChannelCreate,
        <Channel::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
        <<Channel::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
            Display,
        Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
        Xfrm::CreateParam: Clone + Default,
        Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
        Xfrm::Error: ScopedError,
        InnerXfrm: DatagramXfrmCreate,
        Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
        Channel::Param: Clone + Display + Eq + Hash + PartialEq {
        if let AcquireState::Pending { pending } = self {
            match channel.complete_negotiate(pending)
                .map_err(|err| AcquireStateCreateError::Nego {
                    err: err
                })? {
                NegotiatorResult::Pending(pending) =>
                    Ok(AcquireState::Pending {
                        pending: pending
                    }),
                NegotiatorResult::Complete(acquired) =>
                    Ok(AcquireState::Acquired {
                        acquired: acquired
                    })
            }
        } else {
            Err()
        }
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

    fn acquire_nonblock<NameCtx>(
        &mut self,
        caches: &mut NameCtx,
        policy: &SocketAddrPolicy,
        resolve_config: &AddrsConfig,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<Option<Instant>>,
        RegistryAcquireError<
            Channel::AcquireError,
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        trace!(target: "far-channel-registry",
               "checking whether to attempt to initialize");

        let policy = self.policy.unwrap_or(policy.clone());

        match &self.acquired {
            // We still need to initialize
            RetryResult::Retry(when) => {
                if *when <= Instant::now() {
                    debug!(target: "far-channel-registry",
                           "attempt to initialize registry entry");

                    match RegistryAcquired::create_nonblock(
                        caches,
                        &mut self.channel,
                        policy,
                        resolve_config,
                        authn,
                        reporter,
                        flows_param,
                        xfrm_param
                    )? {
                        RetryResult::Retry(when) => {
                            self.acquired = RetryResult::Retry(when);

                            Ok(RetryResult::Retry(when))
                        }
                        RetryResult::Success((acquired, time)) => {
                            self.acquired = RetryResult::Success(acquired);

                            Ok(RetryResult::Success(time))
                        }
                    }
                } else {
                    Ok(RetryResult::Retry(*when))
                }
            }
            RetryResult::Success(acquired) => {
                Ok(RetryResult::Success(acquired.next_refresh()))
            }
        }
    }

}

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
        registry: &mut Registry,
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

impl<AuthN, Start, Flow> ScopedError
    for FlowStateGetFlowError<AuthN, Start, Flow>
where AuthN: ScopedError,
      Flow: ScopedError,
      Start: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            FlowStateGetFlowError::ToAuth { err } => err.scope(),
            FlowStateGetFlowError::Flow { err } => err.scope(),
            FlowStateGetFlowError::Impossible |
            FlowStateGetFlowError::Active => ErrorScope::Unrecoverable
        }
    }
}

impl<Acquire, Nego, Flows> ScopedError
    for AcquireStateCreateError<Acquire, Nego, Flows>
where Acquire: ScopedError,
      Nego: ScopedError,
      Flows: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            AcquireStateCreateError::Acquire { err } => err.scope(),
            AcquireStateCreateError::Nego { err } => err.scope(),
            AcquireStateCreateError::Flows { err } => err.scope(),
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

impl<AuthN, Start, Flow> Display for FlowStateGetFlowError<AuthN, Start, Flow>
where
    Start: Display,
    Flow: Display,
    AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
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

impl<Acquire, Nego, Flows> Display
    for AcquireStateCreateError<Acquire, Nego, Flows>
where Acquire: Display,
      Nego: Display,
      Flows: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquireStateCreateError::Acquire { err } => err.fmt(f),
            AcquireStateCreateError::Nego { err } => err.fmt(f),
            AcquireStateCreateError::Flows { err } => err.fmt(f),
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
