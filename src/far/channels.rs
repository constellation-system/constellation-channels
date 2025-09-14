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
use crate::channels::Backlog;
use crate::channels::SessionResult;
use crate::config::FlowsConfig;
use crate::far::AcquiredResolver;
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

/// Negotiation state for session and authentication negotiations.
///
/// This is used to store current negotiation states, and advance
/// them.  This differs slightly from the near channel version,
/// because session negotiations happen internally in [Flows].
enum SessionNegoState<Session, AuthPending> {
    /// Session negotiation is pending.
    Session {
        /// Message backlog.
        backlog: Backlog,
     },
    /// Session authentication is pending.
    AuthN {
        /// Message backlog.
        backlog: Backlog,
        /// State of pending authentication.
        pending: AuthPending
    },
    /// Session has been negotiated and is clearing its backlog.
    Backlog {
        /// Message backlog.
        backlog: Backlog,
        /// Completed session.
        session: Session
    }
}

/// Current state of sessions.
///
/// This is used to store whether a session is in negotiations, or is
/// active and has already been returned.
enum SessionState<F, AuthN>
where F: Flow,
      AuthN: SessionAuthN<F>
{
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        pending: SessionNegoState<AuthN::AuthNSession, AuthN::Pending>
    },
    /// A session has already been established.
    Active
}

/// Retry information for a given possible [Flows] instance.
struct FlowsRetry {
    nfailures: usize,
    retry_when: Instant
}

struct FlowNegoState<F, AuthN>
where F: Flow,
      AuthN: SessionAuthN<F>
{
    state: Option<SessionState<F, AuthN>>,
     /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Instant
}

struct FlowsEntry<F, Sock, InboundNego, OutboundNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
    AuthN: SessionAuthN<F>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError
{
    sessions: HashMap<Xfrm::PeerAddr, FlowNegoState<F, AuthN>>,
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
    InnerXfrm: DatagramXfrmCreate,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq,
    <Channel::InboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError,
    <Channel::OutboundNego as Negotiator<Channel::Flow>>::NegotiateError: ScopedError
{
    authn: PhantomData<AuthN>,
    xfrm: PhantomData<Xfrm>,
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
                   Channel::OutboundNego, AuthN, Xfrm>
    >,
    flows_config: FlowsConfig,
    flows_param: Channel::Param,
    xfrm_param: InnerXfrm::CreateParam,
    /// Size hint for session tables.
    nsessions_hint: Option<usize>
}

struct ChannelEntry<Channel, AuthN, Xfrm, InnerXfrm>
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
    /// Base [FarChannel](crate::far::FarChannel) object.
    channel: Channel,
    /// Acquired value and flows, if a value has been acquired.
    ///
    /// This is used to store when to retry, if
    /// [Retry](RetryResult::Retry) is present.
    acquired: RetryResult<AcquiredEntry<Channel, AuthN, Xfrm, InnerXfrm>>,
    /// Retry configuration.
    retry: Retry
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
pub enum SessionNegoStepError<AuthN> {
    /// Error occurred stepping session negotiations
    Auth {
        /// The error that occurred stepping session negotiations.
        err: AuthNegoStepError<AuthN>
    }
}

#[derive(Debug)]
pub enum SessionListenError<Flows, Start, AuthN> {
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
        err: SessionNegoStepError<AuthN>
    }
}

impl<Session, AuthPending> SessionNegoState<Session, AuthPending> {
    /// Create a state denoting session negotiations.
    #[inline]
    fn session(backlog_size: Option<usize>) -> Self {
        let backlog = match backlog_size {
            Some(size) => Backlog::with_capacity(size),
            None => Backlog::new()
        };

        SessionNegoState::Session {
            backlog: backlog
        }
    }

    /// Create a state denoting authentication negotiations.
    fn auth<F, AuthN>(
        authn: &AuthN,
        backlog_size: Option<usize>,
        flow: F,
    ) -> Result<
        NegotiatorResult<AuthNResult<Session, ()>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        F: Flow,
        Session: AuthNed<AuthN::Prin, F>,
        AuthN: SessionAuthN<F, AuthNSession = Session>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, ()>, F, Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, ()>,
                     Pending = AuthPending>,
    {
        let backlog = match backlog_size {
            Some(size) => Backlog::with_capacity(size),
            None => Backlog::new()
        };
        // Start authentication negotiations.
        let state = authn
            .start(&(), flow)
            .map_err(|err| SessionNegoToAuthError::Start {
                err: err
            })?;

        match authn
            .negotiate(state)
            .map_err(|err| SessionNegoToAuthError::AuthN { err: err })? {
            // Authentication negotiations complete, succeeded.
            //
            // Clear the backlog
            NegotiatorResult::Complete(AuthNResult::Accept(session)) => Ok(
                Self::clear_backlog(session, backlog)
                    .map_err(|err| SessionNegoToAuthError::IO {
                        err: err
                    })?
                    .map(|session| AuthNResult::Accept(session))
            ),
            // Authentication result other than success.
            NegotiatorResult::Complete(res) =>
                Ok(NegotiatorResult::Complete(res)),
            // Authentication negotiations continue.
            NegotiatorResult::Pending(pending) => {
                trace!(target: "session-auth-nego",
                       "session negotiations continuing later");

                Ok(NegotiatorResult::Pending(SessionNegoState::AuthN {
                    backlog: backlog,
                    pending: pending
                }))
            }
        }
    }

    /// Get the backlog for this state, if we can.
    #[inline]
    fn backlog(
        &mut self
    ) -> &'_ mut Backlog {
        match self {
            SessionNegoState::Session { backlog } => backlog,
            SessionNegoState::AuthN { backlog, .. } => backlog,
            SessionNegoState::Backlog { backlog, .. } => backlog,
        }
    }

    /// Flush as much of the backlog as we can manage.
    fn clear_backlog<Prin, F>(
        mut session: Session,
        mut backlog: Backlog
    ) -> Result<NegotiatorResult<Session, Self>, Error>
    where
        F: Flow,
        Prin: Display,
        Session: AuthNed<Prin, F>,
    {
        debug!(target: "session-auth-nego",
               "session with {} authenticated, clearing backlog",
               session.prin());

        loop {
            if let Some(msg) = backlog.peek() {
                if let Err(err) = session.get_mut().write_all(msg) {
                    match err.kind() {
                        // Need to resume later.
                        ErrorKind::WouldBlock => {
                            trace!(target: "session-auth-nego",
                                   "backlog clearance continuing");

                            return Ok(NegotiatorResult::Pending(
                                SessionNegoState::Backlog {
                                    backlog: backlog,
                                    session: session
                                }
                            ))
                        }
                        // Interrupted should immediately try again.
                        ErrorKind::Interrupted => {
                            trace!(target: "session-auth-nego",
                                   "retrying interrupted send")
                        }
                        _ => return Err(err)
                    }
                } else {
                    if let Some(msg) = backlog.pop() {
                        trace!(target: "session-auth-nego",
                               "sent {}-byte backlogged message to {}",
                               msg.len(), session.prin());
                    } else {
                        // This should never happen.
                        error!(target: "session-auth-nego",
                               "inconsistent backlog state");
                    }
                }
            } else {
                // Backlog is cleared.
                return Ok(NegotiatorResult::Complete(session))
            }
        }
    }

    /// Go into the authentication phase.
    fn to_auth<F, AuthN>(
        self,
        authn: &AuthN,
        flow: F
    ) -> Result<
        NegotiatorResult<AuthNResult<Session, ()>, Self>,
        SessionNegoToAuthError<
            AuthN::NegotiateError,
            AuthN::StartError,
        >
    >
    where
        F: Flow,
        Session: AuthNed<AuthN::Prin, F>,
        AuthN: SessionAuthN<F, AuthNSession = Session>
        + NegotiatorStart<AuthNResult<AuthN::AuthNSession, ()>, F, Param = ()>
        + Negotiator<AuthNResult<AuthN::AuthNSession, ()>,
                     Pending = AuthPending>,
    {
        if let SessionNegoState::Session { backlog } = self {
            // Start authentication negotiations.
            let state = authn
                .start(&(), flow)
                .map_err(|err| SessionNegoToAuthError::Start {
                    err: err
                })?;

            match authn
                .negotiate(state)
                .map_err(|err| SessionNegoToAuthError::AuthN { err: err })? {
                // Authentication negotiations complete, succeeded.
                //
                // Clear the backlog
                NegotiatorResult::Complete(AuthNResult::Accept(session)) => Ok(
                    Self::clear_backlog(session, backlog)
                        .map_err(|err| SessionNegoToAuthError::IO {
                            err: err
                        })?
                        .map(|session| AuthNResult::Accept(session))
                ),
                // Authentication result other than success.
                NegotiatorResult::Complete(res) =>
                    Ok(NegotiatorResult::Complete(res)),
                // Authentication negotiations continue.
                NegotiatorResult::Pending(pending) => {
                    trace!(target: "session-auth-nego",
                           "session negotiations continuing later");

                    Ok(NegotiatorResult::Pending(SessionNegoState::AuthN {
                        backlog: backlog,
                        pending: pending
                    }))
                }
            }
        } else {
            Err(SessionNegoToAuthError::NotSession)
        }
    }

    /// Step negotitions forward in the authentication phase.
    fn step_auth<F, AuthN>(
        self,
        authn: &AuthN
    ) -> Result<
        NegotiatorResult<AuthNResult<Session, ()>, Self>,
        AuthNegoStepError<AuthN::NegotiateError>
    >
    where
        F: Flow,
        Session: AuthNed<AuthN::Prin, F>,
        AuthN: SessionAuthN<F, AuthNSession = Session,
                            Pending = AuthPending,
                            Param = ()> {
        match self {
            // Resuming session negotiations.
            SessionNegoState::Session { .. } => Err(AuthNegoStepError::Session),
            // Resuming authentication negotiations.
            SessionNegoState::AuthN { pending, backlog } => match authn
                .complete_negotiate(pending)
                .map_err(|err| AuthNegoStepError::AuthN { err: err })? {
                // Authentication negotiations complete, succeeded.
                //
                // Clear the backlog
                NegotiatorResult::Complete(AuthNResult::Accept(session)) => Ok(
                    Self::clear_backlog(session, backlog)
                        .map_err(|err| AuthNegoStepError::IO {
                            err: err
                        })?
                        .map(|session| AuthNResult::Accept(session))
                ),
                // Authentication result other than success.
                NegotiatorResult::Complete(res) =>
                    Ok(NegotiatorResult::Complete(res)),
                // Authentication negotiations continue.
                NegotiatorResult::Pending(pending) => {
                    trace!(target: "session-auth-nego",
                           "session negotiations continuing later");

                    Ok(NegotiatorResult::Pending(SessionNegoState::AuthN {
                        backlog: backlog,
                        pending: pending
                    }))
                }
            }
            SessionNegoState::Backlog { session, backlog } =>
                Ok(Self::clear_backlog(session, backlog)
                   .map_err(|err| AuthNegoStepError::IO {
                       err: err
                   })?
                   .map(|session| AuthNResult::Accept(session)))
        }
    }
}

impl<F, AuthN> FlowNegoState<F, AuthN>
where
    F: Flow,
    AuthN: SessionAuthN<F, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
{
    /// Take an incoming negotiated session and create a state in the
    /// authentication phase.
    fn from_flow(
        authn: &AuthN,
        retry: &Retry,
        backlog_size: Option<usize>,
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
        match SessionNegoState::auth(authn, backlog_size, flow) {
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

    /// Get the backlog for this state, if applicable.
    #[inline]
    fn backlog(
        &mut self
    ) -> Result<&'_ mut Backlog, SessionStateBacklogError> {
        if let Some(SessionState::Pending { pending }) = &mut self.state {
            Ok(pending.backlog())
        } else {
            Err(SessionStateBacklogError::Active)
        }
    }

    fn handle_to_auth_result(
        &mut self,
        retry: &Retry,
        peer: &F::PeerAddr,
        res: Result<
            NegotiatorResult<AuthNResult<AuthN::AuthNSession, ()>,
                             SessionNegoState<AuthN::AuthNSession,
                                              AuthN::Pending>>,
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
        backlog_size: Option<usize>,
        param: &OutboundNego::Param,
        addr: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<SessionResult<'_, AuthN::AuthNSession>>,
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

                match SessionNegoState::auth(authn, backlog_size, flow) {
                    // Negotiations completed immediately; set the state
                    // to active and return.
                    Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                        info!(target: "flows-nego-state",
                              "authenticated new session with {} over {}",
                              out.prin(), addr);

                        self.state = Some(SessionState::Active);
                        self.nretries = 0;

                        Ok(RetryResult::Success(SessionResult::Session(out)))
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

                        if let Some(SessionState::Pending { pending }) =
                            &mut self.state {
                            let backlog = pending.backlog();

                            Ok(RetryResult::Success(
                                SessionResult::Pending(backlog)
                            ))
                        } else {
                            Err(FlowStateGetFlowError::Impossible)
                        }
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
                let pending = SessionNegoState::session(backlog_size);

                self.state = Some(SessionState::Pending {
                    pending: pending
                });

                if let Some(SessionState::Pending { pending }) =
                    &mut self.state {
                    let backlog = pending.backlog();

                    Ok(RetryResult::Success(
                        SessionResult::Pending(backlog)
                    ))
                } else {
                    Err(FlowStateGetFlowError::Impossible)
                }
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
        backlog_size: Option<usize>,
        param: &OutboundNego::Param,
        addr: &Xfrm::PeerAddr,
    ) -> Result<
        RetryResult<SessionResult<'_, AuthN::AuthNSession>>,
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
                // Pending negotiation; return a reference to the backlog.
                Some(SessionState::Pending { pending }) => {
                    let backlog = pending.backlog();

                    Ok(RetryResult::Success(SessionResult::Pending(backlog)))
                }
                // There's already an active session.
                Some(SessionState::Active) =>
                    Err(FlowStateGetFlowError::Active),
                // Impossible case.
                None => Err(FlowStateGetFlowError::Impossible)
            }
        } else {
            // No session exists; we need to start one.
            self.create_flow(flows, authn, retry, backlog_size, param, addr)
        }
    }

    /// Take an incoming negotiated session and transition this state
    /// into the authentication phase.
    fn recv_flow(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        backlog_size: Option<usize>,
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

            // XXX Possibly rate-limit incoming connections to
            // avoid DoS?
            None => {
                let res = SessionNegoState::auth(authn, backlog_size, flow);

                self.handle_to_auth_result(retry, &peer, res)
            }
        }
    }

    /// Take an incoming negotiated session and transition this state
    /// into the authentication phase.
    fn step_auth<Addr>(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        addr: Addr,
        ext_endpoints: &mut HashSet<Addr>
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoStepError<AuthN::NegotiateError>
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
            // No existing state at all; ignore this.
            None => {
                debug!(target: "flows-nego-state",
                      "attempting to inactive session with {}",
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

impl<F, Sock, InboundNego, OutboundNego, AuthN, Xfrm>
    FlowsEntry<F, Sock, InboundNego, OutboundNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
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
        backlog_size: Option<usize>,
        in_param: &InboundNego::Param,
        out_param: &OutboundNego::Param,
        endpoint: &Xfrm::PeerAddr,
        ext_endpoints: &mut HashSet<Xfrm::PeerAddr>,
        sessions: &mut Vec<AuthN::AuthNSession>
    ) -> Result<
        RetryResult<SessionResult<'_, AuthN::AuthNSession>>,
        FlowStateGetFlowError<
            AuthN::NegotiateError,
            AuthN::StartError,
            FlowsFlowError<OutboundNego::StartError,
                           OutboundNego::NegotiateError>
        >
    > {
        let now = Instant::now();
        let ent = match self.sessions.entry(endpoint.clone()) {
            Entry::Occupied(ent) => ent.get_mut(),
            Entry::Vacant(mut ent) => ent.insert(FlowNegoState {
                state: None,
                nretries: 0,
                when: now
            })
        };

        if ent.when <= now {
            let out = ent.get_flow(&mut self.flows, authn, retry,
                                   backlog_size, out_param, endpoint)?;

            // Listen, to handle any generated traffic.
            self.listen(authn, retry, backlog_size, in_param,
                        ext_endpoints, sessions)?;

            Ok(out)
        } else {
            Ok(RetryResult::Retry(ent.when))
        }
    }

    fn listen(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        backlog_size: Option<usize>,
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
            AuthN::NegotiateError
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
                            .recv_flow(authn, retry, backlog_size, flow)
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
                            FlowNegoState::from_flow(authn, retry,
                                                     backlog_size, flow)
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
                        .step_auth(authn, retry, endpoint, ext_endpoints)
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

impl<F, Sock, InboundNego, OutboundNego, AuthN, Xfrm> Source
    for FlowsEntry<F, Sock, InboundNego, OutboundNego, AuthN, Xfrm>
where
    F: Flow,
    Sock: Receiver + Sender + Source,
    Sock::Addr: TryFrom<Xfrm::LocalAddr>,
    <Sock::Addr as TryFrom<Xfrm::LocalAddr>>::Error: Display,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego::NegotiateError: ScopedError,
    OutboundNego::NegotiateError: ScopedError,
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
    AuthN: Clone + SessionAuthN<Channel::Flow, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    AuthN::StartError: ScopedError,
    Xfrm: DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Xfrm::Error: ScopedError,
    InnerXfrm: DatagramXfrmCreate,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
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
        let mut filtered = HashMap::with_capacity(self.flows.len());
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
                let flows = match self.tokens.remove(&addr) {
                    Some(token) => {
                        trace!(target: "far-channel-registry",
                               "retaining flows for {}",
                               addr);

                        retained.insert(token);
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
                                   self.flows_param.clone(),
                                   xfrm)
                            .map_err(|err| {
                                FarChannelsRefreshError::Flows {
                                    err: err
                                }
                            })?;

                        FlowsEntry::new(flows, self.nsessions_hint)
                    }
                };

                filtered.insert(addr, flows);
            } else {
                debug!(target: "far-channel-registry",
                       "discarding address {} of unknown type",
                       addr);
            }
        }

        if filtered.is_empty() {
            Err(FarChannelsRefreshError::NoValidAddrs)
        } else {
            let out = filtered.keys().cloned().collect();

            // Replace the flows.
            filtered.shrink_to_fit();
            self.tokens = filtered;

            // Filter out the flows that weren't retained.
            let deletes: Vec<Token> = self.flows.keys().cloned()
                .filter(|tok| !retained.contains(tok))
                .collect();

            for tok in deletes {
                if let Some(flows) = self.flows.remove(&tok) {
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

impl<AuthN> ScopedError for SessionNegoStepError<AuthN>
where AuthN: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            SessionNegoStepError::Auth { err } => err.scope(),
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

impl<AuthN> Display for SessionNegoStepError<AuthN>
where AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoStepError::Auth { err } => err.fmt(f),
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
