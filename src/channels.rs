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

use std::collections::VecDeque;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;

use log::debug;
use log::error;
use log::trace;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::AuthNResult;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;

pub struct Backlog(VecDeque<Vec<u8>>);

pub enum SessionResult<'a, Session> {
    /// Completed session.
    Session(Session),
    /// Access to the backlog for a session still pending negotiations.
    Pending(&'a mut Backlog),
}

pub(crate) enum SessionNegoState<Session, SessionPending, AuthPending> {
    /// Session negotiation is pending.
    Session {
        /// Message backlog.
        backlog: Backlog,
        /// State of pending session negotiation.
        pending: SessionPending
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

#[derive(Debug)]
pub(crate) enum SessionNegoStepError<Session, Start, AuthN> {
    /// An error occurred during session negotiation.
    Session {
        /// The error that occurred during session negotiation.
        err: Session
    },
    /// An error occurred starting authentication negotiation.
    Start {
        /// The error that occurred starting authentication negotiations.
        err: Start
    },
    /// An error occurred during authentication negotiations.
    AuthN {
        /// The error that occurred during authentication negotiations.
        err: AuthN
    },
    /// An error occurred clearing the backlog.
    IO {
        /// The error that occurred clearing the backlog.
        err: Error
    }
}

impl Backlog {
    #[inline]
    pub fn new() -> Backlog {
        Backlog(VecDeque::new())
    }

    #[inline]
    pub fn with_capacity(size: usize) -> Backlog {
        Backlog(VecDeque::with_capacity(size))
    }
}

impl<AuthNSession, SessionPending, AuthPending>
    SessionNegoState<AuthNSession, SessionPending, AuthPending> {
    /// Get the backlog for this negotiation state.
    pub fn backlog(&mut self) -> &mut Backlog {
        match self {
            SessionNegoState::Session { backlog, .. } => backlog,
            SessionNegoState::AuthN { backlog, .. } => backlog,
            SessionNegoState::Backlog { backlog, .. } => backlog,
        }
    }

    fn clear_backlog<Session, Prin>(
        mut session: AuthNSession,
        mut backlog: VecDeque<Vec<u8>>
    ) -> Result<NegotiatorResult<AuthNSession, Self>, Error>
    where
        Prin: Display,
        Session: Read + Write,
        AuthNSession: AuthNed<Prin, Session>,
    {
        debug!(target: "session-auth-nego",
               "session with {} authenticated, clearing backlog",
               session.prin());

        loop {
            if let Some(msg) = backlog.front() {
                if let Err(err) = session.get_mut().write_all(msg) {
                    match err.kind() {
                        // Need to resume later.
                        ErrorKind::WouldBlock => {
                            trace!(target: "session-auth-nego",
                                   "backlog clearance continuing");

                            return Ok(NegotiatorResult::Pending(
                                SessionNegoState::Backlog {
                                    backlog: Backlog(backlog),
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
                    if let Some(msg) = backlog.pop_front() {
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

    /// Step negotiations forward as far as we can.
    pub(crate) fn step<Session, Prin, SessionNego, AuthNego>(
        self,
        session_nego: &SessionNego,
        auth_nego: &AuthNego,
        auth_param: &AuthNego::Param
    ) -> Result<
        NegotiatorResult<AuthNResult<AuthNSession, ()>, Self>,
        SessionNegoStepError<SessionNego::NegotiateError,
                             AuthNego::StartError,
                             AuthNego::NegotiateError>
    >
    where
        Prin: Display,
        Session: Read + Write,
        SessionNego: Negotiator<Session, Pending = SessionPending>,
        AuthNSession: AuthNed<Prin, Session>,
        AuthNego: Negotiator<AuthNResult<AuthNSession, ()>,
                             Pending = AuthPending>
        + NegotiatorStart<AuthNResult<AuthNSession, ()>, Session>
    {
        match self {
            // Resuming session negotiations.
            SessionNegoState::Session { pending, backlog } => match session_nego
                .complete_negotiate(pending)
                .map_err(|err| SessionNegoStepError::Session { err: err })? {
                // Session negotiations completed.
                NegotiatorResult::Complete(session) => {
                    debug!(target: "session-auth-nego",
                           "session negotiated, starting auth negotiation");

                    // Start authentication negotiations.
                    let state = auth_nego
                        .start(auth_param, session)
                        .map_err(|err| SessionNegoStepError::Start {
                            err: err
                        })?;

                    // Try to negotiate immediately.
                    match auth_nego.negotiate(state)
                        .map_err(|err| SessionNegoStepError::AuthN {
                            err: err
                        })? {
                        // Authentication negotiations complete, succeeded.
                        //
                        // Clear the backlog
                        NegotiatorResult::Complete(
                            AuthNResult::Accept(session)
                        ) => Ok(Self::clear_backlog(session, backlog.0)
                                .map_err(|err| SessionNegoStepError::IO {
                                    err: err
                                })?
                                .map(|session| AuthNResult::Accept(session))),
                        // Authentication result other than success.
                        NegotiatorResult::Complete(res) =>
                            Ok(NegotiatorResult::Complete(res)),
                        // Authentication negotiations continue.
                        NegotiatorResult::Pending(pending) => {
                            trace!(target: "session-auth-nego",
                                   "auth negotiations continuing");

                            Ok(NegotiatorResult::Pending(
                                SessionNegoState::AuthN {
                                    backlog: backlog,
                                    pending: pending
                                })
                            )
                        }
                    }
                }
                // Session negotiations continue.
                NegotiatorResult::Pending(pending) => {
                    trace!(target: "session-auth-nego",
                           "session negotiations continuing later");

                    Ok(NegotiatorResult::Pending(SessionNegoState::Session {
                        backlog: backlog,
                        pending: pending
                    }))
                }
            }
            // Resuming authentication negotiations.
            SessionNegoState::AuthN { pending, backlog } => match auth_nego
                .complete_negotiate(pending)
                .map_err(|err| SessionNegoStepError::AuthN { err: err })? {
                // Authentication negotiations complete, succeeded.
                //
                // Clear the backlog
                NegotiatorResult::Complete(AuthNResult::Accept(session)) => Ok(
                    Self::clear_backlog(session, backlog.0)
                        .map_err(|err| SessionNegoStepError::IO {
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
                Ok(Self::clear_backlog(session, backlog.0)
                   .map_err(|err| SessionNegoStepError::IO {
                       err: err
                   })?
                   .map(|session| AuthNResult::Accept(session)))
        }
    }
}

impl<Session, Start, AuthN> Display
    for SessionNegoStepError<Session, Start, AuthN>
where
    Session: Display,
    Start: Display,
    AuthN: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoStepError::Session { err } => err.fmt(f),
            SessionNegoStepError::Start { err } => err.fmt(f),
            SessionNegoStepError::AuthN { err } => err.fmt(f),
            SessionNegoStepError::IO { err } => err.fmt(f)
        }
    }
}
