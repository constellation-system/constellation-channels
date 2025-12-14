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
use std::iter::Peekable;
use std::marker::PhantomData;
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

enum DuplexEntry<Accept, Conn> {
    Accept {
        accept: Accept
    },
    Conn {
        conn: Conn
    }
}

enum SessionNegoEntry<AuthN, Endpoint, Shutdown> {
    /// Authentication negotiation is pending.
    AuthN {
        /// Endpoint for this negotiation.
        endpoint: Endpoint,
        /// Pending negotiation state.
        pending: AuthN,
    },
    Active {
        /// Endpoint for this session.
        endpoint: Endpoint,
    },
    /// Shutdown negotiation is pending.
    Shutdown {
        /// Pending negotiation state.
        pending: Shutdown
    }
}

enum DuplexNegoEntry<Conn, Accept, AuthN, Endpoint, Shutdown> {
    /// Connector session negotiation is pending.
    Conn {
        /// Pending negotiation state.
        pending: Conn
    },
    /// Acceptor session negotiation is pending.
    Accept {
        /// Pending negotiation state.
        pending: Accept
    },
    /// Session-level state.
    Session {
        session: SessionNegoEntry<AuthN, Endpoint, Shutdown>
    }
}

enum NegoEntry<Conn, AuthN, Endpoint, Shutdown> {
    /// Connector session negotiation is pending.
    Conn {
        /// Pending negotiation state.
        pending: Conn
    },
    /// Session-level state.
    Session {
        session: SessionNegoEntry<AuthN, Endpoint, Shutdown>
    }
}

struct ConnectorEntry<State> {
    /// Token to use for registering sessions.
    token: Token,
    state: Option<State>,
    /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Instant
}

enum ChannelMode<Acceptor, Conn, AuthN, ShutdownNego>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Conn::Conn>,
    ShutdownNego::NegotiateError: ScopedError,
    Acceptor: NearChannel<Conn = Conn::Conn, Endpoint = Conn::Endpoint>
        + NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    AuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    /// Full-duplex channels, which can establish outbound as well as
    /// inbound connections.
    Duplex {
        config: Conn::Config,
        /// Acceptor for incoming sessions.
        acceptor: Acceptor,
        /// Token for acceptor.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint.
        tokens: HashMap<Conn::Endpoint, Token>,
        negos: HashMap<
            Token,
            ConnectorEntry<DuplexNegoEntry<Conn::State, Acceptor::State,
                                           AuthN::State, Conn::Endpoint,
                                           ShutdownNego::Pending>>
        >
    },
    /// Outbound-only channels, which can only establish connections.
    Outbound {
        config: Conn::Config,
        /// Session information for each endpoint.
        sessions: HashMap<Conn::Endpoint, Token>,
        negos: HashMap<
            Token,
            ConnectorEntry<NegoEntry<Conn::State, AuthN::State,
                                     Conn::Endpoint, ShutdownNego::Pending>>
        >,
    },
    /// Inbound-only channels, which can only listen for connections.
    Inbound {
        /// Acceptor for incoming sessions.
        acceptor: Acceptor,
        /// Token for acceptor.
        token: Token,
        /// Retry delay for acceptor.
        retry_when: Option<Instant>,
        /// Session information for each endpoint.
        sessions: HashMap<Acceptor::Endpoint, Token>,
        negos: HashMap<Token, NegoEntry<Acceptor::State, AuthN::State,
                                        Acceptor::Endpoint,
                                        ShutdownNego::Pending>>,
    }
}

struct ChannelEntry<Acceptor, Conn, AuthN, ShutdownNego>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Conn::Conn>,
    ShutdownNego::NegotiateError: ScopedError,
    Acceptor: NearChannel<Conn = Conn::Conn, Endpoint = Conn::Endpoint>
        + NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    AuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError
{
    mode: ChannelMode<Acceptor, Conn, AuthN, ShutdownNego>,
    /// Authenticator instance to use for sessions.
    authn: AuthN,
    /// Retry configuration to use.
    retry: Retry,
}

pub struct NearChannels<Acceptor, Conn, AuthN, ShutdownNego>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Conn::Conn>,
    ShutdownNego::NegotiateError: ScopedError,
    Acceptor: NearChannel<Conn = Conn::Conn, Endpoint = Conn::Endpoint>
        + NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    AuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
{
    /// Map from names to `NearChannelID`s.
    ids: HashMap<String, NearChannelID>,
    /// Reverse map from `NearChannelID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Acceptor, Conn, AuthN, ShutdownNego>>
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
pub enum SessionEntryStepError<AuthN, Shutdown> {
    AuthN {
        err: AuthN
    },
    Shutdown {
        err: Shutdown
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
pub enum SessionEntryCreateSessionError<Start, Session, Auth> {
    /// Error occurred starting session negotiations.
    Start {
        /// The error that occurred starting session negotiations.
        err: Start
    },
    /// Error occurred during session negotiations.
    Session {
        /// The error that occurred during session negotiations.
        err: Session
    },
    /// Error occurred during session negotiations.
    Auth {
        /// The error that occurred during session negotiations.
        err: Auth
    },
    /// Session is already active
    Active
}

pub enum SessionEntryShutdownError<Start, Nego> {
    /// Error occurred starting shutdown negotiations.
    Start {
        /// The error that occurred starting shutdown negotiations.
        err: Start
    },
    /// Error occurred during shutdown negotiations.
    Nego {
        /// The error that occurred during shutdown negotiations.
        err: Nego
    },
    /// The session was in a shutdown state.
    Shutdown,
    /// A session negotiation exists.
    Session,
    /// An authentication negotiation exists.
    AuthN,
    /// The session has no existing state.
    None
}

#[derive(Debug)]
pub enum SessionNegoStepError<Session, AuthN, Shutdown> {
    /// An error occurred during session negotiations.
    Session {
        /// The error that occurred during session negotiations.
        err: Session
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
    },
    /// An error occurred during shutdown negotiations.
    Shutdown {
        /// The error that occurred during shutdown negotiations.
        err: Shutdown
    }
}

impl<AuthNPending, Endpoint, ShutdownPending>
    SessionNegoEntry<AuthNPending, Endpoint, ShutdownPending>
where Endpoint: Clone + Eq + Hash {
    fn authn<Stream, AuthN>(
        authn: &AuthN,
        endpoint: Endpoint,
        stream: Stream
    ) -> Result<
        NegotiatorResult<
            AuthNResult<(Self, AuthN::AuthNSession), Stream>,
            Self
        >,
        SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
    >
    where
        Stream: Session,
        AuthN: SessionAuthN<Stream, Param = ()>
            + Negotiator<AuthNResult<AuthN::AuthNSession, Stream>,
                         Pending = AuthNPending>,
        AuthN::NegotiateError: ScopedError,
        AuthN::StartError: ScopedError {
        let state = authn
            .start(&(), stream)
            .map_err(|err| SessionEntryAuthNError::Start {
                err: err
            })?;

        Ok(authn
           .negotiate(state)
           .map_err(|err| SessionEntryAuthNError::AuthN { err: err })?
           .map_pending(|pending| SessionNegoEntry::AuthN {
               endpoint: endpoint.clone(),
               pending: pending
           })
           .map(|res| res.map(|session| (SessionNegoEntry::Active {
               endpoint: endpoint
           }, session))))
    }

    /// Create a `SessionNegoEntry` for shutdown negotiations.
    fn shutdown<Stream, ShutdownNego>(
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        stream: Stream
    ) -> Result<
        NegotiatorResult<(), Self>,
        ShutdownError<ShutdownNego::StartError,
                      ShutdownNego::NegotiateError>
    >
    where
        Stream: Session,
        ShutdownNego: NegotiatorStart<(), Stream>
            + Negotiator<(), Pending = ShutdownPending>,
        ShutdownNego::NegotiateError: ScopedError,
    {
        let state = shutdown.start(param, stream)
            .map_err(|err| ShutdownError::Start { err: err })?;

        Ok(shutdown.negotiate(state)
           .map_err(|err| ShutdownError::Negotiate {
               err: err
           })?
           .map_pending(|pending| SessionNegoEntry::Shutdown {
               pending: pending
           }))
    }

    fn listen<Stream, AuthN, ShutdownNego>(
        self,
        endpoints: &mut HashSet<Endpoint>,
        authn: &AuthN,
        shutdown: &ShutdownNego,
    ) -> Result<
        NegotiatorResult<
            Option<AuthNResult<(Self, AuthN::AuthNSession), Stream>>,
            Self
        >,
        SessionEntryStepError<
            AuthN::NegotiateError,
            ShutdownNego::NegotiateError
        >
    >
    where
        Stream: Session<PeerAddr = Endpoint>,
        AuthN: SessionAuthN<Stream, Param = ()>
            + Negotiator<AuthNResult<AuthN::AuthNSession, Stream>,
                         Pending = AuthNPending>,
        AuthN::NegotiateError: ScopedError,
        AuthN::StartError: ScopedError,
        ShutdownNego: NegotiatorStart<(), Stream>
            + Negotiator<(), Pending = ShutdownPending>,
        ShutdownNego::NegotiateError: ScopedError
    {
        match self {
            SessionNegoEntry::AuthN { pending, endpoint } =>
                Ok(authn
                   .complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::AuthN { err: err })?
                   .map_pending(|pending| SessionNegoEntry::AuthN {
                       endpoint: endpoint.clone(),
                       pending: pending
                   })
                   .map(|res| Some(res.map(|session| (SessionNegoEntry::Active {
                       endpoint: endpoint
                   }, session))))),
            SessionNegoEntry::Active { endpoint } => {
                endpoints.insert(endpoint.clone());

                Ok(NegotiatorResult::Pending(SessionNegoEntry::Active {
                    endpoint: endpoint
                }))
            }
            SessionNegoEntry::Shutdown { pending } =>
                Ok(shutdown.complete_negotiate(pending)
                   .map_err(|err| SessionEntryStepError::Shutdown { err: err })?
                   .map_pending(|pending| SessionNegoEntry::Shutdown {
                       pending: pending
                   })
                   .map(|()| None))
        }
    }
}

impl<ConnPending, AuthNPending, Endpoint, ShutdownPending>
    NegoEntry<ConnPending, AuthNPending, Endpoint, ShutdownPending>
where Endpoint: Clone + Eq + Hash {
    fn session<Conn, AuthN>(
        conn: &Conn,
        authn: &AuthN,
        state: Conn::State,
    ) -> Result<
        NegotiatorResult<
            AuthNResult<(Self, AuthN::AuthNSession), Conn::Conn>,
            Self
        >,
        NegoEntrySessionError<
            Conn::NegotiateError,
            SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
        >
    >
    where
        Conn: NearConnector<Pending = ConnPending> +
        NearChannelCreateWithEndpoint,
        Conn::Conn: Session<PeerAddr = Endpoint>,
        Conn::NegotiateError: ScopedError,
        AuthN: SessionAuthN<Conn::Conn, Param = ()>
            + Negotiator<AuthNResult<AuthN::AuthNSession, Conn::Conn>,
                         Pending = AuthNPending>,
        AuthN::NegotiateError: ScopedError,
        AuthN::StartError: ScopedError {
        conn.negotiate(state)
            .map_err(|err| NegoEntrySessionError::Nego { err: err })?
            .map_pending(|pending| NegoEntry::Conn { pending: pending })
            .flat_map_ok(|(stream, endpoint)|
                         Self::authn(authn, endpoint, stream)
                         .map_err(|err| NegoEntrySessionError::AuthN {
                             err: err
                         }))
    }

    fn authn<Stream, AuthN>(
        authn: &AuthN,
        endpoint: Endpoint,
        stream: Stream
    ) -> Result<
        NegotiatorResult<
            AuthNResult<(Self, AuthN::AuthNSession), Stream>,
            Self
        >,
        SessionEntryAuthNError<AuthN::StartError, AuthN::NegotiateError>
    >
    where
        Stream: Session,
        AuthN: SessionAuthN<Stream, Param = ()>
            + Negotiator<AuthNResult<AuthN::AuthNSession, Stream>,
                         Pending = AuthNPending>,
        AuthN::NegotiateError: ScopedError,
        AuthN::StartError: ScopedError {
        Ok(SessionNegoEntry::authn(authn, endpoint, stream)?
           .map_pending(|session| NegoEntry::Session { session: session })
           .map(|res| res.map(|(session, authned)| (NegoEntry::Session {
               session: session
           }, authned))))
    }

    /// Create a `SessionNegoEntry` for shutdown negotiations.
    fn shutdown<Stream, ShutdownNego>(
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        stream: Stream
    ) -> Result<
        NegotiatorResult<(), Self>,
        ShutdownError<ShutdownNego::StartError,
                      ShutdownNego::NegotiateError>
    >
    where
        Stream: Session,
        ShutdownNego: NegotiatorStart<(), Stream>
            + Negotiator<(), Pending = ShutdownPending>,
        ShutdownNego::NegotiateError: ScopedError,
    {
        Ok(SessionNegoEntry::shutdown(shutdown, param, stream)?
           .map_pending(|session| NegoEntry::Session { session: session }))
    }
}

impl<Conn, AuthN, ShutdownNego> SessionEntry<Conn, AuthN, ShutdownNego>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    AuthN: SessionAuthN<Conn::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Conn::Conn>,
    ShutdownNego::NegotiateError: ScopedError,
{
    #[inline]
    fn create(
        conn: Conn,
        token: Token
    ) -> Self {
        ConnectorEntry {
            token: token,
            state: None,
            nretries: 0,
            when: Instant::now()
        }
    }

    fn recv_session(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        conn: Conn::Conn
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionEntryAuthSessionError<
            AuthN::StartError,
            AuthN::NegotiateError,
        >
    > {
        // Start authentication negotiations.
        let state = authn
            .start(&(), conn)
            .map_err(|err| SessionEntryAuthSessionError::Start {
                err: err
            })?;

        match authn.negotiate(state) {
            // Negotiations completed immediately; set the state
            // to active and return.
            Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                info!(target: "session-nego-state",
                      "authenticated new session with {} over {}",
                      out.prin(), self.conn.endpoint());

                self.state = Some(SessionState::Active);
                self.nretries = 0;
                self.when = Instant::now();

                Ok(Some(out))
            },
            // Authentication failed.
            Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                info!(target: "session-nego-state",
                      "authentication rejected for session with {}",
                      self.conn.endpoint());

                let delay = retry.retry_delay(0);

                debug!(target: "session-nego-state",
                       "authentication rejected, delay for {}.{:03}s",
                       delay.as_secs(), delay.subsec_millis());

                self.state = None;
                self.nretries += 1;
                self.when = Instant::now() + delay;

                Ok(None)
            }
            // Negotiations stopped in a pending state.
            Ok(NegotiatorResult::Pending(pending)) => {
                self.state = Some(SessionState::AuthN {
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
                ErrorScope::System => Err(SessionEntryAuthSessionError::AuthN {
                    err: err
                }),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "session-nego-state",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    info!(target: "session-nego-state",
                          "session authn with {} failed: {}",
                          self.conn.endpoint(), err);

                    let delay = retry.retry_delay(0);

                    debug!(target: "session-nego-state",
                           "auth negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.state = None;
                    self.nretries += 1;
                    self.when = Instant::now() + delay;

                    Ok(None)
                }
            }
        }
    }

    fn negotiate_session(
        &mut self,
        authn: &AuthN,
        retry: &Retry,
        state: Conn::State
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        SessionEntryCreateSessionError<
            Conn::StartError,
            Conn::NegotiateError,
            SessionEntryAuthSessionError<
                AuthN::StartError,
                AuthN::NegotiateError,
            >
        >
    > {
        match self.conn.negotiate(state) {
            // Session negotiations succeeded; launch authentication
            // negotiations.
            Ok(NegotiatorResult::Complete((conn, _))) => self
                .recv_session(authn, retry, conn)
                .map_err(|err| SessionEntryCreateSessionError::Auth {
                    err: err
                })
                .map(RetryResult::Success),
            // Negotiations stopped in a pending state.
            Ok(NegotiatorResult::Pending(pending)) => {
                self.state = Some(SessionState::Session {
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
                    Err(SessionEntryCreateSessionError::Session {
                        err: err
                    }),
                // Retry after a delay
                scope => {
                    if !matches![scope, ErrorScope::Session] {
                        error!(target: "session-nego-state",
                               "shouldn't see error with scope {} here",
                               scope);
                    }

                    info!(target: "session-nego-state",
                          "session with {} failed: {}",
                          self.conn.endpoint(), err);

                    let delay = retry.retry_delay(self.nretries);

                    debug!(target: "session-nego-state",
                           "negotiation failed, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.state = None;
                    self.nretries += 1;
                    self.when = Instant::now() + delay;

                    Ok(RetryResult::Retry(self.when))
                }
            }
        }
    }

    fn create_session(
        &mut self,
        registry: &mut Registry,
        authn: &AuthN,
        retry: &Retry,
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        SessionEntryCreateSessionError<
            Conn::StartError,
            Conn::NegotiateError,
            SessionEntryAuthSessionError<
                AuthN::StartError,
                AuthN::NegotiateError,
            >
        >
    > {
        // Check if we're still delayed.
        let now = Instant::now();

        if self.when < now {
            self.conn.start(registry, self.token)
                .map_err(|err| SessionEntryCreateSessionError::Start {
                    err: err
                })?
                .flat_map_ok(|state|
                             self.negotiate_session(authn, retry, state))
        } else {
            // Still delayed.
            Ok(RetryResult::Retry(self.when))
        }
    }

    fn req_session(
        &mut self,
        registry: &mut Registry,
        authn: &AuthN,
        retry: &Retry,
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        SessionEntryCreateSessionError<
            Conn::StartError,
            Conn::NegotiateError,
            SessionEntryAuthSessionError<
                AuthN::StartError,
                AuthN::NegotiateError,
            >
        >
    > {
        if let Some(state) = &self.state {
            match state {
                // The negotiations are still pending.
                SessionState::Session { .. } |
                SessionState::AuthN { .. } |
                SessionState::Shutdown { .. } => Ok(RetryResult::Success(None)),
                // The session is already negotiated and taken.
                SessionState::Active =>
                    Err(SessionEntryCreateSessionError::Active),
            }
        } else {
            self.create_session(registry, authn, retry)
        }
    }

    fn shutdown_session<Addr>(
        &mut self,
        shutdown: &ShutdownNego,
        param: &ShutdownNego::Param,
        addr: Addr,
        session: AuthN::AuthNSession
    ) -> Result<
        (),
        SessionEntryShutdownError<ShutdownNego::StartError,
                                  ShutdownNego::NegotiateError>
    >
    where Addr: Display
    {
        match &self.state {
            // This is what we expect.
            Some(SessionState::Active) => {
                error!(target: "session-nego-state",
                       "shutting down active session with {}",
                       addr);

                let (_, session) = session.take();
                let state = shutdown.start(param, session)
                    .map_err(|err| SessionEntryShutdownError::Start {
                        err: err
                    })?;

                match shutdown.negotiate(state)
                    .map_err(|err| SessionEntryShutdownError::Nego {
                        err: err
                    })? {
                    NegotiatorResult::Complete(()) => {
                        info!(target: "session-nego-state",
                              "shutdown session with {}",
                              addr);

                        self.state = None;
                    }
                    NegotiatorResult::Pending(pending) => {
                        debug!(target: "session-nego-state",
                               "continuing shutdown negotiation with {}",
                               addr);

                        self.state = Some(SessionState::Shutdown {
                            pending: pending
                        });
                    }
                }

                Ok(())
            }
            // None of these should ever happen, but they're not
            // fatal.
            Some(SessionState::Session { .. }) =>
                Err(SessionEntryShutdownError::Session),
            Some(SessionState::AuthN { .. }) =>
                Err(SessionEntryShutdownError::AuthN),
            Some(SessionState::Shutdown { .. }) =>
                Err(SessionEntryShutdownError::Shutdown),
            None => Err(SessionEntryShutdownError::None)
        }
    }

    /// Step the ongoing negotiations, if possible.
    fn step<Addr>(
        &mut self,
        ext_endpoints: &mut HashSet<Addr>,
        authn: &AuthN,
        shutdown: &ShutdownNego,
        retry: &Retry,
        addr: Addr,
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionNegoStepError<
            Conn::NegotiateError,
            SessionEntryAuthSessionError<
                AuthN::StartError,
                AuthN::NegotiateError,
            >,
            ShutdownNego::NegotiateError
        >
    >
    where Addr: Display + Eq + Hash
    {
        let state = self.state.take();

        match state {
            Some(SessionState::Session { pending }) => match self.conn
                .complete_negotiate(pending) {
                Ok(NegotiatorResult::Complete((conn, _))) => self
                    .recv_session(authn, retry, conn)
                    .map_err(|err| SessionNegoStepError::AuthN { err: err }),
                // Negotiations stopped in a pending state.
                Ok(NegotiatorResult::Pending(pending)) => {
                    self.state = Some(SessionState::Session {
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
                    ErrorScope::System => Err(SessionNegoStepError::Session {
                        err: err
                    }),
                    // Retry after a delay
                    scope => {
                        if !matches![scope, ErrorScope::Session] {
                            error!(target: "session-nego-state",
                                   "shouldn't see error with scope {} here",
                                   scope);
                        }

                        info!(target: "session-nego-state",
                              "session with {} failed: {}",
                              addr, err);

                        let delay = retry.retry_delay(self.nretries);

                        debug!(target: "session-nego-state",
                               "negotiation failed, delay for {}.{:03}s",
                               delay.as_secs(), delay.subsec_millis());

                        self.state = None;
                        self.nretries += 1;
                        self.when = Instant::now() + delay;

                        Ok(None)
                    }
                }
            }
            // A pending authentication negotiation exists; step it.
            Some(SessionState::AuthN { pending }) => match authn
                .complete_negotiate(pending) {
                // Negotiations completed immediately; set the state
                // to active and return.
                Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                    info!(target: "session-nego-state",
                          "authenticated new session with {} over {}",
                          out.prin(), addr);

                    self.state = Some(SessionState::Active);
                    self.nretries = 0;

                    Ok(Some(out))
                },
                // Authentication failed.
                Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                    info!(target: "session-nego-state",
                          "authentication rejected for session with {}",
                          addr);

                    let delay = retry.retry_delay(self.nretries);

                    debug!(target: "session-nego-state",
                           "authentication rejected, delay for {}.{:03}s",
                           delay.as_secs(), delay.subsec_millis());

                    self.state = None;
                    self.nretries += 1;
                    self.when = Instant::now() + delay;

                    Ok(None)
                }
                // Negotiations stopped in a pending state.
                Ok(NegotiatorResult::Pending(pending)) => {
                    self.state = Some(SessionState::AuthN {
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
                    ErrorScope::System => Err(SessionNegoStepError::AuthN {
                        err: SessionEntryAuthSessionError::AuthN {
                            err: err
                        }
                    }),
                    // Retry after a delay
                    scope => {
                        if !matches![scope, ErrorScope::Session] {
                            error!(target: "session-nego-state",
                                   "shouldn't see error with scope {} here",
                                   scope);
                        }

                        info!(target: "session-nego-state",
                              "session with {} failed: {}",
                              addr, err);

                        let delay = retry.retry_delay(self.nretries);

                        debug!(target: "session-nego-state",
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
                    info!(target: "session-nego-state",
                           "successfully shutdown session with {}",
                          addr);

                    Ok(None)
                }
                NegotiatorResult::Pending(pending) => {
                    debug!(target: "session-nego-state",
                           "continuing shutdown negotiation with {}",
                           addr);

                    self.state = Some(SessionState::Shutdown {
                        pending: pending
                    });

                    Ok(None)
                }
            }
            // No existing state at all; ignore this.
            None => {
                debug!(target: "session-nego-state",
                      "attempting to step inactive session with {}",
                      addr);

                Ok(None)
            }
        }
    }
}
/*
impl<Acceptor, Conn, AuthN, ShutdownNego>
    ChannelEntry<Acceptor, Conn, AuthN, ShutdownNego>
where
    Conn: NearConnector + NearChannelCreateWithEndpoint,
    Conn::Conn: Session,
    Conn::NegotiateError: ScopedError,
    ShutdownNego: NegotiatorStart<(), Conn::Conn>,
    ShutdownNego::NegotiateError: ScopedError,
    Acceptor: NearChannel<Conn = Conn::Conn, Endpoint = Conn::Endpoint>
        + NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    AuthN: Clone + Create + SessionAuthN<Conn::Conn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
{
    fn create<Ctx>(
        ctx: &mut Ctx,
        config: NearChannelsEntryConfig<
            Acceptor::Config,
            Conn::Config,
            AuthN::Config
        >,
        default_authn: AuthN::Config,
        token: Token
    ) -> Result<
        Self,
        NearChannelsEntryCreateError<
            Acceptor::CreateError,
            AuthN::CreateError
        >
    >
    where
        Ctx: NSNameCachesCtx
    {
        let (acceptor, conn, authn, retry, nsessions, backlog_size) =
            config.take();
        // XXX this is wrong.  Create the connectors statically.
        let connectors = match nsessions {
            Some(size) => HashMap::with_capacity(size),
            None => HashMap::new()
        };
        let acceptor = Acceptor::create(ctx, acceptor)
            .map_err(|err| NearChannelsEntryCreateError::Accept { err: err })?;
        let authn = authn.unwrap_or(default_authn);
        let authn = AuthN::create(authn)
            .map_err(|err| NearChannelsEntryCreateError::AuthN { err: err })?;
        let inbound = match nsessions {
            Some(size) => HashMap::with_capacity(size),
            None => HashMap::new()
        };

        Ok(ChannelEntry {
            conn: PhantomData,
            acceptor: acceptor,
            connectors: connectors,
            inbound: inbound,
            config: conn,
            authn: authn,
            retry: retry,
            token: token,
            backlog_size: backlog_size,
            retry_when: None
        })
    }

    fn addrs(
        &self,
        buf: &mut Vec<Acceptor::Endpoint>
    ) {
        buf.extend(self.sessions.keys().cloned())
    }

    fn accept_session(
        &mut self,
        authn: &AuthN,
        conn: Acceptor::Conn,
        endpoint: Acceptor::Endpoint,
        token: Token
    ) -> Result<
        Option<AuthN::AuthNSession>,
        SessionEntryAuthSessionError<
            AuthN::StartError,
            AuthN::NegotiateError,
        >
    > {
        // Check if there's a connector entry.
        if let Some(ent) = self.connectors.get_mut(&endpoint) {
            // Deliver the session to the connector entry if there is one.
            ent.recv_session(authn, &self.retry, conn)
        } else {
            // Start authentication negotiations.
            let state = authn
                .start(&(), conn)
                .map_err(|err| SessionEntryAuthSessionError::Start {
                    err: err
                })?;

            match authn.negotiate(state) {
                // Negotiations completed immediately; set the state
                // to active and return.
                Ok(NegotiatorResult::Complete(AuthNResult::Accept(out))) => {
                    info!(target: "near-channel-entry",
                          "authenticated new inbound session with {} over {}",
                          out.prin(), endpoint);

                    let state = SessionState::Active;

                    // Paranoid check.
                    if self.inbound.insert(token, state).is_some() {
                        error!(target: "near-channel-entry",
                               "entry already existed for token {:?}",
                               token);
                    }

                    Ok(Some(out))
                },
                // Authentication failed.  We don't do anything here.
                Ok(NegotiatorResult::Complete(AuthNResult::Reject(_))) => {
                    info!(target: "session-nego-state",
                          "authentication rejected for inbound session with {}",
                          endpoint);

                    Ok(None)
                }
                // Negotiations stopped in a pending state.
                Ok(NegotiatorResult::Pending(pending)) => {
                    let state = SessionState::AuthN {
                        pending: pending
                    };

                    // Paranoid check.
                    if self.inbound.insert(token, state).is_some() {
                        error!(target: "near-channel-entry",
                               "entry already existed for token {:?}",
                               token);
                    }

                    Ok(None)
                }
                // Error occurred; check its scope.
                Err(err) => match err.scope() {
                    // Pass these errors through.
                    ErrorScope::Unrecoverable |
                    ErrorScope::Shutdown |
                    ErrorScope::External |
                    ErrorScope::System =>
                        Err(SessionEntryAuthSessionError::AuthN {
                            err: err
                        }),
                    // Log the failure, but we don't do anything here.
                    scope => {
                        if !matches![scope, ErrorScope::Session] {
                            error!(target: "session-nego-state",
                                   "shouldn't see error with scope {} here",
                                   scope);
                        }

                        info!(target: "session-nego-state",
                              "inbound session authn with {} failed: {}",
                              endpoint, err);

                        Ok(None)
                    }
                }
            }
        }
    }


    fn do_listen<I>(
        &mut self,
        registry: &mut Registry,
        gentok: &mut Peekable<I>,
        ext_endpoints: &mut HashSet<Acceptor::Endpoint>,
        sessions: &mut Vec<AuthN::AuthNSession>,
        tokens: &HashSet<Token>,
        authn: &AuthN,
        shutdown: &ShutdownNego,
    ) -> Result<
        (),
    >
    where I: Iterator<Item = Token>
    {
        let mut states = Vec::new();

        while {
            let read = false;

            // Collect all new sessions.
            loop {
                let token = *gentok.peek().ok_or()?;

                match self.retry_when {
                    Some(when) if Instant::now() < when => break,
                    _ => match self.acceptor.start(registry, token) {
                        Ok(RetryResult::Success(state)) => {
                            // Normal listen result.
                            read = true;

                            // Paranoid checks.  This should never happen.
                            if let Some(next) = gentok.next() {
                                if next != token {
                                    error!(target: "near-channel-entry",
                                           "tokens don't match: {:?} != {:?}",
                                           next, token);
                                }
                            } else {
                                error!(target: "near-channel-entry",
                                       "inconsistent iterator")
                            }

                            states.push((token, state))
                        }
                        Ok(RetryResult::Retry(when)) => {
                            self.retry_when = Some(when);

                            break;
                        }
                        // Error; see if it's WouldBlock.
                        Err(err) => if err.scope() == ErrorScope::WouldBlock {
                            // Non-blocking I/O exhausted.
                            break;
                        } else {
                            // A real error occurred.
                            return Err(SessionListenError::Flows {
                                err: err
                            });
                        }
                    }
                }
            }

            for (token, state) in states.drain(..) {
                match self.acceptor.negotiate(state) {
                    // Session negotiations succeeded; launch authentication
                    // negotiations.
                    Ok(NegotiatorResult::Complete((conn, endpoint))) => self
                        .accept_session(authn, conn, endpoint, token)
                        .map_err(|err| SessionEntryCreateSessionError::Auth {
                            err: err
                        })
                        .map(RetryResult::Success),
                    // Negotiations stopped in a pending state.
                    Ok(NegotiatorResult::Pending(pending)) => {
                        let state = SessionState::Session {
                            pending: pending
                        };

                        // Paranoid check.
                        if self.inbound.insert(token, state).is_some() {
                            error!(target: "near-channel-entry",
                                   "entry already existed for token {:?}",
                                   token);
                        }
                    }
                    // Error occurred; check its scope.
                    Err(err) => match err.scope() {
                        // Pass these errors through.
                        ErrorScope::Unrecoverable |
                        ErrorScope::Shutdown |
                        ErrorScope::External |
                        ErrorScope::System =>
                            Err(SessionEntryCreateSessionError::Session {
                                err: err
                            }),
                        // Retry after a delay
                        scope => {
                            if !matches![scope, ErrorScope::Session] {
                                error!(target: "session-nego-state",
                                       "shouldn't see error with scope {} here",
                                       scope);
                            }

                            info!(target: "session-nego-state",
                                  "inbound session failed: {}",
                                  self.conn.endpoint(), err);

                            let delay = retry.retry_delay(self.nretries);

                            debug!(target: "session-nego-state",
                                   "negotiation failed, delay for {}.{:03}s",
                                   delay.as_secs(), delay.subsec_millis());

                            self.state = None;
                            self.nretries += 1;
                            self.when = Instant::now() + delay;

                            Ok(RetryResult::Retry(self.when))
                        }
                    }
                }
            }


            read
        } {}

        Ok(())
    }

    fn listen<I>(
        &mut self,
        registry: &mut Registry,
        gentok: &mut Peekable<I>,
        ext_endpoints: &mut HashSet<Acceptor::Endpoint>,
        sessions: &mut Vec<AuthN::AuthNSession>,
        tokens: &HashSet<Token>,
        authn: &AuthN,
        shutdown: &ShutdownNego,
    ) -> Result<
        (),
    >
    where I: Iterator<Item = Token>
    {
        if tokens.contains(&self.token) {
            self.do_listen(registry, gentok, ext_endpoints,
                           sessions, tokens, authn, shutdown)
        } else {
            Ok(())
        }
    }

    fn req_session<Ctx, I>(
        &mut self,
        ctx: &mut Ctx,
        registry: &mut Registry,
        tokens: &mut I,
        authn: &AuthN,
        retry: &Retry,
        endpoint: Acceptor::Endpoint,
        verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Option<AuthN::AuthNSession>>,
        NearChannelsEntrySessionError<
            Conn::CreateError,
            SessionEntryCreateSessionError<
                Conn::StartError,
                Conn::NegotiateError,
                SessionEntryAuthSessionError<
                    AuthN::StartError,
                    AuthN::NegotiateError,
                >
            >
        >
    >
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token>
    {
        match self.sessions.entry(endpoint.clone()) {
            // Entry already exists, but there are several possible outcomes.
            Entry::Occupied(mut ent) => ent
                .get_mut()
                .req_session(registry, authn, retry)
                .map_err(|err| NearChannelsEntrySessionError::Req {
                    err: err
                }),
            Entry::Vacant(ent) => {
                let conn = Conn::create_with_endpoint(ctx, self.config,
                                                      endpoint,
                                                      verify_endpoint)
                    .map_err(|err| NearChannelsEntrySessionError::Conn {
                        err: err
                    })?;
                let token = tokens.next()
                    .ok_or(NearChannelsEntrySessionError::NoTokens)?;

                ent.insert(ConnectorEntry::create(conn, token))
                    .req_session(registry, authn, retry)
                    .map_err(|err| NearChannelsEntrySessionError::Req {
                        err: err
                    })
            }
        }
    }
}
*/
impl Display for NearChannelID {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "{}", self.0.0)
    }
}

impl<Accept, AuthN> NearChannelsEntryCreateError<Accept, AuthN>
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

impl<Conn, Req> NearChannelsEntrySessionError<Conn, Req>
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

impl<Start, Session, Auth> SessionEntryCreateSessionError<Start, Session, Auth>
where Start: Display,
      Session: Display,
      Auth: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryCreateSessionError::Start { err } => err.fmt(f),
            SessionEntryCreateSessionError::Session { err } => err.fmt(f),
            SessionEntryCreateSessionError::Auth { err } => err.fmt(f),
            SessionEntryCreateSessionError::Active =>
                write!(f, "session is already taken")
        }
    }
}

impl<AuthN, Shutdown> SessionEntryStepError<AuthN, Shutdown>
where AuthN: Display,
      Shutdown: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryStepError::Shutdown { err } => err.fmt(f),
            SessionEntryStepError::AuthN { err } => err.fmt(f),
        }
    }
}

impl<Start, Auth> SessionEntryAuthNError<Start, Auth>
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

impl<Nego, AuthN> NegoEntrySessionError<Nego, AuthN>
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

impl<Start, Nego> SessionEntryShutdownError<Start, Nego>
where Start: Display,
      Nego: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionEntryShutdownError::Start { err } => err.fmt(f),
            SessionEntryShutdownError::Nego { err } => err.fmt(f),
            SessionEntryShutdownError::Shutdown =>
                write!(f, "session has shutdown state"),
            SessionEntryShutdownError::Session =>
                write!(f, "session has pending session negotiation"),
            SessionEntryShutdownError::AuthN =>
                write!(f, "session has pending authentication negotiation"),
            SessionEntryShutdownError::None =>
                write!(f, "session has no active")
        }
    }
}

impl<Session, AuthN, Shutdown> SessionNegoStepError<Session, AuthN, Shutdown>
where Session: Display,
      AuthN: Display,
      Shutdown: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            SessionNegoStepError::Session { err } => err.fmt(f),
            SessionNegoStepError::AuthN { err } => err.fmt(f),
            SessionNegoStepError::Shutdown { err } => err.fmt(f),
            SessionNegoStepError::IO { err } => err.fmt(f),
        }
    }
}
