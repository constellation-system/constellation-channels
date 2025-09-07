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
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::Instant;

use constellation_auth::authn::SessionAuthN;
use constellation_common::config::Create;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use mio::Token;

use crate::channels::SessionNegoState;
use crate::channels::SessionResult;
use crate::config::NearChannelsEntryConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

/// Newtype wrapper for IDs created to refer to specific channels.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NearChannelID(Token);

enum SessionState<Conn, SessionPending, AuthN> {
    /// Session negotiation is pending.
    Pending {
        /// The pending negotiation state.
        pending: SessionNegoState<Conn, SessionPending, AuthN>
    },
    /// A session has already been established.
    Active
}

struct SessionEntry<Conn, AuthNPending>
where
    Conn: NearConnector
{
    /// Connector to use to obtain sessions.
    conn: Conn,
    state: Option<SessionState<Conn::Conn, Conn::Pending, AuthNPending>>,
    /// Number of retries.
    nretries: usize,
    /// When to retry next.
    when: Instant
}

struct ChannelEntry<Acceptor, Conn, AuthN>
where
    Acceptor: NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    Conn: NearChannel<Conn = Acceptor::Conn, Endpoint = Acceptor::Endpoint>
        + NearChannelCreateWithEndpoint
        + NearConnector,
    AuthN: Clone + SessionAuthN<Acceptor::Conn>,
{
    conn: PhantomData<Conn>,
    /// Configuration for creating outbound connectors.
    config: Conn::Config,
    sessions: HashMap<Acceptor::Endpoint, SessionEntry<Conn, AuthN::Pending>>,
    /// Acceptor for incoming sessions.
    acceptor: Acceptor,
    /// Authenticator instance to use for sessions.
    authn: AuthN,
    /// Retry configuration to use.
    retry: Retry,
    /// Size hint for backlogs.
    backlog_size: Option<usize>
}

pub struct NearChannels<Acceptor, Conn, AuthN>
where
    Acceptor: NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    Conn: NearChannel<Conn = Acceptor::Conn,
                      Endpoint = Acceptor::Endpoint>
        + NearChannelCreateWithEndpoint
        + NearConnector,
    AuthN: Clone + Create + SessionAuthN<Acceptor::Conn>,
{
    /// Map from names to `NearChannelID`s.
    ids: HashMap<String, NearChannelID>,
    /// Reverse map from `NearChannelID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<ChannelEntry<Acceptor, Conn, AuthN>>
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
pub enum NearChannelsEntrySessionError<Conn> {
    Conn {
        err: Conn
    }
    /// Session is already active
    Active
}

impl<Acceptor, Conn, AuthN> ChannelEntry<Acceptor, Conn, AuthN>
where
    Acceptor: NearChannelCreate,
    Acceptor::Endpoint: Clone + Eq + Hash,
    Conn: NearChannel<Conn = Acceptor::Conn, Endpoint = Acceptor::Endpoint>
        + NearChannelCreateWithEndpoint
        + NearConnector,
    AuthN: Clone + Create + SessionAuthN<Acceptor::Conn>,
{
    fn create<Ctx>(
        ctx: &mut Ctx,
        config: NearChannelsEntryConfig<
            Acceptor::Config,
            Conn::Config,
            AuthN::Config
        >,
        default_authn: AuthN::Config
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
        let sessions = match nsessions {
            Some(size) => HashMap::with_capacity(size),
            None => HashMap::new()
        };
        let acceptor = Acceptor::create(ctx, acceptor)
            .map_err(|err| NearChannelsEntryCreateError::Accept { err: err })?;
        let authn = authn.unwrap_or(default_authn);
        let authn = AuthN::create(authn)
            .map_err(|err| NearChannelsEntryCreateError::AuthN { err: err })?;

        Ok(ChannelEntry {
            conn: PhantomData,
            acceptor: acceptor,
            sessions: sessions,
            config: conn,
            authn: authn,
            retry: retry,
            backlog_size: backlog_size
        })
    }

    fn addrs(
        &self,
        buf: &mut Vec<Acceptor::Endpoint>
    ) {
        buf.extend(self.sessions.keys().cloned())
    }


    fn session<Ctx>(
        &mut self,
        ctx: &mut Ctx,
        endpoint: Acceptor::Endpoint
    ) -> Result<
        RetryResult<SessionResult<'_, >>,
        NearChannelsEntrySessionError<Conn::CreateError>
    >
    where
        Ctx: NSNameCachesCtx
    {
        match self.sessions.entry(endpoint.clone()) {
            // Entry already exists, but there are several possible outcomes.
            Entry::Occupied(mut ent) => {
                let ent = ent.get_mut();

                // Check the state of the entry.
                match ent.state {
                    // The session is already negotiated and taken.
                    Some(SessionState::Active) =>
                        Err(NearChannelsEntrySessionError::Active),
                    // The negotiations are still pending; return the
                    // backlog.
                    Some(SessionState::Pending { pending }) =>
                        Ok(RetryResult::Success(
                            SessionResult::Pending(pending.backlog())
                        )),
                    None => {
                        let now = Instant::now();

                        if ent.when < now {

                        } else {
                            Ok(RetryResult::Retry(ent.when))
                        }
                    }
                }
            }
            Entry::Vacant(ent) => {
                let conn = Conn::create_with_endpoint(ctx, self.config,
                                                      endpoint)
            }
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

impl<Conn> NearChannelsEntrySessionError<Conn>
where Conn: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NearChannelsEntrySessionError::Conn { err } => err.fmt(f),
            NearChannelsEntrySessionError::Active =>
                write!(f, "session is already taken")
        }
    }
}
