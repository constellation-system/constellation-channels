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

use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_auth::cred::CredentialsMut;
use constellation_common::config::Create;
use constellation_common::error::ScopedError;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use mio::event::Source;

use crate::near::NearChannel;
use crate::near::NearConnector;
use crate::near::NearChannelCreateWithEndpoint;

pub trait NearSessionNegoTypes {
    type Prin: Clone + Debug + Display + Eq + Hash;
    type AuthNPending;
    type AuthNSession: AuthNed<Self::Prin, Self::Conn>;
    type AuthN: Clone + Create
        + SessionAuthN<Self::Conn,
                       Param = (),
                       Pending = Self::AuthNPending,
                       AuthNSession = Self::AuthNSession,
                       StartError = Self::AuthStartError,
                       NegotiateError = Self::AuthNegoError>;
    type AuthStartError: Display + ScopedError;
    type AuthNegoError: Display + ScopedError;
    type Endpoint: Clone + Debug + Display + Eq + Hash + Sized;
    type Conn: CredentialsMut + Read + Write + Debug + Sized + Source
        + Session<PeerAddr = Self::Endpoint>;
    type ConnState;
    type ConnPending;
    type ShutdownParam;
    type ShutdownPending;
    type ShutdownValue: Source;
    type ShutdownNegoError: Display + ScopedError;
    type ShutdownStartError: Display + ScopedError;
    type ShutdownNego: NegotiatorStart<
        Self::ShutdownValue,
        Self::Conn,
        Param = Self::ShutdownParam,
        Pending = Self::ShutdownPending,
        StartError = Self::ShutdownStartError,
        NegotiateError = Self::ShutdownNegoError
    >;
    type Channel: NearChannel<
        Conn = Self::Conn,
        Endpoint = Self::Endpoint,
        State = Self::ConnState,
        Pending = Self::ConnPending,
        ShutdownValue = Self::ShutdownValue,
        ShutdownNego = Self::ShutdownNego,
        StartError = Self::SessionStartError,
        NegotiateError = Self::SessionNegoError
    >;
    type SessionStartError: Display + ScopedError;
    type SessionNegoError: Display + ScopedError;
}

pub trait NearDuplexNegoTypes {
    type InPrin: Clone + Debug + Display + Eq + Hash;
    type InAuthNPending;
    type InAuthNSession: AuthNed<Self::InPrin, Self::InConn>;
    type InAuthN: Clone + Create
        + SessionAuthN<Self::InConn,
                       Param = (),
                       Pending = Self::InAuthNPending,
                       AuthNSession = Self::InAuthNSession,
                       StartError = Self::InAuthStartError,
                       NegotiateError = Self::InAuthNegoError>;
    type InAuthStartError: Display + ScopedError;
    type InAuthNegoError: Display + ScopedError;
    type InEndpoint: Clone + Debug + Display + Eq + Hash + Sized;
    type InConn: CredentialsMut + Read + Write + Debug + Sized + Source
        + Session<PeerAddr = Self::InEndpoint>;
    type InConnState;
    type InConnPending;
    type InShutdownParam;
    type InShutdownPending;
    type InShutdownValue: Source;
    type InShutdownNegoError: Display + ScopedError;
    type InShutdownStartError: Display + ScopedError;
    type InShutdownNego: NegotiatorStart<
        Self::InShutdownValue,
        Self::InConn,
        Param = Self::InShutdownParam,
        Pending = Self::InShutdownPending,
        StartError = Self::InShutdownStartError,
        NegotiateError = Self::InShutdownNegoError
    >;
    type InChannel: NearChannel<
        Conn = Self::InConn,
        Endpoint = Self::InEndpoint,
        State = Self::InConnState,
        Pending = Self::InConnPending,
        ShutdownValue = Self::InShutdownValue,
        ShutdownNego = Self::InShutdownNego,
        StartError = Self::InSessionStartError,
        NegotiateError = Self::InSessionNegoError
    >;
    type InSessionStartError: Display + ScopedError;
    type InSessionNegoError: Display + ScopedError;
    type Inbound: NearSessionNegoTypes<
        Prin = Self::InPrin,
        AuthNPending = Self::InAuthNPending,
        AuthNSession = Self::InAuthNSession,
        AuthN = Self::InAuthN,
        AuthStartError = Self::InAuthStartError,
        AuthNegoError = Self::InAuthNegoError,
        Endpoint = Self::InEndpoint,
        Conn = Self::InConn,
        ConnState = Self::InConnState,
        ConnPending = Self::InConnPending,
        ShutdownParam = Self::InShutdownParam,
        ShutdownPending = Self::InShutdownPending,
        ShutdownValue = Self::InShutdownValue,
        ShutdownNegoError = Self::InShutdownNegoError,
        ShutdownStartError = Self::InShutdownStartError,
        ShutdownNego = Self::InShutdownNego,
        Channel = Self::InChannel,
        SessionStartError = Self::InSessionStartError,
        SessionNegoError = Self::InSessionNegoError
    >;
    type OutPrin: Clone + Debug + Display + Eq + Hash;
    type OutAuthNPending;
    type OutAuthNSession: AuthNed<Self::OutPrin, Self::OutConn>;
    type OutAuthN: Clone + Create
        + SessionAuthN<Self::OutConn,
                       Param = (),
                       Pending = Self::OutAuthNPending,
                       AuthNSession = Self::OutAuthNSession,
                       StartError = Self::OutAuthStartError,
                       NegotiateError = Self::OutAuthNegoError>;
    type OutAuthStartError: Display + ScopedError;
    type OutAuthNegoError: Display + ScopedError;
    type OutConfig: Clone;
    type OutEndpoint: Clone + Debug + Display + Eq + Hash + Sized;
    type OutConn: CredentialsMut + Read + Write + Debug + Sized + Source
        + Session<PeerAddr = Self::OutEndpoint>;
    type OutConnState;
    type OutConnPending;
    type OutShutdownParam;
    type OutShutdownPending;
    type OutShutdownValue: Source;
    type OutShutdownNegoError: Display + ScopedError;
    type OutShutdownStartError: Display + ScopedError;
    type OutShutdownNego: NegotiatorStart<
        Self::OutShutdownValue,
        Self::OutConn,
        Param = Self::OutShutdownParam,
        Pending = Self::OutShutdownPending,
        StartError = Self::OutShutdownStartError,
        NegotiateError = Self::OutShutdownNegoError
    >;
    type OutChannel: NearConnector +
        NearChannelCreateWithEndpoint<
            Conn = Self::OutConn,
            Endpoint = Self::OutEndpoint,
            State = Self::OutConnState,
            Pending = Self::OutConnPending,
            Config = Self::OutConfig,
            EndpointConfig = Self::OutEndpoint,
            CreateError = Self::OutCreateError,
            ShutdownValue = Self::OutShutdownValue,
            ShutdownNego = Self::OutShutdownNego,
            StartError = Self::OutSessionStartError,
            NegotiateError = Self::OutSessionNegoError
        >;
    type OutCreateError: Display + ScopedError;
    type OutSessionStartError: Display + ScopedError;
    type OutSessionNegoError: Display + ScopedError;
    type Outbound: NearSessionNegoTypes<
        Prin = Self::OutPrin,
        AuthNPending = Self::OutAuthNPending,
        AuthNSession = Self::OutAuthNSession,
        AuthN = Self::OutAuthN,
        AuthStartError = Self::OutAuthStartError,
        AuthNegoError = Self::OutAuthNegoError,
        Endpoint = Self::OutEndpoint,
        Conn = Self::OutConn,
        ConnState = Self::OutConnState,
        ConnPending = Self::OutConnPending,
        ShutdownParam = Self::OutShutdownParam,
        ShutdownPending = Self::OutShutdownPending,
        ShutdownValue = Self::OutShutdownValue,
        ShutdownNegoError = Self::OutShutdownNegoError,
        ShutdownStartError = Self::OutShutdownStartError,
        ShutdownNego = Self::OutShutdownNego,
        Channel = Self::OutChannel,
        SessionStartError = Self::OutSessionStartError,
        SessionNegoError = Self::OutSessionNegoError
    >;
}
