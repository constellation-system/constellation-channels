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
use std::marker::PhantomData;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_auth::cred::CredentialsMut;
use constellation_common::config::Create;
use constellation_common::error::ScopedError;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use mio::event::Source;

#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadClient;
#[cfg(feature = "tls")]
use crate::config::tls::TLSLoadServer;
use crate::near::compound::CompoundNearAcceptor;
use crate::near::compound::CompoundNearAcceptorNegotiateError;
use crate::near::compound::CompoundNearAcceptorNegotiatePending;
use crate::near::compound::CompoundNearAcceptorShutdownNegotiator;
use crate::near::compound::CompoundNearAcceptorShutdownValue;
use crate::near::compound::CompoundNearAcceptorStartError;
use crate::near::compound::CompoundNearAcceptorState;
use crate::near::compound::CompoundNearClientConn;
use crate::near::compound::CompoundNearConcreteAddr;
use crate::near::compound::CompoundNearConnector;
use crate::near::compound::CompoundNearConnectorNegotiateError;
use crate::near::compound::CompoundNearConnectorNegotiatePending;
use crate::near::compound::CompoundNearConnectorShutdownNegotiator;
use crate::near::compound::CompoundNearConnectorShutdownValue;
use crate::near::compound::CompoundNearConnectorStartError;
use crate::near::compound::CompoundNearConnectorState;
use crate::near::compound::CompoundNearNameAddr;
use crate::near::compound::CompoundNearServerConn;
use crate::near::compound::CompoundNearShutdownNegotiatorPending;
use crate::near::compound::CompoundNegotiatorStartError;
use crate::near::compound::CompoundShutdownError;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;

pub trait NearSessionNegoTypes {
    type Prin: Clone + Debug + Display + Eq + Hash;
    type AuthNConfig: Clone + Default;
    type AuthNPending;
    type AuthNSession: AuthNed<Self::Prin, Self::Conn>;
    type AuthN: Create<Config = Self::AuthNConfig, CreateError = Self::AuthCreateError>
        + SessionAuthN<
            Self::Conn,
            Param = (),
            Pending = Self::AuthNPending,
            AuthNSession = Self::AuthNSession,
            StartError = Self::AuthStartError,
            NegotiateError = Self::AuthNegoError
        >;
    type AuthCreateError: Debug + Display;
    type AuthStartError: Debug + Display + ScopedError;
    type AuthNegoError: Debug + Display + ScopedError;
    type Endpoint: Clone + Debug + Display + Eq + Hash + Sized;
    type Conn: CredentialsMut
        + Read
        + Write
        + Debug
        + Sized
        + Source
        + Session<PeerAddr = Self::Endpoint>;
    type ConnState;
    type ConnPending;
    type ShutdownParam;
    type ShutdownPending;
    type ShutdownValue: Source;
    type ShutdownNegoError: Debug + Display + ScopedError;
    type ShutdownStartError: Debug + Display + ScopedError;
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
    type SessionStartError: Debug + Display + ScopedError;
    type SessionNegoError: Debug + Display + ScopedError;
}

pub trait NearDuplexNegoTypes {
    type InEndpoint: Clone + Debug + Display + Eq + Hash + Sized;
    type InConfig;
    type InPrin: Clone + Debug + Display + Eq + Hash;
    type InAuthNConfig: Clone + Default;
    type InAuthNPending;
    type InAuthNSession: AuthNed<Self::InPrin, Self::InConn>;
    type InAuthN: Create<
            Config = Self::InAuthNConfig,
            CreateError = Self::InAuthCreateError
        > + SessionAuthN<
            Self::InConn,
            Param = (),
            Pending = Self::InAuthNPending,
            AuthNSession = Self::InAuthNSession,
            StartError = Self::InAuthStartError,
            NegotiateError = Self::InAuthNegoError
        >;
    type InAuthCreateError: Debug + Display;
    type InAuthStartError: Debug + Display + ScopedError;
    type InAuthNegoError: Debug + Display + ScopedError;
    type InConn: CredentialsMut
        + Read
        + Write
        + Debug
        + Sized
        + Source
        + Session<PeerAddr = Self::InEndpoint>;
    type InConnState;
    type InConnPending;
    type InShutdownParam;
    type InShutdownPending;
    type InShutdownValue: Source;
    type InShutdownNegoError: Debug + Display + ScopedError;
    type InShutdownStartError: Debug + Display + ScopedError;
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
        > + NearChannelCreate<
            Config = Self::InConfig,
            CreateError = Self::InChannelCreateError
        > + Source;
    type InChannelCreateError: Debug + Display;
    type InSessionStartError: Debug + Display + ScopedError;
    type InSessionNegoError: Debug + Display + ScopedError;
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
    type OutEndpoint: Clone
        + Debug
        + Display
        + Eq
        + Hash
        + Sized
        + From<Self::InEndpoint>;
    type OutPrin: Clone + Debug + Display + Eq + Hash;
    type OutAuthNConfig: Clone + Default;
    type OutAuthNPending;
    type OutAuthNSession: AuthNed<Self::OutPrin, Self::OutConn>;
    type OutAuthN: Create<
            Config = Self::OutAuthNConfig,
            CreateError = Self::OutAuthCreateError
        > + SessionAuthN<
            Self::OutConn,
            Param = (),
            Pending = Self::OutAuthNPending,
            AuthNSession = Self::OutAuthNSession,
            StartError = Self::OutAuthStartError,
            NegotiateError = Self::OutAuthNegoError
        >;
    type OutAuthCreateError: Debug + Display;
    type OutAuthStartError: Debug + Display + ScopedError;
    type OutAuthNegoError: Debug + Display + ScopedError;
    type OutConfig: Clone;
    type OutConn: CredentialsMut
        + Read
        + Write
        + Debug
        + Sized
        + Source
        + Session<PeerAddr = Self::OutEndpoint>;
    type OutConnState;
    type OutConnPending;
    type OutShutdownParam;
    type OutShutdownPending;
    type OutShutdownValue: Source;
    type OutShutdownNegoError: Debug + Display + ScopedError;
    type OutShutdownStartError: Debug + Display + ScopedError;
    type OutShutdownNego: NegotiatorStart<
        Self::OutShutdownValue,
        Self::OutConn,
        Param = Self::OutShutdownParam,
        Pending = Self::OutShutdownPending,
        StartError = Self::OutShutdownStartError,
        NegotiateError = Self::OutShutdownNegoError
    >;
    type OutParam: Clone;
    type OutChannel: NearConnector
        + NearChannelCreateWithEndpoint<
            Conn = Self::OutConn,
            Endpoint = Self::OutEndpoint,
            State = Self::OutConnState,
            Pending = Self::OutConnPending,
            Config = Self::OutConfig,
            Param = Self::OutParam,
            EndpointConfig = Self::OutEndpoint,
            CreateError = Self::OutCreateError,
            ShutdownValue = Self::OutShutdownValue,
            ShutdownNego = Self::OutShutdownNego,
            StartError = Self::OutSessionStartError,
            NegotiateError = Self::OutSessionNegoError
        >;
    type OutCreateError: Debug + Display + ScopedError;
    type OutSessionStartError: Debug + Display + ScopedError;
    type OutSessionNegoError: Debug + Display + ScopedError;
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

/// A standard [NearDuplexNegoTypes] object, created from two
/// [NearSessionNegoTypes] instances.
///
/// Given the structure of [NearDuplexNegoTypes], all other instances
/// should just be type aliases of this one.
#[derive(Clone, Default)]
pub struct SimpleNearDuplexNegoTypes<In, Out>
where
    In: NearSessionNegoTypes,
    Out: NearSessionNegoTypes,
    In::Channel: Source,
    Out::Channel: NearConnector
        + NearChannelCreateWithEndpoint<EndpointConfig = Out::Endpoint>,
    <Out::Channel as NearChannelCreateWithEndpoint>::Config: Clone {
    pub intypes: In,
    pub outypes: Out
}

/// A standard [NearSessionNegoTypes] object for [CompoundNearAcceptor]s.
///
/// This will construct a [NearSessionNegoTypes] implemnetation for
/// any [SessionAuthN] satisfying the relatively simple type
/// constraints.  All other [NearSessionNegoTypes] instances based
/// around [CompoundNearAcceptor]s should be type aliases of this.
#[derive(Default)]
pub struct CompoundAcceptorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearServerConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadServer {
    tls: PhantomData<TLS>,
    authn: PhantomData<AuthN>
}

/// A standard [NearSessionNegoTypes] object for [CompoundNearConnector]s.
///
/// This will construct a [NearSessionNegoTypes] implemnetation for
/// any [SessionAuthN] satisfying the relatively simple type
/// constraints.  All other [NearSessionNegoTypes] instances based
/// around [CompoundNearConnector]s should be type aliases of this.
#[derive(Default)]
pub struct CompoundConnectorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearClientConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadClient {
    tls: PhantomData<TLS>,
    authn: PhantomData<AuthN>
}

impl<AuthN, TLS> Clone for CompoundAcceptorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearServerConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadServer
{
    #[inline]
    fn clone(&self) -> Self {
        CompoundAcceptorNegoTypes {
            authn: self.authn,
            tls: self.tls
        }
    }
}

unsafe impl<AuthN, TLS> Send for CompoundAcceptorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearServerConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadServer
{
}

unsafe impl<AuthN, TLS> Sync for CompoundAcceptorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearServerConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadServer
{
}

impl<AuthN, TLS> Clone for CompoundConnectorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearClientConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadClient
{
    #[inline]
    fn clone(&self) -> Self {
        CompoundConnectorNegoTypes {
            authn: self.authn,
            tls: self.tls
        }
    }
}

unsafe impl<AuthN, TLS> Send for CompoundConnectorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearClientConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadClient
{
}

unsafe impl<AuthN, TLS> Sync for CompoundConnectorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearClientConn, Param = ()>,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadClient
{
}

impl<AuthN, TLS> NearSessionNegoTypes for CompoundAcceptorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearServerConn, Param = ()>,
    AuthN::Config: Clone + Default,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadServer
{
    type AuthCreateError = AuthN::CreateError;
    type AuthN = AuthN;
    type AuthNConfig = AuthN::Config;
    type AuthNPending = AuthN::Pending;
    type AuthNSession = AuthN::AuthNSession;
    type AuthNegoError = AuthN::NegotiateError;
    type AuthStartError = AuthN::StartError;
    type Channel = CompoundNearAcceptor<TLS>;
    type Conn = CompoundNearServerConn;
    type ConnPending = CompoundNearAcceptorNegotiatePending;
    type ConnState = CompoundNearAcceptorState;
    type Endpoint = CompoundNearConcreteAddr;
    type Prin = AuthN::Prin;
    type SessionNegoError = CompoundNearAcceptorNegotiateError;
    type SessionStartError = CompoundNearAcceptorStartError;
    type ShutdownNego = CompoundNearAcceptorShutdownNegotiator;
    type ShutdownNegoError = CompoundShutdownError;
    type ShutdownParam = ();
    type ShutdownPending =
        CompoundNearShutdownNegotiatorPending<CompoundNearServerConn>;
    type ShutdownStartError = CompoundNegotiatorStartError;
    type ShutdownValue = CompoundNearAcceptorShutdownValue;
}

impl<AuthN, TLS> NearSessionNegoTypes for CompoundConnectorNegoTypes<AuthN, TLS>
where
    AuthN: Create + SessionAuthN<CompoundNearClientConn, Param = ()>,
    <AuthN as Create>::Config: Clone + Default,
    AuthN::NegotiateError: ScopedError,
    TLS: Clone + Debug + TLSLoadClient
{
    type AuthCreateError = AuthN::CreateError;
    type AuthN = AuthN;
    type AuthNConfig = <AuthN as Create>::Config;
    type AuthNPending = AuthN::Pending;
    type AuthNSession = AuthN::AuthNSession;
    type AuthNegoError = AuthN::NegotiateError;
    type AuthStartError = AuthN::StartError;
    type Channel = CompoundNearConnector<TLS>;
    type Conn = CompoundNearClientConn;
    type ConnPending = CompoundNearConnectorNegotiatePending;
    type ConnState = CompoundNearConnectorState;
    type Endpoint = CompoundNearNameAddr;
    type Prin = AuthN::Prin;
    type SessionNegoError = CompoundNearConnectorNegotiateError;
    type SessionStartError = CompoundNearConnectorStartError;
    type ShutdownNego = CompoundNearConnectorShutdownNegotiator;
    type ShutdownNegoError = CompoundShutdownError;
    type ShutdownParam = ();
    type ShutdownPending =
        CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>;
    type ShutdownStartError = CompoundNegotiatorStartError;
    type ShutdownValue = CompoundNearConnectorShutdownValue;
}

impl<In, Out> NearDuplexNegoTypes for SimpleNearDuplexNegoTypes<In, Out>
where
    In: NearSessionNegoTypes,
    Out: NearSessionNegoTypes,
    Out::Endpoint: From<In::Endpoint>,
    In::Channel: NearChannelCreate + Source,
    Out::Channel: NearConnector
        + NearChannelCreateWithEndpoint<EndpointConfig = Out::Endpoint>,
    <Out::Channel as NearChannelCreateWithEndpoint>::Config: Clone,
    <Out::Channel as NearChannelCreateWithEndpoint>::Param: Clone + Debug
{
    type InAuthCreateError = In::AuthCreateError;
    type InAuthN = In::AuthN;
    type InAuthNConfig = In::AuthNConfig;
    type InAuthNPending = In::AuthNPending;
    type InAuthNSession = In::AuthNSession;
    type InAuthNegoError = In::AuthNegoError;
    type InAuthStartError = In::AuthStartError;
    type InChannel = In::Channel;
    type InChannelCreateError = <In::Channel as NearChannelCreate>::CreateError;
    type InConfig = <In::Channel as NearChannelCreate>::Config;
    type InConn = In::Conn;
    type InConnPending = In::ConnPending;
    type InConnState = In::ConnState;
    type InEndpoint = In::Endpoint;
    type InPrin = In::Prin;
    type InSessionNegoError = In::SessionNegoError;
    type InSessionStartError = In::SessionStartError;
    type InShutdownNego = In::ShutdownNego;
    type InShutdownNegoError = In::ShutdownNegoError;
    type InShutdownParam = In::ShutdownParam;
    type InShutdownPending = In::ShutdownPending;
    type InShutdownStartError = In::ShutdownStartError;
    type InShutdownValue = In::ShutdownValue;
    type Inbound = In;
    type OutAuthCreateError = Out::AuthCreateError;
    type OutAuthN = Out::AuthN;
    type OutAuthNConfig = Out::AuthNConfig;
    type OutAuthNPending = Out::AuthNPending;
    type OutAuthNSession = Out::AuthNSession;
    type OutAuthNegoError = Out::AuthNegoError;
    type OutAuthStartError = Out::AuthStartError;
    type OutChannel = Out::Channel;
    type OutConfig = <Out::Channel as NearChannelCreateWithEndpoint>::Config;
    type OutConn = Out::Conn;
    type OutConnPending = Out::ConnPending;
    type OutConnState = Out::ConnState;
    type OutCreateError =
        <Out::Channel as NearChannelCreateWithEndpoint>::CreateError;
    type OutEndpoint = Out::Endpoint;
    type OutParam = <Out::Channel as NearChannelCreateWithEndpoint>::Param;
    type OutPrin = Out::Prin;
    type OutSessionNegoError = Out::SessionNegoError;
    type OutSessionStartError = Out::SessionStartError;
    type OutShutdownNego = Out::ShutdownNego;
    type OutShutdownNegoError = Out::ShutdownNegoError;
    type OutShutdownParam = Out::ShutdownParam;
    type OutShutdownPending = Out::ShutdownPending;
    type OutShutdownStartError = Out::ShutdownStartError;
    type OutShutdownValue = Out::ShutdownValue;
    type Outbound = Out;
}
