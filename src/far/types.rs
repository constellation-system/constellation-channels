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

use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Session;
use constellation_common::net::Socket;
use mio::event::Source;

use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::far::flows::BufferedFlow;

pub trait FlowAuthNShutdownTypes<Flow>
where Flow: Session {
    type Prin: Display;
    type AuthNSession: AuthNed<Self::Prin, Flow>;
    type AuthPending;
    type AuthStartError: Debug + Display + ScopedError;
    type AuthNegoError: Debug + Display + ScopedError;
    type AuthN: SessionAuthN<
        Flow,
        Param = (),
        AuthNSession = Self::AuthNSession,
        Pending = Self::AuthPending,
        StartError = Self::AuthStartError,
        NegotiateError = Self::AuthNegoError
    >;
    type ShutdownParam;
    type ShutdownPending;
    type ShutdownStartError: Debug + Display + ScopedError;
    type ShutdownNegoError: Debug + Display + ScopedError;
    type ShutdownNego: NegotiatorStart<
        (), Flow,
        Param = Self::ShutdownParam,
        Pending = Self::ShutdownPending,
        StartError = Self::ShutdownStartError,
        NegotiateError = Self::ShutdownNegoError
    >;
}

pub trait FlowsEntryTypes<Flow>: FlowAuthNShutdownTypes<Flow> + Sized
where Flow: Session {
    type LocalAddr: Clone + Display + From<Self::SockAddr>;
    type PeerAddr: Clone + Display + Eq + Hash;
    type SockAddr: Clone + Display
        + TryFrom<Self::LocalAddr, Error = Self::ConvertError>;
    type ConvertError: Debug + Display;
    type Sock: Source + Socket<Addr = Self::SockAddr> + Sender + Receiver;
    type Xfrm: DatagramXfrm<LocalAddr = Self::LocalAddr,
                            PeerAddr = Self::PeerAddr,
                            Error = Self::XfrmError>;
    type XfrmError: Debug + Display + ScopedError;
    type OutParam;
    type OutPending;
    type OutStartError: Debug + Display + ScopedError;
    type OutNegoError: Debug + Display + ScopedError;
    type OutboundNego: Negotiator<Flow,
                                  NegotiateError = Self::OutNegoError>
        + NegotiatorStart<Flow, BufferedFlow<Self::Sock, Self::Xfrm>,
                          Param = Self::OutParam,
                          Pending = Self::OutPending,
                          StartError = Self::OutStartError>;
    type InParam;
    type InPending;
    type InStartError: Debug + Display + ScopedError;
    type InNegoError: Debug + Display + ScopedError;
    type InboundNego: Negotiator<Flow,
                                 NegotiateError = Self::InNegoError>
        + NegotiatorStart<Flow, BufferedFlow<Self::Sock, Self::Xfrm>,
                          Param = Self::InParam,
                          Pending = Self::InPending,
                          StartError = Self::InStartError>;
}

pub trait FarChannelsTypes: FlowsEntryTypes<Self::Flow>
{
    type InnerXfrmCreateParam: Clone;
    type InnerXfrm: DatagramXfrmCreate<
        Addr = Self::ChannelParam,
        CreateParam = Self::InnerXfrmCreateParam,
        Error = Self::InnerXfrmError
    >;
    type InnerXfrmError: Debug + Display + ScopedError;
    type ResolverError: Debug + Display + ScopedError;
    type WrapError: Debug + Display + ScopedError;
    type Acquired: Clone + Eq + Hash
        + FarChannelAcquired<
            WrapError = Self::WrapError,
        > + FarChannelAcquiredResolve<
            Resolved = Self::ChannelParam,
            ResolverError = Self::ResolverError
          >;
    type Flow: Session<LocalAddr = Self::LocalAddr, PeerAddr = Self::PeerAddr>;
    type AcquirePending;
    type AcquireShutdownPending;
    type ChannelParam: Clone + Display + Eq + Hash;
    type AcquireError: Debug + Display + ScopedError;
    type AcquireNegoError: Debug + Display + ScopedError;
    type AcquireShutdownError: Debug + Display + ScopedError;
    type AcquireShutdownNegoError: Debug + Display + ScopedError;
    type InboundNegoCreateError: Debug + Display + ScopedError;
    type OutboundNegoCreateError: Debug + Display + ScopedError;
    type ShutdownNegoCreateError: Debug + Display + ScopedError;
    type XfrmCreateError: Debug + Display + ScopedError;
    type SocketError: Debug + Display + ScopedError;
    type Channel:
    FarChannel<
        Acquired = Self::Acquired,
        AcquirePending = Self::AcquirePending,
        AcquireError = Self::AcquireError,
        NegotiateError = Self::AcquireNegoError,
        ShutdownPending = Self::AcquireShutdownPending,
        ShutdownError = Self::AcquireError,
        ShutdownNegotiateError = Self::AcquireShutdownNegoError
    > + FarChannelFlows<
        Self::Xfrm, Self::InnerXfrm,
        Flow = Self::Flow,
        Param = Self::ChannelParam,
        InboundNego = Self::InboundNego,
        OutboundNego = Self::OutboundNego,
        ShutdownNego = Self::ShutdownNego,
        InboundNegoError = Self::InboundNegoCreateError,
        OutboundNegoError = Self::OutboundNegoCreateError,
        ShutdownNegoError = Self::ShutdownNegoCreateError
    > + FarChannelSocket<
        Socket = Self::Sock,
        SocketError = Self::SocketError
    > + FarChannelXfrm<
        Self::Xfrm, Self::InnerXfrm,
        XfrmError = Self::XfrmCreateError
    >

        + FarChannelCreate;
}

#[derive(Clone, Debug)]
pub struct CompoundFarChannelsTypes;
