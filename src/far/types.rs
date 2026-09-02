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

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::net::SocketAddr;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_common::codec::Decoder;
use constellation_common::codec::Encoder;
use constellation_common::config::Create;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Session;
use constellation_common::net::Socket;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::channels::ChannelParam;
use constellation_streams::threads::types::DatagramDispatchTypes;
use constellation_streams::threads::types::DatagramMulticastPollTypes;
use constellation_streams::threads::types::DatagramSelectorPollTypes;
use constellation_streams::threads::types::LargeObjDispatchTypes;
use constellation_streams::threads::types::LargeObjMulticastPollTypes;
use constellation_streams::threads::types::LargeObjSelectorPollTypes;
use mio::event::Source;

use crate::config::CompoundFarChannelConfig;
use crate::config::CompoundXfrmCreateParam;
use crate::config::CompoundFarChannelXfrmPeerAddr;
use crate::config::CompoundOutboundNegotiatorParam;
use crate::config::FarChannelsConfig;
use crate::far::AcquiredResolveStaticError;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelFlowsError;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::far::channels::AcquiredEntryCreateError;
use crate::far::channels::ChannelEntryCreateError;
use crate::far::channels::FarChannels;
use crate::far::channels::FarChannelsCreateError;
use crate::far::compound::CompoundAcquiredShutdownNegotiatePending;
use crate::far::compound::CompoundFarChannel;
use crate::far::compound::CompoundFarChannelAcquireError;
use crate::far::compound::CompoundFarChannelAcquireNegoError;
use crate::far::compound::CompoundFarChannelAcquireNegoPending;
use crate::far::compound::CompoundFarChannelAcquired;
use crate::far::compound::CompoundFarChannelAcquiredResolverError;
use crate::far::compound::CompoundFarChannelAddr;
use crate::far::compound::CompoundFarChannelCreateError;
use crate::far::compound::CompoundFarChannelParam;
use crate::far::compound::CompoundFarChannelShutdownAcquiredError;
use crate::far::compound::CompoundFarChannelShutdownAcquiredNegoError;
use crate::far::compound::CompoundFarChannelSocket;
use crate::far::compound::CompoundFarChannelSocketError;
use crate::far::compound::CompoundFarChannelXfrm;
use crate::far::compound::CompoundFarChannelXfrmError;
use crate::far::compound::CompoundFarChannelXfrmWrapError;
use crate::far::compound::CompoundFlow;
use crate::far::compound::CompoundInboundNegoError;
use crate::far::compound::CompoundInboundNegotiator;
use crate::far::compound::CompoundInboundNegotiatorPending;
use crate::far::compound::CompoundNegotiateError;
use crate::far::compound::CompoundNegotiatorStartError;
use crate::far::compound::CompoundOutboundNegoError;
use crate::far::compound::CompoundOutboundNegotiator;
use crate::far::compound::CompoundOutboundNegotiatorPending;
use crate::far::compound::CompoundShutdownError;
use crate::far::compound::CompoundShutdownNegotiator;
use crate::far::compound::CompoundShutdownNegotiatorPending;
use crate::far::flows::BufferedFlow;

pub trait FlowAuthNShutdownTypes<Flow>
where
    Flow: Session + Read + Write {
    type AuthConfig: Clone;
    type Prin: Display;
    type AuthNSession: AuthNed<Self::Prin, Flow>;
    type AuthPending;
    type AuthCreateError: Debug + Display;
    type AuthStartError: Debug + Display + ScopedError;
    type AuthNegoError: Debug + Display + ScopedError;
    type AuthN: SessionAuthN<
            Flow,
            Param = (),
            AuthNSession = Self::AuthNSession,
            Pending = Self::AuthPending,
            StartError = Self::AuthStartError,
            NegotiateError = Self::AuthNegoError
        > + Create<Config = Self::AuthConfig, CreateError = Self::AuthCreateError>;
    type ShutdownParam: Clone + Default;
    type ShutdownPending;
    type ShutdownStartError: Debug + Display + ScopedError;
    type ShutdownNegoError: Debug + Display + ScopedError;
    type ShutdownNego: NegotiatorStart<
            (),
            Flow,
            Param = Self::ShutdownParam,
            Pending = Self::ShutdownPending,
            StartError = Self::ShutdownStartError,
            NegotiateError = Self::ShutdownNegoError
        >;
}

pub trait FlowsEntryTypes<Flow>: FlowAuthNShutdownTypes<Flow> + Sized
where
    Flow: Session + Read + Write {
    type Wrapper;
    type OutMsg;
    type DecoderConfig: Clone + Default;
    type DecoderCreateError: Debug + Display + ScopedError;
    type Decoder: Decoder<Self::Wrapper>
        + Create<Config = Self::DecoderConfig,
                 CreateError = Self::DecoderCreateError>;
    type EncoderConfig: Clone + Default;
    type EncoderCreateError: Debug + Display + ScopedError;
    type Encoder: Encoder<Self::OutMsg>
        + Create<Config = Self::EncoderConfig,
                 CreateError = Self::EncoderCreateError>;
    type LocalAddr: Clone + Display + From<Self::SockAddr>;
    type PeerAddr: Clone + Debug + Display + Eq + Hash;
    type SockAddr: Clone
        + Display
        + TryFrom<Self::LocalAddr, Error = Self::ConvertError>;
    type ChannelParam: Clone
        + Display
        + Eq
        + Hash
        + ChannelParam<Self::PeerAddr>;
    type ConvertError: Debug + Display;
    type Sock: Source + Socket<Addr = Self::SockAddr> + Sender + Receiver;
    type Xfrm: DatagramXfrm<
            LocalAddr = Self::LocalAddr,
            PeerAddr = Self::PeerAddr,
            Error = Self::XfrmError
        >;
    type XfrmError: Debug + Display + ScopedError;
    type OutParam;
    type OutPending;
    type OutStartError: Debug + Display + ScopedError;
    type OutNegoError: Debug + Display + ScopedError;
    type OutboundNego: Negotiator<Flow, NegotiateError = Self::OutNegoError>
        + NegotiatorStart<
            Flow,
            BufferedFlow<Self::Sock, Self::Xfrm>,
            Param = Self::OutParam,
            Pending = Self::OutPending,
            StartError = Self::OutStartError
        >;
    type InParam;
    type InPending;
    type InStartError: Debug + Display + ScopedError;
    type InNegoError: Debug + Display + ScopedError;
    type InboundNego: Negotiator<Flow, NegotiateError = Self::InNegoError>
        + NegotiatorStart<
            Flow,
            BufferedFlow<Self::Sock, Self::Xfrm>,
            Param = Self::InParam,
            Pending = Self::InPending,
            StartError = Self::InStartError
        >;
}

pub trait FarChannelsTypes: FlowsEntryTypes<Self::Flow> {
    type Config;
    type CreateError: Debug + Display + ScopedError;
    type InnerXfrmCreateParam: Clone + Default;
    type InnerXfrm: DatagramXfrmCreate<
            Addr = Self::ChannelParam,
            CreateParam = Self::InnerXfrmCreateParam,
            Error = Self::InnerXfrmError
        >;
    type InnerXfrmError: Debug + Display + ScopedError;
    type ResolverError: Debug + Display + ScopedError;
    type WrapError: Debug + Display + ScopedError;
    type Acquired: FarChannelAcquired<WrapError = Self::WrapError>
        + FarChannelAcquiredResolve<
            Resolved = Self::ChannelParam,
            ResolverError = Self::ResolverError
        >;
    type Flow: Session<LocalAddr = Self::LocalAddr, PeerAddr = Self::PeerAddr>
        + Read
        + Write;
    type AcquirePending;
    type AcquireShutdownPending;
    type AcquireError: Debug + Display + ScopedError;
    type AcquireNegoError: Debug + Display + ScopedError;
    type AcquireShutdownError: Debug + Display + ScopedError;
    type AcquireShutdownNegoError: Debug + Display + ScopedError;
    type InboundNegoCreateError: Debug + Display + ScopedError;
    type OutboundNegoCreateError: Debug + Display + ScopedError;
    type ShutdownNegoCreateError: Debug + Display + ScopedError;
    type XfrmCreateError: Debug + Display + ScopedError;
    type SocketError: Debug + Display + ScopedError;
    type Channel: FarChannel<
            Acquired = Self::Acquired,
            AcquirePending = Self::AcquirePending,
            AcquireError = Self::AcquireError,
            NegotiateError = Self::AcquireNegoError,
            ShutdownPending = Self::AcquireShutdownPending,
            ShutdownError = Self::AcquireShutdownError,
            ShutdownNegotiateError = Self::AcquireShutdownNegoError
        > + FarChannelFlows<
            Self::Xfrm,
            Self::InnerXfrm,
            Flow = Self::Flow,
            Param = Self::ChannelParam,
            InboundNego = Self::InboundNego,
            OutboundNego = Self::OutboundNego,
            ShutdownNego = Self::ShutdownNego,
            InboundNegoError = Self::InboundNegoCreateError,
            OutboundNegoError = Self::OutboundNegoCreateError,
            ShutdownNegoError = Self::ShutdownNegoCreateError
        > + FarChannelSocket<Socket = Self::Sock, SocketError = Self::SocketError>
        + FarChannelXfrm<
            Self::Xfrm,
            Self::InnerXfrm,
            XfrmError = Self::XfrmCreateError
        > + FarChannelCreate<Config = Self::Config, CreateError = Self::CreateError>;
}

#[derive(Debug)]
pub struct CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
    outmsg: PhantomData<OutMsg>,
    enc: PhantomData<Enc>,
    wrapper: PhantomData<Wrapper>,
    dec: PhantomData<Dec>,
    authn: PhantomData<AuthN>,
    unix: PhantomData<Unix>,
    udp: PhantomData<UDP>
}

pub type FarChannelsDatagramSelectorPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Types,
    Ctx
> =
    DatagramSelectorPollTypes<
        InMsg,
        OutMsg,
        Wrapper,
        MsgAuth,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        Msgs,
        Recv,
        Ctx
    >;

pub type CompoundFarChannelsDatagramSelectorPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    MsgAuth,
    Unix,
    UDP,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Ctx
> = FarChannelsDatagramSelectorPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    Ctx
>;

pub type FarChannelsLargeObjSelectorPollTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    Types,
    LargeObjTypes,
    Ctx
> =
    LargeObjSelectorPollTypes<
        InMsg,
        OutMsg,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        LargeObjTypes,
        Ctx
    >;

pub type CompoundFarChannelsLargeObjSelectorPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    Unix,
    UDP,
    Epochs,
    Resolve,
    LargeObjTypes,
    Ctx
> = FarChannelsLargeObjSelectorPollTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    LargeObjTypes,
    Ctx
>;

pub type FarChannelsDatagramDispatchTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Types,
    Ctx
> =
    DatagramDispatchTypes<
        InMsg,
        OutMsg,
        Wrapper,
        MsgAuth,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        Msgs,
        Recv,
        Ctx
    >;

pub type CompoundFarChannelsDatagramDispatchTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    MsgAuth,
    Unix,
    UDP,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Ctx
> = FarChannelsDatagramDispatchTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    Ctx
>;

pub type FarChannelsLargeObjDispatchTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    Types,
    LargeObjTypes,
    Ctx
> =
    LargeObjDispatchTypes<
        InMsg,
        OutMsg,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        LargeObjTypes,
        Ctx
    >;

pub type CompoundFarChannelsLargeObjDispatchTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    Unix,
    UDP,
    Epochs,
    Resolve,
    LargeObjTypes,
    Ctx
> = FarChannelsLargeObjDispatchTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    LargeObjTypes,
    Ctx
>;

pub type FarChannelsDatagramMulticastPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Types,
    Ctx
> =
    DatagramMulticastPollTypes<
        InMsg,
        OutMsg,
        Wrapper,
        MsgAuth,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        Msgs,
        Recv,
        Ctx
    >;

pub type CompoundFarChannelsDatagramMulticastPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    MsgAuth,
    Unix,
    UDP,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    Ctx
> = FarChannelsDatagramMulticastPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    MsgAuth,
    Epochs,
    Resolve,
    Msgs,
    Recv,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    Ctx
>;

pub type FarChannelsLargeObjMulticastPollTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    Types,
    LargeObjTypes,
    Ctx
> =
    LargeObjMulticastPollTypes<
        InMsg,
        OutMsg,
        Epochs,
        FarChannels<Types>,
        FarChannelsConfig<
            <Types as FarChannelsTypes>::Config,
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthConfig,
            <Types as FarChannelsTypes>::InnerXfrmCreateParam,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::EncoderConfig,
            <Types as FlowsEntryTypes<
                <Types as FarChannelsTypes>::Flow
            >>::DecoderConfig,
        >,
        FarChannelsCreateError<
            <Types as FlowAuthNShutdownTypes<
                <Types as FarChannelsTypes>::Flow
            >>::AuthCreateError,
            <Types as FarChannelsTypes>::CreateError,
            ChannelEntryCreateError<
                <Types as FarChannelsTypes>::AcquireError,
                <Types as FarChannelsTypes>::ShutdownNegoCreateError,
                <Types as FarChannelsTypes>::AcquireNegoError,
                AcquiredEntryCreateError<
                    <Types as FarChannelsTypes>::ResolverError,
                    FarChannelFlowsError<
                        <Types as FarChannelsTypes>::SocketError,
                        <Types as FarChannelsTypes>::XfrmCreateError,
                        <Types as FarChannelsTypes>::InboundNegoCreateError,
                        <Types as FarChannelsTypes>::OutboundNegoCreateError
                    >,
                    <Types as FarChannelsTypes>::WrapError
                >
            >
        >,
        <Types as FarChannelsTypes>::Flow,
        Resolve,
        LargeObjTypes,
        Ctx
    >;

pub type CompoundFarChannelsLargeObjMulticastPollTypes<
    InMsg,
    OutMsg,
    Wrapper,
    Enc,
    Dec,
    SessAuthN,
    Unix,
    UDP,
    Epochs,
    Resolve,
    LargeObjTypes,
    Ctx
> = FarChannelsLargeObjMulticastPollTypes<
    InMsg,
    OutMsg,
    Epochs,
    Resolve,
    CompoundFarChannelsTypes<SessAuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>,
    LargeObjTypes,
    Ctx
>;

impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec> Clone
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
    #[inline]
    fn clone(&self) -> Self {
        CompoundFarChannelsTypes {
            outmsg: self.outmsg,
            wrapper: self.wrapper,
            enc: self.enc,
            dec: self.dec,
            authn: self.authn,
            unix: self.unix,
            udp: self.udp
        }
    }
}

unsafe impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec> Send
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
}

unsafe impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec> Sync
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
}

impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
    FlowAuthNShutdownTypes<CompoundFlow<Unix, UDP>>
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
    type AuthConfig = AuthN::Config;
    type AuthCreateError = AuthN::CreateError;
    type AuthN = AuthN;
    type AuthNSession = AuthN::AuthNSession;
    type AuthNegoError = AuthN::NegotiateError;
    type AuthPending = AuthN::Pending;
    type AuthStartError = AuthN::StartError;
    type Prin = AuthN::Prin;
    type ShutdownNego = CompoundShutdownNegotiator<Unix, UDP>;
    type ShutdownNegoError = CompoundShutdownError;
    type ShutdownParam = ();
    type ShutdownPending = CompoundShutdownNegotiatorPending<Unix, UDP>;
    type ShutdownStartError = CompoundNegotiatorStartError;
}

impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
    FlowsEntryTypes<CompoundFlow<Unix, UDP>>
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
    type OutMsg = OutMsg;
    type Wrapper = Wrapper;
    type DecoderConfig = <Dec as Create>::Config;
    type DecoderCreateError = <Dec as Create>::CreateError;
    type Decoder = Dec;
    type EncoderConfig = <Enc as Create>::Config;
    type EncoderCreateError = <Enc as Create>::CreateError;
    type Encoder = Enc;
    type ChannelParam = CompoundFarChannelParam;
    type ConvertError = Infallible;
    type InNegoError = CompoundNegotiateError;
    type InParam = ();
    type InPending = CompoundInboundNegotiatorPending<Unix, UDP>;
    type InStartError = CompoundNegotiatorStartError;
    type InboundNego = CompoundInboundNegotiator;
    type LocalAddr = CompoundFarChannelAddr;
    type OutNegoError = CompoundNegotiateError;
    type OutParam = CompoundOutboundNegotiatorParam;
    type OutPending = CompoundOutboundNegotiatorPending<Unix, UDP>;
    type OutStartError = CompoundNegotiatorStartError;
    type OutboundNego = CompoundOutboundNegotiator;
    type PeerAddr = CompoundFarChannelXfrmPeerAddr;
    type Sock = CompoundFarChannelSocket;
    type SockAddr = CompoundFarChannelAddr;
    type Xfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type XfrmError = CompoundFarChannelXfrmWrapError<Unix::Error, UDP::Error>;
}

impl<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec> FarChannelsTypes
    for CompoundFarChannelsTypes<AuthN, Unix, UDP, OutMsg, Wrapper, Enc, Dec>
where
    Dec: Decoder<Wrapper> + Create,
    Dec::Config: Clone + Default,
    Dec::CreateError: Debug + Display + ScopedError,
    Enc: Encoder<OutMsg> + Create,
    Enc::Config: Clone + Default,
    Enc::CreateError: Debug + Display + ScopedError,
    AuthN: Create + SessionAuthN<CompoundFlow<Unix, UDP>, Param = ()>,
    AuthN::Config: Clone,
    AuthN::NegotiateError: ScopedError,
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>,
    Unix::CreateParam: Clone + Default,
    UDP::CreateParam: Clone + Default,
    Unix::Error: ScopedError,
    UDP::Error: ScopedError {
    type AcquireError = CompoundFarChannelAcquireError;
    type AcquireNegoError = CompoundFarChannelAcquireNegoError;
    type AcquirePending = CompoundFarChannelAcquireNegoPending;
    type AcquireShutdownError = CompoundFarChannelShutdownAcquiredError;
    type AcquireShutdownNegoError = CompoundFarChannelShutdownAcquiredNegoError;
    type AcquireShutdownPending = CompoundAcquiredShutdownNegotiatePending;
    type Acquired = CompoundFarChannelAcquired;
    type Channel = CompoundFarChannel;
    type Config = CompoundFarChannelConfig;
    type CreateError = CompoundFarChannelCreateError;
    type Flow = CompoundFlow<Unix, UDP>;
    type InboundNegoCreateError = CompoundInboundNegoError;
    type InnerXfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type InnerXfrmCreateParam =
        CompoundXfrmCreateParam<Unix::CreateParam, UDP::CreateParam>;
    type InnerXfrmError =
        CompoundFarChannelXfrmWrapError<Unix::Error, UDP::Error>;
    type OutboundNegoCreateError = CompoundOutboundNegoError;
    type ResolverError = CompoundFarChannelAcquiredResolverError;
    type ShutdownNegoCreateError = Infallible;
    type SocketError = CompoundFarChannelSocketError;
    type WrapError = AcquiredResolveStaticError;
    type XfrmCreateError = CompoundFarChannelXfrmError;
}
