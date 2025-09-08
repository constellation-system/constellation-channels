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

//! Abstractions for connectionless, datagram-like channels.
//!
//! Far-link channels are an abstraction for communications over
//! channels that may be unstable, high- or variable-latency,
//! low-bandwidth, high-loss, or intermittently-connected, where
//! stream-based abstractions are unlikely to perform well.  The TCP
//! protocol is therefore assumed not to work well, but the UDP
//! protocol is an acceptable model.  Far-link channels are more
//! compatible with covert communications, though such functionality
//! is not provided by this module.
//!
//! # Channel Abstraction
//!
//! "Channels", as they are presented here, are an abstraction that
//! removes much of the complexity of managing communications.  Unlike
//! near-link channels, however, the nature of far-link channels
//! precludes an interface as simple as near-link channels (see
//! [FarChannel] for details).
//!
//! Channels are intended to operate as a base layer for the more
//! general reactive streams paradigm.  The intended use pattern is to
//! attach a codec to the underlying bytestreams provided by the
//! channel, which creates a typed stream.  This is then ultimately
//! connected to a protocol state machine, which reads incoming
//! protocol traffic and generates responses.
//!
//! Far-link channels are connectionless and present a datagram
//! abstraction, similar to UDP or a Unix domain datagram socket.
//! Unlike near-link channels, far-link channels *do* expose the issue
//! of address multiplexing, as this requires knowledge of the
//! protocol level to handle completely.  The far-link abstraction is
//! designed for a peer-to-peer network, and does not have a clear
//! separation into client and server roles.  It can be used for
//! implementing these roles, however.
//!
//! ## Programming Interfaces
//!
//! The basic channel interface is given by [FarChannel].  Channels
//! are created using the [new](FarChannelCreate::new) function, which
//! takes a configuration object as its argument.  Examples of these
//! can be found in the [config](crate::config) module.  Once a
//! channel is set up, the [acquire](FarChannel::acquire) function is
//! used to conduct any initial negotiations (as with SOCKS5) and
//! obtain information specifying the creation of one or more sockets.
//! Raw sockets can be obtained through the
//! [socket](FarChannelSocket::socket) function, though for more common use,
//! [owned_flows](FarChannelOwnedFlows) or
//! [borrowed_flows](FarChannelBorrowFlows) will be used to obtain a
//! traffic splitter instance.
//!
//! This more complex workflow is a consequence of the nature of
//! far-links, and the operating demands of various protocols.  See
//! [FarChannel] for more discussion.
//!
//! ### Traffic Flows
//!
//! As far-link channels are connectionless, traffic on a socket must
//! be split out into separate traffic flows for each peer, which then
//! may need to conduct protocol negotiations of their own.  This is
//! accomplished through two separate APIs, both of which allow for
//! traffic flows (represented by the [Flow](crate::far::flows::Flow)
//! trait) with a single endpoint to be created.  Both sub-traits have
//! similar behavior, but represent different usage patterns:
//!
//! - The borrowed flows API (characterized by
//!   [BorrowedFlows](crate::far::flows::BorrowedFlows)) supports very simple
//!   implementations, and is intended for simple usage patterns, such as
//!   "one-shot" clients. Implementations generally represent a thin
//!   abstraction, do not have internal buffering, and do not support sharing.
//!
//! - The owned flows API (characterized by
//!   [OwnedFlowsInbound](crate::far::flows::OwnedFlowsInbound) and
//!   [OwnedFlowsOutbound](crate::far::flows::OwnedFlowsOutbound)) supports more
//!   complicated implementations, and is suitable for general use.
//!   Implementations support sharing and potentially inter-thread
//!   communication, and thus will generally have internal buffering and
//!   possibly synchronization of some kind. `OwnedFlows` is typically
//!   appropriate for components of larger systems, continuously-running peer
//!   services or connectors, or anything acting like a server.
//!
//! Both traits support a `listen` function, which will listen for a
//! packet and return a [Flow](crate::far::flows::Flow) corresponding
//! to the peer address that sent it, as well as a `flow` function,
//! which will obtain a `Flow` for a given peer address.
//!
//! Depending on the nature of the channels (and by extension, on the
//! traffic splitter instance obtained from it), the `listen` and
//! `flow` functions may also conduct underlying protocol negotations
//! (as with DTLS).  In general, `OwnedFlows` instances will block and
//! retry any failed negotation attempts, whereas `BorrowedFlows`
//! instances will only make one attempt, and will return an error if
//! it fails (this is a consequence of the Rust type system's
//! restrictions on owned vs. mutable borrowed types).
//!
//! See [flows] for more information on specific traffic splitter
//! implementations.
//!
//! # Channel Types
//!
//! This module provides a number of channel types.  the following is
//! a summary of the different channel types:
//!
//! - Unix domain datagram sockets: provided by
//!   [UnixFarChannel](crate::far::unix::UnixFarChannel)
//!
//! - UDP sockets: provided by [UDPFarChannel](crate::far::udp::UDPFarChannel)
//!
//! - Datagram Transport-Layer Security (DTLS) sessions: provided by
//!   [DTLSFarChannel](crate::far::dtls::DTLSFarChannel)
//!
//! - SOCKS5 proxied channels: provided by
//!   [SOCKS5FarChannel](crate::far::socks5::SOCKS5FarChannel)
//!
//! Each of these channel types has a corresponding configuration
//! structure in [config](crate::config).
//!
//! Some of these channel types (DTLS and SOCKS5) are constructed out
//! of other channels.  These channels use type parameters to
//! determine the underlying channel type.  Relatively simple
//! applications can use these directly; applications that need more
//! versatility and support for complex arrangements should use the
//! compound channels provided by this module.
//!
//! ## Authentication
//!
//! Generally speaking, the only viable option for authenticated
//! far-link channels comes from
//! [DTLSFarChannel](crate::far::dtls::DTLSFarChannel), through its
//! PKI mechanism.  The nature of UDP traffic makes it very easy to
//! spoof, and also makes it difficult to implement ordinary
//! authentication protocols.  Unlike with near-links, GSSAPI is not
//! supported for far-link channels for this reason.

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::net::SocketAddr;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::retry::RetryResult;
use constellation_common::sched::SelectError;
use mio::Registry;
use mio::Token;
use mio::event::Source;

use crate::addrs::SocketAddrPolicy;
use crate::config::FlowsConfig;
use crate::config::ResolverConfig;
use crate::far::flows::BufferedFlow;
use crate::far::flows::Flow;
use crate::far::flows::Flows;
#[cfg(feature = "socks5")]
use crate::resolve::cache::NSNameCachesCtx;
use crate::resolve::Resolver;
use crate::unix::UnixSocketPath;

pub mod channels;
pub mod compound;
#[cfg(feature = "dtls")]
pub mod dtls;
pub mod flows;
//pub mod registry;
#[cfg(feature = "socks5")]
pub mod socks5;
pub mod udp;
#[cfg(feature = "unix")]
pub mod unix;

/// Helper trait for wrapping resolved [SocketAddr]s to produce
/// channel-specific `Resolved` values.
pub trait FarChannelAcquired {
    /// Type of resolved values.
    ///
    /// This will be aligned to [Param](FarChannelSocket::Param).
    type Resolved;
    /// Type of errors that can occur when wrapping a resolved [SocketAddr].
    type WrapError: Display + ScopedError;

    /// Wrap a resolved [SocketAddr] to produce a
    /// [Resolved](FarChannelAcquired::Resolved) value.
    fn wrap(
        &self,
        resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError>;
}

/// Helper trait for converting [Acquired](FarChannel::Acquired) types
/// to [Param](FarChannelSocket::Param)s.
pub trait FarChannelAcquiredResolve: FarChannelAcquired {
    /// Type of errors that can occur when obtaining a resolver.
    type ResolverError: Display + ScopedError;

    /// Get the method by which to produce
    /// [Resolved](FarChannelAcquired::Resolved) values.
    fn resolver<Ctx>(
        &self,
        caches: &mut Ctx,
        addr_policy: &SocketAddrPolicy,
        resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, Self::ResolverError>
    where
        Ctx: NSNameCachesCtx;
}

/// Interface for far-link channels.
///
/// This trait provides the basic functionality for far-link channels.
/// Unlike near-link channels, far-link channels do not have a clear
/// separation between client and server roles, and thus this trait
/// represents something more akin to a "peer" role.  This is
/// primarily due to the fact that unlike near-link channels, far-link
/// channels do not have an inherent notion of a "connection".  This
/// results in a more complicated workflow for use than for near-link
/// channels.
///
/// # Operating Demands
///
/// Far-link channels are based on connectionless datagram protocols,
/// which result in a very different set of demands and a more complex
/// model of behavior than for near-link channels.  The following is a
/// summary of the key demands on this workflow:
///
/// * In general, any multiplexing of different possible addresses (as with IPv4
///   and IPv6 addresses for the same machine, or with DNS names that result in
///   multiple addresses) must take place at the *protocol* level.  This is a
///   key difference between far- and near-link channels: as far-links are
///   connectionless, it is *not* an option to simply go with the first address
///   at which a successful connection can be established.
///
/// * All channel types will need to be configured as part of their creation
///   process.  This may involve loading information from files, or validating
///   state, as with DTLS channels.  This should create a durable channel object
///   that allows any subsequent steps to be repeated without reloading and
///   validation.
///
/// * In general, *all* channel instances need to be given a binding address.
///   More specifically, Unix datagram sockets must always be given a path, or
///   else it will be impossible to send any reply to them.
///
/// * SOCKS5 channels require an initial, out-of-band negotiation step to be
///   completed in order to establish the UDP association.  This must be done
///   before sockets are created.
///
/// * The result of the initial negotiation step may mandate the creation of
///   *several* concrete sockets, or a dynamic set of them.  For example, SOCKS5
///   negotiations may result in a DNS name as the address to which forwarded
///   UDP packets are to be sent, which can specify multiple concrete IP
///   addresses that change over time (see [Resolver].
///
/// * In some cases (such as SOCKS5), *all* traffic will need to be transformed,
///   including wrapping packets and changing the destination address.  In other
///   cases (such as DTLS), these transforms will need to take place separately
///   for each traffic flow.
///
/// * The base-level socket types (UDP and Unix domain sockets) may receive
///   packets from multiple sources.  In most cases, this will need to be split
///   into distinct "flows" for each peer.
///
/// * DTLS sessions must be negotiated separately for each flow, once a flow has
///   been established.
///
/// These demands give rise to a more complex workflow, which is
/// represented in the API for this interface.
///
/// # Workflow
///
/// The following is a summary of the process for creating and using a
/// `FarChannel` instance.
///
/// 1. The channel is created with the [new](FarChannelCreate::new) function.
///    This takes both a [Config](FarChannelCreate::Config) and a binding
///    address.
///
/// 2. The acquisition phase is executed in order to perform any precursor
///    out-of-band negotiation requried to set up the channel. This will return
///    an [Acquired](FarChannel::Acquired) result.
///
/// 3. The upstream user of the channel uses the
///    [Acquired](FarChannel::Acquired) result to create one or more
///    [Param](FarChannelSocket::Param) values, which represent information for
///    creating sockets and/or flows.  This is external to the channel, and may
///    use functionality such as [Resolver].
///
/// 4. Each [Param](FarChannelSocket::Param) value is used to create a traffic
///    flow instance using the [owned_flows](FarChannelOwnedFlows::owned_flows)
///    or [borrowed_flows](FarChannelBorrowFlows::borrowed_flows) functionss. In
///    most cases, obtaining `Flows` in this way will be the preferable option.
///
/// 5. If [borrowed_flows](FarChannelBorrowFlows::borrowed_flows) or
///    [borrowed_flows](FarChannelOwnedFlows::owned_flows) is used, traffic will
///    be split into distinct flows using the borrowed or owned flows APIs (see
///    [flows]).  This may involve session negotiations once a flow is
///    established.
pub trait FarChannel: Sized {
    /// The result of the acquisition phase.
    ///
    /// This will be processed by the channel's upstream user to
    /// create one or more [Param](FarChannelSocket::Param)s.
    type Acquired;
    /// Type of negotiation state.
    type State;
    /// Type of errors that can occur in the acquisition phase.
    type AcquireError: Display + ScopedError;
    /// Errors that can occur during negotiations.
    type NegotiateError: Debug + Display;
    type NegotiatePending;

    /// Perform the acquisition phase of establishing the channel.
    ///
    /// Where appropriate, this will perform any out-of-band
    /// negotiation necessary to establish the channel, and return the
    /// information resulting from this process.  This information
    /// will then be used to produce one or more
    /// [Param](FarChannelSocket::Param)s for use in the
    /// [socket](FarChannelSocket::socket) and flows steps.
    ///
    /// In the SOCKS5 channel implementation, this step performs the
    /// SOCKS5 negotiation necessary to establish the UDP association.
    /// As SOCKS5 negotiation can return a DNS name (which may result
    /// in multiple actual IP addresses), the result of this phase may
    /// result in *multiple* distinct `Param` values for creating
    /// sockets.
    ///
    /// In channel types that do not have an initial negotiation step,
    /// this will simply create a socket and return it.
    fn acquire(
        &mut self,
        registry: &Registry,
    ) -> Result<RetryResult<Self::State>, Self::AcquireError>;

    /// Perform negotiations.
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError>;

    /// Complete a failed negotiation.
    fn complete_negotiate(
        &self,
        err: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError>;

    #[cfg(feature = "socks5")]
    /// Obtain the address to use in the SOCKS5 target field.
    ///
    /// This should only be overridden for UDP sockets.
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error>;
}

pub trait FarChannelSocket: Sized {
    /// Type of parameters used to create sockets.
    type Param;
    /// Type of basic sockets created by the channel.
    type Socket: Receiver + Sender + Socket + Source;
    /// Type of errors that can occur in socket creation.
    type SocketError: Display + ScopedError;
    /// Create a basic socket.
    ///
    /// This will create a socket from a [Param](Self::Param).  In
    /// general, this socket will receive traffic from multiple
    /// sources, and thus cannot directly implement the
    /// [Read](std::io::Read) and [Write](std::io::Write) traits.  In
    /// most use cases, it is preferable to use the
    /// [borrowed_flows](FarChannelBorrowFlows::borrowed_flows) or
    /// [owned_flows](FarChannelOwnedFlows::owned_flows) function, as
    /// this provides the ability to split traffic into separate flows
    /// that do implement `Read` and `Write`.
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError>;
}

/// Subtrait for creating [FarChannel]s from configuration parameters.
pub trait FarChannelCreate: FarChannel {
    /// Configuration information used to create the channel.
    type Config;
    /// Type of errors that can occur in channel creation.
    type CreateError: Display + ScopedError;

    /// Create an instance of this `FarChannel`.
    ///
    /// This creates an instance of this `FarChannel` from the
    /// configuration given by `config`, which binds to the address
    /// given by `bind`.
    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token>;
}

pub trait FarChannelXfrm<Xfrm, InnerXfrm>: FarChannelSocket
where
    Xfrm: DatagramXfrm,
    <Self::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    InnerXfrm: DatagramXfrm {
    /// Type of errors that can be returned from
    /// [wrap_xfrm](FarChannelXfrm::wrap_xfrm).
    type XfrmError: Display + ScopedError;

    /// Create an instance of
    /// [Xfrm](FarChannelXfrm::Xfrm) from `xfrm`.
    ///
    /// This should wrap the type `InnerXfrm` to obtain an instance
    /// of `Xfrm`.  If `Xfrm` is the same as `InnerXfrm`,
    /// this can be a simple passthrough function.
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: InnerXfrm
    ) -> Result<Xfrm, Self::XfrmError>;
}

/// Trait for [FarChannel]s that can construct
/// [BorrowedFlows](crate::far::flows::BorrowedFlows) instances.
///
/// This trait represents channels that can construct a traffic
/// splitter instance around a socket created by the channel.  The
/// type of the traffic splitter is given by `F`, though the exact
/// type of [Flow](crate::far::flows::Flow) instances the resulting
/// `F` instance will produce depends on the [BorrowedFlowNegotiator]
/// type [Nego](FarChannelBorrowFlows::Nego) that is defined in this
/// trait.
///
/// # Usage
///
/// The [owned_flows](FarChannelBorrowFlows::borrowed_flows) function
/// is called to obtain a traffic splitter instance of type `F`,
/// created from a socket obtained from the implementing channel.
/// Once this is done, the
/// [BorrowedFlows](crate::far::flows::BorrowedFlows) trait's API can
/// be used to obtain individual [Flow](crate::far::flows::Flow)s
///
/// # Implementation
///
/// Channels should generally implement both this trait as well as
/// [FarChannelOwnedFlows].  See [flows] for details on the
/// differences between the two traits.
///
/// Most implementations will only need to provide the
/// [Nego](FarChannelBorrowFlows::Nego) type definition; the default
/// implementation of [owned_flows](FarChannelBorrowFlows::borrowed_flows)
/// shoul be sufficient for all purposes.
pub trait FarChannelFlows<Xfrm, InnerXfrm>: FarChannelXfrm<Xfrm, InnerXfrm>
where
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<<Self::Socket as Socket>::Addr>,
    <Self::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <<Self::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Display,
    InnerXfrm: DatagramXfrm {
    type Flow: Flow;
    type InboundNego: NegotiatorStart<
        Self::Flow,
        BufferedFlow<Self::Socket, Xfrm>
    >;
    type OutboundNego: NegotiatorStart<
        Self::Flow,
        BufferedFlow<Self::Socket, Xfrm>
    >;
    type InboundNegoError: Display + ScopedError;
    type OutboundNegoError: Display + ScopedError;

    /// Create a negotiator for establishing a traffic splitter instance.
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError>;

    /// Create a negotiator for establishing a traffic splitter instance.
    fn outbound_negotiator(
        &self
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError>;

    /// Create a traffic splitter instance around a socket created by
    /// this channel.
    ///
    /// This will create an instance of the type `F`, using a socket
    /// created from `param`.  Once created, the flows structure can
    /// be used to split traffic into distinct traffic
    /// [Flow](crate::far::flows::Flow)s for each peer address.
    fn flows(
        &self,
        config: FlowsConfig,
        param: Self::Param,
        xfrm: InnerXfrm,
    ) -> Result<
        Flows<Self::Flow, Self::Socket, Self::InboundNego,
              Self::OutboundNego, Xfrm>,
        FarChannelFlowsError<
            Self::SocketError,
            Self::XfrmError,
            Self::InboundNegoError,
            Self::OutboundNegoError
        >
    > {
        let socket = self
            .socket(&param)
            .map_err(|e| FarChannelFlowsError::Socket { socket: e })?;
        let xfrm = self
            .wrap_xfrm(param, xfrm)
            .map_err(|e| FarChannelFlowsError::Xfrm { xfrm: e })?;
        let inbound_nego = self.inbound_negotiator()
            .map_err(|e| FarChannelFlowsError::InboundNego { err: e })?;
        let outbound_nego = self.outbound_negotiator()
            .map_err(|e| FarChannelFlowsError::OutboundNego { err: e })?;

        Ok(Flows::create(config, socket, inbound_nego, outbound_nego, xfrm))
    }
}

/// Result from [resolver](FarChannelAcquiredResolve::resolver).
pub enum AcquiredResolver<Resolved> {
    /// A dynamic set of addresses that must be acquired using a
    /// [Resolver].
    Resolve {
        /// [Resolver] to use to acquire addresses.
        resolver: Resolver<SocketAddr>
    },
    /// A static set of socket parameters that does not change with time.
    StaticMulti {
        /// Static parameters.
        params: Vec<Resolved>
    },
    /// A single socket parameter that does not change with time.
    StaticSingle {
        /// Static parameter.
        param: Resolved
    }
}

/// Common error to be produced for [wrap](FarChannelAcquired::wrap)
/// for all types that only have static resolution.
#[derive(Debug)]
pub enum AcquiredResolveStaticError {
    /// Does not have dynamic resolution.
    Static
}

/// Multiplexer for errors that can occur when creating a
/// traffic splitter instance.
#[derive(Debug)]
pub enum FarChannelFlowsError<Socket, Xfrm, InboundNego, OutboundNego> {
    /// Error occurred while wrapping the inner [DatagramXfrm] instance.
    Xfrm {
        /// The error occurred while wrapping the inner
        /// [DatagramXfrm] instance.
        xfrm: Xfrm
    },
    /// Error occurred while obtaining the socket.
    Socket {
        /// The error that occurred while obtaining the socket.
        socket: Socket
    },
    /// Error occurred creating the outbound negotiator.
    OutboundNego {
        /// The error that occurred creating the outbound negotiator.
        err: OutboundNego
    },
    /// Error occurred creating the inbound negotiator.
    InboundNego {
        /// The error that occurred creating the inbound negotiator.
        err: InboundNego
    }

}

impl ScopedError for AcquiredResolveStaticError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            AcquiredResolveStaticError::Static => ErrorScope::Unrecoverable
        }
    }
}

impl FarChannelAcquired for SocketAddr {
    type Resolved = SocketAddr;
    type WrapError = AcquiredResolveStaticError;

    #[inline]
    fn wrap(
        &self,
        _resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError> {
        Err(AcquiredResolveStaticError::Static)
    }
}

impl FarChannelAcquiredResolve for SocketAddr {
    type ResolverError = SelectError;

    #[inline]
    fn resolver<Ctx>(
        &self,
        _caches: &mut Ctx,
        addr_policy: &SocketAddrPolicy,
        _resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, SelectError>
    where
        Ctx: NSNameCachesCtx {
        if addr_policy.check_ip(&self.ip()) {
            Ok(AcquiredResolver::StaticSingle { param: *self })
        } else {
            Err(SelectError::Empty)
        }
    }
}

impl FarChannelAcquired for UnixSocketPath {
    type Resolved = UnixSocketPath;
    type WrapError = AcquiredResolveStaticError;

    #[inline]
    fn wrap(
        &self,
        _resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError> {
        Err(AcquiredResolveStaticError::Static)
    }
}

impl FarChannelAcquiredResolve for UnixSocketPath {
    type ResolverError = Infallible;

    #[inline]
    fn resolver<Ctx>(
        &self,
        _caches: &mut Ctx,
        _addr_policy: &SocketAddrPolicy,
        _resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, Infallible>
    where
        Ctx: NSNameCachesCtx {
        Ok(AcquiredResolver::StaticSingle {
            param: self.clone()
        })
    }
}

impl<Socket, Xfrm, InboundNego, OutboundNego> ScopedError
    for FarChannelFlowsError<Socket, Xfrm, InboundNego, OutboundNego>
where
    Socket: ScopedError,
    Xfrm: ScopedError,
    InboundNego: ScopedError,
    OutboundNego: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelFlowsError::Xfrm { xfrm } => xfrm.scope(),
            FarChannelFlowsError::Socket { socket } => socket.scope(),
            FarChannelFlowsError::InboundNego { err } => err.scope(),
            FarChannelFlowsError::OutboundNego { err } => err.scope()
        }
    }
}

impl<Socket, Xfrm, InboundNego, OutboundNego> Display
    for FarChannelFlowsError<Socket, Xfrm, InboundNego, OutboundNego>
where
    Xfrm: Display,
    Socket: Display,
    InboundNego: Display,
    OutboundNego: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            FarChannelFlowsError::Xfrm { xfrm } => xfrm.fmt(f),
            FarChannelFlowsError::Socket { socket } => socket.fmt(f),
            FarChannelFlowsError::InboundNego { err } => err.fmt(f),
            FarChannelFlowsError::OutboundNego { err } => err.fmt(f)
        }
    }
}

impl Display for AcquiredResolveStaticError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            AcquiredResolveStaticError::Static => {
                write!(f, "static parameter resolution only")
            }
        }
    }
}
