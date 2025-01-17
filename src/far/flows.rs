// Copyright © 2024 The Johns Hopkins Applied Physics Laboratory LLC.
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

//! Traffic flow multiplexers.
//!
//! Far-link channels are connectionless, and may send and receive
//! traffic from multiple peers on a single socket.  Moreover, some
//! [FarChannel] implementations support session protocol negotiations
//! with peers (such as with DTLS).  This requires a mechanism for
//! splitting out traffic flows with individual peers and managing
//! them as separate entities.  This functionality is provided by the
//! [Flows] trait and its implementations in this module.
//!
//! # Usage
//!
//! The two primary traits in the module are [Flows] and [Flow].
//! `Flow` represents an individual traffic flow, and implementations
//! must also provide [Read] and [Write] implementations.  [Flows] can
//! be thought of as an abstraction over a socket, and can be used to
//! obtain individual [Flow]s for each peer.
//!
//! ## Obtaining [Flow]s from [Flows]
//!
//! [Flows] instances should also provide implementations of one of
//! two sub-traits: [OwnedFlows] and [BorrowedFlows].  Both sub-traits
//! provide two functions: [flow](OwnedFlows::flow) and
//! [listen](OwnedFlowsListener::listen).
//!
//! Users can obtain a flow for a given peer from an address using
//! `flow`.  This is typically used to establish a client or
//! peer-to-peer flow with a known endpoint.
//!
//! Additionally, users can obtain inbound flows from arbitrary peers
//! using `listen`.  This is typically used in a server-type use case.
//!
//! ## Borrowed vs. Owned Flows
//!
//! Implementors of the [Flows] trait also provide an implementation
//! of one of two sub-traits: [BorrowedFlows] and [OwnedFlows].  Both
//! sub-traits support the [listen](OwnedFlowsListener::listen) and
//! [flow](OwnedFlows::flow) functions, but behave differently with
//! respect to lifetime semantics:
//!
//! - [BorrowedFlows] assumes that individual [Flow]s represent a mutable borrow
//!   of the parent `Flows` object.  In general, this means that only one `Flow`
//!   can exist at any given time.  This supports very simple implementations,
//!   and is intended for simple usage patterns, such as "one-shot" clients.
//!   Implementations generally represent a thin abstraction, do not have
//!   internal buffering, and do not support sharing.
//!
//! - [OwnedFlows] assumes that individual [Flow]s represent owned objects,
//!   separate from their parent `Flows`.  This supports more complicated
//!   implementations, and is suitable for general use. Implementations support
//!   sharing and potentially inter-thread communication, and thus will
//!   generally have internal buffering and possibly synchronization of some
//!   kind.  `OwnedFlows` is typically appropriate for components of larger
//!   systems, continuously-running peer services or connectors, or anything
//!   acting like a server.
//!
//! ## Creating [Flows]
//!
//! [Flows] instances are obtained from [FarChannel]s directly,
//! through the
//! [owned_flows](crate::far::FarChannelOwnedFlows::owned_flows) and
//! [borrowed_flows](crate::far::FarChannelBorrowFlows::borrowed_flows)
//! functions, depending on whether the specific `Flows` instance
//! implements [OwnedFlows] or [BorrowedFlows].
//!
//! # Implementations
//!
//! This module provides several implementations of [Flows], each with
//! a different intended usage pattern:
//!
//! - [SingleFlow] is intended for uses where a channel will only *ever* be used
//!   to talk to a single peer.  It implements [BorrowedFlows], and will discard
//!   any traffic from any peer other than its intended target.  This is
//!   primarily intended for very simple "one-shot" clients.
//!
//! - [MultiFlows] is intended for uses where a channel may talk to multiple
//!   peers, but will only every talk to a single peer at a given time.  It
//!   implements [BorrowedFlows], and its [Flow] instance will discard traffic
//!   from any source other than its current peer.  As only one `Flow` may exist
//!   at a time, this precludes users from communicating with multiple peers at
//!   once. This is primarily intended for clients that may dispatch
//!   transactions to multiple endpoints, and for testing.

use std::collections::hash_map::Entry;
use std::collections::hash_map::OccupiedEntry;
use std::collections::hash_map::VacantEntry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::Weak;
use std::thread::sleep;
use std::thread::spawn;
use std::thread::JoinHandle;
use std::time::Instant;

use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::SessionAuthN;
use constellation_auth::cred::Credentials;
use constellation_common::codec::DatagramCodec;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::nonblock::NonblockResult;
use constellation_common::retry::RetryResult;
use constellation_common::retry::RetryWhen;
use constellation_common::shutdown::ShutdownFlag;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::stream::ConcurrentStream;
use constellation_streams::stream::PullStreamListener;
use constellation_streams::stream::StreamID;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;

use crate::config::ThreadedFlowsParams;
use crate::far::FarChannel;

/// Trait for traffic flows from an individual peer address.
///
/// Implementors of this trait are also expected to implement [Read]
/// and [Write].
pub trait Flow: Credentials + Read + Write {
    /// The type of local addresses.
    type LocalAddr: Display;
    /// The type of peer (remote) addresses.
    type PeerAddr: Display;

    /// Get the local address for this flow.
    fn local_addr(&self) -> Result<Self::LocalAddr, Error>;

    /// Get the peer (remote) address for this flow.
    fn peer_addr(&self) -> Self::PeerAddr;
}

/// Base trait for traffic flow splitters.
///
/// Implementors of this trait are expected to also implement either
/// [OwnedFlows] or [BorrowedFlows] as appropriate.
pub trait FlowsLocalAddr<LocalAddr>: Sized {
    /// Get the local address for the underlying socket.
    fn local_addr(&self) -> Result<LocalAddr, Error>;
}

pub trait BorrowedFlowsOutbound<'a, F, PeerAddr, Prin>
where
    F: 'a + Credentials + Flow + Read + Write {
    /// Errors that can occur when obtaining flows.
    type FlowError: Display + ScopedError;

    /// Get a [Flow] instance to send messages to the peer
    /// at `addr`.
    ///
    /// This will create a [Flow] for all traffic to
    /// or from `addr`.  The `endpoint` parameter is used to indicate
    /// the original endpoint, as opposed to the concrete peer address
    /// (e.g. a DNS name that resolved to `addr`).  This is used
    /// primarily for any session negotiations, such as with DTLS.
    ///
    /// After the `Flow` is created in this way for the first time, it
    /// will receive all traffic originating from `addr`.
    ///
    /// This may also conduct session negotiations as part of the flow
    /// creation process.  In general, implementations of this method
    /// will retry failed session negotiations until they succeed,
    /// according to a [Retry](constellation_common::retry::Retry)
    /// policy provided by the channel.
    fn flow(
        &'a mut self,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<(F, Prin), Self::FlowError>;
}

pub trait BorrowedFlowsInbound<'a, F, PeerAddr, Prin>
where
    F: 'a + Credentials + Flow + Read + Write {
    /// Errors that can occur listening.
    type ListenError: Display;

    /// Listen for traffic from a new peer, and create a new flow for
    /// that peer.
    ///
    /// This is used to listen for traffic from a peer for which there
    /// does not yet exist any flow.  A new [Flow](OwnedFlows::Flow)
    /// will then be created, which will then be used to send and
    /// receive all traffic involving that peer.
    ///
    /// This may also conduct session negotiations as part of the flow
    /// creation process.  In general, implementations of this method
    /// will retry failed session negotiations until they succeed,
    /// according to a [Retry](constellation_common::retry::Retry)
    /// policy provided by the channel.
    fn listen(&'a mut self) -> Result<(F, PeerAddr, Prin), Self::ListenError>;
}

pub trait OwnedFlowsOutbound<F, PeerAddr, Prin>
where
    F: Credentials + Flow + Read + Write {
    /// Errors that can occur when obtaining flows.
    type FlowError: Display + ScopedError;

    /// Get a [Flow] instance to send messages to the peer
    /// at `addr`.
    ///
    /// This will create a [Flow] for all traffic to
    /// or from `addr`.  The `endpoint` parameter is used to indicate
    /// the original endpoint, as opposed to the concrete peer address
    /// (e.g. a DNS name that resolved to `addr`).  This is used
    /// primarily for any session negotiations, such as with DTLS.
    ///
    /// After the `Flow` is created in this way for the first time, it
    /// will receive all traffic originating from `addr`.
    ///
    /// This may also conduct session negotiations as part of the flow
    /// creation process.  In general, implementations of this method
    /// will retry failed session negotiations until they succeed,
    /// according to a [Retry](constellation_common::retry::Retry)
    /// policy provided by the channel.
    fn flow(
        &mut self,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<(F, Prin), Self::FlowError>;
}

pub trait OwnedFlowsInbound<F, PeerAddr, Prin>
where
    F: Credentials + Flow + Read + Write {
    /// Errors that can occur listening.
    type ListenError: Display;

    /// Listen for traffic from a new peer, and create a new flow for
    /// that peer.
    ///
    /// This is used to listen for traffic from a peer for which there
    /// does not yet exist any flow.  A new [Flow](OwnedFlows::Flow)
    /// will then be created, which will then be used to send and
    /// receive all traffic involving that peer.
    ///
    /// This may also conduct session negotiations as part of the flow
    /// creation process.  In general, implementations of this method
    /// will retry failed session negotiations until they succeed,
    /// according to a [Retry](constellation_common::retry::Retry)
    /// policy provided by the channel.
    fn listen(&mut self) -> Result<(F, PeerAddr, Prin), Self::ListenError>;
}

/// Trait for creating traffic flow splitters.
///
/// This is used primarily with
/// [owned_flows](crate::far::FarChannelOwnedFlows::owned_flows) and
/// [borrowed_flows](crate::far::FarChannelBorrowFlows::borrowed_flows).
/// It is not intended to be used directly.
pub trait BorrowedFlowsCreate<'a, Sock, Nego, AuthN, Xfrm>: FlowsLocalAddr<Sock::Addr>
    + BorrowedFlowsOutbound<'a, Nego::Flow<'a>, Xfrm::PeerAddr, AuthN::Prin>
    + BorrowedFlowsInbound<'a, Nego::Flow<'a>, Xfrm::PeerAddr, AuthN::Prin>
where
    Sock: Socket,
    Nego: 'a + BorrowedFlowNegotiator<Self::Flow>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    /// Type of basic [Flow]s produced by this instance.
    ///
    /// This will likely differ from the type of [Flow] produced by
    /// the [Negotiator].
    type Flow: 'a + Credentials + Flow + Read + Write;
    /// Additional parameter used to create this type.
    type CreateParam;
    /// Type of errors that can occur creating a traffic splitter.
    type CreateError: Display + ScopedError;

    /// Create a traffic flow splitter around a socket.
    ///
    /// This will create an instance of this flow splitter around
    /// `socket`, using the additional parameter `param`.
    fn create(
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError>;
}

/// Trait for creating [OwnedFlows] from a configuration object.
pub trait OwnedFlowsCreate<Sock, Nego, AuthN, Xfrm>: FlowsLocalAddr<Sock::Addr>
    + OwnedFlowsOutbound<Nego::Flow, Xfrm::PeerAddr, AuthN::Prin>
    + OwnedFlowsInbound<Nego::Flow, Xfrm::PeerAddr, AuthN::Prin>
where
    Sock: Socket,
    Nego: OwnedFlowNegotiator<Self::Flow>,
    AuthN: SessionAuthN<Nego::Flow>,
    Xfrm: DatagramXfrm {
    /// Type of basic [Flow]s produced by this instance.
    ///
    /// This will likely differ from the type of [Flow] produced by
    /// the [Negotiator].
    type Flow: Credentials + Flow + Read + Write;
    /// Channel identifier for the created [Flows].
    type ChannelID: Clone + Display + Eq + Hash;
    type CreateParam;
    /// Errors that can occur when creating this type.
    type CreateError: Display + ScopedError;
    type Reporter;

    /// Create a traffic flow splitter around a socket.
    ///
    /// This will create an instance of this flow splitter around
    /// `socket`, using the additional parameter `param`.  The
    /// splitter will attach itself to `listener`, and will report all
    /// incoming flows there.
    fn create_with_reporter(
        id: Self::ChannelID,
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        reporter: Self::Reporter,
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError>;
}

pub trait BorrowedFlowNegotiator<Inner>: Send + Sync
where Inner: Credentials + Flow + Read + Write {
    /// Resulting [Flow] type.
    ///
    /// This may differ from `Inner`, which is the type of flows used
    /// to do the negotiation.
    type Flow<'a>: Credentials + Flow + Read + Write + Send
    where Self: 'a;
    /// errors that can occur during negotiations.
    type NegotiateError: Display;

    fn negotiate_outbound(
        &mut self,
        inner: Inner,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;

    /// Negotiate an inbound session.
    ///
    /// This may block for a a long time; users should generally use
    /// [negotiate_nonblock](Negotiator::negotiate_nonblock)
    /// to try to negotiate without blocking, then set up the
    /// necessary machinery to handle a potentially stalled
    /// negotiation before calling this function.
    fn negotiate_inbound(
        &mut self,
        inner: Inner,
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;
}

/// Trait for session negotiators for [OwnedFlows].
///
/// This allows the details of session negotiation to be abstracted
/// over.
pub trait OwnedFlowNegotiator<Inner>: Send + Sync
where Inner: Credentials + Flow + Read + Write {
    /// Resulting [Flow] type.
    ///
    /// This may differ from `Inner`, which is the type of flows used
    /// to do the negotiation.
    type Flow: Credentials + Flow + Read + Write + Send;
    /// errors that can occur during negotiations.
    type NegotiateError: Display;

    fn negotiate_outbound_nonblock(
        &mut self,
        inner: Inner,
    ) -> Result<NonblockResult<Self::Flow, Inner>, Self::NegotiateError>;

    fn negotiate_outbound(
        &mut self,
        inner: Inner,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;

    /// Attempt to negotiate an inbound session without blocking.
    ///
    /// This means that no additional messages need to be sent.  This
    /// will return a [NonblockResult] indicating success or failure;
    /// if failure is indicated, then
    /// [negotiate](Negotiator::negotiate) should be called
    /// with the same parameters.
    ///
    /// Errors returned indicate "hard" errors.
    fn negotiate_inbound_nonblock(
        &mut self,
        inner: Inner,
    ) -> Result<NonblockResult<Self::Flow, Inner>, Self::NegotiateError>;

    /// Negotiate an inbound session.
    ///
    /// This may block for a a long time; users should generally use
    /// [negotiate_nonblock](Negotiator::negotiate_nonblock)
    /// to try to negotiate without blocking, then set up the
    /// necessary machinery to handle a potentially stalled
    /// negotiation before calling this function.
    fn negotiate_inbound(
        &mut self,
        inner: Inner,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;
}

/// Retry information for [Negotiator].
pub struct NegotiateRetry<Flow> {
    when: Instant,
    flow: Flow
}

/// A simple [BorrowedFlows] instance that communicates only with a
/// single peer.
///
/// This functions as its own [Flow](BorrowedFlows::Flow) instance,
/// and communicates exclusively with one peer.  Any traffic from
/// another peer will be dropped.
pub struct SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    /// The underlying socket.
    socket: Sock,
    /// Authenticator to use.
    authn: AuthN,
    /// Negotiator to use.
    nego: Nego,
    /// The channel context.
    xfrm: Xfrm,
    /// The peer address.
    addr: Xfrm::PeerAddr
}

/// A [BorrowedFlows] instance that communicates with one peer at a
/// time.
///
/// This creates [MultiFlow]s, which permit communication with a
/// single peer at a time.
pub struct MultiFlows<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    /// The underlying socket.
    socket: Sock,
    /// Authenticator to use.
    authn: AuthN,
    /// Negotiator to use.
    nego: Nego,
    /// The channel context.
    xfrm: Xfrm,
}

/// Individual traffic flows associated with [MultiFlows].
///
/// This will communicate exclusively with one peer, until incoming
/// traffic from another peer is detected, at which point the [Read]
/// functions will fail with an error.  Under some conditions, traffic
/// from another peer may be dropped.
pub struct MultiFlow<'a, Sock: Socket, Xfrm: DatagramXfrm> {
    socket: &'a mut Sock,
    xfrm: &'a mut Xfrm,
    addr: Xfrm::PeerAddr
}

/// An [OwnedFlows] instance based on threading.
pub struct ThreadedFlows<Sock, AuthN, Nego, Xfrm, ChannelID>
where
    Sock: Socket,
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    ChannelID: Clone + Display + Eq + Hash + Send {
    /// Inner structure.
    inner: Arc<ThreadedFlowsInner<Sock, AuthN, Nego, Xfrm, ChannelID>>
}

/// An [OwnedFlowsListener] instance based on threading.
pub struct ThreadedFlowsListener<ID, Prin, Flow>
where
    Prin: Clone + Display + Eq + Hash,
    ID: Clone + Display + Eq + Hash {
    /// Receiver for the backlog queue.
    backlog_recv: Arc<Mutex<mpsc::Receiver<(ID, Prin, Flow)>>>
}

/// A [PullStreamListener] instance based on an [OwnedFlowsListener].
pub struct ThreadedFlowsPullStreamListener<Msg, Codec, ID, Prin, Flow>
where
    Codec: Clone + DatagramCodec<Msg>,
    Flow: Credentials + Read + Write,
    Prin: Clone + Display + Eq + Hash,
    ID: Clone + Display + Eq + Hash,
    [(); Codec::MAX_BYTES]: {
    msg: PhantomData<Msg>,
    codec: Codec,
    inner: ThreadedFlowsListener<ID, Prin, Flow>
}

/// A reporter for [ThreadedFlows].
///
/// This is used to report newly-created flows, which will then be
/// received by a corresponding listener.
pub struct ThreadedFlowsReporter<ID, Prin, Flow> {
    /// Sender for the backlog queue.
    backlog_send: mpsc::Sender<(ID, Prin, Flow)>
}

#[derive(Clone)]
struct ThreadedFlowEntry {
    /// Send half of the message buffer.
    send: mpsc::Sender<Vec<u8>>,
    /// Condition variable used to signal readiness.
    cond: Weak<Condvar>
}

struct ThreadedFlowsInner<Sock, AuthN, Nego, Xfrm, ChannelID>
where
    Sock: Socket,
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    ChannelID: Clone + Display + Eq + Hash + Send {
    id: PhantomData<ChannelID>,
    nego: Nego,
    authn: AuthN,
    /// Join handle for the listener thread.
    listener: Option<JoinHandle<()>>,
    /// Flag to indicate whether the listener should shut down.
    shutdown: ShutdownFlag,
    /// Socket from which to read messages.
    socket: Arc<Sock>,
    /// Xfrm used to unwrap messages.
    xfrm: Arc<Mutex<Xfrm>>,
    /// Table holding existing flows.
    flows: Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry>>>,
    /// Table of negotiator threads.
    // ISSUE #9: this should eventually get replaced with some kind of
    // thread pool mechanism.
    negotiators:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>>
}

struct ThreadedFlowsAuthNThread<Flow, AuthN, Addr, Param, ID>
where
    Flow: Credentials + Read + Write,
    AuthN: SessionAuthN<Flow>,
    Param: Clone + Display + Send,
    Addr: Clone + Display + Send,
    ID: Clone + Display + Eq + Hash + Send {
    /// Authenticator to use.
    authn: AuthN,
    /// Flow to use for authentication.
    flow: Flow,
    /// Sender for the backlog queue.  This should only be used by
    /// listener threads.
    backlog_send: mpsc::Sender<(StreamID<Addr, ID, Param>, AuthN::Prin, Flow)>,
    /// ID of the channel for which this is being negotiated.
    id: StreamID<Addr, ID, Param>,
    /// Whether the negotiator is still live.
    shutdown: ShutdownFlag,
    /// Table of all pending negotiators
    negotiators: Arc<Mutex<HashMap<Addr, ThreadedFlowsNegotiateEntry>>>
}

/// Thread information to use to negotiate an individual session.
struct ThreadedFlowsNegotiateThread<Sock, AuthN, Xfrm, Nego, Param, ChannelID>
where
    AuthN: SessionAuthN<Nego::Flow>,
    Sock: Socket,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    ChannelID: Clone + Display + Eq + Hash + Send {
    authn: AuthN,
    /// Sender for the backlog queue.  This should only be used by
    /// listener threads.
    backlog_send: mpsc::Sender<(
        StreamID<Xfrm::PeerAddr, ChannelID, Param>,
        AuthN::Prin,
        Nego::Flow
    )>,
    /// Underlying flow to use for negotiations.
    flow: ThreadedFlow<Sock, Xfrm>,
    /// ID of the channel for which this is being negotiated.
    id: StreamID<Xfrm::PeerAddr, ChannelID, Param>,
    /// Whether the negotiator is still live.
    shutdown: ShutdownFlag,
    /// Negotiator for new flows.
    negotiator: Nego,
    /// Table of all pending negotiators
    negotiators:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>>
}

struct ThreadedFlowsNegotiateEntry {
    shutdown: ShutdownFlag,
    join: JoinHandle<()>
}

struct ThreadedFlowsListenThread<Sock, AuthN, Xfrm, Nego, Param, ChannelID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow>,
    Sock: Socket,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    ChannelID: Clone + Display + Eq + Hash + Send {
    /// Maximum size of messages.
    msgsize: usize,
    /// Channel ID.
    channel: ChannelID,
    /// Parameters used to create the [Flows].
    param: Param,
    /// Socket from which to read messages.
    socket: Arc<Sock>,
    /// Flag to indicate whether the listener should shut down.
    shutdown: ShutdownFlag,
    /// Xfrm used to unwrap messages.
    xfrm: Arc<Mutex<Xfrm>>,
    /// Authenticator to use for new sessions.
    authn: AuthN,
    /// Sender for the backlog queue.  This should only be used by
    /// listener threads.
    backlog_send: mpsc::Sender<(
        StreamID<Xfrm::PeerAddr, ChannelID, Param>,
        AuthN::Prin,
        Nego::Flow
    )>,
    /// Table holding existing flows.
    flows: Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry>>>,
    /// Negotiator for new flows.
    negotiator: Nego,
    /// Table of negotiator threads.
    negotiators:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>>
}

/// A [Flow] instance created by [ThreadedFlows].
pub struct ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Sock: Socket {
    /// Peer address.
    addr: Xfrm::PeerAddr,
    /// Xfrm used to unwrap messages.
    xfrm: Arc<Mutex<Xfrm>>,
    /// Socket used to send messages.
    socket: Arc<Sock>,
    /// Strong reference to the consumer half of the message buffer.
    buf: mpsc::Receiver<Vec<u8>>,
    /// Condition variable used to signal readiness.
    cond: Arc<Condvar>
}

/// An [Negotiator] instance that simply passes the
/// underlying [OwnedFlows] instance through.
///
/// This is used for channel types that do not need to perform any
/// actual negotiation.
#[derive(Clone, Default)]
pub struct PassthruNegotiator;

/// Errors that can occur for [flow](OwnedFlows::flow) for
/// [ThreadedFlows].
#[derive(Clone, Debug)]
pub enum ThreadedFlowsFlowError {
    /// The flow for this address has already been taken.
    Taken,
    /// Mutex was poisoned.
    MutexPoison
}

/// Errors that can occur for [listen](OwnedFlowsListener::listen) for
/// [ThreadedFlows].
pub enum ThreadedFlowsListenError {
    /// Listener thread was shut down.
    Shutdown,
    /// Mutex was poisoned.
    MutexPoison
}

impl ScopedError for ThreadedFlowsFlowError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ThreadedFlowsFlowError::Taken => ErrorScope::Unrecoverable,
            ThreadedFlowsFlowError::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

impl<Flow> RetryWhen for NegotiateRetry<Flow> {
    #[inline]
    fn when(&self) -> Instant {
        self.when
    }
}

impl<Flow> NegotiateRetry<Flow> {
    #[inline]
    pub fn new(
        flow: Flow,
        when: Instant
    ) -> Self {
        NegotiateRetry {
            flow: flow,
            when: when
        }
    }

    #[inline]
    pub fn take(self) -> (Flow, Instant) {
        (self.flow, self.when)
    }
}

impl<F> OwnedFlowNegotiator<F> for PassthruNegotiator
where
    F: Flow + Send,
{
    type Flow = F;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate_outbound_nonblock(
        &mut self,
        inner: F,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        Ok(NonblockResult::Success(inner))
    }

    #[inline]
    fn negotiate_outbound(
        &mut self,
        inner: F,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Self::Flow>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }

    #[inline]
    fn negotiate_inbound_nonblock(
        &mut self,
        inner: F,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        Ok(NonblockResult::Success(inner))
    }

    #[inline]
    fn negotiate_inbound(
        &mut self,
        inner: F,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Self::Flow>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }
}

impl<F> BorrowedFlowNegotiator<F> for PassthruNegotiator
where
    F: Flow,
{
    type Flow = F;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate_outbound(
        &mut self,
        inner: F,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Self::Flow>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }

    #[inline]
    fn negotiate_inbound(
        &mut self,
        inner: F,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Self::Flow>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }
}

impl<Flow, AuthN, Addr, Param, ID>
    ThreadedFlowsAuthNThread<Flow, AuthN, Addr, Param, ID>
where
    Flow: Credentials + Read + Write,
    AuthN: SessionAuthN<Flow>,
    Param: Clone + Display + Send,
    Addr: Clone + Display + Eq + Hash + Send,
    ID: Clone + Display + Eq + Hash + Send
{
    fn authn(
        id: &StreamID<Addr, ID, Param>,
        authn: AuthN,
        shutdown: ShutdownFlag,
        mut flow: Flow,
        backlog_send: mpsc::Sender<(
            StreamID<Addr, ID, Param>,
            AuthN::Prin,
            Flow
        )>
    ) -> Result<(), Error> {
        if shutdown.is_live() {
            trace!(target: "flows-threaded-authn",
                   "trying authentication for {}",
                   id);

            // The negotiation succeeded; do authentication.
            match authn.session_authn(&mut flow) {
                Ok(AuthNResult::Accept(prin)) => {
                    info!(target: "flows-threaded-authn",
                          "stream {} authenticated as {}",
                          id, prin);

                    // Add it to the backlog.
                    backlog_send.send((id.clone(), prin, flow)).map_err(|_| {
                        Error::new(ErrorKind::Other, "listen channel closed")
                    })
                }
                Ok(AuthNResult::Reject) => {
                    info!(target: "flows-threaded-authn",
                          "stream {} failed authentication",
                          id);

                    Ok(())
                }
                Err(err) => {
                    error!(target: "flows-threaded-authn",
                           "error during authentication: {}",
                           err);

                    Err(Error::new(ErrorKind::Other, "error in authentication"))
                }
            }
        } else {
            Ok(())
        }
    }

    fn run(self) {
        let ThreadedFlowsAuthNThread {
            id,
            flow,
            authn,
            shutdown,
            backlog_send,
            negotiators
        } = self;

        debug!(target: "flows-threaded-authn",
               "threaded flows authenticator for {} starting",
               id);

        if let Err(err) = Self::authn(&id, authn, shutdown, flow, backlog_send)
        {
            error!(target: "flows-threaded-negotiate",
                   "threaded flows negotiator for {} failed with error: {}",
                   id, err);
        } else {
            debug!(target: "flows-threaded-negotiate",
                   "threaded flows negotiator for {} exiting",
                   id);
        }

        // Remove ourselves from the negotiator pool.
        match negotiators.lock() {
            Ok(mut guard) => {
                trace!(target: "flows-threaded-negotiate",
                       "removing negotiator for {}",
                       id);

                guard.remove(id.party_addr());
            }
            Err(_) => {
                error!(target: "flows-threaded-negotiate",
                       "mutex poisoned");
            }
        };
    }
}

impl<Sock, AuthN, Xfrm, Nego, Param, ID>
    ThreadedFlowsNegotiateThread<Sock, AuthN, Xfrm, Nego, Param, ID>
where
    AuthN: SessionAuthN<Nego::Flow>,
    Sock: Socket,
    Param: Clone + Display + Eq + Hash + Send,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    ID: Clone + Display + Eq + Hash + Send
{
    fn negotiate(
        id: &StreamID<Xfrm::PeerAddr, ID, Param>,
        authn: AuthN,
        mut negotiator: Nego,
        shutdown: ShutdownFlag,
        flow: ThreadedFlow<Sock, Xfrm>,
        backlog_send: mpsc::Sender<(
            StreamID<Xfrm::PeerAddr, ID, Param>,
            AuthN::Prin,
            Nego::Flow
        )>
    ) -> Result<(), Error> {
        if shutdown.is_live() {
            trace!(target: "flows-threaded-negotiate",
                   "trying negotiatons for {}",
                   id);

            match negotiator.negotiate_inbound(flow) {
                // Negotiation successful.
                Ok(RetryResult::Success(flow)) => {
                    trace!(target: "flows-threaded-negotiate",
                           "negotiatons for {} successful",
                           id);

                    ThreadedFlowsAuthNThread::authn(
                        id,
                        authn,
                        shutdown,
                        flow,
                        backlog_send
                    )
                }
                // Wait and retry.
                Ok(RetryResult::Retry(retry)) => {
                    let (flow, when) = retry.take();
                    let now = Instant::now();
                    let duration = when - now;

                    if now < when {
                        trace!(target: "flows-threaded-negotiate",
                               "retrying negotiatons for {} in {}.{:03}s",
                               id, duration.as_secs(),
                               duration.subsec_millis());

                        sleep(duration);
                    }

                    Self::negotiate(
                        id,
                        authn,
                        negotiator,
                        shutdown,
                        flow,
                        backlog_send
                    )
                }
                Err(err) => {
                    error!(target: "flows-threaded-negotiate",
                           "error negotiating session: {}",
                           err);

                    Err(Error::new(
                        ErrorKind::Other,
                        "unrecoverable error negotiating session"
                    ))
                }
            }
        } else {
            Ok(())
        }
    }

    fn run(self) {
        let ThreadedFlowsNegotiateThread {
            backlog_send,
            authn,
            flow,
            id,
            shutdown,
            negotiator,
            negotiators
        } = self;

        debug!(target: "flows-threaded-negotiate",
               "threaded flows negotiator for {} starting",
               id);

        if let Err(err) = Self::negotiate(
            &id,
            authn,
            negotiator,
            shutdown,
            flow,
            backlog_send
        ) {
            error!(target: "flows-threaded-negotiate",
                   "threaded flows negotiator for {} failed with error: {}",
                   id, err);
        } else {
            debug!(target: "flows-threaded-negotiate",
                   "threaded flows negotiator for {} exiting",
                   id);
        }

        // Remove ourselves from the negotiator pool.
        match negotiators.lock() {
            Ok(mut guard) => {
                trace!(target: "flows-threaded-negotiate",
                       "removing negotiator for {}",
                       id);

                guard.remove(id.party_addr());
            }
            Err(_) => {
                error!(target: "flows-threaded-negotiate",
                       "mutex poisoned");
            }
        };
    }
}

impl<Sock, AuthN, Xfrm, Nego, Param, ID>
    ThreadedFlowsListenThread<Sock, AuthN, Xfrm, Nego, Param, ID>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send,
    AuthN::Prin: 'static + Send,
    Xfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + Send,
    Xfrm::PeerAddr: 'static + Eq + Hash,
    Sock: 'static + Socket,
    Param: Clone + Display + Eq + Hash + Send,
    Nego: 'static
        + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>
        + Clone
        + Send
        + Sync,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    fn negotiate(
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            StreamID<Xfrm::PeerAddr, ID, Param>,
            AuthN::Prin,
            Nego::Flow
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        flow: ThreadedFlow<Sock, Xfrm>,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr
    ) -> Result<(), Error> {
        debug!(target: "flows-threaded-listen",
               "negotiating new session");

        match negotiator.negotiate_inbound_nonblock(flow) {
            // Nonblocking negotiation succeeded.
            Ok(NonblockResult::Success(mut flow)) => {
                trace!(target: "flows-threaded-listen",
                       "session negotiation did not require blocking");

                let id =
                    StreamID::new(addr.clone(), channel.clone(), param.clone());

                match authn.session_authn_nonblock(&mut flow) {
                    Ok(NonblockResult::Success(AuthNResult::Accept(prin))) => {
                        info!(target: "far-channel-registry",
                              "stream {} authenticated as {}",
                              id, prin);

                        // Add it to the backlog.
                        backlog_send.send((id.clone(), prin, flow)).map_err(
                            |_| {
                                Error::new(
                                    ErrorKind::Other,
                                    "listen channel closed"
                                )
                            }
                        )
                    }
                    Ok(NonblockResult::Success(AuthNResult::Reject)) => {
                        info!(target: "far-channel-registry",
                              "stream {} failed authentication",
                              id);

                        Ok(())
                    }
                    Ok(NonblockResult::Fail(())) => {
                        trace!(target: "flows-threaded-listen",
                               "session authentication requires blocking");

                        let shutdown = ShutdownFlag::new();
                        let thread = ThreadedFlowsAuthNThread {
                            backlog_send: backlog_send.clone(),
                            negotiators: negotiators.clone(),
                            authn: authn.clone(),
                            id: id,
                            shutdown: shutdown.clone(),
                            flow: flow
                        };
                        let mut guard = negotiators.lock().map_err(|_| {
                            Error::new(ErrorKind::Other, "mutex poisoned")
                        })?;

                        debug!(target: "flows-threaded-listen",
                               "launching authenticator thread");

                        let join = spawn(|| thread.run());
                        let entry = ThreadedFlowsNegotiateEntry {
                            shutdown: shutdown,
                            join: join
                        };

                        guard.insert(addr.clone(), entry);

                        Ok(())
                    }
                    Err(err) => {
                        error!(target: "flows-threaded-negotiate",
                               "error during authentication: {}",
                               err);

                        Err(Error::new(
                            ErrorKind::Other,
                            "error in authentication"
                        ))
                    }
                }
            }
            // We need to block.
            Ok(NonblockResult::Fail(flow)) => {
                trace!(target: "flows-threaded-listen",
                       "session negotiation requires blocking");

                let shutdown = ShutdownFlag::new();
                let id =
                    StreamID::new(addr.clone(), channel.clone(), param.clone());
                let thread = ThreadedFlowsNegotiateThread {
                    backlog_send: backlog_send.clone(),
                    negotiators: negotiators.clone(),
                    negotiator: negotiator.clone(),
                    authn: authn.clone(),
                    id: id,
                    shutdown: shutdown.clone(),
                    flow: flow
                };
                let mut guard = negotiators.lock().map_err(|_| {
                    Error::new(ErrorKind::Other, "mutex poisoned")
                })?;

                debug!(target: "flows-threaded-listen",
                       "launching negotiator thread");

                let join = spawn(|| thread.run());
                let entry = ThreadedFlowsNegotiateEntry {
                    shutdown: shutdown,
                    join: join
                };

                guard.insert(addr.clone(), entry);

                Ok(())
            }
            Err(err) => {
                error!(target: "flows-threaded-listen",
                   "error negotiating session: {}", err);

                Err(Error::new(
                    ErrorKind::Other,
                    "unrecoverable error negotiating session"
                ))
            }
        }
    }

    fn create_flow(
        socket: &Arc<Sock>,
        xfrm: &Arc<Mutex<Xfrm>>,
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            StreamID<Xfrm::PeerAddr, ID, Param>,
            AuthN::Prin,
            Nego::Flow
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        ent: VacantEntry<Xfrm::PeerAddr, ThreadedFlowEntry>,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        msg: Vec<u8>
    ) -> Result<(), Error> {
        let (send, recv) = mpsc::channel();
        let cond = Arc::new(Condvar::new());

        trace!(target: "flows-threaded-listen",
               "buffering {} bytes to {}",
               msg.len(), addr);

        // Deliver the first message.
        send.send(msg).map_err(|_| {
            Error::new(ErrorKind::Other, "per-flow channel closed unexpectedly")
        })?;

        // Add it to the flows table.
        ent.insert(ThreadedFlowEntry {
            send: send,
            cond: Arc::downgrade(&cond)
        });
        let flow = ThreadedFlow {
            socket: socket.clone(),
            addr: addr.clone(),
            xfrm: xfrm.clone(),
            cond: cond,
            buf: recv
        };

        Self::negotiate(
            authn,
            backlog_send,
            negotiator,
            negotiators,
            flow,
            channel,
            param,
            addr
        )
    }

    fn replace_flow(
        socket: &Arc<Sock>,
        xfrm: &Arc<Mutex<Xfrm>>,
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            StreamID<Xfrm::PeerAddr, ID, Param>,
            AuthN::Prin,
            Nego::Flow
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        ent: &mut OccupiedEntry<Xfrm::PeerAddr, ThreadedFlowEntry>,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        msg: Vec<u8>
    ) -> Result<(), Error> {
        let (send, recv) = mpsc::channel();
        let cond = Arc::new(Condvar::new());

        trace!(target: "flows-threaded-listen",
               "buffering {} bytes to {}",
               msg.len(), addr);

        send.send(msg).map_err(|_| {
            Error::new(ErrorKind::Other, "per-flow channel closed unexpectedly")
        })?;
        ent.insert(ThreadedFlowEntry {
            send: send,
            cond: Arc::downgrade(&cond)
        });

        let flow = ThreadedFlow {
            socket: socket.clone(),
            addr: addr.clone(),
            xfrm: xfrm.clone(),
            cond: cond,
            buf: recv
        };

        Self::negotiate(
            authn,
            backlog_send,
            negotiator,
            negotiators,
            flow,
            channel,
            param,
            addr
        )
    }

    fn handle_msg(
        flows: &Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry>>>,
        socket: &Arc<Sock>,
        xfrm: &Arc<Mutex<Xfrm>>,
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            StreamID<Xfrm::PeerAddr, ID, Param>,
            AuthN::Prin,
            Nego::Flow
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        msg: Vec<u8>
    ) -> Result<(), Error> {
        trace!(target: "flows-threaded-listen",
               "checking for existing flow on {}",
               param);

        // Check if the flow already exists.
        match flows.lock() {
            Ok(mut guard) => match guard.entry(addr.clone()) {
                Entry::Occupied(mut ent) => {
                    let flow = ent.get_mut();

                    // Check if the flow has expired.
                    let msg = match flow.cond.upgrade() {
                        Some(cond) => {
                            trace!(target: "flows-threaded-listen",
                                   concat!("buffering {} bytes to ",
                                           "existing flow to {}"),
                                   msg.len(), addr);

                            // Try to deliver the message.
                            let out = match flow.send.send(msg) {
                                // Done, we're good.
                                Ok(()) => None,
                                // The per-flow send buffer
                                // closed; recreate the flow.
                                Err(mpsc::SendError(msg)) => {
                                    debug!(target: "flows-threaded-listen",
                                           concat!("send buffer to {} ",
                                                   "closed, replacing"),
                                           addr);

                                    Some(msg)
                                }
                            };

                            cond.notify_all();

                            out
                        }
                        None => {
                            // The flow has expired;
                            // create a new one.
                            trace!(target: "flows-threaded-listen",
                                   "replacing expired flow for {}",
                                   addr);

                            Some(msg)
                        }
                    };

                    match msg {
                        Some(msg) => Self::replace_flow(
                            socket,
                            xfrm,
                            authn,
                            backlog_send,
                            negotiator,
                            negotiators,
                            &mut ent,
                            channel,
                            param,
                            addr,
                            msg
                        ),
                        None => Ok(())
                    }
                }
                Entry::Vacant(ent) => {
                    // There is no existing flow, create one.
                    trace!(target: "flows-threaded-listen",
                           "creating new flow for {}",
                           addr);

                    Self::create_flow(
                        socket,
                        xfrm,
                        authn,
                        backlog_send,
                        negotiator,
                        negotiators,
                        ent,
                        channel,
                        param,
                        addr,
                        msg
                    )
                }
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "mutex poisoned"))
        }
    }

    fn run_loop(self) -> Result<(), Error> {
        let ThreadedFlowsListenThread {
            mut negotiator,
            backlog_send,
            negotiators,
            socket,
            shutdown,
            channel,
            param,
            xfrm,
            flows,
            authn,
            ..
        } = self;
        let mut valid = true;

        while shutdown.is_live() && valid {
            trace!(target: "flows-threaded-listen",
                   "listening for incoming message on {}",
                   param);

            let mut msg = vec![0; self.msgsize];
            let (n, addr) = socket.recv_from(&mut msg)?;

            if n != 0 {
                trace!(target: "flows-threaded-listen",
                       "received {} bytes from {} on {}",
                       n, addr, param);

                let (msglen, addr) = match xfrm.lock() {
                    Ok(mut guard) => {
                        guard.unwrap(&mut msg[..n], addr).map_err(|err| {
                            Error::new(ErrorKind::Other, err.to_string())
                        })
                    }
                    Err(_) => {
                        Err(Error::new(ErrorKind::Other, "mutex poisoned"))
                    }
                }?;

                trace!(target: "flows-threaded-listen",
                       "unwrapped message from {} on {} to {} bytes",
                       addr, param, msglen);

                msg.truncate(msglen);

                if let Err(err) = Self::handle_msg(
                    &flows,
                    &socket,
                    &xfrm,
                    &authn,
                    &backlog_send,
                    &mut negotiator,
                    &negotiators,
                    &channel,
                    &param,
                    &addr,
                    msg
                ) {
                    match err.scope() {
                        ErrorScope::Shutdown => {
                            debug!(target: "flows-threaded-listen",
                                   "listen thread for {} shutting down",
                                   addr);

                            valid = false;
                        }
                        ErrorScope::Retryable => {}
                        _ => {
                            valid = false;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn run(self) {
        let addr = match self.socket.local_addr() {
            Ok(addr) => addr,
            Err(err) => {
                error!(target: "flows-threaded-listen",
                       "error getting socket address: {}",
                       err);

                return;
            }
        };

        debug!(target: "flows-threaded-listen",
               "threaded flows listener for {} starting",
               addr);

        if let Err(err) = self.run_loop() {
            error!(target: "flows-threaded-listen",
                   "threaded flows listener for {} failed with error: {}",
                   addr, err);
        } else {
            debug!(target: "flows-threaded-listen",
                   "threaded flows listener for {} exiting",
                   addr);
        }
    }
}

impl<Sock, AuthN, Nego, Xfrm, ID> Clone
    for ThreadedFlows<Sock, AuthN, Nego, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlows {
            inner: self.inner.clone()
        }
    }
}

impl<Sock, AuthN, Nego, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for ThreadedFlows<Sock, AuthN, Nego, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.inner.local_addr()
    }
}

impl<Sock, AuthN, Nego, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for ThreadedFlowsInner<Sock, AuthN, Nego, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<Sock, AuthN, Nego, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for Arc<ThreadedFlowsInner<Sock, AuthN, Nego, Xfrm, ID>>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.as_ref().local_addr()
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> FlowsLocalAddr<Sock::Addr>
    for MultiFlows<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Credentials
    for SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type Cred<'b> = Xfrm::PeerAddr
    where Self: 'b;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.addr.clone()))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> FlowsLocalAddr<Sock::Addr>
    for SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsCreate<'a, Sock, Nego, AuthN, Xfrm>
    for MultiFlows<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type Flow = MultiFlow<'a, Sock, Xfrm>;
    type CreateParam = ();
    type CreateError = Infallible;

    #[inline]
    fn create(
        socket: Sock,
        authn: AuthN,
        nego: Nego,
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError> {
        Ok(MultiFlows {
            socket: socket,
            authn: authn,
            nego: nego,
            xfrm: xfrm
        })
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsCreate<'a, Sock, Nego, AuthN, Xfrm>
    for SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type Flow = MultiFlow<'a, Sock, Xfrm>;
    type CreateParam = Xfrm::PeerAddr;
    type CreateError = Infallible;

    #[inline]
    fn create(
        socket: Sock,
        authn: AuthN,
        nego: Nego,
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError> {
        Ok(SingleFlow {
            socket: socket,
            authn: authn,
            addr: param,
            nego: nego,
            xfrm: xfrm
        })
    }
}

impl<Sock, Nego, AuthN, Xfrm, InnerXfrm, ID>
    OwnedFlowsCreate<Sock, Nego, AuthN, InnerXfrm>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send,
    AuthN::Prin: 'static + Send,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    InnerXfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<
            Socket = Sock,
        >
        + Send,
    InnerXfrm::PeerAddr: 'static + Eq + Hash,
    Sock: 'static + Socket + Send,
    InnerXfrm::Param: Clone + Display + Eq + Hash + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type ChannelID = ID;
    type CreateError = InnerXfrm::ParamError;
    type CreateParam = ThreadedFlowsParams;
    type Reporter = ThreadedFlowsReporter<
        StreamID<InnerXfrm::PeerAddr, ID, InnerXfrm::Param>,
        AuthN::Prin,
        Nego::Flow
    >;

    #[inline]
    fn create_with_reporter(
        id: ID,
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        reporter: Self::Reporter,
        xfrm: InnerXfrm,
        param: ThreadedFlowsParams
    ) -> Result<Self, Self::CreateError> {
        let inner =
            Arc::<ThreadedFlowsInner<Sock, Xfrm, ID>>
            ::create_with_reporter(
                id, socket, authn, negotiator, reporter, xfrm, param
            )?;

        Ok(ThreadedFlows { inner: inner })
    }
}

impl<Sock, Nego, AuthN, Xfrm, InnerXfrm, ID>
    OwnedFlowsCreate<Sock, Nego, AuthN, InnerXfrm>
    for Arc<ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send,
    AuthN::Prin: 'static + Send,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    InnerXfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<
            Socket = Sock,
        >
        + Send,
    InnerXfrm::PeerAddr: 'static + Eq + Hash,
    Sock: 'static + Socket + Send,
    InnerXfrm::Param: Clone + Display + Eq + Hash + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type ChannelID = ID;
    type CreateError = InnerXfrm::ParamError;
    type CreateParam = ThreadedFlowsParams;
    type Reporter = ThreadedFlowsReporter<
        StreamID<InnerXfrm::PeerAddr, ID, InnerXfrm::Param>,
        AuthN::Prin,
        Nego::Flow
    >;

    #[inline]
    fn create_with_reporter(
        id: ID,
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        reporter: Self::Reporter,
        xfrm: InnerXfrm,
        param: ThreadedFlowsParams
    ) -> Result<Self, Self::CreateError> {
        let flows = match param.flows_size_hint() {
            Some(hint) => HashMap::with_capacity(hint),
            None => HashMap::new()
        };
        let channel_param = xfrm.param(&socket)?;
        // ISSUE #11: Need to manage the size of the negotiators map.
        let negotiators = Arc::new(Mutex::new(HashMap::new()));
        let xfrm = Arc::new(Mutex::new(xfrm));
        let flows = Arc::new(Mutex::new(flows));
        let socket = Arc::new(socket);
        let shutdown = ShutdownFlag::new();
        let listener: ThreadedFlowsListenThread<
            Sock,
            AuthN,
            InnerXfrm,
            Nego,
            InnerXfrm::Param,
            ID
        > = ThreadedFlowsListenThread {
            param: channel_param,
            channel: id.clone(),
            shutdown: shutdown.clone(),
            authn: authn.clone(),
            xfrm: xfrm.clone(),
            flows: flows.clone(),
            socket: socket.clone(),
            backlog_send: reporter.backlog_send.clone(),
            msgsize: param.packet_size(),
            negotiators: negotiators.clone(),
            negotiator: negotiator
        };

        let join = spawn(|| listener.run());

        Ok(Arc::new(ThreadedFlowsInner {
            id: PhantomData,
            negotiators: negotiators,
            listener: Some(join),
            shutdown: shutdown,
            xfrm: xfrm,
            flows: flows,
            socket: socket
        }))
    }
}

impl<F, Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutbound<F, Xfrm::PeerAddr, AuthN::Prin>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send,
    F: Flow
{
    type FlowError = ThreadedFlowsFlowError;

    #[inline]
    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<F, ThreadedFlowsFlowError> {
        self.inner.flow(addr, endpoint)
    }
}

impl Drop for ThreadedFlowEntry {
    fn drop(&mut self) {
        if let Some(cond) = self.cond.upgrade() {
            cond.notify_all()
        }
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> Drop
    for ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send,
{
    fn drop(&mut self) {
        // Signal to the thread that it should quit.
        self.shutdown.set();

        // Send a zero-byte message to the listener thread to break it
        // out of a listen call.
        match self.socket.local_addr() {
            Ok(addr) => {
                trace!(target: "flows-threaded",
                       "pinging listen thread for {}",
                       addr);

                if let Err(err) = self.socket.send_to(&addr, &[]) {
                    error!(target: "flows-threaded",
                           "error pinging listen thread for {}: {}",
                           addr, err);
                } else {
                    // Wait on the listener thread.
                    match self.listener.take() {
                        Some(listener) => {
                            if listener.join().is_err() {
                                error!(target: "flows-threaded",
                                       "error joining listen thread for {}",
                                       addr);
                            }
                        }
                        None => {
                            error!(target: "flows-threaded",
                                   "no join handle for {}",
                                   addr);
                        }
                    }
                }
            }
            Err(err) => {
                error!(target: "flows-threaded",
                       "error getting socket address: {}",
                       err);
            }
        }

        let stop_negotiators = match self.negotiators.lock() {
            Ok(mut negotiators) => {
                // Signal all the negotiator threads to quit.
                for (addr, entry) in negotiators.iter_mut() {
                    debug!(target: "flows-threaded-listen",
                           "signalling negotiator for {} to shut down",
                           addr);

                    entry.shutdown.set();
                }

                true
            }
            Err(_) => {
                error!(target: "flows-threaded",
                       "mutex poisoned");

                false
            }
        };

        if stop_negotiators {
            let ents = match self.negotiators.lock() {
                Ok(mut negotiators) => negotiators.drain().collect(),
                Err(_) => {
                    error!(target: "flows-threaded",
                           "mutex poisoned");

                    vec![]
                }
            };

            // Signal all the negotiator threads to quit.
            for (addr, entry) in ents {
                debug!(target: "flows-threaded-listen",
                       "waiting on negotiator for {} to shut down",
                       addr);

                if entry.join.join().is_err() {
                    error!(target: "flows-threaded",
                           "could not join negotiator thread for {}",
                           addr);
                }
            }
        }
    }
}

impl<Addr, Prin, Flow> Clone for ThreadedFlowsReporter<Addr, Prin, Flow> {
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlowsReporter {
            backlog_send: self.backlog_send.clone()
        }
    }
}

impl<Msg, Codec, Addr, Prin, Flow> PullStreamListener<Msg>
    for ThreadedFlowsPullStreamListener<Msg, Codec, Addr, Prin, Flow>
where
    Codec: Clone + DatagramCodec<Msg> + Send,
    Flow: Credentials + Read + Write + Send,
    Addr: Clone + Display + Eq + Hash,
    Prin: Clone + Display + Eq + Hash,
    Msg: Send,
    [(); Codec::MAX_BYTES]:
{
    type Addr = Addr;
    type ListenError = ThreadedFlowsListenError;
    type Prin = Prin;
    type Stream = DatagramCodecStream<Msg, Flow, Codec>;

    #[inline]
    fn listen(
        &mut self
    ) -> Result<(Self::Addr, Self::Prin, Self::Stream), Self::ListenError> {
        let (addr, prin, flow) = self.inner.listen()?;

        Ok((
            addr,
            prin,
            DatagramCodecStream::create(self.codec.clone(), flow)
        ))
    }
}

impl<Msg, Codec, Addr, Prin, Flow>
    ThreadedFlowsPullStreamListener<Msg, Codec, Addr, Prin, Flow>
where
    Codec: Clone + DatagramCodec<Msg>,
    Flow: Credentials + Read + Write,
    Addr: Clone + Display + Eq + Hash,
    Prin: Clone + Display + Eq + Hash,
    [(); Codec::MAX_BYTES]:
{
    #[inline]
    pub fn create(
        listener: ThreadedFlowsListener<Addr, Prin, Flow>,
        codec: Codec
    ) -> Self {
        ThreadedFlowsPullStreamListener {
            msg: PhantomData,
            inner: listener,
            codec: codec
        }
    }
}

impl<Msg, Codec, Addr, Prin, Flow> Clone
    for ThreadedFlowsPullStreamListener<Msg, Codec, Addr, Prin, Flow>
where
    Codec: Clone + DatagramCodec<Msg>,
    Flow: Credentials + Read + Write,
    Addr: Clone + Display + Eq + Hash,
    Prin: Clone + Display + Eq + Hash,
    [(); Codec::MAX_BYTES]:
{
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlowsPullStreamListener {
            msg: PhantomData,
            codec: self.codec.clone(),
            inner: self.inner.clone()
        }
    }
}

impl<Addr, Prin, Flow> Clone for ThreadedFlowsListener<Addr, Prin, Flow>
where
    Prin: Clone + Display + Eq + Hash,
    Addr: Clone + Display + Eq + Hash
{
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlowsListener {
            backlog_recv: self.backlog_recv.clone()
        }
    }
}

impl<Addr, Prin, Flow> ThreadedFlowsListener<Addr, Prin, Flow>
where
    Prin: Clone + Display + Eq + Hash,
    Addr: Clone + Display + Eq + Hash
{
    #[inline]
    pub fn new() -> (Self, ThreadedFlowsReporter<Addr, Prin, Flow>) {
        let (send, recv) = mpsc::channel();

        (
            ThreadedFlowsListener {
                backlog_recv: Arc::new(Mutex::new(recv))
            },
            ThreadedFlowsReporter { backlog_send: send }
        )
    }
}

impl<Addr, Prin, Flow> OwnedFlowsInbound<Flow, Addr, Prin>
    for ThreadedFlowsListener<Addr, Prin, Flow>
where
    Prin: Clone + Display + Eq + Hash,
    Addr: Clone + Display + Eq + Hash
{
    type ListenError = ThreadedFlowsListenError;

    #[inline]
    fn listen(
        &mut self
    ) -> Result<(Addr, Prin, Flow), ThreadedFlowsListenError> {
        trace!(target: "owned-flows-listener",
               "listening for incoming flow");

        match self.backlog_recv.lock() {
            Ok(guard) => {
                guard.recv().map_err(|_| ThreadedFlowsListenError::Shutdown)
            }
            Err(_) => Err(ThreadedFlowsListenError::MutexPoison)
        }
    }
}

impl<F, Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutbound<F, Xfrm::PeerAddr, AuthN::Prin>
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket,
    ID: Clone + Display + Eq + Hash + Send,
    F: Flow
{
    type FlowError = ThreadedFlowsFlowError;

    #[inline]
    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<F, ThreadedFlowsFlowError> {
        // See if a flow already exists.
        match self.flows.lock() {
            Ok(mut guard) => match guard.entry(addr.clone()) {
                // It does, but it might be a dead weak reference.
                Entry::Occupied(mut ent) => {
                    let flow = ent.get_mut();

                    // See if the weak reference is still good.
                    if flow.cond.upgrade().is_some() {
                        // If it's still good, this entry is taken.
                        trace!(target: "flows-threaded",
                               "flow already exists for {}",
                               ent.key());

                        Err(ThreadedFlowsFlowError::Taken)
                    } else {
                        // It's expired, so create a new flow.
                        trace!(target: "flows-threaded",
                               concat!("entry for {} was expired, ",
                                       "creating new flow"),
                               ent.key());

                        let (send, recv) = mpsc::channel();
                        let cond = Arc::new(Condvar::new());

                        ent.insert(ThreadedFlowEntry {
                            send: send,
                            cond: Arc::downgrade(&cond)
                        });

                        let flow = ThreadedFlow {
                            socket: self.socket.clone(),
                            xfrm: self.xfrm.clone(),
                            cond: cond.clone(),
                            addr: addr,
                            buf: recv
                        };

                        Ok(flow)
                    }
                }
                // It's empty, so create a new flow.
                Entry::Vacant(ent) => {
                    trace!(target: "flows-threaded",
                           "creating new flow for {}",
                           ent.key());

                    let (send, recv) = mpsc::channel();
                    let cond = Arc::new(Condvar::new());
                    let addr = ent.key().clone();

                    ent.insert(ThreadedFlowEntry {
                        send: send,
                        cond: Arc::downgrade(&cond)
                    });

                    let flow = ThreadedFlow {
                        socket: self.socket.clone(),
                        xfrm: self.xfrm.clone(),
                        cond: cond,
                        addr: addr,
                        buf: recv
                    };

                    Ok(flow)
                }
            },
            Err(_) => Err(ThreadedFlowsFlowError::MutexPoison)
        }
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsInbound<'a, MultiFlow<'a, Sock, Xfrm>,
                         Xfrm::PeerAddr, AuthN::Prin>
    for MultiFlows<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type ListenError = Error;

    #[inline]
    fn listen(
        &'a mut self
    ) -> Result<(Xfrm::PeerAddr, MultiFlow<'a, Sock, Xfrm>), Error>
    {
        let mtu = match self.socket.mtu() {
            Some(mtu) => mtu,
            None => {
                warn!(target: "flows-multi",
                      "could not obtain MTU, defaulting to 1536");

                1536
            }
        };
        let mut buf = vec![0; mtu];
        let (n, addr) = self.socket.peek_from(&mut buf)?;
        let (_, addr) = self
            .xfrm
            .unwrap(&mut buf[..n], addr)
            .map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;

        Ok((
            addr.clone(),
            MultiFlow {
                socket: &mut self.socket,
                addr: addr,
                xfrm: &mut self.xfrm
            }
        ))
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsOutbound<'a, MultiFlow<'a, Sock, Xfrm>,
                         Xfrm::PeerAddr, AuthN::Prin>
    for MultiFlows<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type FlowError = Infallible;

    #[inline]
    fn flow(
        &'a mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<MultiFlow<'a, Sock, Xfrm>, Infallible> {
        Ok(MultiFlow {
            socket: &mut self.socket,
            xfrm: &mut self.xfrm,
            addr: addr
        })
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsInbound<'a, MultiFlow<'a, Sock, Xfrm>,
                         Xfrm::PeerAddr, AuthN::Prin>
    for SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type ListenError = Error;

    #[inline]
    fn listen(
        &'a mut self
    ) -> Result<(Xfrm::PeerAddr, MultiFlow<'a, Sock, Xfrm>), Error>
    {
        let addr = self.addr.clone();

        Ok((addr, self))
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm>
    BorrowedFlowsOutbound<'a, MultiFlow<'a, Sock, Xfrm>,
                         Xfrm::PeerAddr, AuthN::Prin>
    for SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type FlowError = Infallible;

    #[inline]
    fn flow(
        &'a mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<MultiFlow<'a, Sock, Xfrm>, Infallible> {
        let expected = self.addr.clone();

        if expected == addr {
            Ok(self)
        } else {
            Err(expected)
        }
    }
}

impl<Sock, Xfrm> ConcurrentStream for ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket
{
    #[inline]
    fn condvar(&self) -> Arc<Condvar> {
        self.cond.clone()
    }
}

impl<Sock, Xfrm> Credentials for ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket
{
    type Cred<'b> = Xfrm::PeerAddr
    where Self: 'b;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.peer_addr()))
        } else {
            Ok(None)
        }
    }
}

impl<Sock, Xfrm> Flow for ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket
{
    type LocalAddr = Xfrm::LocalAddr;
    type PeerAddr = Xfrm::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.addr.clone()
    }
}

impl<'a, Sock, Xfrm> Credentials for MultiFlow<'a, Sock, Xfrm>
where
    Sock::Addr: Clone + Eq,
    Sock: Receiver + Sender,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>
{
    type Cred<'b> = Xfrm::PeerAddr
    where Self: 'b;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.peer_addr()))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Xfrm> Flow for MultiFlow<'a, Sock, Xfrm>
where
    Sock::Addr: Clone + Eq,
    Sock: Receiver + Sender,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>
{
    type LocalAddr = Xfrm::LocalAddr;
    type PeerAddr = Xfrm::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.addr.clone()
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Credentials
    for &'a mut SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type Cred<'b> = Xfrm::PeerAddr
    where Self: 'b;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.addr.clone()))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Credentials
    for &'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type Cred<'b> = Xfrm::PeerAddr
    where Self: 'b;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.addr.clone()))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Flow
    for &'a mut SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    type LocalAddr = Xfrm::LocalAddr;
    type PeerAddr = Xfrm::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.addr.clone()
    }
}

impl<Sock, Xfrm> Read for ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self.buf.try_recv() {
            // There's a buffered message; deliver it.
            Ok(msg) => {
                let len = msg.len();

                trace!(target: "flow-buffered",
                       "delivering {} bytes from {}",
                       len, self.addr);

                buf[..len].copy_from_slice(&msg);

                Ok(len)
            }
            Err(mpsc::TryRecvError::Empty) => Err(Error::new(
                ErrorKind::WouldBlock,
                "receive channel is empty"
            )),
            Err(_) => Err(Error::new(
                ErrorKind::ConnectionReset,
                "connection was reset"
            ))
        }
    }
}

impl<'a, Sock, Xfrm> Read for MultiFlow<'a, Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Sock::Addr: Clone + Eq,
    Sock: Receiver
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        let (n, addr) = self.socket.recv_from(buf)?;

        match self.xfrm.unwrap(&mut buf[..n], addr) {
            Ok((n, peer)) => {
                if self.addr != peer {
                    warn!(target: "far-multi-flow",
                      "discarding {} bytes from {} (expected {})",
                      n, peer, self.addr);

                    Err(Error::new(
                        ErrorKind::Other,
                        "discarded {} bytes from wrong address {}"
                    ))
                } else {
                    Ok(n)
                }
            }
            Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
        }
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Read
    for &'a mut SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        let mut nbytes;

        while {
            let (n, addr) = self.socket.recv_from(buf)?;

            match self.xfrm.unwrap(&mut buf[..n], addr) {
                Ok((n, peer)) => {
                    nbytes = n;

                    if self.addr != peer {
                        warn!(target: "far-multi-flow",
                              "discarding {} bytes from {} (expected {})",
                              nbytes, peer, self.addr);

                        true
                    } else {
                        false
                    }
                }
                Err(err) => {
                    return Err(Error::new(ErrorKind::Other, err.to_string()))
                }
            }
        } {}

        Ok(nbytes)
    }
}

impl<'a, Sock, Xfrm> Write for MultiFlow<'a, Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Sock::Addr: Clone + Eq,
    Sock: Sender
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self.xfrm.wrap(buf, self.addr.clone()) {
            Ok((Some(buf), addr)) => self.socket.send_to(&addr, &buf),
            Ok((None, addr)) => self.socket.send_to(&addr, buf),
            Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, Sock, Nego, AuthN, Xfrm> Write
    for &'a mut SingleFlow<'a, Sock, Nego, AuthN, Xfrm>
where
    Sock: Socket,
    Nego: BorrowedFlowNegotiator<&'a SingleFlow<'a, Sock, Nego, AuthN, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self.xfrm.wrap(buf, self.addr.clone()) {
            Ok((Some(buf), addr)) => self.socket.send_to(&addr, &buf),
            Ok((None, addr)) => self.socket.send_to(&addr, buf),
            Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<Sock, Xfrm> Write for ThreadedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self.xfrm.lock() {
            Ok(mut guard) => match guard.wrap(buf, self.addr.clone()) {
                Ok((Some(buf), addr)) => self.socket.send_to(&addr, &buf),
                Ok((None, addr)) => self.socket.send_to(&addr, buf),
                Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "mutex poisoned"))
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.socket.as_ref().flush()
    }
}

impl Display for ThreadedFlowsFlowError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            ThreadedFlowsFlowError::Taken => {
                write!(f, "flow for this address has already been claimed")
            }
            ThreadedFlowsFlowError::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}

impl Display for ThreadedFlowsListenError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            ThreadedFlowsListenError::Shutdown => {
                write!(f, "reporting channel shutdown")
            }
            ThreadedFlowsListenError::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}
