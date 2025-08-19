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

//! Traffic flow multiplexers.
//!
//! Far-link channels are connectionless, and may send and receive
//! traffic from multiple peers on a single socket.  Moreover, some
//! [FarChannel](crate::far::FarChannel) implementations support
//! session protocol negotiations with peers (such as with DTLS).
//! This requires a mechanism for splitting out traffic flows with
//! individual peers and managing them as separate entities.
//!
//! # Usage
//!
//! The two primary APIs in the module are the traffic splitter and
//! [Flow] APIs.  `Flow` represents an individual traffic flow, and
//! implementations must also provide [Read] and [Write]
//! implementations.  Traffic splitters have two separate APIs
//! depending on whether the instance is owned or borrowed.  They can
//! be thought of as an abstraction over a socket, and can be used to
//! obtain individual [Flow]s for each peer.
//!
//! ## Obtaining [Flow]s from Traffic Splitters
//!
//! Traffic splitter instances should also provide implementations of
//! one of two sub-traits: [OwnedFlows] and [BorrowedFlows].  Both
//! sub-traits provide two functions: [flow](OwnedFlowsOutbound::flow) and
//! [listen](OwnedFlowsInbound::listen).
//!
//! Users can obtain a flow for a given peer from an address using
//! `flow`.  This is typically used to establish a client or
//! peer-to-peer flow with a known endpoint.
//!
//! Additionally, users can obtain inbound flows from arbitrary peers
//! using `listen`.  This is typically used in a server-type use case.
//!
//! ## Borrowed vs. Owned Traffic Splitters
//!
//! The traffic splitters API is split into two trait hierarchies,
//! depending on whether the associated traffic splitters are owned or
//! borrowed:
//!
//! - The borrowed trait hierarchy is characterized primarily by
//!   [BorrowedFlows], and assumes that individual [Flow]s represent a mutable
//!   borrow of the parent traffic splitter object.  In general, this means that
//!   only one `Flow` can exist at any given time.  This supports very simple
//!   implementations, and is intended for simple usage patterns, such as
//!   "one-shot" clients. Implementations generally represent a thin
//!   abstraction, do not have internal buffering, and do not support sharing.
//!
//! - The owned trait hierarchy is characterized by the [OwnedFlowsInbound] and
//!   [OwnedFlowsOutbound] traits, and assumes that individual [Flow]s represent
//!   owned objects, separate from their parent `Flows`.  This supports more
//!   complicated implementations, and is suitable for general use.
//!   Implementations support sharing and potentially inter-thread
//!   communication, and thus will generally have internal buffering and
//!   possibly synchronization of some kind.  `OwnedFlows` is typically
//!   appropriate for components of larger systems, continuously-running peer
//!   services or connectors, or anything acting like a server.  Typically, the
//!   [FarChannelRegistry](crate::far::registry::FarChannelRegistry) API will be
//!   used as the actual mechanism for obtaining owned flows.
//!
//! ## Creating Traffic Splitters
//!
//! Traffic splitter instances are obtained from
//! [FarChannel](crate::far::FarChannel)s directly, through the
//! [owned_flows](crate::far::FarChannelOwnedFlows::owned_flows) and
//! [borrowed_flows](crate::far::FarChannelBorrowFlows::borrowed_flows)
//! functions, depending on whether the specific `Flows` instance
//! implements [OwnedFlows] or [BorrowedFlows].
//!
//! # Implementations
//!
//! This module provides several implementations of traffic flow
//! splitters, each with a different intended usage pattern:
//!
//! - [ThreadedFlows] is intended for most complex uses, and implements the
//!   owned trait API.  This should be used for most complex use cases where
//!   many different [Flow]s may exist at a given time.  It is also required for
//!   use with [FarChannelRegistry](crate::far::registry::FarChannelRegistry).
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
use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::rc::Rc;
use std::rc::Weak;

use constellation_auth::authn::AuthNed;
use constellation_auth::cred::Credentials;
use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use log::debug;
use log::error;
use log::trace;
use mio::Interest;
use mio::Registry;
use mio::Token;
use mio::event::Source;

use crate::config::FlowsConfig;

pub type MsgBuf = VecDeque<Vec<u8>>;

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

enum PendingEntry<In, Out> {
    /// A stalled inbound negotiation.
    In {
        /// Information for resuming an inbound negotiation.
        resume: In,
        buf: Rc<MsgBuf>
    },
    /// A stalled outbound negotiation.
    Out {
        /// Information for resuming an outbound negotiation.
        resume: Out,
        buf: Rc<MsgBuf>
    }
}

pub struct Flows<F, Sock, InboundNego, OutboundNego, Xfrm>
where
    F: Flow,
    Sock: Socket + Sender + Receiver + Source,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash {
    /// Maximum message size.
    msgsize: usize,
    /// Default [VecDeque] size.
    bufsize: Option<usize>,
    /// Negotiator for outgoing sessions.
    outbound_nego: OutboundNego,
    /// Negotiator for incoming sessions.
    inbound_nego: InboundNego,
    /// Socket from which to read messages.
    socket: Rc<Sock>,
    /// Xfrm used to unwrap messages.
    xfrm: Rc<Xfrm>,
    /// Outgoing message buffer.
    outbuf: Rc<MsgBuf>,
    /// Table holding existing flows.
    // XXX The VecDeque should eventually get replaced by a proper
    // ring-buffer, to minimize allocation
    msgbufs: HashMap<Xfrm::PeerAddr, Weak<MsgBuf>>,
    /// Table of negotiator threads.
    // XXX Add mechanism for expiring stale negotiation states.
    pending: Rc<
        HashMap<
            Xfrm::PeerAddr,
            PendingEntry<InboundNego::Pending, OutboundNego::Pending>
        >
    >
}

impl<F, Sock, InboundNego, OutboundNego, Xfrm>
    Flows<F, Sock, InboundNego, OutboundNego, Xfrm>
where
    F: Flow,
    Sock: Socket + Sender + Receiver + Source,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash {
    fn create(
        config: FlowsConfig,
        socket: Sock,
        outbound_nego: OutboundNego,
        inbound_nego: InboundNego,
        xfrm: Xfrm
    ) -> Self {
        let (msgsize, bufsize, nflows, nnegos) = config.take();
        let xfrm = Rc::new(xfrm);
        let outbuf = match bufsize {
            Some(size) => VecDeque::with_capacity(size),
            None => VecDeque::new()
        };
        let outbuf = Rc::new(outbuf);
        let msgbufs = match nflows {
            Some(size) => HashMap::with_capacity(size),
            None => HashMap::new()
        };
        let socket = Rc::new(socket);
        let pending = match nnegos {
            Some(size) => HashMap::with_capacity(size),
            None => HashMap::new()
        };
        let pending = Rc::new(pending);

        Flows {
            outbound_nego: outbound_nego,
            inbound_nego: inbound_nego,
            msgsize: msgsize,
            bufsize: bufsize,
            pending: pending,
            outbuf: outbuf,
            msgbufs: msgbufs,
            socket: socket,
            xfrm: xfrm
        }
    }
}

pub struct BufferedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Sock: Socket + Receiver {
    /// Peer address.
    addr: Xfrm::PeerAddr,
    /// Xfrm used to unwrap messages.
    xfrm: Rc<Xfrm>,
    /// Socket used to send messages.
    socket: Rc<Sock>,
    /// Outgoing message buffer.
    outbuf: Rc<MsgBuf>,
    /// Strong reference to the incoming message buffer.
    inbuf: Rc<MsgBuf>,
}

pub enum ListenResult<Flow, Endpoint> {
    /// A message from a totally new endpoint was received.
    New {
        /// The endpoint for the flow.
        endpoint: Endpoint,
        /// The new flow.
        flow: Flow
    },
    /// A message for an existing flow was received.
    Existing {
        /// The endpoint for the flow.
        endpoint: Endpoint
    }
}

#[derive(Debug)]
pub enum FlowsListenError<Xfrm, Start, In, Out> {
    Xfrm {
        err: Xfrm
    },
    /// Error starting negotiation.
    Start {
        /// The error that occurred starting negotiation.
        err: Start
    },
    /// Unrecoverable error during inbound negotiations.
    In {
        /// The error that occurred during inbound negotiations.
        err: In
    },
    /// Unrecoverable error during outbound negotiations.
    Out {
        /// The error that occurred during outbound negotiations.
        err: Out
    },
    /// Low-level I/O error occurred.
    IO {
        /// The low-level I/O error that occurred.
        err: Error
    },
    /// Failed to [get_mut](Rc::get_mut).
    ///
    /// This should never happen.
    GetMut,
    /// Failed to [split](RecoverableError::split) returned nothing.
    ///
    /// This should never happen.
    BadSplit
}

#[derive(Debug)]
pub enum FlowsFlowError<Start, Nego> {
    /// Error starting negotiation.
    Start {
        /// The error that occurred starting negotiation.
        err: Start
    },
    /// Unrecoverable error during negotiations.
    Nego {
        /// The error that occurred during negotiations.
        err: Nego
    },
    /// Low-level I/O error occurred.
    IO {
        /// The low-level I/O error that occurred.
        err: Error
    },
    /// Failed to [get_mut](Rc::get_mut).
    ///
    /// This should never happen.
    GetMut,
    /// Failed to [split](RecoverableError::split) returned nothing.
    ///
    /// This should never happen.
    BadSplit
}

impl<F, Sock, InboundNego, OutboundNego, Xfrm> Source
    for Flows<F, Sock, InboundNego, OutboundNego, Xfrm>
where
    F: Flow,
    Sock: Socket + Sender + Receiver + Source,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash {
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        Rc::get_mut(&mut self.socket)
            .ok_or(Error::new(ErrorKind::Other, "get_mut failed"))?
            .register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        Rc::get_mut(&mut self.socket)
            .ok_or(Error::new(ErrorKind::Other, "get_mut failed"))?
            .reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        Rc::get_mut(&mut self.socket)
            .ok_or(Error::new(ErrorKind::Other, "get_mut failed"))?
            .deregister(registry)
    }
}

impl<F, Sock, InboundNego, OutboundNego, Xfrm>
    Flows<F, Sock, InboundNego, OutboundNego, Xfrm>
where
    F: Flow,
    Sock: Socket + Sender + Receiver + Source,
    OutboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    InboundNego: NegotiatorStart<F, BufferedFlow<Sock, Xfrm>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash {
    /// Get the local address for the underlying socket.
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }

    fn listen(
        &mut self,
    ) -> Result<Option<ListenResult<F, Xfrm::PeerAddr>>,
                FlowsListenError<Xfrm::Error, InboundNego::StartError,
                                 InboundNego::NegotiateError,
                                 OutboundNego::NegotiateError>> {
        let local_addr = self.local_addr()
            .map_err(|err| FlowsListenError::IO { err: err })?;

        trace!(target: "flows",
               "listening for incoming message on {}",
               local_addr);

        // Get one message.
        let mut msg = vec![0; self.msgsize];
        let (n, addr, cred) = self.socket.recv_from(&mut msg)
            .map_err(|err| FlowsListenError::IO { err: err })?;

        // Some sockets return zero-length messages.
        if n != 0 {
            trace!(target: "flows",
                   "received {} bytes from {} on {}",
                   n, addr, local_addr);

            // Unwrap it.
            let (msglen, addr) = match Rc::get_mut(&mut self.xfrm) {
                Some(mut xfrm) => {
                    xfrm.unwrap(&mut msg[..n], addr)
                        .map_err(|err| FlowsListenError::Xfrm { err: err })
                }
                None => Err(FlowsListenError::GetMut)
            }?;

            trace!(target: "flows",
                   "unwrapped message from {} on {} to {} bytes",
                   addr, local_addr, msglen);

            msg.truncate(msglen);

            // First, see if there's an existing flow.
            let newbuf = match self.msgbufs.entry(addr.clone()) {
                Entry::Occupied(ent) => match ent.get().upgrade()  {
                    Some(buf) => {
                        // Weak reference is still good; deliver the message.
                        buf.push_back(msg);

                        None
                    }
                    None => {
                        // Weak reference expired.
                        trace!(target: "flows",
                               "expiring stale flow from {} on {}",
                               addr, local_addr);

                        let buf = match self.bufsize {
                            Some(len) => VecDeque::with_capacity(len),
                            None => VecDeque::new()
                        };
                        let buf = Rc::new(buf);

                        // Deliver the message and update this entry.
                        buf.push_back(msg);

                        let _ = ent.insert(Rc::downgrade(&buf.clone()));

                        Some(buf)
                    }
                }
                Entry::Vacant(ent) => {
                    // We need to create a new entry.
                    debug!(target: "flows",
                           "creating new flow from {} on {}",
                           addr, local_addr);

                    let buf = match self.bufsize {
                        Some(len) => VecDeque::with_capacity(len),
                        None => VecDeque::new()
                    };
                    let buf = Rc::new(buf);

                    buf.push_back(msg);

                    Some(buf)
                }
            };

            // See if we need to create a new negotiation.
            if let Some(buf) = newbuf {
                let flow = BufferedFlow {
                    addr: addr.clone(),
                    xfrm: self.xfrm.clone(),
                    socket: self.socket.clone(),
                    outbuf: self.outbuf.clone(),
                    inbuf: buf
                };
                let nego = self.inbound_nego.start(flow)
                    .map_err(|err| FlowsListenError::Start { err: err })?;

                // Short-circuit: try to negotiate immediately.
                match self.inbound_nego.negotiate(nego)
                    .map_err(|err| FlowsListenError::In { err: err })? {
                    // We're done, the negotiation succeeded.
                    NegotiatorResult::Complete(flow) => {
                        debug!(target: "flows",
                               "negotiation completed immediately for {}",
                               addr);

                        Ok(Some(ListenResult::New {
                            endpoint: addr,
                            flow: flow
                        }))
                    }
                    NegotiatorResult::Pending(pending) => {
                        trace!(target: "flows",
                               "creating pending negotiation for {}",
                               addr);

                        let pending = PendingEntry::In {
                            resume: pending,
                            buf: buf
                        };

                        // Set up a pending negotiation.
                        if Rc::get_mut(&mut self.pending)
                            .ok_or(FlowsListenError::GetMut)?
                            .insert(addr.clone(), pending)
                            .is_some() {
                            error!(target: "flows",
                                   "stray pending entry for {}",
                                   addr);

                        }

                        Ok(None)
                    }
                }
            } else if let Entry::Occupied(mut ent) =
                Rc::get_mut(&mut self.pending)
                .ok_or(FlowsListenError::GetMut)?
                .entry(addr.clone()) {
                // Resume a pending negotiation
                trace!(target: "flows",
                       "resuming pending negotiation for {}",
                       addr);

                match ent.remove() {
                    PendingEntry::Out { resume, buf } => match self
                        .outbound_nego
                        .complete_negotiate(resume)
                        .map_err(|err| FlowsListenError::Out { err: err })? {
                        NegotiatorResult::Complete(flow) => {
                            debug!(target: "flows",
                                   "negotiation completed for {}",
                                   addr);

                            Ok(Some(ListenResult::New {
                                endpoint: addr,
                                flow: flow
                            }))
                        }
                        NegotiatorResult::Pending(pending) => {
                            trace!(target: "flows",
                                   "continuing negotiation for {}",
                                   addr);

                            // Set up a pending negotiation.
                            let pending = PendingEntry::Out {
                                resume: pending,
                                buf: buf
                            };

                            ent.insert(pending);

                            Ok(None)
                        }
                    }
                    PendingEntry::In { resume, buf } => match self
                        .inbound_nego
                        .complete_negotiate(resume)
                        .map_err(|err| FlowsListenError::In { err: err })? {
                        NegotiatorResult::Complete(flow) => {
                            debug!(target: "flows",
                                   "negotiation completed for {}",
                                   addr);

                            Ok(Some(ListenResult::New {
                                endpoint: addr,
                                flow: flow
                            }))
                        }
                        NegotiatorResult::Pending(pending) => {
                            trace!(target: "flows",
                                   "continuing negotiation for {}",
                                   addr);

                            // Set up a pending negotiation.
                            let pending = PendingEntry::In {
                                resume: pending,
                                buf: buf
                            };

                            ent.insert(pending);

                            Ok(None)
                        }
                    }
                }
            } else {
                // This went to an established flow.
                Ok(Some(ListenResult::Existing { endpoint: addr}))
            }
        } else {
            Ok(None)
        }
    }

    fn flow(
        &self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<Option<F>,
                FlowsFlowError<OutboundNego::StartError,
                               OutboundNego::NegotiateError>> {
        let local_addr = self.local_addr()
            .map_err(|err| FlowsFlowError::IO { err: err })?;

        trace!(target: "flows",
               "requested flow to {} on {}",
               addr, local_addr);

        // First, see if there's an existing flow.
        let (negotiate, buf) = match self.msgbufs.entry(addr.clone()) {
            Entry::Occupied(ent) => match ent.get().upgrade() {
                // There's an existing buffer, use that.
                Some(buf) => (false, buf.clone()),
                None => {
                    // Weak reference expired set up a new negotiation.
                    trace!(target: "flows",
                           "expiring stale flow from {} on {}",
                           addr, local_addr);

                    let buf = match self.bufsize {
                        Some(len) => VecDeque::with_capacity(len),
                        None => VecDeque::new()
                    };
                    let buf = Rc::new(buf);
                    let _ = ent.insert(Rc::downgrade(&buf.clone()));

                    (true, buf)
                }
            }
            Entry::Vacant(ent) => {
                // We need to create a new entry.
                debug!(target: "flows",
                       "creating new flow from {} on {}",
                       addr, local_addr);

                let buf = match self.bufsize {
                    Some(len) => VecDeque::with_capacity(len),
                    None => VecDeque::new()
                };
                let buf = Rc::new(buf);

                (true, buf)
            }
        };
        let flow = BufferedFlow {
            addr: addr.clone(),
            xfrm: self.xfrm.clone(),
            socket: self.socket.clone(),
            outbuf: self.outbuf.clone(),
            inbuf: buf
        };

        if negotiate {
            let nego = self.outbound_nego.start(flow)
                .map_err(|err| FlowsFlowError::Start { err: err })?;

            // Try to negotiate immediately.
            match self.outbound_nego.negotiate(nego)
                .map_err(|err| FlowsFlowError::Nego { err: err })?
            {
                // We're done, the negotiation succeeded.
                NegotiatorResult::Complete(flow) => {
                    debug!(target: "flows",
                           "negotiation completed immediately for {}",
                           addr);

                    Ok(Some(flow))
                }
                NegotiatorResult::Pending(pending) => {
                    trace!(target: "flows",
                           "creating pending negotiation for {}",
                           addr);

                    let pending = PendingEntry::Out {
                        resume: pending,
                        buf: buf
                    };

                    // Set up a pending negotiation.
                    if Rc::get_mut(&mut self.pending)
                        .ok_or(FlowsFlowError::GetMut)?
                        .insert(addr.clone(), pending)
                        .is_some() {
                        error!(target: "flows",
                               "stray pending entry for {}",
                               addr);
                    }

                    Ok(None)
                }
            }
        } else {
            Ok(Some(flow))
        }
    }
}

impl<Sock, Xfrm> Flow for BufferedFlow<Sock, Xfrm>
where
    Sock: Socket + Receiver + Sender,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash {
    type LocalAddr = Sock::Addr;
    type PeerAddr = Xfrm::PeerAddr;

    /// Get the local address for this flow.
    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    /// Get the peer (remote) address for this flow.
    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.addr.clone()
    }

}

impl<Sock, Xfrm> Read for BufferedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket + Receiver
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match Rc::get_mut(&mut self.outbuf)
            .ok_or(Error::new(ErrorKind::Other, "get_mut failed"))?
            .pop_back() {
            // There's a buffered message; deliver it.
            Some(msg) => {
                let len = msg.len();

                trace!(target: "flow-buffered",
                       "delivering {} bytes from {}",
                       len, self.addr);

                buf[..len].copy_from_slice(&msg);

                Ok(len)
            }
            None => Err(Error::new(
                ErrorKind::WouldBlock,
                "receive channel is empty"
            ))
        }
    }
}

impl<Sock, Xfrm> Write for BufferedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket + Sender + Receiver
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        let len = buf.len();

        match Rc::get_mut(&mut self.xfrm)
            .ok_or(Error::new(ErrorKind::Other, "get_mut failed"))?
            .wrap(buf, self.addr.clone()) {
            // Copied transformation.
            Ok((Some(buf), addr)) => self.socket.send_to(&addr, &buf)
                .or_else(|err| if err.kind() == ErrorKind::WouldBlock {
                    // Would block.  Buffer the message and succeed.

                    // Try to get the output buffer to push the message.
                    match Rc::get_mut(&mut self.outbuf) {
                        Some(outbuf) => {
                            outbuf.push_back(buf);

                            Ok(len)
                        },
                        // This shouldn't happen.
                        None => Err(Error::new(ErrorKind::Other,
                                               "get_mut failed"))
                    }
                } else {
                    // Propagate the error.
                    Err(err)
                }),
            // In-place transformation
            Ok((None, addr)) => self.socket.send_to(&addr, &buf)
                .or_else(|err| if err.kind() == ErrorKind::WouldBlock {
                    // Would block.  Buffer the message and succeed.

                    // Try to get the output buffer to push the message.
                    match Rc::get_mut(&mut self.outbuf) {
                        Some(outbuf) => {
                            outbuf.push_back(buf.to_vec());

                            Ok(len)
                        },
                        // This shouldn't happen.
                        None => Err(Error::new(ErrorKind::Other,
                                               "get_mut failed"))
                    }
                } else {
                    // Propagate the error.
                    Err(err)
                }),
            // Error occurred transforming.
            Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        self.socket.flush()
    }
}

impl<Sock, Xfrm> Credentials for BufferedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Hash,
    Sock: Socket + Sender + Receiver
{
    type Cred = Xfrm::PeerAddr;
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

impl<Xfrm, Start, In, Out> ScopedError
    for FlowsListenError<Xfrm, Start, In, Out>
where
    Xfrm: ScopedError,
    Start: ScopedError,
    In: ScopedError,
    Out: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            FlowsListenError::Xfrm { err } => err.scope(),
            FlowsListenError::Start { err } => err.scope(),
            FlowsListenError::In { err } => err.scope(),
            FlowsListenError::Out { err } => err.scope(),
            FlowsListenError::IO { err } => err.scope(),
            FlowsListenError::GetMut |
            FlowsListenError::BadSplit => ErrorScope::Unrecoverable,
        }
    }
}

impl<Start, Nego> ScopedError for FlowsFlowError<Start, Nego>
where
    Start: ScopedError,
    Nego: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            FlowsFlowError::Start { err } => err.scope(),
            FlowsFlowError::Nego { err } => err.scope(),
            FlowsFlowError::IO { err } => err.scope(),
            FlowsFlowError::GetMut |
            FlowsFlowError::BadSplit => ErrorScope::Unrecoverable,
        }
    }
}

impl<Xfrm, Start, In, Out> Display
    for FlowsListenError<Xfrm, Start, In, Out>
where
    Xfrm: Display,
    Start: Display,
    In: Display,
    Out: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            FlowsListenError::Xfrm { err } => err.fmt(f),
            FlowsListenError::Start { err } => err.fmt(f),
            FlowsListenError::In { err } => err.fmt(f),
            FlowsListenError::Out { err } => err.fmt(f),
            FlowsListenError::IO { err } => write!(f, "{}", err),
            FlowsListenError::GetMut =>
                write!(f, "get_mut() failed unexpectedly"),
            FlowsListenError::BadSplit =>
                write!(f, "split() returned no result unexpectedly"),
        }
    }
}

impl<Start, Nego> Display for FlowsFlowError<Start, Nego>
where
    Start: Display,
    Nego: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            FlowsFlowError::Start { err } => err.fmt(f),
            FlowsFlowError::Nego { err } => err.fmt(f),
            FlowsFlowError::IO { err } => write!(f, "{}", err),
            FlowsFlowError::GetMut =>
                write!(f, "get_mut() failed unexpectedly"),
            FlowsFlowError::BadSplit =>
                write!(f, "split() returned no result unexpectedly"),
        }
    }
}
