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
use std::collections::hash_map::OccupiedEntry;
use std::collections::hash_map::VacantEntry;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::rc::Rc;
use std::rc::Weak;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread::sleep;
use std::thread::spawn;
use std::thread::JoinHandle;
use std::time::Instant;

use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::SessionAuthN;
use constellation_auth::cred::Credentials;
use constellation_common::codec::DatagramCodec;
use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorStart;
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
use mio::event::Source;

use crate::config::ThreadedFlowsParams;

type MsgBuf = VecDeque<u8>;

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

pub struct Flows<Sock, Nego, Xfrm, ChannelID>
where
    Sock: Socket + Sender + Receiver,
    Nego: NegotiatorStart<MsgBuf>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    ChannelID: Clone + Display + Eq + Hash + Send {
    id: PhantomData<ChannelID>,
    /// Maximum message size.
    msgsize: usize,
    /// Default [VecDeque] size.
    bufsize: Option<usize>,
    /// Negotiator for incoming sessions.
    nego: Nego,
    /// Socket from which to read messages.
    socket: Sock,
    /// Outgoing message buffer.
    outbuf: Rc<MsgBuf>,
    /// Xfrm used to unwrap messages.
    xfrm: Rc<Xfrm>,
    /// Table holding existing flows.
    // XXX The VecDeque should eventually get replaced by a proper
    // ring-buffer, to minimize allocation
    flows: Rc<HashMap<Xfrm::PeerAddr, Weak<MsgBuf>>>,
    /// Table of negotiator threads.
    // XXX Add mechanism for expiring stale negotiation states.
    pending: Rc<
        HashMap<
            Xfrm::PeerAddr,
            <Nego::NegotiateError as RecoverableError>::Completable
        >
    >
}

/// Information for an ongoing negotiation.
struct PendingFlow<Nego>
where Nego: NegotiatorStart<MsgBuf> {
    /// Information for resuming negotiations.
    resume: <Nego::NegotiateError as RecoverableError>::Completable,
    /// Pending messages buffer.
    pending: VecDeque<Vec<u8>>
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
pub enum FlowsListenError<Xfrm, Start, Nego> {
    Xfrm {
        err: Xfrm
    },
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

pub enum FlowsFlowError<Xfrm, Start, Nego> {
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

impl<Sock, Nego, Xfrm, ChannelID> Flows<Sock, Nego, Xfrm, ChannelID>
where
    Sock: Socket + Sender + Receiver,
    Nego: NegotiatorStart<BufferedFlow<Sock, Xfrm>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    ChannelID: Clone + Display + Eq + Hash + Send {

    /// Get the local address for the underlying socket.
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }

    fn listen(
        &mut self,
    ) -> Result<ListenResult<Nego::Outcome, Xfrm::PeerAddr>,
                FlowsListenError<Xfrm::Error, Nego::StartError>> {
        trace!(target: "flows",
               "listening for incoming message on {}",
               self.local_addr());

        // Get one message.
        let mut msg = vec![0; self.msgsize];
        let (n, addr, cred) = self.socket.recv_from(&mut msg)
            .map_err(|err| FlowsListenError::IO { err: err })?;

        // Some sockets return zero-length messages.
        if n != 0 {
            trace!(target: "flows",
                   "received {} bytes from {} on {}",
                   n, addr, self.local_addr());

            // Unwrap it.
            let (msglen, addr) = match self.xfrm.get_mut() {
                Some(mut xfrm) => {
                    xfrm.unwrap(&mut msg[..n], addr)
                        .map_err(|err| FlowsListenError::Xfrm { err: err })
                }
                None => Err(FlowsListenError::GetMut)
            }?;

            trace!(target: "flows",
                       "unwrapped message from {} on {} to {} bytes",
                   addr, self.local_addr(), msglen);

            msg.truncate(msglen);

            // First, see if there's an existing flow.
            let newbuf = match self.flows.get_mut()
                .ok_or(FlowsListenError::GetMut)?
                .entry(addr.clone()) {
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
                               addr, self.local_addr());

                        let buf = match self.buflen {
                            Some(len) => VecDeque::with_capacity(len),
                            None => VecDeque::new()
                        };
                        let buf = Rc::new(buf);

                        // Deliver the message and update this entry.
                        buf.push_back(msg);

                        let _ = ent.insert(Rc::downgrade(buf.clone()));

                        Some(buf)
                    }
                }
                Entry::Vacant(ent) => {
                    // We need to create a new entry.
                    debug!(target: "flows",
                           "creating new flow from {} on {}",
                           addr, self.local_addr());

                    let buf = match self.buflen {
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
                let nego = self.nego.start(flow)
                    .map_err(|err| FlowsListenError::Start { err: err })?;

                // Short-circuit: try to negotiate immediately.
                match self.nego.negotiate(nego) {
                    // We're done, the negotiation succeeded.
                    Ok(flow) => {
                        debug!(target: "flows",
                               "negotiation completed immediately for {}",
                               addr);

                        Ok(ListenResult::New {
                            endpoint: addr,
                            flow: flow
                        })
                    }
                    Err(err) => match err.split() {
                        // Negotiations require more messages.
                        (Some(err), _) => {
                            trace!(target: "flows",
                                   "creating pending negotiation for {}",
                                   addr);

                            // Set up a pending negotiation.
                            if self.pending
                                .get_mut()
                                .ok_or(FlowsListenError::GetMut)?
                                .insert(addr.clone(), err)
                                .is_some() {
                                error!(target: "flows",
                                       "stray pending entry for {}",
                                       addr);

                            }
                        }
                        // A hard error occurred.
                        (_, Some(err)) =>
                            Err(FlowsListenError::Nego { err: err }),
                        // This shouldn't ever happen.
                        _ => Err(FlowsListenError::BadSplit)
                    }
                }
            } else if let Entry::Occupied(mut ent) = self
                .pending
                .get_mut()
                .ok_or(FlowsListenError::GetMut)?
                .entry(addr.clone()) {
                let resume = ent.remove();

                // Resume a pending negotiation
                trace!(target: "flows",
                       "resuming pending negotiation for {}",
                       addr);

                match self.nego.negotiate(resume) {
                    Ok(flow) => {
                        debug!(target: "flows",
                               "negotiation completed for {}",
                               addr);

                        Ok(ListenResult::New {
                            endpoint: addr,
                            flow: flow
                        })
                    }
                    Err(err) => match err.split() {
                        // Negotiations require more messages.
                        (Some(err), _) => {
                            trace!(target: "flows",
                                   "continuing negotiation for {}",
                                   addr);

                            // Set up a pending negotiation.
                            let buf = match self.buflen {
                                Some(len) => VecDeque::with_capacity(len),
                                None => VecDeque::new()
                            };
                            let pending = PendingFlow {
                                resume: err,
                                pending: buf
                            };

                            ent.insert(pending)
                        }
                        // A hard error occurred.
                        (_, Some(err)) =>
                            Err(FlowsListenError::Nego { err: err }),
                        // This shouldn't ever happen.
                        _ => Err(FlowsListenError::BadSplit)
                    }
                }
            } else {
                // This went to an established flow.
                Ok(ListenResult::Existing { endpoint: addr})
            }
        }
    }

    fn flow(
        &self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<Option<Nego::Outcome>, Self::FlowError> {
        trace!(target: "flows",
               "requested flow to {} on {}",
               addr, self.local_addr());

        // First, see if there's an existing flow.
        let (negotiate, buf) = match self.flows.get_mut()
            .ok_or(FlowsFlowError::GetMut)?
            .entry(addr.clone()) {
            Entry::Occupied(ent) => match ent.get().upgrade() {
                // There's an existing buffer, use that.
                Some(buf) => (false, buf.clone()),
                None => {
                    // Weak reference expired set up a new negotiation.
                    trace!(target: "flows",
                           "expiring stale flow from {} on {}",
                           addr, self.local_addr());

                    let buf = match self.buflen {
                        Some(len) => VecDeque::with_capacity(len),
                        None => VecDeque::new()
                    };
                    let buf = Rc::new(buf);
                    let _ = ent.insert(Rc::downgrade(buf.clone()));

                    (true, buf)
                }
            }
            Entry::Vacant(ent) => {
                // We need to create a new entry.
                debug!(target: "flows",
                       "creating new flow from {} on {}",
                       addr, self.local_addr());

                let buf = match self.buflen {
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
            let nego = self.nego.start(flow)
                .map_err(|err| FlowsListenError::Start { err: err })?;

            // Try to negotiate immediately.
            match self.nego.negotiate(nego) {
                // We're done, the negotiation succeeded.
                Ok(flow) => {
                    debug!(target: "flows",
                           "negotiation completed immediately for {}",
                           addr);

                    Ok(Some(flow))
                }
                Err(err) => match err.split() {
                    // Negotiations require more messages.
                    (Some(err), _) => {
                        trace!(target: "flows",
                               "creating pending negotiation for {}",
                               addr);

                        // Set up a pending negotiation.
                        if self.pending
                            .get_mut()
                            .ok_or(FlowsFlowError::GetMut)?
                            .insert(addr.clone(), err)
                            .is_some() {
                            error!(target: "flows",
                                   "stray pending entry for {}",
                                   addr);
                        }

                        Ok(None)
                    }
                    // A hard error occurred.
                    (_, Some(err)) =>
                        Err(FlowsFlowError::Nego { err: err }),
                    // This shouldn't ever happen.
                    _ => Err(FlowsFlowError::BadSplit)
                }
            }
        } else {
            Ok(Some(flow))
        }
    }
}

impl<Sock, Xfrm> Flow for BufferedFlow<Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Sock: Socket + Receiver {

    /// Get the local address for this flow.
    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    /// Get the peer (remote) address for this flow.
    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.addr
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
        match self.buf.pop_back() {
            // There's a buffered message; deliver it.
            Ok((msg, _)) => {
                let len = msg.len();

                trace!(target: "flow-buffered",
                       "delivering {} bytes from {}",
                       len, self.addr);

                buf[..len].copy_from_slice(&msg);

                Ok(len)
            }
            None =>  Err(Error::new(
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

        // Try to get the transformer.
        match Rc::get_mut(&mut self.xfrm) {
            // Transform the message.
            Some(xfrm) => match xfrm.wrap(buf, self.addr.clone()) {
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
            // This shouldn't happen.
            None => Err(Error::new(ErrorKind::Other, "get_mut failed"))
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

pub trait Flows: Source {
    /// Type of basic [Flow]s produced by this instance.
    ///
    /// This will likely differ from the type of [Flow] produced by
    /// the [BorrowedFlowNegotiator].
    type Flow: Credentials + Flow + Read + Write;
    type InboundState;
    type OutboundState;
    type NegotiateInboundError: Debug + Display + RecoverableError;
    type NegotiateOutboundError: Debug + Display + RecoverableError;

    /// Perform negotiations on an inbound negotiation state.
    ///
    /// This may fail with an error that may be
    /// [Completable](RecoverableError::Completable) (see
    /// [split](RecoerableError::split).  In such a case,
    /// [complete_negotiate_inbound](Flows::complete_negotiate_inbound)
    /// is used to finish the negotiations.
    ///
    /// # Parameters
    ///
    /// * `state`: The negotiation state to use for negotiations.
    fn negotiate_inbound(
        &self,
        state: Self::InboundState
    ) -> Result<Self::Flow, Self::NegotiateInboundError>;

    /// Complete a failed inbound negotiation.
    ///
    /// # Parameters
    ///
    /// * `err`: The completable error from a previous
    ///   [negotiate_inbound](Flows::negotiate_inbound) or
    ///   `complete_negotiate_inbound` attempt.
    fn complete_negotiate_inbound(
        &self,
        err: <Self::NegotiateInboundError as RecoverableError>::Completable
    ) -> Result<Self::Flow, Self::NegotiateInboundError>;

    /// Perform negotiations on an outbound negotiation state.
    ///
    /// This may fail with an error that may be
    /// [Completable](RecoverableError::Completable) (see
    /// [split](RecoerableError::split).  In such a case,
    /// [complete_negotiate_outbound](Flows::complete_negotiate_outbound)
    /// is used to finish the negotiations.
    ///
    /// # Parameters
    ///
    /// * `state`: The negotiation state to use for negotiations.
    fn negotiate_outbound(
        &self,
        state: Self::OutboundState
    ) -> Result<Self::Flow, Self::NegotiateOutboundError>;

    /// Complete a failed outbound negotiation.
    ///
    /// # Parameters
    ///
    /// * `err`: The completable error from a previous
    ///   [negotiate_outbound](Flows::negotiate_outbound) or
    ///   `complete_negotiate_outbound` attempt.
    fn complete_negotiate_outbound(
        &self,
        err: <Self::NegotiateOutboundError as RecoverableError>::Completable
    ) -> Result<Self::Flow, Self::NegotiateOutboundError>;
}

pub trait FlowsStart<PeerAddr>: Flows {
    /// Type of errors that can occur starting a negotiation.
    type FlowError: Display + ScopedError;
    /// Type of errors that can occur starting a negotiation.
    type ListenError: Display + ScopedError;

    /// Start a session negotiation.
    ///
    /// This is similar in nature to
    /// (Negotiator::start)[constellation_common::net::Negotiator::start],
    /// the underlying stream is supplied by the channel.
    fn listen(
        &self,
    ) -> Result<ListenResult<Self::InboundState, PeerAddr>, Self::ListenError>;

    /// Start a session negotiation.
    ///
    /// This is similar in nature to
    /// (Negotiator::start)[constellation_common::net::Negotiator::start],
    /// the underlying stream is supplied by the channel.
    fn flow(
        &self,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<Self::OutboundState, Self::FlowError>;
}

pub trait BorrowedFlowsRaw<'a, F, PeerAddr>
where
    F: Credentials + Flow + Read + Write {
    /// Errors that can occur when obtaining flows.
    type RawFlowError: Display + ScopedError;
    /// Errors that can occur listening.
    type RawListenError: Display + ScopedError;

    /// Get a [Flow] instance to send messages to the peer at `addr`.
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
    fn flow_raw(
        &'a mut self,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<F>, Self::RawFlowError>;

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
    fn listen_raw(
        &'a mut self
    ) -> Result<RetryResult<(F, PeerAddr)>, Self::RawListenError>;
}

/// Trait for creating traffic flow splitters.
///
/// This is used primarily with
/// [owned_flows](crate::far::FarChannelOwnedFlows::owned_flows) and
/// [borrowed_flows](crate::far::FarChannelBorrowFlows::borrowed_flows).
/// It is not intended to be used directly.
pub trait BorrowedFlowsCreate<'a, Sock, Xfrm>:
    FlowsLocalAddr<Sock::Addr>
where
    Sock: Socket,
    Xfrm: DatagramXfrm {
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
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError>;
}

pub trait BorrowedFlowsFlow {
    /// Type of basic [Flow]s produced by this instance.
    ///
    /// This will likely differ from the type of [Flow] produced by
    /// the [BorrowedFlowNegotiator].
    type Flow: Credentials + Flow + Read + Write;
}

/// Trait for creating traffic flow splitters.
///
/// This is used primarily with
/// [owned_flows](crate::far::FarChannelOwnedFlows::owned_flows) and
/// [borrowed_flows](crate::far::FarChannelBorrowFlows::borrowed_flows).
/// It is not intended to be used directly.
pub trait BorrowedFlows<'a, Nego, AuthN, PeerAddr>:
    BorrowedFlowsRaw<'a, Self::Flow, PeerAddr> + BorrowedFlowsFlow
where
    Nego: 'a + BorrowedFlowNegotiator<Self::Flow>,
    AuthN: SessionAuthN<Nego::Flow<'a>> {
    /// Errors that can occur when obtaining flows.
    type ListenError: Display + ScopedError;
    type FlowError: Display + ScopedError;

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
    fn listen(
        &'a mut self,
        nego: &'a Nego,
        authn: &AuthN
    ) -> Result<RetryResult<(AuthN::AuthNSession, PeerAddr)>, Self::ListenError>;

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
        nego: &'a Nego,
        authn: &AuthN,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<AuthN::AuthNSession>, Self::FlowError>;
}

pub trait BorrowedFlowNegotiator<Inner>: Send + Sync
where
    Inner: Credentials + Flow + Read + Write {
    /// Resulting [Flow] type.
    ///
    /// This may differ from `Inner`, which is the type of flows used
    /// to do the negotiation.
    type Flow<'a>: Credentials + Flow + Read + Write
    where
        Self: 'a;
    /// Errors that can occur during negotiations.
    type NegotiateError: Display + ScopedError;

    /// Negotiate an outbound session.
    fn negotiate_outbound(
        &self,
        inner: Inner,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;

    /// Negotiate an inbound session.
    fn negotiate_inbound(
        &self,
        inner: Inner
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;
}

pub trait OwnedFlowsOutboundRaw<F, PeerAddr>
where
    F: Credentials + Flow + Read + Write {
    /// Errors that can occur when obtaining flows.
    type RawFlowError: Display + ScopedError;

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
    fn flow_raw(
        &mut self,
        addr: PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<F>, Self::RawFlowError>;
}

pub trait OwnedFlowsOutbound<Session, PeerAddr> {
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
    ) -> Result<RetryResult<Session>, Self::FlowError>;
}

pub trait OwnedFlowsInboundRaw<F, PeerAddr>
where
    F: Credentials + Flow + Read + Write {
    /// Errors that can occur listening.
    type RawListenError: Display + ScopedError;

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
    fn listen_raw(
        &mut self
    ) -> Result<RetryResult<(F, PeerAddr)>, Self::RawListenError>;
}

pub trait OwnedFlowsInbound<Session, PeerAddr> {
    /// Errors that can occur listening.
    type ListenError: Display + ScopedError;

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
    fn listen(
        &mut self
    ) -> Result<RetryResult<(Session, PeerAddr)>, Self::ListenError>;
}

pub trait OwnedFlows {
    /// Type of basic [Flow]s produced by this instance.
    ///
    /// This will likely differ from the type of [Flow] produced by
    /// the [OwnedFlowNegotiator].
    type Flow: Credentials + Flow + Read + Write;
}

/// Trait for creating [OwnedFlows] from a configuration object.
pub trait OwnedFlowsCreate<Sock, Nego, AuthN, Xfrm>:
    FlowsLocalAddr<Sock::Addr>
    + OwnedFlowsOutbound<AuthN::AuthNSession, Xfrm::PeerAddr>
    + OwnedFlows
where
    Sock: Socket,
    Nego: OwnedFlowNegotiator<Self::Flow>,
    AuthN: SessionAuthN<Nego::Flow>,
    Xfrm: DatagramXfrm {
    /// Channel identifier for the created traffic splitter.
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

/// Trait for session negotiators for [OwnedFlows].
///
/// This allows the details of session negotiation to be abstracted
/// over.
pub trait OwnedFlowNegotiator<Inner>: Send + Sync
where
    Inner: Credentials + Flow + Read + Write {
    /// Resulting [Flow] type.
    ///
    /// This may differ from `Inner`, which is the type of flows used
    /// to do the negotiation.
    type Flow: Credentials + Flow + Read + Write;
    /// errors that can occur during negotiations.
    type NegotiateError: Display + ScopedError;

    /// Attempt to negotiate an outbound session without blocking.
    ///
    /// This means that no additional messages need to be sent.  This
    /// will return a [NonblockResult] indicating success or failure;
    /// if failure is indicated, then
    /// [negotiate_outbound](OwnedFlowNegotiator::negotiate_outbound)
    /// should be called with the same parameters.
    ///
    /// Errors returned indicate "hard" errors.
    fn negotiate_outbound_nonblock(
        &self,
        inner: Inner
    ) -> Result<NonblockResult<Self::Flow, Inner>, Self::NegotiateError>;

    /// Negotiate an outbound session.
    ///
    /// This may block for a a long time; users should generally use
    /// [negotiate_outbound_nonblock](OwnedFlowNegotiator::negotiate_outbound_nonblock)
    /// to try to negotiate without blocking, then set up the
    /// necessary machinery to handle a potentially stalled
    /// negotiation before calling this function.
    fn negotiate_outbound(
        &self,
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
    /// [negotiate](OwnedFlowNegotiator::negotiate_inbound) should be
    /// called with the same parameters.
    ///
    /// Errors returned indicate "hard" errors.
    fn negotiate_inbound_nonblock(
        &self,
        inner: Inner
    ) -> Result<NonblockResult<Self::Flow, Inner>, Self::NegotiateError>;

    /// Negotiate an inbound session.
    ///
    /// This may block for a a long time; users should generally use
    /// [negotiate_inbound_nonblock](OwnedFlowNegotiator::negotiate_inbound_nonblock)
    /// to try to negotiate without blocking, then set up the
    /// necessary machinery to handle a potentially stalled
    /// negotiation before calling this function.
    fn negotiate_inbound(
        &self,
        inner: Inner
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Inner>>,
        Self::NegotiateError
    >;
}

#[derive(Debug)]
pub enum FlowNegoAuthNError<Flow, Nego, AuthN> {
    Flow { err: Flow },
    Nego { err: Nego },
    AuthN { err: AuthN },
    AuthNFail
}

pub enum FlowNegoAuthNRetry<Flow, Nego, AuthN> {
    Flow { err: Flow },
    Nego { err: Nego },
    AuthN { err: AuthN }
}

#[derive(Debug)]
pub enum SingleFlowError<Addr> {
    WrongAddr { expected: Addr, actual: Addr }
}

#[derive(Debug)]
pub enum MultiFlowError<Xfrm, Addr> {
    Addr { err: Addr },
    Xfrm { err: Xfrm },
    IO { err: Error }
}

/// Retry information for [OwnedFlowNegotiator] and
/// [BorrowedFlowNegotiator].
pub struct NegotiateRetry<Flow> {
    /// When the operation should be retried.
    when: Instant,
    /// The flow on which to retry.
    flow: Flow
}

/// A simple [BorrowedFlows] instance that communicates only with a
/// single peer.
///
/// This functions as its own [Flow] instance,
/// and communicates exclusively with one peer.  Any traffic from
/// another peer will be dropped.
pub struct SingleFlow<'a, Sock, Xfrm>
where
    Sock: 'a + Socket + Sender + Receiver,
    Xfrm: 'a + DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError {
    lifetime: PhantomData<&'a mut ()>,
    /// The underlying socket.
    socket: Sock,
    /// The channel context.
    xfrm: Xfrm,
    /// The peer address.
    addr: Xfrm::LocalAddr
}

/// A [BorrowedFlows] instance that communicates with one peer at a
/// time.
///
/// This creates [MultiFlow]s, which permit communication with a
/// single peer at a time.
pub struct MultiFlows<'a, Sock, Xfrm>
where
    Sock: 'a + Socket + Sender + Receiver,
    Xfrm: 'a + DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    Xfrm::Error: ScopedError,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError {
    lifetime: PhantomData<&'a ()>,
    /// The underlying socket.
    socket: Sock,
    /// The channel context.
    xfrm: Xfrm
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
    addr: Xfrm::LocalAddr
}

/// An owned traffic splitter instance that operates using threads.
///
/// This will create a separate thread for listening for inbound
/// traffic flows, and will automatically generate [ThreadedFlow]s for
/// them, perform negitation and authentication, and report them via
/// [ThreadedFlowsListener].  Individual [Flow]s can also be obtained
/// using the [OwnedFlowsOutbound] API.
pub struct ThreadedFlows<Sock, Nego, AuthN, Xfrm, ChannelID>
where
    Sock: Socket + Sender + Receiver,
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    ChannelID: Clone + Display + Eq + Hash + Send {
    /// Inner structure.
    inner: Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ChannelID>>
}

/// An [OwnedFlowsInbound] instance based on threading.
pub struct ThreadedFlowsListener<Session, ID>
where
    ID: Clone + Display + Eq + Hash {
    /// Receiver for the backlog queue.
    backlog_recv: Arc<Mutex<mpsc::Receiver<(Session, ID)>>>
}

/// A [PullStreamListener] instance based on an [OwnedFlowsInbound]
/// instance.
pub struct ThreadedFlowsPullStreamListener<Session, Msg, Codec, ID>
where
    Codec: Clone + DatagramCodec<Msg>,
    ID: Clone + Display + Eq + Hash {
    msg: PhantomData<Msg>,
    codec: Codec,
    inner: ThreadedFlowsListener<Session, ID>
}

/// A reporter for [ThreadedFlows].
///
/// This is used to report newly-created flows, which will then be
/// received by a corresponding listener.
pub struct ThreadedFlowsReporter<Session, ID> {
    /// Sender for the backlog queue.
    backlog_send: mpsc::Sender<(Session, ID)>
}

#[derive(Clone)]
struct ThreadedFlowEntry<Cred> {
    /// Send half of the message buffer.
    send: mpsc::Sender<(Vec<u8>, Option<Cred>)>,
    /// Condition variable used to signal readiness.
    cond: Weak<Condvar>
}

struct ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ChannelID>
where
    Sock: Socket + Sender + Receiver,
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
    flows:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry<Sock::MsgCred>>>>,
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
    backlog_send:
        mpsc::Sender<(AuthN::AuthNSession, StreamID<Addr, ID, Param>)>,
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
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    ChannelID: Clone + Display + Eq + Hash + Send {
    authn: AuthN,
    /// Sender for the backlog queue.  This should only be used by
    /// listener threads.
    backlog_send: mpsc::Sender<(
        AuthN::AuthNSession,
        StreamID<Xfrm::PeerAddr, ChannelID, Param>
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
    Sock: Socket + Sender + Receiver,
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
        AuthN::AuthNSession,
        StreamID<Xfrm::PeerAddr, ChannelID, Param>
    )>,
    /// Table holding existing flows.
    flows:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry<Sock::MsgCred>>>>,
    /// Negotiator for new flows.
    negotiator: Nego,
    /// Table of negotiator threads.
    negotiators:
        Arc<Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>>
}

/// An [OwnedFlowNegotiator] instance that simply passes the
/// underlying traffic splitter instance through.
///
/// This is used for channel types that do not need to perform any
/// actual negotiation.
#[derive(Clone, Default)]
pub struct PassthruNegotiator;

/// Errors that can occur for [flow](OwnedFlowsOutbound::flow) for
/// [ThreadedFlows].
#[derive(Clone, Debug)]
pub enum ThreadedFlowsFlowError {
    /// The flow for this address has already been taken.
    Taken,
    /// Mutex was poisoned.
    MutexPoison
}

/// Errors that can occur for [listen](OwnedFlowsInbound::listen) for
/// [ThreadedFlows].
pub enum ThreadedFlowsListenError {
    /// Listener thread was shut down.
    Shutdown,
    /// Mutex was poisoned.
    MutexPoison
}

impl<Xfrm, Addr> ScopedError for MultiFlowError<Xfrm, Addr>
where
    Addr: ScopedError,
    Xfrm: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            MultiFlowError::Addr { err } => err.scope(),
            MultiFlowError::Xfrm { err } => err.scope(),
            MultiFlowError::IO { err } => err.scope()
        }
    }
}

impl ScopedError for ThreadedFlowsListenError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            ThreadedFlowsListenError::Shutdown => ErrorScope::Shutdown,
            ThreadedFlowsListenError::MutexPoison => ErrorScope::Unrecoverable
        }
    }
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

impl<Flow, Nego, AuthN> ScopedError for FlowNegoAuthNError<Flow, Nego, AuthN>
where
    Flow: ScopedError,
    Nego: ScopedError,
    AuthN: ScopedError
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            FlowNegoAuthNError::AuthN { err } => err.scope(),
            FlowNegoAuthNError::Nego { err } => err.scope(),
            FlowNegoAuthNError::Flow { err } => err.scope(),
            FlowNegoAuthNError::AuthNFail => ErrorScope::External
        }
    }
}

impl<Addr> ScopedError for SingleFlowError<Addr>
where
    Addr: Display
{
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            SingleFlowError::WrongAddr { .. } => ErrorScope::Unrecoverable
        }
    }
}

impl<Flow, Nego, AuthN> RetryWhen for FlowNegoAuthNRetry<Flow, Nego, AuthN>
where
    Flow: RetryWhen,
    Nego: RetryWhen,
    AuthN: RetryWhen
{
    #[inline]
    fn when(&self) -> Instant {
        match self {
            FlowNegoAuthNRetry::AuthN { err } => err.when(),
            FlowNegoAuthNRetry::Nego { err } => err.when(),
            FlowNegoAuthNRetry::Flow { err } => err.when()
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
    F: Flow + Send
{
    type Flow = F;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate_outbound_nonblock(
        &self,
        inner: F
    ) -> Result<NonblockResult<Self::Flow, F>, Self::NegotiateError> {
        Ok(NonblockResult::Success(inner))
    }

    #[inline]
    fn negotiate_outbound(
        &self,
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
        &self,
        inner: F
    ) -> Result<NonblockResult<Self::Flow, F>, Self::NegotiateError> {
        Ok(NonblockResult::Success(inner))
    }

    #[inline]
    fn negotiate_inbound(
        &self,
        inner: F
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<Self::Flow>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }
}

impl<F> BorrowedFlowNegotiator<F> for PassthruNegotiator
where
    F: Flow
{
    type Flow<'a> = F;
    type NegotiateError = Infallible;

    #[inline]
    fn negotiate_outbound(
        &self,
        inner: F,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Self::Flow<'_>>>,
        Self::NegotiateError
    > {
        Ok(RetryResult::Success(inner))
    }

    #[inline]
    fn negotiate_inbound(
        &self,
        inner: F
    ) -> Result<
        RetryResult<Self::Flow<'_>, NegotiateRetry<Self::Flow<'_>>>,
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
        flow: Flow,
        backlog_send: mpsc::Sender<(
            AuthN::AuthNSession,
            StreamID<Addr, ID, Param>
        )>
    ) -> Result<(), Error> {
        if shutdown.is_live() {
            trace!(target: "flows-threaded-authn",
                   "trying authentication for {}",
                   id);

            // The negotiation succeeded; do authentication.
            match authn.session_authn(flow) {
                Ok(AuthNResult::Accept(session)) => {
                    info!(target: "flows-threaded-authn",
                          "stream {} authenticated as {}",
                          id, session.prin());

                    // Add it to the backlog.
                    backlog_send.send((session, id.clone())).map_err(|_| {
                        Error::new(ErrorKind::Other, "listen channel closed")
                    })
                }
                Ok(AuthNResult::Reject(_)) => {
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
    Sock: Socket + Sender + Receiver,
    Param: Clone + Display + Eq + Hash + Send,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    ID: Clone + Display + Eq + Hash + Send
{
    fn negotiate(
        id: &StreamID<Xfrm::PeerAddr, ID, Param>,
        authn: AuthN,
        negotiator: Nego,
        shutdown: ShutdownFlag,
        flow: ThreadedFlow<Sock, Xfrm>,
        backlog_send: mpsc::Sender<(
            AuthN::AuthNSession,
            StreamID<Xfrm::PeerAddr, ID, Param>
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
    AuthN::AuthNSession: 'static + Send,
    Xfrm: 'static + DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: 'static + Eq + Hash,
    Sock: 'static + Socket + Sender + Receiver,
    Sock::MsgCred: 'static + Send,
    Param: 'static + Clone + Display + Eq + Hash + Send,
    Nego: 'static
        + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>
        + Clone
        + Send
        + Sync,
    Nego::Flow: Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    fn negotiate(
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            AuthN::AuthNSession,
            StreamID<Xfrm::PeerAddr, ID, Param>
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
            Ok(NonblockResult::Success(flow)) => {
                trace!(target: "flows-threaded-listen",
                       "session negotiation did not require blocking");

                let id =
                    StreamID::new(addr.clone(), channel.clone(), param.clone());

                match authn.session_authn_nonblock(flow) {
                    Ok(NonblockResult::Success(AuthNResult::Accept(
                        session
                    ))) => {
                        info!(target: "far-channel-registry",
                              "stream {} authenticated as {}",
                              id, session.prin());

                        // Add it to the backlog.
                        backlog_send.send((session, id.clone())).map_err(|_| {
                            Error::new(
                                ErrorKind::Other,
                                "listen channel closed"
                            )
                        })
                    }
                    Ok(NonblockResult::Success(AuthNResult::Reject(_))) => {
                        info!(target: "far-channel-registry",
                              "stream {} failed authentication",
                              id);

                        Ok(())
                    }
                    Ok(NonblockResult::Fail(flow)) => {
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
            AuthN::AuthNSession,
            StreamID<Xfrm::PeerAddr, ID, Param>
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        ent: VacantEntry<Xfrm::PeerAddr, ThreadedFlowEntry<Sock::MsgCred>>,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        cred: Option<Sock::MsgCred>,
        msg: Vec<u8>
    ) -> Result<(), Error> {
        let (send, recv) = mpsc::channel();
        let cond = Arc::new(Condvar::new());

        trace!(target: "flows-threaded-listen",
               "buffering {} bytes to {}",
               msg.len(), addr);

        // Deliver the first message.
        send.send((msg, cred)).map_err(|_| {
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
            AuthN::AuthNSession,
            StreamID<Xfrm::PeerAddr, ID, Param>
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        ent: &mut OccupiedEntry<
            Xfrm::PeerAddr,
            ThreadedFlowEntry<Sock::MsgCred>
        >,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        cred: Option<Sock::MsgCred>,
        msg: Vec<u8>
    ) -> Result<(), Error> {
        let (send, recv) = mpsc::channel();
        let cond = Arc::new(Condvar::new());

        trace!(target: "flows-threaded-listen",
               "buffering {} bytes to {}",
               msg.len(), addr);

        send.send((msg, cred)).map_err(|_| {
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
        flows: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowEntry<Sock::MsgCred>>>
        >,
        socket: &Arc<Sock>,
        xfrm: &Arc<Mutex<Xfrm>>,
        authn: &AuthN,
        backlog_send: &mpsc::Sender<(
            AuthN::AuthNSession,
            StreamID<Xfrm::PeerAddr, ID, Param>
        )>,
        negotiator: &mut Nego,
        negotiators: &Arc<
            Mutex<HashMap<Xfrm::PeerAddr, ThreadedFlowsNegotiateEntry>>
        >,
        channel: &ID,
        param: &Param,
        addr: &Xfrm::PeerAddr,
        cred: Option<Sock::MsgCred>,
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
                    let res = match flow.cond.upgrade() {
                        Some(cond) => {
                            trace!(target: "flows-threaded-listen",
                                   concat!("buffering {} bytes to ",
                                           "existing flow to {}"),
                                   msg.len(), addr);

                            // Try to deliver the message.
                            let out = match flow.send.send((msg, cred)) {
                                // Done, we're good.
                                Ok(()) => None,
                                // The per-flow send buffer
                                // closed; recreate the flow.
                                Err(mpsc::SendError(payload)) => {
                                    debug!(target: "flows-threaded-listen",
                                           concat!("send buffer to {} ",
                                                   "closed, replacing"),
                                           addr);

                                    Some(payload)
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

                            Some((msg, cred))
                        }
                    };

                    match res {
                        Some((msg, cred)) => Self::replace_flow(
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
                            cred,
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
                        cred,
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
            let (n, addr, cred) = socket.recv_from(&mut msg)?;

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
                    cred,
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

impl<Sock, Nego, AuthN, Xfrm, ID> Clone
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlows {
            inner: self.inner.clone()
        }
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.inner.local_addr()
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> FlowsLocalAddr<Sock::Addr>
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Clone + Display + Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.as_ref().local_addr()
    }
}

impl<Sock, Xfrm> FlowsLocalAddr<Sock::Addr> for MultiFlows<'_, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<Sock, Xfrm> Credentials for SingleFlow<'_, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Cred = Xfrm::PeerAddr;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(Xfrm::PeerAddr::from(self.addr.clone())))
        } else {
            Ok(None)
        }
    }
}

impl<Sock, Xfrm> FlowsLocalAddr<Sock::Addr> for SingleFlow<'_, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn local_addr(&self) -> Result<Sock::Addr, Error> {
        self.socket.local_addr()
    }
}

impl<'a, Sock, Xfrm> BorrowedFlowsCreate<'a, Sock, Xfrm>
    for MultiFlows<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type CreateError = Infallible;
    type CreateParam = ();

    #[inline]
    fn create(
        socket: Sock,
        xfrm: Xfrm,
        _param: Self::CreateParam
    ) -> Result<Self, Self::CreateError> {
        Ok(MultiFlows {
            lifetime: PhantomData,
            socket: socket,
            xfrm: xfrm
        })
    }
}

impl<'a, Sock, Xfrm> BorrowedFlowsCreate<'a, Sock, Xfrm>
    for SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type CreateError = <Xfrm::LocalAddr as TryFrom<Xfrm::PeerAddr>>::Error;
    type CreateParam = Xfrm::PeerAddr;

    #[inline]
    fn create(
        socket: Sock,
        xfrm: Xfrm,
        param: Self::CreateParam
    ) -> Result<Self, Self::CreateError> {
        let addr = Sock::Addr::try_from(param)?;

        Ok(SingleFlow {
            lifetime: PhantomData,
            socket: socket,
            addr: addr,
            xfrm: xfrm
        })
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> OwnedFlows
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    AuthN::AuthNSession: 'static + Send,
    Nego: 'static + Clone + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    Nego::Flow: Send,
    Xfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<Socket = Sock>
        + Send,
    Xfrm: 'static + DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Xfrm::Param: Clone + Display + Eq + Hash + Send,
    Sock: 'static + Socket + Sender + Receiver + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type Flow = ThreadedFlow<Sock, Xfrm>;
}

impl<Sock, Nego, AuthN, Xfrm, ID> OwnedFlowsCreate<Sock, Nego, AuthN, Xfrm>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    AuthN::AuthNSession: 'static + Send,
    Nego: 'static + Clone + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    Nego::Flow: Send,
    Xfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<Socket = Sock>
        + Send,
    Xfrm: 'static + DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Xfrm::Param: Clone + Display + Eq + Hash + Send,
    Sock: 'static + Socket + Sender + Receiver + Send,
    Sock::MsgCred: 'static + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type ChannelID = ID;
    type CreateError = Xfrm::ParamError;
    type CreateParam = ThreadedFlowsParams;
    type Reporter = ThreadedFlowsReporter<
        AuthN::AuthNSession,
        StreamID<Xfrm::PeerAddr, ID, Xfrm::Param>
    >;

    #[inline]
    fn create_with_reporter(
        id: ID,
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        reporter: Self::Reporter,
        xfrm: Xfrm,
        param: ThreadedFlowsParams
    ) -> Result<Self, Self::CreateError> {
        let inner =
            Arc::<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
            ::create_with_reporter(
                id, socket, authn, negotiator, reporter, xfrm, param
            )?;

        Ok(ThreadedFlows { inner: inner })
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID> OwnedFlows
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    AuthN::AuthNSession: 'static + Send,
    Nego: 'static + Clone + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    Nego::Flow: Send,
    Xfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<Socket = Sock>
        + Send,
    Xfrm::PeerAddr: 'static + Eq + Hash,
    Xfrm::Param: Clone + Display + Eq + Hash + Send,
    Sock: 'static + Socket + Sender + Receiver + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type Flow = ThreadedFlow<Sock, Xfrm>;
}

impl<Sock, Nego, AuthN, Xfrm, ID> OwnedFlowsCreate<Sock, Nego, AuthN, Xfrm>
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: 'static + Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    AuthN::AuthNSession: 'static + Send,
    Nego: 'static + Clone + OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>>,
    Nego::Flow: Send,
    Xfrm: 'static
        + DatagramXfrm<LocalAddr = Sock::Addr>
        + DatagramXfrmCreateParam<Socket = Sock>
        + Send,
    Xfrm::PeerAddr: 'static + Eq + Hash,
    Xfrm::Param: Clone + Display + Eq + Hash + Send,
    Sock: 'static + Socket + Sender + Receiver + Send,
    Sock::MsgCred: 'static + Send,
    ID: 'static + Clone + Display + Eq + Hash + Send
{
    type ChannelID = ID;
    type CreateError = Xfrm::ParamError;
    type CreateParam = ThreadedFlowsParams;
    type Reporter = ThreadedFlowsReporter<
        AuthN::AuthNSession,
        StreamID<Xfrm::PeerAddr, ID, Xfrm::Param>
    >;

    #[inline]
    fn create_with_reporter(
        id: ID,
        socket: Sock,
        authn: AuthN,
        negotiator: Nego,
        reporter: Self::Reporter,
        xfrm: Xfrm,
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
            Xfrm,
            Nego,
            Xfrm::Param,
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
            negotiator: negotiator.clone()
        };

        let join = spawn(|| listener.run());

        Ok(Arc::new(ThreadedFlowsInner {
            id: PhantomData,
            authn: authn,
            nego: negotiator,
            negotiators: negotiators,
            listener: Some(join),
            shutdown: shutdown,
            xfrm: xfrm,
            flows: flows,
            socket: socket
        }))
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutbound<AuthN::AuthNSession, Xfrm::PeerAddr>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    type FlowError = FlowNegoAuthNError<
        ThreadedFlowsFlowError,
        Nego::NegotiateError,
        AuthN::Error
    >;

    #[inline]
    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<AuthN::AuthNSession>, Self::FlowError> {
        self.inner.flow(addr, endpoint)
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutboundRaw<ThreadedFlow<Sock, Xfrm>, Xfrm::PeerAddr>
    for ThreadedFlows<Sock, Nego, AuthN, Xfrm, ID>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    type RawFlowError = ThreadedFlowsFlowError;

    #[inline]
    fn flow_raw(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<ThreadedFlow<Sock, Xfrm>>, Self::RawFlowError> {
        self.inner.flow_raw(addr, endpoint)
    }
}

impl<Cred> Drop for ThreadedFlowEntry<Cred> {
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
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
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

impl<Session, Addr> Clone for ThreadedFlowsReporter<Session, Addr> {
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlowsReporter {
            backlog_send: self.backlog_send.clone()
        }
    }
}
// impl<Session, Msg, Codec, Addr> PullStreamListener<Msg>
// for ThreadedFlowsPullStreamListener<Session, Msg, Codec, Addr>
// where
// Codec: Clone + DatagramCodec<Msg> + Send,
// F: Credentials + Flow + Read + Write + Send,
// Addr: Clone + Display + Eq + Hash,
// Prin: Clone + Display + Eq + Hash,
// Msg: Send
// {
// type Addr = Addr;
// type ListenError = ThreadedFlowsListenError;
// type Prin = Prin;
// type Stream = DatagramCodecStream<Msg, F, Codec>;
//
// #[inline]
// fn listen(
// &mut self
// ) -> Result<
// RetryResult<(Self::Stream, Self::Addr, Self::Prin)>,
// Self::ListenError
// > {
// Ok(self.inner.listen()?.map(|(flow, addr, prin)| {
// (
// DatagramCodecStream::create(self.codec.clone(), flow),
// addr,
// prin
// )
// }))
// }
// }
impl<Session, Msg, Codec, Addr>
    ThreadedFlowsPullStreamListener<Session, Msg, Codec, Addr>
where
    Codec: Clone + DatagramCodec<Msg>,
    Addr: Clone + Display + Eq + Hash
{
    #[inline]
    pub fn create(
        listener: ThreadedFlowsListener<Session, Addr>,
        codec: Codec
    ) -> Self {
        ThreadedFlowsPullStreamListener {
            msg: PhantomData,
            inner: listener,
            codec: codec
        }
    }
}

impl<Session, Msg, Codec, Addr> Clone
    for ThreadedFlowsPullStreamListener<Session, Msg, Codec, Addr>
where
    Session: Clone,
    Codec: Clone + DatagramCodec<Msg>,
    Addr: Clone + Display + Eq + Hash
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

impl<Session, Addr> Clone for ThreadedFlowsListener<Session, Addr>
where
    Session: Clone,
    Addr: Clone + Display + Eq + Hash
{
    #[inline]
    fn clone(&self) -> Self {
        ThreadedFlowsListener {
            backlog_recv: self.backlog_recv.clone()
        }
    }
}

impl<Session, Addr> ThreadedFlowsListener<Session, Addr>
where
    Addr: Clone + Display + Eq + Hash
{
    #[inline]
    pub fn new() -> (Self, ThreadedFlowsReporter<Session, Addr>) {
        let (send, recv) = mpsc::channel();

        (
            ThreadedFlowsListener {
                backlog_recv: Arc::new(Mutex::new(recv))
            },
            ThreadedFlowsReporter { backlog_send: send }
        )
    }
}

impl<Session, Addr> OwnedFlowsInbound<Session, Addr>
    for ThreadedFlowsListener<Session, Addr>
where
    Addr: Clone + Display + Eq + Hash
{
    type ListenError = ThreadedFlowsListenError;

    #[inline]
    fn listen(
        &mut self
    ) -> Result<RetryResult<(Session, Addr)>, ThreadedFlowsListenError> {
        trace!(target: "owned-flows-listener",
               "listening for incoming flow");

        match self.backlog_recv.lock() {
            Ok(guard) => guard
                .recv()
                .map(RetryResult::Success)
                .map_err(|_| ThreadedFlowsListenError::Shutdown),
            Err(_) => Err(ThreadedFlowsListenError::MutexPoison)
        }
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutbound<AuthN::AuthNSession, Xfrm::PeerAddr>
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    type FlowError = FlowNegoAuthNError<
        ThreadedFlowsFlowError,
        Nego::NegotiateError,
        AuthN::Error
    >;

    fn flow(
        &mut self,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<AuthN::AuthNSession>, Self::FlowError> {
        let flow = match self
            .flow_raw(addr, endpoint)
            .map_err(|err| FlowNegoAuthNError::Flow { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry));
            }
        };
        let flow = match self
            .nego
            .negotiate_outbound(flow, endpoint)
            .map_err(|err| FlowNegoAuthNError::Nego { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry.when));
            }
        };

        match self
            .authn
            .session_authn(flow)
            .map_err(|err| FlowNegoAuthNError::AuthN { err: err })?
        {
            AuthNResult::Accept(session) => Ok(RetryResult::Success(session)),
            AuthNResult::Reject(_) => Err(FlowNegoAuthNError::AuthNFail)
        }
    }
}

impl<Sock, Nego, AuthN, Xfrm, ID>
    OwnedFlowsOutboundRaw<ThreadedFlow<Sock, Xfrm>, Xfrm::PeerAddr>
    for Arc<ThreadedFlowsInner<Sock, Nego, AuthN, Xfrm, ID>>
where
    AuthN: Clone + SessionAuthN<Nego::Flow> + Send + Sync,
    Nego: OwnedFlowNegotiator<ThreadedFlow<Sock, Xfrm>> + Send + Sync,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr> + Send,
    Xfrm::PeerAddr: Eq + Hash,
    Sock: Socket + Sender + Receiver,
    ID: Clone + Display + Eq + Hash + Send
{
    type RawFlowError = ThreadedFlowsFlowError;

    fn flow_raw(
        &mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<ThreadedFlow<Sock, Xfrm>>, Self::RawFlowError> {
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

                        Ok(RetryResult::Success(flow))
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

                    Ok(RetryResult::Success(flow))
                }
            },
            Err(_) => Err(ThreadedFlowsFlowError::MutexPoison)
        }
    }
}

impl<'a, Sock, Xfrm>
    BorrowedFlowsRaw<'a, MultiFlow<'a, Sock, Xfrm>, Xfrm::PeerAddr>
    for MultiFlows<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type RawFlowError = <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error;
    type RawListenError = MultiFlowError<
        Xfrm::Error,
        <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error
    >;

    #[inline]
    fn listen_raw(
        &'a mut self
    ) -> Result<
        RetryResult<(MultiFlow<'a, Sock, Xfrm>, Xfrm::PeerAddr)>,
        Self::RawListenError
    > {
        let mtu = match self.socket.mtu() {
            Some(mtu) => mtu,
            None => {
                warn!(target: "flows-multi",
                      "could not obtain MTU, defaulting to 1536");

                1536
            }
        };
        let mut buf = vec![0; mtu];
        let (n, addr) = self
            .socket
            .peek_from(&mut buf)
            .map_err(|err| MultiFlowError::IO { err: err })?;
        let (_, addr) = self
            .xfrm
            .unwrap(&mut buf[..n], addr)
            .map_err(|err| MultiFlowError::Xfrm { err: err })?;
        let sockaddr = Xfrm::LocalAddr::try_from(addr.clone())
            .map_err(|err| MultiFlowError::Addr { err: err })?;

        Ok(RetryResult::Success((
            MultiFlow {
                socket: &mut self.socket,
                addr: sockaddr,
                xfrm: &mut self.xfrm
            },
            addr
        )))
    }

    fn flow_raw(
        &'a mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<MultiFlow<'a, Sock, Xfrm>>, Self::RawFlowError>
    {
        let addr = Sock::Addr::try_from(addr)?;

        Ok(RetryResult::Success(MultiFlow {
            socket: &mut self.socket,
            xfrm: &mut self.xfrm,
            addr: addr
        }))
    }
}

impl<'a, Sock, Xfrm> BorrowedFlowsFlow for MultiFlows<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Flow = MultiFlow<'a, Sock, Xfrm>;
}

impl<'a, Sock, Nego, AuthN, Xfrm> BorrowedFlows<'a, Nego, AuthN, Xfrm::PeerAddr>
    for MultiFlows<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Nego: 'a + BorrowedFlowNegotiator<MultiFlow<'a, Sock, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Xfrm::Error: ScopedError,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type FlowError = FlowNegoAuthNError<
        Self::RawFlowError,
        Nego::NegotiateError,
        AuthN::Error
    >;
    type ListenError = FlowNegoAuthNError<
        Self::RawListenError,
        Nego::NegotiateError,
        AuthN::Error
    >;

    fn listen(
        &'a mut self,
        nego: &'a Nego,
        authn: &AuthN
    ) -> Result<
        RetryResult<(AuthN::AuthNSession, Xfrm::PeerAddr)>,
        Self::ListenError
    > {
        let (flow, addr) = match self
            .listen_raw()
            .map_err(|err| FlowNegoAuthNError::Flow { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry));
            }
        };
        let flow = match nego
            .negotiate_inbound(flow)
            .map_err(|err| FlowNegoAuthNError::Nego { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry.when));
            }
        };

        match authn
            .session_authn(flow)
            .map_err(|err| FlowNegoAuthNError::AuthN { err: err })?
        {
            AuthNResult::Accept(session) => {
                Ok(RetryResult::Success((session, addr)))
            }
            AuthNResult::Reject(_) => Err(FlowNegoAuthNError::AuthNFail)
        }
    }

    fn flow(
        &'a mut self,
        nego: &'a Nego,
        authn: &AuthN,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<AuthN::AuthNSession>, Self::FlowError> {
        let flow = match self
            .flow_raw(addr, endpoint)
            .map_err(|err| FlowNegoAuthNError::Flow { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry));
            }
        };
        let flow = match nego
            .negotiate_outbound(flow, endpoint)
            .map_err(|err| FlowNegoAuthNError::Nego { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry.when));
            }
        };

        match authn
            .session_authn(flow)
            .map_err(|err| FlowNegoAuthNError::AuthN { err: err })?
        {
            AuthNResult::Accept(session) => Ok(RetryResult::Success(session)),
            AuthNResult::Reject(_) => Err(FlowNegoAuthNError::AuthNFail)
        }
    }
}

impl<'a, Sock, Xfrm>
    BorrowedFlowsRaw<'a, &'a mut SingleFlow<'a, Sock, Xfrm>, Xfrm::PeerAddr>
    for SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type RawFlowError = SingleFlowError<Xfrm::PeerAddr>;
    type RawListenError = Infallible;

    #[inline]
    fn listen_raw(
        &'a mut self
    ) -> Result<
        RetryResult<(&'a mut SingleFlow<'a, Sock, Xfrm>, Xfrm::PeerAddr)>,
        Self::RawListenError
    > {
        let addr = Xfrm::PeerAddr::from(self.addr.clone());

        Ok(RetryResult::Success((self, addr)))
    }

    fn flow_raw(
        &'a mut self,
        addr: Xfrm::PeerAddr,
        _endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<&'a mut SingleFlow<'a, Sock, Xfrm>>,
        Self::RawFlowError
    > {
        let expected = Xfrm::PeerAddr::from(self.addr.clone());

        if expected == addr {
            Ok(RetryResult::Success(self))
        } else {
            Err(SingleFlowError::WrongAddr {
                expected: expected,
                actual: addr
            })
        }
    }
}

impl<'a, Sock, Xfrm> BorrowedFlowsFlow for SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Flow = &'a mut SingleFlow<'a, Sock, Xfrm>;
}

impl<'a, Sock, Nego, AuthN, Xfrm> BorrowedFlows<'a, Nego, AuthN, Xfrm::PeerAddr>
    for SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Nego: 'a + BorrowedFlowNegotiator<&'a mut SingleFlow<'a, Sock, Xfrm>>,
    AuthN: SessionAuthN<Nego::Flow<'a>>,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type FlowError = FlowNegoAuthNError<
        SingleFlowError<Xfrm::PeerAddr>,
        Nego::NegotiateError,
        AuthN::Error
    >;
    type ListenError =
        FlowNegoAuthNError<Infallible, Nego::NegotiateError, AuthN::Error>;

    fn listen(
        &'a mut self,
        nego: &'a Nego,
        authn: &AuthN
    ) -> Result<
        RetryResult<(AuthN::AuthNSession, Xfrm::PeerAddr)>,
        Self::ListenError
    > {
        let (flow, addr) = match self
            .listen_raw()
            .map_err(|err| FlowNegoAuthNError::Flow { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry));
            }
        };
        let flow = match nego
            .negotiate_inbound(flow)
            .map_err(|err| FlowNegoAuthNError::Nego { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry.when));
            }
        };

        match authn
            .session_authn(flow)
            .map_err(|err| FlowNegoAuthNError::AuthN { err: err })?
        {
            AuthNResult::Accept(session) => {
                Ok(RetryResult::Success((session, addr)))
            }
            AuthNResult::Reject(_) => Err(FlowNegoAuthNError::AuthNFail)
        }
    }

    fn flow(
        &'a mut self,
        nego: &'a Nego,
        authn: &AuthN,
        addr: Xfrm::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<AuthN::AuthNSession>, Self::FlowError> {
        let flow = match self
            .flow_raw(addr, endpoint)
            .map_err(|err| FlowNegoAuthNError::Flow { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry));
            }
        };
        let flow = match nego
            .negotiate_outbound(flow, endpoint)
            .map_err(|err| FlowNegoAuthNError::Nego { err: err })?
        {
            RetryResult::Success(out) => out,
            RetryResult::Retry(retry) => {
                return Ok(RetryResult::Retry(retry.when));
            }
        };

        match authn
            .session_authn(flow)
            .map_err(|err| FlowNegoAuthNError::AuthN { err: err })?
        {
            AuthNResult::Accept(session) => Ok(RetryResult::Success(session)),
            AuthNResult::Reject(_) => Err(FlowNegoAuthNError::AuthNFail)
        }
    }
}

impl<Sock, Xfrm> Credentials for MultiFlow<'_, Sock, Xfrm>
where
    Sock::Addr: Clone + Eq,
    Sock: Receiver + Sender,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Cred = Xfrm::PeerAddr;
    type CredError = <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Self::CredError> {
        if self.socket.allow_session_addr_creds() {
            Ok(Some(self.peer_addr()))
        } else {
            Ok(None)
        }
    }
}

impl<Sock, Xfrm> Flow for MultiFlow<'_, Sock, Xfrm>
where
    Sock::Addr: Clone + Eq,
    Sock: Receiver + Sender,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type LocalAddr = Xfrm::LocalAddr;
    type PeerAddr = Xfrm::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        Xfrm::PeerAddr::from(self.addr.clone())
    }
}

impl<'a, Sock, Xfrm> Credentials for &'a mut SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Cred = Xfrm::PeerAddr;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        let addr = Xfrm::PeerAddr::from(self.addr.clone());

        if self.socket.allow_session_addr_creds() {
            Ok(Some(addr))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Xfrm> Credentials for &'a SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type Cred = Xfrm::PeerAddr;
    type CredError = Infallible;

    #[inline]
    fn creds(&self) -> Result<Option<Xfrm::PeerAddr>, Infallible> {
        let addr = Xfrm::PeerAddr::from(self.addr.clone());

        if self.socket.allow_session_addr_creds() {
            Ok(Some(addr))
        } else {
            Ok(None)
        }
    }
}

impl<'a, Sock, Xfrm> Flow for &'a mut SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    type LocalAddr = Xfrm::LocalAddr;
    type PeerAddr = Xfrm::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        Xfrm::PeerAddr::from(self.addr.clone())
    }
}

impl<'a, Sock, Xfrm> Read for &'a mut SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        let mut nbytes = 0;

        while {
            let (n, peer, _) = self.socket.recv_from(buf)?;

            if self.addr != peer {
                warn!(target: "far-multi-flow",
                      "discarding {} bytes from {} (expected {})",
                      n, peer, self.addr);

                true
            } else {
                match self.xfrm.unwrap(&mut buf[..n], peer) {
                    Ok((n, _)) => {
                        nbytes = n;
                    }
                    Err(err) => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            err.to_string()
                        ))
                    }
                }

                false
            }
        } {}

        Ok(nbytes)
    }
}

impl<'a, Sock, Xfrm> Write for &'a mut SingleFlow<'a, Sock, Xfrm>
where
    Sock: Socket + Sender + Receiver,
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        let addr = Xfrm::PeerAddr::from(self.addr.clone());

        match self.xfrm.wrap(buf, addr) {
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

impl<Sock, Xfrm> Read for MultiFlow<'_, Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Sock::Addr: Clone + Eq,
    Sock: Receiver,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        let (n, peer, _) = self.socket.recv_from(buf)?;

        if self.addr != peer {
            warn!(target: "far-multi-flow",
                  "discarding {} bytes from {} (expected {})",
                  n, peer, self.addr);

            Err(Error::new(
                ErrorKind::Other,
                "discarded {} bytes from wrong address {}"
            ))
        } else {
            match self.xfrm.unwrap(&mut buf[..n], peer) {
                Ok((n, _)) => Ok(n),
                Err(err) => Err(Error::new(ErrorKind::Other, err.to_string()))
            }
        }
    }
}

impl<Sock, Xfrm> Write for MultiFlow<'_, Sock, Xfrm>
where
    Xfrm: DatagramXfrm<LocalAddr = Sock::Addr>,
    Sock::Addr: Clone + Eq,
    Sock: Sender,
    Xfrm::PeerAddr: From<Sock::Addr>,
    Sock::Addr: TryFrom<Xfrm::PeerAddr>,
    <Sock::Addr as TryFrom<Xfrm::PeerAddr>>::Error: Display + ScopedError
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        let addr = Xfrm::PeerAddr::from(self.addr.clone());

        match self.xfrm.wrap(buf, addr) {
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

impl<Flow, Nego, AuthN> Display for FlowNegoAuthNError<Flow, Nego, AuthN>
where
    Flow: Display,
    Nego: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            FlowNegoAuthNError::AuthN { err } => err.fmt(f),
            FlowNegoAuthNError::Nego { err } => err.fmt(f),
            FlowNegoAuthNError::Flow { err } => err.fmt(f),
            FlowNegoAuthNError::AuthNFail => write!(f, "authentication failed")
        }
    }
}

impl<Addr> Display for SingleFlowError<Addr>
where
    Addr: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SingleFlowError::WrongAddr { expected, actual } => write!(
                f,
                "wrong address: expected {}, actual {}",
                expected, actual
            )
        }
    }
}

impl<Xfrm, Addr> Display for MultiFlowError<Xfrm, Addr>
where
    Xfrm: Display,
    Addr: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            MultiFlowError::Addr { err } => err.fmt(f),
            MultiFlowError::Xfrm { err } => err.fmt(f),
            MultiFlowError::IO { err } => err.fmt(f)
        }
    }
}
