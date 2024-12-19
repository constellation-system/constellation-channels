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

//! Common structure for managing [FarChannel](crate::far::FarChannel)
//! instances.
//!
//! The [FarChannelRegistry] maintains a set of
//! [FarChannel](crate::far::FarChannel) instances, and manages the
//! creation of flow instances through the necessary processes.  This
//! can be used to allow a set of configurable channel options to be
//! created for a particular application or domain, which can then be
//! referenced by name to create flows to specific endpoints.
use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread::sleep;
use std::time::Instant;
use std::vec::IntoIter;

use constellation_auth::authn::AuthNResult;
use constellation_auth::authn::SessionAuthN;
use constellation_common::codec::DatagramCodec;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Socket;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_common::sched::Policy;
use constellation_streams::addrs::Addrs;
use constellation_streams::channels::ChannelParam;
use constellation_streams::channels::Channels;
use constellation_streams::channels::ChannelsCreate;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::stream::StreamID;
use constellation_streams::stream::StreamReporter;
use constellation_streams::stream::ThreadedStream;
use log::debug;
use log::info;
use log::trace;
use log::warn;

use crate::addrs::SocketAddrPolicy;
use crate::config::AddrKind;
use crate::config::AddrsConfig;
use crate::config::ChannelRegistryChannelsConfig;
use crate::config::ChannelRegistryConfig;
use crate::far::flows::CreateOwnedFlows;
use crate::far::flows::Flows;
use crate::far::flows::OwnedFlows;
use crate::far::flows::OwnedFlowsNegotiator;
use crate::far::AcquiredResolver;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlowsError;
use crate::far::FarChannelOwnedFlows;
use crate::resolve::cache::NSNameCacheError;
use crate::resolve::cache::NSNameCachesCtx;

/// Trait for context objects that provide access to a [FarChannelRegistry].
pub trait FarChannelRegistryCtx<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::CreateParam: Clone + Default,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
    /// Get a reference to the far channel registry.
    fn far_channel_registry(
        &mut self
    ) -> Arc<FarChannelRegistry<Channel, F, AuthN, Xfrm>>;
}

/// Newtype wrapper for IDs created to refer to specific channels.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FarChannelRegistryID(usize);

/// Handle for one live [Flows] instance.
///
/// This is capable of being shared between the thread controlling the
/// registry, and a listener thread.
#[derive(Clone)]
struct RegistryFlows<Owned>
where
    Owned: OwnedFlows {
    flows: Arc<Mutex<Option<Owned>>>,
    retry: Arc<RwLock<RegistryFlowsRetry>>
}

struct RegistryFlowsRetry {
    nfailures: usize,
    retry_when: Instant
}

/// Portion of a registry entry that depends on an acquired value.
///
/// This exists to resolve a single acquired value into a set of
/// addresses, and keep that updated.
struct RegistryAcquired<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm>,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve {
    /// Acquired value from the channel.
    acquired: Channel::Acquired,
    /// Resolver generated by the acquired value.
    resolver: AcquiredResolver<Channel::Param>,
    /// Current set of [Flows].
    flows: HashMap<Channel::Param, RegistryFlows<Channel::Owned>>
}

/// Entry in the registry for a single channel.
struct RegistryEntry<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm>,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve {
    /// Base [FarChannel](crate::far::FarChannel) object.
    channel: Channel,
    /// Acquired value and flows, if a value has been acquired.
    acquired: RetryResult<RegistryAcquired<Channel, F, AuthN, Xfrm>>,
    /// Retry configuration.
    retry: Retry
}

/// Structure for managing a collection of
/// [FarChannel](crate::far::FarChannel)s.
///
/// This structure provides two primary functions:
///
///  - Associating [FarChannel](crate::far::FarChannel)s with a common name, and
///    a [FarChannelRegistryID] that can be used to reference it.
///
///  - Manaching most of the process of creating flows from a
///    [FarChannel](crate::far::FarChannel) (see documentation for details).
///
/// This trait provides access to the names and IDs.  For flow
/// creation, see [FarChannelRegistryChannels].
pub struct FarChannelRegistry<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
    /// Config for creating resolvers.
    resolve_config: AddrsConfig,
    authn: AuthN,
    reporter: F::Reporter,
    flows_param: F::CreateParam,
    xfrm_param: Xfrm::CreateParam,
    policy: SocketAddrPolicy,
    /// Map from names to `FarChannelRegistryID`s.
    ids: HashMap<String, FarChannelRegistryID>,
    /// Reverse map from `FarChannelRegistryID`s to names.
    names: Vec<String>,
    /// Array of registry entries for each channel.
    channels: Vec<Arc<RwLock<RegistryEntry<Channel, F, AuthN, Xfrm>>>>
}

/// [Channels] instance based on [FarChannelRegistry].
///
/// This type is likely to be merged with [FarChannelRegistry] in the
/// future.
pub struct FarChannelRegistryChannels<
    Msg,
    Codec,
    Reporter,
    Channel,
    F,
    AuthN,
    Xfrm
> where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Codec: Clone + DatagramCodec<Msg> + Send,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Reporter:
        StreamReporter<
            Stream = ThreadedStream<
                DatagramCodecStream<
                    Msg,
                    <Channel::Owned as OwnedFlows>::Flow,
                    Codec
                >
            >,
            Src = StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                FarChannelRegistryID,
                Channel::Param
            >,
            Prin = <AuthN as SessionAuthN<
                <Channel::Owned as OwnedFlows>::Flow
            >>::Prin
        >,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq {
    msg: PhantomData<Msg>,
    /// Reference to the registry.
    registry: Arc<FarChannelRegistry<Channel, F, AuthN, Xfrm>>,
    /// List of channel names to get.
    ids: Vec<FarChannelRegistryID>,
    reporter: Reporter,
    codec: Codec
}

/// Errors that can occur when acquiring on channels managed by
/// [FarChannelRegistry].
#[derive(Debug)]
pub enum RegistryAcquireError<Acquire, Resolver, Flows, Wrap> {
    Acquire {
        err: Acquire
    },
    Resolver {
        err: Resolver
    },
    Refresh {
        err: RegistryRefreshError<Flows, Wrap>
    }
}

/// Errors that can occur when refreshing parameters for channels
/// managed by [FarChannelRegistry].
#[derive(Debug)]
pub enum RegistryRefreshError<Flows, Wrap> {
    NameCaches { err: NSNameCacheError },
    Flows { err: Flows },
    Wrap { err: Wrap },
    NoValidAddrs
}

/// Errors that can occur when obtaining [Flows] for channels managed
/// by [FarChannelRegistry].
#[derive(Debug)]
pub enum RegistryFlowsError<Acquire> {
    Acquire { err: Acquire },
    ParamNotFound,
    MutexPoison
}

/// Errors that can occur when creating a [FarChannelRegistry].
#[derive(Debug)]
pub enum FarChannelRegistryCreateError<Channel> {
    Create { err: Channel },
    DuplicateID { name: String }
}

/// Errors that can occur when creating a [FarChannelRegistryChannels].
#[derive(Debug)]
pub enum FarChannelRegistryChannelsCreateError<Codec> {
    Codec { err: Codec },
    Missing { name: String }
}

/// Errors that can occur when acquiring on channels managed by
/// [FarChannelRegistry].
#[derive(Debug)]
pub enum FarChannelRegistryAcquireError<Acquire> {
    Acquire { err: Acquire },
    MutexPoison
}

/// Errors that can occur when obtaining [Flows] for channels managed
/// by [FarChannelRegistry].
#[derive(Debug)]
pub enum FarChannelRegistryFlowsError<Acquire> {
    Acquire {
        err: FarChannelRegistryAcquireError<Acquire>
    },
    ChannelNotFound,
    MutexPoison
}

/// Errors that can occur when obtaining a flow for channels managed
/// by [FarChannelRegistry].
#[derive(Debug)]
pub enum FarChannelRegistryFlowError<Acquire, Flow, Auth> {
    Acquire { err: Acquire },
    Flow { err: Flow },
    Auth { err: Auth },
    AuthNFailed,
    MutexPoison
}

/// Errors that can occur when obtaining a stream for channels managed
/// by [FarChannelRegistry].
#[derive(Debug)]
pub enum FarChannelRegistryStreamError<Acquire, Flow, Report, Auth> {
    Flow {
        err: FarChannelRegistryFlowError<Acquire, Flow, Auth>
    },
    Report {
        err: Report
    }
}

struct RegistryMutexPoison;

enum ReadOnlyResult<T> {
    Success(T),
    NeedsWrite
}

/// Placeholder for when read-only versions fail.
#[derive(Debug)]
pub enum ReadOnlyErr {
    NotFound,
    MutexPoison
}

impl<Owned> RegistryFlows<Owned>
where
    Owned: OwnedFlows
{
    /// Create a new `RegistryFlows` around `flows`.
    #[inline]
    pub fn new(flows: Owned) -> Self {
        RegistryFlows {
            flows: Arc::new(Mutex::new(Some(flows))),
            retry: Arc::new(RwLock::new(RegistryFlowsRetry {
                nfailures: 0,
                retry_when: Instant::now()
            }))
        }
    }
}

impl<Channel, F, AuthN, Xfrm> RegistryAcquired<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm>,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq
{
    /// Check to see if a refresh is needed.
    fn needs_refresh(&self) -> bool {
        match &self.resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver } => resolver.needs_refresh(),
            _ => false
        }
    }

    fn next_refresh(&self) -> Option<Instant> {
        match &self.resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver } => resolver.refresh_when(),
            _ => None
        }
    }

    /// Refresh the addresses and update all [Flows], if needed.
    ///
    /// The [RefreshResult] reports all new addresses, if a refresh
    /// happens.
    fn refresh_nonblock(
        &mut self,
        id: &FarChannelRegistryID,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<(Option<Vec<Channel::Param>>, Option<Instant>)>,
        RegistryRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    > {
        match &mut self.resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver }
                if resolver.needs_refresh() =>
            {
                resolver
                    .addrs()
                    .map_err(|err| RegistryRefreshError::NameCaches {
                        err: err
                    })?
                    .map_ok(|(resolved, next_refresh)| {
                        trace!(target: "far-channel-registry",
                           "refreshing addresses for registry entry");

                        let mut filtered =
                            HashMap::with_capacity(self.flows.len());

                        for (addr, _, _) in resolved {
                            if policy.check(&addr) {
                                trace!(target: "far-channel-registry",
                                   "keeping address: {}",
                                   addr);

                                let addr = self.acquired.wrap(addr).map_err(
                                    |err| RegistryRefreshError::Wrap {
                                        err: err
                                    }
                                )?;
                                // Only create a new flows if there
                                // isn't one already in existence.
                                let flows = match self.flows.remove(&addr) {
                                    Some(flows) => {
                                        trace!(target: "far-channel-registry",
                                           "retaining flows for {}",
                                           addr);

                                        flows
                                    }
                                    None => {
                                        debug!(target: "far-channel-registry",
                                           "establishing flows for {}",
                                           addr);

                                        let xfrm =
                                            Xfrm::create(&addr, xfrm_param);

                                        let flows = channel
                                            .owned_flows(
                                                *id,
                                                addr.clone(),
                                                xfrm,
                                                authn.clone(),
                                                reporter.clone(),
                                                flows_param.clone()
                                            )
                                            .map_err(|err| {
                                                RegistryRefreshError::Flows {
                                                    err: err
                                                }
                                            })?;

                                        RegistryFlows::new(flows)
                                    }
                                };

                                filtered.insert(addr, flows);
                            } else {
                                debug!(target: "far-channel-registry",
                                   "discarding address {} of unknown type",
                                   addr);
                            }
                        }

                        if filtered.is_empty() {
                            Err(RegistryRefreshError::NoValidAddrs)
                        } else {
                            let out = filtered.keys().cloned().collect();

                            // Replace the flows.
                            filtered.shrink_to_fit();
                            self.flows = filtered;

                            Ok((Some(out), next_refresh))
                        }
                    })
            }
            // Only a resolver can refresh.  Everything else is trivial.
            _ => Ok(RetryResult::Success((None, self.next_refresh())))
        }
    }

    /// Try to obtain a snapshot without performing any read
    /// operations.
    fn try_snapshot_addrs_readonly(
        &self
    ) -> ReadOnlyResult<(Vec<Channel::Param>, Option<Instant>)> {
        if !self.needs_refresh() {
            ReadOnlyResult::Success((
                self.flows.keys().cloned().collect(),
                self.next_refresh()
            ))
        } else {
            ReadOnlyResult::NeedsWrite
        }
    }

    /// Obtain a snapshot of the current address set.
    ///
    /// The result will also indicate whether a refresh occurred.
    fn snapshot_addrs_nonblock(
        &mut self,
        id: &FarChannelRegistryID,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        RegistryRefreshError<
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    > {
        Ok(self
            .refresh_nonblock(
                id,
                channel,
                policy,
                authn,
                reporter,
                flows_param,
                xfrm_param
            )?
            .map(|(out, refresh_when)| match out {
                // No refresh was necessary, generate the addresses directly.
                None => (self.flows.keys().cloned().collect(), refresh_when),
                // The refresh generated the address list for us.
                Some(out) => (out, refresh_when)
            }))
    }

    fn get_flow(
        retry: &Retry,
        ent: &RegistryFlows<Channel::Owned>,
        param: &Channel::Param,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<<Channel::Owned as OwnedFlows>::Flow>,
        RegistryMutexPoison
    > {
        match ent.flows.lock() {
            Ok(mut flows_guard) => match &mut *flows_guard {
                // The flows are live, try creating the flow
                Some(flows) => {
                    let flow_addr =
                        <F::Xfrm as DatagramXfrm>::PeerAddr::from(addr.clone());

                    match flows.flow(flow_addr, endpoint) {
                        // Created a flow; zero out the failures and return it.
                        Ok(flow) => match ent.retry.write() {
                            Ok(mut guard) => {
                                guard.nfailures = 0;

                                Ok(RetryResult::Success(flow))
                            }
                            Err(_) => Err(RegistryMutexPoison)
                        },
                        // Error; record it and return a retry.
                        Err(err) => {
                            warn!(target: "far-channel-registry",
                                  "error getting flow to {} on {}: {}",
                                  param, addr, err);

                            match ent.retry.write() {
                                Ok(mut retry_guard) => {
                                    let retry_when = Instant::now() +
                                        retry.retry_delay(
                                            retry_guard.nfailures
                                        );

                                    retry_guard.nfailures += 1;
                                    retry_guard.retry_when = retry_when;

                                    Ok(RetryResult::Retry(retry_when))
                                }
                                Err(_) => Err(RegistryMutexPoison)
                            }
                        }
                    }
                }
                // The flows were shut down by somebody; return a retry.
                None => match ent.retry.read() {
                    Ok(guard) => Ok(RetryResult::Retry(guard.retry_when)),
                    Err(_) => Err(RegistryMutexPoison)
                }
            },
            Err(_) => Err(RegistryMutexPoison)
        }
    }

    fn try_flows_readonly(
        &self,
        addr: &Channel::Param
    ) -> Result<
        ReadOnlyResult<(&RegistryFlows<Channel::Owned>, Option<Instant>)>,
        ReadOnlyErr
    > {
        if !self.needs_refresh() {
            match self.flows.get(addr) {
                // Check if we've been shut down.
                Some(ent) => {
                    let avail = ent
                        .flows
                        .lock()
                        .map_err(|_| ReadOnlyErr::MutexPoison)
                        .map(|guard| guard.is_some())?;

                    if avail {
                        Ok(ReadOnlyResult::Success((ent, self.next_refresh())))
                    } else {
                        Ok(ReadOnlyResult::NeedsWrite)
                    }
                }
                None => Err(ReadOnlyErr::NotFound)
            }
        } else {
            Ok(ReadOnlyResult::NeedsWrite)
        }
    }

    fn try_flow_readonly(
        &self,
        retry: &Retry,
        param: &Channel::Param,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        ReadOnlyResult<
            RetryResult<(
                <Channel::Owned as OwnedFlows>::Flow,
                Option<Instant>
            )>
        >,
        ReadOnlyErr
    > {
        match self.try_flows_readonly(param)? {
            ReadOnlyResult::Success((flows, refresh_when)) => {
                Ok(ReadOnlyResult::Success(
                    Self::get_flow(retry, flows, param, addr, endpoint)
                        .map_err(|_| ReadOnlyErr::MutexPoison)?
                        .map(|flow| (flow, refresh_when))
                ))
            }
            ReadOnlyResult::NeedsWrite => Ok(ReadOnlyResult::NeedsWrite)
        }
    }

    fn flows_nonblock(
        &mut self,
        id: &FarChannelRegistryID,
        addr: &Channel::Param,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<(
            &RegistryFlows<Channel::Owned>,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        RegistryFlowsError<
            RegistryRefreshError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    > {
        self.refresh_nonblock(
            id,
            channel,
            policy,
            authn,
            reporter,
            flows_param,
            xfrm_param
        )
        .map_err(|err| RegistryFlowsError::Acquire { err: err })?
        .map_ok(move |(addrs, refresh_when)| {
            let flows = self
                .flows
                .get(addr)
                .ok_or(RegistryFlowsError::ParamNotFound)?;

            Ok((flows, addrs, refresh_when))
        })
    }

    fn flow_nonblock(
        &mut self,
        id: &FarChannelRegistryID,
        retry: &Retry,
        param: &Channel::Param,
        channel: &Channel,
        policy: &SocketAddrPolicy,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<(
            <Channel::Owned as OwnedFlows>::Flow,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        RegistryFlowsError<
            RegistryRefreshError<
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    > {
        self.flows_nonblock(
            id,
            param,
            channel,
            policy,
            authn,
            reporter,
            flows_param,
            xfrm_param
        )?
        .flat_map_ok(|(flows, addrs, refresh_when)| {
            Ok(Self::get_flow(retry, flows, param, addr, endpoint)
                .map_err(|_| RegistryFlowsError::MutexPoison)?
                .map(|flow| (flow, addrs, refresh_when)))
        })
    }

    /// Create a new entry where one does not already exist.
    fn create_nonblock<NameCtx>(
        id: &FarChannelRegistryID,
        caches: &mut NameCtx,
        channel: &mut Channel,
        policy: &SocketAddrPolicy,
        resolve_config: &AddrsConfig,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<(Self, Option<Instant>)>,
        RegistryAcquireError<
            Channel::AcquireError,
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        let acquired = channel
            .acquire()
            .map_err(|err| RegistryAcquireError::Acquire { err: err })?;
        let mut resolver = acquired
            .resolver(caches, policy, resolve_config.resolver())
            .map_err(|err| RegistryAcquireError::Resolver { err: err })?;

        // Decide what kinds of addresses to keep.
        let mut keep_ipv4 = false;
        let mut keep_ipv6 = false;

        for kind in resolve_config.addr_policy().iter() {
            match kind {
                AddrKind::IPv6 => {
                    trace!(target: "far-channel-registry",
                           "retaining IPv6 addresses");

                    keep_ipv6 = true;
                }
                AddrKind::IPv4 => {
                    trace!(target: "far-channel-registry",
                           "retaining IPv4 addresses");

                    keep_ipv4 = true;
                }
            }
        }

        let flows = match &mut resolver {
            // This is the only nontrivial case.  First thing, check
            // the addresses.
            AcquiredResolver::Resolve { resolver } => resolver
                .addrs()
                .map_err(|err| RegistryAcquireError::Refresh {
                    err: RegistryRefreshError::NameCaches { err: err }
                })?
                .map_ok(|(resolved, time)| {
                    trace!(target: "far-channel-registry",
                           "refreshing addresses for registry entry");

                    let mut tab = HashMap::with_capacity(resolved.len());

                    // Filter out all the addresses we're keeping.
                    for (addr, _, _) in resolved {
                        if (addr.is_ipv6() && keep_ipv6) ||
                            (addr.is_ipv4() || keep_ipv4)
                        {
                            trace!(target: "far-channel-registry",
                                   "keeping address: {}",
                                   addr);

                            let addr = acquired.wrap(addr).map_err(|err| {
                                RegistryAcquireError::Refresh {
                                    err: RegistryRefreshError::Wrap {
                                        err: err
                                    }
                                }
                            })?;

                            debug!(target: "far-channel-registry",
                                   "establishing flows for {}",
                                   addr);

                            let xfrm = Xfrm::create(&addr, xfrm_param);
                            let flows = channel
                                .owned_flows(
                                    *id,
                                    addr.clone(),
                                    xfrm,
                                    authn.clone(),
                                    reporter.clone(),
                                    flows_param.clone()
                                )
                                .map_err(|err| {
                                    RegistryAcquireError::Refresh {
                                        err: RegistryRefreshError::Flows {
                                            err: err
                                        }
                                    }
                                })?;

                            tab.insert(addr, RegistryFlows::new(flows));
                        } else {
                            debug!(target: "far-channel-registry",
                                   "discarding address {}",
                                   addr);
                        }
                    }

                    if tab.is_empty() {
                        Err(RegistryAcquireError::Refresh {
                            err: RegistryRefreshError::NoValidAddrs
                        })
                    } else {
                        // Replace the flows.
                        tab.shrink_to_fit();

                        Ok((tab, time))
                    }
                }),
            AcquiredResolver::StaticMulti { params } => {
                let mut tab = HashMap::with_capacity(params.len());

                for addr in params {
                    debug!(target: "far-channel-registry",
                           "establishing flows for {}",
                               addr);

                    let xfrm = Xfrm::create(addr, xfrm_param);
                    let flows = channel
                        .owned_flows(
                            *id,
                            addr.clone(),
                            xfrm,
                            authn.clone(),
                            reporter.clone(),
                            flows_param.clone()
                        )
                        .map_err(|err| RegistryAcquireError::Refresh {
                            err: RegistryRefreshError::Flows { err: err }
                        })?;

                    tab.insert(addr.clone(), RegistryFlows::new(flows));
                }

                Ok(RetryResult::Success((tab, None)))
            }
            AcquiredResolver::StaticSingle { param } => {
                let mut tab = HashMap::with_capacity(1);

                debug!(target: "far-channel-registry",
                       "establishing flows for {}",
                       param);

                let xfrm = Xfrm::create(param, xfrm_param);
                let flows = channel
                    .owned_flows(
                        *id,
                        param.clone(),
                        xfrm,
                        authn.clone(),
                        reporter.clone(),
                        flows_param.clone()
                    )
                    .map_err(|err| RegistryAcquireError::Refresh {
                        err: RegistryRefreshError::Flows { err: err }
                    })?;

                tab.insert(param.clone(), RegistryFlows::new(flows));

                Ok(RetryResult::Success((tab, None)))
            }
        }?;

        Ok(flows.map(|(flows, time)| {
            (
                RegistryAcquired {
                    acquired: acquired,
                    resolver: resolver,
                    flows: flows
                },
                time
            )
        }))
    }
}

impl<Channel, F, AuthN, Xfrm> RegistryEntry<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq
{
    #[inline]
    fn create<NameCtx>(
        caches: &mut NameCtx,
        config: Channel::Config,
        retry: Retry
    ) -> Result<Self, Channel::CreateError>
    where
        NameCtx: NSNameCachesCtx {
        let channel = Channel::new(caches, config)?;

        Ok(RegistryEntry {
            acquired: RetryResult::Retry(Instant::now()),
            channel: channel,
            retry: retry
        })
    }

    #[inline]
    fn try_acquired_readonly(
        &self
    ) -> ReadOnlyResult<&RegistryAcquired<Channel, F, AuthN, Xfrm>> {
        match &self.acquired {
            RetryResult::Success(out) => ReadOnlyResult::Success(out),
            _ => ReadOnlyResult::NeedsWrite
        }
    }

    #[inline]
    fn acquire_nonblock<NameCtx>(
        &mut self,
        id: &FarChannelRegistryID,
        caches: &mut NameCtx,
        policy: &SocketAddrPolicy,
        resolve_config: &AddrsConfig,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<Option<Instant>>,
        RegistryAcquireError<
            Channel::AcquireError,
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        trace!(target: "far-channel-registry",
               "checking whether to attempt to initialize");

        match &self.acquired {
            // We still need to initialize
            RetryResult::Retry(when) => {
                if *when <= Instant::now() {
                    debug!(target: "far-channel-registry",
                           "attempt to initialize registry entry");

                    match RegistryAcquired::create_nonblock(
                        id,
                        caches,
                        &mut self.channel,
                        policy,
                        resolve_config,
                        authn,
                        reporter,
                        flows_param,
                        xfrm_param
                    )? {
                        RetryResult::Retry(when) => {
                            self.acquired = RetryResult::Retry(when);

                            Ok(RetryResult::Retry(when))
                        }
                        RetryResult::Success((acquired, time)) => {
                            self.acquired = RetryResult::Success(acquired);

                            Ok(RetryResult::Success(time))
                        }
                    }
                } else {
                    Ok(RetryResult::Retry(*when))
                }
            }
            RetryResult::Success(acquired) => {
                Ok(RetryResult::Success(acquired.next_refresh()))
            }
        }
    }

    /// Try to obtain a snapshot without performing any read
    /// operations.
    #[inline]
    fn try_snapshot_addrs_readonly(
        &self
    ) -> ReadOnlyResult<(Vec<Channel::Param>, Option<Instant>)> {
        match self.try_acquired_readonly() {
            ReadOnlyResult::Success(acquired) => {
                acquired.try_snapshot_addrs_readonly()
            }
            ReadOnlyResult::NeedsWrite => ReadOnlyResult::NeedsWrite
        }
    }

    fn snapshot_addrs_nonblock<NameCtx>(
        &mut self,
        id: &FarChannelRegistryID,
        caches: &mut NameCtx,
        policy: &SocketAddrPolicy,
        resolve_config: &AddrsConfig,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        RegistryAcquireError<
            Channel::AcquireError,
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        self.acquire_nonblock(
            id,
            caches,
            policy,
            resolve_config,
            authn,
            reporter,
            flows_param,
            xfrm_param
        )?
        .flat_map_ok(|_| match &mut self.acquired {
            RetryResult::Success(acquired) => acquired
                .snapshot_addrs_nonblock(
                    id,
                    &self.channel,
                    policy,
                    authn,
                    reporter,
                    flows_param,
                    xfrm_param
                )
                .map_err(|err| RegistryAcquireError::Refresh { err: err }),
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        })
    }

    #[inline]
    fn try_flow_readonly(
        &self,
        param: &Channel::Param,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        ReadOnlyResult<
            RetryResult<(
                <Channel::Owned as OwnedFlows>::Flow,
                Option<Instant>
            )>
        >,
        ReadOnlyErr
    > {
        match self.try_acquired_readonly() {
            ReadOnlyResult::Success(acquired) => Ok(acquired
                .try_flow_readonly(&self.retry, param, addr, endpoint)?),
            ReadOnlyResult::NeedsWrite => Ok(ReadOnlyResult::NeedsWrite)
        }
    }

    fn flow_nonblock<NameCtx>(
        &mut self,
        id: &FarChannelRegistryID,
        caches: &mut NameCtx,
        param: &Channel::Param,
        policy: &SocketAddrPolicy,
        resolve_config: &AddrsConfig,
        authn: &AuthN,
        reporter: &F::Reporter,
        flows_param: &F::CreateParam,
        xfrm_param: &Xfrm::CreateParam,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<(
            <Channel::Owned as OwnedFlows>::Flow,
            Option<Vec<Channel::Param>>,
            Option<Instant>
        )>,
        RegistryFlowsError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        self.acquire_nonblock(
            id,
            caches,
            policy,
            resolve_config,
            authn,
            reporter,
            flows_param,
            xfrm_param
        )
        .map_err(|err| RegistryFlowsError::Acquire { err: err })?
        .flat_map_ok(|_| match &mut self.acquired {
            RetryResult::Success(acquired) => acquired
                .flow_nonblock(
                    id,
                    &self.retry,
                    param,
                    &self.channel,
                    policy,
                    authn,
                    reporter,
                    flows_param,
                    xfrm_param,
                    addr,
                    endpoint
                )
                .map_err(|err| match err {
                    RegistryFlowsError::Acquire { err } => {
                        RegistryFlowsError::Acquire {
                            err: RegistryAcquireError::Refresh { err: err }
                        }
                    }
                    RegistryFlowsError::ParamNotFound => {
                        RegistryFlowsError::ParamNotFound
                    }
                    RegistryFlowsError::MutexPoison => {
                        RegistryFlowsError::MutexPoison
                    }
                }),
            RetryResult::Retry(when) => Ok(RetryResult::Retry(*when))
        })
    }
}

impl<Channel, F, AuthN, Xfrm> FarChannelRegistry<Channel, F, AuthN, Xfrm>
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone + Display + Eq + Hash + PartialEq
{
    /// Create a `FarChannelRegistry` from its configuration.
    ///
    /// This will just create the channels; it will not attempt to
    /// acquire them.
    pub fn create<NameCtx>(
        caches: &mut NameCtx,
        authn: AuthN,
        reporter: F::Reporter,
        config: ChannelRegistryConfig<
            Channel::Config,
            F::CreateParam,
            Xfrm::CreateParam
        >
    ) -> Result<Self, FarChannelRegistryCreateError<Channel::CreateError>>
    where
        NameCtx: NSNameCachesCtx {
        let (mut configs, resolve, flows_param, xfrm_param) = config.take();
        let policy = SocketAddrPolicy::create(resolve.addr_policy());
        let mut channels = Vec::with_capacity(configs.len());
        let mut names = Vec::with_capacity(configs.len());
        let mut ids = HashMap::with_capacity(configs.len());

        debug!(target: "far-channel-registry",
               "creating channel registry");

        // Set up all the channels, but don't run the whole acquire
        // workflow with them yet.
        for (curr, config) in configs.drain(..).enumerate() {
            let (name, config, retry) = config.take();

            debug!(target: "far-channel-registry",
                   "creating channel {}",
                   name);

            let entry = RegistryEntry::create(caches, config, retry).map_err(
                |err| FarChannelRegistryCreateError::Create { err: err }
            )?;

            channels.push(Arc::new(RwLock::new(entry)));

            debug!(target: "far-channel-registry",
                   "assigned ID {} to channel {}",
                   curr, name);

            // There should not be any duplicate keys
            if ids
                .insert(name.clone(), FarChannelRegistryID(curr))
                .is_some()
            {
                return Err(FarChannelRegistryCreateError::DuplicateID {
                    name: name
                });
            }

            names.push(name);
        }

        Ok(FarChannelRegistry {
            resolve_config: resolve,
            ids: ids,
            channels: channels,
            authn: authn,
            reporter: reporter,
            flows_param: flows_param,
            names: names,
            policy: policy,
            xfrm_param: xfrm_param
        })
    }

    /// Try to acquire on all channels, but never wait.
    pub fn acquire_all_nonblock<NameCtx>(
        &self,
        caches: &mut NameCtx
    ) -> Result<
        RetryResult<()>,
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        debug!(target: "far-channel-registry",
               "trying to acquire all channels");

        let mut min_time: Option<Instant> = None;

        for i in 0..self.channels.len() {
            let channel = &self.channels[i];
            let id = FarChannelRegistryID(i);

            trace!(target: "far-channel-registry",
                   "trying read-only mode");

            // Try to get it done with read-only mode first
            let need_write = match channel.read() {
                Ok(guard) => matches!(
                    (*guard).try_acquired_readonly(),
                    ReadOnlyResult::NeedsWrite
                ),
                Err(_) => {
                    return Err(FarChannelRegistryAcquireError::MutexPoison)
                }
            };

            if need_write {
                trace!(target: "far-channel-registry",
                       "acquiring write lock for channel");

                match channel.write() {
                    Ok(mut guard) => guard
                        .acquire_nonblock(
                            &id,
                            caches,
                            &self.policy,
                            &self.resolve_config,
                            &self.authn,
                            &self.reporter,
                            &self.flows_param,
                            &self.xfrm_param
                        )
                        .map_err(|err| {
                            FarChannelRegistryAcquireError::Acquire { err: err }
                        })?
                        .app_retry(|when| {
                            // Accumulate retry results and take their minimum.
                            trace!(target: "far-channel-registry",
                                   "channel acquisition failed with retry");

                            min_time = Some(
                                min_time.map_or(when, |time| time.min(when))
                            );
                        }),
                    Err(_) => {
                        return Err(FarChannelRegistryAcquireError::MutexPoison)
                    }
                }
            }
        }

        match min_time {
            Some(when) => Ok(RetryResult::Retry(when)),
            None => Ok(RetryResult::Success(()))
        }
    }

    pub fn acquire_all<NameCtx>(
        &self,
        caches: &mut NameCtx
    ) -> Result<
        (),
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        debug!(target: "far-channel-registry",
               "acquiring all channels");

        while let RetryResult::Retry(when) =
            self.acquire_all_nonblock(caches)?
        {
            let now = Instant::now();

            if when > now {
                let delay = when - now;

                warn!(target: "far-channel-registry",
                      "failed to acquire some channels, retry after {}.{:03}s",
                      delay.as_secs(), delay.subsec_millis());

                sleep(delay);
            } else {
                warn!(target: "far-channel-registry",
                      "failed to acquire some channels, retry immediately");
            }
        }

        Ok(())
    }

    fn snapshot_addrs_nonblock_id<NameCtx>(
        &self,
        caches: &mut NameCtx,
        id: &FarChannelRegistryID
    ) -> Result<
        RetryResult<(Vec<Channel::Param>, Option<Instant>)>,
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        // First try the read-only option
        match self.channels[id.0].read() {
            Ok(guard) => match guard.try_snapshot_addrs_readonly() {
                ReadOnlyResult::Success(out) => {
                    return Ok(RetryResult::Success(out))
                }
                _ => Ok(())
            },
            Err(_) => Err(FarChannelRegistryAcquireError::MutexPoison)
        }?;

        // Fall back to write mode.
        match self.channels[id.0].write() {
            Ok(mut guard) => guard
                .snapshot_addrs_nonblock(
                    id,
                    caches,
                    &self.policy,
                    &self.resolve_config,
                    &self.authn,
                    &self.reporter,
                    &self.flows_param,
                    &self.xfrm_param
                )
                .map_err(|err| FarChannelRegistryAcquireError::Acquire {
                    err: err
                }),
            Err(_) => Err(FarChannelRegistryAcquireError::MutexPoison)
        }
    }

    #[inline]
    fn addrs_nonblock_id<NameCtx>(
        &self,
        caches: &mut NameCtx,
        id: &FarChannelRegistryID
    ) -> Result<
        RetryResult<(IntoIter<Channel::Param>, Option<Instant>)>,
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        Ok(self
            .snapshot_addrs_nonblock_id(caches, id)?
            .map(|(out, when)| (out.into_iter(), when)))
    }

    #[inline]
    pub fn snapshot_addrs_nonblock<NameCtx>(
        &self,
        caches: &mut NameCtx,
        name: &str
    ) -> Result<
        RetryResult<Option<(Vec<Channel::Param>, Option<Instant>)>>,
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        match self.ids.get(name) {
            Some(id) => {
                Ok(self.snapshot_addrs_nonblock_id(caches, id)?.map(Some))
            }
            None => Ok(RetryResult::Success(None))
        }
    }

    #[inline]
    pub fn addrs_nonblock<NameCtx>(
        &self,
        caches: &mut NameCtx,
        name: &str
    ) -> Result<
        RetryResult<Option<(IntoIter<Channel::Param>, Option<Instant>)>>,
        FarChannelRegistryAcquireError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >
    >
    where
        NameCtx: NSNameCachesCtx {
        Ok(self
            .snapshot_addrs_nonblock(caches, name)?
            .map(|out| out.map(|(v, when)| (v.into_iter(), when))))
    }

    fn flow_nonblock_id<NameCtx>(
        &self,
        caches: &mut NameCtx,
        id: &FarChannelRegistryID,
        param: &Channel::Param,
        addr: &<Channel::Xfrm as DatagramXfrm>::PeerAddr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<(<AuthN as SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>>::Prin,
                     <Channel::Owned as OwnedFlows>::Flow)>,
        FarChannelRegistryFlowError<
            RegistryFlowsError<
                RegistryAcquireError<
                    Channel::AcquireError,
                    <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                    FarChannelFlowsError<
                        Channel::SocketError,
                        F::CreateError,
                        Channel::XfrmError,
                        Channel::OwnedFlowsError
                    >,
                    <Channel::Acquired as FarChannelAcquired>::WrapError
                >
            >,
            <Channel::Owned as OwnedFlows>::FlowError,
            <AuthN as SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>>::Error
        >
    >
    where NameCtx: NSNameCachesCtx{
        let flow = match self.channels[id.0].read() {
            Ok(guard) => match guard
                .try_flow_readonly(param, addr, endpoint)
                .map_err(|err| match err {
                    ReadOnlyErr::NotFound => {
                        FarChannelRegistryFlowError::Acquire {
                            err: RegistryFlowsError::ParamNotFound
                        }
                    }
                    ReadOnlyErr::MutexPoison => {
                        FarChannelRegistryFlowError::MutexPoison
                    }
                })? {
                ReadOnlyResult::Success(out) => Ok(out.map(|(flow, _)| flow)),
                // Fall back to write mode.
                ReadOnlyResult::NeedsWrite => match self.channels[id.0].write()
                {
                    Ok(mut guard) => Ok(guard
                        .flow_nonblock(
                            id,
                            caches,
                            param,
                            &self.policy,
                            &self.resolve_config,
                            &self.authn,
                            &self.reporter,
                            &self.flows_param,
                            &self.xfrm_param,
                            addr,
                            endpoint
                        )
                        .map_err(|err| FarChannelRegistryFlowError::Acquire {
                            err: err
                        })?
                        .map(|(out, _, _)| out)),
                    Err(_) => Err(FarChannelRegistryFlowError::MutexPoison)
                }
            },
            Err(_) => Err(FarChannelRegistryFlowError::MutexPoison)
        }?;

        // ISSUE #14: questionable whether authentication should be done
        // here, or whether it should be pushed down into Flows.
        //
        // Notably, doing it here requires two type constraints for AuthN.

        flow.map_ok(|mut flow| match self.authn.session_authn(&mut flow) {
            Ok(AuthNResult::Accept(prin)) => {
                info!(target: "far-channel-registry",
                      "stream {} authenticated as {}",
                      id, prin);

                Ok((prin, flow))
            }
            Ok(AuthNResult::Reject) => {
                warn!(target: "far-channel-registry",
                      "stream from {} failed authentication",
                      addr);

                Err(FarChannelRegistryFlowError::AuthNFailed)
            }
            Err(err) => Err(FarChannelRegistryFlowError::Auth { err: err })
        })
    }

    /// Get the ID for the named channel.
    #[inline]
    pub fn id(
        &self,
        name: &str
    ) -> Option<FarChannelRegistryID> {
        self.ids.get(name).copied()
    }

    /// Get an iterator over all names and channel IDs.
    #[inline]
    pub fn ids(&self) -> Iter<'_, String, FarChannelRegistryID> {
        self.ids.iter()
    }

    #[inline]
    pub fn name(
        &self,
        id: FarChannelRegistryID
    ) -> &str {
        &self.names[id.0]
    }

    #[inline]
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

impl<Msg, Codec, Reporter, Channel, F, AuthN, Xfrm, NameCtx> Channels<NameCtx>
    for FarChannelRegistryChannels<
        Msg,
        Codec,
        Reporter,
        Channel,
        F,
        AuthN,
        Xfrm
    >
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Codec: Clone + DatagramCodec<Msg> + Send,
    NameCtx: NSNameCachesCtx,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Reporter:
        StreamReporter<
            Stream = ThreadedStream<
                DatagramCodecStream<
                    Msg,
                    <Channel::Owned as OwnedFlows>::Flow,
                    Codec
                >
            >,
            Src = StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                FarChannelRegistryID,
                Channel::Param
            >,
            Prin = <AuthN as SessionAuthN<
                <Channel::Owned as OwnedFlows>::Flow
            >>::Prin
        >,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr: Hash
{
    type Addr = <Channel::Xfrm as DatagramXfrm>::PeerAddr;
    type ChannelID = FarChannelRegistryID;
    type Param = Channel::Param;
    type ParamError = FarChannelRegistryAcquireError<
        RegistryAcquireError<
            Channel::AcquireError,
            <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
            FarChannelFlowsError<
                Channel::SocketError,
                F::CreateError,
                Channel::XfrmError,
                Channel::OwnedFlowsError
            >,
            <Channel::Acquired as FarChannelAcquired>::WrapError
        >
    >;
    type ParamIter = IntoIter<(FarChannelRegistryID, Channel::Param)>;
    type Stream = ThreadedStream<
        DatagramCodecStream<Msg, <Channel::Owned as OwnedFlows>::Flow, Codec>
    >;
    type StreamError = FarChannelRegistryStreamError<
        RegistryFlowsError<
            RegistryAcquireError<
                Channel::AcquireError,
                <Channel::Acquired as FarChannelAcquiredResolve>::ResolverError,
                FarChannelFlowsError<
                    Channel::SocketError,
                    F::CreateError,
                    Channel::XfrmError,
                    Channel::OwnedFlowsError
                >,
                <Channel::Acquired as FarChannelAcquired>::WrapError
            >
        >,
        <Channel::Owned as OwnedFlows>::FlowError,
        Reporter::ReportError,
        <AuthN as SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>>::Error
    >;

    fn params(
        &mut self,
        ctx: &mut NameCtx
    ) -> Result<RetryResult<(Self::ParamIter, Option<Instant>)>, Self::ParamError>
    {
        // ISSUE #15: this is probably not the most efficient way to do this,
        // because we're creating arrays.
        let mut iters = Vec::with_capacity(self.ids.len());
        let mut refresh_when: Option<Instant> = None;
        let mut retry_when: Option<Instant> = None;
        let mut size_hint = 0;

        // Split up the retry results.
        for id in &self.ids {
            match self.registry.addrs_nonblock_id(ctx, id)? {
                RetryResult::Retry(when) => {
                    let min_time =
                        retry_when.map_or(when, |time| time.min(when));

                    retry_when = Some(min_time)
                }
                RetryResult::Success((iter, when)) => {
                    refresh_when = match (refresh_when, when) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (None, when) => when,
                        (when, None) => when
                    };
                    size_hint += match iter.size_hint() {
                        (_, Some(size)) => size,
                        (size, _) => size
                    };
                    iters.push((*id, iter));
                }
            }
        }

        // Bail out if we got a retry result at any point.
        if let Some(when) = retry_when {
            return Ok(RetryResult::Retry(when));
        }

        let mut out = Vec::with_capacity(size_hint);

        for (id, iter) in iters.drain(..) {
            for param in iter {
                out.push((id, param));
            }
        }

        Ok(RetryResult::Success((out.into_iter(), refresh_when)))
    }

    #[inline]
    fn stream(
        &mut self,
        ctx: &mut NameCtx,
        id: &FarChannelRegistryID,
        param: &Self::Param,
        addr: &Self::Addr,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<RetryResult<Self::Stream>, Self::StreamError> {
        self.registry
            .flow_nonblock_id(ctx, id, param, addr, endpoint)
            .map_err(|err| FarChannelRegistryStreamError::Flow { err: err })?
            .map_ok(|(prin, flow)| {
                let stream =
                    DatagramCodecStream::create(self.codec.clone(), flow);
                let stream = ThreadedStream::new(stream);

                let id = StreamID::new(addr.clone(), *id, param.clone());

                match self.reporter.report(id, prin, stream.clone()) {
                    Ok(Some(stream)) => Ok(stream),
                    Ok(None) => Ok(stream),
                    Err(err) => {
                        Err(FarChannelRegistryStreamError::Report { err: err })
                    }
                }
            })
    }
}

impl<Msg, Codec, Reporter, Channel, F, AuthN, Xfrm, RegistryCtx>
    ChannelsCreate<RegistryCtx, Vec<String>>
    for FarChannelRegistryChannels<
        Msg,
        Codec,
        Reporter,
        Channel,
        F,
        AuthN,
        Xfrm
    >
where
    AuthN: Clone + SessionAuthN<<Channel::Nego as OwnedFlowsNegotiator>::Flow>,
    AuthN: Clone + SessionAuthN<<Channel::Owned as OwnedFlows>::Flow>,
    Codec: Clone + DatagramCodec<Msg> + Send,
    Codec::Param: Default,
    RegistryCtx:
        NSNameCachesCtx + FarChannelRegistryCtx<Channel, F, AuthN, Xfrm>,
    Channel: FarChannelOwnedFlows<F, AuthN, Xfrm> + FarChannelCreate,
    F: Flows
        + CreateOwnedFlows<Channel::Nego, AuthN, ChannelID = FarChannelRegistryID>
        + OwnedFlows,
    F::Socket: From<Channel::Socket>,
    F::Xfrm: From<Channel::Xfrm>,
    <F::Xfrm as DatagramXfrm>::PeerAddr:
        From<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    F::CreateParam: Clone + Default,
    F::Reporter: Clone,
    Xfrm: DatagramXfrm + DatagramXfrmCreate<Addr = Channel::Param>,
    Xfrm::CreateParam: Clone + Default,
    Xfrm::LocalAddr: From<<Channel::Socket as Socket>::Addr>,
    Reporter:
        StreamReporter<
            Stream = ThreadedStream<
                DatagramCodecStream<
                    Msg,
                    <Channel::Owned as OwnedFlows>::Flow,
                    Codec
                >
            >,
            Src = StreamID<
                <Channel::Xfrm as DatagramXfrm>::PeerAddr,
                FarChannelRegistryID,
                Channel::Param
            >,
            Prin = <AuthN as SessionAuthN<
                <Channel::Owned as OwnedFlows>::Flow
            >>::Prin
        >,
    Channel::Acquired: FarChannelAcquiredResolve<Resolved = Channel::Param>,
    Channel::Param: Clone
        + Display
        + Eq
        + Hash
        + PartialEq
        + ChannelParam<<Channel::Xfrm as DatagramXfrm>::PeerAddr>,
    <Channel::Xfrm as DatagramXfrm>::PeerAddr: Hash
{
    type Config = ChannelRegistryChannelsConfig<Codec::Param>;
    type CreateError =
        FarChannelRegistryChannelsCreateError<Codec::CreateError>;
    type Reporter = Reporter;

    fn create(
        ctx: &mut RegistryCtx,
        reporter: Self::Reporter,
        config: Self::Config,
        mut names: Vec<String>
    ) -> Result<Self, Self::CreateError> {
        let registry = ctx.far_channel_registry();
        let ids =
            if !names.is_empty() {
                let mut ids = Vec::with_capacity(names.len());

                for name in names.drain(..) {
                    match registry.id(&name) {
                        Some(id) => ids.push(id),
                        None => return Err(
                            FarChannelRegistryChannelsCreateError::Missing {
                                name: name
                            }
                        )
                    }
                }

                ids
            } else {
                registry.ids().map(|(_, id)| *id).collect()
            };
        let codec_config = config.take();
        let codec = Codec::create(codec_config).map_err(|err| {
            FarChannelRegistryChannelsCreateError::Codec { err: err }
        })?;

        Ok(FarChannelRegistryChannels {
            msg: PhantomData,
            codec: codec,
            reporter: reporter,
            registry: registry,
            ids: ids
        })
    }
}

impl From<FarChannelRegistryID> for usize {
    #[inline]
    fn from(val: FarChannelRegistryID) -> usize {
        val.0
    }
}

impl<Acquire> ScopedError for FarChannelRegistryAcquireError<Acquire>
where
    Acquire: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelRegistryAcquireError::Acquire { err } => err.scope(),
            FarChannelRegistryAcquireError::MutexPoison => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Acquire, Flow, Report, Auth> ScopedError
    for FarChannelRegistryStreamError<Acquire, Flow, Report, Auth>
where
    Acquire: ScopedError,
    Flow: ScopedError,
    Report: ScopedError,
    Auth: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelRegistryStreamError::Report { err } => err.scope(),
            FarChannelRegistryStreamError::Flow { err } => err.scope()
        }
    }
}

impl<Acquire, Flow, Auth> ScopedError
    for FarChannelRegistryFlowError<Acquire, Flow, Auth>
where
    Acquire: ScopedError,
    Flow: ScopedError,
    Auth: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            FarChannelRegistryFlowError::Acquire { err } => err.scope(),
            FarChannelRegistryFlowError::Flow { err } => err.scope(),
            FarChannelRegistryFlowError::Auth { err } => err.scope(),
            FarChannelRegistryFlowError::AuthNFailed => ErrorScope::External,
            FarChannelRegistryFlowError::MutexPoison => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Acquire> ScopedError for RegistryFlowsError<Acquire>
where
    Acquire: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            RegistryFlowsError::Acquire { err } => err.scope(),
            RegistryFlowsError::ParamNotFound => ErrorScope::Unrecoverable,
            RegistryFlowsError::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

impl<Acquire, Resolver, Flows, Wrap> ScopedError
    for RegistryAcquireError<Acquire, Resolver, Flows, Wrap>
where
    Acquire: ScopedError,
    Resolver: ScopedError,
    Flows: ScopedError,
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            RegistryAcquireError::Acquire { err } => err.scope(),
            RegistryAcquireError::Resolver { err } => err.scope(),
            RegistryAcquireError::Refresh { err } => err.scope()
        }
    }
}

impl<Flows, Wrap> ScopedError for RegistryRefreshError<Flows, Wrap>
where
    Flows: ScopedError,
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            RegistryRefreshError::NameCaches { err } => err.scope(),
            RegistryRefreshError::Flows { err } => err.scope(),
            RegistryRefreshError::Wrap { err } => err.scope(),
            RegistryRefreshError::NoValidAddrs => ErrorScope::Unrecoverable
        }
    }
}

impl<Acquire, Resolver, Flows, Wrap> Display
    for RegistryAcquireError<Acquire, Resolver, Flows, Wrap>
where
    Acquire: Display,
    Resolver: Display,
    Flows: Display,
    Wrap: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            RegistryAcquireError::Acquire { err } => err.fmt(f),
            RegistryAcquireError::Resolver { err } => err.fmt(f),
            RegistryAcquireError::Refresh { err } => err.fmt(f)
        }
    }
}

impl<Flows, Wrap> Display for RegistryRefreshError<Flows, Wrap>
where
    Flows: Display,
    Wrap: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            RegistryRefreshError::NameCaches { err } => err.fmt(f),
            RegistryRefreshError::Flows { err } => err.fmt(f),
            RegistryRefreshError::Wrap { err } => err.fmt(f),
            RegistryRefreshError::NoValidAddrs => {
                write!(f, "no valid addresses")
            }
        }
    }
}

impl<Acquire> Display for RegistryFlowsError<Acquire>
where
    Acquire: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            RegistryFlowsError::Acquire { err } => err.fmt(f),
            RegistryFlowsError::ParamNotFound => write!(f, "param not found"),
            RegistryFlowsError::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}

impl<Channel> Display for FarChannelRegistryCreateError<Channel>
where
    Channel: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryCreateError::Create { err } => err.fmt(f),
            FarChannelRegistryCreateError::DuplicateID { name } => {
                write!(f, "duplicate channel ID: \"{}\"", name)
            }
        }
    }
}

impl<Channel> Display for FarChannelRegistryChannelsCreateError<Channel>
where
    Channel: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryChannelsCreateError::Codec { err } => err.fmt(f),
            FarChannelRegistryChannelsCreateError::Missing { name } => {
                write!(f, "missing channel ID: \"{}\"", name)
            }
        }
    }
}

impl<Acquire> Display for FarChannelRegistryAcquireError<Acquire>
where
    Acquire: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryAcquireError::Acquire { err } => err.fmt(f),
            FarChannelRegistryAcquireError::MutexPoison => {
                write!(f, "mutex poisoned")
            }
        }
    }
}

impl<Acquire> Display for FarChannelRegistryFlowsError<Acquire>
where
    Acquire: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryFlowsError::Acquire { err } => err.fmt(f),
            FarChannelRegistryFlowsError::ChannelNotFound => {
                write!(f, "channel not found")
            }
            FarChannelRegistryFlowsError::MutexPoison => {
                write!(f, "mutex poisoned")
            }
        }
    }
}

impl<Acquire, Flow, Report, Auth> Display
    for FarChannelRegistryStreamError<Acquire, Flow, Report, Auth>
where
    Acquire: Display,
    Flow: Display,
    Report: Display,
    Auth: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryStreamError::Report { err } => err.fmt(f),
            FarChannelRegistryStreamError::Flow { err } => err.fmt(f)
        }
    }
}

impl<Acquire, Flow, AuthN> Display
    for FarChannelRegistryFlowError<Acquire, Flow, AuthN>
where
    Acquire: Display,
    Flow: Display,
    AuthN: Display
{
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            FarChannelRegistryFlowError::Acquire { err } => err.fmt(f),
            FarChannelRegistryFlowError::Flow { err } => err.fmt(f),
            FarChannelRegistryFlowError::Auth { err } => err.fmt(f),
            FarChannelRegistryFlowError::AuthNFailed => {
                write!(f, "authentication failed")
            }
            FarChannelRegistryFlowError::MutexPoison => {
                write!(f, "mutex poisoned")
            }
        }
    }
}

impl Display for FarChannelRegistryID {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "far channel #{}", self.0)
    }
}
