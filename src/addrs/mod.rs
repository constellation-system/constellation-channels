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

//! Dynamic address multiplexing functionality.
//!
//! This module provides an abstraction for tracking and selecting
//! among multiple addresses.  This is a problem often overlooked in
//! network applications
//!
//! # Motivation
//!
//! Many applications do not adequately handle the issues around
//! network addresses and address resolution.  This leads to
//! poorly-written applications experiencing non-obvious and
//! frustrating failures, as well as applications that need to be
//! periodically restarted in order to work properly.
//!
//! ## Refreshing Name Resolution
//!
//! Many applications incorrectly assume that name resolution is
//! static for all time, and will perform only a single name
//! resolution at the start of execution.  While this is fine for some
//! simple client applications, it is problematic for anything that
//! expects to run continuously, as it will miss changes to name
//! resolution.
//!
//! ## Handling Multiple Addresses
//!
//! A common (and false) assumption in network application development
//! is that a client or server need only concern itself with a single
//! address.  There are a few common simplifications that combine to
//! support this:
//!
//! * Assuming that any given machine has a single, distinguished network (often
//!   IP) address.
//!
//! * Assuming that a name resolution (often DNS) will yield a single IP
//!   address.
//!
//! These assumptions do not hold in general.  Machines may have
//! multiple network interfaces, each with their own addresses (to say
//! nothing of the effects of tunneling interfaces).  Even machines
//! with a single network interface may have both IPv4 and IPv6
//! addresses for it.  Additionally, DNS may produce a one-to-many
//! mapping from a given name to network addresses, which may contain
//! a mix of different *kinds* of networks (such as IPv4 and IPv6).
//!
//! Failure to account for this can lead to bad outcomes for
//! applications, such as selecting an IPv6 address from DNS
//! resolution and trying to connect exclusively to it, when the
//! corresponding server is listening exclusively on IPv4.  A similar
//! scenario can occur in a partitioned network, where a server has
//! different network addresses for different partitions.
//!
//! Finally, client configurations may wish to provide multiple
//! addresses in some scenarios, which are meant to serve as
//! equivalent endpoints for the same service.
//!
//! # Address Multiplexing with [Addrs]
//!
//! This module provides [Addrs], which is intended to serve as a
//! solution to the issues described above.  `Addrs` is a configurable
//! address multiplexer, capable of selecting among multiple addresses
//! based on their past performance using the [addr](AddrMultiplexer::addr)
//! function.  Successes and failures can be recorded using the
//! [success](AddrMultiplexer::success) and
//! [failure](AddrMultiplexer::failure) functions.  `Addrs` uses an
//! internal scoring system based on a combination of the frequency of
//! success, how recently the address was last used, and a
//! configurable address preference policy.
//!
//! `Addrs` can be configured to acquire addresses from name
//! resolution, or select from among a static list of addresses.  If
//! name resolution is used, the list will be periodically refreshed
//! according to a [ResolverConfig](crate::config::ResolverConfig)
//! policy.
//!
//! # Intended Use
//!
//! [Addrs] is provided primarily as a resource for implementing
//! protocols based on far-link channels.
//!
//! For near-link channels, `Addrs` already is used by
//! [NearConnector](crate::near::NearConnector) instances such as
//! [TCPNearConnector](crate::near::tcp::TCPNearConnector) to handle
//! address multiplexing, using the success and failure of connection
//! attempts as indicators to report using
//! [success](AddrMultiplexer::success) and
//! [failure](AddrMultiplexer::failure).
//!
//! Far-link channels, on the other hand, are a more complicated
//! issue, as it is much harder to detect success and failure of
//! datagram protocol transmissions.  In the general case, this can
//! only be done at the protocol state-machine level, and thus
//! far-links cannot perform address multiplexing at the channel level
//! the way near-links can.  Even with session protocols like DTLS,
//! where successful negotiation of a session can be detected, a
//! channel might "go dark" at some point in the future, which can
//! only be detected at the protocol level in the general case.
//!
//! `Addrs` is therefore provided as one possible mechanism for
//! dealing with these issues.  It is intended to be used as a
//! component in a protocol-level solution to the problem of multiple
//! addresses.
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::thread::sleep;
use std::time::Instant;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::RetryResult;
use constellation_common::sched::EpochChange;
use constellation_common::sched::History;
use constellation_common::sched::Policy;
use constellation_common::sched::RefreshError;
use constellation_common::sched::ReportError;
use constellation_common::sched::Scheduler;
use constellation_common::sched::SelectError;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use log::error;
use log::trace;
use log::warn;

use crate::config::AddrKind;
use crate::config::AddrsConfig;
use crate::resolve::cache::NSNameCacheError;
use crate::resolve::cache::NSNameCachesCtx;
use crate::resolve::MixedResolver;
use crate::resolve::MixedResolverCreateError;
use crate::resolve::RefreshResult;
use crate::resolve::Resolution;

/// Dynamic address multiplexer.
///
/// `AddrMultiplexer` provides an abstraction for selecting from one of
/// potentially many addresses based on a combination of their past
/// success rate, how recently they were used, and a configured order
/// of preference.  "Success" in this context is protocol-dependent:
/// in connection-based protocols, it can refer to successful or
/// failed connection attempts.  In datagram protocols, "success" and
/// "failure" are more complicated and protocol-dependent concepts.
pub struct AddrMultiplexer<Epochs: Iterator> {
    resolver: MixedResolver<SocketAddr, IPEndpoint>,
    /// The address multiplexer used to select addresses.
    sched: Scheduler<Epochs, AddrsHistory, SocketAddrPolicy, IPEndpointAddr>
}

/// Address selection result.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddrSelectResult<Epoch> {
    /// The selected address.
    addr: SocketAddr,
    /// The original endpoint from which this was derived.
    endpoint: IPEndpointAddr,
    /// Information about the new epoch.
    ///
    /// This will only be `Some` if the epoch changed; otherwise, it
    /// will be `None`.
    epoch: Option<EpochChange<Epoch, SocketAddr, IPEndpointAddr>>
}

/// Errors that can occur when creating an [AddrMultiplexer].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddrsError {
    /// Refresh error.
    Refresh(RefreshError),
    /// Error accessing name caches.
    NameCaches(NSNameCacheError),
    /// Static addresses specified, but none of them were valid.
    StaticAddrsInvalid
}

/// Errors that can occur when creating an [AddrMultiplexer].
#[derive(Clone, Debug)]
pub enum AddrsCreateError {
    /// Refresh error.
    Refresh(RefreshError),
    Resolver(
        MixedResolverCreateError<
            <Resolution<SocketAddr> as TryFrom<IPEndpoint>>::Error
        >
    )
}

/// [Policy] instance for [SocketAddr]s.
pub struct SocketAddrPolicy {
    /// Whether to prefer IPv6 addresses over IPv4, or the reverse.
    prefer_ipv6: bool,
    /// Whether to allow IPv6 addresses.
    keep_ipv6: bool,
    /// Whether to allow IPv4 addresses.
    keep_ipv4: bool
}

#[derive(Clone, Debug)]
struct AddrsHistory {
    /// Which successive retry we are on.
    nretries: usize,
    /// Total number of successes.
    nsuccesses: usize,
    /// Total number of failures.
    nfailures: usize
}

impl ScopedError for AddrsError {
    fn scope(&self) -> ErrorScope {
        match self {
            AddrsError::Refresh(err) => err.scope(),
            AddrsError::NameCaches(err) => err.scope(),
            AddrsError::StaticAddrsInvalid => ErrorScope::System
        }
    }
}

impl ScopedError for AddrsCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            AddrsCreateError::Refresh(err) => err.scope(),
            AddrsCreateError::Resolver(err) => err.scope()
        }
    }
}

impl<Epoch> AddrSelectResult<Epoch> {
    /// Get the selected address.
    #[inline]
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    #[inline]
    pub fn endpoint(&self) -> &IPEndpointAddr {
        &self.endpoint
    }

    /// Get the new epoch information, if it exists.
    #[inline]
    pub fn epoch(
        &self
    ) -> Option<&EpochChange<Epoch, SocketAddr, IPEndpointAddr>> {
        self.epoch.as_ref()
    }

    /// Deconstruct this into the socket address and the epoch change info.
    #[inline]
    pub fn take(
        self
    ) -> (
        SocketAddr,
        IPEndpointAddr,
        Option<EpochChange<Epoch, SocketAddr, IPEndpointAddr>>
    ) {
        (self.addr, self.endpoint, self.epoch)
    }
}

impl<Epochs> AddrMultiplexer<Epochs>
where
    Epochs: Iterator,
    Epochs::Item: Clone + Eq
{
    /// Create an `AddrMultiplexer` from an [IPEndpoint].
    ///
    /// This can specify either a static IP address, or a name to be
    /// resolved.  The appropriate variant will be produced for either
    /// case.
    pub fn create<Ctx>(
        ctx: &mut Ctx,
        endpoints: Vec<IPEndpoint>,
        epochs: Epochs,
        resolve: AddrsConfig
    ) -> Result<Self, AddrsCreateError>
    where
        Ctx: NSNameCachesCtx {
        let (addr_policy, resolver) = resolve.take();
        let retry = resolver.retry().clone();
        let policy = SocketAddrPolicy::create(&addr_policy);
        let sched = Scheduler::new((), retry, policy, epochs)
            .map_err(AddrsCreateError::Refresh)?;
        let resolver = MixedResolver::create(ctx, resolver, endpoints)
            .map_err(AddrsCreateError::Resolver)?;

        Ok(AddrMultiplexer {
            sched: sched,
            resolver: resolver
        })
    }

    /// Report a success for the address `addr`.
    ///
    /// This will increase the likelihood of the address being
    /// selected in the future.
    #[inline]
    pub fn success(
        &mut self,
        addr: &SocketAddr,
        origin: &IPEndpointAddr
    ) -> Result<(), ReportError<SocketAddr>> {
        self.sched.success(addr, origin)
    }

    /// Report a failure for the address `addr`.
    ///
    /// This will decrease the likelihood of the address being
    /// selected in the future.
    #[inline]
    pub fn failure(
        &mut self,
        addr: &SocketAddr,
        origin: &IPEndpointAddr
    ) -> Result<(), ReportError<SocketAddr>> {
        self.sched.failure(addr, origin)
    }

    /// Refresh addresses if necessary and return the time for which
    /// the caller should sleep before retrying if refreshing failed.
    ///
    /// If this function returns `Err`, it indicates a "hard" error;
    /// normal failure to refresh the addresses will be handled by
    /// returning `Some` amount of time for which the caller should
    /// sleep before retrying.  If this returns `None`, then the
    /// refresh was completely successful.
    pub fn refresh(
        &mut self
    ) -> Result<
        RefreshResult<EpochChange<Epochs::Item, SocketAddr, IPEndpointAddr>>,
        AddrsError
    > {
        if self.resolver.needs_refresh() {
            self.resolver
                .addrs()
                .map_err(AddrsError::NameCaches)?
                .flat_map_ok(|(resolved, _)| {
                    let addrs = resolved.map(|(addr, endpoint, _)| {
                        (addr, endpoint.ip_endpoint().clone())
                    });

                    match self.sched.refresh(Instant::now(), addrs) {
                        // Refresh succeeded.
                        Ok(epoch) => Ok(RefreshResult::Success(epoch)),
                        // No valid addresses were returned.  Return the
                        // time of the next retry.
                        Err(RefreshError::NoValidItems) => {
                            let when = self.resolver.refresh_when();

                            warn!(target: "addrs",
                                  concat!("no valid addresses were found for ",
                                          "{}, retry at {:?}"),
                                  self.resolver.names(), when);

                            match when {
                                Some(when) => Ok(RefreshResult::Retry(when)),
                                None => Err(AddrsError::StaticAddrsInvalid)
                            }
                        }
                        // Hard error
                        Err(err) => Err(AddrsError::Refresh(err))
                    }
                })
        } else {
            Ok(RefreshResult::Success(None))
        }
    }

    fn addr_no_refresh(
        &mut self,
        refresh: Option<EpochChange<Epochs::Item, SocketAddr, IPEndpointAddr>>
    ) -> Result<RetryResult<AddrSelectResult<Epochs::Item>>, AddrsError> {
        match self.sched.select() {
            Ok(val) => Ok(val.map(|(addr, endpoint, _)| AddrSelectResult {
                addr: addr,
                endpoint: endpoint,
                epoch: refresh
            })),
            // Uninitialized static multiplexer.  This should
            // never happen.
            Err(SelectError::Empty) => {
                error!(target: "addr-multiplex",
                       "no addresses in initialized multiplexer");

                Err(AddrsError::StaticAddrsInvalid)
            }
        }
    }

    pub fn addr_nonblock(
        &mut self
    ) -> Result<RetryResult<AddrSelectResult<Epochs::Item>>, AddrsError> {
        self.refresh()?
            .flat_map_ok(|epoch| self.addr_no_refresh(epoch))
    }

    /// Select an address from the available options.
    ///
    /// Under normal circumstances, this will block until addresses
    /// are available.  Note that this call can block for a long time,
    /// or even indefinitely if misconfigured, such as if a
    /// non-existent DNS name is specified, if the address policy
    /// requires a class of addresses that are not supported by
    /// available DNS servers (e.g. requires IPv6, when only IPv4
    /// addresses are resolvable), or if no DNS servers are reachable.
    ///
    /// The only cases where this function will return an error
    /// represent genuinely fatal programming errors.
    pub fn addr(
        &mut self
    ) -> Result<AddrSelectResult<Epochs::Item>, AddrsError> {
        loop {
            match self.addr_nonblock()? {
                RetryResult::Retry(when) => {
                    let now = Instant::now();

                    if now < when {
                        let delay = when - now;

                        trace!(target: "addrs",
                               "sleeping for {}.{:03}s",
                               delay.as_secs(), delay.subsec_millis());

                        sleep(delay)
                    }
                }
                RetryResult::Success(out) => return Ok(out)
            }
        }
    }
}

impl History for AddrsHistory {
    type Config = ();

    #[inline]
    fn new(_config: &()) -> Self {
        AddrsHistory {
            nretries: 0,
            nsuccesses: 0,
            nfailures: 0
        }
    }

    #[inline]
    fn success(
        &mut self,
        _config: &()
    ) {
        self.nretries = 0;
        self.nsuccesses += 1;
    }

    #[inline]
    fn failure(
        &mut self,
        _config: &()
    ) {
        self.nretries += 1;
        self.nfailures += 1;
    }

    /// Record a retry.
    #[inline]
    fn retry(
        &mut self,
        _config: &Self::Config
    ) {
        self.nretries += 1;
    }

    /// Get the number of retries.
    #[inline]
    fn nretries(&self) -> usize {
        self.nretries
    }

    #[inline]
    fn cache_score(
        &mut self,
        _config: &()
    ) {
    }

    #[inline]
    fn clear_score_cache(&mut self) {}

    /// Get the score for this history.
    fn score(
        &self,
        _config: &()
    ) -> f32 {
        let exp_retries = (self.nretries as f32).exp2() - 1.0;
        let total = self.nsuccesses as f32 + self.nfailures as f32;
        let diff =
            (self.nsuccesses as f32 - self.nfailures as f32) - exp_retries;

        if total != 0.0 {
            diff / total
        } else {
            0.0
        }
    }
}

impl SocketAddrPolicy {
    pub fn create(addr_policy: &[AddrKind]) -> Self {
        let (keep_ipv4, keep_ipv6, prefer_ipv6) = if !addr_policy.is_empty() {
            let mut saw_ipv6 = false;
            let mut saw_ipv4 = false;
            let mut prefer_ipv6 = false;

            // Deduplicate the address type list, yell about duplicates.
            for kind in addr_policy.iter() {
                match kind {
                    AddrKind::IPv6 => {
                        if saw_ipv6 {
                            error!(target: "resolve",
                                   "address policy has duplicate IPv6 entry");
                        }

                        if !saw_ipv4 {
                            prefer_ipv6 = true;
                        }

                        saw_ipv6 = true;
                    }
                    AddrKind::IPv4 => {
                        if saw_ipv4 {
                            error!(target: "resolve",
                                   "address policy has duplicate IPv4 entry");
                        }

                        saw_ipv4 = true;
                    }
                }
            }

            (saw_ipv4, saw_ipv6, prefer_ipv6)
        } else {
            error!(target: "resolve",
                   "empty address policy, defaulting to \"[ ipv6, ipv4 ]\"");

            (true, true, true)
        };

        SocketAddrPolicy {
            prefer_ipv6: prefer_ipv6,
            keep_ipv6: keep_ipv6,
            keep_ipv4: keep_ipv4
        }
    }

    #[inline]
    pub fn check_ip(
        &self,
        item: &IpAddr
    ) -> bool {
        (item.is_ipv6() && self.keep_ipv6) || (item.is_ipv4() && self.keep_ipv4)
    }
}

impl Policy for SocketAddrPolicy {
    type Item = SocketAddr;

    /// Compare two item's
    fn cmp_items(
        &self,
        a: &Self::Item,
        b: &Self::Item
    ) -> Ordering {
        match (a, b) {
            // Same address type.
            (SocketAddr::V4(_), SocketAddr::V4(_)) |
            (SocketAddr::V6(_), SocketAddr::V6(_)) => Ordering::Equal,
            // Differing address types.
            (SocketAddr::V4(_), SocketAddr::V6(_)) =>
            // Reverse ordering.
            {
                if self.prefer_ipv6 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (SocketAddr::V6(_), SocketAddr::V4(_)) =>
            // Reverse ordering.
            {
                if self.prefer_ipv6 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
        }
    }

    #[inline]
    fn check(
        &self,
        item: &Self::Item
    ) -> bool {
        self.check_ip(&item.ip())
    }
}

impl Display for AddrsError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            AddrsError::Refresh(err) => err.fmt(f),
            AddrsError::NameCaches(err) => err.fmt(f),
            AddrsError::StaticAddrsInvalid => {
                write!(f, "static address list contains no valid addresses")
            }
        }
    }
}

impl Display for AddrsCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            AddrsCreateError::Refresh(err) => err.fmt(f),
            AddrsCreateError::Resolver(err) => err.fmt(f)
        }
    }
}
