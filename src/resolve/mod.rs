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

//! Periodically-refreshing name resolution.
//!
//! This module provides [Resolver], which implements configurable
//! name-resolution with periodic refreshes and a backoff-delay
//! mechanism for failed resolution.
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::hash::Hash;
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::thread::sleep;
use std::time::Duration;
use std::time::Instant;
use std::vec::IntoIter;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::Retry;
use constellation_common::retry::RetryResult;
use constellation_streams::addrs::Addrs;
use constellation_streams::addrs::AddrsCreate;
use log::trace;
use log::warn;

use crate::config::ResolverConfig;
use crate::resolve::cache::NSName;
use crate::resolve::cache::NSNameCacheError;
use crate::resolve::cache::NSNameCaches;
use crate::resolve::cache::NSNameCachesCtx;

pub mod cache;

/// Information about how to resolve a name.
pub enum Resolution<Addr> {
    /// Perform a name lookup, and then associate with a given port.
    NSLookup {
        /// Name to resolve.
        name: String,
        /// Port with which to associate.
        port: u16
    },
    /// Static resolution.
    Static {
        /// Address to return.
        addr: Addr
    }
}

/// A simple wrapper around names being resolved that implements [Display].
#[derive(Copy, Clone)]
pub struct DisplayNSNames<'a, Addr, Origin> {
    /// The names being resolved.
    names: Option<&'a [NSName]>,
    addrs: Option<&'a [(Addr, Origin)]>
}

/// Configurable name resolver for a single name.
///
/// At present, the only mechanism for this is the standard nslookup
/// functionality.
pub struct Resolver<Addr: Clone + Display + Eq + From<SocketAddr> + Hash> {
    addr: PhantomData<Addr>,
    /// Renewal period.
    renewal: Duration,
    /// Retry configuration.
    retry: Retry,
    /// Cached resolved names.
    names: Vec<NSName>,
    /// The earliest time at which to refresh caches.
    refresh_when: Instant,
    /// The latest time at which something was cached.
    cached_when: Instant
}

/// Resolver capable of handling a mix of static and dynamic
/// [Resolution]s.
pub enum MixedResolver<Addr, Origin>
where
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash,
    Resolution<Addr>: TryFrom<Origin> {
    /// Purely resolved addresses.
    Resolve {
        /// Resolver for obtaining resolved addresses.
        resolver: Resolver<Addr>
    },
    /// Mixed static and resolved addresses
    Mixed {
        /// Resolver for obtaining resolved addresses.
        resolver: Resolver<Addr>,
        /// Fixed addresses to add into the resolved addresses.
        addrs: Vec<(Addr, Origin)>
    },
    /// Purely fixed addresses.
    Static {
        /// Fixed addresses.
        addrs: Vec<(Addr, Origin)>
    }
}

/// Iterator for [MixedResolver].
pub struct MixedResolverIter<Addr, Origin: From<IPEndpoint>> {
    resolved: Option<IntoIter<(Addr, IPEndpoint, Instant)>>,
    fixed: Option<IntoIter<(Addr, Origin)>>
}

/// Errors that can occur creating a [MixedResolver]
#[derive(Clone, Debug)]
pub enum MixedResolverCreateError<Convert> {
    /// Error occurred creating the cache.
    Cache {
        /// Error creating the cache.
        err: NSNameCacheError
    },
    /// Error occurred converting a source.
    Convert {
        /// Error converting a source.
        err: Convert
    },
    /// Resolution is entirely static, and no acceptable addresses
    /// were given.
    Empty
}

/// Result of a refresh operation.
///
/// This can indicate that the refresh succeeded, that nothing
/// happened, or that it should be retried at a point in the future.
pub type RefreshResult<T> = RetryResult<Option<T>>;

impl<Addr, Origin> Addrs for MixedResolver<Addr, Origin>
where
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash,
    Origin: Clone + From<IPEndpoint>,
    Resolution<Addr>: TryFrom<Origin>
{
    type Addr = Addr;
    type AddrsError = NSNameCacheError;
    type AddrsIter = MixedResolverIter<Addr, Origin>;
    type Origin = Origin;

    #[inline]
    fn refresh_when(&self) -> Option<Instant> {
        match self {
            MixedResolver::Resolve { resolver } |
            MixedResolver::Mixed { resolver, .. } => resolver.refresh_when(),
            MixedResolver::Static { .. } => None
        }
    }

    #[inline]
    fn addrs(
        &mut self
    ) -> Result<
        RetryResult<(MixedResolverIter<Addr, Origin>, Option<Instant>)>,
        NSNameCacheError
    > {
        match self {
            MixedResolver::Resolve { resolver } => {
                Ok(resolver.addrs()?.map(|(addrs, refresh_when)| {
                    let iter = MixedResolverIter {
                        resolved: Some(addrs),
                        fixed: None
                    };

                    (iter, refresh_when)
                }))
            }
            MixedResolver::Mixed { resolver, addrs } => {
                Ok(resolver.addrs()?.map(|(resolved, refresh_when)| {
                    let iter = MixedResolverIter {
                        fixed: Some(addrs.clone().into_iter()),
                        resolved: Some(resolved)
                    };

                    (iter, refresh_when)
                }))
            }
            MixedResolver::Static { addrs } => {
                let iter = MixedResolverIter {
                    fixed: Some(addrs.clone().into_iter()),
                    resolved: None
                };

                Ok(RetryResult::Success((iter, None)))
            }
        }
    }
}

impl<Addr, Origin, Ctx> AddrsCreate<Ctx, Vec<Origin>>
    for MixedResolver<Addr, Origin>
where
    Ctx: NSNameCachesCtx,
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash,
    Origin: Clone + From<IPEndpoint>,
    Resolution<Addr>: TryFrom<Origin>,
    <Resolution<Addr> as TryFrom<Origin>>::Error: Display
{
    type Config = ResolverConfig;
    type CreateError =
        MixedResolverCreateError<<Resolution<Addr> as TryFrom<Origin>>::Error>;

    fn create(
        ctx: &mut Ctx,
        config: Self::Config,
        origins: Vec<Origin>
    ) -> Result<Self, Self::CreateError> {
        let mut fixed = Vec::with_capacity(origins.len());
        let mut resolved = Vec::with_capacity(origins.len());

        for origin in origins {
            match Resolution::try_from(origin.clone())
                .map_err(|err| MixedResolverCreateError::Convert { err: err })?
            {
                Resolution::NSLookup { name, port } => {
                    resolved.push((name, port))
                }
                Resolution::Static { addr } => fixed.push((addr, origin))
            }
        }

        if !resolved.is_empty() {
            let resolver = Resolver::create(ctx, config, resolved.into_iter())
                .map_err(|err| MixedResolverCreateError::Cache { err: err })?;

            if !fixed.is_empty() {
                fixed.shrink_to_fit();

                Ok(MixedResolver::Mixed {
                    resolver: resolver,
                    addrs: fixed
                })
            } else {
                Ok(MixedResolver::Resolve { resolver: resolver })
            }
        } else if !fixed.is_empty() {
            fixed.shrink_to_fit();

            Ok(MixedResolver::Static { addrs: fixed })
        } else {
            Err(MixedResolverCreateError::Empty)
        }
    }
}

impl<Addr> MixedResolver<Addr, IPEndpoint>
where
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash,
    Resolution<Addr>: TryFrom<IPEndpoint>
{
    /// Get a representation of the names being resolved that
    /// implements [Display].
    #[inline]
    pub fn names(&self) -> DisplayNSNames<'_, Addr, IPEndpoint> {
        match self {
            MixedResolver::Resolve { resolver, .. } => resolver.names(),
            MixedResolver::Mixed { resolver, addrs } => {
                let mut out = resolver.names();

                out.addrs = Some(&addrs[..]);

                out
            }
            MixedResolver::Static { addrs } => DisplayNSNames {
                addrs: Some(&addrs[..]),
                names: None
            }
        }
    }
}

impl<Addr> Addrs for Resolver<Addr>
where
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash
{
    type Addr = Addr;
    type AddrsError = NSNameCacheError;
    type AddrsIter = IntoIter<(Addr, IPEndpoint, Instant)>;
    type Origin = IPEndpoint;

    #[inline]
    fn refresh_when(&self) -> Option<Instant> {
        Some(self.refresh_when)
    }

    #[inline]
    fn addrs(
        &mut self
    ) -> Result<
        RetryResult<(IntoIter<(Addr, IPEndpoint, Instant)>, Option<Instant>)>,
        NSNameCacheError
    > {
        Ok(self.snapshot()?.map(|(snapshot, cached_when)| {
            (snapshot.into_iter(), Some(cached_when))
        }))
    }
}

impl<Addr, Ctx, I> AddrsCreate<Ctx, I> for Resolver<Addr>
where
    Ctx: NSNameCachesCtx,
    I: Iterator<Item = (String, u16)>,
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash
{
    type Config = ResolverConfig;
    type CreateError = NSNameCacheError;

    fn create(
        ctx: &mut Ctx,
        config: Self::Config,
        origin: I
    ) -> Result<Self, Self::CreateError> {
        let (renewal, retry) = config.take();
        let caches = ctx.name_caches();
        let names = caches.ns_names(origin)?;
        let now = Instant::now();

        Ok(Resolver {
            addr: PhantomData,
            names: names,
            renewal: Duration::from_secs(renewal as u64),
            retry: retry,
            refresh_when: now,
            cached_when: now
        })
    }
}

impl<Addr> Resolver<Addr>
where
    Addr: Clone + Display + Eq + From<SocketAddr> + Hash
{
    /// Get a representation of the names being resolved that
    /// implements [Display].
    #[inline]
    pub fn names(&self) -> DisplayNSNames<'_, Addr, IPEndpoint> {
        DisplayNSNames {
            names: Some(&self.names),
            addrs: None
        }
    }

    /// Get the latest past time that addresses were cached.
    ///
    /// This is a "fast path"- it does not take a lock on shared
    /// caches, and only reports the cache times as of the last time
    /// the caches were refreshed.
    #[inline]
    pub fn cached_when(&self) -> Instant {
        self.cached_when
    }

    /// Check if a refresh is needed.
    #[inline]
    pub fn needs_refresh(&self) -> bool {
        Instant::now() > self.refresh_when
    }

    /// Refresh all caches.
    ///
    /// This will return a [RefreshResult] depending on the outcome:
    ///
    ///  - `Success(None)`: No refresh was needed.
    ///
    ///  - `Success(Some(..))`: A refresh was performed, yielding at least one
    ///    result.
    ///
    ///  - [Retry](RefreshResult::Retry): A refresh was performed, but no
    ///    addresses were found.  The refresh should be retried at the specified
    ///    time.
    pub fn refresh(&mut self) -> Result<RefreshResult<()>, NSNameCacheError> {
        // Don't spin on this condition; it could livelock for
        // misconfigurations.
        if self.needs_refresh() {
            let Resolver {
                names,
                renewal,
                retry,
                refresh_when,
                cached_when,
                ..
            } = self;
            let mut cache_empty = true;

            // Run until we have at least one cache entry.
            while cache_empty {
                // Worst-case behavior here is a busy loop,
                // but it won't deadsleep forever.
                //
                // Also, reset this every iteration.
                let mut min_refresh: Option<Instant> = None;
                let mut max_cached = *cached_when;

                // Run over each name, try to refresh the cache.
                for name in names.iter_mut() {
                    let (empty, cached_when) = name.refresh(*renewal, retry)?;

                    cache_empty &= empty;
                    min_refresh = match min_refresh {
                        Some(min_refresh) => {
                            Some(min_refresh.min(name.refresh_when()))
                        }
                        None => Some(name.refresh_when())
                    };

                    if let Some(cached_when) = cached_when {
                        max_cached = max_cached.max(cached_when)
                    }
                }

                // If the cache is still empty, we have to
                // sleep.
                if cache_empty {
                    let now = Instant::now();

                    match min_refresh {
                        Some(min_refresh) if min_refresh > now => {
                            let delay = min_refresh - now;

                            warn!(target: "resolve",
                                  concat!("no valid addresses found, ",
                                          "retry after {}.{:03}s"),
                                  delay.as_secs(), delay.subsec_millis());

                            return Ok(RefreshResult::Retry(min_refresh));
                        }
                        _ => {
                            warn!(target: "resolve",
                                  concat!("no valid addresses found, ",
                                          "retrying resolution without ",
                                          "delay"));

                            return Ok(RefreshResult::Retry(Instant::now()));
                        }
                    }
                } else {
                    // Set the refresh time to the global
                    // minimum through this iteration.
                    *refresh_when = min_refresh.unwrap_or(Instant::now());
                    *cached_when = max_cached;
                }
            }

            Ok(RefreshResult::Success(Some(())))
        } else {
            Ok(RefreshResult::Success(None))
        }
    }

    fn do_snapshot(
        &mut self
    ) -> Result<(Vec<(Addr, IPEndpoint, Instant)>, Instant), NSNameCacheError>
    {
        let Resolver {
            names, cached_when, ..
        } = self;

        let mut cached_max = *cached_when;
        // Rationale: guess one IPv4 and one IPv6 address per name.
        let mut out = Vec::with_capacity(names.len() * 2);

        for name in names {
            match name.cache().read() {
                Ok(guard) => {
                    if !guard.cached().is_empty() {
                        match guard.cached_when() {
                            Some(time) => {
                                for addr in guard.cached().iter() {
                                    let addr =
                                        SocketAddr::new(*addr, name.port());
                                    let endpoint = IPEndpointAddr::name(
                                        String::from(name.name())
                                    );
                                    let endpoint =
                                        IPEndpoint::new(endpoint, name.port());

                                    cached_max = cached_max.max(time);
                                    out.push((Addr::from(addr), endpoint, time))
                                }
                            }
                            None => return Err(NSNameCacheError::Inconsistent)
                        }
                    }
                }
                Err(_) => return Err(NSNameCacheError::MutexPoison)
            }
        }

        out.shrink_to_fit();
        *cached_when = cached_max;

        Ok((out, cached_max))
    }

    /// Take a non-atomic snapshot of all resolved names.
    ///
    /// This function is expensive.  Even if the caches are not
    /// refreshed, it still needs to copy all of their contents to
    /// create the output iterator.  It is advised to check
    /// [refresh_when](Resolver::refresh_when) to avoid redundant
    /// calls to this function.
    ///
    /// # Strictness
    ///
    /// This function only makes a "best effort" to implement the
    /// refresh time policy.  If multiple names are provided, under
    /// certain conditions and configurations, it is possible that the
    /// address resolution results returned by this will be stale.
    /// The rationale behind this is that NS lookups are inherently
    /// non-atomic; thus, there exists an unavoidable tradeoff between
    /// strictness and livelock avoidance.  Therefore, strictness is
    /// sacrified to prevent an adversary capable of selectively
    /// disrupting NS lookups from inducing a livelock.
    pub fn snapshot(
        &mut self
    ) -> Result<
        RetryResult<(Vec<(Addr, IPEndpoint, Instant)>, Instant)>,
        NSNameCacheError
    > {
        // Refresh if necessary.
        self.refresh()?.map_ok(|_| self.do_snapshot())
    }

    /// Get an iterator for the current set of resolved addresses.
    ///
    /// This will potentially block for a long time, or indefinitely
    /// if the time for refreshing the resolution is past and there
    /// are no reachable DNS servers, or if the specified name does
    /// not exist in any DNS server's records.
    ///
    /// This function is also expensive.  Even if the caches are not
    /// refreshed, it still needs to copy all of their contents to
    /// create the output iterator.  It is advised to check
    /// [refresh_when](Resolver::refresh_when) to avoid redundant
    /// calls to this function.
    ///
    /// This function only makes a "best effort" to implement the
    /// refresh time policy.  If multiple names are provided, under
    /// certain conditions and configurations, it is possible that the
    /// address resolution results returned by this will be stale.
    /// The rationale behind this is that NS lookups are inherently
    /// non-atomic; thus, there exists an unavoidable tradeoff between
    /// strictness and livelock avoidance.  Therefore, strictness is
    /// sacrified to prevent an adversary capable of selectively
    /// disrupting NS lookups from inducing a livelock.
    pub fn addrs_block(
        &mut self
    ) -> Result<
        (IntoIter<(Addr, IPEndpoint, Instant)>, Option<Instant>),
        NSNameCacheError
    > {
        loop {
            match self.addrs()? {
                RetryResult::Retry(when) => {
                    let now = Instant::now();

                    if now < when {
                        let delay = when - now;

                        trace!(target: "resolve",
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

impl From<IPEndpoint> for Resolution<SocketAddr> {
    fn from(val: IPEndpoint) -> Resolution<SocketAddr> {
        let (ip, port) = val.take();

        match ip {
            IPEndpointAddr::Name(name) => Resolution::NSLookup {
                name: name,
                port: port
            },
            IPEndpointAddr::Addr(addr) => Resolution::Static {
                addr: SocketAddr::new(addr, port)
            }
        }
    }
}

impl<Addr, Origin> Iterator for MixedResolverIter<Addr, Origin>
where
    Origin: From<IPEndpoint>
{
    type Item = (Addr, Origin, Instant);

    fn next(&mut self) -> Option<(Addr, Origin, Instant)> {
        match &mut self.resolved {
            Some(resolved) => match resolved.next() {
                None => {
                    self.resolved = None;

                    self.next()
                }
                Some((addr, origin, when)) => {
                    Some((addr, Origin::from(origin), when))
                }
            },
            None => match &mut self.fixed {
                Some(fixed) => match fixed.next() {
                    None => {
                        self.fixed = None;

                        self.next()
                    }
                    Some((addr, origin)) => Some((addr, origin, Instant::now()))
                },
                None => None
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }
}

impl<Addr, Origin> ExactSizeIterator for MixedResolverIter<Addr, Origin>
where
    Origin: From<IPEndpoint>
{
    #[inline]
    fn len(&self) -> usize {
        match (&self.resolved, &self.fixed) {
            (Some(resolved), Some(fixed)) => resolved.len() + fixed.len(),
            (Some(resolved), None) => resolved.len(),
            (None, Some(fixed)) => fixed.len(),
            (None, None) => 0
        }
    }
}

impl<Addr, Origin> FusedIterator for MixedResolverIter<Addr, Origin> where
    Origin: From<IPEndpoint>
{
}

impl<Addr, Origin> Display for DisplayNSNames<'_, Addr, Origin>
where
    Addr: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self.names {
            Some(names) => match self.addrs {
                Some(addrs) => {
                    let mut first = true;

                    write!(f, "[")?;

                    for name in names.iter() {
                        if first {
                            first = false;

                            write!(f, "{}", name.name())?
                        } else {
                            write!(f, ",{}", name.name())?
                        }
                    }

                    for (addr, _) in addrs.iter() {
                        if first {
                            first = false;

                            write!(f, "{}", addr)?
                        } else {
                            write!(f, ",{}", addr)?
                        }
                    }

                    write!(f, "]")
                }
                None => {
                    if names.len() == 1 {
                        write!(f, "{}", names[0].name())
                    } else {
                        let mut first = true;

                        write!(f, "[")?;

                        for name in names.iter() {
                            if first {
                                first = false;

                                write!(f, "{}", name.name())?
                            } else {
                                write!(f, ",{}", name.name())?
                            }
                        }

                        write!(f, "]")
                    }
                }
            },
            None => match self.addrs {
                Some(addrs) => {
                    if addrs.len() == 1 {
                        write!(f, "{}", addrs[0].0)
                    } else {
                        let mut first = true;

                        write!(f, "[")?;

                        for (addr, _) in addrs.iter() {
                            if first {
                                first = false;

                                write!(f, "{}", addr)?
                            } else {
                                write!(f, ",{}", addr)?
                            }
                        }

                        write!(f, "]")
                    }
                }
                None => Ok(())
            }
        }
    }
}

impl<Convert> ScopedError for MixedResolverCreateError<Convert>
where
    Convert: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            MixedResolverCreateError::Cache { err } => err.scope(),
            MixedResolverCreateError::Convert { err } => err.scope(),
            MixedResolverCreateError::Empty => ErrorScope::External
        }
    }
}

impl<Convert> Display for MixedResolverCreateError<Convert>
where
    Convert: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            MixedResolverCreateError::Cache { err } => err.fmt(f),
            MixedResolverCreateError::Convert { err } => err.fmt(f),
            MixedResolverCreateError::Empty => {
                write!(f, "no addresses provided")
            }
        }
    }
}
