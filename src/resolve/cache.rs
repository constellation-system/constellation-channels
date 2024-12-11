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

//! Caches for name resolution.
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::Weak;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use constellation_common::error::ErrorScope;
use constellation_common::error::MutexPoison;
use constellation_common::error::ScopedError;
use constellation_common::retry::Retry;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;

use crate::config::ThreadedNSNameCachesConfig;

/// Context object that can field an [NSNameCaches] instance.
pub trait NSNameCachesCtx {
    /// Exact type of name caches.
    type NameCaches: NSNameCaches;

    /// Get a reference to the name caches.
    fn name_caches(&mut self) -> &mut Self::NameCaches;
}

/// Trait for name resolution caches.
pub trait NSNameCaches {
    // XXX we will want to make the error an associated type here
    // eventually.

    /// Create an [NSName] for `name` and `port`.
    fn ns_name(
        &self,
        name: String,
        port: u16
    ) -> Result<NSName, NSNameCacheError>;

    /// Convert an [Iterator] over names into a [Vec] of [NSName]s.
    #[inline]
    fn ns_names<I>(
        &self,
        names: I
    ) -> Result<Vec<NSName>, NSNameCacheError>
    where
        I: Iterator<Item = (String, u16)> {
        names.map(|(name, port)| self.ns_name(name, port)).collect()
    }
}

/// Cached NSS name lookups.
pub(crate) struct NSNameCache {
    /// Cached addresses.
    cached: Vec<IpAddr>,
    /// When these were cached.
    cached_when: Option<Instant>,
    /// Number of retries.
    nretries: usize
}

// XXX NSName is messy and should be refactored.
//
// 1) Parameterize it on the name cache type
// 2) Move it back into resolve

/// Handle to a cache of NS name lookups.
#[derive(Clone)]
pub struct NSName {
    /// Name to be resolved.
    name: String,
    /// Port number to which to bind.
    port: u16,
    /// Time at which to refresh resolved addresses.
    refresh_when: Instant,
    /// Shared cache object.
    cache: Arc<RwLock<NSNameCache>>
}

/// Notifier for additions to the name caches.
struct ThreadedNSNameCachesNotify {
    /// Condition variable to signal when adding cache entries.
    cond: Condvar,
    /// Boolean flag to indicate that cache entries have been added.
    added: Mutex<bool>
}

/// Shared name resolution caches, without a refresher thread.
///
/// This is a collection of shared caches used to build [NSName]s.
#[derive(Clone)]
pub struct SharedNSNameCaches {
    /// Name resolution cache.
    caches: Arc<RwLock<HashMap<String, Weak<RwLock<NSNameCache>>>>>
}

/// Shared name resolution caches, with a refresher thread.
///
/// This is identical to [SharedNSNameCaches], except that a thread
/// will be launched to automatically refresh entries in the
/// background.
///
/// Lookups will still also attempt to refresh cache entries; however,
/// the refresher thread should ensure that they are up to date most
/// of the time.
#[derive(Clone)]
pub struct ThreadedNSNameCaches {
    /// Name resolution cache.
    caches: Arc<RwLock<HashMap<String, Weak<RwLock<NSNameCache>>>>>,
    /// Notifier for the refresher thread.
    notify: Arc<ThreadedNSNameCachesNotify>
}

/// Errors that can occur when handling name caches.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NSNameCacheError {
    /// Cache is in an inconsistent state.
    Inconsistent,
    /// Mutex was poisoned.
    MutexPoison
}

impl NSName {
    /// Create a new `NSName`
    #[inline]
    fn create(
        name: String,
        port: u16,
        cache: Arc<RwLock<NSNameCache>>
    ) -> NSName {
        let now = Instant::now();

        NSName {
            cache: cache,
            refresh_when: now,
            name: name,
            port: port
        }
    }

    /// Get a handle for the cache associated with this name.
    #[inline]
    pub(crate) fn cache(&self) -> Arc<RwLock<NSNameCache>> {
        self.cache.clone()
    }

    /// Get the name being resolved.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the next time at which this `NSName` should be refreshed.
    #[inline]
    pub fn refresh_when(&self) -> Instant {
        self.refresh_when
    }

    /// Get the port associated with resolved addresses for this `NSName`.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Refresh the underlying cache if needed, returning whether it
    /// is empty and when it was last refreshed.
    pub(crate) fn refresh(
        &mut self,
        renewal: Duration,
        retry: &Retry
    ) -> Result<(bool, Option<Instant>), NSNameCacheError> {
        // First, check in read-only mode if the cache entry is stale.
        let out = match self.cache.read() {
            Ok(guard) => {
                if let Some(time) = guard.cached_when &&
                    time >= self.refresh_when
                {
                    trace!(target: "ns-name",
                           "cache entry for \"{}\" was refreshed recently",
                           self.name);

                    Ok(Some((guard.cached.is_empty(), guard.cached_when)))
                } else {
                    trace!(target: "ns-name",
                           "cache entry for \"{}\" is stale",
                           self.name);

                    Ok(None)
                }
            }
            Err(_) => Err(NSNameCacheError::MutexPoison)
        }?;

        match out {
            Some(out) => Ok(out),
            None => match self.cache.write() {
                Ok(mut guard) => {
                    if let Some(time) = guard.cached_when &&
                        time >= self.refresh_when
                    {
                        // Someone got to it before we did.
                        trace!(target: "ns-name",
                               "cache entry for \"{}\" was refreshed",
                               self.name);

                        Ok((guard.cached.is_empty(), guard.cached_when))
                    } else {
                        let (_, _, refresh_when) =
                            guard.refresh(&self.name, renewal, retry);

                        self.refresh_when = refresh_when;

                        Ok((guard.cached.is_empty(), guard.cached_when))
                    }
                }
                Err(_) => Err(NSNameCacheError::MutexPoison)
            }
        }
    }
}

impl NSNameCache {
    /// Get the cached addresses.
    #[inline]
    pub(crate) fn cached(&self) -> &[IpAddr] {
        &self.cached
    }

    /// Get the time at which this cache was last refreshed.
    #[inline]
    pub(crate) fn cached_when(&self) -> Option<Instant> {
        self.cached_when
    }

    /// Refresh this cache entry, returning whether the cache is
    /// empty, when it was cached, and when it needs to be refreshed
    /// again.
    ///
    /// This does not check if the refresh needs to actually be performed.
    fn refresh(
        &mut self,
        name: &str,
        renewal: Duration,
        retry: &Retry
    ) -> (bool, Option<Instant>, Instant) {
        info!(target: "resolve",
              "refreshing name resolution for \"{}\"",
              name);
        match (name, 0).to_socket_addrs() {
            Ok(addrs) => {
                let addrs = addrs.map(|a| a.ip()).collect();
                let now = Instant::now();

                info!(target: "resolve",
                      "refreshed name resolution for \"{}\"",
                      name);

                self.cached_when = Some(now);
                self.cached = addrs;

                (self.cached.is_empty(), self.cached_when, now + renewal)
            }
            Err(err) => {
                let delay = retry.retry_delay(self.nretries);
                let now = Instant::now();

                warn!(target: "resolve",
                      concat!("resolution for \"{}\" ",
                              "failed ({}), ",
                              "retry in {}.{:03}s"),
                      name, err, delay.as_secs(),
                      delay.subsec_millis());

                self.nretries += 1;
                self.cached.clear();

                (self.cached.is_empty(), self.cached_when, now + delay)
            }
        }
    }

    /// Refresh this cache entry if needed, returning whether the
    /// cache is empty, when it was cached, and when it needs to be
    /// refreshed again.
    fn check_refresh(
        &mut self,
        name: &str,
        renewal: Duration,
        retry: &Retry
    ) -> (bool, Option<Instant>, Instant) {
        let now = Instant::now();

        if let Some(time) = self.cached_when &&
            time >= now
        {
            (self.cached.is_empty(), self.cached_when, now + renewal)
        } else {
            self.refresh(name, renewal, retry)
        }
    }
}

impl ThreadedNSNameCachesNotify {
    /// Create a new notifier.
    #[inline]
    fn new() -> Self {
        ThreadedNSNameCachesNotify {
            added: Mutex::new(false),
            cond: Condvar::new()
        }
    }

    /// Set the flag and notify one waiter.
    #[inline]
    fn notify(&self) -> Result<(), MutexPoison> {
        match self.added.lock() {
            Ok(mut guard) => {
                trace!(target: "ns-name-cache-notify",
                       "sending notification");

                *guard = true;

                self.cond.notify_one();

                Ok(())
            }
            Err(_) => Err(MutexPoison)
        }
    }

    /// Wait until the time `until` only if the flag is clear,
    /// otherwise return immediately.
    #[inline]
    fn wait(
        &self,
        until: Option<Instant>
    ) -> Result<(), MutexPoison> {
        match self.added.lock() {
            // Check if the flag is set
            Ok(guard) => {
                let mut guard = guard;

                // Keep waiting until the flag is set, or the delay
                // has passed.
                while !*guard &&
                    until.map(|until| until > Instant::now()).unwrap_or(true)
                {
                    // See if we need a timeout.
                    match until {
                        // We have a timeout.
                        Some(until) => {
                            let now = Instant::now();

                            // Check that the timeout hasn't happened.
                            if until > now {
                                // Wait until the timeout.
                                let delay = until - now;

                                trace!(target: "ns-name-cache-notify",
                                       "waiting {}.{:03}s for notify",
                                       delay.as_secs(), delay.subsec_millis());

                                guard = self
                                    .cond
                                    .wait_timeout(guard, until - now)
                                    .map(|(guard, _)| guard)
                                    .map_err(|_| MutexPoison)?;
                            }
                        }
                        // No timeout.
                        None => {
                            trace!(target: "ns-name-cache-notify",
                                   "waiting indefinitely for notify");

                            guard = self
                                .cond
                                .wait(guard)
                                .map_err(|_| MutexPoison)?;
                        }
                    }
                }

                // We're done; clear the flag and go.
                trace!(target: "ns-name-cache-notify",
                       "finished waiting");

                *guard = false;

                Ok(())
            }
            Err(_) => Err(MutexPoison)
        }
    }
}

/// Main runner for the refresher thread.
fn run_refresh_thread(
    cache: Weak<RwLock<HashMap<String, Weak<RwLock<NSNameCache>>>>>,
    notify: Arc<ThreadedNSNameCachesNotify>,
    renewal: Duration,
    retry: Retry
) {
    debug!(target: "ns-name-cache-refresh",
           "launching refresher thread for name caches");

    while let Some(cache) = cache.upgrade() {
        debug!(target: "ns-name-cache-refresh",
               "checking name caches for refresh");

        // Do a read-only scan of the cache to see if we need to
        // do anything.
        let earliest = match cache.read() {
            Ok(guard) => {
                let mut earliest: Option<Instant> = None;

                for (name, cache) in guard.iter() {
                    if let Some(cache) = cache.upgrade() {
                        match cache.read() {
                            // Check when the entry was last refreshed.
                            Ok(guard) => {
                                match guard.cached_when {
                                    // The entry needs to be refreshed
                                    // after the renewal period.
                                    Some(prev) => {
                                        let when = prev + renewal;

                                        earliest =
                                            Some(earliest.map_or(
                                                Instant::now(),
                                                |curr| curr.min(when)
                                            ));
                                    }
                                    // The entry is brand new, and
                                    // needs to be resolved for the
                                    // frist time.
                                    None => {
                                        let now = Instant::now();

                                        error!(target: "ns-name-cache-refresh",
                                           "entry for {} not initialized",
                                           name);

                                        earliest =
                                            Some(earliest.map_or(
                                                Instant::now(),
                                                |curr| curr.min(now)
                                            ));
                                    }
                                }
                            }
                            Err(_) => {
                                error!(target: "ns-name-cache-refresh",
                                       "rw lock poisoned for {}",
                                       name);
                                warn!(target: "ns-name-cache-refresh",
                                      "refresher thread exiting");

                                return;
                            }
                        }
                    } else {
                        // A stale cache entry, needs to be purged.
                        let now = Instant::now();

                        debug!(target: "ns-name-cache-refresh",
                               "entry for {} is expired",
                               name);

                        earliest = Some(
                            earliest
                                .map_or(Instant::now(), |curr| curr.min(now))
                        );
                    }
                }

                earliest
            }
            Err(_) => {
                error!(target: "ns-name-cache-refresh",
                       "name cache rw lock poisoned");
                warn!(target: "ns-name-cache-refresh",
                      "refresher thread exiting");

                return;
            }
        };

        // Check if we need to do a write pass.
        let earliest = if let Some(earliest) = earliest &&
            earliest <= Instant::now()
        {
            debug!(target: "ns-name-cache-refresh",
                   "refreshing name caches");

            match cache.write() {
                Ok(mut guard) => {
                    let mut earliest: Option<Instant> = None;

                    for (name, cache) in guard.iter() {
                        if let Some(cache) = cache.upgrade() {
                            match cache.write() {
                                Ok(mut guard) => {
                                    let (_, _, when) = guard
                                        .check_refresh(name, renewal, &retry);

                                    earliest =
                                        Some(earliest.map_or(when, |curr| {
                                            curr.min(when)
                                        }));
                                }
                                Err(_) => {
                                    error!(target: "ns-name-cache-refresh",
                                           "rw lock poisoned for {}",
                                           name);
                                    warn!(target: "ns-name-cache-refresh",
                                          "refresher thread exiting");

                                    return;
                                }
                            }
                        } else {
                            debug!(target: "ns-name-cache-refresh",
                                   "entry for {} is expired",
                                   name);
                        }
                    }

                    // Wipe out all the stale entries
                    guard.retain(|_, cache| cache.upgrade().is_some());

                    earliest
                }
                Err(_) => {
                    error!(target: "ns-name-cache-refresh",
                           "name cache rw lock poisoned");
                    warn!(target: "ns-name-cache-refresh",
                          "refresher thread exiting");

                    return;
                }
            }
        } else {
            earliest
        };

        // Now wait for notification
        if notify.wait(earliest).is_err() {
            error!(target: "ns-name-cache-refresh",
                   "name cache notify mutex poisoned");
            warn!(target: "ns-name-cache-refresh",
                  "refresher thread exiting");

            return;
        }
    }

    info!(target: "ns-name-cache-refresh",
          "name caches have been dropped, refresher thread exiting")
}

impl NSNameCachesCtx for SharedNSNameCaches {
    type NameCaches = SharedNSNameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut SharedNSNameCaches {
        self
    }
}

impl ScopedError for NSNameCacheError {
    fn scope(&self) -> ErrorScope {
        match self {
            NSNameCacheError::Inconsistent => ErrorScope::Unrecoverable,
            NSNameCacheError::MutexPoison => ErrorScope::Unrecoverable
        }
    }
}

impl Default for SharedNSNameCaches {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SharedNSNameCaches {
    #[inline]
    pub fn create(size_hint: Option<usize>) -> Self {
        match size_hint {
            Some(size) => Self::with_capacity(size),
            None => Self::new()
        }
    }

    #[inline]
    pub fn new() -> Self {
        SharedNSNameCaches {
            caches: Arc::new(RwLock::new(HashMap::new()))
        }
    }

    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        SharedNSNameCaches {
            caches: Arc::new(RwLock::new(HashMap::with_capacity(size)))
        }
    }

    /// Obtain the shared [NSNameCache] for `name`, and indicate
    /// whether it was newly-created.
    ///
    /// The boolean flag to indicate it was newly-created is for the
    /// implementation of [ThreadedNSNameCaches], to tell when to
    /// notify.
    fn cache(
        &self,
        name: String
    ) -> Result<(Arc<RwLock<NSNameCache>>, bool), NSNameCacheError> {
        debug!(target: "ns-name-caches",
               "acquiring NS name cache for {}",
               name);

        trace!(target: "ns-name-caches",
               "attempting read-only lookup for {}",
               name);

        // Try to get a result from read-only operations.
        let out = match self.caches.read() {
            // We get a weak reference; try to upgrade it.
            Ok(read) => Ok(read.get(&name).and_then(|weak| weak.upgrade())),
            Err(_) => Err(NSNameCacheError::MutexPoison)
        }?;

        // Check to see if we can return immediately, or if we
        // need to write to the caches.
        match out {
            // We can return immediately.
            Some(out) => {
                trace!(target: "ns-name-caches",
                       "acquired existing cache for {}",
                       name);

                Ok((out, false))
            }
            // We possibly need to insert into the cache (though
            // someone else might have done that already).
            None => match self.caches.write() {
                Ok(mut write) => match write.entry(name) {
                    // There's an entry, but it might be a dead weak reference.
                    Entry::Occupied(mut ent) => match ent.get().upgrade() {
                        // There's a valid reference here; return it.
                        Some(out) => {
                            trace!(target: "ns-name-caches",
                                   "found valid cache for {}",
                                   ent.key());

                            Ok((out, false))
                        }
                        // The weak reference had expired; create a new cache.
                        None => {
                            trace!(target: "ns-name-caches",
                                   "found expired weak reference for {}",
                                   ent.key());

                            let cache = Arc::new(RwLock::new(NSNameCache {
                                cached: vec![],
                                cached_when: None,
                                nretries: 0
                            }));

                            ent.insert(Arc::downgrade(&cache));

                            Ok((cache, true))
                        }
                    },
                    // Nothing's here; create a new cache.
                    Entry::Vacant(ent) => {
                        debug!(target: "ns-name-caches",
                               "creating new name cache for {}",
                               ent.key());

                        let cache = Arc::new(RwLock::new(NSNameCache {
                            cached: vec![],
                            cached_when: None,
                            nretries: 0
                        }));

                        ent.insert(Arc::downgrade(&cache));

                        Ok((cache, true))
                    }
                },
                Err(_) => Err(NSNameCacheError::MutexPoison)
            }
        }
    }
}

impl NSNameCaches for SharedNSNameCaches {
    #[inline]
    fn ns_name(
        &self,
        name: String,
        port: u16
    ) -> Result<NSName, NSNameCacheError> {
        let (cache, _) = self.cache(name.clone())?;

        Ok(NSName::create(name, port, cache))
    }
}

impl NSNameCachesCtx for ThreadedNSNameCaches {
    type NameCaches = ThreadedNSNameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut ThreadedNSNameCaches {
        self
    }
}

impl ThreadedNSNameCaches {
    pub fn create(
        config: ThreadedNSNameCachesConfig
    ) -> (Self, JoinHandle<()>) {
        info!(target: "ns-name-cache",
              "creating name caches");

        let (size_hint, renewal, retry) = config.take();
        let caches = match size_hint {
            Some(size) => Arc::new(RwLock::new(HashMap::with_capacity(size))),
            None => Arc::new(RwLock::new(HashMap::new()))
        };
        let notify = Arc::new(ThreadedNSNameCachesNotify::new());
        let thread_caches = Arc::downgrade(&caches);
        let thread_notify = notify.clone();

        // Start the refresher thread.
        let handle = std::thread::spawn(move || {
            run_refresh_thread(thread_caches, thread_notify, renewal, retry)
        });

        (
            ThreadedNSNameCaches {
                caches: caches,
                notify: notify
            },
            handle
        )
    }

    /// Obtain the shared [NSNameCache] for `name`.
    fn cache(
        &self,
        name: String
    ) -> Result<Arc<RwLock<NSNameCache>>, NSNameCacheError> {
        debug!(target: "ns-name-caches",
               "acquiring NS name cache for {}",
               name);

        trace!(target: "ns-name-caches",
               "attempting read-only lookup for {}",
               name);

        // Try to get a result from read-only operations.
        let out = match self.caches.read() {
            // We get a weak reference; try to upgrade it.
            Ok(read) => Ok(read.get(&name).and_then(|weak| weak.upgrade())),
            Err(_) => Err(NSNameCacheError::MutexPoison)
        }?;

        // Check to see if we can return immediately, or if we
        // need to write to the caches.
        match out {
            // We can return immediately.
            Some(out) => {
                trace!(target: "ns-name-caches",
                       "acquired existing cache for {}",
                       name);

                Ok(out)
            }
            // We possibly need to insert into the cache (though
            // someone else might have done that already).
            None => match self.caches.write() {
                Ok(mut write) => match write.entry(name) {
                    // There's an entry, but it might be a dead weak reference.
                    Entry::Occupied(mut ent) => match ent.get().upgrade() {
                        // There's a valid reference here; return it.
                        Some(out) => {
                            trace!(target: "ns-name-caches",
                                   "found valid cache for {}",
                                   ent.key());

                            Ok(out)
                        }
                        // The weak reference had expired; create a new cache.
                        None => {
                            trace!(target: "ns-name-caches",
                                   "found expired weak reference for {}",
                                   ent.key());

                            let cache = Arc::new(RwLock::new(NSNameCache {
                                cached: vec![],
                                cached_when: None,
                                nretries: 0
                            }));

                            ent.insert(Arc::downgrade(&cache));
                            self.notify
                                .notify()
                                .map_err(|_| NSNameCacheError::MutexPoison)?;

                            Ok(cache)
                        }
                    },
                    // Nothing's here; create a new cache.
                    Entry::Vacant(ent) => {
                        debug!(target: "ns-name-caches",
                               "creating new name cache for {}",
                               ent.key());

                        let cache = Arc::new(RwLock::new(NSNameCache {
                            cached: vec![],
                            cached_when: None,
                            nretries: 0
                        }));

                        ent.insert(Arc::downgrade(&cache));
                        self.notify
                            .notify()
                            .map_err(|_| NSNameCacheError::MutexPoison)?;

                        Ok(cache)
                    }
                },
                Err(_) => Err(NSNameCacheError::MutexPoison)
            }
        }
    }
}

impl NSNameCaches for ThreadedNSNameCaches {
    #[inline]
    fn ns_name(
        &self,
        name: String,
        port: u16
    ) -> Result<NSName, NSNameCacheError> {
        let cache = self.cache(name.clone())?;

        Ok(NSName::create(name, port, cache))
    }
}

impl Drop for ThreadedNSNameCaches {
    fn drop(&mut self) {
        info!(target: "ns-name-cache",
              "destroying name caches");

        if self.notify.notify().is_err() {
            error!(target: "ns-name-cache",
                  "mutex poisoned while destroying name caches");
        }
    }
}

impl Display for NSNameCacheError {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            NSNameCacheError::Inconsistent => write!(f, "inconsistent state"),
            NSNameCacheError::MutexPoison => write!(f, "mutex poisoned")
        }
    }
}
