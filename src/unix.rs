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

//! Utilities for Unix Sockets.
//!
//! This module contains utilities for Unix sockets.  This primarily
//! consists of wrapper types to deal with the fact that [PathBuf] and
//! [SocketAddr] don't have [Display] instances.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Error;
use std::os::unix::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_streams::channels::ChannelParam;

/// A wrapper around [SocketAddr]s for Unix sockets.
///
/// This is primarily to deal with the fact that `SocketAddr` does not
/// have a [Display] instance.
#[derive(Clone, Debug)]
pub struct UnixSocketAddr(SocketAddr);

/// A wrapper around [PathBuf]s for Unix socket addresses.
///
/// This is primarily to deal with the fact that `PathBuf` does not
/// have a [Display] instance.
#[derive(Clone, Debug)]
pub struct UnixSocketPath(PathBuf);

impl Display for UnixSocketAddr {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self.0.as_pathname() {
            Some(name) => name.to_string_lossy().fmt(f),
            None => write!(f, "<unnamed unix socket>")
        }
    }
}

impl Eq for UnixSocketAddr {}

impl ChannelParam<UnixSocketAddr> for UnixSocketAddr {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &UnixSocketAddr
    ) -> bool {
        true
    }
}

impl<'a> From<&'a UnixSocketAddr> for &'a SocketAddr {
    #[inline]
    fn from(val: &'a UnixSocketAddr) -> &'a SocketAddr {
        &val.0
    }
}

impl From<UnixSocketAddr> for PassthruDatagramXfrmParam {
    #[inline]
    fn from(_val: UnixSocketAddr) -> Self {
        PassthruDatagramXfrmParam
    }
}

impl From<UnixSocketAddr> for SocketAddr {
    #[inline]
    fn from(val: UnixSocketAddr) -> SocketAddr {
        val.0
    }
}

impl From<SocketAddr> for UnixSocketAddr {
    #[inline]
    fn from(val: SocketAddr) -> UnixSocketAddr {
        UnixSocketAddr(val)
    }
}

impl TryFrom<&'_ str> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &str) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<String> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: String) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<&'_ Path> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &Path) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<&'_ PathBuf> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: &PathBuf) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl TryFrom<PathBuf> for UnixSocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: PathBuf) -> Result<UnixSocketAddr, Error> {
        Ok(UnixSocketAddr(SocketAddr::from_pathname(val)?))
    }
}

impl Hash for UnixSocketAddr {
    #[inline]
    fn hash<H>(
        &self,
        h: &mut H
    ) where
        H: Hasher {
        if let Some(name) = self.0.as_pathname() {
            name.hash(h)
        }
    }
}

impl Ord for UnixSocketAddr {
    #[inline]
    fn cmp(
        &self,
        other: &Self
    ) -> Ordering {
        match (self.0.as_pathname(), other.0.as_pathname()) {
            (Some(a), Some(b)) => a.cmp(b),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal
        }
    }
}

impl PartialEq for UnixSocketAddr {
    #[inline]
    fn eq(
        &self,
        other: &Self
    ) -> bool {
        match (self.0.as_pathname(), other.0.as_pathname()) {
            (Some(a), Some(b)) => a.eq(b),
            (None, None) => true,
            _ => false
        }
    }
}

impl PartialOrd for UnixSocketAddr {
    #[inline]
    fn partial_cmp(
        &self,
        other: &Self
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<SocketAddr> for UnixSocketAddr {
    #[inline]
    fn as_ref(&self) -> &SocketAddr {
        &self.0
    }
}

impl AsRef<Path> for UnixSocketPath {
    #[inline]
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Display for UnixSocketPath {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        self.0.to_string_lossy().fmt(f)
    }
}

impl From<PathBuf> for UnixSocketPath {
    #[inline]
    fn from(val: PathBuf) -> UnixSocketPath {
        UnixSocketPath(val)
    }
}

impl From<UnixSocketPath> for PathBuf {
    #[inline]
    fn from(val: UnixSocketPath) -> PathBuf {
        val.0
    }
}
