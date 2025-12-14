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

use std::fmt::Display;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;

use mio::net::TcpStream;
use mio::net::UnixStream;

use crate::unix::UnixSocketAddr;

/// Trait for sessions with an individual peer address.
///
/// Implementors of this trait are also expected to implement [Read]
/// and [Write].
pub trait Session: Read + Write {
    /// The type of local addresses.
    type LocalAddr: Display;
    /// The type of peer (remote) addresses.
    type PeerAddr: Display;

    /// Get the local address for this flow.
    fn local_addr(&self) -> Result<Self::LocalAddr, Error>;

    /// Get the peer (remote) address for this flow.
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error>;
}

impl Session for UnixStream {
    type LocalAddr = UnixSocketAddr;
    type PeerAddr = UnixSocketAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.local_addr().map(|addr| UnixSocketAddr::from(addr))
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.peer_addr().map(|addr| UnixSocketAddr::from(addr))
    }
}

impl Session for TcpStream {
    type LocalAddr = SocketAddr;
    type PeerAddr = SocketAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.peer_addr()
    }
}
