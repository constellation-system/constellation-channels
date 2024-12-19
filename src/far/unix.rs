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

//! Far-link channels over Unix domain sockets.
//!
//! This module provides a [FarChannel] implementation over Unix
//! domain datagram sockets.  These are an interprocess communication
//! mechanism available on most Unix-type operating systems that
//! resemble UDP-like functionality, but are strictly local to a
//! machine.
//!
//! # Unix Domain Sockets
//!
//! A Unix domain datagram socket is referenced by a filesystem path,
//! and appears as a special file.  It is created by establishing the
//! socket at a give path, after which other processes can send
//! datagrams to it by using the path as an address.  It behaves
//! similarly to a very stable, high-bandwidth UDP socket.  Unix
//! sockets also support additional functionality, such as sending
//! file descriptors and authorizations.  This functionality is not
//! supported by the far channel API.
//!
//! Unix sockets cannot connect across machines; however, they serve
//! as a viable replacement for UDP sockets on `localhost`, and offer
//! several advantages.  Notably, it is impossible to misconfigure a
//! Unix socket to allow traffic to or from machines other than
//! `localhost`, thus avoiding a potential security issue.
//!
//! # Far-Links Over Unix Sockets
//!
//! [UnixFarChannel] provides the means to use Unix domain sockets
//! within the far-link framework.  [UnixFarChannel]s can be used to
//! listen on a Unix socket, creating the socket when the `FarChannel`
//! is created, and deleting it when it is dropped.  The sockets
//! created by `UnixFarChannel`s can be used to send packets to other
//! `UnixFarChannel`s.  In this way, Unix sockets can be easily
//! substituted in place of UDP sockets connecting to or listening on
//! `localhost`.
//!
//! # Examples
//!
//! The following is an example of connecting, sending, and
//! receiving over Unix sockets:
//!
//! ```
//! # use constellation_common::net::PassthruDatagramXfrm;
//! # use constellation_channels::config::UnixFarChannelConfig;
//! # use constellation_channels::far::FarChannel;
//! # use constellation_channels::far::FarChannelCreate;
//! # use constellation_channels::far::FarChannelBorrowFlows;
//! # use constellation_channels::far::flows::BorrowedFlows;
//! # use constellation_channels::far::flows::CreateFlows;
//! # use constellation_channels::far::flows::MultiFlows;
//! # use constellation_channels::far::flows::SingleFlow;
//! # use constellation_channels::far::unix::UnixDatagramSocket;
//! # use constellation_channels::far::unix::UnixFarChannel;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use constellation_channels::unix::UnixSocketAddr;
//! # use std::convert::TryFrom;
//! # use std::io::Read;
//! # use std::io::Write;
//! # use std::sync::Arc;
//! # use std::sync::Barrier;
//! # use std::thread::sleep;
//! # use std::thread::spawn;
//! # use std::time::Duration;
//! #
//! const CHANNEL_CONFIG: &'static str = "path: example_server.sock\n";
//! const CLIENT_CONFIG: &'static str = "path: example_client.sock\n";
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! let client_config: UnixFarChannelConfig =
//!     serde_yaml::from_str(CLIENT_CONFIG).unwrap();
//! let channel_config: UnixFarChannelConfig =
//!     serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
//! let channel_path = channel_config.path().to_path_buf();
//! let client_path = client_config.path().to_path_buf();
//! let nscaches = SharedNSNameCaches::new();
//! let barrier = Arc::new(Barrier::new(2));
//!
//! let client_addr = UnixSocketAddr::try_from(&client_path).unwrap();
//! # let client_barrier = barrier.clone();
//! let mut client_nscaches = nscaches.clone();
//! let listen = spawn(move || {
//!     let mut listener =
//!         UnixFarChannel::new(&mut client_nscaches, channel_config)
//!             .expect("Expected success");
//!     let param = listener.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: MultiFlows<
//!         UnixFarChannel,
//!         PassthruDatagramXfrm<UnixSocketAddr>
//!     > = listener.borrowed_flows(param, xfrm, ()).unwrap();
//!
//! #   client_barrier.wait();
//!
//!     let mut buf = [0; FIRST_BYTES.len()];
//!     let (peer_addr, mut flow) = flows.listen().unwrap();
//!
//! #   client_barrier.wait();
//!
//!     let nbytes = flow.read(&mut buf).unwrap();
//!     let mut flow = flows.flow(client_addr.clone(), None).unwrap();
//!
//!     flow.write_all(&SECOND_BYTES).expect("Expected success");
//!
//! #   client_barrier.wait();
//!
//!     assert_eq!(peer_addr, client_addr);
//!     assert_eq!(FIRST_BYTES.len(), nbytes);
//!     assert_eq!(FIRST_BYTES, buf);
//! });
//!
//! let channel_addr = UnixSocketAddr::try_from(&channel_path).unwrap();
//! let channel_barrier = barrier;
//! let mut channel_nscaches = nscaches.clone();
//! let send = spawn(move || {
//!     let mut conn =
//!         UnixFarChannel::new(&mut channel_nscaches, client_config)
//!             .expect("expected success");
//!     let param = conn.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: SingleFlow<
//!         UnixFarChannel,
//!         PassthruDatagramXfrm<UnixSocketAddr>
//!     > = conn
//!         .borrowed_flows(param, xfrm, channel_addr.clone())
//!         .unwrap();
//!
//! #   channel_barrier.wait();
//!
//!     let mut flow = flows.flow(channel_addr.clone(), None).unwrap();
//!
//!     flow.write_all(&FIRST_BYTES).expect("Expected success");
//!
//! #   channel_barrier.wait();
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!     let (peer_addr, mut flow) = flows.listen().unwrap();
//!
//! #   channel_barrier.wait();
//!
//!     flow.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(peer_addr, channel_addr);
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! listen.join().unwrap();
//! send.join().unwrap();
//! ```

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fs::remove_file;
use std::io::Error;
use std::os::unix::net::UnixDatagram;

use constellation_auth::authn::SessionAuthN;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use log::info;
use log::warn;

use crate::config::UnixFarChannelConfig;
use crate::far::flows::CreateOwnedFlows;
use crate::far::flows::Flows;
use crate::far::flows::OwnedFlows;
use crate::far::flows::PassthruNegotiator;
use crate::far::BorrowedFlows;
use crate::far::CreateFlows;
use crate::far::FarChannel;
use crate::far::FarChannelBorrowFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelOwnedFlows;
use crate::resolve::cache::NSNameCachesCtx;
use crate::unix::UnixSocketAddr;

/// Unix socket far-link channel.
///
/// This is a [FarChannel] instance that communicates over Unix domain
/// datagram sockets.  This can serve as an alternative to UDP
/// sockets.  When communications are strictly local to a given
/// machine.
///
/// This expects the socket not to exist initially, and will create
/// the socket and begin listening for connections.  It also has a
/// [Drop] implementation that will delete the socket.
///
/// # Usage
///
/// The primary usage of `UnixFarChannel` takes place through its
/// [FarChannel] instance.
///
/// ## Configuration and Creation
///
/// A `UnixFarChannel` is created using the [new](FarChannelCreate::new)
/// function from its [FarChannel] instance.  This function takes a
/// [UnixFarChannelConfig] as its principal argument, which supplies
/// all configuration information.
///
/// ### Example
///
/// The following example shows how to create a `UnixFarChannel`:
///
/// ```
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::unix::UnixFarChannel;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "path: example.sock\n",
/// );
/// let unix_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let mut channel = UnixFarChannel::new(&mut nscaches, unix_config)
///     .expect("Expected success");
/// ```
pub struct UnixFarChannel {
    /// The address to which to bind.
    bind: UnixSocketAddr
}

/// Wrapper around a [UnixDatagram].
///
/// This is a wrapper to disambiguate implementations of [Socket],
/// [Receiver], and [Sender].
pub struct UnixDatagramSocket {
    /// The underlying [UnixDatagram].
    socket: UnixDatagram
}

/// Base-level transformer for [UnixFarChannel]s.
pub struct UnixDatagramXfrm;

impl Default for UnixDatagramXfrm {
    #[inline]
    fn default() -> Self {
        UnixDatagramXfrm
    }
}

impl DatagramXfrm for UnixDatagramXfrm {
    type Error = Infallible;
    type LocalAddr = UnixSocketAddr;
    type PeerAddr = UnixSocketAddr;
    type SizeError = Infallible;

    #[inline]
    fn header_size(
        &self,
        _addr: &Self::PeerAddr
    ) -> Result<usize, Infallible> {
        Ok(0)
    }

    #[inline]
    fn msg_buf(
        &self,
        _buf: &[u8],
        _addr: &Self::PeerAddr,
        _mtu: Option<usize>
    ) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(None)
    }

    #[inline]
    fn wrap(
        &mut self,
        _msg: &[u8],
        addr: Self::PeerAddr
    ) -> Result<(Option<Vec<u8>>, Self::PeerAddr), Self::Error> {
        Ok((None, addr))
    }

    #[inline]
    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Self::PeerAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        Ok((buf.len(), addr))
    }
}

impl DatagramXfrmCreate for UnixDatagramXfrm {
    type Addr = UnixSocketAddr;
    type CreateParam = ();

    #[inline]
    fn create(
        _addr: &UnixSocketAddr,
        _param: &()
    ) -> Self {
        UnixDatagramXfrm
    }
}

impl DatagramXfrmCreateParam for UnixDatagramXfrm {
    type Param = UnixSocketAddr;
    type ParamError = Error;
    type Socket = UnixDatagramSocket;

    #[inline]
    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError> {
        socket.socket.local_addr().map(UnixSocketAddr::from)
    }
}

impl FarChannel for UnixFarChannel {
    type AcquireError = Infallible;
    type Acquired = UnixSocketAddr;
    type Config = UnixFarChannelConfig;
    type Param = UnixSocketAddr;
    type Socket = UnixDatagramSocket;
    type SocketError = Error;

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        _val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        Ok(IPEndpoint::new(IPEndpointAddr::Name(String::from("")), 0))
    }

    #[inline]
    fn acquire(&mut self) -> Result<UnixSocketAddr, Infallible> {
        Ok(self.bind.clone())
    }

    #[inline]
    fn socket(
        &self,
        param: &UnixSocketAddr
    ) -> Result<UnixDatagramSocket, Error> {
        let socket = UnixDatagram::bind_addr(param.into())?;

        Ok(UnixDatagramSocket { socket: socket })
    }
}

impl FarChannelCreate for UnixFarChannel {
    type CreateError = Error;

    #[inline]
    fn new<Ctx>(
        _caches: &mut Ctx,
        config: UnixFarChannelConfig
    ) -> Result<Self, Error>
    where
        Ctx: NSNameCachesCtx {
        let addr = UnixSocketAddr::try_from(config.path())?;

        Ok(UnixFarChannel { bind: addr })
    }
}

impl<F, Xfrm> FarChannelBorrowFlows<F, Xfrm> for UnixFarChannel
where
    F: Flows + CreateFlows + BorrowedFlows,
    F::Socket: From<UnixDatagramSocket>,
    F::Xfrm: From<Xfrm>,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<UnixSocketAddr>
{
    type Borrowed = F;
    type BorrowedFlowsError = Infallible;
    type Xfrm = Xfrm;
    type XfrmError = Infallible;

    #[inline]
    fn wrap_xfrm(
        &self,
        _param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        Ok(xfrm)
    }

    #[inline]
    fn wrap_borrowed_flows(
        &self,
        flows: F
    ) -> Result<F, Infallible> {
        Ok(flows)
    }
}

impl<F, AuthN, Xfrm> FarChannelOwnedFlows<F, AuthN, Xfrm> for UnixFarChannel
where
    AuthN: SessionAuthN<F::Flow>,
    F: Flows
        + CreateOwnedFlows<PassthruNegotiator<Xfrm::PeerAddr, F>, AuthN>
        + OwnedFlows,
    F::Socket: From<UnixDatagramSocket>,
    F::Xfrm: From<Xfrm>,
    F::Flow: Send,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<UnixSocketAddr>
{
    type Nego = PassthruNegotiator<Xfrm::PeerAddr, F>;
    type Owned = F;
    type OwnedFlowsError = Infallible;
    type Xfrm = Xfrm;
    type XfrmError = Infallible;

    #[inline]
    fn negotiator(&self) -> Self::Nego {
        PassthruNegotiator::default()
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        _param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        Ok(xfrm)
    }

    #[inline]
    fn wrap_owned_flows(
        &self,
        flows: F
    ) -> Result<Self::Owned, Self::OwnedFlowsError> {
        Ok(flows)
    }
}

impl Drop for UnixDatagramSocket {
    fn drop(&mut self) {
        match self.socket.local_addr() {
            Ok(addr) => {
                if let Some(path) = addr.as_pathname() {
                    match remove_file(path) {
                        Ok(()) => {
                            // Normal deletion of the socket.
                            info!(target: "unix-far-channel",
                              "cleaned up unix socket {}",
                              path.to_string_lossy())
                        }
                        Err(err) => {
                            // An error occurred.  We can't do anything
                            // other than log it.
                            warn!(target: "unix-far-channel",
                              "error cleaning up unix socket {} ({})",
                              path.to_string_lossy(), err)
                        }
                    }
                }
            }
            Err(err) => {
                warn!(target: "unix-far-channel",
                  "error getting address of unix socket ({})",
                  err)
            }
        }
    }
}

impl Socket for UnixDatagramSocket {
    type Addr = UnixSocketAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::Addr, Error> {
        let addr = self.socket.local_addr()?;

        Ok(UnixSocketAddr::from(addr))
    }

    #[inline]
    fn allow_session_addr_creds(&self) -> bool {
        true
    }
}

impl Sender for UnixDatagramSocket {
    #[inline]
    fn send_to(
        &self,
        addr: &Self::Addr,
        buf: &[u8]
    ) -> Result<usize, Error> {
        self.socket.send_to_addr(buf, addr.as_ref())
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Receiver for UnixDatagramSocket {
    #[inline]
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        let (nbytes, addr) = self.socket.recv_from(buf)?;

        Ok((nbytes, UnixSocketAddr::from(addr)))
    }

    #[inline]
    fn peek_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        let (nbytes, addr) = self.socket.peek_from(buf)?;

        Ok((nbytes, UnixSocketAddr::from(addr)))
    }
}

#[cfg(test)]
use std::fs::metadata;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::io::Write;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;

#[cfg(test)]
use crate::far::flows::MultiFlows;
#[cfg(test)]
use crate::far::flows::SingleFlow;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[test]
fn test_send_recv() {
    init();

    const CHANNEL_CONFIG: &'static str =
        concat!("path: test_far_send_recv_channel.sock\n",);
    const CLIENT_CONFIG: &'static str =
        concat!("path: test_far_send_recv_client.sock\n");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let client_config: UnixFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let channel_config: UnixFarChannelConfig =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let channel_path = channel_config.path().to_path_buf();
    let client_path = client_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&channel_path).is_err());
    assert!(metadata(&client_path).is_err());

    let client_addr = UnixSocketAddr::try_from(&client_path).unwrap();
    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut listener =
            UnixFarChannel::new(&mut client_nscaches, channel_config)
                .expect("Expected success");
        let param = listener.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: MultiFlows<
            UnixFarChannel,
            PassthruDatagramXfrm<UnixSocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();

        client_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let (peer_addr, mut flow) = flows.listen().unwrap();

        client_barrier.wait();

        let nbytes = flow.read(&mut buf).unwrap();
        let mut flow = flows.flow(client_addr.clone(), None).unwrap();

        flow.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let channel_addr = UnixSocketAddr::try_from(&channel_path).unwrap();
    let channel_barrier = barrier;
    let mut channel_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut conn =
            UnixFarChannel::new(&mut channel_nscaches, client_config)
                .expect("expected success");
        let param = conn.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: SingleFlow<
            UnixFarChannel,
            PassthruDatagramXfrm<UnixSocketAddr>
        > = conn
            .borrowed_flows(param, xfrm, channel_addr.clone())
            .unwrap();

        channel_barrier.wait();

        let mut flow = flows.flow(channel_addr.clone(), None).unwrap();

        flow.write_all(&FIRST_BYTES).expect("Expected success");

        channel_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];
        let (peer_addr, mut flow) = flows.listen().unwrap();

        channel_barrier.wait();

        flow.read_exact(&mut buf).unwrap();

        assert_eq!(peer_addr, channel_addr);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&channel_path).is_err());
    assert!(metadata(&client_path).is_err());
}
