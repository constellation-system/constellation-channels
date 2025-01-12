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

//! Far-link channels over UDP sockets.
//!
//! This module provides a [FarChannel] implementation over UDP
//! sockets.  Note that traffic communicated in this way are neither
//! authenticated nor secure inherently.
//!
//! # Examples
//!
//! The following is an example of connecting, sending, and
//! receiving over UDP:
//!
//! ```
//! # use constellation_common::net::PassthruDatagramXfrm;
//! # use constellation_channels::config::UDPFarChannelConfig;
//! # use constellation_channels::far::FarChannel;
//! # use constellation_channels::far::FarChannelCreate;
//! # use constellation_channels::far::FarChannelBorrowFlows;
//! # use constellation_channels::far::flows::BorrowedFlows;
//! # use constellation_channels::far::flows::CreateBorrowedFlows;
//! # use constellation_channels::far::flows::MultiFlows;
//! # use constellation_channels::far::flows::SingleFlow;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use constellation_channels::far::udp::UDPFarChannel;
//! # use constellation_channels::far::udp::UDPFarSocket;
//! # use std::convert::TryFrom;
//! # use std::io::Read;
//! # use std::io::Write;
//! # use std::net::SocketAddr;
//! # use std::sync::Arc;
//! # use std::sync::Barrier;
//! # use std::thread::sleep;
//! # use std::thread::spawn;
//! # use std::time::Duration;
//! #
//! const CHANNEL_CONFIG: &'static str = concat!("addr: ::1\n",
//!                                              "port: 7005\n");
//! const CLIENT_CONFIG: &'static str = concat!("addr: ::1\n",
//!                                             "port: 7006\n");
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! let channel_config: UDPFarChannelConfig =
//!     serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
//! let client_config: UDPFarChannelConfig =
//!     serde_yaml::from_str(CLIENT_CONFIG).unwrap();
//! let channel_addr = SocketAddr::new(channel_config.addr().clone(),
//!                                    channel_config.port());
//! let client_addr = SocketAddr::new(client_config.addr().clone(),
//!                                   client_config.port());
//! let nscaches = SharedNSNameCaches::new();
//! # let barrier = Arc::new(Barrier::new(2));
//!
//! let mut client_nscaches = nscaches.clone();
//! let client_barrier = barrier.clone();
//! let listen = spawn(move || {
//!     let mut listener =
//!         UDPFarChannel::new(&mut client_nscaches, channel_config)
//!             .expect("Expected success");
//!     let param = listener.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: MultiFlows<
//!         UDPFarChannel,
//!         PassthruDatagramXfrm<SocketAddr>
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
//! let mut channel_nscaches = nscaches.clone();
//! let channel_barrier = barrier;
//! let send = spawn(move || {
//!     let mut conn = UDPFarChannel::new(&mut channel_nscaches, client_config)
//!         .expect("expected success");
//!     let param = conn.acquire().unwrap();
//!     let xfrm = PassthruDatagramXfrm::new();
//!     let mut flows: SingleFlow<
//!         UDPFarChannel,
//!         PassthruDatagramXfrm<SocketAddr>
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
use std::io::Error;
use std::net::SocketAddr;
use std::net::UdpSocket;

use constellation_auth::authn::SessionAuthN;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpoint;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use log::warn;

use crate::config::UDPFarChannelConfig;
use crate::far::flows::OwnedFlows;
use crate::far::flows::PassthruNegotiator;
use crate::far::BorrowedFlows;
use crate::far::CreateBorrowedFlows;
use crate::far::CreateOwnedFlows;
use crate::far::FarChannel;
use crate::far::FarChannelBorrowFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelOwnedFlows;
use crate::far::Flows;
use crate::resolve::cache::NSNameCachesCtx;

/// A UDP-based far-link channel.
///
/// This is a [FarChannel] instance that communicates over the UDP
/// protocol.  Communications over this channel are unauthenticated
/// and unprotected, unless another layer is used to secure the
/// channel.
///
/// # Usage
///
/// The primary use of a `UDPFarChannel` takes place through its
/// [FarChannel] instance.
///
/// ## Configuration and Creation
///
/// A `UDPFarChannel` is created using the [new](FarChannelCreate::new)
/// function from its [FarChannel] instance.  This function takes a
/// [UDPFarChannelConfig] as its principal argument, which supplies
/// all configuration information.
///
/// ### Example
///
/// The following example shows how to create a `UDPFarChannel`:
///
/// ```
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::udp::UDPFarChannel;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "addr: ::1\n",
///     "port: 7006\n",
/// );
/// let udp_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let mut channel = UDPFarChannel::new(&mut nscaches, udp_config)
///     .expect("Expected success");
/// ```
pub struct UDPFarChannel {
    unsafe_allow_ip_addr_creds: bool,
    bind: SocketAddr
}

/// Wrapper around a [UdpSocket].
///
/// This is primarily to prevent ambiguities between functions native
/// to [UdpSocket] and equivalent ones provided by [Socket], [Send],
/// and [Receiver].
pub struct UDPFarSocket {
    unsafe_allow_ip_addr_creds: bool,
    socket: UdpSocket
}

/// Base-level transformer for [UDPFarChannel]s.
pub struct UDPDatagramXfrm;

impl Default for UDPDatagramXfrm {
    #[inline]
    fn default() -> Self {
        UDPDatagramXfrm
    }
}

impl DatagramXfrm for UDPDatagramXfrm {
    type Error = Infallible;
    type LocalAddr = SocketAddr;
    type PeerAddr = SocketAddr;
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

impl DatagramXfrmCreate for UDPDatagramXfrm {
    type Addr = SocketAddr;
    type CreateParam = ();

    #[inline]
    fn create(
        _addr: &SocketAddr,
        _param: &()
    ) -> Self {
        UDPDatagramXfrm
    }
}

impl DatagramXfrmCreateParam for UDPDatagramXfrm {
    type Param = SocketAddr;
    type ParamError = Error;
    type Socket = UDPFarSocket;

    #[inline]
    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError> {
        socket.socket.local_addr()
    }
}

impl FarChannel for UDPFarChannel {
    type AcquireError = Infallible;
    type Acquired = SocketAddr;
    type Config = UDPFarChannelConfig;
    type Param = SocketAddr;
    type Socket = UDPFarSocket;
    type SocketError = Error;

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        addr: &SocketAddr
    ) -> Result<IPEndpoint, Error> {
        if addr.ip().is_unspecified() {
            match addr {
                SocketAddr::V4(_) => Ok(IPEndpoint::NULL_IPV4),
                SocketAddr::V6(_) => Ok(IPEndpoint::NULL_IPV6)
            }
        } else {
            Ok(IPEndpoint::from(*addr))
        }
    }

    #[inline]
    fn acquire(&mut self) -> Result<SocketAddr, Infallible> {
        Ok(self.bind)
    }

    #[inline]
    fn socket(
        &self,
        param: &SocketAddr
    ) -> Result<UDPFarSocket, Error> {
        let socket = UdpSocket::bind(param)?;

        Ok(UDPFarSocket {
            unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
            socket: socket
        })
    }
}

impl FarChannelCreate for UDPFarChannel {
    type CreateError = Infallible;

    #[inline]
    fn new<Ctx>(
        _caches: &mut Ctx,
        config: UDPFarChannelConfig
    ) -> Result<Self, Infallible>
    where
        Ctx: NSNameCachesCtx {
        let (addr, port, unsafe_opts) = config.take();

        if unsafe_opts.allow_ip_addr_creds() {
            warn!(target: "udp-far-channel",
                  concat!("unsafe option allow_ip_addr_creds enabled for ",
                          "UDP far channel on {}:{} (this allows for trivial ",
                          "spoofing of channel credentials)"),
            addr, port)
        }

        Ok(UDPFarChannel {
            unsafe_allow_ip_addr_creds: unsafe_opts.allow_ip_addr_creds(),
            bind: SocketAddr::new(addr, port)
        })
    }
}

impl<F, Xfrm> FarChannelBorrowFlows<F, Xfrm> for UDPFarChannel
where
    F: Flows + CreateBorrowedFlows + BorrowedFlows,
    F::Socket: From<UDPFarSocket>,
    F::Xfrm: From<Xfrm>,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<SocketAddr>
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

impl<F, AuthN, Xfrm> FarChannelOwnedFlows<F, AuthN, Xfrm> for UDPFarChannel
where
    F: Flows
        + CreateOwnedFlows<PassthruNegotiator<Xfrm::PeerAddr, F>, AuthN>
        + OwnedFlows,
    F::Xfrm: From<Xfrm>,
    F::Socket: From<UDPFarSocket>,
    F::Flow: Send,
    AuthN: SessionAuthN<F::Flow>,
    Xfrm: DatagramXfrm,
    Xfrm::LocalAddr: From<SocketAddr>
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

impl Socket for UDPFarSocket {
    type Addr = SocketAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::Addr, Error> {
        self.socket.local_addr()
    }

    #[inline]
    fn allow_session_addr_creds(&self) -> bool {
        self.unsafe_allow_ip_addr_creds
    }
}

impl Sender for UDPFarSocket {
    #[inline]
    fn mtu(&self) -> Option<usize> {
        match self.socket.local_addr() {
            Ok(addr) => {
                let ip_header = match addr {
                    SocketAddr::V4(_) => 20,
                    SocketAddr::V6(_) => 40
                };
                let udp_header = 8;
                let frame = 1500;

                Some(frame - ip_header - udp_header)
            }
            Err(err) => {
                warn!(target: "far-udp",
                      "couldn't get socket local address ({})",
                      err);

                None
            }
        }
    }

    #[inline]
    fn send_to(
        &self,
        addr: &Self::Addr,
        buf: &[u8]
    ) -> Result<usize, Error> {
        self.socket.send_to(buf, addr)
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Receiver for UDPFarSocket {
    #[inline]
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        let (nbytes, addr) = self.socket.recv_from(buf)?;

        Ok((nbytes, addr))
    }

    #[inline]
    fn peek_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        let (nbytes, addr) = self.socket.peek_from(buf)?;

        Ok((nbytes, addr))
    }
}

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

    const CHANNEL_CONFIG: &'static str = concat!("addr: ::1\n", "port: 7007\n");
    const CLIENT_CONFIG: &'static str = concat!("addr: ::1\n", "port: 7008\n");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let channel_config: UDPFarChannelConfig =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: UDPFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let channel_addr =
        SocketAddr::new(channel_config.addr().clone(), channel_config.port());
    let client_addr =
        SocketAddr::new(client_config.addr().clone(), client_config.port());
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut listener =
            UDPFarChannel::new(&mut client_nscaches, channel_config)
                .expect("Expected success");
        let param = listener.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: MultiFlows<
            UDPFarChannel,
            PassthruDatagramXfrm<SocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();
        let mut buf = [0; FIRST_BYTES.len()];

        client_barrier.wait();

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

    let mut channel_nscaches = nscaches.clone();
    let channel_barrier = barrier;
    let send = spawn(move || {
        let mut conn = UDPFarChannel::new(&mut channel_nscaches, client_config)
            .expect("expected success");
        let param = conn.acquire().unwrap();
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows: SingleFlow<
            UDPFarChannel,
            PassthruDatagramXfrm<SocketAddr>
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
}
