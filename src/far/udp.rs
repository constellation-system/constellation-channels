// Copyright © 2024-26 The Johns Hopkins Applied Physics Laboratory LLC.
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

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::hash::Hash;
use std::io::Error;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::Deref;
use std::ops::DerefMut;

use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpoint;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::PassthruNegotiator;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::net::TrivialNegotiator;
use constellation_common::retry::RetryResult;
use constellation_streams::threads::TokensCtx;
use log::warn;
use mio::Interest;
use mio::Registry;
use mio::Token;
use mio::event::Source;
use mio::net::UdpSocket;

use crate::config::UDPFarChannelConfig;
use crate::far::FarChannel;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::far::flows::BufferedFlow;
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
/// # use std::iter::empty;
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::udp::UDPFarChannel;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// # use constellation_streams::threads::WithTokens;
/// #
/// const CONFIG: &'static str = concat!(
///     "addr: ::1\n",
///     "port: 7006\n",
/// );
/// let udp_config = yaml_serde::from_str(CONFIG).unwrap();
/// let mut ctx = WithTokens::new(SharedNSNameCaches::new());
///
/// let mut channel = UDPFarChannel::create(&mut ctx, udp_config)
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
pub struct UDPDatagramXfrm<Addr>
where
    SocketAddr: TryFrom<Addr>,
    <SocketAddr as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<SocketAddr> + Send {
    addr: PhantomData<Addr>
}

impl Source for UDPFarSocket {
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.socket.register(registry, token, interests)
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        self.socket.reregister(registry, token, interests)
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        self.socket.deregister(registry)
    }
}

impl<Addr> Default for UDPDatagramXfrm<Addr>
where
    SocketAddr: TryFrom<Addr>,
    <SocketAddr as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<SocketAddr> + Send
{
    #[inline]
    fn default() -> Self {
        UDPDatagramXfrm { addr: PhantomData }
    }
}

impl<Addr> DatagramXfrm for UDPDatagramXfrm<Addr>
where
    SocketAddr: TryFrom<Addr>,
    <SocketAddr as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<SocketAddr> + Send
{
    type Error = <SocketAddr as TryFrom<Addr>>::Error;
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

impl<Addr> DatagramXfrmCreate for UDPDatagramXfrm<Addr>
where
    SocketAddr: TryFrom<Addr>,
    <SocketAddr as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<SocketAddr> + Send
{
    type Addr = SocketAddr;
    type CreateParam = ();

    #[inline]
    fn create(
        _addr: &SocketAddr,
        _param: &()
    ) -> Self {
        UDPDatagramXfrm::default()
    }
}

impl FarChannel for UDPFarChannel {
    type AcquireError = Infallible;
    type AcquirePending = Infallible;
    type AcquireState = SocketAddr;
    type Acquired = SocketAddr;
    type NegotiateError = Infallible;
    type ShutdownError = Infallible;
    type ShutdownNegotiateError = Infallible;
    type ShutdownPending = Infallible;
    type ShutdownState = ();

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
    fn acquire(
        &mut self,
        _tokens: &mut Vec<Token>,
        _registry: &Registry
    ) -> Result<RetryResult<SocketAddr>, Infallible> {
        Ok(RetryResult::Success(self.bind))
    }

    #[inline]
    fn negotiate(
        &self,
        state: Self::AcquireState
    ) -> Result<
        NegotiatorResult<Self::Acquired, Self::AcquirePending>,
        Self::NegotiateError
    > {
        Ok(NegotiatorResult::Complete(state))
    }

    #[inline]
    fn complete_negotiate(
        &self,
        _err: Infallible
    ) -> Result<
        NegotiatorResult<Self::Acquired, Self::AcquirePending>,
        Self::NegotiateError
    > {
        panic!("This should never be called!")
    }

    #[inline]
    fn shutdown(
        &self,
        _acquired: Self::Acquired
    ) -> Result<Self::ShutdownState, Self::ShutdownError> {
        Ok(())
    }

    #[inline]
    fn shutdown_negotiate(
        &self,
        _tokens: &mut Vec<Token>,
        _registry: &Registry,
        _state: Self::ShutdownState
    ) -> Result<
        NegotiatorResult<(), Self::ShutdownPending>,
        Self::ShutdownNegotiateError
    > {
        Ok(NegotiatorResult::Complete(()))
    }

    #[inline]
    fn complete_shutdown_negotiate(
        &self,
        _tokens: &mut Vec<Token>,
        _registry: &Registry,
        _err: Self::ShutdownPending
    ) -> Result<
        NegotiatorResult<(), Self::ShutdownPending>,
        Self::ShutdownNegotiateError
    > {
        panic!("This should never be called!")
    }
}

impl FarChannelSocket for UDPFarChannel {
    type Param = SocketAddr;
    type Socket = UDPFarSocket;
    type SocketError = Error;

    #[inline]
    fn socket(
        &self,
        param: &SocketAddr
    ) -> Result<UDPFarSocket, Error> {
        let socket = UdpSocket::bind(*param)?;

        Ok(UDPFarSocket {
            unsafe_allow_ip_addr_creds: self.unsafe_allow_ip_addr_creds,
            socket: socket
        })
    }
}

impl FarChannelCreate for UDPFarChannel {
    type Config = UDPFarChannelConfig;
    type CreateError = Infallible;

    #[inline]
    fn create<Ctx>(
        _ctx: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx + TokensCtx {
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

impl<Xfrm> FarChannelXfrm<Xfrm, Xfrm> for UDPFarChannel
where
    SocketAddr: TryFrom<Xfrm::LocalAddr>,
    <SocketAddr as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<SocketAddr>,
    Xfrm: DatagramXfrm
{
    type XfrmError = Infallible;

    #[inline]
    fn wrap_xfrm(
        &self,
        _param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Xfrm, Self::XfrmError> {
        Ok(xfrm)
    }
}

impl<Xfrm> FarChannelFlows<Xfrm, Xfrm> for UDPFarChannel
where
    SocketAddr: TryFrom<Xfrm::LocalAddr>,
    <SocketAddr as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<SocketAddr>,
    Xfrm: DatagramXfrm
{
    type Flow = BufferedFlow<Self::Socket, Xfrm>;
    type InboundNego = PassthruNegotiator;
    type InboundNegoError = Infallible;
    type OutboundNego = PassthruNegotiator;
    type OutboundNegoError = Infallible;
    type ShutdownNego = TrivialNegotiator;
    type ShutdownNegoError = Infallible;

    #[inline]
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        Ok(PassthruNegotiator)
    }

    #[inline]
    fn inbound_nego_param(&self) {}

    #[inline]
    fn outbound_negotiator(
        &self
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        Ok(PassthruNegotiator)
    }

    #[inline]
    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        Ok(TrivialNegotiator)
    }

    #[inline]
    fn shutdown_nego_param(&self) {}
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
        self.socket.send_to(buf, *addr)
    }

    fn send_to_vectored(
        &self,
        addr: &Self::Addr,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        // ISSUE #28: statically-allocated thread-local storage would
        // be a better way to do this.
        let size = bufs.iter().map(|buf| buf.len()).sum();
        let mut msg = vec![0; size];
        let mut curr = 0;

        for buf in bufs {
            let buf = buf.deref();
            let len = buf.len();

            msg[curr..curr + len].copy_from_slice(buf);
            curr += len;
        }

        self.send_to(addr, &msg)
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Receiver for UDPFarSocket {
    type MsgCred = SocketAddr;

    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        let (nbytes, addr) = self.socket.recv_from(buf)?;

        if self.unsafe_allow_ip_addr_creds {
            Ok((nbytes, addr, Some(addr)))
        } else {
            Ok((nbytes, addr, None))
        }
    }

    fn recv_from_vectored(
        &self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        let size = bufs.iter().map(|buf| buf.len()).sum();
        let mut msg = vec![0; size];
        let (nbytes, addr, cred) = self.recv_from(&mut msg)?;
        let mut curr = 0;
        let mut idx = 0;

        while curr < nbytes && idx < bufs.len() {
            let buf = bufs[idx].deref_mut();
            let len = buf.len();
            let avail = nbytes - curr;
            let len = len.min(avail);

            buf[..len].copy_from_slice(&msg[curr..curr + len]);
            bufs[idx].advance(len);
            curr += len;
            idx += 1;
        }

        Ok((nbytes, addr, cred))
    }
}
