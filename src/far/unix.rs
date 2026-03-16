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

use std::convert::Infallible;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;
use std::fs::remove_file;
use std::hash::Hash;
use std::io::Error;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::os::unix::net::UCred;

use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::PassthruNegotiator;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::net::TrivialNegotiator;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::threads::TokensCtx;
use log::info;
use log::warn;
use mio::event::Source;
use mio::net::UnixDatagram;
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::config::UnixFarChannelConfig;
use crate::far::flows::BufferedFlow;
use crate::far::FarChannel;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::resolve::cache::NSNameCachesCtx;

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
/// # use std::iter::empty;
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
/// let mut channel = UnixFarChannel::create(&mut nscaches, &mut empty(),
///                                          unix_config)
///     .expect("Expected success");
/// ```
pub struct UnixFarChannel {
    /// The address to which to bind.
    bind: UnixSocketPath
}

/// Wrapper around a [UnixDatagram].
///
/// This is a wrapper to disambiguate implementations of [Socket],
/// [Receiver], and [Sender].
pub struct UnixDatagramSocket {
    /// The underlying [UnixDatagram].
    socket: UnixDatagram
}

pub struct UnixDatagramFlows {
    /// The underlying [UnixDatagram].
    socket: UnixDatagram
}

/// Base-level transformer for [UnixFarChannel]s.
pub struct UnixDatagramXfrm<Addr>
where
    UnixSocketPath: TryFrom<Addr>,
    <UnixSocketPath as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<UnixSocketPath> + Send {
    addr: PhantomData<Addr>
}

impl<Addr> Default for UnixDatagramXfrm<Addr>
where
    UnixSocketPath: TryFrom<Addr>,
    <UnixSocketPath as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<UnixSocketPath> + Send
{
    #[inline]
    fn default() -> Self {
        UnixDatagramXfrm { addr: PhantomData }
    }
}

impl<Addr> DatagramXfrm for UnixDatagramXfrm<Addr>
where
    UnixSocketPath: TryFrom<Addr>,
    <UnixSocketPath as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<UnixSocketPath> + Send
{
    type Error = <UnixSocketPath as TryFrom<Addr>>::Error;
    type LocalAddr = Addr;
    type PeerAddr = UnixSocketPath;
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
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error> {
        Ok((None, addr.into()))
    }

    #[inline]
    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Addr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        let addr = addr.try_into()?;

        Ok((buf.len(), addr))
    }
}

impl<Addr> DatagramXfrmCreate for UnixDatagramXfrm<Addr>
where
    UnixSocketPath: TryFrom<Addr>,
    <UnixSocketPath as TryFrom<Addr>>::Error: Debug + Display,
    Addr: Clone + Debug + Display + Eq + Hash + From<UnixSocketPath> + Send
{
    type Addr = UnixSocketPath;
    type CreateParam = ();

    #[inline]
    fn create(
        _addr: &UnixSocketPath,
        _param: &()
    ) -> Self {
        UnixDatagramXfrm::default()
    }
}

impl FarChannel for UnixFarChannel {
    type AcquireError = Infallible;
    type AcquirePending = Infallible;
    type AcquireState = UnixSocketPath;
    type Acquired = UnixSocketPath;
    type NegotiateError = Infallible;
    type ShutdownError = Infallible;
    type ShutdownNegotiateError = Infallible;
    type ShutdownPending = Infallible;
    type ShutdownState = ();

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        _val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        Ok(IPEndpoint::new(IPEndpointAddr::Name(String::from("")), 0))
    }

    #[inline]
    fn acquire(
        &mut self,
        _tokens: &mut Vec<Token>,
        _registry: &Registry
    ) -> Result<RetryResult<UnixSocketPath>, Infallible> {
        Ok(RetryResult::Success(self.bind.clone()))
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

impl FarChannelSocket for UnixFarChannel {
    type Param = UnixSocketPath;
    type Socket = UnixDatagramSocket;
    type SocketError = Error;

    #[inline]
    fn socket(
        &self,
        param: &UnixSocketPath
    ) -> Result<UnixDatagramSocket, Error> {
        let addr = param.try_into()?;
        let socket = UnixDatagram::bind_addr(&addr)?;

        Ok(UnixDatagramSocket { socket: socket })
    }
}

impl FarChannelCreate for UnixFarChannel {
    type Config = UnixFarChannelConfig;
    type CreateError = Error;

    #[inline]
    fn create<Ctx>(
        _ctx: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx + TokensCtx {
        let addr = UnixSocketPath::from(config.path());

        Ok(UnixFarChannel { bind: addr })
    }
}

impl<Xfrm> FarChannelXfrm<Xfrm, Xfrm> for UnixFarChannel
where
    UnixSocketPath: TryFrom<Xfrm::LocalAddr>,
    <UnixSocketPath as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<UnixSocketPath>,
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

impl<Xfrm> FarChannelFlows<Xfrm, Xfrm> for UnixFarChannel
where
    UnixSocketPath: TryFrom<Xfrm::LocalAddr>,
    <UnixSocketPath as TryFrom<Xfrm::LocalAddr>>::Error: Debug + Display,
    Xfrm::LocalAddr: From<UnixSocketPath>,
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
    fn inbound_nego_param(&self) -> () {
        ()
    }

    #[inline]
    fn outbound_negotiator(
        &self
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        Ok(PassthruNegotiator)
    }

    #[inline]
    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::OutboundNegoError> {
        Ok(TrivialNegotiator)
    }

    #[inline]
    fn shutdown_nego_param(&self) -> () {
        ()
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

impl Source for UnixDatagramSocket {
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

impl Socket for UnixDatagramSocket {
    type Addr = UnixSocketPath;

    #[inline]
    fn local_addr(&self) -> Result<Self::Addr, Error> {
        let addr = self.socket.local_addr()?;

        UnixSocketPath::try_from(addr)
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
        self.socket.send_to(buf, addr.as_ref())
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

impl Receiver for UnixDatagramSocket {
    type MsgCred = UCred;

    #[inline]
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        let (nbytes, addr) = self.socket.recv_from(buf)?;
        let addr = UnixSocketPath::try_from(addr)?;

        Ok((nbytes, addr, None))
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
