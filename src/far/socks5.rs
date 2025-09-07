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

//! Near-link channels over SOCKS5 proxies.
//!
//! This module provides a [FarChannel] implementation over SOCKS5
//! proxies.
//!
//! # SOCKS5
//!
//! SOCKS5 is a proxy connection protocol defined by [RFC
//! 1928](https://datatracker.ietf.org/doc/html/rfc1928).  It permits
//! TCP and UDP traffic to be forwarded through a proxy, with DNS
//! lookups being done by the proxy itself.
//!
//! SOCKS5 is the standard means of routing traffic through the Tor
//! network and accessing hidden services.  This module can therefore
//! be used to construct near-links that talk through Tor.
//!
//! ## SOCKS5 UDP Issues
//!
//! Support for UDP associations over SOCKS5 is relatively spotty
//! among SOCKS5 proxies, and the UDP association portion of RFC 1928
//! is considered problematic in several ways.  Notably, **the Tor
//! router does not support UDP associations**. The only way to
//! forward traffic through Tor is through the
//! [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector).
//!
//! RFC 1928 requires a TCP connection to be established to the SOCKS5
//! proxy, which will then negotiate the UDP association.  This
//! connection- which is thereafter not used -*must* remain alive for
//! the duration of the UDP association.  If the connection is dropped
//! for any reason, the UDP association is deleted.  For nested SOCKS5
//! connections, this means that one TCP connection must be
//! established and maintained per hop.
//!
//! Additionally, RFC 1928 is unclear as to how the SOCKS5 proxy
//! should relay incoming UDP traffic to the UDP association back to
//! the client.  A mechanism is provided by which a client can set a
//! source address and port; however, this requires the client to know
//! the external IP address that will be used to send packets (which
//! is not always possible), only allows one such address to be set,
//! and cannot be changed once established.  For nested SOCKS5 proxy
//! configurations, there is no way to obtain an external address and
//! port for a UDP association at all.  In addition to complicating
//! the return address issue, these problems introduce potential
//! security issues by allowing a malicous party to spoof traffic
//! relatively easily.
//!
//! # Functionality
//!
//! This module only supports client-side SOCKS5 far-links, through
//! [SOCKS5FarChannel].  This uses the UDP associate command to
//! establish a UDP socket on the external side of the proxy, whose
//! traffic will be forwarded back to the client.  Note that RFC 1928
//! has several flaws, and that support for UDP associate is not
//! present on all implementations (notably, it is not supported by
//! Tor).
//!
//! ## Nested Proxies
//!
//! This module can support nested SOCKS5 UDP associations.  Doing so
//! is a complicated procedure.  The following describes how this is
//! done for a two-layer nested proxy, with a client connecting to the
//! "inner" proxy, which in turn connects to the "outer" proxy:
//!
//! * The client establishes a SOCKS5-proxied TCP connection through the inner
//!   proxy to the outer, for the purposes of negotiating the UDP association.
//!   The client must keep this connection alive once negotiation is complete.
//!
//! * The client negotiates the UDP association with the outer proxy, obtaining
//!   the address and port to which to send UDP packets (note that the client
//!   *cannot* directly send packets to this address).
//!
//! * The client establishes a TCP connection directly to the inner proxy, and
//!   negotiates the UDP association with it.  The client must also keep this
//!   connection alive once negotiation is complete.
//!
//! * The client establishes a UDP socket that will first wrap any UDP packet
//!   with a SOCKS5 header for forwarding through the outer proxy to its
//!   original destination, and then will wrap the result in *another* SOCKS5
//!   header for forwarding through the inner proxy to the forwarding address
//!   given by the outer proxy.
//!
//! For more nested proxies, this procedure simply adds more steps.
//! Note that for `n` nested proxies, this will require `n` live TCP
//! connections and `n` SOCKS5 headers for each packet.
//!
//! ## Authentication
//!
//! This module supports both widely-published SOCKS5 authorization
//! modes: plaintext password ([RFC
//! 1929](https://datatracker.ietf.org/doc/html/rfc1961)), and GSSAPI
//! ([RFC 1961](https://datatracker.ietf.org/doc/html/rfc1961)).
//!
//! # Security
//!
//! SOCKS5 far-links involve two *separate* logical connections *and*
//! two datagram traffic flows: the one to the proxy, and the one
//! through the proxy to the target.  Both steps of these have
//! separate security concerns.  Additionally, the SOCKS5 proxy itself
//! potentially represents an inherent middleman.
//!
//! Security-sensitive applications must take steps to protect both
//! the connection *to* the proxy, and the connection *through* the
//! proxy.
//!
//! Additionally, note that while GSSAPI does provide message
//! security, the level of security provided by the Kerberos instance
//! (the primary use of GSSAPI) is inadequate by modern standards.
//!
//! Finally, flaws in the UDP association portion of RFC 1928 make it
//! relatively easy for a malicious third party to inject their own
//! traffic into a UDP association.  Secure applications must
//! therefore take additional steps to guarantee the authenticity of
//! messages.

use std::cell::RefCell;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::iter::once;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::Deref;
use std::rc::Rc;

use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Socket;
use constellation_common::retry::RetryResult;
use constellation_socks5::comm::SOCKS5Param;
use constellation_socks5::comm::SOCKS5UDPXfrm;
use constellation_socks5::error::SOCKS5Error;
use constellation_socks5::params::SOCKS5Params;
use constellation_socks5::state::SOCKS5State;
use constellation_socks5::state::SOCKS5UDPInfo;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::state_machine::RawStateMachine;
use constellation_streams::state_machine::RawStateMachineError;
use log::info;
use mio::Registry;
use mio::Token;

use crate::addrs::SocketAddrPolicy;
use crate::config::ResolverConfig;
use crate::config::SOCKS5AssocConfig;
use crate::config::SOCKS5AuthNConfig;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelCreate;
use crate::far::FarChannelFlows;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::far::flows::BufferedFlow;
use crate::near::NearChannelCreate;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCacheError;
use crate::resolve::cache::NSNameCachesCtx;
use crate::resolve::Resolver;

/// A far-link channel that communicates through a SOCKS5 proxy.
///
/// This is a [FarChannel] and instance that sets up a UDP association
/// with a SOCKS5 proxy to forward datagram traffic.  To do this, it
/// must first connect to the proxy using a separate
/// [NearConnector]-based channel (given by `Proxy`), which then
/// establishes the UDP association.  The proxy channel can be any
/// `NearConnector` instance, which may talk over a separate set of
/// protocols than the main connection.  Once this negotiation is
/// complete, it then forwards traffic through a separate [FarChannel]
/// (given by `Datagram`) through the proxy and on to the destination.
///
/// Traffic flows to the endpoint through the proxy are neither
/// inherently secure nor authenticated, and by their very nature
/// involve a middleman (the proxy).  Separately, neither connections
/// nor datagram traffic flows *to* the proxy are inherently secure by
/// themselves.
///
/// # Usage
///
/// The primary use of a `SOCKS5FarChannel` takes place through its
/// [FarChannel] instance.
///
/// ## Configuration and Creation
///
/// A `SOCKS5FarChannel` is created using the
/// [create](FarChannelCreate::new) function from its [FarChannel]
/// instance.  This function takes a [SOCKS5AssocConfig] as its
/// principal argument, which supplies all configuration information.
///
/// ### Example
///
/// The following example shows how to create a `SOCKS5FarChannel`,
/// using a [TCPNearConnector](crate::near::tcp::TCPNearConnector) as
/// to connect to the proxy itself:
///
/// ```
/// # use std::iter::once;
/// # use std::net::SocketAddr;
/// # use mio::Token;
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::socks5::SOCKS5FarChannel;
/// # use constellation_channels::far::udp::UDPFarChannel;
/// # use constellation_channels::near::tcp::TCPNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "addr: 0.0.0.0\n",
///     "port: 0\n",
///     "proxy:\n",
///     "  addr: test.example.com\n",
///     "  port: 9050\n",
///     "auth:\n",
///     "  username: test\n",
///     "  password: abc123\n"
/// );
/// let socks5_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let channel: SOCKS5FarChannel<TCPNearConnector, SocketAddr, UDPFarChannel> =
///     SOCKS5FarChannel::new(&mut nscaches, &mut once(Token(0)), socks5_config)
///     .unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `SOCKS5FarChannel` has been created, sockets can be created
/// by first calling [acquire](FarChannel::acquire) to obtain the
/// address to which to send UDP packets to be forwarded by the proxy.
/// This will be an [IPEndpoint], which may resolve to multiple
/// independent [SocketAddr]s.  An individual socket can then be
/// created for any one of these addresses using the
/// [socket](FarChannelSocket::socket) function.
///
/// The SOCKS5 proxy negotiation occurs transparently in the call to
/// [acquire](FarChannel::acquire).  This will block until a UDP
/// association is successfully negotiated, or until an error in
/// encountered that indicates an implementation error.
///
/// ## Complex Configurations
///
/// A `SOCKS5FarChannel` provides a [FarChannel] instance, which
/// resembles a [UDPFarChannel](crate::far::udp::UDPFarChannel).
/// Additionally, it makes use of a separate `NearConnector` to
/// establish the connection to the proxy itself, which need not be a
/// `TCPNearConnector`.  Depending on the needs of the application, it
/// is possible to engineer any of the following:
///
/// - Local SOCKS5 proxy: connecting to a local SOCKS5 proxy via a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector), which then
///   establishes a UDP forwarding port.  (Note that unlike with
///   [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector), the
///   forwarding must still take place over a UDP socket.)
///
/// - Double-layer SOCKS5 proxy: connecting to a remote SOCKS5 proxy via a
///   connection made through a *different* SOCKS5 proxy.  This could be
///   extended to any number of layered proxy connections.
pub struct SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearConnector + NearChannelCreate,
    Datagram: FarChannel {
    peer_addr: PhantomData<PeerAddr>,
    /// The session information, used to create sockets.
    // XXX This doesn't seem to be set anywhere.
    session: Rc<RefCell<Option<SOCKS5UDPInfo>>>,
    /// The authentication configuration for connecting to the proxy.
    auth: SOCKS5AuthNConfig,
    /// The [FarChannel] that will be used to forward UDP traffic.
    datagram: Datagram,
    /// The [NearConnector] that will be used to connect to the proxy.
    proxy: Proxy,
    /// The current number of retries.
    nretries: usize,
    /// Token to use for the keepalive connection.
    token: Token
}

pub struct SOCKS5SessionNegotiation<Proxy, Datagram> {
    datagram: Datagram,
    proxy: Proxy
}

/// Type of results from [acquire](FarChannel::acquire) for
/// [SOCKS5FarChannel].
pub struct SOCKS5Acquired<Acquired, PeerAddr> {
    addr: PhantomData<PeerAddr>,
    /// Datagram socket address.
    datagram: Acquired,
    /// Proxy address.
    proxy: IPEndpoint
}

/// Errors that can occur when creating a [SOCKS5FarChannel].
#[derive(Debug)]
pub enum SOCKS5CreateError<Proxy, Datagram> {
    /// Proxy negotiation channel creation error.
    Proxy { proxy: Proxy },
    /// Datagram channel creation error.
    Datagram { datagram: Datagram },
    NoTokens
}

/// Errors that can occur during the [acquire](FarChannel::acquire)
/// step of establishing a [SOCKS5FarChannel].
#[derive(Debug)]
pub enum SOCKS5AcquireError<Proxy, Datagram> {
    /// Proxy connection error.
    Proxy { proxy: Proxy },
    /// Datagram channel acquire error.
    Datagram { datagram: Datagram },
}

/// Errors that can occur during the [acquire](FarChannelSocket::socket)
/// step of establishing a [SOCKS5FarChannel].
#[derive(Debug)]
pub enum SOCKS5SocketError<Datagram> {
    /// Low-level I/O error occurred.
    IO { error: Error },
    /// Datagram channel socket error.
    Datagram { datagram: Datagram }
}

#[derive(Debug)]
pub enum SOCKS5XfrmError<Datagram> {
    /// Datagram channel socket error.
    Datagram { datagram: Datagram },
    /// Lost the keepalive connection to the proxy.
    ///
    /// The caller should attempt to [acquire](FarChannel::acquire)
    /// again and then repeat this call.
    LostConn,
    /// Failed to get a mutable reference.
    GetMut
}

/// Errors that can occur when getting a resolver for a [SOCKS5Acquired]
#[derive(Debug)]
pub enum SOCKS5AcquiredResolveError<Wrap> {
    /// Error accessing name caches.
    NameCache { err: NSNameCacheError },
    /// Error wrapping a [SocketAddr].
    Wrap { err: Wrap },
    /// No valid addresses.
    NoValidAddrs
}

#[derive(Debug)]
pub enum SOCKS5NegotiateError<Datagram, Proxy> {
    Proxy {
        err: Proxy
    },
    Datagram {
        err: Datagram,
    },
    SOCKS5 {
        err: SOCKS5Error
    },
    IO {
        err: Error
    },
    BadSplit
}

pub enum SOCKS5NegotiatePending<Datagram, DatagramState, DatagramPending,
                                Proxy, ProxyPending> {
    Proxy {
        state: DatagramState,
        pending: ProxyPending
    },
    Datagram {
        proxy: Proxy,
        pending: DatagramPending,
    },
    SOCKS5 {
        endpoint: IPEndpoint,
        datagram: Datagram,
        proxy: Proxy,
        pending: <RawStateMachineError<SOCKS5State> as RecoverableError>::Completable
    },
    IO {
        datagram: Datagram,
        proxy: Proxy,
    }
}

impl<Datagram, Proxy> ScopedError
    for SOCKS5NegotiateError<Datagram, Proxy>
where Datagram: ScopedError,
      Proxy: ScopedError,
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5NegotiateError::Proxy { err, .. } => err.scope(),
            SOCKS5NegotiateError::Datagram { err, .. } => err.scope(),
            SOCKS5NegotiateError::SOCKS5 { err, .. } => err.scope(),
            SOCKS5NegotiateError::IO { err, .. } => err.scope(),
            SOCKS5NegotiateError::BadSplit => ErrorScope::Unrecoverable
        }
    }
}

impl<Proxy, Datagram> ScopedError for SOCKS5AcquireError<Proxy, Datagram>
where
    Proxy: ScopedError,
    Datagram: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5AcquireError::Proxy { proxy } => proxy.scope(),
            SOCKS5AcquireError::Datagram { datagram } => datagram.scope(),
        }
    }
}

impl<Proxy, Datagram> ScopedError for SOCKS5CreateError<Proxy, Datagram>
where
    Proxy: ScopedError,
    Datagram: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5CreateError::Proxy { proxy } => proxy.scope(),
            SOCKS5CreateError::Datagram { datagram } => datagram.scope(),
            SOCKS5CreateError::NoTokens => ErrorScope::Unrecoverable
        }
    }
}

impl<Datagram> ScopedError for SOCKS5SocketError<Datagram>
where
    Datagram: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5SocketError::IO { error } => error.scope(),
            SOCKS5SocketError::Datagram { datagram } => datagram.scope()
        }
    }
}

impl<Datagram> ScopedError for SOCKS5XfrmError<Datagram>
where
    Datagram: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5XfrmError::Datagram { datagram } => datagram.scope(),
            SOCKS5XfrmError::LostConn => ErrorScope::Session,
            SOCKS5XfrmError::GetMut => ErrorScope::Unrecoverable
        }
    }
}

impl<Wrap> ScopedError for SOCKS5AcquiredResolveError<Wrap>
where
    Wrap: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5AcquiredResolveError::NameCache { err } => err.scope(),
            SOCKS5AcquiredResolveError::Wrap { err } => err.scope(),
            SOCKS5AcquiredResolveError::NoValidAddrs => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Acquired, PeerAddr> FarChannelAcquired
    for SOCKS5Acquired<Acquired, PeerAddr>
where
    Acquired: FarChannelAcquired,
    PeerAddr: From<IPEndpoint>
{
    type Resolved = SOCKS5Param<Acquired::Resolved, PeerAddr>;
    type WrapError = Acquired::WrapError;

    #[inline]
    fn wrap(
        &self,
        resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError> {
        let datagram = self.datagram.wrap(resolved)?;
        let proxy = PeerAddr::from(self.proxy.clone());

        Ok(SOCKS5Param::new(datagram, proxy))
    }
}

impl<Acquired, PeerAddr> FarChannelAcquiredResolve
    for SOCKS5Acquired<Acquired, PeerAddr>
where
    Acquired: FarChannelAcquiredResolve,
    PeerAddr: From<IPEndpoint>
{
    type ResolverError = SOCKS5AcquiredResolveError<Acquired::WrapError>;

    fn resolver<Ctx>(
        &self,
        caches: &mut Ctx,
        addr_policy: &SocketAddrPolicy,
        resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, Self::ResolverError>
    where
        Ctx: NSNameCachesCtx {
        match self.proxy.ip_addr() {
            IPEndpointAddr::Name(name) => {
                let resolver = Resolver::create(
                    caches,
                    resolver.clone(),
                    once((name.clone(), self.proxy.port()))
                )
                .map_err(|err| {
                    SOCKS5AcquiredResolveError::NameCache { err: err }
                })?;

                Ok(AcquiredResolver::Resolve { resolver: resolver })
            }
            IPEndpointAddr::Addr(addr) => {
                if addr_policy.check_ip(addr) {
                    let addr = SocketAddr::new(*addr, self.proxy.port());
                    let wrapped = self.datagram.wrap(addr).map_err(|err| {
                        SOCKS5AcquiredResolveError::Wrap { err: err }
                    })?;
                    let proxy = PeerAddr::from(self.proxy.clone());

                    Ok(AcquiredResolver::StaticSingle {
                        param: SOCKS5Param::new(wrapped, proxy)
                    })
                } else {
                    Err(SOCKS5AcquiredResolveError::NoValidAddrs)
                }
            }
        }
    }
}

impl<Proxy, PeerAddr, Datagram> SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelSocket + FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>,
{
    fn negotiate_endpoint(
        &self,
        mut stream: Proxy::Conn,
        datagram: Datagram::Acquired,
        target: IPEndpoint
    ) -> Result<
        NegotiatorResult<
            SOCKS5Acquired<Datagram::Acquired, IPEndpoint>,
            SOCKS5NegotiatePending<
                Datagram::Acquired,
                Datagram::State,
                Datagram::NegotiatePending,
                Proxy::Conn,
                Proxy::Pending
            >
        >,
        SOCKS5NegotiateError<
            Datagram::NegotiateError,
            Proxy::NegotiateError,
        >
    > {
        let params = match &self.auth {
            SOCKS5AuthNConfig::None => {
                SOCKS5Params::assoc_no_auth(target.clone())
            }
            SOCKS5AuthNConfig::Password {
                username,
                password
            } => SOCKS5Params::assoc_password_auth(
                target.clone(),
                username.clone(),
                password.clone()
            ),
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNConfig::GSSAPI { gssapi } => {
                SOCKS5Params::assoc_gssapi_auth(
                    target.clone(),
                    gssapi.clone(),
                    None
                )
            }
        };
        let machine: RawStateMachine<SOCKS5State> =
            RawStateMachine::new(params);

        // Run the protocol negotiation
        match machine.run(&mut stream) {
            Ok(socks5) => {
                let endpoint = socks5.ip_endpoint().clone();

                info!(target: "far-socks5",
                      "established SOCKS5 UDP association for {} with {}",
                      endpoint, self.proxy.endpoint());

                Ok(NegotiatorResult::Complete(SOCKS5Acquired {
                    addr: PhantomData,
                    datagram: datagram,
                    proxy: endpoint
                }))
            }
            Err(err) => match err.split() {
                (Some(pending), None) => Ok(NegotiatorResult::Pending(
                    SOCKS5NegotiatePending::SOCKS5 {
                        endpoint: target,
                        datagram: datagram,
                        proxy: stream,
                        pending: pending
                    }
                )),
                (None, Some(err)) => Err(SOCKS5NegotiateError::SOCKS5 {
                    err: err
                }),
                _ => Err(SOCKS5NegotiateError::BadSplit)
            }
        }
    }

    fn negotiate_acquired(
        &self,
        stream: Proxy::Conn,
        datagram: Datagram::Acquired
    ) -> Result<
        NegotiatorResult<
            SOCKS5Acquired<Datagram::Acquired, IPEndpoint>,
            SOCKS5NegotiatePending<
                Datagram::Acquired,
                Datagram::State,
                Datagram::NegotiatePending,
                Proxy::Conn,
                Proxy::Pending
            >
        >,
        SOCKS5NegotiateError<
            Datagram::NegotiateError,
            Proxy::NegotiateError,
        >
    > {
        match self.datagram.socks5_target(&datagram) {
            Ok(target) => self.negotiate_endpoint(stream, datagram, target),
            Err(err) => Err(SOCKS5NegotiateError::IO {
                err: err
            })
        }
    }

    fn negotiate_datagram(
        &self,
        stream: Proxy::Conn,
        datagram: Datagram::State
    ) -> Result<
        NegotiatorResult<
            SOCKS5Acquired<Datagram::Acquired, IPEndpoint>,
            SOCKS5NegotiatePending<
                Datagram::Acquired,
                Datagram::State,
                Datagram::NegotiatePending,
                Proxy::Conn,
                Proxy::Pending
            >
        >,
        SOCKS5NegotiateError<
            Datagram::NegotiateError,
            Proxy::NegotiateError,
        >
    > {
        match self.datagram.negotiate(datagram)
            .map_err(|err| SOCKS5NegotiateError::Datagram { err: err })? {
            NegotiatorResult::Complete(acquired) =>
                    self.negotiate_acquired(stream, acquired),
            NegotiatorResult::Pending(pending) =>
                Ok(NegotiatorResult::Pending(SOCKS5NegotiatePending::Datagram {
                    pending: pending,
                    proxy: stream
                }))
        }
    }
}

impl<Proxy, PeerAddr, Datagram> FarChannel
    for SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelSocket + FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>,
{
    type State = SOCKS5SessionNegotiation<Proxy::State, Datagram::State>;
    type NegotiateError = SOCKS5NegotiateError<
        Datagram::NegotiateError,
        Proxy::NegotiateError,
    >;
    type NegotiatePending = SOCKS5NegotiatePending<
        Datagram::Acquired,
        Datagram::State,
        Datagram::NegotiatePending,
        Proxy::Conn,
        Proxy::Pending
    >;
    type AcquireError = SOCKS5AcquireError<
        Proxy::StartError,
        Datagram::AcquireError
    >;
    type Acquired = SOCKS5Acquired<Datagram::Acquired, IPEndpoint>;

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.datagram.socks5_target(&val.datagram)
    }

    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::State>, Self::AcquireError> {
        self
            .proxy
            .start(registry, self.token.clone())
            .map_err(|err| SOCKS5AcquireError::Proxy { proxy: err })?
            .flat_map_ok(|proxy| self
                    .datagram
                    .acquire(registry)
                    .map_err(|err| SOCKS5AcquireError::Datagram {
                        datagram: err
                    })?
                    .map_ok(|datagram| Ok(SOCKS5SessionNegotiation {
                        datagram: datagram,
                        proxy: proxy
                    })))
    }

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match self.proxy.negotiate(state.proxy)
            .map_err(|err| SOCKS5NegotiateError::Proxy { err: err })? {
            NegotiatorResult::Complete((stream, _)) =>
                self.negotiate_datagram(stream, state.datagram),
            NegotiatorResult::Pending(pending) =>
                Ok(NegotiatorResult::Pending(SOCKS5NegotiatePending::Proxy {
                    state: state.datagram,
                    pending: pending
                })),
        }
    }

    #[inline]
    fn complete_negotiate(
        &self,
        err: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match err {
            SOCKS5NegotiatePending::Proxy { state, pending } => match self.proxy
                .complete_negotiate(pending)
                .map_err(|err| SOCKS5NegotiateError::Proxy { err: err })? {
                NegotiatorResult::Complete((stream, _)) =>
                    self.negotiate_datagram(stream, state),
                NegotiatorResult::Pending(pending) =>
                    Ok(NegotiatorResult::Pending(SOCKS5NegotiatePending::Proxy {
                        pending: pending,
                        state: state
                    })),
            }
            SOCKS5NegotiatePending::Datagram { proxy, pending } => match self
                .datagram.complete_negotiate(pending)
                .map_err(|err| SOCKS5NegotiateError::Datagram { err: err })? {
                NegotiatorResult::Complete(acquired) =>
                    self.negotiate_acquired(proxy, acquired),
                NegotiatorResult::Pending(pending) =>
                    Ok(NegotiatorResult::Pending(
                        SOCKS5NegotiatePending::Datagram {
                            pending: pending,
                            proxy: proxy
                        }
                    ))
            }
            SOCKS5NegotiatePending::SOCKS5 {
                endpoint, datagram, mut proxy, pending
            } => {
                let machine: RawStateMachine<SOCKS5State> =
                    RawStateMachine::complete(pending);

                // Run the protocol negotiation
                match machine.run(&mut proxy) {
                    Ok(socks5) => {
                        let endpoint = socks5.ip_endpoint().clone();

                        info!(target: "far-socks5",
                              concat!("established SOCKS5 UDP association ",
                                      "for {} with {}"),
                              endpoint, self.proxy.endpoint());

                        Ok(NegotiatorResult::Complete(SOCKS5Acquired {
                            addr: PhantomData,
                            datagram: datagram,
                            proxy: endpoint
                        }))
                    }
                    Err(err) => match err.split() {
                        (Some(pending), None) => Ok(NegotiatorResult::Pending(
                            SOCKS5NegotiatePending::SOCKS5 {
                                endpoint: endpoint.clone(),
                                datagram: datagram,
                                proxy: proxy,
                                pending: pending
                            }
                        )),
                        (None, Some(err)) => Err(SOCKS5NegotiateError::SOCKS5 {
                            err: err
                        }),
                        _ => Err(SOCKS5NegotiateError::BadSplit)
                    }
                }
            }
            SOCKS5NegotiatePending::IO { datagram, proxy } => match self
                .datagram.socks5_target(&datagram) {
                Ok(target) => self.negotiate_endpoint(proxy, datagram, target),
                Err(err) => Err(SOCKS5NegotiateError::IO {
                    err: err
                })
            }
        }
    }

}

impl<Proxy, Datagram, PeerAddr> FarChannelSocket
    for SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelSocket + FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>,
{
    type Param = SOCKS5Param<Datagram::Param, PeerAddr>;
    type Socket = Datagram::Socket;
    type SocketError = SOCKS5SocketError<Datagram::SocketError>;

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.datagram
            .socket(param.inner())
            .map_err(|e| SOCKS5SocketError::Datagram { datagram: e })
    }
}

impl<Proxy, Datagram, Xfrm, InnerXfrm> FarChannelXfrm<Xfrm, InnerXfrm>
    for SOCKS5FarChannel<Proxy, InnerXfrm::PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelXfrm<Xfrm, InnerXfrm> + FarChannelSocket + FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>,
    <<Datagram::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Debug + Display,
    Xfrm: DatagramXfrm + From<SOCKS5UDPXfrm<Xfrm>>,
    Xfrm::LocalAddr: From<<Datagram::Socket as Socket>::Addr>,
    Xfrm::PeerAddr: From<InnerXfrm::PeerAddr>,
    InnerXfrm: DatagramXfrm
{
    type XfrmError = SOCKS5XfrmError<Datagram::XfrmError>;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: InnerXfrm
    ) -> Result<Xfrm, Self::XfrmError> {
        match self.session.try_borrow_mut()
            .map_err(|_| SOCKS5XfrmError::GetMut)?
            .deref(){
            Some(session) => {
                let (datagram, proxy) = param.take();
                let xfrm =
                    self.datagram.wrap_xfrm(datagram, xfrm).map_err(
                        |e| SOCKS5XfrmError::Datagram { datagram: e }
                    )?;
                let proxy_addr = Xfrm::PeerAddr::from(proxy);
                let xfrm = session.udp_xfrm(proxy_addr, xfrm);
                let xfrm = Xfrm::from(xfrm);

                Ok(xfrm)
            }
            // Keepalive connection was lost
            None => Err(SOCKS5XfrmError::LostConn)
        }
    }
}

impl<Proxy, PeerAddr, Datagram> FarChannelCreate
    for SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelCreate + FarChannelSocket,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>
{
    type Config = SOCKS5AssocConfig<Proxy::Config, Datagram::Config>;
    type CreateError =
        SOCKS5CreateError<Proxy::CreateError, Datagram::CreateError>;

    fn new<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        let token = tokens.next().ok_or(SOCKS5CreateError::NoTokens)?;
        let (bind, auth, proxy) = config.take();
        let datagram = Datagram::new(caches, tokens, bind)
            .map_err(|e| SOCKS5CreateError::Datagram { datagram: e })?;
        let proxy = Proxy::create(caches, proxy)
            .map_err(|e| SOCKS5CreateError::Proxy { proxy: e })?;

        Ok(SOCKS5FarChannel {
            peer_addr: PhantomData,
            session: Rc::new(RefCell::new(None)),
            auth: auth,
            proxy: proxy,
            nretries: 0,
            datagram: datagram,
            token: token
        })
    }
}

impl<Proxy, Datagram, Xfrm, InnerXfrm> FarChannelFlows<Xfrm, InnerXfrm>
    for SOCKS5FarChannel<Proxy, InnerXfrm::PeerAddr, Datagram>
where
    InnerXfrm: DatagramXfrm,
    Xfrm: DatagramXfrm + From<SOCKS5UDPXfrm<Xfrm>>,
    Proxy: NearConnector + NearChannelCreate,
    Datagram: FarChannelFlows<Xfrm, InnerXfrm> + FarChannelSocket + FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: TryFrom<Xfrm::LocalAddr>,
    <Datagram::Socket as Socket>::Addr: TryFrom<SocketAddr>,
    <<Datagram::Socket as Socket>::Addr as TryFrom<Xfrm::LocalAddr>>::Error:
        Debug + Display,
    Datagram::InboundNego: NegotiatorStart<
        Datagram::Flow,
        BufferedFlow<Datagram::Socket, Xfrm>
    >,
    Datagram::OutboundNego: NegotiatorStart<
        Datagram::Flow,
        BufferedFlow<Datagram::Socket, Xfrm>
    >,
    Xfrm::LocalAddr: From<<Datagram::Socket as Socket>::Addr>,
    Xfrm::PeerAddr: From<InnerXfrm::PeerAddr>,
    <Datagram::Socket as Socket>::Addr: From<SocketAddr>
{
    type OutboundNego = Datagram::OutboundNego;
    type InboundNego = Datagram::InboundNego;
    type OutboundNegoError = Datagram::OutboundNegoError;
    type InboundNegoError = Datagram::InboundNegoError;
    type Flow = Datagram::Flow;

    #[inline]
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        self.datagram.inbound_negotiator()
    }

    #[inline]
    fn outbound_negotiator(
        &self
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        self.datagram.outbound_negotiator()
    }
}

impl<Datagram, Proxy> Display
    for SOCKS5NegotiateError<Datagram, Proxy>
where Datagram: Display,
      Proxy: Display,
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5NegotiateError::Proxy { err } => err.fmt(f),
            SOCKS5NegotiateError::Datagram { err } => err.fmt(f),
            SOCKS5NegotiateError::SOCKS5 { err } => write!(f, "{}", err),
            SOCKS5NegotiateError::IO { err } => write!(f, "{}", err),
            SOCKS5NegotiateError::BadSplit =>
                write!(f, "invalid result from split()")
        }
    }
}

impl<Proxy, Datagram> Display for SOCKS5CreateError<Proxy, Datagram>
where
    Proxy: Display,
    Datagram: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5CreateError::Proxy { proxy } => proxy.fmt(f),
            SOCKS5CreateError::Datagram { datagram } => datagram.fmt(f),
            SOCKS5CreateError::NoTokens => write!(f, "tokens exhausted")
        }
    }
}

impl<Proxy, Datagram> Display for SOCKS5AcquireError<Proxy, Datagram>
where
    Proxy: Display,
    Datagram: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5AcquireError::Proxy { proxy } => proxy.fmt(f),
            SOCKS5AcquireError::Datagram { datagram } => datagram.fmt(f),
        }
    }
}

impl<Datagram> Display for SOCKS5SocketError<Datagram>
where
    Datagram: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5SocketError::IO { error } => write!(f, "{}", error),
            SOCKS5SocketError::Datagram { datagram } => datagram.fmt(f)
        }
    }
}

impl<Datagram> Display for SOCKS5XfrmError<Datagram>
where
    Datagram: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5XfrmError::Datagram { datagram } => datagram.fmt(f),
            SOCKS5XfrmError::LostConn => {
                write!(f, "lost SOCKS5 TCP connection")
            }
            SOCKS5XfrmError::GetMut => write!(f, "get mutable reference failed")
        }
    }
}

impl<Wrap> Display for SOCKS5AcquiredResolveError<Wrap>
where
    Wrap: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5AcquiredResolveError::NameCache { err } =>
                write!(f, "{}", err),
            SOCKS5AcquiredResolveError::Wrap { err } => err.fmt(f),
            SOCKS5AcquiredResolveError::NoValidAddrs => {
                write!(f, "no valid addresses supplied")
            }
        }
    }
}
