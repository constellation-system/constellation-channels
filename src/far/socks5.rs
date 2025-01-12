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

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::iter::once;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;

use constellation_auth::authn::SessionAuthN;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Socket;
use constellation_socks5::comm::SOCKS5Param;
use constellation_socks5::comm::SOCKS5UDPXfrm;
use constellation_socks5::error::SOCKS5Error;
use constellation_socks5::params::SOCKS5Params;
use constellation_socks5::state::SOCKS5State;
use constellation_socks5::state::SOCKS5UDPInfo;
use constellation_streams::addrs::AddrsCreate;
use constellation_streams::state_machine::RawStateMachine;
use log::debug;
use log::error;
use log::info;
use log::warn;

use crate::addrs::SocketAddrPolicy;
use crate::config::ResolverConfig;
use crate::config::SOCKS5AssocConfig;
use crate::config::SOCKS5AuthNConfig;
use crate::far::flows::BorrowedFlows;
use crate::far::flows::CreateBorrowedFlows;
use crate::far::flows::CreateOwnedFlows;
use crate::far::flows::Flows;
use crate::far::flows::Negotiator;
use crate::far::flows::OwnedFlows;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelBorrowFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelOwnedFlows;
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
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::socks5::SOCKS5FarChannel;
/// # use constellation_channels::far::udp::UDPFarChannel;
/// # use constellation_channels::near::tcp::TCPNearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// # use std::net::SocketAddr;
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
///     SOCKS5FarChannel::new(&mut nscaches, socks5_config)
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
/// [socket](FarChannel::socket) function.
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
pub struct SOCKS5FarChannel<
    Proxy: NearConnector + NearChannelCreate,
    ProxyAddr,
    Datagram: FarChannel
> {
    addr: PhantomData<ProxyAddr>,
    /// The TCP connection, which must be kept alive.
    #[allow(dead_code)]
    keepalive: Arc<Mutex<Option<Proxy>>>,
    /// The session information, used to create sockets.
    session: Arc<Mutex<Option<SOCKS5UDPInfo>>>,
    /// The authentication configuration for connecting to the proxy.
    auth: SOCKS5AuthNConfig,
    /// The [FarChannel] that will be used to forward UDP traffic.
    datagram: Datagram,
    /// The [NearConnector] that will be used to connect to the proxy.
    proxy: Proxy,
    /// The current number of retries.
    nretries: usize
}

/// Errors that can occur when creating a [SOCKS5FarChannel].
#[derive(Debug)]
pub enum SOCKS5CreateError<Proxy, Datagram> {
    /// Proxy negotiation channel creation error.
    Proxy { proxy: Proxy },
    /// Datagram channel creation error.
    Datagram { datagram: Datagram }
}

/// Errors that can occur during the [acquire](FarChannel::acquire)
/// step of establishing a [SOCKS5FarChannel].
#[derive(Debug)]
pub enum SOCKS5AcquireError<Proxy, Datagram> {
    /// Low-level I/O error occurred.
    IO { error: Error },
    /// Proxy connection error.
    Proxy { proxy: Proxy },
    /// Datagram channel acquire error.
    Datagram { datagram: Datagram },
    /// SOCKS5 negotiation error.
    SOCKS5 { socks5: SOCKS5Error },
    /// Mutex was poisoned.
    MutexPoison
}

/// Errors that can occur during the [acquire](FarChannel::socket)
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
    /// Mutex was poisoned.
    MutexPoison
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

impl<Proxy, Datagram> ScopedError for SOCKS5AcquireError<Proxy, Datagram>
where
    Proxy: ScopedError,
    Datagram: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5AcquireError::IO { error } => error.scope(),
            SOCKS5AcquireError::Proxy { proxy } => proxy.scope(),
            SOCKS5AcquireError::Datagram { datagram } => datagram.scope(),
            SOCKS5AcquireError::SOCKS5 { socks5 } => socks5.scope(),
            SOCKS5AcquireError::MutexPoison => ErrorScope::Unrecoverable
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
            SOCKS5CreateError::Datagram { datagram } => datagram.scope()
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
            SOCKS5XfrmError::MutexPoison => ErrorScope::Unrecoverable
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
        match self.proxy.ip_endpoint() {
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

impl<Proxy, PeerAddr, Datagram> FarChannel
    for SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannel,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: From<SocketAddr>
{
    type AcquireError =
        SOCKS5AcquireError<Proxy::TakeConnectError, Datagram::AcquireError>;
    type Acquired = SOCKS5Acquired<Datagram::Acquired, IPEndpoint>;
    type Config = SOCKS5AssocConfig<Proxy::Config, Datagram::Config>;
    type Param = SOCKS5Param<Datagram::Param, PeerAddr>;
    type Socket = Datagram::Socket;
    type SocketError = SOCKS5SocketError<Datagram::SocketError>;

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.datagram.socks5_target(&val.datagram)
    }

    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        // If acquire fails on the underlying channel,
        // return the error.
        let datagram = self
            .datagram
            .acquire()
            .map_err(|e| SOCKS5AcquireError::Datagram { datagram: e })?;

        loop {
            match self.session.lock() {
                Ok(mut guard) => match &*guard {
                    // Session already exists; return its endpoint.
                    Some(session) => {
                        debug!(target: "far-socks5",
                               concat!("reusing existing SOCKS5 UDP ",
                                       "association ({} on {})"),
                               session.ip_endpoint(),
                               self.proxy.endpoint());
                        return Ok(SOCKS5Acquired {
                            addr: PhantomData,
                            datagram: datagram,
                            proxy: session.ip_endpoint().clone()
                        });
                    }
                    // No session exists; create one.
                    None => {
                        debug!(target: "far-socks5",
                               "establishing SOCKS5 UDP association with {}",
                               self.proxy.endpoint());

                        let target = self
                            .datagram
                            .socks5_target(&datagram)
                            .map_err(|e| SOCKS5AcquireError::IO { error: e })?;
                        let params = match &self.auth {
                            SOCKS5AuthNConfig::None => {
                                SOCKS5Params::assoc_no_auth(target)
                            }
                            SOCKS5AuthNConfig::Password {
                                username,
                                password
                            } => SOCKS5Params::assoc_password_auth(
                                target,
                                username.clone(),
                                password.clone()
                            ),
                            #[cfg(feature = "gssapi")]
                            SOCKS5AuthNConfig::GSSAPI { gssapi } => {
                                SOCKS5Params::assoc_gssapi_auth(
                                    target,
                                    gssapi.clone(),
                                    None
                                )
                            }
                        };
                        let (mut stream, _) =
                            self.proxy.take_connection().map_err(|e| {
                                SOCKS5AcquireError::Proxy { proxy: e }
                            })?;
                        let machine: RawStateMachine<SOCKS5State> =
                            RawStateMachine::new(params);

                        // Run the protocol negotiation
                        match machine.run(&mut stream) {
                            Ok(socks5) => {
                                let endpoint = socks5.ip_endpoint().clone();

                                info!(target: "far-socks5",
                                      concat!("established SOCKS5 UDP ",
                                              "association for {} with {}"),
                                      endpoint, self.proxy.endpoint());

                                self.nretries = 0;
                                *guard = Some(socks5.udp_info());

                                return Ok(SOCKS5Acquired {
                                    addr: PhantomData,
                                    datagram: datagram,
                                    proxy: endpoint
                                });
                            }
                            Err(e) => {
                                warn!(target: "far-socks5",
                                      concat!("SOCKS5 UDP association ",
                                              "negotiation with {} failed ",
                                              "({})"),
                                      self.proxy.endpoint(), e);

                                if let Err(err) = self.proxy.fail(self.nretries)
                                {
                                    error!(target: "near-session",
                                           "error resetting connection ({})",
                                           err);
                                }

                                self.nretries += 1;
                            }
                        }
                    }
                },
                // Mutex poisoned.
                Err(_) => return Err(SOCKS5AcquireError::MutexPoison)
            }
        }
    }

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

impl<Proxy, PeerAddr, Datagram> FarChannelCreate
    for SOCKS5FarChannel<Proxy, PeerAddr, Datagram>
where
    Proxy: NearChannelCreate + NearConnector,
    Datagram: FarChannelCreate,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: From<SocketAddr>
{
    type CreateError =
        SOCKS5CreateError<Proxy::CreateError, Datagram::CreateError>;

    fn new<Ctx>(
        caches: &mut Ctx,
        config: SOCKS5AssocConfig<Proxy::Config, Datagram::Config>
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (bind, auth, proxy) = config.take();
        let datagram = Datagram::new(caches, bind)
            .map_err(|e| SOCKS5CreateError::Datagram { datagram: e })?;
        let proxy = Proxy::new(caches, proxy)
            .map_err(|e| SOCKS5CreateError::Proxy { proxy: e })?;

        Ok(SOCKS5FarChannel {
            keepalive: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
            auth: auth,
            proxy: proxy,
            nretries: 0,
            datagram: datagram,
            addr: PhantomData
        })
    }
}

impl<F, Proxy, ProxyAddr, Datagram, Xfrm> FarChannelBorrowFlows<F, Xfrm>
    for SOCKS5FarChannel<Proxy, ProxyAddr, Datagram>
where
    Proxy: NearConnector + NearChannelCreate,
    Xfrm: DatagramXfrm,
    Xfrm::PeerAddr: From<ProxyAddr>,
    Xfrm::LocalAddr:
        From<<Datagram::Socket as Socket>::Addr> + From<SocketAddr>,
    Xfrm: From<SOCKS5UDPXfrm<Xfrm>>,
    Datagram: FarChannelBorrowFlows<F, Xfrm>,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: From<SocketAddr>,
    Datagram::Borrowed: BorrowedFlows,
    F: Flows + CreateBorrowedFlows + BorrowedFlows,
    F::Socket: From<Datagram::Socket>,
    F::Xfrm: From<Datagram::Xfrm>,
    F::Xfrm: From<Xfrm>
{
    type Borrowed = Datagram::Borrowed;
    type BorrowedFlowsError = Datagram::BorrowedFlowsError;
    type Xfrm = Datagram::Xfrm;
    type XfrmError = SOCKS5XfrmError<Datagram::XfrmError>;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match self.session.lock() {
            Ok(guard) => match &*guard {
                Some(session) => {
                    let (datagram, proxy) = param.take();
                    let xfrm =
                        session.udp_xfrm(Xfrm::PeerAddr::from(proxy), xfrm);

                    self.datagram
                        .wrap_xfrm(datagram, Xfrm::from(xfrm))
                        .map_err(|e| SOCKS5XfrmError::Datagram { datagram: e })
                }
                // Keepalive connection was lost
                None => Err(SOCKS5XfrmError::LostConn)
            },
            // Mutex was poisoned.
            Err(_) => Err(SOCKS5XfrmError::MutexPoison)
        }
    }

    #[inline]
    fn wrap_borrowed_flows(
        &self,
        flows: F
    ) -> Result<Self::Borrowed, Self::BorrowedFlowsError> {
        self.datagram.wrap_borrowed_flows(flows)
    }
}

impl<F, Proxy, ProxyAddr, Datagram, AuthN, Xfrm>
    FarChannelOwnedFlows<F, AuthN, Xfrm>
    for SOCKS5FarChannel<Proxy, ProxyAddr, Datagram>
where
    Proxy: NearConnector + NearChannelCreate,
    Xfrm: DatagramXfrm,
    Xfrm::PeerAddr: From<ProxyAddr>,
    Xfrm::LocalAddr:
        From<<Datagram::Socket as Socket>::Addr> + From<SocketAddr>,
    Xfrm: From<SOCKS5UDPXfrm<Xfrm>>,
    Datagram: FarChannelOwnedFlows<F, AuthN, Xfrm>,
    Datagram::Socket: Socket,
    <Datagram::Socket as Socket>::Addr: From<SocketAddr>,
    Datagram::Owned: OwnedFlows,
    Datagram::Nego: Negotiator<Inner = F::Flow>,
    AuthN: SessionAuthN<<Datagram::Nego as Negotiator>::Flow>,
    F: Flows + CreateOwnedFlows<Datagram::Nego, AuthN> + OwnedFlows,
    F::Socket: From<Datagram::Socket>,
    F::Xfrm: From<Datagram::Xfrm>,
    F::Xfrm: From<Xfrm>
{
    type Nego = Datagram::Nego;
    type Owned = Datagram::Owned;
    type OwnedFlowsError = Datagram::OwnedFlowsError;
    type Xfrm = Datagram::Xfrm;
    type XfrmError = SOCKS5XfrmError<Datagram::XfrmError>;

    #[inline]
    fn negotiator(&self) -> Self::Nego {
        self.datagram.negotiator()
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: Xfrm
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match self.session.lock() {
            Ok(guard) => match &*guard {
                Some(session) => {
                    let (datagram, proxy) = param.take();
                    let xfrm =
                        session.udp_xfrm(Xfrm::PeerAddr::from(proxy), xfrm);

                    self.datagram
                        .wrap_xfrm(datagram, Xfrm::from(xfrm))
                        .map_err(|e| SOCKS5XfrmError::Datagram { datagram: e })
                }
                // Keepalive connection was lost
                None => Err(SOCKS5XfrmError::LostConn)
            },
            // Mutex was poisoned.
            Err(_) => Err(SOCKS5XfrmError::MutexPoison)
        }
    }

    #[inline]
    fn wrap_owned_flows(
        &self,
        flows: F
    ) -> Result<Self::Owned, Self::OwnedFlowsError> {
        self.datagram.wrap_owned_flows(flows)
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
            SOCKS5CreateError::Datagram { datagram } => datagram.fmt(f)
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
            SOCKS5AcquireError::IO { error } => error.fmt(f),
            SOCKS5AcquireError::Proxy { proxy } => proxy.fmt(f),
            SOCKS5AcquireError::Datagram { datagram } => datagram.fmt(f),
            SOCKS5AcquireError::SOCKS5 { socks5 } => socks5.fmt(f),
            SOCKS5AcquireError::MutexPoison => write!(f, "mutex poisoned")
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
            SOCKS5SocketError::IO { error } => error.fmt(f),
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
            SOCKS5XfrmError::MutexPoison => write!(f, "mutex poisoned")
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
            SOCKS5AcquiredResolveError::NameCache { err } => err.fmt(f),
            SOCKS5AcquiredResolveError::Wrap { err } => err.fmt(f),
            SOCKS5AcquiredResolveError::NoValidAddrs => {
                write!(f, "no valid addresses supplied")
            }
        }
    }
}
