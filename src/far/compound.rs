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

//! A flexible, configurable [FarChannel] instance.
//!
//! Compound channels support arbitrary nesting of different channel
//! types, which can be constructed according to a configuration.
//! This functionality is provided by [CompoundFarChannel].  Most
//! applications should use these implementations, unless there is a
//! good reason to impose more stringent restrictions on what types of
//! channels can be configured.

use std::convert::Infallible;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
#[cfg(feature = "unix")]
use std::os::unix::net::UCred;

use constellation_auth::cred::Credentials;
#[cfg(feature = "tls")]
use constellation_auth::cred::SSLCred;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::DatagramXfrm;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::DatagramXfrmCreateParam;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::PassthruNegotiator;
use constellation_common::net::PassthruSessionNegotiation;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Session;
use constellation_common::net::Socket;
use constellation_common::net::TrivialNegotiator;
use constellation_common::retry::RetryResult;
use constellation_common::sched::SelectError;
use constellation_common::unix::UnixSocketPath;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5Param;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5UDPXfrm;
#[cfg(feature = "socks5")]
use constellation_socks5::error::SOCKS5UDPError;
use constellation_streams::channels::ChannelParam;
use mio::event::Source;
use mio::Interest;
use mio::Registry;
use mio::Token;

use crate::addrs::SocketAddrPolicy;
use crate::config::tls::TLSLoadConfigError;
use crate::config::tls::TLSPeerConfig;
use crate::config::CompoundFarChannelConfig;
use crate::config::CompoundFarEndpoint;
use crate::config::CompoundFarIPChannelConfig;
use crate::config::CompoundXfrmCreateParam;
use crate::config::ResolverConfig;
use crate::far::dtls::DTLSFarChannel;
use crate::far::dtls::DTLSFlow;
use crate::far::dtls::DTLSInboundNegoError;
use crate::far::dtls::DTLSInboundNegoPending;
use crate::far::dtls::DTLSInboundNegotiator;
use crate::far::dtls::DTLSInboundNegotiatorState;
use crate::far::dtls::DTLSNegotiateError;
use crate::far::dtls::DTLSOutboundNegoError;
use crate::far::dtls::DTLSOutboundNegoPending;
use crate::far::dtls::DTLSOutboundNegotiator;
use crate::far::dtls::DTLSOutboundNegotiatorState;
use crate::far::dtls::DTLSOutboundParam;
use crate::far::flows::BufferedFlow;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquireError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredShutdownError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredShutdownNegoError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredShutdownPending;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredShutdownState;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5Acquired;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredResolveError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5CreateError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5FarChannel;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5NegotiateError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5NegotiatePending;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5SessionNegotiation;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5SocketError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5XfrmError;
use crate::far::udp::UDPFarChannel;
use crate::far::udp::UDPFarSocket;
use crate::far::unix::UnixDatagramSocket;
use crate::far::unix::UnixFarChannel;
use crate::far::AcquiredResolveStaticError;
use crate::far::AcquiredResolver;
use crate::far::FarChannel;
use crate::far::FarChannelAcquired;
use crate::far::FarChannelAcquiredResolve;
use crate::far::FarChannelFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelSocket;
use crate::far::FarChannelXfrm;
use crate::near::compound::CompoundNearClientConn;
use crate::near::compound::CompoundResolvingNearConnector;
use crate::near::compound::CompoundNearConnectorState;
use crate::near::compound::CompoundNearConnectorCreateError;
use crate::near::compound::CompoundNearConnectorStartError;
use crate::near::compound::CompoundNearConnectorNegotiateError;
use crate::near::compound::CompoundNearConnectorNegotiatePending;
use crate::near::compound::CompoundNearShutdownNegotiatorPending;
use crate::near::compound::CompoundNearShutdownNegotiatorState;
use crate::resolve::cache::NSNameCachesCtx;
use crate::resolve::Resolution;
use crate::tls::TLSShutdownError;
use crate::tls::DTLSShutdownNegotiator;
use crate::tls::TLSShutdownNegoPending;
use crate::tls::TLSShutdownNegotiatorState;
use crate::tls::TLSStartError;

/// Type alias for [CompoundNearConnector] instances that use
/// [TLSPeerConfig] as their TLS configuration.
type ProxyNearConnector = CompoundResolvingNearConnector<TLSPeerConfig>;

/// Versatile IP-only far-link channel.
///
/// This is a subset of [CompoundFarChannel] that supports only
/// IP-based protocols (no Unix sockets).  This is used primarily for
/// SOCKS5 relays.
pub enum CompoundFarIPChannel {
    /// Wrapper around a [UDPFarChannel].
    UDP {
        /// The inner [UDPFarChannel].
        udp: UDPFarChannel
    },
    #[cfg(feature = "dtls")]
    /// Wrapper around a [DTLSFarChannel].
    DTLS {
        /// The inner [DTLSFarChannel].
        dtls: Box<DTLSFarChannel<CompoundFarIPChannel>>
    },
    #[cfg(feature = "socks5")]
    /// Wrapper around a [SOCKS5FarChannel].
    SOCKS5 {
        /// The inner [SOCKS5FarChannel].
        socks5: Box<SOCKS5FarChannel<
            ProxyNearConnector,
            CompoundFarIPChannelXfrmPeerAddr,
            CompoundFarIPChannel
        >>
    }
}

/// Versatile far-link channel.
///
/// This is a [FarChannel] instance that can support arbitrarily
/// complex nested channel configurations consisting of SOCKS5 and DTLS
/// layers, with either UDP or Unix domain sockets serving as the base
/// connections.
///
/// See [CompoundFarChannelConfig] for example configuratons.
///
/// # Usage
///
/// The primary use of a `CompoundFarChannel` takes place through its
/// [FarChannel] instance.
///
/// ## Configuration and Creation
///
/// A `CompoundFarChannel` is created using the
/// [new](FarChannelCreate::new) function from its [FarChannel]
/// instance.  This function takes a
/// [CompoundFarConnectorConfig](crate::config::CompoundFarChannelConfig)
/// as its principal argument, which supplies all configuration
/// unformation.
///
/// ### Example
///
/// The following example shows how to create a `CompoundFarChannel`:
///
/// ```
/// # use std::iter::empty;
/// # use constellation_channels::far::FarChannelCreate;
/// # use constellation_channels::far::compound::CompoundFarChannel;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "dtls:\n",
///     "  trust-root:\n",
///     "    root-certs:\n",
///     "      - test/data/certs/server/ca_cert.pem\n",
///     "  cert: test/data/certs/client/certs/test_client_cert.pem\n",
///     "  key: test/data/certs/client/private/test_client_key.pem\n",
///     "  udp:\n",
///     "    addr: ::0\n",
///     "    port: 7002\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector = CompoundFarChannel::create(&mut nscaches, &mut empty(),
///                                            accept_config).unwrap();
/// ```
pub enum CompoundFarChannel {
    #[cfg(feature = "unix")]
    /// Wrapper around a [UnixFarChannel].
    Unix {
        /// The inner [UnixFarChannel].
        unix: UnixFarChannel
    },
    #[cfg(feature = "dtls")]
    DTLS {
        dtls: Box<DTLSFarChannel<CompoundFarChannel>>
    },
    IP {
        ip: CompoundFarIPChannel
    }
}

pub enum CompoundFarIPChannelAcquireState {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5SessionNegotiation<CompoundNearConnectorState,
                                             CompoundFarIPChannelAcquireState>>
    },
    UDP {
        udp: SocketAddr
    },
}

pub enum CompoundFarChannelAcquireState {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketPath
    },
    IP {
        ip: CompoundFarIPChannelAcquireState
    }
}

/// Multiplexer for [Acquired](FarChannel::Acquired)s for
/// [CompoundFarIPChannel].
pub enum CompoundFarIPChannelAcquired {
    UDP {
        udp: SocketAddr
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5Acquired<CompoundFarIPChannelAcquired,
                                   CompoundNearClientConn,
                                   IPEndpoint>>
    }
}

/// Multiplexer for [Acquired](FarChannel::Acquired)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelAcquired {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketPath
    },
    IP {
        ip: CompoundFarIPChannelAcquired
    }
}

/// Multiplexer for [Param](FarChannelSocket::Param)s for
/// [CompoundFarIPChannel].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CompoundFarIPChannelParam {
    UDP {
        udp: SocketAddr
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5Param<
                CompoundFarIPChannelParam,
                CompoundFarIPChannelXfrmPeerAddr
            >
        >
    }
}

/// Multiplexer for [Param](FarChannelSocket::Param)s for
/// [CompoundFarChannel].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CompoundFarChannelParam {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketPath
    },
    IP {
        ip: CompoundFarIPChannelParam
    }
}

pub enum CompoundOutboundNegotiatorParam {
    Basic,
    DTLS {
        dtls: Box<DTLSOutboundParam<CompoundOutboundNegotiatorParam>>
    }
}

/// [DatagramXfrm] instance for [CompoundFarChannel]s.
pub enum CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    #[cfg(feature = "unix")]
    Unix {
        unix: Unix
    },
    IP {
        ip: CompoundFarIPChannelXfrm<UDP>
    }
}

/// [DatagramXfrm] instance for [CompoundFarIPChannel]s.
pub enum CompoundFarIPChannelXfrm<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    UDP {
        udp: UDP
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5UDPXfrm<CompoundFarIPChannelXfrm<UDP>>>
    }
}

/// Multiplexer for [AcquireError](FarChannel::AcquireError)s for
/// [CompoundFarChannel].
#[derive(Debug)]
pub enum CompoundFarIPChannelAcquireError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5AcquireError<
                CompoundNearConnectorStartError,
                CompoundFarIPChannelAcquireError
            >
        >
    }
}

#[derive(Debug)]
pub enum CompoundFarChannelAcquireError {
    IP {
        ip: CompoundFarIPChannelAcquireError
    }
}

/// Multiplexer for [CreateError](FarChannelCreate::CreateError)s for
/// [CompoundFarChannel].
#[derive(Debug)]
pub enum CompoundFarChannelCreateError {
    IO {
        err: Error
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5CreateError<
                CompoundNearConnectorCreateError,
                CompoundFarChannelCreateError
            >
        >
    }
}

pub enum CompoundFarIPChannelAcquireNegoPending {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiatePending<
                CompoundFarIPChannelAcquired,
                CompoundFarIPChannelAcquireState,
                CompoundFarIPChannelAcquireNegoPending,
                CompoundNearClientConn,
                CompoundNearConnectorNegotiatePending
            >
        >
    }
}

pub enum CompoundFarChannelAcquireNegoPending {
    IP {
        ip: CompoundFarIPChannelAcquireNegoPending
    }
}

#[derive(Debug)]
pub enum CompoundFarIPChannelAcquireNegoError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5NegotiateError<
                CompoundFarIPChannelAcquireNegoError,
                CompoundNearConnectorNegotiateError,
            >
        >
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarChannelAcquireNegoError {
    IP {
        err: CompoundFarIPChannelAcquireNegoError
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarChannelCreateNegoError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5CreateError<
                CompoundNearConnectorCreateError,
                CompoundFarChannelCreateError
            >
        >
    }
}

#[derive(Debug)]
pub enum CompoundFarIPChannelShutdownAcquiredError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        err: Box<
            SOCKS5AcquiredShutdownError<
                crate::near::compound::CompoundNegotiatorStartError,
                CompoundFarIPChannelShutdownAcquiredError
            >
        >
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarChannelShutdownAcquiredError {
    IP {
        err: CompoundFarIPChannelShutdownAcquiredError
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarIPChannelShutdownAcquiredNegoError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        err: Box<
            SOCKS5AcquiredShutdownNegoError<
                crate::near::compound::CompoundShutdownError,
                CompoundFarIPChannelShutdownAcquiredNegoError
            >
        >
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarChannelShutdownAcquiredNegoError {
    IP {
        err: CompoundFarIPChannelShutdownAcquiredNegoError
    },
    Mismatch
}

/// Multiplexer for [Socket](FarChannelSocket::Socket)s for
/// [CompoundFarIPChannel].
pub enum CompoundFarIPChannelSocket {
    UDP { udp: UDPFarSocket }
}

/// Multiplexer for [Socket](FarChannelSocket::Socket)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelSocket {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixDatagramSocket
    },
    IP {
        ip: CompoundFarIPChannelSocket
    }
}

/// Multiplexer for [Addr](Socket::Addr)s for
/// [CompoundFarChannelSocket].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CompoundFarChannelAddr {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketPath
    },
    IP {
        ip: SocketAddr
    }
}

/// Peer addresses that can occur in [CompoundFarIPChannel]s.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub enum CompoundFarIPChannelXfrmPeerAddr {
    UDP {
        udp: SocketAddr
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: IPEndpoint
    }
}

/// Peer addresses that can occur in [CompoundFarChannel]s.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub enum CompoundFarChannelXfrmPeerAddr {
    #[cfg(feature = "unix")]
    Unix { unix: UnixSocketPath },
    IP {
        ip: CompoundFarIPChannelXfrmPeerAddr
    }
}

pub enum CompoundFarIPChannelSizeError<UDP> {
    UDP { udp: UDP },
    Mismatch
}

pub enum CompoundFarChannelSizeError<Unix, UDP> {
    Unix {
        unix: Unix
    },
    IP {
        ip: CompoundFarIPChannelSizeError<UDP>
    }
}

/// Multiplexer for [SocketError](FarChannelSocket::SocketError)s for
/// [CompoundFarIPChannel].
pub enum CompoundFarIPChannelSocketError {
    UDP {
        udp: Error
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5SocketError<CompoundFarIPChannelSocketError>>
    },
    Mismatch
}

/// Multiplexer for [SocketError](FarChannelSocket::SocketError)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelSocketError {
    #[cfg(feature = "unix")]
    Unix {
        unix: Error
    },
    IP {
        ip: CompoundFarIPChannelSocketError
    }
}

/// Multiplexer for [XfrmError](FarChannelXfrm::XfrmError)s for
/// [CompoundFarChannel].
#[derive(Debug)]
pub enum CompoundFarChannelXfrmError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5XfrmError<CompoundFarChannelXfrmError>>
    },
    Mismatch
}

/// Multiplexer for [XfrmError](FarChannelXfrm::XfrmError)s for
/// [CompoundFarChannel].
pub enum CompoundFarIPChannelXfrmWrapError<UDP> {
    UDP {
        udp: UDP
    },
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5UDPError<CompoundFarIPChannelXfrmWrapError<UDP>>>
    },
    Mismatch
}

/// Multiplexer for [XfrmError](FarChannelXfrm::XfrmError)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelXfrmWrapError<Unix, UDP> {
    Unix {
        unix: Unix
    },
    IP {
        ip: CompoundFarIPChannelXfrmWrapError<UDP>
    }
}

/// [Negotiator] instance for inbound sessions for [CompoundFarChannel]s.
pub enum CompoundInboundNegotiator {
    Basic,
    DTLS {
        dtls: Box<DTLSInboundNegotiator<
            CompoundInboundNegotiator,
        >>
    }
}

/// [Negotiator] instance for outbound sessions for [CompoundFarChannel]s.
pub enum CompoundOutboundNegotiator {
    Basic,
    DTLS {
        dtls: Box<DTLSOutboundNegotiator<
            CompoundOutboundNegotiator,
        >>
    }
}

/// [Negotiator] instance for shutting down sessions for
/// [CompoundFarChannel]s.
pub enum CompoundShutdownNegotiator<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic,
    IP {
        ip: CompoundIPShutdownNegotiator<UDP>
    },
    DTLS {
        dtls: Box<DTLSShutdownNegotiator<CompoundFlow<Unix, UDP>,
                                         CompoundShutdownNegotiator<Unix, UDP>>>
    }
}

/// [Negotiator] instance for shutting down sessions for
/// [CompoundFarChannel]s.
pub enum CompoundIPShutdownNegotiator<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic,
    DTLS {
        dtls: Box<DTLSShutdownNegotiator<CompoundIPFlow<UDP>,
                                         CompoundIPShutdownNegotiator<UDP>>>
    }
}

/// [Negotiator] instance for shutting down acquired channels for
/// [CompoundFarChannel]s.
pub enum CompoundAcquiredShutdownNegotiateState {
    Basic,
    IP {
        ip: CompoundIPAcquiredShutdownNegotiateState
    },
    SOCKS5 {
        socks5: Box<SOCKS5AcquiredShutdownState<
            CompoundNearShutdownNegotiatorState<CompoundNearClientConn>,
            CompoundAcquiredShutdownNegotiateState
        >>
    }
}

/// [Negotiator] instance for shutting down acquired channels for
/// [CompoundFarChannel]s.
pub enum CompoundIPAcquiredShutdownNegotiateState {
    Basic,
    SOCKS5 {
        socks5: Box<SOCKS5AcquiredShutdownState<
            CompoundNearShutdownNegotiatorState<CompoundNearClientConn>,
            CompoundIPAcquiredShutdownNegotiateState
        >>
    }
}

pub enum CompoundInboundNegotiatorState<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Unix {
        unix: PassthruSessionNegotiation<CompoundFlow<Unix, UDP>>
    },
    DTLS {
        dtls: Box<DTLSInboundNegotiatorState<
            CompoundInboundNegotiatorState<Unix, UDP>,
        >>
    },
    IP {
        ip: CompoundIPInboundNegotiatorState<UDP>
    }
}

pub enum CompoundIPInboundNegotiatorState<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    UDP {
        udp: PassthruSessionNegotiation<CompoundIPFlow<UDP>>
    },
    DTLS {
        dtls: Box<DTLSInboundNegotiatorState<
            CompoundIPInboundNegotiatorState<UDP>,
        >>
    }
}

pub enum CompoundOutboundNegotiatorState<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Unix {
        unix: PassthruSessionNegotiation<CompoundFlow<Unix, UDP>>
    },
    DTLS {
        dtls: Box<DTLSOutboundNegotiatorState<
            CompoundOutboundNegotiatorState<Unix, UDP>,
        >>
    },
    IP {
        ip: CompoundIPOutboundNegotiatorState<UDP>
    }
}

pub enum CompoundIPOutboundNegotiatorState<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    UDP {
        udp: PassthruSessionNegotiation<CompoundIPFlow<UDP>>
    },
    DTLS {
        dtls: Box<DTLSOutboundNegotiatorState<
            CompoundIPOutboundNegotiatorState<UDP>,
        >>
    }
}

pub enum CompoundShutdownNegotiatorState<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic,
    DTLS {
        dtls: Box<TLSShutdownNegotiatorState<
            CompoundFlow<Unix, UDP>,
            CompoundShutdownNegotiatorState<Unix, UDP>,
        >>
    },
    IP {
        ip: CompoundIPShutdownNegotiatorState<UDP>
    }
}

pub enum CompoundIPShutdownNegotiatorState<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic,
    DTLS {
        dtls: Box<TLSShutdownNegotiatorState<
            CompoundIPFlow<UDP>,
            CompoundIPShutdownNegotiatorState<UDP>,
        >>
    }
}

pub enum CompoundInboundNegotiatorPending<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<DTLSInboundNegoPending<
            CompoundFlow<Unix, UDP>,
            CompoundInboundNegotiatorPending<Unix, UDP>
        >>
    },
    IP {
        ip: CompoundIPInboundNegotiatorPending<UDP>
    }
}

pub enum CompoundIPInboundNegotiatorPending<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<DTLSInboundNegoPending<
            CompoundIPFlow<UDP>,
            CompoundIPInboundNegotiatorPending<UDP>
        >>
    }
}

pub enum CompoundOutboundNegotiatorPending<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<DTLSOutboundNegoPending<
            CompoundFlow<Unix, UDP>,
            CompoundOutboundNegotiatorPending<Unix, UDP>
        >>
    },
    IP {
        ip: CompoundIPOutboundNegotiatorPending<UDP>
    }
}

pub enum CompoundIPOutboundNegotiatorPending<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<DTLSOutboundNegoPending<
            CompoundIPFlow<UDP>,
            CompoundIPOutboundNegotiatorPending<UDP>
        >>
    }
}

pub enum CompoundShutdownNegotiatorPending<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<TLSShutdownNegoPending<
            CompoundFlow<Unix, UDP>,
            CompoundShutdownNegotiatorPending<Unix, UDP>,
        >>
    },
    IP {
        ip: CompoundIPShutdownNegotiatorPending<UDP>
    }
}

pub enum CompoundIPShutdownNegotiatorPending<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    DTLS {
        dtls: Box<TLSShutdownNegoPending<
            CompoundIPFlow<UDP>,
            CompoundIPShutdownNegotiatorPending<UDP>,
        >>
    }
}

/// [Negotiator] instance for shutting down acquired channels for
/// [CompoundFarChannel]s.
pub enum CompoundAcquiredShutdownNegotiatePending {
    Basic,
    IP {
        ip: CompoundIPAcquiredShutdownNegotiatePending
    },
    SOCKS5 {
        socks5: Box<SOCKS5AcquiredShutdownPending<
            CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>,
            CompoundAcquiredShutdownNegotiateState,
            CompoundAcquiredShutdownNegotiatePending
        >>
    }
}

/// [Negotiator] instance for shutting down acquired channels for
/// [CompoundFarChannel]s.
pub enum CompoundIPAcquiredShutdownNegotiatePending {
    Basic,
    SOCKS5 {
        socks5: Box<SOCKS5AcquiredShutdownPending<
            CompoundNearShutdownNegotiatorPending<CompoundNearClientConn>,
            CompoundIPAcquiredShutdownNegotiateState,
            CompoundIPAcquiredShutdownNegotiatePending
        >>
    }
}

#[derive(Debug)]
pub enum CompoundInboundNegoError {
    DTLS {
        dtls: Box<DTLSInboundNegoError<CompoundInboundNegoError>>
    },
}

#[derive(Debug)]
pub enum CompoundOutboundNegoError {
    DTLS {
        dtls: Box<DTLSOutboundNegoError<CompoundOutboundNegoError>>
    },
}

#[derive(Debug)]
pub enum CompoundNegotiateError {
    DTLS {
        dtls: Box<DTLSNegotiateError<CompoundNegotiateError>>
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundShutdownError {
    DTLS {
        dtls: Box<TLSShutdownError<CompoundShutdownError>>
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundNegotiatorStartError {
    DTLS {
        dtls: Box<TLSStartError<CompoundNegotiatorStartError,
                                TLSLoadConfigError>>
    },
    Mismatch
}

/// Message credentials that can be harvested from
/// [CompoundFarChannel]s.
#[derive(Clone)]
pub enum CompoundFarChannelMsgCred {
    /// Credential harvested from a [UnixFarChannel].
    Unix {
        /// Unix socket message credentials.
        unix: UCred
    },
    /// Credential harvested from a [CompoundFarIPChannel].
    IP {
        /// IP credentials.
        ///
        /// Note that UDP credentials are unsafe.
        ip: CompoundFarIPChannelMsgCred
    }
}

/// Message credentials that can be harvested from
/// [CompoundFarIPChannel]s.
#[derive(Clone)]
pub enum CompoundFarIPChannelMsgCred {
    /// Credentials harvested from a [UDPFarChannel].
    ///
    /// These are unsafe.
    UDP {
        /// Peer address.
        ///
        /// This is unsafe to use as a credential.
        unsafe_udp: SocketAddr
    }
}

/// Session credentials that can be harvested from
/// [CompoundFarChannel]s.
pub enum CompoundFarChannelSessionCred {
    /// Credential harvested from DTLS sessions.
    #[cfg(feature = "dtls")]
    DTLS {
        /// DTLS credentials.
        dtls: Box<SSLCred<CompoundFarChannelSessionCred>>
    },
    /// Credentials harvested from basic channels.
    Basic {
        /// Credentials from basic channels.
        basic: CompoundFarChannelXfrmPeerAddr
    },
    IP {
        ip: CompoundFarIPChannelSessionCred
    }
}

pub enum CompoundFarIPChannelSessionCred {
    /// Credential harvested from DTLS sessions.
    #[cfg(feature = "dtls")]
    DTLS {
        /// DTLS credentials.
        dtls: Box<SSLCred<CompoundFarIPChannelSessionCred>>
    },
    /// Credentials harvested from basic channels.
    Basic {
        /// Credentials from basic channels.
        basic: CompoundFarIPChannelXfrmPeerAddr
    }
}

/// Multiplexer for [Flow]s for [CompoundFarChannel].
pub enum CompoundIPFlow<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic {
        flow: BufferedFlow<
            CompoundFarIPChannelSocket,
            CompoundFarIPChannelXfrm<UDP>
        >
    },
    DTLS {
        flow: Box<DTLSFlow<CompoundIPFlow<UDP>>>
    }
}

pub enum CompoundFlow<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    Basic {
        flow: BufferedFlow<
            CompoundFarChannelSocket,
            CompoundFarChannelXfrm<Unix, UDP>
        >
    },
    DTLS {
        flow: Box<DTLSFlow<CompoundFlow<Unix, UDP>>>
    },
    IP {
        flow: CompoundIPFlow<UDP>
    }
}

/// Errors that can occur harvesting credentials.
pub enum CompoundFarChannelSessionCredError<Cred> {
    Basic { error: Cred }
}

pub enum CompoundOwnedIPFlowsNegotiateError {
    DTLS {
        error: Box<DTLSNegotiateError<CompoundOwnedIPFlowsNegotiateError>>
    }
}

#[derive(Debug)]
pub enum CompoundFarIPChannelAcquiredResolverError {
    SOCKS5 {
        err: SOCKS5AcquiredResolveError<AcquiredResolveStaticError>
    },
    UDP {
        err: SelectError
    },
    UDPResolve
}

#[derive(Debug)]
pub enum CompoundFarChannelAcquiredResolverError {
    IP {
        err: CompoundFarIPChannelAcquiredResolverError
    },
    UnixResolve
}

#[derive(Debug)]
pub enum CompoundFarChannelParamError<Unix, UDP> {
    Unix {
        err: Unix
    },
    IP {
        err: CompoundFarIPChannelParamError<UDP>
    },
    Mismatch
}

#[derive(Debug)]
pub enum CompoundFarIPChannelParamError<UDP> {
    UDP { err: UDP }
}

#[derive(Debug)]
pub enum CompoundFarIPChannelXfrmPeerAddrError {
    SOCKS5
}

impl<Unix, UDP> Credentials for CompoundFlow<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Cred = CompoundFarChannelSessionCred;
    type CredError = CompoundFarChannelSessionCredError<Error>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred>,
        CompoundFarChannelSessionCredError<Error>
    > {
        match self {
            CompoundFlow::DTLS { flow } => {
                let cred = flow.creds()?;

                Ok(cred.map(|cred| CompoundFarChannelSessionCred::DTLS {
                    dtls: Box::new(cred)
                }))
            }
            CompoundFlow::Basic { flow } => {
                let cred = flow.creds().map_err(|err| {
                    CompoundFarChannelSessionCredError::Basic { error: err }
                })?;

                Ok(cred.map(|cred| CompoundFarChannelSessionCred::Basic {
                    basic: cred
                }))
            }
            CompoundFlow::IP { flow } => {
                let cred = flow.creds()?;

                Ok(cred.map(|cred| CompoundFarChannelSessionCred::IP {
                    ip: cred
                }))
            }
        }
    }
}

impl<Unix, UDP> Credentials for Box<CompoundFlow<Unix, UDP>>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Cred = CompoundFarChannelSessionCred;
    type CredError = CompoundFarChannelSessionCredError<Error>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred>,
        CompoundFarChannelSessionCredError<Error>
    > {
        self.as_ref().creds()
    }
}

impl<UDP> Credentials for CompoundIPFlow<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Cred = CompoundFarIPChannelSessionCred;
    type CredError = CompoundFarChannelSessionCredError<Error>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred>,
        CompoundFarChannelSessionCredError<Error>
    > {
        match self {
            CompoundIPFlow::DTLS { flow } => {
                let cred = flow.creds()?;

                Ok(cred.map(|cred| CompoundFarIPChannelSessionCred::DTLS {
                    dtls: Box::new(cred)
                }))
            }
            CompoundIPFlow::Basic { flow } => {
                let cred = flow.creds().map_err(|err| {
                    CompoundFarChannelSessionCredError::Basic { error: err }
                })?;

                Ok(cred.map(|cred| CompoundFarIPChannelSessionCred::Basic {
                    basic: cred
                }))
            }
        }
    }
}

impl<UDP> Credentials for Box<CompoundIPFlow<UDP>>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Cred = CompoundFarIPChannelSessionCred;
    type CredError = CompoundFarChannelSessionCredError<Error>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred>,
        CompoundFarChannelSessionCredError<Error>
    > {
        self.as_ref().creds()
    }
}

impl FarChannelAcquired for CompoundFarChannelAcquired {
    type Resolved = CompoundFarChannelParam;
    type WrapError = AcquiredResolveStaticError;

    #[inline]
    fn wrap(
        &self,
        resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError> {
        match self {
            CompoundFarChannelAcquired::Unix { .. } => {
                Err(AcquiredResolveStaticError::Static)
            }
            CompoundFarChannelAcquired::IP { ip } => ip
                .wrap(resolved)
                .map(|param| CompoundFarChannelParam::IP { ip: param })
        }
    }
}

impl FarChannelAcquiredResolve for CompoundFarChannelAcquired {
    type ResolverError = CompoundFarChannelAcquiredResolverError;

    #[inline]
    fn resolver<Ctx>(
        &self,
        caches: &mut Ctx,
        addr_policy: &SocketAddrPolicy,
        resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, Self::ResolverError>
    where
        Ctx: NSNameCachesCtx {
        match self {
            CompoundFarChannelAcquired::Unix { unix } => match unix
                .resolver(caches, addr_policy, resolver)
            {
                Ok(AcquiredResolver::Resolve { .. }) => {
                    Err(CompoundFarChannelAcquiredResolverError::UnixResolve)
                }
                Ok(AcquiredResolver::StaticMulti { mut params }) => {
                    Ok(AcquiredResolver::StaticMulti {
                        params: params
                            .drain(..)
                            .map(|addr| CompoundFarChannelParam::Unix {
                                unix: addr
                            })
                            .collect()
                    })
                }
                Ok(AcquiredResolver::StaticSingle { param }) => {
                    Ok(AcquiredResolver::StaticSingle {
                        param: CompoundFarChannelParam::Unix { unix: param }
                    })
                }
            },
            CompoundFarChannelAcquired::IP { ip } => match ip
                .resolver(caches, addr_policy, resolver)
                .map_err(|err| CompoundFarChannelAcquiredResolverError::IP {
                    err: err
                })? {
                AcquiredResolver::Resolve { resolver } => {
                    Ok(AcquiredResolver::Resolve { resolver })
                }
                AcquiredResolver::StaticMulti { mut params } => {
                    Ok(AcquiredResolver::StaticMulti {
                        params: params
                            .drain(..)
                            .map(|param| CompoundFarChannelParam::IP {
                                ip: param
                            })
                            .collect()
                    })
                }
                AcquiredResolver::StaticSingle { param } => {
                    Ok(AcquiredResolver::StaticSingle {
                        param: CompoundFarChannelParam::IP { ip: param }
                    })
                }
            }
        }
    }
}

impl FarChannelAcquired for CompoundFarIPChannelAcquired {
    type Resolved = CompoundFarIPChannelParam;
    type WrapError = AcquiredResolveStaticError;

    #[inline]
    fn wrap(
        &self,
        resolved: SocketAddr
    ) -> Result<Self::Resolved, Self::WrapError> {
        match self {
            CompoundFarIPChannelAcquired::UDP { .. } => {
                Err(AcquiredResolveStaticError::Static)
            }
            CompoundFarIPChannelAcquired::SOCKS5 { socks5 } => {
                socks5.wrap(resolved).map(|param| {
                    let (param, peer) = param.take();
                    let peer = CompoundFarIPChannelXfrmPeerAddr::SOCKS5 {
                        socks5: peer
                    };
                    let param = SOCKS5Param::new(param, peer);

                    CompoundFarIPChannelParam::SOCKS5 {
                        socks5: Box::new(param)
                    }
                })
            }
        }
    }
}

impl FarChannelAcquiredResolve for CompoundFarIPChannelAcquired {
    type ResolverError = CompoundFarIPChannelAcquiredResolverError;

    #[inline]
    fn resolver<Ctx>(
        &self,
        caches: &mut Ctx,
        addr_policy: &SocketAddrPolicy,
        resolver: &ResolverConfig
    ) -> Result<AcquiredResolver<Self::Resolved>, Self::ResolverError>
    where
        Ctx: NSNameCachesCtx {
        match self {
            CompoundFarIPChannelAcquired::UDP { udp } => match udp
                .resolver(caches, addr_policy, resolver)
                .map_err(|err| {
                    CompoundFarIPChannelAcquiredResolverError::UDP { err: err }
                })? {
                AcquiredResolver::Resolve { .. } => {
                    Err(CompoundFarIPChannelAcquiredResolverError::UDPResolve)
                }
                AcquiredResolver::StaticMulti { mut params } => {
                    Ok(AcquiredResolver::StaticMulti {
                        params: params
                            .drain(..)
                            .map(|addr| CompoundFarIPChannelParam::UDP {
                                udp: addr
                            })
                            .collect()
                    })
                }
                AcquiredResolver::StaticSingle { param } => {
                    Ok(AcquiredResolver::StaticSingle {
                        param: CompoundFarIPChannelParam::UDP { udp: param }
                    })
                }
            },
            CompoundFarIPChannelAcquired::SOCKS5 { socks5 } => {
                match socks5.resolver(caches, addr_policy, resolver).map_err(
                    |err| CompoundFarIPChannelAcquiredResolverError::SOCKS5 {
                        err: err
                    }
                )? {
                    AcquiredResolver::Resolve { resolver } => {
                        Ok(AcquiredResolver::Resolve { resolver })
                    }
                    AcquiredResolver::StaticMulti { mut params } => {
                        Ok(AcquiredResolver::StaticMulti {
                            params: params
                                .drain(..)
                                .map(|param| {
                                    let (param, peer) = param.take();
                                    let peer =
                                    CompoundFarIPChannelXfrmPeerAddr::SOCKS5 {
                                        socks5: peer
                                    };
                                    let param = SOCKS5Param::new(param, peer);

                                    CompoundFarIPChannelParam::SOCKS5 {
                                        socks5: Box::new(param)
                                    }
                                })
                                .collect()
                        })
                    }
                    AcquiredResolver::StaticSingle { param } => {
                        let (param, peer) = param.take();
                        let peer = CompoundFarIPChannelXfrmPeerAddr::SOCKS5 {
                            socks5: peer
                        };
                        let param = SOCKS5Param::new(param, peer);

                        Ok(AcquiredResolver::StaticSingle {
                            param: CompoundFarIPChannelParam::SOCKS5 {
                                socks5: Box::new(param)
                            }
                        })
                    }
                }
            }
        }
    }
}

impl<Unix, UDP> From<CompoundFarIPChannelXfrm<UDP>>
    for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    #[inline]
    fn from(val: CompoundFarIPChannelXfrm<UDP>) -> Self {
        CompoundFarChannelXfrm::IP { ip: val }
    }
}

impl From<UnixSocketPath> for CompoundFarChannelXfrmPeerAddr {
    #[inline]
    fn from(val: UnixSocketPath) -> Self {
        CompoundFarChannelXfrmPeerAddr::Unix { unix: val }
    }
}

impl From<SocketAddr> for CompoundFarIPChannelXfrmPeerAddr {
    #[inline]
    fn from(val: SocketAddr) -> Self {
        CompoundFarIPChannelXfrmPeerAddr::UDP { udp: val }
    }
}

impl From<SocketAddr> for CompoundFarChannelXfrmPeerAddr {
    #[inline]
    fn from(val: SocketAddr) -> Self {
        CompoundFarChannelXfrmPeerAddr::IP {
            ip: CompoundFarIPChannelXfrmPeerAddr::from(val)
        }
    }
}

impl From<CompoundFarEndpoint> for Option<IPEndpointAddr> {
    fn from(val: CompoundFarEndpoint) -> Option<IPEndpointAddr> {
        match val {
            CompoundFarEndpoint::UDP { udp } => Some(udp.ip_addr().clone()),
            CompoundFarEndpoint::Unix { .. } => None
        }
    }
}

impl TryFrom<CompoundFarEndpoint>
    for Resolution<CompoundFarChannelXfrmPeerAddr>
{
    type Error = Error;

    fn try_from(
        val: CompoundFarEndpoint
    ) -> Result<Resolution<CompoundFarChannelXfrmPeerAddr>, Error> {
        match val {
            CompoundFarEndpoint::UDP { udp } => {
                let (udp, port) = udp.take();

                match udp {
                    IPEndpointAddr::Name(name) => Ok(Resolution::NSLookup {
                        name: name,
                        port: port
                    }),
                    IPEndpointAddr::Addr(addr) => Ok(Resolution::Static {
                        addr: CompoundFarChannelXfrmPeerAddr::from(
                            SocketAddr::new(addr, port)
                        )
                    })
                }
            }
            CompoundFarEndpoint::Unix { unix_datagram } => {
                Ok(Resolution::Static {
                    addr: CompoundFarChannelXfrmPeerAddr::Unix {
                        unix: UnixSocketPath::from(unix_datagram)
                    }
                })
            }
        }
    }
}

impl CompoundFarChannelXfrmPeerAddr {
    #[inline]
    pub fn unix(addr: UnixSocketPath) -> Self {
        CompoundFarChannelXfrmPeerAddr::Unix { unix: addr }
    }

    #[inline]
    pub fn udp(addr: SocketAddr) -> Self {
        CompoundFarChannelXfrmPeerAddr::IP {
            ip: CompoundFarIPChannelXfrmPeerAddr::udp(addr)
        }
    }

    #[inline]
    pub fn socks5(addr: IPEndpoint) -> Self {
        CompoundFarChannelXfrmPeerAddr::IP {
            ip: CompoundFarIPChannelXfrmPeerAddr::socks5(addr)
        }
    }
}

impl CompoundFarIPChannelXfrmPeerAddr {
    #[inline]
    pub fn udp(addr: SocketAddr) -> Self {
        CompoundFarIPChannelXfrmPeerAddr::UDP { udp: addr }
    }

    #[inline]
    pub fn socks5(addr: IPEndpoint) -> Self {
        CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5: addr }
    }
}

impl ChannelParam<CompoundFarChannelXfrmPeerAddr> for CompoundFarChannelParam {
    #[inline]
    fn accepts_addr(
        &self,
        addr: &CompoundFarChannelXfrmPeerAddr
    ) -> bool {
        matches!(
            (self, addr),
            (
                CompoundFarChannelParam::Unix { .. },
                CompoundFarChannelXfrmPeerAddr::Unix { .. }
            ) | (
                CompoundFarChannelParam::IP { .. },
                CompoundFarChannelXfrmPeerAddr::IP { .. }
            )
        )
    }
}

impl ChannelParam<SocketAddr> for CompoundFarChannelParam {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &SocketAddr
    ) -> bool {
        matches!(self, CompoundFarChannelParam::IP { .. })
    }
}

impl ChannelParam<UnixSocketPath> for CompoundFarChannelParam {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &UnixSocketPath
    ) -> bool {
        matches!(self, CompoundFarChannelParam::Unix { .. })
    }
}

impl<Unix, UDP> DatagramXfrm for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Error = CompoundFarChannelXfrmWrapError<Unix::Error, UDP::Error>;
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarChannelXfrmPeerAddr;
    type SizeError =
        CompoundFarChannelSizeError<Unix::SizeError, UDP::SizeError>;

    fn header_size(
        &self,
        addr: &Self::PeerAddr
    ) -> Result<usize, Self::SizeError> {
        match (self, addr) {
            (
                CompoundFarChannelXfrm::Unix { unix },
                CompoundFarChannelXfrmPeerAddr::Unix { unix: addr }
            ) => {
                let size = unix.header_size(addr).map_err(|e| {
                    CompoundFarChannelSizeError::Unix { unix: e }
                })?;

                Ok(size)
            }
            (
                CompoundFarChannelXfrm::IP { ip },
                CompoundFarChannelXfrmPeerAddr::IP { ip: addr }
            ) => {
                let size = ip
                    .header_size(addr)
                    .map_err(|e| CompoundFarChannelSizeError::IP { ip: e })?;

                Ok(size)
            }
            _ => Err(CompoundFarChannelSizeError::IP {
                ip: CompoundFarIPChannelSizeError::Mismatch
            })
        }
    }

    fn wrap(
        &mut self,
        msg: &[u8],
        addr: Self::PeerAddr
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error> {
        match (self, addr) {
            (
                CompoundFarChannelXfrm::Unix { unix },
                CompoundFarChannelXfrmPeerAddr::Unix { unix: addr }
            ) => {
                let (out, addr) = unix.wrap(msg, addr).map_err(|e| {
                    CompoundFarChannelXfrmWrapError::Unix { unix: e }
                })?;
                let addr = CompoundFarChannelAddr::Unix { unix: addr };

                Ok((out, addr))
            }
            (
                CompoundFarChannelXfrm::IP { ip },
                CompoundFarChannelXfrmPeerAddr::IP { ip: addr }
            ) => {
                let (out, addr) = ip.wrap(msg, addr).map_err(|e| {
                    CompoundFarChannelXfrmWrapError::IP { ip: e }
                })?;
                let addr = CompoundFarChannelAddr::IP { ip: addr };

                Ok((out, addr))
            }
            _ => Err(CompoundFarChannelXfrmWrapError::IP {
                ip: CompoundFarIPChannelXfrmWrapError::Mismatch
            })
        }
    }

    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: CompoundFarChannelAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        match (self, addr) {
            (
                CompoundFarChannelXfrm::Unix { unix },
                CompoundFarChannelAddr::Unix { unix: addr }
            ) => {
                let (out, addr) = unix.unwrap(buf, addr).map_err(|e| {
                    CompoundFarChannelXfrmWrapError::Unix { unix: e }
                })?;
                let addr = CompoundFarChannelXfrmPeerAddr::Unix { unix: addr };

                Ok((out, addr))
            }
            (CompoundFarChannelXfrm::IP { ip },
             CompoundFarChannelAddr::IP { ip: addr }) => {
                let (size, addr) = ip.unwrap(buf, addr).map_err(|e| {
                    CompoundFarChannelXfrmWrapError::IP { ip: e }
                })?;

                Ok((size, CompoundFarChannelXfrmPeerAddr::IP { ip: addr }))
            }
            _ => Err(CompoundFarChannelXfrmWrapError::IP {
                ip: CompoundFarIPChannelXfrmWrapError::Mismatch
            })
        }
    }
}

impl<UDP> DatagramXfrm for CompoundFarIPChannelXfrm<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Error = CompoundFarIPChannelXfrmWrapError<UDP::Error>;
    type LocalAddr = SocketAddr;
    type PeerAddr = CompoundFarIPChannelXfrmPeerAddr;
    type SizeError = CompoundFarIPChannelSizeError<UDP::SizeError>;

    fn header_size(
        &self,
        addr: &Self::PeerAddr
    ) -> Result<usize, Self::SizeError> {
        match (self, addr) {
            (
                CompoundFarIPChannelXfrm::UDP { udp },
                CompoundFarIPChannelXfrmPeerAddr::UDP { udp: addr }
            ) => {
                let size = udp.header_size(addr).map_err(|e| {
                    CompoundFarIPChannelSizeError::UDP { udp: e }
                })?;

                Ok(size)
            }
            (
                CompoundFarIPChannelXfrm::SOCKS5 { socks5: xfrm },
                CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5: addr }
            ) => {
                let size = xfrm.header_size(addr)?;

                Ok(size)
            }
            _ => Err(CompoundFarIPChannelSizeError::Mismatch)
        }
    }

    fn wrap(
        &mut self,
        msg: &[u8],
        addr: Self::PeerAddr
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error> {
        match (self, addr) {
            (
                CompoundFarIPChannelXfrm::UDP { udp },
                CompoundFarIPChannelXfrmPeerAddr::UDP { udp: addr }
            ) => {
                let (out, addr) = udp.wrap(msg, addr).map_err(|e| {
                    CompoundFarIPChannelXfrmWrapError::UDP { udp: e }
                })?;

                Ok((out, addr))
            }
            (
                CompoundFarIPChannelXfrm::SOCKS5 { socks5: xfrm },
                CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5: addr }
            ) => {
                let (out, addr) = xfrm.wrap(msg, addr).map_err(|e| {
                    CompoundFarIPChannelXfrmWrapError::SOCKS5 {
                        socks5: Box::new(e)
                    }
                })?;

                Ok((out, addr))
            }
            _ => Err(CompoundFarIPChannelXfrmWrapError::Mismatch)
        }
    }

    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: SocketAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        match (self, addr) {
            (CompoundFarIPChannelXfrm::UDP { udp }, addr) => {
                let (out, addr) = udp.unwrap(buf, addr).map_err(|e| {
                    CompoundFarIPChannelXfrmWrapError::UDP { udp: e }
                })?;
                let addr = CompoundFarIPChannelXfrmPeerAddr::UDP { udp: addr };

                Ok((out, addr))
            }
            (CompoundFarIPChannelXfrm::SOCKS5 { socks5: xfrm }, addr) => {
                let (out, addr) = xfrm.unwrap(buf, addr).map_err(|e| {
                    CompoundFarIPChannelXfrmWrapError::SOCKS5 {
                        socks5: Box::new(e)
                    }
                })?;

                Ok((
                    out,
                    CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5: addr }
                ))
            }
        }
    }
}

impl<Unix, UDP> DatagramXfrmCreateParam for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreateParam<
            Socket = UnixDatagramSocket,
            Param = UnixSocketPath
        >,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreateParam<Socket = UDPFarSocket, Param = SocketAddr>
{
    type Param = CompoundFarChannelParam;
    type ParamError =
        CompoundFarChannelParamError<Unix::ParamError, UDP::ParamError>;
    type Socket = CompoundFarChannelSocket;

    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError> {
        match (self, socket) {
            (
                CompoundFarChannelXfrm::Unix { unix: xfrm },
                CompoundFarChannelSocket::Unix { unix: socket }
            ) => {
                let param = xfrm.param(socket).map_err(|err| {
                    CompoundFarChannelParamError::Unix { err: err }
                })?;

                Ok(CompoundFarChannelParam::Unix { unix: param })
            }
            (
                CompoundFarChannelXfrm::IP { ip: xfrm },
                CompoundFarChannelSocket::IP { ip: socket }
            ) => {
                let param = xfrm.param(socket).map_err(|err| {
                    CompoundFarChannelParamError::IP { err: err }
                })?;

                Ok(CompoundFarChannelParam::IP { ip: param })
            }
            _ => Err(CompoundFarChannelParamError::Mismatch)
        }
    }
}

impl<Unix, UDP> DatagramXfrmCreate for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>
        + DatagramXfrmCreate<Addr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>
{
    type Addr = CompoundFarChannelParam;
    type CreateParam =
        CompoundXfrmCreateParam<Unix::CreateParam, UDP::CreateParam>;

    #[inline]
    fn create(
        addr: &CompoundFarChannelParam,
        param: &Self::CreateParam
    ) -> Self {
        match addr {
            CompoundFarChannelParam::Unix { unix } => {
                CompoundFarChannelXfrm::Unix {
                    unix: Unix::create(unix, param.unix())
                }
            }
            CompoundFarChannelParam::IP { ip } => CompoundFarChannelXfrm::IP {
                ip: CompoundFarIPChannelXfrm::create(ip, param.udp())
            }
        }
    }
}

impl<UDP> DatagramXfrmCreateParam for CompoundFarIPChannelXfrm<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreateParam<Socket = UDPFarSocket, Param = SocketAddr>
{
    type Param = CompoundFarIPChannelParam;
    type ParamError = CompoundFarIPChannelParamError<UDP::ParamError>;
    type Socket = CompoundFarIPChannelSocket;

    fn param(
        &self,
        socket: &Self::Socket
    ) -> Result<Self::Param, Self::ParamError> {
        match (self, socket) {
            (CompoundFarIPChannelXfrm::SOCKS5 { socks5: xfrm }, socket) => {
                let param = xfrm.param(socket)?;

                Ok(CompoundFarIPChannelParam::SOCKS5 {
                    socks5: Box::new(param)
                })
            }
            (
                CompoundFarIPChannelXfrm::UDP { udp: xfrm },
                CompoundFarIPChannelSocket::UDP { udp: socket }
            ) => {
                let param = xfrm.param(socket).map_err(|err| {
                    CompoundFarIPChannelParamError::UDP { err: err }
                })?;

                Ok(CompoundFarIPChannelParam::UDP { udp: param })
            }
        }
    }
}

impl<UDP> DatagramXfrmCreate for CompoundFarIPChannelXfrm<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
        + DatagramXfrmCreate<Addr = SocketAddr>
{
    type Addr = CompoundFarIPChannelParam;
    type CreateParam = UDP::CreateParam;

    #[inline]
    fn create(
        addr: &CompoundFarIPChannelParam,
        param: &Self::CreateParam
    ) -> Self {
        match addr {
            CompoundFarIPChannelParam::UDP { udp } => {
                CompoundFarIPChannelXfrm::UDP {
                    udp: UDP::create(udp, param)
                }
            }
            CompoundFarIPChannelParam::SOCKS5 { socks5 } => {
                CompoundFarIPChannelXfrm::create(socks5.inner(), param)
            }
        }
    }
}

impl<Unix, UDP> DatagramXfrm for Box<CompoundFarChannelXfrm<Unix, UDP>>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Error = CompoundFarChannelXfrmWrapError<Unix::Error, UDP::Error>;
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarChannelXfrmPeerAddr;
    type SizeError =
        CompoundFarChannelSizeError<Unix::SizeError, UDP::SizeError>;

    fn header_size(
        &self,
        addr: &Self::PeerAddr
    ) -> Result<usize, Self::SizeError> {
        self.as_ref().header_size(addr)
    }

    fn wrap(
        &mut self,
        msg: &[u8],
        addr: Self::PeerAddr
    ) -> Result<(Option<Vec<u8>>, Self::LocalAddr), Self::Error> {
        self.as_mut().wrap(msg, addr)
    }

    fn unwrap(
        &mut self,
        buf: &mut [u8],
        addr: Self::LocalAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        self.as_mut().unwrap(buf, addr)
    }
}

impl Sender for CompoundFarIPChannelSocket {
    #[inline]
    fn mtu(&self) -> Option<usize> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => udp.mtu()
        }
    }

    #[inline]
    fn send_to(
        &self,
        addr: &Self::Addr,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => udp.send_to(addr, buf)
        }
    }

    #[inline]
    fn send_to_vectored(
        &self,
        addr: &Self::Addr,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                udp.send_to_vectored(addr, buf)
            }
        }
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => udp.flush()
        }
    }
}

impl Sender for CompoundFarChannelSocket {
    #[inline]
    fn mtu(&self) -> Option<usize> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => unix.mtu(),
            CompoundFarChannelSocket::IP { ip } => ip.mtu()
        }
    }

    fn send_to(
        &self,
        addr: &Self::Addr,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match (self, addr) {
            (
                CompoundFarChannelSocket::Unix { unix },
                CompoundFarChannelAddr::Unix { unix: addr }
            ) => unix.send_to(addr, buf),
            (
                CompoundFarChannelSocket::IP { ip },
                CompoundFarChannelAddr::IP { ip: addr }
            ) => ip.send_to(addr, buf),
            _ => Err(Error::new(
                ErrorKind::Other,
                "socket and address type mismatch"
            ))
        }
    }

    fn send_to_vectored(
        &self,
        addr: &Self::Addr,
        bufs: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match (self, addr) {
            (
                CompoundFarChannelSocket::Unix { unix },
                CompoundFarChannelAddr::Unix { unix: addr }
            ) => unix.send_to_vectored(addr, bufs),
            (
                CompoundFarChannelSocket::IP { ip },
                CompoundFarChannelAddr::IP { ip: addr }
            ) => ip.send_to_vectored(addr, bufs),
            _ => Err(Error::new(
                ErrorKind::Other,
                "socket and address type mismatch"
            ))
        }
    }

    #[inline]
    fn flush(&self) -> Result<(), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => unix.flush(),
            CompoundFarChannelSocket::IP { ip } => ip.flush()
        }
    }
}

impl Socket for CompoundFarIPChannelSocket {
    type Addr = SocketAddr;

    #[inline]
    fn allow_session_addr_creds(&self) -> bool {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                udp.allow_session_addr_creds()
            }
        }
    }

    #[inline]
    fn local_addr(&self) -> Result<Self::Addr, Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => udp.local_addr()
        }
    }
}

impl Socket for CompoundFarChannelSocket {
    type Addr = CompoundFarChannelAddr;

    #[inline]
    fn allow_session_addr_creds(&self) -> bool {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                unix.allow_session_addr_creds()
            }
            CompoundFarChannelSocket::IP { ip } => ip.allow_session_addr_creds()
        }
    }

    #[inline]
    fn local_addr(&self) -> Result<Self::Addr, Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                let unix = unix.local_addr()?;

                Ok(CompoundFarChannelAddr::Unix { unix: unix })
            }
            CompoundFarChannelSocket::IP { ip } => {
                let ip = ip.local_addr()?;

                Ok(CompoundFarChannelAddr::IP { ip: ip })
            }
        }
    }
}

impl Receiver for CompoundFarChannelSocket {
    type MsgCred = CompoundFarChannelMsgCred;

    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                let (nbytes, addr, cred) = unix.recv_from(buf)?;
                let cred = cred
                    .map(|cred| CompoundFarChannelMsgCred::Unix { unix: cred });

                Ok((nbytes, CompoundFarChannelAddr::Unix { unix: addr }, cred))
            }
            CompoundFarChannelSocket::IP { ip } => {
                let (nbytes, addr, cred) = ip.recv_from(buf)?;
                let cred =
                    cred.map(|cred| CompoundFarChannelMsgCred::IP { ip: cred });

                Ok((nbytes, CompoundFarChannelAddr::IP { ip: addr }, cred))
            }
        }
    }

    fn recv_from_vectored(
        &self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                let (nbytes, addr, cred) = unix.recv_from_vectored(bufs)?;
                let cred = cred
                    .map(|cred| CompoundFarChannelMsgCred::Unix { unix: cred });

                Ok((nbytes, CompoundFarChannelAddr::Unix { unix: addr }, cred))
            }
            CompoundFarChannelSocket::IP { ip } => {
                let (nbytes, addr, cred) = ip.recv_from_vectored(bufs)?;
                let cred =
                    cred.map(|cred| CompoundFarChannelMsgCred::IP { ip: cred });

                Ok((nbytes, CompoundFarChannelAddr::IP { ip: addr }, cred))
            }
        }
    }
}

impl Receiver for CompoundFarIPChannelSocket {
    type MsgCred = CompoundFarIPChannelMsgCred;

    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                let (nbytes, addr, cred) = udp.recv_from(buf)?;
                let cred = cred.map(|cred| CompoundFarIPChannelMsgCred::UDP {
                    unsafe_udp: cred
                });

                Ok((nbytes, addr, cred))
            }
        }
    }

    fn recv_from_vectored(
        &self,
        bufs: &mut [IoSliceMut<'_>]
    ) -> Result<(usize, Self::Addr, Option<Self::MsgCred>), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                let (nbytes, addr, cred) = udp.recv_from_vectored(bufs)?;
                let cred = cred.map(|cred| CompoundFarIPChannelMsgCred::UDP {
                    unsafe_udp: cred
                });

                Ok((nbytes, addr, cred))
            }
        }
    }
}

impl<UDP> ScopedError for CompoundFarIPChannelXfrmWrapError<UDP>
where
    UDP: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelXfrmWrapError::UDP { udp } => udp.scope(),
            CompoundFarIPChannelXfrmWrapError::SOCKS5 { socks5 } => {
                socks5.scope()
            }
            CompoundFarIPChannelXfrmWrapError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Unix, UDP> ScopedError for CompoundFarChannelXfrmWrapError<Unix, UDP>
where
    Unix: ScopedError,
    UDP: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelXfrmWrapError::Unix { unix } => unix.scope(),
            CompoundFarChannelXfrmWrapError::IP { ip } => ip.scope()
        }
    }
}

impl ScopedError for CompoundFarIPChannelXfrmPeerAddrError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelXfrmPeerAddrError::SOCKS5 => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl<Cred> ScopedError for CompoundFarChannelSessionCredError<Cred>
where
    Cred: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelSessionCredError::Basic { error } => error.scope()
        }
    }
}

impl<Unix, UDP> ScopedError for CompoundFarChannelParamError<Unix, UDP>
where
    Unix: ScopedError,
    UDP: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelParamError::Unix { err } => err.scope(),
            CompoundFarChannelParamError::IP { err } => err.scope(),
            CompoundFarChannelParamError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl<UDP> ScopedError for CompoundFarIPChannelParamError<UDP>
where
    UDP: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelParamError::UDP { err } => err.scope()
        }
    }
}

impl ScopedError for CompoundFarIPChannelAcquireError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelAcquireError::SOCKS5 { socks5 } =>
                socks5.scope()
        }
    }
}

impl ScopedError for CompoundFarChannelAcquireError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelAcquireError::IP { ip } => ip.scope()
        }
    }
}

impl ScopedError for CompoundFarChannelCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelCreateError::IO { err } => err.scope(),
            CompoundFarChannelCreateError::SOCKS5 { socks5 } => socks5.scope()
        }
    }
}

impl ScopedError for CompoundFarIPChannelAcquireNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelAcquireNegoError::SOCKS5 { socks5 } =>
                socks5.scope(),
            CompoundFarIPChannelAcquireNegoError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundFarChannelAcquireNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelAcquireNegoError::IP { err } => err.scope(),
            CompoundFarChannelAcquireNegoError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundFarIPChannelShutdownAcquiredError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelShutdownAcquiredError::SOCKS5 { err } =>
                err.scope(),
            CompoundFarIPChannelShutdownAcquiredError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundFarChannelShutdownAcquiredError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelShutdownAcquiredError::IP { err } =>
                err.scope(),
            CompoundFarChannelShutdownAcquiredError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundFarIPChannelShutdownAcquiredNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelShutdownAcquiredNegoError::SOCKS5 { err } =>
                err.as_ref().scope(),
            CompoundFarIPChannelShutdownAcquiredNegoError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundFarChannelShutdownAcquiredNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelShutdownAcquiredNegoError::IP { err } =>
                err.scope(),
            CompoundFarChannelShutdownAcquiredNegoError::Mismatch =>
                ErrorScope::Unrecoverable
        }
    }
}

impl FarChannel for CompoundFarIPChannel {
    type AcquireError = CompoundFarIPChannelAcquireError;
    type Acquired = CompoundFarIPChannelAcquired;
    type AcquireState = CompoundFarIPChannelAcquireState;
    type NegotiateError = CompoundFarIPChannelAcquireNegoError;
    type NegotiatePending = CompoundFarIPChannelAcquireNegoPending;
    type ShutdownState = CompoundIPAcquiredShutdownNegotiateState;
    type ShutdownPending = CompoundIPAcquiredShutdownNegotiatePending;
    type ShutdownError = CompoundFarIPChannelShutdownAcquiredError;
    type ShutdownNegotiateError = CompoundFarIPChannelShutdownAcquiredNegoError;

    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::AcquireState>, Self::AcquireError> {
        match self {
            CompoundFarIPChannel::UDP { udp } => {
                let Ok(udp) = udp.acquire(registry);

                Ok(udp.map(|udp| CompoundFarIPChannelAcquireState::UDP {
                    udp: udp
                }))
            }
            CompoundFarIPChannel::DTLS { dtls } => dtls.acquire(registry),
            CompoundFarIPChannel::SOCKS5 { socks5 } => {
                let socks5 = socks5.acquire(registry).map_err(|err| {
                    CompoundFarIPChannelAcquireError::SOCKS5 {
                        socks5: Box::new(err)
                    }
                })?;

                Ok(socks5.map(|socks5|
                              CompoundFarIPChannelAcquireState::SOCKS5 {
                                  socks5: Box::new(socks5)
                              }))
            }
        }
    }

    fn negotiate(
        &self,
        state: Self::AcquireState
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundFarIPChannel::UDP { udp },
             CompoundFarIPChannelAcquireState::UDP { udp: state }) => {
                let Ok(NegotiatorResult::Complete(udp)) = udp.negotiate(state);

                Ok(NegotiatorResult::Complete(CompoundFarIPChannelAcquired::UDP { udp: udp }))
            }
            (CompoundFarIPChannel::DTLS { dtls }, state) =>
                dtls.negotiate(state),
            (CompoundFarIPChannel::SOCKS5 { socks5 },
             CompoundFarIPChannelAcquireState::SOCKS5 { socks5: state }) => {
                Ok(socks5.negotiate(*state)
                   .map_err(|err|
                            CompoundFarIPChannelAcquireNegoError::SOCKS5 {
                                socks5: Box::new(err)
                            })?
                   .map_pending(|pending|
                                CompoundFarIPChannelAcquireNegoPending::SOCKS5 {
                                    socks5: Box::new(pending)
                                })
                   .map(|socks5| CompoundFarIPChannelAcquired::SOCKS5 {
                       socks5: Box::new(socks5)
                   }))
            }
            _ => Err(CompoundFarIPChannelAcquireNegoError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match (self, pending) {
            (CompoundFarIPChannel::DTLS { dtls }, pending) =>
                dtls.complete_negotiate(pending),
            (CompoundFarIPChannel::SOCKS5 { socks5 },
             CompoundFarIPChannelAcquireNegoPending::SOCKS5 {
                 socks5: pending
             }) => {
                let socks5 = socks5.complete_negotiate(*pending)
                    .map_err(|err|
                             CompoundFarIPChannelAcquireNegoError::SOCKS5 {
                                 socks5: Box::new(err)
                             })?
                    .map_pending(|pending|
                                 CompoundFarIPChannelAcquireNegoPending::SOCKS5 {
                                     socks5: Box::new(pending)
                                 })
                    .map(|socks5| CompoundFarIPChannelAcquired::SOCKS5 {
                    socks5: Box::new(socks5)
                })
                    ;

                Ok(socks5)
            }
            _ => Err(CompoundFarIPChannelAcquireNegoError::Mismatch)
        }
    }

    fn shutdown(
        &mut self,
        acquired: Self::Acquired
    ) -> Result<Self::ShutdownState, Self::ShutdownError> {
        match (self, acquired) {
            (CompoundFarIPChannel::UDP { udp },
             CompoundFarIPChannelAcquired::UDP { udp: acquired }) => {
                let Ok(()) = udp.shutdown(acquired);

                Ok(CompoundIPAcquiredShutdownNegotiateState::Basic)
            }
            (CompoundFarIPChannel::DTLS { dtls }, acquired) => {
                dtls.shutdown(acquired)
            }
            (CompoundFarIPChannel::SOCKS5 { socks5 },
             CompoundFarIPChannelAcquired::SOCKS5 { socks5: acquired }) => {
                let state = socks5.shutdown(*acquired)
                    .map_err(|err|
                             CompoundFarIPChannelShutdownAcquiredError::SOCKS5 {
                                 err: Box::new(err)
                             })?;

                Ok(CompoundIPAcquiredShutdownNegotiateState::SOCKS5 {
                    socks5: Box::new(state)
                })
            }
            _ => Err(CompoundFarIPChannelShutdownAcquiredError::Mismatch)
        }
    }

    fn shutdown_negotiate(
        &self,
        registry: &Registry,
        state: Self::ShutdownState
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        match (self, state) {
            (CompoundFarIPChannel::UDP { .. },
             CompoundIPAcquiredShutdownNegotiateState::Basic) =>
                Ok(NegotiatorResult::Complete(())),
            (CompoundFarIPChannel::DTLS { dtls }, acquired) => {
                dtls.shutdown_negotiate(registry, acquired)
            }
            (CompoundFarIPChannel::SOCKS5 { socks5 },
             CompoundIPAcquiredShutdownNegotiateState::SOCKS5 {
                 socks5: state
             }) =>
                Ok(socks5
                   .shutdown_negotiate(registry, *state)
                   .map_err(|err| {
                       CompoundFarIPChannelShutdownAcquiredNegoError::SOCKS5 {
                           err: Box::new(err)
                       }
                   })?
                   .map_pending(|pending| {
                       CompoundIPAcquiredShutdownNegotiatePending::SOCKS5 {
                           socks5: Box::new(pending)
                       }
                   })),
            _ => Err(CompoundFarIPChannelShutdownAcquiredNegoError::Mismatch)
        }
    }

    fn complete_shutdown_negotiate(
        &self,
        registry: &Registry,
        err: Self::ShutdownPending
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        match (self, err) {
            (CompoundFarIPChannel::UDP { .. },
             CompoundIPAcquiredShutdownNegotiatePending::Basic) =>
                Ok(NegotiatorResult::Complete(())),
            (CompoundFarIPChannel::DTLS { dtls }, acquired) => {
                dtls.complete_shutdown_negotiate(registry, acquired)
            }
            (CompoundFarIPChannel::SOCKS5 { socks5 },
             CompoundIPAcquiredShutdownNegotiatePending::SOCKS5 {
                 socks5: state
             }) =>
                Ok(socks5
                   .complete_shutdown_negotiate(registry, *state)
                   .map_err(|err| {
                       CompoundFarIPChannelShutdownAcquiredNegoError::SOCKS5 {
                           err: Box::new(err)
                       }
                   })?
                   .map_pending(|pending| {
                       CompoundIPAcquiredShutdownNegotiatePending::SOCKS5 {
                           socks5: Box::new(pending)
                       }
                   })),
            _ => Err(CompoundFarIPChannelShutdownAcquiredNegoError::Mismatch)
        }
    }

    #[cfg(feature = "socks5")]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        match (self, val) {
            (
                CompoundFarIPChannel::UDP { udp },
                CompoundFarIPChannelAcquired::UDP { udp: val }
            ) => udp.socks5_target(val),
            (CompoundFarIPChannel::DTLS { dtls }, val) => {
                dtls.socks5_target(val)
            }
            (
                CompoundFarIPChannel::SOCKS5 { socks5 },
                CompoundFarIPChannelAcquired::SOCKS5 { socks5: val }
            ) => socks5.socks5_target(val),
            _ => Err(Error::new(
                ErrorKind::Other,
                "socket and address type mismatch"
            ))
        }
    }
}

impl Source for CompoundFarIPChannelSocket {
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } =>
                udp.register(registry, token, interests),
        }
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } =>
                udp.reregister(registry, token, interests),
        }
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } =>
                udp.deregister(registry),
        }
    }
}

impl FarChannelSocket for CompoundFarIPChannel {
    type Param = CompoundFarIPChannelParam;
    type Socket = CompoundFarIPChannelSocket;
    type SocketError = CompoundFarIPChannelSocketError;

    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        match (self, param) {
            (
                CompoundFarIPChannel::UDP { udp },
                CompoundFarIPChannelParam::UDP { udp: param }
            ) => {
                let udp = udp.socket(param).map_err(|e| {
                    CompoundFarIPChannelSocketError::UDP { udp: e }
                })?;

                Ok(CompoundFarIPChannelSocket::UDP { udp: udp })
            }
            (CompoundFarIPChannel::DTLS { dtls }, param) => dtls.socket(param),
            (
                CompoundFarIPChannel::SOCKS5 { socks5 },
                CompoundFarIPChannelParam::SOCKS5 { socks5: param }
            ) => socks5.socket(param.as_ref()).map_err(|e| {
                CompoundFarIPChannelSocketError::SOCKS5 {
                    socks5: Box::new(e)
                }
            }),
            _ => Err(CompoundFarIPChannelSocketError::Mismatch)
        }
    }
}

impl FarChannelCreate for CompoundFarIPChannel {
    type Config = CompoundFarIPChannelConfig;
    type CreateError = CompoundFarChannelCreateError;

    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        match config {
            CompoundFarIPChannelConfig::UDP { udp } => {
                let Ok(udp) = UDPFarChannel::create(caches, tokens, udp);

                Ok(CompoundFarIPChannel::UDP { udp: udp })
            }
            CompoundFarIPChannelConfig::DTLS { dtls } => {
                let dtls = DTLSFarChannel::create(caches, tokens, *dtls)?;

                Ok(CompoundFarIPChannel::DTLS { dtls: Box::new(dtls) })
            }
            CompoundFarIPChannelConfig::SOCKS5 { socks5_udp } => {
                let socks5 =
                    SOCKS5FarChannel::create(caches, tokens, *socks5_udp)
                    .map_err(|err| CompoundFarChannelCreateError::SOCKS5 {
                        socks5: Box::new(err)
                    })?;

                Ok(CompoundFarIPChannel::SOCKS5 { socks5: Box::new(socks5) })
            }
        }
    }
}

impl FarChannel for CompoundFarChannel {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarChannelAcquired;
    type AcquireState = CompoundFarChannelAcquireState;
    type NegotiateError = CompoundFarChannelAcquireNegoError;
    type NegotiatePending = CompoundFarChannelAcquireNegoPending;
    type ShutdownState = CompoundAcquiredShutdownNegotiateState;
    type ShutdownPending = CompoundAcquiredShutdownNegotiatePending;
    type ShutdownError = CompoundFarChannelShutdownAcquiredError;
    type ShutdownNegotiateError = CompoundFarChannelShutdownAcquiredNegoError;

    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::AcquireState>, Self::AcquireError> {
        match self {
            CompoundFarChannel::Unix { unix } => {
                let Ok(unix) = unix.acquire(registry);

                Ok(unix.map(|unix| CompoundFarChannelAcquireState::Unix {
                    unix: unix
                }))
            }
            CompoundFarChannel::DTLS { dtls } => dtls.acquire(registry),
            CompoundFarChannel::IP { ip } => {
                Ok(ip.acquire(registry)
                    .map_err(|err| CompoundFarChannelAcquireError::IP {
                        ip: err
                    })?
                    .map(|ip| CompoundFarChannelAcquireState::IP { ip: ip }))
            }
        }
    }

    fn negotiate(
        &self,
        state: Self::AcquireState
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundFarChannel::Unix { unix },
             CompoundFarChannelAcquireState::Unix { unix: state }) => {
                let Ok(NegotiatorResult::Complete(unix)) =
                    unix.negotiate(state);

                Ok(NegotiatorResult::Complete(CompoundFarChannelAcquired::Unix {
                    unix: unix
                }))
            }
            (CompoundFarChannel::DTLS { dtls }, state) =>
                dtls.negotiate(state),
            (CompoundFarChannel::IP { ip },
             CompoundFarChannelAcquireState::IP { ip: state }) => {
                Ok(ip.negotiate(state)
                   .map_err(|err| {
                       CompoundFarChannelAcquireNegoError::IP {
                           err: err
                       }
                   })?
                   .map_pending(|pending|
                                 CompoundFarChannelAcquireNegoPending::IP {
                                     ip: pending
                                 })
                   .map(|ip| CompoundFarChannelAcquired::IP { ip: ip }))
            }
            _ => Err(CompoundFarChannelAcquireNegoError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        match (self, pending) {
            (CompoundFarChannel::DTLS { dtls }, pending) =>
                dtls.complete_negotiate(pending),
            (CompoundFarChannel::IP { ip },
             CompoundFarChannelAcquireNegoPending::IP { ip: pending }) => {
                Ok(ip.complete_negotiate(pending)
                   .map_err(|err| {
                       CompoundFarChannelAcquireNegoError::IP {
                           err: err
                       }
                   })?
                   .map_pending(|pending|
                                 CompoundFarChannelAcquireNegoPending::IP {
                                     ip: pending
                                 })
                   .map(|ip| CompoundFarChannelAcquired::IP { ip: ip }))
            }
            _ => Err(CompoundFarChannelAcquireNegoError::Mismatch)
        }
    }

    fn shutdown(
        &mut self,
        acquired: Self::Acquired
    ) -> Result<Self::ShutdownState, Self::ShutdownError> {
        match (self, acquired) {
            (CompoundFarChannel::Unix { unix },
             CompoundFarChannelAcquired::Unix { unix: acquired }) => {
                let Ok(()) = unix.shutdown(acquired);

                Ok(CompoundAcquiredShutdownNegotiateState::Basic)
            }
            (CompoundFarChannel::IP { ip },
             CompoundFarChannelAcquired::IP { ip: acquired }) => ip
                .shutdown(acquired)
                .map_err(|err| CompoundFarChannelShutdownAcquiredError::IP {
                    err: err
                })
                .map(|state| {
                    CompoundAcquiredShutdownNegotiateState::IP {
                           ip: state
                       }
                }),
            (CompoundFarChannel::DTLS { dtls }, acquired) => {
                dtls.shutdown(acquired)
            }
            _ => Err(CompoundFarChannelShutdownAcquiredError::Mismatch)
        }
    }

    fn shutdown_negotiate(
        &self,
        registry: &Registry,
        state: Self::ShutdownState
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        match (self, state) {
            (CompoundFarChannel::Unix { .. },
             CompoundAcquiredShutdownNegotiateState::Basic) =>
                Ok(NegotiatorResult::Complete(())),
            (CompoundFarChannel::DTLS { dtls }, acquired) => {
                dtls.shutdown_negotiate(registry, acquired)
            }
            (CompoundFarChannel::IP { ip },
             CompoundAcquiredShutdownNegotiateState::IP { ip: state }) =>
                Ok(ip
                   .shutdown_negotiate(registry, state)
                   .map_err(|err| {
                       CompoundFarChannelShutdownAcquiredNegoError::IP {
                           err: err
                       }
                   })?
                   .map_pending(|pending| {
                       CompoundAcquiredShutdownNegotiatePending::IP {
                           ip: pending
                       }
                   })),
            _ => Err(CompoundFarChannelShutdownAcquiredNegoError::Mismatch)
        }
    }

    fn complete_shutdown_negotiate(
        &self,
        registry: &Registry,
        err: Self::ShutdownPending
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        match (self, err) {
            (CompoundFarChannel::Unix { .. },
             CompoundAcquiredShutdownNegotiatePending::Basic) =>
                Ok(NegotiatorResult::Complete(())),
            (CompoundFarChannel::DTLS { dtls }, acquired) => {
                dtls.complete_shutdown_negotiate(registry, acquired)
            }
            (CompoundFarChannel::IP { ip },
             CompoundAcquiredShutdownNegotiatePending::IP { ip: pending }) =>
                Ok(ip
                   .complete_shutdown_negotiate(registry, pending)
                   .map_err(|err| {
                       CompoundFarChannelShutdownAcquiredNegoError::IP {
                           err: err
                       }
                   })?
                   .map_pending(|pending| {
                       CompoundAcquiredShutdownNegotiatePending::IP {
                           ip: pending
                       }
                   })),
            _ => Err(CompoundFarChannelShutdownAcquiredNegoError::Mismatch)
        }
    }

    #[cfg(feature = "socks5")]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        match (self, val) {
            (
                CompoundFarChannel::Unix { unix },
                CompoundFarChannelAcquired::Unix { unix: val }
            ) => unix.socks5_target(val),
            (
                CompoundFarChannel::IP { ip },
                CompoundFarChannelAcquired::IP { ip: val }
            ) => ip.socks5_target(val),
            (CompoundFarChannel::DTLS { dtls }, val) => dtls.socks5_target(val),
            _ => Err(Error::new(
                ErrorKind::Other,
                "socket and address type mismatch"
            ))
        }
    }
}

impl Source for CompoundFarChannelSocket {
    #[inline]
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } =>
                unix.register(registry, token, interests),
            CompoundFarChannelSocket::IP { ip } =>
                ip.register(registry, token, interests),
        }
    }

    #[inline]
    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest
    ) -> Result<(), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } =>
                unix.reregister(registry, token, interests),
            CompoundFarChannelSocket::IP { ip } =>
                ip.reregister(registry, token, interests),
        }
    }

    #[inline]
    fn deregister(
        &mut self,
        registry: &Registry
    ) -> Result<(), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } =>
                unix.deregister(registry),
            CompoundFarChannelSocket::IP { ip } =>
                ip.deregister(registry),
        }
    }
}

impl FarChannelSocket for CompoundFarChannel {
    type Param = CompoundFarChannelParam;
    type Socket = CompoundFarChannelSocket;
    type SocketError = CompoundFarChannelSocketError;

    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        match (self, param) {
            (
                CompoundFarChannel::Unix { unix },
                CompoundFarChannelParam::Unix { unix: param }
            ) => {
                let unix = unix.socket(param).map_err(|e| {
                    CompoundFarChannelSocketError::Unix { unix: e }
                })?;

                Ok(CompoundFarChannelSocket::Unix { unix: unix })
            }
            (CompoundFarChannel::DTLS { dtls }, param) => dtls.socket(param),
            (
                CompoundFarChannel::IP { ip },
                CompoundFarChannelParam::IP { ip: param }
            ) => {
                let ip = ip
                    .socket(param)
                    .map_err(|e| CompoundFarChannelSocketError::IP { ip: e })?;

                Ok(CompoundFarChannelSocket::IP { ip: ip })
            }
            _ => Err(CompoundFarChannelSocketError::IP {
                ip: CompoundFarIPChannelSocketError::Mismatch
            })
        }
    }
}

impl FarChannelCreate for CompoundFarChannel {
    type Config = CompoundFarChannelConfig;
    type CreateError = CompoundFarChannelCreateError;

    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        match config {
            CompoundFarChannelConfig::Unix { unix_datagram } => {
                let unix = UnixFarChannel::create(caches, tokens, unix_datagram)
                    .map_err(|err| CompoundFarChannelCreateError::IO {
                        err: err
                    })?;

                Ok(CompoundFarChannel::Unix { unix: unix })
            }
            CompoundFarChannelConfig::UDP { udp } => {
                let Ok(udp) = UDPFarChannel::create(caches, tokens, udp);

                Ok(CompoundFarChannel::IP {
                    ip: CompoundFarIPChannel::UDP { udp: udp }
                })
            }
            CompoundFarChannelConfig::DTLS { dtls } => {
                let dtls = DTLSFarChannel::create(caches, tokens, *dtls)?;

                Ok(CompoundFarChannel::DTLS { dtls: Box::new(dtls) })
            }
            CompoundFarChannelConfig::SOCKS5 { socks5_udp } => {
                let socks5 =
                    SOCKS5FarChannel::create(caches, tokens, *socks5_udp)
                    .map_err(|err| CompoundFarChannelCreateError::SOCKS5 {
                        socks5: Box::new(err)
                    })?;

                Ok(CompoundFarChannel::IP {
                    ip: CompoundFarIPChannel::SOCKS5 {
                        socks5: Box::new(socks5)
                    }
                })
            }
        }
    }
}

impl FarChannel for Box<CompoundFarIPChannel> {
    type AcquireError = CompoundFarIPChannelAcquireError;
    type Acquired = CompoundFarIPChannelAcquired;
    type AcquireState = CompoundFarIPChannelAcquireState;
    type NegotiateError = CompoundFarIPChannelAcquireNegoError;
    type NegotiatePending = CompoundFarIPChannelAcquireNegoPending;
    type ShutdownState = CompoundIPAcquiredShutdownNegotiateState;
    type ShutdownPending = CompoundIPAcquiredShutdownNegotiatePending;
    type ShutdownError = CompoundFarIPChannelShutdownAcquiredError;
    type ShutdownNegotiateError = CompoundFarIPChannelShutdownAcquiredNegoError;

    #[inline]
    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::AcquireState>, Self::AcquireError> {
        self.as_mut().acquire(registry)
    }

    #[inline]
    fn negotiate(
        &self,
        state: Self::AcquireState
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }

    #[inline]
    fn shutdown(
        &mut self,
        acquired: Self::Acquired
    ) -> Result<Self::ShutdownState, Self::ShutdownError> {
        self.as_mut().shutdown(acquired)
    }

    #[inline]
    fn shutdown_negotiate(
        &self,
        registry: &Registry,
        state: Self::ShutdownState
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        self.as_ref().shutdown_negotiate(registry, state)
    }

    #[inline]
    fn complete_shutdown_negotiate(
        &self,
        registry: &Registry,
        err: Self::ShutdownPending
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        self.as_ref().complete_shutdown_negotiate(registry, err)
    }

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.as_ref().socks5_target(val)
    }
}

impl FarChannelSocket for Box<CompoundFarIPChannel> {
    type Param = CompoundFarIPChannelParam;
    type Socket = CompoundFarIPChannelSocket;
    type SocketError = CompoundFarIPChannelSocketError;

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.as_ref().socket(param)
    }
}

impl FarChannelCreate for Box<CompoundFarIPChannel> {
    type Config = Box<CompoundFarIPChannelConfig>;
    type CreateError = CompoundFarChannelCreateError;

    #[inline]
    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        CompoundFarIPChannel::create(caches, tokens, config.as_ref().clone())
            .map(Box::new)
    }
}

impl FarChannel for Box<CompoundFarChannel> {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarChannelAcquired;
    type AcquireState = CompoundFarChannelAcquireState;
    type NegotiateError = CompoundFarChannelAcquireNegoError;
    type NegotiatePending = CompoundFarChannelAcquireNegoPending;
    type ShutdownState = CompoundAcquiredShutdownNegotiateState;
    type ShutdownPending = CompoundAcquiredShutdownNegotiatePending;
    type ShutdownError = CompoundFarChannelShutdownAcquiredError;
    type ShutdownNegotiateError = CompoundFarChannelShutdownAcquiredNegoError;

    #[inline]
    fn acquire(
        &mut self,
        registry: &Registry
    ) -> Result<RetryResult<Self::AcquireState>, Self::AcquireError> {
        self.as_mut().acquire(registry)
    }

    #[inline]
    fn negotiate(
        &self,
        state: Self::AcquireState
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: Self::NegotiatePending
    ) -> Result<NegotiatorResult<Self::Acquired, Self::NegotiatePending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }

    #[inline]
    fn shutdown(
        &mut self,
        acquired: Self::Acquired
    ) -> Result<Self::ShutdownState, Self::ShutdownError> {
        self.as_mut().shutdown(acquired)
    }

    #[inline]
    fn shutdown_negotiate(
        &self,
        registry: &Registry,
        state: Self::ShutdownState
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        self.as_ref().shutdown_negotiate(registry, state)
    }

    #[inline]
    fn complete_shutdown_negotiate(
        &self,
        registry: &Registry,
        err: Self::ShutdownPending
    ) -> Result<NegotiatorResult<(), Self::ShutdownPending>,
                Self::ShutdownNegotiateError> {
        self.as_ref().complete_shutdown_negotiate(registry, err)
    }

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.as_ref().socks5_target(val)
    }
}

impl FarChannelSocket for Box<CompoundFarChannel> {
    type Param = CompoundFarChannelParam;
    type Socket = CompoundFarChannelSocket;
    type SocketError = CompoundFarChannelSocketError;

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.as_ref().socket(param)
    }
}

impl FarChannelCreate for Box<CompoundFarChannel> {
    type Config = Box<CompoundFarChannelConfig>;
    type CreateError = CompoundFarChannelCreateError;

    #[inline]
    fn create<Ctx, I>(
        caches: &mut Ctx,
        tokens: &mut I,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx,
        I: Iterator<Item = Token> {
        CompoundFarChannel::create(caches, tokens, config.as_ref().clone())
            .map(Box::new)
    }
}

impl<Unix, UDP> FarChannelXfrm<CompoundFarChannelXfrm<Unix, UDP>,
                               CompoundFarChannelXfrm<Unix, UDP>>
    for CompoundFarChannel
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type XfrmError = CompoundFarChannelXfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<CompoundFarChannelXfrm<Unix, UDP>, Self::XfrmError> {
        match (self, param, xfrm) {
            (
                CompoundFarChannel::Unix { unix },
                CompoundFarChannelParam::Unix { unix: param },
                xfrm
            ) => {
                let Ok(xfrm) = <UnixFarChannel as FarChannelXfrm<
                    CompoundFarChannelXfrm<Unix, UDP>,
                    CompoundFarChannelXfrm<Unix, UDP>
                >>::wrap_xfrm(unix, param, xfrm);

                Ok(xfrm)
            }
            (CompoundFarChannel::DTLS { dtls }, param, xfrm) => {
                <DTLSFarChannel<CompoundFarChannel> as FarChannelXfrm<
                    CompoundFarChannelXfrm<Unix, UDP>,
                    CompoundFarChannelXfrm<Unix, UDP>
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            (
                CompoundFarChannel::IP { ip },
                CompoundFarChannelParam::IP { ip: param },
                CompoundFarChannelXfrm::IP { ip: xfrm }
            ) => {
                let xfrm = <CompoundFarIPChannel as FarChannelXfrm<
                    CompoundFarIPChannelXfrm<UDP>,
                    CompoundFarIPChannelXfrm<UDP>
                >>::wrap_xfrm(ip, param, xfrm)?;

                Ok(CompoundFarChannelXfrm::IP { ip: xfrm })
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch)
        }
    }
}

impl<Unix, UDP> FarChannelXfrm<CompoundFarChannelXfrm<Unix, UDP>,
                               CompoundFarChannelXfrm<Unix, UDP>>
    for Box<CompoundFarChannel>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type XfrmError = CompoundFarChannelXfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<CompoundFarChannelXfrm<Unix, UDP>, Self::XfrmError> {
        let out = <CompoundFarChannel as FarChannelXfrm<
            CompoundFarChannelXfrm<Unix, UDP>,
            CompoundFarChannelXfrm<Unix, UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<UDP> FarChannelXfrm<CompoundFarIPChannelXfrm<UDP>,
                         CompoundFarIPChannelXfrm<UDP>>
    for CompoundFarIPChannel
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type XfrmError = CompoundFarChannelXfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<CompoundFarIPChannelXfrm<UDP>, Self::XfrmError> {
        match (self, param) {
            (
                CompoundFarIPChannel::UDP { udp },
                CompoundFarIPChannelParam::UDP { udp: param }
            ) => {
                let Ok(xfrm) = <UDPFarChannel as FarChannelXfrm<
                    CompoundFarIPChannelXfrm<UDP>,
                    CompoundFarIPChannelXfrm<UDP>
                >>::wrap_xfrm(udp, param, xfrm);

                Ok(xfrm)
            }
            (
                CompoundFarIPChannel::SOCKS5 { socks5 },
                CompoundFarIPChannelParam::SOCKS5 { socks5: param }
            ) => <SOCKS5FarChannel<
                   CompoundResolvingNearConnector<TLSPeerConfig>,
                   CompoundFarIPChannelXfrmPeerAddr,
                   CompoundFarIPChannel
                > as FarChannelXfrm<CompoundFarIPChannelXfrm<UDP>,
                                    CompoundFarIPChannelXfrm<UDP>>>::wrap_xfrm(
                socks5, *param, xfrm
            )
            .map_err(|e| CompoundFarChannelXfrmError::SOCKS5 {
                socks5: Box::new(e)
            }),
            (CompoundFarIPChannel::DTLS { dtls }, param) => {
                <DTLSFarChannel<CompoundFarIPChannel> as FarChannelXfrm<
                    CompoundFarIPChannelXfrm<UDP>,
                    CompoundFarIPChannelXfrm<UDP>
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch)
        }
    }
}

impl<UDP> FarChannelXfrm<CompoundFarIPChannelXfrm<UDP>,
                         CompoundFarIPChannelXfrm<UDP>>
    for Box<CompoundFarIPChannel>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type XfrmError = CompoundFarChannelXfrmError;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<CompoundFarIPChannelXfrm<UDP>, Self::XfrmError> {
        let out = <CompoundFarIPChannel as FarChannelXfrm<
            CompoundFarIPChannelXfrm<UDP>,
            CompoundFarIPChannelXfrm<UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<Unix, UDP> Negotiator<CompoundFlow<Unix, UDP>>
    for CompoundInboundNegotiator
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundInboundNegotiatorState<Unix, UDP>;
    type Pending = CompoundInboundNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundNegotiateError;

    fn negotiate(
        &self,
        state: CompoundInboundNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundInboundNegotiator::Basic,
             CompoundInboundNegotiatorState::Unix { unix }) => {
                let Ok(NegotiatorResult::Complete(out)) =
                    PassthruNegotiator.negotiate(unix);

                Ok(NegotiatorResult::Complete(out))
            },
            (nego, CompoundInboundNegotiatorState::IP { ip: state }) => {
                Ok(nego.negotiate(state)?
                   .map_pending(|pending|
                                CompoundInboundNegotiatorPending::IP {
                                    ip: pending
                                })
                   .map(|ip| CompoundFlow::IP { flow: ip }))
            }
            (CompoundInboundNegotiator::DTLS { dtls },
             CompoundInboundNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundInboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundInboundNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, pending) {
            (nego, CompoundInboundNegotiatorPending::IP { ip: pending }) => {
                Ok(nego.complete_negotiate(pending)?
                   .map_pending(|pending|
                                CompoundInboundNegotiatorPending::IP {
                                    ip: pending
                                })
                   .map(|ip| CompoundFlow::IP { flow: ip }))
            }
            (CompoundInboundNegotiator::DTLS { dtls },
             CompoundInboundNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundInboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }
}

impl<Unix, UDP> NegotiatorStart<CompoundFlow<Unix, UDP>,
                                BufferedFlow<CompoundFarChannelSocket,
                                             CompoundFarChannelXfrm<Unix, UDP>>>
    for CompoundInboundNegotiator
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarChannelSocket,
                             CompoundFarChannelXfrm<Unix, UDP>>
    ) -> Result<Self::State, Self::StartError> {
        match self {
            CompoundInboundNegotiator::Basic => {
                let flow = CompoundFlow::Basic { flow: stream };
                let Ok(state) = PassthruNegotiator.start(param, flow);

                Ok(CompoundInboundNegotiatorState::Unix { unix: state })
            },
            CompoundInboundNegotiator::DTLS { dtls } => {
                let state = dtls.start(param, stream)
                    .map_err(|err| CompoundNegotiatorStartError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundInboundNegotiatorState::DTLS {
                    dtls: Box::new(state)
                })
            }
        }
    }
}

impl<Unix, UDP> Negotiator<CompoundFlow<Unix, UDP>>
    for Box<CompoundInboundNegotiator>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundInboundNegotiatorState<Unix, UDP>;
    type Pending = CompoundInboundNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: CompoundInboundNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: CompoundInboundNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<Unix, UDP> NegotiatorStart<CompoundFlow<Unix, UDP>,
                                BufferedFlow<CompoundFarChannelSocket,
                                             CompoundFarChannelXfrm<Unix, UDP>>>
    for Box<CompoundInboundNegotiator>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarChannelSocket,
                             CompoundFarChannelXfrm<Unix, UDP>>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<Unix, UDP> Negotiator<CompoundFlow<Unix, UDP>>
    for CompoundOutboundNegotiator
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundOutboundNegotiatorState<Unix, UDP>;
    type Pending = CompoundOutboundNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundNegotiateError;

    fn negotiate(
        &self,
        state: CompoundOutboundNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundOutboundNegotiator::Basic,
             CompoundOutboundNegotiatorState::Unix { unix }) => {
                let Ok(NegotiatorResult::Complete(out)) =
                    PassthruNegotiator.negotiate(unix);

                Ok(NegotiatorResult::Complete(out))
            },
            (nego, CompoundOutboundNegotiatorState::IP { ip: state }) => {
                Ok(nego.negotiate(state)?
                   .map_pending(|pending|
                                CompoundOutboundNegotiatorPending::IP {
                                    ip: pending
                                })
                   .map(|ip| CompoundFlow::IP { flow: ip }))
            }
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundOutboundNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundOutboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundOutboundNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, pending) {
            (nego, CompoundOutboundNegotiatorPending::IP { ip: pending }) => {
                Ok(nego.complete_negotiate(pending)?
                   .map_pending(|pending|
                                CompoundOutboundNegotiatorPending::IP {
                                    ip: pending
                                })
                   .map(|ip| CompoundFlow::IP { flow: ip }))
            }
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundOutboundNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundOutboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }
}

impl<Unix, UDP> NegotiatorStart<CompoundFlow<Unix, UDP>,
                                BufferedFlow<CompoundFarChannelSocket,
                                             CompoundFarChannelXfrm<Unix, UDP>>>
    for CompoundOutboundNegotiator
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = CompoundOutboundNegotiatorParam;
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarChannelSocket,
                             CompoundFarChannelXfrm<Unix, UDP>>
    ) -> Result<Self::State, Self::StartError> {
        match (self, param) {
            (CompoundOutboundNegotiator::Basic,
             CompoundOutboundNegotiatorParam::Basic)=> {
                let flow = CompoundFlow::Basic { flow: stream };
                let Ok(state) = PassthruNegotiator.start(&(), flow);

                Ok(CompoundOutboundNegotiatorState::Unix { unix: state })
            },
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundOutboundNegotiatorParam::DTLS { dtls: param })=> {
                let state = dtls.start(param, stream)
                    .map_err(|err| CompoundNegotiatorStartError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundOutboundNegotiatorState::DTLS {
                    dtls: Box::new(state)
                })
            }
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl<Unix, UDP> Negotiator<CompoundFlow<Unix, UDP>>
    for Box<CompoundOutboundNegotiator>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundOutboundNegotiatorState<Unix, UDP>;
    type Pending = CompoundOutboundNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: CompoundOutboundNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: CompoundOutboundNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<CompoundFlow<Unix, UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<Unix, UDP> NegotiatorStart<CompoundFlow<Unix, UDP>,
                                BufferedFlow<CompoundFarChannelSocket,
                                             CompoundFarChannelXfrm<Unix, UDP>>>
    for Box<CompoundOutboundNegotiator>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = CompoundOutboundNegotiatorParam;
    type StartError = CompoundNegotiatorStartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarChannelSocket,
                             CompoundFarChannelXfrm<Unix, UDP>>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<Unix, UDP> Negotiator<()> for CompoundShutdownNegotiator<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundShutdownNegotiatorState<Unix, UDP>;
    type Pending = CompoundShutdownNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundShutdownError;

    fn negotiate(
        &self,
        state: CompoundShutdownNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        match (self, state) {
            (CompoundShutdownNegotiator::Basic,
             CompoundShutdownNegotiatorState::Basic) => {
                let Ok(NegotiatorResult::Complete(())) =
                    TrivialNegotiator.negotiate(());

                Ok(NegotiatorResult::Complete(()))
            },
            (CompoundShutdownNegotiator::IP { ip },
             CompoundShutdownNegotiatorState::IP { ip: state }) => {
                Ok(ip.negotiate(state)?
                   .map_pending(|pending|
                                CompoundShutdownNegotiatorPending::IP {
                                    ip: pending
                                }))
            }
            (CompoundShutdownNegotiator::DTLS { dtls },
             CompoundShutdownNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundShutdownError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundShutdownNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                }))
            }
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundShutdownNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        match (self, pending) {
            (CompoundShutdownNegotiator::IP { ip },
             CompoundShutdownNegotiatorPending::IP { ip: pending }) => {
                Ok(ip.complete_negotiate(pending)?
                   .map_pending(|pending|
                                CompoundShutdownNegotiatorPending::IP {
                                    ip: pending
                                }))
            }
            (CompoundShutdownNegotiator::DTLS { dtls },
             CompoundShutdownNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundShutdownError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundShutdownNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                }))
            }
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }
}

impl<Unix, UDP> NegotiatorStart<(), CompoundFlow<Unix, UDP>>
    for CompoundShutdownNegotiator<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundFlow<Unix, UDP>
    ) -> Result<Self::State, Self::StartError> {
        match (self, stream) {
            (CompoundShutdownNegotiator::Basic, CompoundFlow::Basic { .. }) =>
                Ok(CompoundShutdownNegotiatorState::Basic),
            (CompoundShutdownNegotiator::IP { ip },
             CompoundFlow::IP { flow }) => ip
                .start(param, flow)
                .map(|state| CompoundShutdownNegotiatorState::IP {
                    ip: state
                }),
            (CompoundShutdownNegotiator::DTLS { dtls },
             CompoundFlow::DTLS { flow }) => dtls
                .start(param, *flow)
                .map(|state| CompoundShutdownNegotiatorState::DTLS {
                    dtls: Box::new(state)
                }),
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl<Unix, UDP> Negotiator<()>
    for Box<CompoundShutdownNegotiator<Unix, UDP>>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundShutdownNegotiatorState<Unix, UDP>;
    type Pending = CompoundShutdownNegotiatorPending<Unix, UDP>;
    type NegotiateError = CompoundShutdownError;

    fn negotiate(
        &self,
        state: CompoundShutdownNegotiatorState<Unix, UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    fn complete_negotiate(
        &self,
        pending: CompoundShutdownNegotiatorPending<Unix, UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<Unix, UDP> NegotiatorStart<(), CompoundFlow<Unix, UDP>>
    for Box<CompoundShutdownNegotiator<Unix, UDP>>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundFlow<Unix, UDP>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<UDP> Negotiator<CompoundIPFlow<UDP>> for CompoundInboundNegotiator
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPInboundNegotiatorState<UDP>;
    type Pending = CompoundIPInboundNegotiatorPending<UDP>;
    type NegotiateError = CompoundNegotiateError;

    fn negotiate(
        &self,
        state: CompoundIPInboundNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundInboundNegotiator::Basic,
             CompoundIPInboundNegotiatorState::UDP { udp }) => {
                let Ok(NegotiatorResult::Complete(out)) =
                    PassthruNegotiator.negotiate(udp);

                Ok(NegotiatorResult::Complete(out))
            },
            (CompoundInboundNegotiator::DTLS { dtls },
             CompoundIPInboundNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPInboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundIPFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundIPInboundNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, pending) {
            (CompoundInboundNegotiator::DTLS { dtls },
             CompoundIPInboundNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPInboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundIPFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }
}

impl<UDP> NegotiatorStart<CompoundIPFlow<UDP>,
                          BufferedFlow<CompoundFarIPChannelSocket,
                                       CompoundFarIPChannelXfrm<UDP>>>
    for CompoundInboundNegotiator
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarIPChannelSocket,
                             CompoundFarIPChannelXfrm<UDP>>
    ) -> Result<Self::State, Self::StartError> {
        match self {
            CompoundInboundNegotiator::Basic => {
                let flow = CompoundIPFlow::Basic { flow: stream };
                let Ok(state) = PassthruNegotiator.start(param, flow);

                Ok(CompoundIPInboundNegotiatorState::UDP { udp: state })
            },
            CompoundInboundNegotiator::DTLS { dtls } => {
                let state = dtls.start(param, stream)
                    .map_err(|err| CompoundNegotiatorStartError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundIPInboundNegotiatorState::DTLS {
                    dtls: Box::new(state)
                })
            }
        }
    }
}

impl<UDP> Negotiator<CompoundIPFlow<UDP>> for Box<CompoundInboundNegotiator>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPInboundNegotiatorState<UDP>;
    type Pending = CompoundIPInboundNegotiatorPending<UDP>;
    type NegotiateError = CompoundNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: CompoundIPInboundNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: CompoundIPInboundNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<UDP> NegotiatorStart<CompoundIPFlow<UDP>,
                          BufferedFlow<CompoundFarIPChannelSocket,
                                       CompoundFarIPChannelXfrm<UDP>>>
    for Box<CompoundInboundNegotiator>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarIPChannelSocket,
                             CompoundFarIPChannelXfrm<UDP>>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<UDP> Negotiator<CompoundIPFlow<UDP>> for CompoundOutboundNegotiator
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPOutboundNegotiatorState<UDP>;
    type Pending = CompoundIPOutboundNegotiatorPending<UDP>;
    type NegotiateError = CompoundNegotiateError;

    fn negotiate(
        &self,
        state: CompoundIPOutboundNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, state) {
            (CompoundOutboundNegotiator::Basic,
             CompoundIPOutboundNegotiatorState::UDP { udp }) => {
                let Ok(NegotiatorResult::Complete(out)) =
                    PassthruNegotiator.negotiate(udp);

                Ok(NegotiatorResult::Complete(out))
            },
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundIPOutboundNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPOutboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundIPFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundIPOutboundNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        match (self, pending) {
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundIPOutboundNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundNegotiateError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPOutboundNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                })
                   .map(|dtls| CompoundIPFlow::DTLS { flow: Box::new(dtls) }))
            }
            _ => Err(CompoundNegotiateError::Mismatch)
        }
    }
}

impl<UDP> NegotiatorStart<CompoundIPFlow<UDP>,
                          BufferedFlow<CompoundFarIPChannelSocket,
                                       CompoundFarIPChannelXfrm<UDP>>>
    for CompoundOutboundNegotiator
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = CompoundOutboundNegotiatorParam;
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarIPChannelSocket,
                             CompoundFarIPChannelXfrm<UDP>>
    ) -> Result<Self::State, Self::StartError> {
        match (self, param) {
            (CompoundOutboundNegotiator::Basic,
             CompoundOutboundNegotiatorParam::Basic)=> {
                let flow = CompoundIPFlow::Basic { flow: stream };
                let Ok(state) = PassthruNegotiator.start(&(), flow);

                Ok(CompoundIPOutboundNegotiatorState::UDP { udp: state })
            },
            (CompoundOutboundNegotiator::DTLS { dtls },
             CompoundOutboundNegotiatorParam::DTLS { dtls: param })=> {
                let state = dtls.start(param, stream)
                    .map_err(|err| CompoundNegotiatorStartError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundIPOutboundNegotiatorState::DTLS {
                    dtls: Box::new(state)
                })
            }
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl<UDP> Negotiator<CompoundIPFlow<UDP>> for Box<CompoundOutboundNegotiator>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPOutboundNegotiatorState<UDP>;
    type Pending = CompoundIPOutboundNegotiatorPending<UDP>;
    type NegotiateError = CompoundNegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: CompoundIPOutboundNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: CompoundIPOutboundNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<CompoundIPFlow<UDP>, Self::Pending>,
                Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<UDP> NegotiatorStart<CompoundIPFlow<UDP>,
                          BufferedFlow<CompoundFarIPChannelSocket,
                                       CompoundFarIPChannelXfrm<UDP>>>
    for Box<CompoundOutboundNegotiator>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = CompoundOutboundNegotiatorParam;
    type StartError = CompoundNegotiatorStartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: BufferedFlow<CompoundFarIPChannelSocket,
                             CompoundFarIPChannelXfrm<UDP>>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<UDP> Negotiator<()> for CompoundIPShutdownNegotiator<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPShutdownNegotiatorState<UDP>;
    type Pending = CompoundIPShutdownNegotiatorPending<UDP>;
    type NegotiateError = CompoundShutdownError;

    fn negotiate(
        &self,
        state: CompoundIPShutdownNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        match (self, state) {
            (CompoundIPShutdownNegotiator::Basic,
             CompoundIPShutdownNegotiatorState::Basic) => {
                let Ok(NegotiatorResult::Complete(out)) =
                    TrivialNegotiator.negotiate(());

                Ok(NegotiatorResult::Complete(out))
            },
            (CompoundIPShutdownNegotiator::DTLS { dtls },
             CompoundIPShutdownNegotiatorState::DTLS { dtls: state }) => {
                Ok(dtls.negotiate(*state)
                   .map_err(|err| CompoundShutdownError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPShutdownNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                }))
            }
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }

    fn complete_negotiate(
        &self,
        pending: CompoundIPShutdownNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        match (self, pending) {
            (CompoundIPShutdownNegotiator::DTLS { dtls },
             CompoundIPShutdownNegotiatorPending::DTLS { dtls: pending }) => {
                Ok(dtls.complete_negotiate(*pending)
                   .map_err(|err| CompoundShutdownError::DTLS {
                       dtls: Box::new(err)
                   })?
                   .map_pending(|pending|
                                CompoundIPShutdownNegotiatorPending::DTLS {
                                    dtls: Box::new(pending)
                                }))
            }
            _ => Err(CompoundShutdownError::Mismatch)
        }
    }
}

impl<UDP> NegotiatorStart<(), CompoundIPFlow<UDP>>
    for CompoundIPShutdownNegotiator<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundIPFlow<UDP>
    ) -> Result<Self::State, Self::StartError> {
        match (self, stream) {
            (CompoundIPShutdownNegotiator::Basic,
             CompoundIPFlow::Basic { .. }) =>
                Ok(CompoundIPShutdownNegotiatorState::Basic),
            (CompoundIPShutdownNegotiator::DTLS { dtls },
             CompoundIPFlow::DTLS { flow }) => dtls
                .start(param, *flow)
                .map(|state| CompoundIPShutdownNegotiatorState::DTLS {
                    dtls: Box::new(state)
                }),
            _ => Err(CompoundNegotiatorStartError::Mismatch)
        }
    }
}

impl<UDP> Negotiator<()>
    for Box<CompoundIPShutdownNegotiator<UDP>>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type State = CompoundIPShutdownNegotiatorState<UDP>;
    type Pending = CompoundIPShutdownNegotiatorPending<UDP>;
    type NegotiateError = CompoundShutdownError;

    #[inline]
    fn negotiate(
        &self,
        state: CompoundIPShutdownNegotiatorState<UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        self.as_ref().negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: CompoundIPShutdownNegotiatorPending<UDP>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        self.as_ref().complete_negotiate(pending)
    }
}

impl<UDP> NegotiatorStart<(), CompoundIPFlow<UDP>>
    for Box<CompoundIPShutdownNegotiator<UDP>>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type Param = ();
    type StartError = CompoundNegotiatorStartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: CompoundIPFlow<UDP>
    ) -> Result<Self::State, Self::StartError> {
        self.as_ref().start(param, stream)
    }
}

impl<Unix, UDP> FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                                CompoundFarChannelXfrm<Unix, UDP>>
    for CompoundFarChannel
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Flow = CompoundFlow<Unix, UDP>;
    type OutboundNego = CompoundOutboundNegotiator;
    type InboundNego = CompoundInboundNegotiator;
    type ShutdownNego = CompoundShutdownNegotiator<Unix, UDP>;
    type OutboundNegoError = CompoundOutboundNegoError;
    type InboundNegoError = CompoundInboundNegoError;
    type ShutdownNegoError = Infallible;

    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        match self {
            CompoundFarChannel::Unix { .. } => {
                Ok(CompoundInboundNegotiator::Basic)
            }
            CompoundFarChannel::IP { ip } =>
                <CompoundFarIPChannel as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>>
                ::inbound_negotiator(ip),
            CompoundFarChannel::DTLS { dtls } => {
                let dtls = <DTLSFarChannel<CompoundFarChannel> as
                            FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                                            CompoundFarChannelXfrm<Unix, UDP>>
                            >::inbound_negotiator(dtls)
                    .map_err(|err| CompoundInboundNegoError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundInboundNegotiator::DTLS {
                    dtls: Box::new(dtls)
                })
            }
        }
    }

    fn outbound_negotiator(
        &self,
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        match self {
            CompoundFarChannel::Unix { .. } => {
                Ok(CompoundOutboundNegotiator::Basic)
            }
            CompoundFarChannel::IP { ip } =>
                <CompoundFarIPChannel as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>>
                ::outbound_negotiator(ip),
            CompoundFarChannel::DTLS { dtls } => {
                let dtls = <DTLSFarChannel<CompoundFarChannel> as
                            FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                                            CompoundFarChannelXfrm<Unix, UDP>>
                            >::outbound_negotiator(dtls)
                    .map_err(|err| CompoundOutboundNegoError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundOutboundNegotiator::DTLS {
                    dtls: Box::new(dtls)
                })
            }
        }
    }

    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        match self {
            CompoundFarChannel::Unix { .. } =>
                Ok(CompoundShutdownNegotiator::Basic),
            CompoundFarChannel::IP { ip } =>
                <CompoundFarIPChannel as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>>
                 ::shutdown_negotiator(ip)
                .map(|ip| CompoundShutdownNegotiator::IP {
                    ip: ip
                }),
            CompoundFarChannel::DTLS { dtls } =>
                <DTLSFarChannel<CompoundFarChannel> as
                 FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                                 CompoundFarChannelXfrm<Unix, UDP>>
                 >::shutdown_negotiator(dtls)
                .map(|dtls| CompoundShutdownNegotiator::DTLS {
                    dtls: Box::new(dtls)
                })
        }
    }
}

impl<Unix, UDP> FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                                CompoundFarChannelXfrm<Unix, UDP>>
    for Box<CompoundFarChannel>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Flow = CompoundFlow<Unix, UDP>;
    type OutboundNego = CompoundOutboundNegotiator;
    type InboundNego = CompoundInboundNegotiator;
    type ShutdownNego = CompoundShutdownNegotiator<Unix, UDP>;
    type OutboundNegoError = CompoundOutboundNegoError;
    type InboundNegoError = CompoundInboundNegoError;
    type ShutdownNegoError = Infallible;

    #[inline]
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        <CompoundFarChannel as
         FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                         CompoundFarChannelXfrm<Unix, UDP>>>
            ::inbound_negotiator(self.as_ref())
    }

    #[inline]
    fn outbound_negotiator(
        &self,
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        <CompoundFarChannel as
         FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                         CompoundFarChannelXfrm<Unix, UDP>>>
            ::outbound_negotiator(self.as_ref())
    }

    #[inline]
    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        <CompoundFarChannel as
         FarChannelFlows<CompoundFarChannelXfrm<Unix, UDP>,
                         CompoundFarChannelXfrm<Unix, UDP>>>
            ::shutdown_negotiator(self.as_ref())
    }
}

impl<UDP> FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                          CompoundFarIPChannelXfrm<UDP>>
    for CompoundFarIPChannel
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Flow = CompoundIPFlow<UDP>;
    type OutboundNego = CompoundOutboundNegotiator;
    type InboundNego = CompoundInboundNegotiator;
    type ShutdownNego = CompoundIPShutdownNegotiator<UDP>;
    type OutboundNegoError = CompoundOutboundNegoError;
    type InboundNegoError = CompoundInboundNegoError;
    type ShutdownNegoError = Infallible;

    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        match self {
            CompoundFarIPChannel::UDP { .. } => {
                Ok(CompoundInboundNegotiator::Basic)
            }
            CompoundFarIPChannel::SOCKS5 { socks5, .. } => {
                <SOCKS5FarChannel<CompoundResolvingNearConnector<TLSPeerConfig>,
                                  CompoundFarIPChannelXfrmPeerAddr,
                                  CompoundFarIPChannel> as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>
                 >::inbound_negotiator(socks5)
            }
            CompoundFarIPChannel::DTLS { dtls } => {
                let dtls = <DTLSFarChannel<CompoundFarIPChannel> as
                            FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                            CompoundFarIPChannelXfrm<UDP>>
                            >::inbound_negotiator(dtls)
                    .map_err(|err| CompoundInboundNegoError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundInboundNegotiator::DTLS {
                    dtls: Box::new(dtls)
                })
            }
        }
    }

    fn outbound_negotiator(
        &self,
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        match self {
            CompoundFarIPChannel::UDP { .. } => {
                Ok(CompoundOutboundNegotiator::Basic)
            }
            CompoundFarIPChannel::SOCKS5 { socks5, .. } => {
                <SOCKS5FarChannel<CompoundResolvingNearConnector<TLSPeerConfig>,
                                  CompoundFarIPChannelXfrmPeerAddr,
                                  CompoundFarIPChannel> as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>
                 >::outbound_negotiator(socks5)
            }
            CompoundFarIPChannel::DTLS { dtls } => {
                let dtls = <DTLSFarChannel<CompoundFarIPChannel> as
                            FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                            CompoundFarIPChannelXfrm<UDP>>
                            >::outbound_negotiator(dtls)
                    .map_err(|err| CompoundOutboundNegoError::DTLS {
                        dtls: Box::new(err)
                    })?;

                Ok(CompoundOutboundNegotiator::DTLS {
                    dtls: Box::new(dtls)
                })
            }
        }
    }

    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        match self {
            CompoundFarIPChannel::UDP { .. } =>
                Ok(CompoundIPShutdownNegotiator::Basic),
            CompoundFarIPChannel::SOCKS5 { socks5, .. } =>
                <SOCKS5FarChannel<CompoundResolvingNearConnector<TLSPeerConfig>,
                                  CompoundFarIPChannelXfrmPeerAddr,
                                  CompoundFarIPChannel> as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>
                 >::shutdown_negotiator(socks5),
            CompoundFarIPChannel::DTLS { dtls } =>
                <DTLSFarChannel<CompoundFarIPChannel> as
                 FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                 CompoundFarIPChannelXfrm<UDP>>
                 >::shutdown_negotiator(dtls)
                .map(|dtls| CompoundIPShutdownNegotiator::DTLS {
                    dtls: Box::new(dtls)
                }),
        }
    }
}

impl<UDP> FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                          CompoundFarIPChannelXfrm<UDP>>
    for Box<CompoundFarIPChannel>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    type Flow = CompoundIPFlow<UDP>;
    type OutboundNego = CompoundOutboundNegotiator;
    type InboundNego = CompoundInboundNegotiator;
    type ShutdownNego = CompoundIPShutdownNegotiator<UDP>;
    type OutboundNegoError = CompoundOutboundNegoError;
    type InboundNegoError = CompoundInboundNegoError;
    type ShutdownNegoError = Infallible;

    #[inline]
    fn inbound_negotiator(
        &self
    ) -> Result<Self::InboundNego, Self::InboundNegoError> {
        <CompoundFarIPChannel as FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                                 CompoundFarIPChannelXfrm<UDP>>>
            ::inbound_negotiator(self.as_ref())
    }

    #[inline]
    fn outbound_negotiator(
        &self,
    ) -> Result<Self::OutboundNego, Self::OutboundNegoError> {
        <CompoundFarIPChannel as FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                                 CompoundFarIPChannelXfrm<UDP>>>
            ::outbound_negotiator(self.as_ref())
    }

    #[inline]
    fn shutdown_negotiator(
        &self
    ) -> Result<Self::ShutdownNego, Self::ShutdownNegoError> {
        <CompoundFarIPChannel as FarChannelFlows<CompoundFarIPChannelXfrm<UDP>,
                                                 CompoundFarIPChannelXfrm<UDP>>>
            ::shutdown_negotiator(self.as_ref())
    }
}

impl<Unix, UDP> Session for CompoundFlow<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarChannelXfrmPeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.local_addr(),
            CompoundFlow::DTLS { flow } => flow.local_addr(),
            CompoundFlow::IP { flow } => flow.local_addr()
        }
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.peer_addr(),
            CompoundFlow::DTLS { flow } => flow.peer_addr(),
            CompoundFlow::IP { flow } => Ok(CompoundFarChannelXfrmPeerAddr::IP {
                ip: flow.peer_addr()?
            })

        }
    }
}

impl<Unix, UDP> Session for Box<CompoundFlow<Unix, UDP>>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarChannelXfrmPeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.as_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.as_ref().peer_addr()
    }
}

impl<Unix, UDP> Read for CompoundFlow<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read(buf),
            CompoundFlow::DTLS { flow } => flow.read(buf),
            CompoundFlow::IP { flow } => flow.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_vectored(buf),
            CompoundFlow::DTLS { flow } => flow.read_vectored(buf),
            CompoundFlow::IP { flow } => flow.read_vectored(buf)
        }
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_to_end(buf),
            CompoundFlow::DTLS { flow } => flow.read_to_end(buf),
            CompoundFlow::IP { flow } => flow.read_to_end(buf)
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_to_string(buf),
            CompoundFlow::DTLS { flow } => flow.read_to_string(buf),
            CompoundFlow::IP { flow } => flow.read_to_string(buf)
        }
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_exact(buf),
            CompoundFlow::DTLS { flow } => flow.read_exact(buf),
            CompoundFlow::IP { flow } => flow.read_exact(buf)
        }
    }
}

impl<Unix, UDP> Write for CompoundFlow<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write(buf),
            CompoundFlow::DTLS { flow } => flow.write(buf),
            CompoundFlow::IP { flow } => flow.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write_vectored(buf),
            CompoundFlow::DTLS { flow } => flow.write_vectored(buf),
            CompoundFlow::IP { flow } => flow.write_vectored(buf)

        }
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write_all(buf),
            CompoundFlow::DTLS { flow } => flow.write_all(buf),
            CompoundFlow::IP { flow } => flow.write_all(buf)

        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.flush(),
            CompoundFlow::DTLS { flow } => flow.flush(),
            CompoundFlow::IP { flow } => flow.flush()

        }
    }
}

impl<UDP> Session for CompoundIPFlow<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarIPChannelXfrmPeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => {
                let addr = flow.local_addr()?;
                let addr = CompoundFarChannelAddr::IP { ip: addr };

                Ok(addr)
            },
            CompoundIPFlow::DTLS { flow } => flow.local_addr()
        }
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.peer_addr(),
            CompoundIPFlow::DTLS { flow } => flow.peer_addr()
        }
    }
}

impl<UDP> Session for Box<CompoundIPFlow<UDP>>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    type LocalAddr = CompoundFarChannelAddr;
    type PeerAddr = CompoundFarIPChannelXfrmPeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.as_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Result<Self::PeerAddr, Error> {
        self.as_ref().peer_addr()
    }
}

impl<UDP> Read for CompoundIPFlow<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.read(buf),
            CompoundIPFlow::DTLS { flow } => flow.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.read_vectored(buf),
            CompoundIPFlow::DTLS { flow } => flow.read_vectored(buf)
        }
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.read_to_end(buf),
            CompoundIPFlow::DTLS { flow } => flow.read_to_end(buf)
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.read_to_string(buf),
            CompoundIPFlow::DTLS { flow } => flow.read_to_string(buf)
        }
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.read_exact(buf),
            CompoundIPFlow::DTLS { flow } => flow.read_exact(buf)
        }
    }
}

impl<UDP> Write for CompoundIPFlow<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr> {
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.write(buf),
            CompoundIPFlow::DTLS { flow } => flow.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.write_vectored(buf),
            CompoundIPFlow::DTLS { flow } => flow.write_vectored(buf)
        }
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.write_all(buf),
            CompoundIPFlow::DTLS { flow } => flow.write_all(buf)
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundIPFlow::Basic { flow } => flow.flush(),
            CompoundIPFlow::DTLS { flow } => flow.flush()
        }
    }
}


impl Display for CompoundFarIPChannelParam {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelParam::UDP { udp } => {
                write!(f, "udp://{}", udp)
            }
            CompoundFarIPChannelParam::SOCKS5 { socks5 } => {
                write!(f, "socks5://{}", socks5)
            }
        }
    }
}

impl Display for CompoundFarChannelParam {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelParam::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundFarChannelParam::IP { ip } => write!(f, "{}", ip)
        }
    }
}

impl Display for CompoundFarIPChannelAcquireError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelAcquireError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
        }
    }
}


impl Display for CompoundFarChannelAcquireError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelAcquireError::IP { ip } => {
                write!(f, "{}", ip)
            }
        }
    }
}

impl Display for CompoundFarChannelCreateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelCreateError::IO { err } => {
                write!(f, "{}", err)
            }
            CompoundFarChannelCreateError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
        }
    }
}

impl Display for CompoundFarChannelAcquireNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelAcquireNegoError::IP { err } =>
                write!(f, "{}", err),
            CompoundFarChannelAcquireNegoError::Mismatch =>
                write!(f, "channel and acquire state type mismatch")
        }
    }
}

impl Display for CompoundFarIPChannelAcquireNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelAcquireNegoError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarIPChannelAcquireNegoError::Mismatch =>
                write!(f, "channel and acquire state type mismatch")
        }
    }
}

impl Display for CompoundFarChannelAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelAddr::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundFarChannelAddr::IP { ip } => write!(f, "{}", ip)
        }
    }
}

impl Display for CompoundFarIPChannelXfrmPeerAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelXfrmPeerAddr::UDP { udp } => {
                write!(f, "udp://{}", udp)
            }
            CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5 } => {
                write!(f, "socks5://{}", socks5)
            }
        }
    }
}

impl Display for CompoundFarChannelXfrmPeerAddr {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelXfrmPeerAddr::Unix { unix } => {
                write!(f, "unix://{}", unix)
            }
            CompoundFarChannelXfrmPeerAddr::IP { ip } => write!(f, "{}", ip)
        }
    }
}

impl<Unix, UDP> Debug for CompoundFarChannelSizeError<Unix, UDP>
where
    Unix: Debug,
    UDP: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSizeError::Unix { unix } => unix.fmt(f),
            CompoundFarChannelSizeError::IP { ip } => ip.fmt(f)
        }
    }
}

impl<Unix, UDP> Display for CompoundFarChannelSizeError<Unix, UDP>
where
    Unix: Display,
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSizeError::Unix { unix } => unix.fmt(f),
            CompoundFarChannelSizeError::IP { ip } => ip.fmt(f)
        }
    }
}

impl<UDP> Debug for CompoundFarIPChannelSizeError<UDP>
where
    UDP: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelSizeError::UDP { udp } => udp.fmt(f),
            CompoundFarIPChannelSizeError::Mismatch => {
                write!(f, "transform and address type mismatch")
            }
        }
    }
}

impl<UDP> Display for CompoundFarIPChannelSizeError<UDP>
where
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelSizeError::UDP { udp } => udp.fmt(f),
            CompoundFarIPChannelSizeError::Mismatch => {
                write!(f, "transform and address type mismatch")
            }
        }
    }
}

impl Debug for CompoundFarIPChannelSocketError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelSocketError::UDP { udp } => {
                write!(f, "{}", udp)
            }
            CompoundFarIPChannelSocketError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarIPChannelSocketError::Mismatch => {
                write!(f, "socket and param type mismatch")
            }
        }
    }
}

impl Display for CompoundFarIPChannelSocketError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelSocketError::UDP { udp } => {
                write!(f, "{}", udp)
            }
            CompoundFarIPChannelSocketError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarIPChannelSocketError::Mismatch => {
                write!(f, "socket and param type mismatch")
            }
        }
    }
}

impl ScopedError for CompoundFarIPChannelSocketError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelSocketError::UDP { udp } => udp.scope(),
            CompoundFarIPChannelSocketError::SOCKS5 { socks5 } => {
                socks5.scope()
            }
            CompoundFarIPChannelSocketError::Mismatch => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundFarChannelSocketError {
    fn scope(&self) -> ErrorScope {
        match self {
            #[cfg(feature = "unix")]
            CompoundFarChannelSocketError::Unix { unix } => unix.scope(),
            CompoundFarChannelSocketError::IP { ip } => ip.scope()
        }
    }
}

impl Debug for CompoundFarChannelSocketError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSocketError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundFarChannelSocketError::IP { ip } => write!(f, "{}", ip)
        }
    }
}

impl Display for CompoundFarIPChannelXfrmPeerAddrError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelXfrmPeerAddrError::SOCKS5 => {
                write!(f, "cannot convert SOCKS5 address to IP address")
            }
        }
    }
}

impl Display for CompoundFarChannelSocketError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSocketError::Unix { unix } => {
                write!(f, "{}", unix)
            }
            CompoundFarChannelSocketError::IP { ip } => write!(f, "{}", ip)
        }
    }
}

impl ScopedError for CompoundFarChannelXfrmError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelXfrmError::SOCKS5 { socks5 } => socks5.scope(),
            CompoundFarChannelXfrmError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl Display for CompoundFarChannelXfrmError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelXfrmError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarChannelXfrmError::Mismatch => {
                write!(f, "channel, param, transform type mismatch")
            }
        }
    }
}

impl<Unix, UDP> Debug for CompoundFarChannelXfrmWrapError<Unix, UDP>
where
    Unix: Debug,
    UDP: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelXfrmWrapError::Unix { unix } => unix.fmt(f),
            CompoundFarChannelXfrmWrapError::IP { ip } => ip.fmt(f)
        }
    }
}

impl<Unix, UDP> Display for CompoundFarChannelXfrmWrapError<Unix, UDP>
where
    Unix: Display,
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelXfrmWrapError::Unix { unix } => unix.fmt(f),
            CompoundFarChannelXfrmWrapError::IP { ip } => ip.fmt(f)
        }
    }
}

impl<UDP> Debug for CompoundFarIPChannelXfrmWrapError<UDP>
where
    UDP: Debug
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelXfrmWrapError::UDP { udp } => udp.fmt(f),
            CompoundFarIPChannelXfrmWrapError::SOCKS5 { socks5 } => {
                write!(f, "{:?}", socks5)
            }
            CompoundFarIPChannelXfrmWrapError::Mismatch => {
                write!(f, "transform and address type mismatch")
            }
        }
    }
}

impl<UDP> Display for CompoundFarIPChannelXfrmWrapError<UDP>
where
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelXfrmWrapError::UDP { udp } => udp.fmt(f),
            CompoundFarIPChannelXfrmWrapError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarIPChannelXfrmWrapError::Mismatch => {
                write!(f, "transform and address type mismatch")
            }
        }
    }
}

impl Display for CompoundInboundNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundInboundNegoError::DTLS { dtls } => write!(f, "{}", dtls),
        }
    }
}

impl Display for CompoundOutboundNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundOutboundNegoError::DTLS { dtls } => write!(f, "{}", dtls),
        }
    }
}

impl Display for CompoundNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundNegotiateError::DTLS { dtls } => write!(f, "{}", dtls),
            CompoundNegotiateError::Mismatch =>
                write!(f, "negotiator and state type mismatch")
        }
    }
}

impl Display for CompoundShutdownError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundShutdownError::DTLS { dtls } => write!(f, "{}", dtls),
            CompoundShutdownError::Mismatch =>
                write!(f, "negotiator and state type mismatch")
        }
    }
}

impl Display for CompoundNegotiatorStartError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundNegotiatorStartError::DTLS { dtls } =>
                write!(f, "{}", dtls),
            CompoundNegotiatorStartError::Mismatch =>
                write!(f, "negotiator and param type mismatch")
        }
    }
}

impl Display for CompoundFarIPChannelAcquiredResolverError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelAcquiredResolverError::SOCKS5 { err } => {
                write!(f, "{}", err)
            }
            CompoundFarIPChannelAcquiredResolverError::UDP { err } => {
                write!(f, "{}", err)
            }
            CompoundFarIPChannelAcquiredResolverError::UDPResolve => {
                write!(f, "UDP socket should not generate resolver")
            }
        }
    }
}

impl ScopedError for CompoundInboundNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundInboundNegoError::DTLS { dtls } => dtls.scope(),
        }
    }
}

impl ScopedError for CompoundOutboundNegoError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundOutboundNegoError::DTLS { dtls } => dtls.scope(),
        }
    }
}

impl ScopedError for CompoundNegotiateError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundNegotiateError::DTLS { dtls } => dtls.scope(),
            CompoundNegotiateError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for CompoundShutdownError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundShutdownError::DTLS { dtls } => dtls.scope(),
            CompoundShutdownError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for Box<CompoundNegotiateError> {
    #[inline]
    fn scope(&self) -> ErrorScope {
        self.as_ref().scope()
    }
}

impl ScopedError for Box<CompoundShutdownError> {
    #[inline]
    fn scope(&self) -> ErrorScope {
        self.as_ref().scope()
    }
}

impl ScopedError for CompoundNegotiatorStartError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundNegotiatorStartError::DTLS { dtls } => dtls.scope(),
            CompoundNegotiatorStartError::Mismatch => ErrorScope::Unrecoverable
        }
    }
}

impl ScopedError for Box<CompoundNegotiatorStartError> {
    #[inline]
    fn scope(&self) -> ErrorScope {
        self.as_ref().scope()
    }
}

impl ScopedError for CompoundFarChannelAcquiredResolverError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelAcquiredResolverError::IP { err } => err.scope(),
            CompoundFarChannelAcquiredResolverError::UnixResolve => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl ScopedError for CompoundFarIPChannelAcquiredResolverError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarIPChannelAcquiredResolverError::SOCKS5 { err } => {
                err.scope()
            }
            CompoundFarIPChannelAcquiredResolverError::UDP { err } => {
                err.scope()
            }
            CompoundFarIPChannelAcquiredResolverError::UDPResolve => {
                ErrorScope::Unrecoverable
            }
        }
    }
}

impl Display for CompoundFarChannelAcquiredResolverError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelAcquiredResolverError::IP { err } => {
                write!(f, "{}", err)
            }
            CompoundFarChannelAcquiredResolverError::UnixResolve => {
                write!(f, "Unix socket should not generate resolver")
            }
        }
    }
}

impl<F> Display for CompoundFarChannelSessionCredError<F>
where
    F: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSessionCredError::Basic { error } => error.fmt(f)
        }
    }
}

impl Display for CompoundFarIPChannelShutdownAcquiredError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelShutdownAcquiredError::SOCKS5 { err } =>
                write!(f, "{}", err),
            CompoundFarIPChannelShutdownAcquiredError::Mismatch =>
                write!(f, "channel and acquired type mismatch")
        }
    }
}

impl Display for CompoundFarChannelShutdownAcquiredError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelShutdownAcquiredError::IP { err } =>
                write!(f, "{}", err),
            CompoundFarChannelShutdownAcquiredError::Mismatch =>
                write!(f, "channel and acquired type mismatch")
        }
    }
}

impl Display for CompoundFarIPChannelShutdownAcquiredNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelShutdownAcquiredNegoError::SOCKS5 { err } =>
                write!(f, "{}", err),
            CompoundFarIPChannelShutdownAcquiredNegoError::Mismatch =>
                write!(f, "channel and acquired type mismatch")
        }
    }
}

impl Display for CompoundFarChannelShutdownAcquiredNegoError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelShutdownAcquiredNegoError::IP { err } =>
                write!(f, "{}", err),
            CompoundFarChannelShutdownAcquiredNegoError::Mismatch =>
                write!(f, "channel and acquired type mismatch")
        }
    }
}

impl<F> Debug for CompoundFarChannelSessionCredError<F>
where
    F: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelSessionCredError::Basic { error } => error.fmt(f)
        }
    }
}

impl Debug for CompoundOwnedIPFlowsNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundOwnedIPFlowsNegotiateError::DTLS { error } => {
                write!(f, "{}", error)
            }
        }
    }
}

impl Display for CompoundOwnedIPFlowsNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundOwnedIPFlowsNegotiateError::DTLS { error } => {
                write!(f, "{}", error)
            }
        }
    }
}

impl<Unix, UDP> Display for CompoundFarChannelParamError<Unix, UDP>
where
    Unix: Display,
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelParamError::Unix { err } => err.fmt(f),
            CompoundFarChannelParamError::IP { err } => err.fmt(f),
            CompoundFarChannelParamError::Mismatch => {
                write!(f, "socket and transform type mismatch")
            }
        }
    }
}

impl<UDP> Display for CompoundFarIPChannelParamError<UDP>
where
    UDP: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarIPChannelParamError::UDP { err } => err.fmt(f)
        }
    }
}

impl From<UnixDatagramSocket> for CompoundFarChannelSocket {
    #[inline]
    fn from(val: UnixDatagramSocket) -> CompoundFarChannelSocket {
        CompoundFarChannelSocket::Unix { unix: val }
    }
}

impl From<CompoundFarIPChannelSocket> for CompoundFarChannelSocket {
    #[inline]
    fn from(val: CompoundFarIPChannelSocket) -> CompoundFarChannelSocket {
        CompoundFarChannelSocket::IP { ip: val }
    }
}

impl From<UDPFarSocket> for CompoundFarChannelSocket {
    #[inline]
    fn from(val: UDPFarSocket) -> CompoundFarChannelSocket {
        CompoundFarChannelSocket::IP {
            ip: CompoundFarIPChannelSocket::from(val)
        }
    }
}

impl From<UDPFarSocket> for CompoundFarIPChannelSocket {
    #[inline]
    fn from(val: UDPFarSocket) -> CompoundFarIPChannelSocket {
        CompoundFarIPChannelSocket::UDP { udp: val }
    }
}

impl From<UnixSocketPath> for CompoundFarChannelAddr {
    #[inline]
    fn from(val: UnixSocketPath) -> CompoundFarChannelAddr {
        CompoundFarChannelAddr::Unix { unix: val }
    }
}

impl TryFrom<CompoundFarChannelAddr> for UnixSocketPath {
    type Error = CompoundFarChannelAddr;

    #[inline]
    fn try_from(
        val: CompoundFarChannelAddr
    ) -> Result<UnixSocketPath, CompoundFarChannelAddr> {
        match val {
            CompoundFarChannelAddr::Unix { unix } => Ok(unix),
            err => Err(err)
        }
    }
}

impl From<SocketAddr> for CompoundFarChannelAddr {
    #[inline]
    fn from(val: SocketAddr) -> CompoundFarChannelAddr {
        CompoundFarChannelAddr::IP { ip: val }
    }
}

impl<Unix, UDP> From<CompoundFarIPChannelSizeError<UDP>>
    for CompoundFarChannelSizeError<Unix, UDP>
{
    #[inline]
    fn from(
        val: CompoundFarIPChannelSizeError<UDP>
    ) -> CompoundFarChannelSizeError<Unix, UDP> {
        CompoundFarChannelSizeError::IP { ip: val }
    }
}

impl TryFrom<CompoundFarChannelXfrmPeerAddr>
    for CompoundFarIPChannelXfrmPeerAddr
{
    type Error = Error;

    #[inline]
    fn try_from(
        val: CompoundFarChannelXfrmPeerAddr
    ) -> Result<CompoundFarIPChannelXfrmPeerAddr, Error> {
        match val {
            CompoundFarChannelXfrmPeerAddr::IP { ip } => Ok(ip),
            _ => Err(Error::new(
                ErrorKind::Other,
                "cannot convert Unix socket address to IP address"
            ))
        }
    }
}

impl TryFrom<CompoundFarIPChannelXfrmPeerAddr> for CompoundFarChannelAddr {
    type Error = CompoundFarIPChannelXfrmPeerAddrError;

    #[inline]
    fn try_from(
        val: CompoundFarIPChannelXfrmPeerAddr
    ) -> Result<CompoundFarChannelAddr, CompoundFarIPChannelXfrmPeerAddrError>
    {
        match val {
            CompoundFarIPChannelXfrmPeerAddr::UDP { udp } => {
                Ok(CompoundFarChannelAddr::IP { ip: udp })
            }
            CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { .. } => {
                Err(CompoundFarIPChannelXfrmPeerAddrError::SOCKS5)
            }
        }
    }
}

impl TryFrom<CompoundFarChannelXfrmPeerAddr> for CompoundFarChannelAddr {
    type Error = CompoundFarIPChannelXfrmPeerAddrError;

    #[inline]
    fn try_from(
        val: CompoundFarChannelXfrmPeerAddr
    ) -> Result<CompoundFarChannelAddr, CompoundFarIPChannelXfrmPeerAddrError>
    {
        match val {
            CompoundFarChannelXfrmPeerAddr::Unix { unix } => {
                Ok(CompoundFarChannelAddr::Unix { unix: unix })
            }
            CompoundFarChannelXfrmPeerAddr::IP { ip } => {
                CompoundFarChannelAddr::try_from(ip)
            }
        }
    }
}

impl From<CompoundFarIPChannelXfrmPeerAddr> for CompoundFarChannelXfrmPeerAddr {
    #[inline]
    fn from(
        val: CompoundFarIPChannelXfrmPeerAddr
    ) -> CompoundFarChannelXfrmPeerAddr {
        CompoundFarChannelXfrmPeerAddr::IP { ip: val }
    }
}

impl From<CompoundFarIPChannelXfrmPeerAddr> for IPEndpoint {
    #[inline]
    fn from(val: CompoundFarIPChannelXfrmPeerAddr) -> IPEndpoint {
        match val {
            CompoundFarIPChannelXfrmPeerAddr::UDP { udp } => {
                IPEndpoint::from(udp)
            }
            CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { socks5 } => socks5
        }
    }
}

impl<Unix, UDP> From<SOCKS5UDPXfrm<CompoundFarIPChannelXfrm<UDP>>>
    for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketPath, PeerAddr = UnixSocketPath>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    #[inline]
    fn from(
        val: SOCKS5UDPXfrm<CompoundFarIPChannelXfrm<UDP>>
    ) -> CompoundFarChannelXfrm<Unix, UDP> {
        CompoundFarChannelXfrm::IP {
            ip: CompoundFarIPChannelXfrm::from(val)
        }
    }
}

impl<UDP> From<SOCKS5UDPXfrm<CompoundFarIPChannelXfrm<UDP>>>
    for CompoundFarIPChannelXfrm<UDP>
where
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    #[inline]
    fn from(
        val: SOCKS5UDPXfrm<CompoundFarIPChannelXfrm<UDP>>
    ) -> CompoundFarIPChannelXfrm<UDP> {
        CompoundFarIPChannelXfrm::SOCKS5 {
            socks5: Box::new(val)
        }
    }
}

impl TryFrom<CompoundFarChannelAddr> for SocketAddr {
    type Error = Error;

    #[inline]
    fn try_from(val: CompoundFarChannelAddr) -> Result<SocketAddr, Error> {
        match val {
            CompoundFarChannelAddr::Unix { .. } => Err(Error::new(
                ErrorKind::Other,
                "address type mismatch: expected IP, got Unix"
            )),
            CompoundFarChannelAddr::IP { ip } => Ok(ip)
        }
    }
}

impl From<CompoundFarChannelAddr> for CompoundFarChannelXfrmPeerAddr {
    fn from(val: CompoundFarChannelAddr) -> CompoundFarChannelXfrmPeerAddr {
        match val {
            CompoundFarChannelAddr::Unix { unix } => {
                CompoundFarChannelXfrmPeerAddr::Unix { unix: unix }
            }
            CompoundFarChannelAddr::IP { ip } => {
                let ip = CompoundFarIPChannelXfrmPeerAddr::from(ip);

                CompoundFarChannelXfrmPeerAddr::IP { ip: ip }
            }
        }
    }
}

#[cfg(test)]
use std::iter::empty;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use mio::Poll;

#[cfg(test)]
use crate::config::FlowsConfig;
#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::far::flows::accept_one;
#[cfg(test)]
use crate::far::flows::connect_one;
#[cfg(test)]
use crate::far::flows::read_one;
#[cfg(test)]
use crate::far::flows::write_one;
#[cfg(test)]
use crate::far::udp::UDPDatagramXfrm;
#[cfg(test)]
use crate::far::unix::UnixDatagramXfrm;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[test]
fn test_compound_dtls_unix() {
    init();

    const CHANNEL_PATH: &'static str = "test_compound_dtls_unix_server.sock";
    const CLIENT_PATH: &'static str = "test_compound_dtls_unix_client.sock";

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_compound_dtls_unix_server.sock\n",
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  key: test/data/certs/client/private/test_client_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_compound_dtls_unix_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CLIENT_PATH).unwrap()
    );
    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut listener =
            CompoundFarChannel::create(&mut server_nscaches, &mut empty(),
                                       server_config)
                .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } =>
                CompoundFarChannelParam::Unix {
                    unix: unix
                },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = listener.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        server_barrier.wait();

        let (mut flow, peer_addr) =
            accept_one(&mut flows, &mut poll, &(), token)
            .expect("Expected success");

        server_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &peer_addr, &(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
            .expect("Expected success");

        server_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let server_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CHANNEL_PATH).unwrap()
    );
    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(endpoint, CompoundOutboundNegotiatorParam::Basic))
        };
        let mut conn =
            CompoundFarChannel::create(&mut client_nscaches, &mut empty(),
                                       client_config)
                .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } =>
                CompoundFarChannelParam::Unix {
                    unix: unix
                },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = conn.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        client_barrier.wait();

        let mut flow = connect_one(&mut flows, &mut poll, &negoparam, &(),
                                   server_addr.clone(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
            .expect("Expected success");

        client_barrier.wait();
        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &server_addr, &(), token)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}

#[test]
fn test_compound_dtls_udp() {
    init();

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
        "  udp:\n",
        "    addr: ::1\n",
        "    port: 7003\n"
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  key: test/data/certs/client/private/test_client_key.pem\n",
        "  udp:\n",
        "    addr: ::1\n",
        "    port: 7004\n"
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7004".parse().unwrap());
    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut listener =
            CompoundFarChannel::create(&mut server_nscaches, &mut empty(),
                                       server_config)
                .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::IP {
                ip: CompoundFarIPChannelAcquireState::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = listener.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        server_barrier.wait();

        let (mut flow, peer_addr) =
            accept_one(&mut flows, &mut poll, &(), token)
            .expect("Expected success");

        server_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &peer_addr, &(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
            .expect("Expected success");

        server_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let server_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7003".parse().unwrap());
    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(endpoint, CompoundOutboundNegotiatorParam::Basic))
        };
        let mut conn =
            CompoundFarChannel::create(&mut client_nscaches, &mut empty(),
                                       client_config)
                .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::IP {
                ip: CompoundFarIPChannelAcquireState::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = conn.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        client_barrier.wait();

        let mut flow = connect_one(&mut flows, &mut poll, &negoparam, &(),
                                   server_addr.clone(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
            .expect("Expected success");

        client_barrier.wait();
        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &server_addr, &(), token)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}

#[test]
fn test_compound_dtls_double() {
    init();

    const CHANNEL_PATH: &'static str = "test_compound_dtls_double_server.sock";
    const CLIENT_PATH: &'static str = "test_compound_dtls_double_client.sock";

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "  key: test/data/certs/server/private/test_server_key.pem\n",
        "  dtls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - P-384\n",
        "      - X25519\n",
        "      - P-256\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - test/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "    cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "    key: test/data/certs/server/private/test_server_key.pem\n",
        "    unix-datagram:\n",
        "      path: test_compound_dtls_double_server.sock\n",
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "  key: test/data/certs/client/private/test_client_key.pem\n",
        "  dtls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - P-384\n",
        "      - X25519\n",
        "      - P-256\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - test/data/certs/server/ca_cert.pem\n",
        "      crls: []\n",
        "    cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "    key: test/data/certs/client/private/test_client_key.pem\n",
        "    unix-datagram:\n",
        "      path: test_compound_dtls_double_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CLIENT_PATH).unwrap()
    );
    let mut server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut listener =
            CompoundFarChannel::create(&mut server_nscaches, &mut empty(),
                                       server_config)
                .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } =>
                CompoundFarChannelParam::Unix {
                    unix: unix
                },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = listener.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        server_barrier.wait();

        let (mut flow, peer_addr) =
            accept_one(&mut flows, &mut poll, &(), token)
            .expect("Expected success");

        server_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &peer_addr, &(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
            .expect("Expected success");

        server_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let server_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CHANNEL_PATH).unwrap()
    );
    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(endpoint.clone(),
                                                  CompoundOutboundNegotiatorParam::Basic))
        };
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(endpoint, negoparam))
        };
        let mut conn =
            CompoundFarChannel::create(&mut client_nscaches, &mut empty(),
                                       client_config)
                .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn.acquire(poll.registry())
            .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } =>
                CompoundFarChannelParam::Unix {
                    unix: unix
                },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<UnixDatagramXfrm<UnixSocketPath>,
                                         UDPDatagramXfrm<SocketAddr>> =
            CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows = conn.flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry().register(&mut flows, token,
                                 Interest::READABLE | Interest::WRITABLE)
            .expect("Expected success");

        client_barrier.wait();

        let mut flow = connect_one(&mut flows, &mut poll, &negoparam, &(),
                                   server_addr.clone(), token)
            .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
            .expect("Expected success");

        client_barrier.wait();
        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                              &mut buf, &server_addr, &(), token)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}
