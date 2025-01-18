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

//! A flexible, configurable [FarChannel] instance.
//!
//! Compound channels support arbitrary nesting of different channel
//! types, which can be constructed according to a configuration.
//! This functionality is provided by [CompoundFarChannel].  Most
//! applications should use these implementations, unless there is a
//! good reason to impose more stringent restrictions on what types of
//! channels can be configured.
//!
//! ### Examples
//!
//! The following shows an example use of [CompoundFarChannel].
//! establishing a DTLS session over UDP (note that `CLIENT_CONFIG`
//! and `SERVER_CONFIG` can be modified to support any alternate
//! configuration):
//!
//! ```
//! # use constellation_common::net::DatagramXfrmCreate;
//! # use constellation_common::net::IPEndpointAddr;
//! # use constellation_common::net::PassthruDatagramXfrm;
//! # use constellation_channels::config::CompoundFarChannelConfig;
//! # use constellation_channels::config::CompoundXfrmCreateParam;
//! # use constellation_channels::far::compound::CompoundFarChannel;
//! # use constellation_channels::far::compound::CompoundFarChannelAcquired;
//! # use constellation_channels::far::compound::CompoundFarChannelAddr;
//! # use constellation_channels::far::compound::CompoundFarChannelXfrm;
//! # use constellation_channels::far::compound::CompoundFarChannelXfrmPeerAddr;
//! # use constellation_channels::far::compound::CompoundFarChannelMultiFlows;
//! # use constellation_channels::far::compound::CompoundFarChannelParam;
//! # use constellation_channels::far::compound::CompoundFarChannelSingleFlow;
//! # use constellation_channels::far::compound::CompoundFarChannelSocket;
//! # use constellation_channels::far::compound::CompoundFarIPChannelAcquired;
//! # use constellation_channels::far::compound::CompoundFarIPChannelParam;
//! # use constellation_channels::far::compound::CompoundFlows;
//! # use constellation_channels::far::FarChannel;
//! # use constellation_channels::far::FarChannelCreate;
//! # use constellation_channels::far::FarChannelBorrowFlows;
//! # use constellation_channels::far::flows::MultiFlows;
//! # use constellation_channels::far::flows::SingleFlow;
//! # use constellation_channels::far::flows::BorrowedFlows;
//! # use constellation_channels::resolve::cache::SharedNSNameCaches;
//! # use constellation_channels::unix::UnixSocketAddr;
//! # use std::net::Shutdown;
//! # use std::net::SocketAddr;
//! # use std::thread::spawn;
//! # use std::io::Read;
//! # use std::io::Write;
//! # use std::sync::Arc;
//! # use std::sync::Barrier;
//! # use std::thread::sleep;
//! # use std::time::Duration;
//! #
//! const CHANNEL_CONFIG: &'static str =
//!     concat!(
//!         "dtls:\n",
//!         "  cipher-suites:\n",
//!         "    - TLS_AES_256_GCM_SHA384\n",
//!         "    - TLS_CHACHA20_POLY1305_SHA256\n",
//!         "  key-exchange-groups:\n",
//!         "    - P-384\n",
//!         "    - X25519\n",
//!         "    - P-256\n",
//!         "  trust-root:\n",
//!         "    root-certs:\n",
//!         "      - test/data/certs/client/ca_cert.pem\n",
//!         "    crls: []\n",
//!         "  cert: test/data/certs/server/certs/test_server_cert.pem\n",
//!         "  key: test/data/certs/server/private/test_server_key.pem\n",
//!         "  udp:\n",
//!         "    addr: ::1\n",
//!         "    port: 7000\n"
//!     );
//! const CLIENT_CONFIG: &'static str =
//!     concat!(
//!         "dtls:\n",
//!         "  cipher-suites:\n",
//!         "    - TLS_AES_256_GCM_SHA384\n",
//!         "    - TLS_CHACHA20_POLY1305_SHA256\n",
//!         "  key-exchange-groups:\n",
//!         "    - P-384\n",
//!         "    - X25519\n",
//!         "    - P-256\n",
//!         "  trust-root:\n",
//!         "    root-certs:\n",
//!         "      - test/data/certs/server/ca_cert.pem\n",
//!         "    crls: []\n",
//!         "  cert: test/data/certs/client/certs/test_client_cert.pem\n",
//!         "  key: test/data/certs/client/private/test_client_key.pem\n",
//!         "  udp:\n",
//!         "    addr: ::1\n",
//!         "    port: 7001\n"
//!     );
//! const FIRST_BYTES: [u8; 8] = [ 0x00, 0x01, 0x02, 0x03,
//!                                0x04, 0x05, 0x06, 0x07 ];
//! const SECOND_BYTES: [u8; 8] = [ 0x08, 0x09, 0x0a, 0x0b,
//!                                 0x0c, 0x0d, 0x0e, 0x0f ];
//! let channel_config: CompoundFarChannelConfig =
//!     serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
//! let client_config: CompoundFarChannelConfig =
//!     serde_yaml::from_str(CLIENT_CONFIG).unwrap();
//! let nscaches = SharedNSNameCaches::new();
//! # let barrier = Arc::new(Barrier::new(2));
//!
//! let client_addr =
//!     CompoundFarChannelXfrmPeerAddr::udp("[::1]:7001".parse().unwrap());
//! let mut client_nscaches = nscaches.clone();
//! let client_barrier = barrier.clone();
//! let listen = spawn(move || {
//!     let mut listener =
//!         CompoundFarChannel::new(&mut client_nscaches, channel_config)
//!             .expect("Expected success");
//!     let param = match listener.acquire().unwrap() {
//!         CompoundFarChannelAcquired::IP {
//!             ip: CompoundFarIPChannelAcquired::UDP { udp }
//!         } => CompoundFarChannelParam::IP {
//!             ip: CompoundFarIPChannelParam::UDP { udp: udp }
//!         },
//!         _ => panic!("Expected UDP acquired")
//!     };
//!     let create_param = CompoundXfrmCreateParam::default();
//!     let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);
//!     let mut flows: CompoundFarChannelMultiFlows<
//!         PassthruDatagramXfrm<UnixSocketAddr>,
//!         PassthruDatagramXfrm<SocketAddr>
//!     > = listener.borrowed_flows(param, xfrm, ()).unwrap();
//!
//! #   client_barrier.wait();
//!
//!     let mut buf = [0; FIRST_BYTES.len()];
//!     let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();
//!
//! #   client_barrier.wait();
//!
//!     let nbytes = flow.read(&mut buf).unwrap();
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
//! let channel_addr =
//!     CompoundFarChannelXfrmPeerAddr::udp("[::1]:7000".parse().unwrap());
//! let mut channel_nscaches = nscaches.clone();
//! let channel_barrier = barrier;
//! let send = spawn(move || {
//!     let mut conn =
//!         CompoundFarChannel::new(&mut channel_nscaches, client_config)
//!             .expect("expected success");
//!     let param = match conn.acquire().unwrap() {
//!         CompoundFarChannelAcquired::IP {
//!             ip: CompoundFarIPChannelAcquired::UDP { udp }
//!         } => CompoundFarChannelParam::IP {
//!             ip: CompoundFarIPChannelParam::UDP { udp: udp }
//!         },
//!         _ => panic!("Expected UDP acquired")
//!     };
//!     let create_param = CompoundXfrmCreateParam::default();
//!     let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);
//!
//! #   channel_barrier.wait();
//!
//!     let mut flows: CompoundFarChannelSingleFlow<
//!         PassthruDatagramXfrm<UnixSocketAddr>,
//!         PassthruDatagramXfrm<SocketAddr>
//!     > = conn
//!         .borrowed_flows(param, xfrm, channel_addr.clone())
//!         .unwrap();
//!     let servername = "test-server.nowhere.com";
//!     let endpoint = IPEndpointAddr::name(String::from(servername));
//!     let mut flow = BorrowedFlows::flow(
//!         &mut flows,
//!         channel_addr.clone(),
//!         Some(&endpoint)
//!     )
//!     .unwrap();
//!
//!     flow.write_all(&FIRST_BYTES).expect("Expected success");
//!
//! #   channel_barrier.wait();
//!
//!     let mut buf = [0; SECOND_BYTES.len()];
//!
//! #   channel_barrier.wait();
//!
//!     flow.read_exact(&mut buf).unwrap();
//!
//!     assert_eq!(SECOND_BYTES, buf);
//! });
//!
//! send.join().unwrap();
//! listen.join().unwrap();
//! ```

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
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Condvar;

use constellation_auth::authn::SessionAuthN;
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
use constellation_common::net::Receiver;
use constellation_common::net::Sender;
use constellation_common::net::Socket;
use constellation_common::nonblock::NonblockResult;
use constellation_common::retry::RetryResult;
use constellation_common::sched::SelectError;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5Param;
#[cfg(feature = "socks5")]
use constellation_socks5::comm::SOCKS5UDPXfrm;
#[cfg(feature = "socks5")]
use constellation_socks5::error::SOCKS5UDPError;
use constellation_streams::channels::ChannelParam;
use constellation_streams::stream::ConcurrentStream;

use crate::addrs::SocketAddrPolicy;
use crate::config::tls::TLSPeerConfig;
use crate::config::CompoundEndpoint;
use crate::config::CompoundFarChannelConfig;
use crate::config::CompoundFarIPChannelConfig;
use crate::config::CompoundXfrmCreateParam;
use crate::config::ResolverConfig;
use crate::far::dtls::DTLSFarChannel;
use crate::far::dtls::DTLSFlow;
use crate::far::dtls::DTLSNegotiateError;
use crate::far::dtls::DTLSNegotiator;
use crate::far::flows::BorrowedFlowNegotiator;
use crate::far::flows::BorrowedFlowsCreate;
use crate::far::flows::Flow;
use crate::far::flows::NegotiateRetry;
use crate::far::flows::OwnedFlowNegotiator;
use crate::far::flows::OwnedFlowsCreate;
use crate::far::flows::PassthruNegotiator;
use crate::far::flows::ThreadedFlows;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquireError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5Acquired;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5AcquiredResolveError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5CreateError;
#[cfg(feature = "socks5")]
use crate::far::socks5::SOCKS5FarChannel;
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
use crate::far::FarChannelBorrowFlows;
use crate::far::FarChannelCreate;
use crate::far::FarChannelOwnedFlows;
use crate::near::compound::CompoundNearConnector;
use crate::near::compound::CompoundNearConnectorCreateError;
use crate::near::compound::CompoundNearConnectorTakeConnectError;
use crate::resolve::cache::NSNameCachesCtx;
use crate::resolve::Resolution;
use crate::unix::UnixSocketAddr;

/// Type alias for [CompoundNearConnector] instances that use
/// [TLSPeerConfig] as their TLS configuration.
type ProxyNearConnector = CompoundNearConnector<TLSPeerConfig>;

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
        dtls: DTLSFarChannel<Box<CompoundFarIPChannel>>
    },
    #[cfg(feature = "socks5")]
    /// Wrapper around a [SOCKS5FarChannel].
    SOCKS5 {
        /// The inner [SOCKS5FarChannel].
        socks5: SOCKS5FarChannel<
            Box<ProxyNearConnector>,
            CompoundFarIPChannelXfrmPeerAddr,
            Box<CompoundFarIPChannel>
        >
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
/// let connector = CompoundFarChannel::new(&mut nscaches,
///                                         accept_config).unwrap();
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
        dtls: DTLSFarChannel<Box<CompoundFarChannel>>
    },
    IP {
        ip: CompoundFarIPChannel
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
        socks5: Box<SOCKS5Acquired<CompoundFarIPChannelAcquired, IPEndpoint>>
    }
}

/// Multiplexer for [Acquired](FarChannel::Acquired)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelAcquired {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    IP {
        ip: CompoundFarIPChannelAcquired
    }
}

/// Multiplexer for [Param](FarChannel::Param)s for
/// [CompoundFarIPChannel].
#[derive(Clone, Eq, Hash, PartialEq)]
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

/// Multiplexer for [Param](FarChannel::Param)s for
/// [CompoundFarChannel].
#[derive(Clone, Eq, Hash, PartialEq)]
pub enum CompoundFarChannelParam {
    #[cfg(feature = "unix")]
    Unix {
        unix: UnixSocketAddr
    },
    IP {
        ip: CompoundFarIPChannelParam
    }
}

/// [DatagramXfrm] instance for [CompoundFarChannel]s.
pub enum CompoundFarChannelXfrm<
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
> {
    #[cfg(feature = "unix")]
    Unix {
        unix: Unix
    },
    IP {
        ip: CompoundFarIPChannelXfrm<UDP>
    }
}

/// [DatagramXfrm] instance for [CompoundFarIPChannel]s.
pub enum CompoundFarIPChannelXfrm<
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
> {
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
pub enum CompoundFarChannelAcquireError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<
            SOCKS5AcquireError<
                CompoundNearConnectorTakeConnectError,
                CompoundFarChannelAcquireError
            >
        >
    }
}

/// Multiplexer for [CreateError](FarChannelCreate::CreateError)s for
/// [CompoundFarChannel].
#[derive(Debug)]
pub enum CompoundFarChannelCreateError {
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

/// Multiplexer for [Socket](FarChannel::Socket)s for
/// [CompoundFarIPChannel].
pub enum CompoundFarIPChannelSocket {
    UDP { udp: UDPFarSocket }
}

/// Multiplexer for [Socket](FarChannel::Socket)s for
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
        unix: UnixSocketAddr
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
    Unix { unix: UnixSocketAddr },
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

/// Multiplexer for [SocketError](FarChannel::SocketError)s for
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

/// Multiplexer for [SocketError](FarChannel::SocketError)s for
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

/// Multiplexer for [XfrmError](FarChannelOwnedFlows::XfrmError)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelXfrmError {
    #[cfg(feature = "socks5")]
    SOCKS5 {
        socks5: Box<SOCKS5XfrmError<CompoundFarChannelXfrmError>>
    },
    Mismatch
}

/// Multiplexer for [XfrmError](FarChannelOwnedFlows::XfrmError)s for
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

/// Multiplexer for [XfrmError](FarChannelOwnedFlows::XfrmError)s for
/// [CompoundFarChannel].
pub enum CompoundFarChannelXfrmWrapError<Unix, UDP> {
    Unix {
        unix: Unix
    },
    IP {
        ip: CompoundFarIPChannelXfrmWrapError<UDP>
    }
}

/// [ThreadedFlows] using [CompoundFarChannel]s.
pub type CompoundFarChannelThreadedFlows<Unix, UDP, ID> =
    ThreadedFlows<CompoundFarChannel, CompoundFarChannelXfrm<Unix, UDP>, ID>;

/// [Negotiator] instance for [CompoundFarChannel]s.
#[derive(Clone)]
pub enum CompoundNegotiator {
    Basic,
    DTLS {
        dtls: DTLSNegotiator<Box<CompoundNegotiator>>
    }
}

/// Credentials that can be harvested from [CompoundFarChannel]s.
pub enum CompoundFarCredential<'a, Basic> {
    /// Credential harvested from DTLS sessions.
    #[cfg(feature = "dtls")]
    DTLS {
        /// DTLS credentials.
        dtls: Box<SSLCred<'a, CompoundFarCredential<'a, Basic>>>
    },
    /// Credentials harvested from basic channels.
    Basic {
        /// Credentials from basic channels.
        basic: Basic
    }
}

/// Multiplexer for [Flow]s for [CompoundFarChannel].
pub enum CompoundFlow<F>
where
    F: Flow {
    Basic {
        flow: F
    },
    DTLS {
        flow: DTLSFlow<Box<CompoundFlow<F>>>
    }
}

/// Errors that can occur harvesting credentials.
pub enum CompoundFarCredentialError<Cred> {
    Basic { error: Cred }
}

/// Multiplexer for
/// [ListenError](crate::far::flows::OwnedFlowsListener::ListenError)s
/// for [CompoundFarChannel].
pub enum CompoundOwnedFlowsNegotiateError {
    DTLS {
        error: Box<DTLSNegotiateError<CompoundOwnedFlowsNegotiateError>>
    },
    Mismatch
}

/// Multiplexer for [ListenError](
/// crate::far::flows::OwnedFlowsListener::ListenError)s for
/// [CompoundFarIPChannel].
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

impl<F> ConcurrentStream for CompoundFlow<F>
where
    F: ConcurrentStream + Flow
{
    #[inline]
    fn condvar(&self) -> Arc<Condvar> {
        match self {
            CompoundFlow::Basic { flow } => flow.condvar(),
            CompoundFlow::DTLS { flow } => flow.condvar()
        }
    }
}

impl<F> Credentials for CompoundFlow<F>
where
    F: Credentials + Flow
{
    type Cred<'a> = CompoundFarCredential<'a, F::Cred<'a>>
    where F: 'a;
    type CredError = CompoundFarCredentialError<<F as Credentials>::CredError>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred<'_>>,
        CompoundFarCredentialError<<F as Credentials>::CredError>
    > {
        match self {
            CompoundFlow::DTLS { flow } => {
                let cred = flow.creds()?;

                Ok(cred.map(|cred| CompoundFarCredential::DTLS {
                    dtls: Box::new(cred)
                }))
            }
            CompoundFlow::Basic { flow } => {
                let cred = flow.creds().map_err(|err| {
                    CompoundFarCredentialError::Basic { error: err }
                })?;

                Ok(cred
                    .map(|cred| CompoundFarCredential::Basic { basic: cred }))
            }
        }
    }
}

impl<F> ConcurrentStream for Box<CompoundFlow<F>>
where
    F: ConcurrentStream + Flow
{
    #[inline]
    fn condvar(&self) -> Arc<Condvar> {
        self.as_ref().condvar()
    }
}

impl<F> Credentials for Box<CompoundFlow<F>>
where
    F: Credentials + Flow
{
    type Cred<'a> = CompoundFarCredential<'a, F::Cred<'a>>
    where F: 'a;
    type CredError = CompoundFarCredentialError<<F as Credentials>::CredError>;

    #[inline]
    fn creds(
        &self
    ) -> Result<
        Option<Self::Cred<'_>>,
        CompoundFarCredentialError<<F as Credentials>::CredError>
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
                .unwrap()
            {
                AcquiredResolver::Resolve { .. } => {
                    Err(CompoundFarChannelAcquiredResolverError::UnixResolve)
                }
                AcquiredResolver::StaticMulti { mut params } => {
                    Ok(AcquiredResolver::StaticMulti {
                        params: params
                            .drain(..)
                            .map(|addr| CompoundFarChannelParam::Unix {
                                unix: addr
                            })
                            .collect()
                    })
                }
                AcquiredResolver::StaticSingle { param } => {
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
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>
{
    #[inline]
    fn from(val: CompoundFarIPChannelXfrm<UDP>) -> Self {
        CompoundFarChannelXfrm::IP { ip: val }
    }
}

impl From<UnixSocketAddr> for CompoundFarChannelXfrmPeerAddr {
    #[inline]
    fn from(val: UnixSocketAddr) -> Self {
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

impl From<CompoundEndpoint> for Option<IPEndpointAddr> {
    fn from(val: CompoundEndpoint) -> Option<IPEndpointAddr> {
        match val {
            CompoundEndpoint::IP { ip } => Some(ip.ip_endpoint().clone()),
            CompoundEndpoint::Unix { .. } => None
        }
    }
}

impl TryFrom<CompoundEndpoint> for Resolution<CompoundFarChannelXfrmPeerAddr> {
    type Error = Error;

    fn try_from(
        val: CompoundEndpoint
    ) -> Result<Resolution<CompoundFarChannelXfrmPeerAddr>, Error> {
        match val {
            CompoundEndpoint::IP { ip } => {
                let (ip, port) = ip.take();

                match ip {
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
            CompoundEndpoint::Unix { unix } => Ok(Resolution::Static {
                addr: CompoundFarChannelXfrmPeerAddr::Unix {
                    unix: UnixSocketAddr::try_from(unix)?
                }
            })
        }
    }
}

impl CompoundFarChannelXfrmPeerAddr {
    #[inline]
    pub fn unix(addr: UnixSocketAddr) -> Self {
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

impl ChannelParam<UnixSocketAddr> for CompoundFarChannelParam {
    #[inline]
    fn accepts_addr(
        &self,
        _addr: &UnixSocketAddr
    ) -> bool {
        matches!(self, CompoundFarChannelParam::Unix { .. })
    }
}

impl<Unix, UDP> DatagramXfrm for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
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
            (CompoundFarChannelXfrm::IP { ip }, addr) => {
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
    type LocalAddr = CompoundFarChannelAddr;
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
                let addr = CompoundFarChannelAddr::IP { ip: addr };

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
        addr: CompoundFarChannelAddr
    ) -> Result<(usize, Self::PeerAddr), Self::Error> {
        match (self, addr) {
            (
                CompoundFarIPChannelXfrm::UDP { udp },
                CompoundFarChannelAddr::IP { ip: addr }
            ) => {
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
            _ => Err(CompoundFarIPChannelXfrmWrapError::Mismatch)
        }
    }
}

impl<Unix, UDP> DatagramXfrmCreateParam for CompoundFarChannelXfrm<Unix, UDP>
where
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>
        + DatagramXfrmCreateParam<
            Socket = UnixDatagramSocket,
            Param = UnixSocketAddr
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
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>
        + DatagramXfrmCreate<Addr = UnixSocketAddr>,
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
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
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

    #[inline]
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
    #[inline]
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                let (nbytes, addr) = unix.recv_from(buf)?;

                Ok((nbytes, CompoundFarChannelAddr::Unix { unix: addr }))
            }
            CompoundFarChannelSocket::IP { ip } => {
                let (nbytes, addr) = ip.recv_from(buf)?;

                Ok((nbytes, CompoundFarChannelAddr::IP { ip: addr }))
            }
        }
    }

    #[inline]
    fn peek_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        match self {
            CompoundFarChannelSocket::Unix { unix } => {
                let (nbytes, addr) = unix.peek_from(buf)?;

                Ok((nbytes, CompoundFarChannelAddr::Unix { unix: addr }))
            }
            CompoundFarChannelSocket::IP { ip } => {
                let (nbytes, addr) = ip.peek_from(buf)?;

                Ok((nbytes, CompoundFarChannelAddr::IP { ip: addr }))
            }
        }
    }
}

impl Receiver for CompoundFarIPChannelSocket {
    #[inline]
    fn recv_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                let (nbytes, addr) = udp.recv_from(buf)?;

                Ok((nbytes, addr))
            }
        }
    }

    #[inline]
    fn peek_from(
        &self,
        buf: &mut [u8]
    ) -> Result<(usize, Self::Addr), Error> {
        match self {
            CompoundFarIPChannelSocket::UDP { udp } => {
                let (nbytes, addr) = udp.peek_from(buf)?;

                Ok((nbytes, addr))
            }
        }
    }
}

impl<Cred> ScopedError for CompoundFarCredentialError<Cred>
where
    Cred: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarCredentialError::Basic { error } => error.scope()
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

impl ScopedError for CompoundFarChannelAcquireError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelAcquireError::SOCKS5 { socks5 } => socks5.scope()
        }
    }
}

impl ScopedError for CompoundFarChannelCreateError {
    fn scope(&self) -> ErrorScope {
        match self {
            CompoundFarChannelCreateError::SOCKS5 { socks5 } => socks5.scope()
        }
    }
}

impl FarChannel for CompoundFarIPChannel {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarIPChannelAcquired;
    type Config = CompoundFarIPChannelConfig;
    type Param = CompoundFarIPChannelParam;
    type Socket = CompoundFarIPChannelSocket;
    type SocketError = CompoundFarIPChannelSocketError;

    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        match self {
            CompoundFarIPChannel::UDP { udp } => {
                let udp = udp.acquire().unwrap();

                Ok(CompoundFarIPChannelAcquired::UDP { udp: udp })
            }
            CompoundFarIPChannel::DTLS { dtls } => dtls.acquire(),
            CompoundFarIPChannel::SOCKS5 { socks5 } => {
                let socks5 = socks5.acquire().map_err(|err| {
                    CompoundFarChannelAcquireError::SOCKS5 {
                        socks5: Box::new(err)
                    }
                })?;

                Ok(CompoundFarIPChannelAcquired::SOCKS5 {
                    socks5: Box::new(socks5)
                })
            }
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
    type CreateError = CompoundFarChannelCreateError;

    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundFarIPChannelConfig::UDP { udp } => {
                let udp = UDPFarChannel::new(caches, udp).unwrap();

                Ok(CompoundFarIPChannel::UDP { udp: udp })
            }
            CompoundFarIPChannelConfig::DTLS { dtls } => {
                let dtls = DTLSFarChannel::new(caches, dtls)?;

                Ok(CompoundFarIPChannel::DTLS { dtls: dtls })
            }
            CompoundFarIPChannelConfig::SOCKS5 { socks5 } => {
                let socks5 =
                    SOCKS5FarChannel::new(caches, socks5).map_err(|err| {
                        CompoundFarChannelCreateError::SOCKS5 {
                            socks5: Box::new(err)
                        }
                    })?;

                Ok(CompoundFarIPChannel::SOCKS5 { socks5: socks5 })
            }
        }
    }
}

impl FarChannel for CompoundFarChannel {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarChannelAcquired;
    type Config = CompoundFarChannelConfig;
    type Param = CompoundFarChannelParam;
    type Socket = CompoundFarChannelSocket;
    type SocketError = CompoundFarChannelSocketError;

    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        match self {
            CompoundFarChannel::Unix { unix } => {
                let unix = unix.acquire().unwrap();

                Ok(CompoundFarChannelAcquired::Unix { unix: unix })
            }
            CompoundFarChannel::DTLS { dtls } => dtls.acquire(),
            CompoundFarChannel::IP { ip } => {
                let ip = ip.acquire()?;

                Ok(CompoundFarChannelAcquired::IP { ip: ip })
            }
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
    type CreateError = CompoundFarChannelCreateError;

    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        match config {
            CompoundFarChannelConfig::Unix { unix } => {
                let unix = UnixFarChannel::new(caches, unix).unwrap();

                Ok(CompoundFarChannel::Unix { unix: unix })
            }
            CompoundFarChannelConfig::UDP { udp } => {
                let udp = UDPFarChannel::new(caches, udp).unwrap();

                Ok(CompoundFarChannel::IP {
                    ip: CompoundFarIPChannel::UDP { udp: udp }
                })
            }
            CompoundFarChannelConfig::DTLS { dtls } => {
                let dtls = DTLSFarChannel::new(caches, dtls)?;

                Ok(CompoundFarChannel::DTLS { dtls: dtls })
            }
            CompoundFarChannelConfig::SOCKS5 { socks5 } => {
                let socks5 =
                    SOCKS5FarChannel::new(caches, socks5).map_err(|err| {
                        CompoundFarChannelCreateError::SOCKS5 {
                            socks5: Box::new(err)
                        }
                    })?;

                Ok(CompoundFarChannel::IP {
                    ip: CompoundFarIPChannel::SOCKS5 { socks5: socks5 }
                })
            }
        }
    }
}

impl FarChannel for Box<CompoundFarIPChannel> {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarIPChannelAcquired;
    type Config = Box<CompoundFarIPChannelConfig>;
    type Param = CompoundFarIPChannelParam;
    type Socket = CompoundFarIPChannelSocket;
    type SocketError = CompoundFarIPChannelSocketError;

    #[inline]
    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        self.as_mut().acquire()
    }

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.as_ref().socks5_target(val)
    }

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.as_ref().socket(param)
    }
}

impl FarChannelCreate for Box<CompoundFarIPChannel> {
    type CreateError = CompoundFarChannelCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundFarIPChannel::new(caches, config.as_ref().clone()).map(Box::new)
    }
}

impl FarChannel for Box<CompoundFarChannel> {
    type AcquireError = CompoundFarChannelAcquireError;
    type Acquired = CompoundFarChannelAcquired;
    type Config = Box<CompoundFarChannelConfig>;
    type Param = CompoundFarChannelParam;
    type Socket = CompoundFarChannelSocket;
    type SocketError = CompoundFarChannelSocketError;

    #[inline]
    fn acquire(&mut self) -> Result<Self::Acquired, Self::AcquireError> {
        self.as_mut().acquire()
    }

    #[cfg(feature = "socks5")]
    #[inline]
    fn socks5_target(
        &self,
        val: &Self::Acquired
    ) -> Result<IPEndpoint, Error> {
        self.as_ref().socks5_target(val)
    }

    #[inline]
    fn socket(
        &self,
        param: &Self::Param
    ) -> Result<Self::Socket, Self::SocketError> {
        self.as_ref().socket(param)
    }
}

impl FarChannelCreate for Box<CompoundFarChannel> {
    type CreateError = CompoundFarChannelCreateError;

    #[inline]
    fn new<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        CompoundFarChannel::new(caches, config.as_ref().clone()).map(Box::new)
    }
}

impl<'a, F, AuthN, Unix, UDP>
    FarChannelBorrowFlows<'a, F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for CompoundFarChannel
where
    AuthN: SessionAuthN<<CompoundNegotiator as BorrowedFlowNegotiator<F::Flow>>::Flow<'a>>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: BorrowedFlowsCreate<'a, CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type BorrowedFlowsError = Infallible;
    type Xfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = CompoundNegotiator;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match (self, param, xfrm) {
            (CompoundFarChannel::Unix { unix },
             CompoundFarChannelParam::Unix { unix: param },
             xfrm) => {
                let xfrm = <UnixFarChannel as FarChannelBorrowFlows<
                    F,
                    CompoundFarChannelXfrm<Unix, UDP>,
                >>::wrap_xfrm(unix, param, xfrm)
                .unwrap();

                Ok(xfrm)
            }
            (CompoundFarChannel::DTLS { dtls }, param, xfrm) => {
                <DTLSFarChannel<Box<CompoundFarChannel>> as FarChannelBorrowFlows<
                    F,
                    CompoundFarChannelXfrm<Unix, UDP>,
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            (CompoundFarChannel::IP { ip },
             CompoundFarChannelParam::IP { ip: param },
             CompoundFarChannelXfrm::IP { ip: xfrm }) => {
                let xfrm = <CompoundFarIPChannel as FarChannelBorrowFlows<
                    F,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(ip, param, xfrm)?;

                Ok(CompoundFarChannelXfrm::IP { ip: xfrm })
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch),
        }
    }
}

impl<'a, F, AuthN, Unix, UDP>
    FarChannelBorrowFlows<'a, F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for Box<CompoundFarChannel>
where
    AuthN: SessionAuthN<<CompoundNegotiator as BorrowedFlowNegotiator<F::Flow>>::Flow<'a>>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: BorrowedFlowsCreate<'a, CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type BorrowedFlowsError = Infallible;
    type Xfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = CompoundNegotiator;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        let out = <CompoundFarChannel as FarChannelBorrowFlows<
            F,
            CompoundFarChannelXfrm<Unix, UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<'a, F, AuthN, UDP>
    FarChannelBorrowFlows<'a, F, AuthN, CompoundFarIPChannelXfrm<UDP>>
    for CompoundFarIPChannel
where
    AuthN: SessionAuthN<<CompoundNegotiator as BorrowedFlowNegotiator<F::Flow>>::Flow<'a>>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: BorrowedFlowsCreate<'a, CompoundFarIPChannelSocket, CompoundNegotiator, AuthN, CompoundFarIPChannelXfrm<UDP>>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type BorrowedFlowsError = Infallible;
    type Xfrm = CompoundFarIPChannelXfrm<UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = CompoundNegotiator;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match (self, param) {
            (CompoundFarIPChannel::UDP { udp }, CompoundFarIPChannelParam::UDP { udp: param }) => {
                let xfrm = <UDPFarChannel as FarChannelBorrowFlows<
                    F,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(udp, param, xfrm)
                .unwrap();

                Ok(xfrm)
            }
            (
                CompoundFarIPChannel::SOCKS5 { socks5 },
                CompoundFarIPChannelParam::SOCKS5 { socks5: param },
            ) => <SOCKS5FarChannel<
                Box<CompoundNearConnector<TLSPeerConfig>>,
                CompoundFarIPChannelXfrmPeerAddr,
                Box<CompoundFarIPChannel>,
            > as FarChannelBorrowFlows<F, CompoundFarIPChannelXfrm<UDP>>>::wrap_xfrm(
                socks5, *param, xfrm,
            )
            .map_err(|e| CompoundFarChannelXfrmError::SOCKS5 {
                socks5: Box::new(e),
            }),
            (CompoundFarIPChannel::DTLS { dtls }, param) => {
                <DTLSFarChannel<Box<CompoundFarIPChannel>> as FarChannelBorrowFlows<
                    F,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch),
        }
    }
}

impl<'a, F, AuthN, UDP>
    FarChannelBorrowFlows<'a, F, AuthN, CompoundFarIPChannelXfrm<UDP>>
    for Box<CompoundFarIPChannel>
where
    AuthN: SessionAuthN<<CompoundNegotiator as BorrowedFlowNegotiator<F::Flow>>::Flow<'a>>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: BorrowedFlowsCreate<'a, CompoundFarIPChannelSocket, CompoundNegotiator, AuthN, CompoundFarIPChannelXfrm<UDP>>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type BorrowedFlowsError = Infallible;
    type Xfrm = CompoundFarIPChannelXfrm<UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = CompoundNegotiator;

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        let out = <CompoundFarIPChannel as FarChannelBorrowFlows<
            F,
            CompoundFarIPChannelXfrm<UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<F, AuthN, Unix, UDP>
    FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for CompoundFarChannel
where
    AuthN: SessionAuthN<<CompoundNegotiator as OwnedFlowNegotiator<F::Flow>>::Flow>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: OwnedFlowsCreate<CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type OwnedFlowsError = Infallible;
    type Xfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = CompoundNegotiator;

    fn negotiator(&self) -> CompoundNegotiator<F> {
        match self {
            CompoundFarChannel::Unix { .. } =>
                CompoundNegotiator::Basic { flow: PhantomData },
            CompoundFarChannel::IP { ip } =>
                <CompoundFarIPChannel as FarChannelOwnedFlows<F, AuthN, CompoundFarIPChannelXfrm<UDP>>>
                    ::negotiator(ip),

            CompoundFarChannel::DTLS { dtls } =>
                CompoundNegotiator::DTLS {
                    dtls: <DTLSFarChannel<Box<CompoundFarChannel>> as FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>>
                    ::negotiator(dtls)
                }
        }
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match (self, param, xfrm) {
            (CompoundFarChannel::Unix { unix },
             CompoundFarChannelParam::Unix { unix: param },
             xfrm) => {
                let xfrm = <UnixFarChannel as FarChannelOwnedFlows<
                        F, AuthN,
                    CompoundFarChannelXfrm<Unix, UDP>,
                >>::wrap_xfrm(unix, param, xfrm)
                .unwrap();

                Ok(xfrm)
            }
            (CompoundFarChannel::DTLS { dtls }, param, xfrm) => {
                <DTLSFarChannel<Box<CompoundFarChannel>> as FarChannelOwnedFlows<
                    F, AuthN,
                    CompoundFarChannelXfrm<Unix, UDP>,
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            (CompoundFarChannel::IP { ip },
             CompoundFarChannelParam::IP { ip: param },
             CompoundFarChannelXfrm::IP { ip: xfrm }) => {
                let xfrm = <CompoundFarIPChannel as FarChannelOwnedFlows<
                    F, AuthN,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(ip, param, xfrm)?;

                Ok(CompoundFarChannelXfrm::IP { ip: xfrm })
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch),
        }
    }
}

impl<F, AuthN, Unix, UDP>
    FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for Box<CompoundFarChannel>
where
    AuthN: SessionAuthN<<CompoundNegotiator as OwnedFlowNegotiator<F::Flow>>::Flow>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: OwnedFlowsCreate<CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type OwnedFlowsError = Infallible;
    type Xfrm = CompoundFarChannelXfrm<Unix, UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type Nego = Box<CompoundNegotiator>;

    fn negotiator(&self) -> Box<CompoundNegotiator<F>> {
        match self.as_ref() {
            CompoundFarChannel::Unix { .. } => {
                Box::new(CompoundNegotiator::Basic { flow: PhantomData })
            }
            CompoundFarChannel::IP { ip } => {
                let out = <CompoundFarIPChannel as FarChannelOwnedFlows<
                    F,
                    AuthN,
                    CompoundFarIPChannelXfrm<UDP>
                >>::negotiator(ip);

                Box::new(out)
            }
            CompoundFarChannel::DTLS { dtls } => {
                let out = CompoundNegotiator::DTLS {
                    dtls: <DTLSFarChannel<Box<CompoundFarChannel>> as FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>>
                    ::negotiator(dtls)
                };

                Box::new(out)
            }
        }
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarChannelXfrm<Unix, UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        let out = <CompoundFarChannel as FarChannelOwnedFlows<
            F,
            AuthN,
            CompoundFarChannelXfrm<Unix, UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<F, AuthN, Unix, UDP>
    FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for CompoundFarIPChannel
where
    AuthN: SessionAuthN<<CompoundNegotiator as OwnedFlowNegotiator<F::Flow>>::Flow>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: OwnedFlowsCreate<CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type Xfrm = CompoundFarIPChannelXfrm<UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type OwnedFlowsError = Infallible;
    type Nego = CompoundNegotiator;

    fn negotiator(&self) -> CompoundNegotiator<F> {
        match self {
            CompoundFarIPChannel::UDP { .. } |
            CompoundFarIPChannel::SOCKS5 { .. } =>
                CompoundNegotiator::Basic { flow: PhantomData },
            CompoundFarIPChannel::DTLS { dtls } =>
                CompoundNegotiator::DTLS {
                    dtls: <DTLSFarChannel<Box<CompoundFarIPChannel>> as FarChannelOwnedFlows<F, AuthN, CompoundFarIPChannelXfrm<UDP>>>
                    ::negotiator(dtls)
                }
        }
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        match (self, param) {
            (CompoundFarIPChannel::UDP { udp },
             CompoundFarIPChannelParam::UDP { udp: param }) => {
                let xfrm = <UDPFarChannel as FarChannelOwnedFlows<
                    F, AuthN,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(udp, param, xfrm)
                .unwrap();

                Ok(xfrm)
            }
            (
                CompoundFarIPChannel::SOCKS5 { socks5 },
                CompoundFarIPChannelParam::SOCKS5 { socks5: param },
            ) => <SOCKS5FarChannel<
                Box<CompoundNearConnector<TLSPeerConfig>>,
                CompoundFarIPChannelXfrmPeerAddr,
                Box<CompoundFarIPChannel>,
            > as FarChannelOwnedFlows<F, AuthN, CompoundFarIPChannelXfrm<UDP>>>::wrap_xfrm(
                socks5, *param, xfrm,
            )
            .map_err(|e| CompoundFarChannelXfrmError::SOCKS5 {
                socks5: Box::new(e),
            }),
            (CompoundFarIPChannel::DTLS { dtls }, param) => {
                <DTLSFarChannel<Box<CompoundFarIPChannel>> as FarChannelOwnedFlows<
                    F, AuthN,
                    CompoundFarIPChannelXfrm<UDP>,
                >>::wrap_xfrm(dtls, param, xfrm)
            }
            _ => Err(CompoundFarChannelXfrmError::Mismatch),
        }
    }
}

impl<F, AuthN, Unix, UDP>
    FarChannelOwnedFlows<F, AuthN, CompoundFarChannelXfrm<Unix, UDP>>
    for Box<CompoundFarIPChannel>
where
    AuthN: SessionAuthN<<CompoundNegotiator as OwnedFlowNegotiator<F::Flow>>::Flow>,
    AuthN: SessionAuthN<CompoundFlow<F::Flow>>,
    F: OwnedFlowsCreate<CompoundFarChannelSocket, CompoundNegotiator, AuthN, CompoundFarChannelXfrm<Unix, UDP>>,
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
    UDP: DatagramXfrm<LocalAddr = SocketAddr, PeerAddr = SocketAddr>,
{
    type Xfrm = CompoundFarIPChannelXfrm<UDP>;
    type XfrmError = CompoundFarChannelXfrmError;
    type OwnedFlowsError = Infallible;
    type Nego = Box<CompoundNegotiator>;

    fn negotiator(&self) -> Box<CompoundNegotiator<F>> {
        match self.as_ref() {
            CompoundFarIPChannel::UDP { .. } |
            CompoundFarIPChannel::SOCKS5 { .. } => {
                Box::new(CompoundNegotiator::Basic { flow: PhantomData })
            }
            CompoundFarIPChannel::DTLS { dtls } => {
                let out = CompoundNegotiator::DTLS {
                    dtls: <DTLSFarChannel<Box<CompoundFarIPChannel>> as FarChannelOwnedFlows<F, AuthN, CompoundFarIPChannelXfrm<UDP>>>
                    ::negotiator(dtls)
                };

                Box::new(out)
            }
        }
    }

    #[inline]
    fn wrap_xfrm(
        &self,
        param: Self::Param,
        xfrm: CompoundFarIPChannelXfrm<UDP>
    ) -> Result<Self::Xfrm, Self::XfrmError> {
        let out = <CompoundFarIPChannel as FarChannelOwnedFlows<
            F,
            AuthN,
            CompoundFarIPChannelXfrm<UDP>
        >>::wrap_xfrm(self.as_ref(), param, xfrm)?;

        Ok(out)
    }
}

impl<'a, F> BorrowedFlowNegotiator<F> for CompoundNegotiator
where
    F: 'a + Credentials + Flow + Read + Write
{
    type Flow<'b> = CompoundFlow<F>;
    type NegotiateError = CompoundOwnedFlowsNegotiateError;

    fn negotiate_outbound(
        &mut self,
        inner: F::Flow,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(RetryResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { dtls } => Ok(dtls
                .negotiate_outbound(inner, endpoint)
                .map_err(|err| CompoundOwnedFlowsNegotiateError::DTLS {
                    error: Box::new(err)
                })?
                .map(|flow| CompoundFlow::DTLS { flow: flow }))
        }
    }

    fn negotiate_inbound(
        &mut self,
        inner: F::Flow,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(RetryResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { dtls } => Ok(dtls
                .negotiate_inbound(inner)
                .map_err(|err| CompoundOwnedFlowsNegotiateError::DTLS {
                    error: Box::new(err)
                })?
                .map(|flow| CompoundFlow::DTLS { flow: flow }))
        }
    }
}

impl<F> OwnedFlowNegotiator<F> for CompoundNegotiator
where
    F: Credentials + Flow + Read + Write
{
    type Flow = CompoundFlow<F>;
    type NegotiateError = CompoundOwnedFlowsNegotiateError;

    #[inline]
    fn negotiate_outbound_nonblock(
        &mut self,
        inner: F::Flow,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(NonblockResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { .. } => Ok(NonblockResult::Fail(inner))
        }
    }

    fn negotiate_outbound(
        &mut self,
        inner: F::Flow,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(RetryResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { dtls } => Ok(dtls
                .negotiate_outbound(inner, endpoint)
                .map_err(|err| CompoundOwnedFlowsNegotiateError::DTLS {
                    error: Box::new(err)
                })?
                .map(|flow| CompoundFlow::DTLS { flow: flow }))
        }
    }

    #[inline]
    fn negotiate_inbound_nonblock(
        &mut self,
        inner: F::Flow,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(NonblockResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { .. } => Ok(NonblockResult::Fail(inner))
        }
    }

    fn negotiate_inbound(
        &mut self,
        inner: F::Flow,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        match self {
            CompoundNegotiator::Basic { .. } => {
                Ok(RetryResult::Success(CompoundFlow::Basic { flow: inner }))
            }
            CompoundNegotiator::DTLS { dtls } => Ok(dtls
                .negotiate_inbound(inner)
                .map_err(|err| CompoundOwnedFlowsNegotiateError::DTLS {
                    error: Box::new(err)
                })?
                .map(|flow| CompoundFlow::DTLS { flow: flow }))
        }
    }
}

impl<F> OwnedFlowNegotiator<F> for Box<CompoundNegotiator>
where
    F: Credentials + Flow + Read + Write
{
    type Flow = Box<CompoundFlow<F>>;
    type NegotiateError = CompoundOwnedFlowsNegotiateError;

    #[inline]
    fn negotiate_outbound_nonblock(
        &mut self,
        inner: F::Flow,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        self.as_mut()
            .negotiate_inbound_nonblock(inner)
            .map(|out| match out {
                NonblockResult::Success(out) => {
                    NonblockResult::Success(Box::new(out))
                }
                NonblockResult::Fail(out) => NonblockResult::Fail(out)
            })
    }

    #[inline]
    fn negotiate_outbound(
        &mut self,
        inner: F::Flow,
        endpoint: Option<&IPEndpointAddr>
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        self.as_mut()
            .negotiate_outbound(inner, endpoint)
            .map(|out| out.map(Box::new))
    }

    #[inline]
    fn negotiate_inbound_nonblock(
        &mut self,
        inner: F::Flow,
    ) -> Result<NonblockResult<Self::Flow, Self::Inner>, Self::NegotiateError>
    {
        self.as_mut()
            .negotiate_inbound_nonblock(inner)
            .map(|out| match out {
                NonblockResult::Success(out) => {
                    NonblockResult::Success(Box::new(out))
                }
                NonblockResult::Fail(out) => NonblockResult::Fail(out)
            })
    }

    #[inline]
    fn negotiate_inbound(
        &mut self,
        inner: F::Flow,
    ) -> Result<
        RetryResult<Self::Flow, NegotiateRetry<F::Flow>>,
        Self::NegotiateError
    > {
        self.as_mut()
            .negotiate_inbound(inner)
            .map(|out| out.map(Box::new))
    }
}

impl<F> Flow for CompoundFlow<F>
where
    F: Flow
{
    type LocalAddr = F::LocalAddr;
    type PeerAddr = F::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.local_addr(),
            CompoundFlow::DTLS { flow } => flow.local_addr()
        }
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        match self {
            CompoundFlow::Basic { flow } => flow.peer_addr(),
            CompoundFlow::DTLS { flow } => flow.peer_addr()
        }
    }
}

impl<F> Flow for Box<CompoundFlow<F>>
where
    F: Flow
{
    type LocalAddr = F::LocalAddr;
    type PeerAddr = F::PeerAddr;

    #[inline]
    fn local_addr(&self) -> Result<Self::LocalAddr, Error> {
        self.as_ref().local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> Self::PeerAddr {
        self.as_ref().peer_addr()
    }
}

impl<F> Read for CompoundFlow<F>
where
    F: Flow
{
    #[inline]
    fn read(
        &mut self,
        buf: &mut [u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read(buf),
            CompoundFlow::DTLS { flow } => flow.read(buf)
        }
    }

    #[inline]
    fn read_vectored(
        &mut self,
        buf: &mut [IoSliceMut<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_vectored(buf),
            CompoundFlow::DTLS { flow } => flow.read_vectored(buf)
        }
    }

    #[inline]
    fn read_to_end(
        &mut self,
        buf: &mut Vec<u8>
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_to_end(buf),
            CompoundFlow::DTLS { flow } => flow.read_to_end(buf)
        }
    }

    #[inline]
    fn read_to_string(
        &mut self,
        buf: &mut String
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_to_string(buf),
            CompoundFlow::DTLS { flow } => flow.read_to_string(buf)
        }
    }

    #[inline]
    fn read_exact(
        &mut self,
        buf: &mut [u8]
    ) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.read_exact(buf),
            CompoundFlow::DTLS { flow } => flow.read_exact(buf)
        }
    }
}

impl<F> Write for CompoundFlow<F>
where
    F: Flow
{
    #[inline]
    fn write(
        &mut self,
        buf: &[u8]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write(buf),
            CompoundFlow::DTLS { flow } => flow.write(buf)
        }
    }

    #[inline]
    fn write_vectored(
        &mut self,
        buf: &[IoSlice<'_>]
    ) -> Result<usize, Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write_vectored(buf),
            CompoundFlow::DTLS { flow } => flow.write_vectored(buf)
        }
    }

    #[inline]
    fn write_all(
        &mut self,
        buf: &[u8]
    ) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.write_all(buf),
            CompoundFlow::DTLS { flow } => flow.write_all(buf)
        }
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        match self {
            CompoundFlow::Basic { flow } => flow.flush(),
            CompoundFlow::DTLS { flow } => flow.flush()
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
            CompoundFarChannelParam::IP { ip } => ip.fmt(f)
        }
    }
}

impl Display for CompoundFarChannelAcquireError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelAcquireError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
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
            CompoundFarChannelCreateError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
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
                write!(f, "type mismatch with channel and address")
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
                write!(f, "type mismatch with channel and address")
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
                write!(f, "type mismatch with channel and parameter")
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
                write!(f, "type mismatch with channel and parameter")
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

impl Debug for CompoundFarChannelXfrmError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarChannelXfrmError::SOCKS5 { socks5 } => {
                write!(f, "{}", socks5)
            }
            CompoundFarChannelXfrmError::Mismatch => {
                write!(f, "type mismatch with context and parameter")
            }
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
                write!(f, "type mismatch with context and parameter")
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
                write!(f, "type mismatch with context and parameter")
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
                write!(f, "type mismatch with context and parameter")
            }
        }
    }
}

impl Debug for CompoundOwnedFlowsNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundOwnedFlowsNegotiateError::DTLS { error } => {
                write!(f, "{}", error)
            }
            CompoundOwnedFlowsNegotiateError::Mismatch => {
                write!(f, "address type mismatch")
            }
        }
    }
}

impl Display for CompoundOwnedFlowsNegotiateError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundOwnedFlowsNegotiateError::DTLS { error } => {
                write!(f, "{}", error)
            }
            CompoundOwnedFlowsNegotiateError::Mismatch => {
                write!(f, "address type mismatch")
            }
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

impl<F> Display for CompoundFarCredentialError<F>
where
    F: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarCredentialError::Basic { error } => error.fmt(f)
        }
    }
}

impl<F> Debug for CompoundFarCredentialError<F>
where
    F: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            CompoundFarCredentialError::Basic { error } => error.fmt(f)
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
                write!(f, "mismatched socket and transform")
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

impl From<UnixSocketAddr> for CompoundFarChannelAddr {
    #[inline]
    fn from(val: UnixSocketAddr) -> CompoundFarChannelAddr {
        CompoundFarChannelAddr::Unix { unix: val }
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
    type Error = Error;

    #[inline]
    fn try_from(
        val: CompoundFarIPChannelXfrmPeerAddr
    ) -> Result<CompoundFarChannelAddr, Error> {
        match val {
            CompoundFarIPChannelXfrmPeerAddr::UDP { udp } => {
                Ok(CompoundFarChannelAddr::IP { ip: udp })
            }
            CompoundFarIPChannelXfrmPeerAddr::SOCKS5 { .. } => Err(Error::new(
                ErrorKind::Other,
                "cannot convert SOCKS5 address to IP address"
            ))
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
    Unix: DatagramXfrm<LocalAddr = UnixSocketAddr, PeerAddr = UnixSocketAddr>,
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

#[cfg(test)]
use std::sync::Barrier;
#[cfg(test)]
use std::thread::spawn;

#[cfg(test)]
use constellation_common::net::PassthruDatagramXfrm;

#[cfg(test)]
use crate::init;
#[cfg(test)]
use crate::resolve::cache::SharedNSNameCaches;

#[test]
fn test_compound_dtls_unix() {
    init();

    const CHANNEL_PATH: &'static str = "test_compound_dtls_unix_server.sock";
    const CLIENT_PATH: &'static str = "test_compound_dtls_unix_client.sock";

    const CHANNEL_CONFIG: &'static str = concat!(
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
        "  unix:\n",
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
        "  unix:\n",
        "    path: test_compound_dtls_unix_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let channel_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketAddr::try_from(CLIENT_PATH).unwrap()
    );
    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut listener =
            CompoundFarChannel::new(&mut client_nscaches, channel_config)
                .expect("Expected success");
        let param = match listener.acquire().unwrap() {
            CompoundFarChannelAcquired::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected unix acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows: CompoundFarChannelMultiFlows<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();

        client_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();

        client_barrier.wait();

        let nbytes = flow.read(&mut buf).unwrap();

        flow.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let channel_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketAddr::try_from(CHANNEL_PATH).unwrap()
    );
    let mut channel_nscaches = nscaches.clone();
    let channel_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            CompoundFarChannel::new(&mut channel_nscaches, client_config)
                .expect("expected success");
        let param = match conn.acquire().unwrap() {
            CompoundFarChannelAcquired::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected unix acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);

        channel_barrier.wait();

        let mut flows: CompoundFarChannelSingleFlow<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = conn
            .borrowed_flows(param, xfrm, channel_addr.clone())
            .unwrap();
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut flow = BorrowedFlows::flow(
            &mut flows,
            channel_addr.clone(),
            Some(&endpoint)
        )
        .unwrap();

        flow.write_all(&FIRST_BYTES).expect("Expected success");

        channel_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        channel_barrier.wait();

        flow.read_exact(&mut buf).unwrap();

        // assert_eq!(peer_addr, channel_addr);
        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}

#[test]
fn test_compound_dtls_udp() {
    init();

    const CHANNEL_CONFIG: &'static str = concat!(
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
    let channel_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7004".parse().unwrap());
    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut listener =
            CompoundFarChannel::new(&mut client_nscaches, channel_config)
                .expect("Expected success");
        let param = match listener.acquire().unwrap() {
            CompoundFarChannelAcquired::IP {
                ip: CompoundFarIPChannelAcquired::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected UDP acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows: CompoundFarChannelMultiFlows<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();

        client_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();

        client_barrier.wait();

        let nbytes = flow.read(&mut buf).unwrap();

        flow.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let channel_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7003".parse().unwrap());
    let mut channel_nscaches = nscaches.clone();
    let channel_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            CompoundFarChannel::new(&mut channel_nscaches, client_config)
                .expect("expected success");
        let param = match conn.acquire().unwrap() {
            CompoundFarChannelAcquired::IP {
                ip: CompoundFarIPChannelAcquired::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected UDP acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);

        channel_barrier.wait();

        let mut flows: CompoundFarChannelSingleFlow<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = conn
            .borrowed_flows(param, xfrm, channel_addr.clone())
            .unwrap();
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut flow = BorrowedFlows::flow(
            &mut flows,
            channel_addr.clone(),
            Some(&endpoint)
        )
        .unwrap();

        flow.write_all(&FIRST_BYTES).expect("Expected success");

        channel_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        channel_barrier.wait();

        flow.read_exact(&mut buf).unwrap();

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

    const CHANNEL_CONFIG: &'static str = concat!(
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
        "    unix:\n",
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
        "    unix:\n",
        "      path: test_compound_dtls_double_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let channel_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketAddr::try_from(CLIENT_PATH).unwrap()
    );
    let mut client_nscaches = nscaches.clone();
    let client_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut listener =
            CompoundFarChannel::new(&mut client_nscaches, channel_config)
                .expect("Expected success");
        let param = match listener.acquire().unwrap() {
            CompoundFarChannelAcquired::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected unix acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);
        let mut flows: CompoundFarChannelMultiFlows<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = listener.borrowed_flows(param, xfrm, ()).unwrap();

        client_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let (peer_addr, mut flow) = BorrowedFlows::listen(&mut flows).unwrap();

        client_barrier.wait();

        let nbytes = flow.read(&mut buf).unwrap();

        flow.write_all(&SECOND_BYTES).expect("Expected success");

        client_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let channel_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketAddr::try_from(CHANNEL_PATH).unwrap()
    );
    let mut channel_nscaches = nscaches.clone();
    let channel_barrier = barrier;
    let send = spawn(move || {
        let mut conn =
            CompoundFarChannel::new(&mut channel_nscaches, client_config)
                .expect("expected success");
        let param = match conn.acquire().unwrap() {
            CompoundFarChannelAcquired::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected unix acquired")
        };
        let create_param = CompoundXfrmCreateParam::default();
        let xfrm = CompoundFarChannelXfrm::create(&param, &create_param);

        channel_barrier.wait();

        let mut flows: CompoundFarChannelSingleFlow<
            PassthruDatagramXfrm<UnixSocketAddr>,
            PassthruDatagramXfrm<SocketAddr>
        > = conn
            .borrowed_flows(param, xfrm, channel_addr.clone())
            .unwrap();
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut flow = BorrowedFlows::flow(
            &mut flows,
            channel_addr.clone(),
            Some(&endpoint)
        )
        .unwrap();

        flow.write_all(&FIRST_BYTES).expect("Expected success");

        channel_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        channel_barrier.wait();

        flow.read_exact(&mut buf).unwrap();

        assert_eq!(SECOND_BYTES, buf);
    });

    send.join().unwrap();
    listen.join().unwrap();
}
