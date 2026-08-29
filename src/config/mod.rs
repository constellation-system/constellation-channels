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

//! Configuration structures.
//!
//! This module contains definitions of types that supply
//! configuration information.  Each of these types has a YAML format,
//! which can be parsed using `yaml_serde`, thus allowing
//! configurations to be easily loaded from text files.
//!
//! # Near-Link Configurations
//!
//! The following is a list of the different types of near-link
//! channel configuration structures provided by this module:
//!
//! - Flexible, nested channels: provided by [CompoundNearAcceptorConfig] and
//!   [CompoundNearConnectorConfig]
//! - TCP channels: provided by [TCPNearAcceptorConfig] and
//!   [TCPNearConnectorConfig]
//! - Unix domain socket channels: provided by [UnixNearChannelConfig] and
//!   [UnixNearConnectorConfig]
//! - Transport-Layer Security (TLS) channels: provided by
//!   [TLSNearAcceptorConfig] and [TLSNearConnectorConfig]
//! - SOCKS5 proxied channels: provided by [SOCKS5ConnectConfig]
//!
//! # Far-Link Configurations
//!
//! The following is a list of the different types of far-link
//! channel configuration structures provided by this module:
//!
//! - UDP channels: provided by [UDPFarChannelConfig]
//! - Unix domain datagram socket channels: provided by [UnixFarChannelConfig]
//! - Datagram Transport-Layer Security (DTLS) channels: provided by
//!   [DTLSFarChannelConfig]
//! - SOCKS5 UDP association proxied channels: provided by [SOCKS5AssocConfig]
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "gssapi")]
use constellation_common::config::authn::ClientGSSAPIConfig;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::Retry;
use constellation_common::unix::UnixSocketPath;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::MapAccess;
use serde::de::Visitor;
use serde::ser::SerializeStruct;

use crate::config::tls::TLSClientConfig;
use crate::config::tls::TLSLoadClient;
use crate::config::tls::TLSLoadServer;
use crate::config::tls::TLSPeerConfig;
use crate::config::tls::TLSServerConfig;

#[cfg(feature = "tls")]
pub mod tls;

/// Address kind selectors.
///
/// These are used to filter for address types in [AddrsConfig].
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
#[serde(try_from = "&'_ str")]
pub enum AddrKind {
    /// IPv6 addresses.
    ///
    /// The YAML representation of this value is the string `ipv6`.
    IPv6,
    /// IPv4 addresses.
    ///
    /// The YAML representation of this value is the string `ipv4`.
    IPv4
}

/// Address source configuration.
///
/// This controls how often DNS names are resolved, how retries work,
/// and what the address preference is.  This is used primarily to
/// configure a [Resolver](crate::resolve::Resolver).
///
/// # YAML Format
///
/// The YAML format has two fields, one of which is flattened.  There
/// is also a [Default] instance, which provides default values.  The
/// fields are:
///
/// - `addr-policy`: A list (in order of preference) of [AddrKind]s, indicating
///   what address types are allowed.  The default is to allow both IPv6 and
///   IPv4, preferring IPv6.
///
/// - `resolver`: A [ResolverConfig] structure, which is flattened.
///
/// ## Examples
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// addr-policy:
///   - ipv6
/// renewal: 3600
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct AddrsConfig {
    /// Address type preference.
    addr_policy: Vec<AddrKind>,
    #[serde(default)]
    #[serde(flatten)]
    resolver: ResolverConfig
}

/// Configuration for a channel registry.
///
/// This is used to create one or more channel endpoints, which can be
/// referenced by unique names.  This is almost always used in
/// conjunction with far channels, owing to their connectionless
/// semantics.
///
/// # YAML Format
///
/// The YAML format has four fields:
///
///  - `channels`: An array of [ChannelRegistryEntryConfig] structures.
///
///  - `default-resolve`: An [AddrsConfig] structure.  This is optional, and set
///    to the default value if not present.
///
///  - `default-flows-params`: A configuration object for creating the type of
///    traffic splitters used for managing flows. This is optional, and set to
///    the default value if not present.
///
///  - `default-transform-params`: A configuration object for creating the type
///    of base [DatagramXfrm](constellation_common::net::DatagramXfrm) used to
///    create flows.  This is optional, and set to the default value if not
///    present.
///
/// ## Examples
///
/// The following is an example of registry with two entries, with the
/// channel type being configured by a [CompoundFarChannelConfig]:
///
/// ```yaml
/// channels:
///   - id: "example-udp"
///     udp:
///       addr: ::0
///       port: 7777
///
///   - id: "example-unix"
///     unix:
///       path: /var/run/example.sock
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "channel-registry")]
#[serde(rename_all = "kebab-case")]
pub struct FarChannelsConfig<Channel, AuthN, Xfrm>
where
    Xfrm: Default {
    /// Configuration of all channels.
    channels: Vec<FarChannelEntryConfig<Channel, AuthN, Xfrm>>,
    /// Resolver configuration.
    #[serde(default)]
    default_resolve: AddrsConfig,
    /// Default authentication config.
    default_authn: AuthN,
    /// Context creation parameters.
    #[serde(default)]
    default_xfrm_params: Xfrm,
    /// Flows creation parameters.
    #[serde(default)]
    default_flows_params: FlowsConfig,
    /// Retry configuration.
    #[serde(
        default = "FarChannelsConfig::<Channel, AuthN, Xfrm>::default_retry_value"
    )]
    default_retry: Retry,
    #[serde(default)]
    default_flows_size_hint: Option<usize>
}

/// Configuration parameters for stream creation for
/// [FarChannelRegistry](crate::far::registry::FarChannelRegistry).
///
/// This is a configuration object used to configure the stream
/// creation for
/// [FarChannelRegistry](crate::far::registry::FarChannelRegistry).
///
/// # YAML Format
///
/// The YAML format has one field:
///
///  - `codec`: Parameters used to create the
///    [DatagramCodec](constellation_common::codec::DatagramCodec) instances
///    used to encode and decode messages.
#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "channels")]
#[serde(rename_all = "kebab-case")]
pub struct FarChannelRegistryChannelsConfig<Codec>
where
    Codec: Default {
    codec: Codec
}

/// Entry for a single channel in the channel registry.
///
/// This is used to configure a single entry in a channel registry.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
///  - `id`: Contains a unique name for the channel in this registry.
///
///  - `channel`: Contains a channel configuration.  This field is flattened.
///
/// ## Examples
///
/// The following is an example of a single entry, with the channel
/// type being configured by a [CompoundFarChannelConfig]:
///
/// ```yaml
/// id: "example"
/// udp:
///   addr: ::0
///   port: 7777
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "far-channel-entry")]
#[serde(rename_all = "kebab-case")]
pub struct FarChannelEntryConfig<Channel, AuthN, Xfrm>
where
    Xfrm: Default {
    /// Unique name of the channel.
    id: String,
    /// Channel configuration.
    #[serde(flatten)]
    channel: Channel,
    /// Authenticator configuration.
    #[serde(
        default = "FarChannelEntryConfig::<Channel, AuthN, Xfrm>::default_authn"
    )]
    authn: Option<AuthN>,
    /// Resolver configuration.
    #[serde(default)]
    resolve: Option<AddrsConfig>,
    /// Context creation parameters.
    #[serde(default)]
    xfrm_params: Option<Xfrm>,
    /// Flows creation parameters.
    #[serde(default)]
    flows_params: Option<FlowsConfig>,
    /// Retry configuration.
    #[serde(default)]
    retry: Option<Retry>,
    #[serde(default)]
    flows_size_hint: Option<usize>
}

/// Creation parameters for
/// [CompoundFarChannelXfrm](crate::far::compound::CompoundFarChannelXfrm)
/// instances.
///
/// This specifies the creation parameters used for the base-level
/// [DatagramXfrm](constellation_common::net::DatagramXfrm) instances
/// used in
/// [CompoundFarChannelXfrm](crate::far::compound::CompoundFarChannelXfrm).
/// In most ordinary use, the default value of this configuration
/// object will be used, and no configuration information will need to
/// be provided.
///
/// In more elaborate uses, this object allows different configuration
/// parameters to be provided for
/// [DatagramXfrm](constellation_common::net::DatagramXfrm) instances
/// underlying Unix datagram and UDP channels.  This allows the
/// base-level transforms to be customized to each channel type.
///
/// # YAML Format
///
/// The YAML format has two fields, both of which have default values:
///
///  - `unix`: Creation parameters for the
///    [DatagramXfrm](constellation_common::net::DatagramXfrm) instance used for
///    Unix socket channels.
///
///  - `udp`: Creation parameters for the
///    [DatagramXfrm](constellation_common::net::DatagramXfrm) instance used for
///    UDP socket channels.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "xfrm-params")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct CompoundXfrmCreateParam<Unix, UDP> {
    #[serde(default)]
    unix: Unix,
    #[serde(default)]
    udp: UDP
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(untagged)]
pub enum CompoundNearConnectorParam {
    TLS {
        tls: Box<TLSParam<Option<CompoundNearConnectorParam>>>
    }
}

/// Endpoint for
/// [CompoundFarChannel](crate::far::compound::CompoundFarChannel)s.
///
/// # YAML Format
///
/// The YAML format has two variants:
///
///  - `unix`: A path to a Unix socket.
///
///  - `ip`: An [IPEndpoint] structure.
#[derive(
    Clone, Debug, Eq, Deserialize, Hash, PartialEq, PartialOrd, Serialize,
)]
#[serde(untagged)]
pub enum CompoundFarEndpoint {
    /// Unix socket address.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Path to the Unix socket.
        unix_datagram: PathBuf
    },
    /// UDP endpoint.
    UDP {
        /// IP address and port
        udp: IPEndpoint
    }
}

/// Peer addresses that can occur in [CompoundFarIPChannel]s.
#[derive(
    Clone, Debug, Eq, Deserialize, Hash, PartialEq, PartialOrd, Serialize,
)]
#[serde(untagged)]
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
#[derive(
    Clone, Debug, Eq, Deserialize, Hash, PartialEq, PartialOrd, Serialize,
)]
#[serde(untagged)]
pub enum CompoundFarChannelXfrmPeerAddr {
    #[cfg(feature = "unix")]
    Unix {
        #[serde(rename = "unix-datagram")]
        unix: UnixSocketPath
    },
    IP {
        #[serde(flatten)]
        ip: CompoundFarIPChannelXfrmPeerAddr
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CompoundOutboundNegotiatorParam {
    Basic,
    DTLS {
        dtls: Box<DTLSOutboundParam<CompoundOutboundNegotiatorParam>>
    }
}

/// Compound IP-only far-link channel configuration.
///
/// This is a subset of [CompoundFarChannelConfig] that contains only
/// IP-based protocols (no Unix sockets).  It is not configured
/// directly, and instead exists for deriving configurations as part
/// of the operation of
/// [SOCKS5FarChannel](crate::far::socks5::SOCKS5FarChannel).  The
/// following channel types are supported:
///
/// - [UDPFarChannel](crate::far::udp::UDPFarChannel)
/// - [DTLSFarChannel](crate::far::dtls::DTLSFarChannel)
/// - [SOCKS5FarChannel](crate::far::socks5::SOCKS5FarChannel)
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundFarIPChannelConfig {
    /// UDP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// UDP connection.
    UDP {
        /// UDP socket configuration.
        udp: UDPFarChannelConfig
    },
    /// DTLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// DTLS connection.
    #[serde(rename_all = "kebab-case")]
    DTLS {
        /// DTLS session negotiation configuration.
        dtls: Box<DTLSFarChannelConfig<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5_udp: Box<
            SOCKS5AssocConfig<
                CompoundResolvingNearConnectorConfig<TLSPeerConfig>,
                CompoundFarIPChannelConfig
            >
        >
    }
}

/// Compound far-link channel configuration.
///
/// This represents the configuration for
/// [CompoundFarChannel](crate::far::compound::CompoundFarChannel)s.  These
/// allow any of the far-link channel types provided by this package
/// to be configured using a single interface.  This includes the
/// following channel types:
///
/// - [UnixFarChannel](crate::far::unix::UnixFarChannel)
/// - [UDPFarChannel](crate::far::udp::UDPFarChannel)
/// - [DTLSFarChannel](crate::far::dtls::DTLSFarChannel)
/// - [SOCKS5FarChannel](crate::far::socks5::SOCKS5FarChannel)
///
/// Compound far-links can also be configured recursively, allowing
/// for arbitrarily-complex nested channel configurations.
///
/// # YAML Format
///
/// The YAML format has four options, each corresponding to the four
/// different channel types:
///
/// - `unix-datagram`: Contains a [UnixFarChannelConfig], and creates a
///   [UnixFarChannel](crate::far::unix::UnixFarChannel).
///
/// - `udp`: Contains a [UDPFarChannelConfig], and creates a
///   [UDPFarChannel](crate::far::udp::UDPFarChannel).
///
/// - `dtls`: Contains a [DTLSFarChannelConfig], and creates a
///   [DTLSFarChannel](crate::far::dtls::DTLSFarChannel).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundFarConnectorConfig`.
///
/// - `socks5-udp`: Contains a [SOCKS5AssocConfig], and creates a
///   [SOCKS5FarChannel](crate::far::socks5::SOCKS5FarChannel).  The channel
///   configuration under the `proxy` of this structure is an instance of
///   [CompoundNearConnectorConfig].
///
/// ## Examples
///
/// The following are examples of different possible configurations.
/// Note that because of the recursive nature of compound far-link
/// configurations, there are many more possibilities.
///
/// ### DTLS Over Local SOCKS5
///
/// The following configuration shows a DTLS channel going through a
/// SOCKS5 proxy, which is reached via a Unix socket to negotiate the
/// UDP association, and then packets are sent through a UDP socket:
///
/// ```yaml
/// dtls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   cert: /etc/ssl/certs/client-cert.pem
///   cert-chain: /etc/ssl/certs/client-chain.pem
///   key: /etc/ssl/private/client-key.pem
///   trust-root:
///     root-certs:
///       - /etc/ssl/certs/server-ca-cert.pem
///     crls:
///       - /etc/ssl/crls/server-ca-crl.pem
///   socks5:
///     proxy:
///       unix-datagram:
///         path: /var/run/proxy/proxy.sock
///     addr: ::1
///     port: 5000
/// ```
///
/// ### DTLS Over Secured Remote SOCKS5
///
/// The following configuration shows a DTLS session going through
/// a SOCKS5 proxy, which is reached via a second DTLS connection over
/// UDP:
///
/// ```yaml
/// dtls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   cert: /etc/ssl/certs/client-cert.pem
///   cert-chain: /etc/ssl/certs/client-chain.pem
///   key: /etc/ssl/private/client-key.pem
///   trust-root:
///     dirs:
///       - /etc/ssl/CA/
///   socks5-udp:
///     proxy:
///       tls:
///         cipher-suites:
///           - TLS_AES_256_GCM_SHA384
///         key-exchange-groups:
///           - P-521
///           - P-384
///         signature-algorithms:
///           - ecdsa_secp521r1_sha512
///           - ecdsa_secp384r1_sha384
///         verify-endpoint: test.example.com
///         trust-root:
///           root-certs:
///             - /etc/ssl/certs/proxy-ca-cert.pem
///           crls:
///             - /etc/ssl/crls/proxy-ca-crl.pem
///         tcp:
///           addr: proxy.example.com
///           port: 9050
///     dtls:
///       cipher-suites:
///         - TLS_AES_256_GCM_SHA384
///       key-exchange-groups:
///         - P-521
///         - P-384
///       signature-algorithms:
///         - ecdsa_secp521r1_sha512
///         - ecdsa_secp384r1_sha384
///       verify-endpoint: test.example.com
///       cert: /etc/ssl/certs/client-cert.pem
///       cert-chain: /etc/ssl/certs/client-chain.pem
///       key: /etc/ssl/private/client-key.pem
///       trust-root:
///         root-certs:
///           - /etc/ssl/certs/proxy-ca-cert.pem
///         crls:
///           - /etc/ssl/crls/proxy-ca-crl.pem
///       udp:
///         addr: ::0
///         port: 0
/// ```
///
/// ### Double SOCKS5 Proxies
///
/// The following configuration shows a channel going through *two*
/// SOCKS5 proxies (no DTLS configurations are included here), the
/// first layer being a GSSAPI-authenticated proxy at
/// `proxy.example.com`, and the second being a password-authenticated
/// proxy at `tor.nowhere.com`:
///
/// ```yaml
/// socks5-udp:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   auth:
///     username: test
///     password: abc123
///   socks5-udp:
///     proxy:
///       tcp:
///         addr: proxy.example.com
///         port: 8888
///     auth: gssapi
///     udp:
///       addr: ::0
///       port: 0
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundFarChannelConfig {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix_datagram: UnixFarChannelConfig
    },
    /// UDP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// UDP connection.
    UDP {
        /// UDP socket configuration.
        udp: UDPFarChannelConfig
    },
    /// DTLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// DTLS connection.
    #[serde(rename_all = "kebab-case")]
    DTLS {
        /// DTLS session negotiation configuration.
        dtls: Box<DTLSFarChannelConfig<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5_udp: Box<
            SOCKS5AssocConfig<
                CompoundResolvingNearConnectorConfig<TLSPeerConfig>,
                CompoundFarIPChannelConfig
            >
        >
    }
}

#[derive(
    Clone, Debug, Eq, Deserialize, Hash, PartialEq, PartialOrd, Serialize,
)]
#[serde(untagged)]
pub enum CompoundNearEndpoint {
    /// Unix socket address.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Path to the Unix socket.
        unix_stream: PathBuf
    },
    /// TCP endpoint.
    TCP {
        /// IP address and port
        tcp: IPEndpoint
    }
}

/// Compound server-side near-link configuration.
///
/// This represents the configuration for
/// [CompoundNearAcceptor](crate::near::compound::CompoundNearAcceptor)s.
/// These allow any of the server-side near-link channel types
/// provided by this package to be configured as a near-link acceptor.
/// This includes the following channel types:
///
/// - [UnixNearAcceptor](crate::near::unix::UnixNearAcceptor)
/// - [TCPNearAcceptor](crate::near::tcp::TCPNearAcceptor)
/// - [TLSNearAcceptor](crate::near::tls::TLSNearAcceptor)
///
/// Compound near-links can also be configured recursively, allowing
/// for arbitrarily-complex nested channel configurations.
///
/// Note that SOCKS5 acceptors are *not* supported, as [RFC
/// 1928](https://datatracker.ietf.org/doc/html/rfc1928) does not
/// provide any means of setting up such an arrangement.  (Note that
/// the `bind` command is for FTP-type protocols, where the server
/// establishes a connection to the client, not for binding to a
/// remote port for arbitrary connections.)
///
/// # YAML Format
///
/// The YAML format has four options, each corresponding to the four
/// different channel types:
///
/// - `unix-stream`: Contains a [UnixNearChannelConfig], and creates a
///   [UnixNearAcceptor](crate::near::unix::UnixNearAcceptor).
///
/// - `tcp`: Contains a [TCPNearAcceptorConfig], and creates a
///   [TCPNearAcceptor](crate::near::tcp::TCPNearAcceptor).
///
/// - `tls`: Contains a [TLSNearAcceptorConfig], and creates a
///   [TLSNearAcceptor](crate::near::tls::TLSNearAcceptor).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundNearAcceptorConfig`.
///
/// ## Examples
///
/// The following are example configurations.
///
/// ### TLS Over TCP
///
/// The following example shows how to listen on a TCP port, which
/// will then be used to establish TLS sessions:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-auth:
///     verify: optional
///     trust-root:
///       root-certs:
///         - /etc/ssl/certs/client-ca-cert.pem
///       crls:
///         - /etc/ssl/crls/client-ca-crl.pem
///   cert: /etc/ssl/certs/server-cert.pem
///   cert-chain: /etc/ssl/certs/server-cert-chain.pem
///   key: /etc/ssl/private/key.pem
///   tcp:
///     addr: ::0
///     port: 5001
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundNearAcceptorConfig<TLS: TLSLoadServer> {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix_stream: UnixNearChannelConfig
    },
    /// TCP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TCP connection.
    TCP { tcp: TCPNearAcceptorConfig },
    /// TLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TLS connection.
    #[serde(rename_all = "kebab-case")]
    TLS {
        tls: TLSChannelConfig<TLS, Box<Self>>
    }
}

/// Compound client-side near-link configuration.
///
/// This represents the configuration for
/// [CompoundNearConnector](crate::near::compound::CompoundNearConnector)s.
/// These allow any of the client-side near-link channel types
/// provided by this package to be configured as a near-link
/// connector.  This includes the following channel types:
///
/// - [UnixNearConnector](crate::near::unix::UnixNearConnector)
/// - [TCPNearConnector](crate::near::tcp::TCPNearConnector)
/// - [TLSNearConnector](crate::near::tls::TLSNearConnector)
/// - [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector)
///
/// Compound near-links can also be configured recursively, allowing
/// for arbitrarily-complex nested channel configurations.
///
/// # YAML Format
///
/// The YAML format has four options, each corresponding to the four
/// different channel types:
///
/// - `unix-stream`: Contains a [UnixNearConnectorConfig], and creates a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector).
///
/// - `tcp`: Contains a [TCPResolvingNearConnectorConfig], and creates a
///   [TCPResolvingNearConnector](crate::near::tcp::TCPResolvingNearConnector).
///
/// - `tls`: Contains a [TLSNearConnectorConfig], and creates a
///   [TLSNearConnector](crate::near::tls::TLSNearConnector).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundNearConnectorConfig`.
///
/// - `socks5-tcp`: Contains a [SOCKS5ConnectConfig], and creates a
///   [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector). The
///   channel configuration under the `proxy` of this structure is another
///   instance of `CompoundNearConnectorConfig`.
///
/// ## Examples
///
/// The following are examples of different possible configurations.
/// Note that because of the recursive nature of compound near-link
/// configurations, there are many more possibilities.
///
/// ### TLS Over Local SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a Unix socket:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     root-certs:
///       - /etc/ssl/certs/server-ca-cert.pem
///     crls:
///       - /etc/ssl/crls/server-ca-crl.pem
///   socks5-tcp:
///     proxy:
///       unix-stream:
///         path: /var/run/proxy/proxy.sock
///     target:
///       addr: en.wikipedia.org
///       port: 443
/// ```
///
/// ### TLS Over Secured Remote SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a second TLS connection over TCP:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     dirs:
///       - /etc/ssl/CA/
///   socks5:
///     proxy:
///       tls:
///         cipher-suites:
///           - TLS_AES_256_GCM_SHA384
///         key-exchange-groups:
///           - P-521
///           - P-384
///         signature-algorithms:
///           - ecdsa_secp521r1_sha512
///           - ecdsa_secp384r1_sha384
///         verify-endpoint: test.example.com
///         trust-root:
///           root-certs:
///             - /etc/ssl/certs/proxy-ca-cert.pem
///           crls:
///             - /etc/ssl/crls/proxy-ca-crl.pem
///         tcp:
///           addr: proxy.example.com
///           port: 9050
///     target:
///       addr: en.wikipedia.org
///       port: 443
/// ```
///
/// ### Double SOCKS5 Proxies
///
/// The following configuration shows a connection going through *two*
/// SOCKS5 proxies (no TLS configurations are included here), the
/// first layer being a GSSAPI-authenticated proxy at
/// `proxy.example.com`, and the second being a password-authenticated
/// proxy at `tor.nowhere.com`:
///
/// ```yaml
/// socks5:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   target:
///     addr: en.wikipedia.org
///     port: 80
///   auth:
///     username: test
///     password: abc123
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundResolvingNearConnectorConfig<TLS>
where
    TLS: TLSLoadClient {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix_stream: UnixNearChannelConfig
    },
    /// TCP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TCP connection.
    TCP {
        /// TCP socket configuration.
        tcp: TCPResolvingNearConnectorConfig
    },
    /// TLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TLS connection.
    #[serde(rename_all = "kebab-case")]
    TLS {
        /// TLS session negotiation configuration.
        tls: TLSChannelConfig<TLS, Box<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5_tcp: SOCKS5ConnectConfig<Box<Self>>
    }
}

/// Compound client-side near-link partial configuration.
///
/// This represents the configuration for
/// [CompoundNearConnector](crate::near::compound::CompoundNearConnector)s.
/// These allow any of the client-side near-link channel types
/// provided by this package to be configured as a near-link
/// connector.  This includes the following channel types:
///
/// - [UnixNearConnector](crate::near::unix::UnixNearConnector)
/// - [TCPNearConnector](crate::near::tcp::TCPNearConnector)
/// - [TLSNearConnector](crate::near::tls::TLSNearConnector)
/// - [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector)
///
/// Compound near-links can also be configured recursively, allowing
/// for arbitrarily-complex nested channel configurations.
///
/// # YAML Format
///
/// The YAML format has four options, each corresponding to the four
/// different channel types:
///
/// - `unix-stream`: Contains a [UnixNearConnectorPartialConfig], and creates a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector).
///
/// - `tcp`: Contains a [TCPResolvingNearConnectorPartialConfig], and creates a
///   [TCPResolvingNearConnector](crate::near::tcp::TCPResolvingNearConnector).
///
/// - `tls`: Contains a [TLSNearConnectorConfig], and creates a
///   [TLSNearConnector](crate::near::tls::TLSNearConnector).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundNearConnectorPartialConfig`.
///
/// - `socks5-tcp`: Contains a [SOCKS5ConnectConfig], and creates a
///   [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector). The
///   channel configuration under the `proxy` of this structure is another
///   instance of `CompoundNearConnectorPartialConfig`.
///
/// ## Examples
///
/// The following are examples of different possible configurations.
/// Note that because of the recursive nature of compound near-link
/// configurations, there are many more possibilities.
///
/// ### TLS Over Local SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a Unix socket:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     root-certs:
///       - /etc/ssl/certs/server-ca-cert.pem
///     crls:
///       - /etc/ssl/crls/server-ca-crl.pem
///   socks5-tcp:
///     proxy:
///       unix-stream:
///         path: /var/run/proxy/proxy.sock
/// ```
///
/// ### TLS Over Secured Remote SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a second TLS connection over TCP:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     dirs:
///       - /etc/ssl/CA/
///   socks5:
///     proxy:
///       tls:
///         cipher-suites:
///           - TLS_AES_256_GCM_SHA384
///         key-exchange-groups:
///           - P-521
///           - P-384
///         signature-algorithms:
///           - ecdsa_secp521r1_sha512
///           - ecdsa_secp384r1_sha384
///         verify-endpoint: test.example.com
///         trust-root:
///           root-certs:
///             - /etc/ssl/certs/proxy-ca-cert.pem
///           crls:
///             - /etc/ssl/crls/proxy-ca-crl.pem
///         tcp:
///           addr: proxy.example.com
///           port: 9050
/// ```
///
/// ### Double SOCKS5 Proxies
///
/// The following configuration shows a connection going through *two*
/// SOCKS5 proxies (no TLS configurations are included here), the
/// first layer being a GSSAPI-authenticated proxy at
/// `proxy.example.com`, and the second being a password-authenticated
/// proxy at `tor.nowhere.com`:
///
/// ```yaml
/// socks5:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   auth:
///     username: test
///     password: abc123
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundResolvingNearConnectorPartialConfig<TLS: TLSLoadClient> {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix_stream: Option<UnixNearConnectorPartialConfig>
    },
    /// TCP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TCP connection.
    TCP {
        /// TCP socket configuration.
        tcp: Option<TCPResolvingNearConnectorPartialConfig>
    },
    /// TLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TLS connection.
    #[serde(rename_all = "kebab-case")]
    TLS {
        /// TLS session negotiation configuration.
        tls: TLSChannelConfig<TLS, Box<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5_tcp: SOCKS5ConnectPartialConfig<
            Box<CompoundResolvingNearConnectorConfig<TLS>>
        >
    }
}

/// Compound client-side near-link partial configuration.
///
/// This represents the configuration for
/// [CompoundNearConnector](crate::near::compound::CompoundNearConnector)s.
/// These allow any of the client-side near-link channel types
/// provided by this package to be configured as a near-link
/// connector.  This includes the following channel types:
///
/// - [UnixNearConnector](crate::near::unix::UnixNearConnector)
/// - [TCPNearConnector](crate::near::tcp::TCPNearConnector)
/// - [TLSNearConnector](crate::near::tls::TLSNearConnector)
/// - [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector)
///
/// Compound near-links can also be configured recursively, allowing
/// for arbitrarily-complex nested channel configurations.
///
/// # YAML Format
///
/// The YAML format has four options, each corresponding to the four
/// different channel types:
///
/// - `unix-stream`: Contains a [UnixNearConnectorPartialConfig], and creates a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector).
///
/// - `tcp`: Contains a [TCPNearConnectorPartialConfig], and creates a
///   [TCPNearConnector](crate::near::tcp::TCPNearConnector).
///
/// - `tls`: Contains a [TLSNearConnectorConfig], and creates a
///   [TLSNearConnector](crate::near::tls::TLSNearConnector).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundNearConnectorPartialConfig`.
///
/// - `socks5-tcp`: Contains a [SOCKS5ConnectConfig], and creates a
///   [SOCKS5NearConnector](crate::near::socks5::SOCKS5NearConnector). The
///   channel configuration under the `proxy` of this structure is another
///   instance of `CompoundNearConnectorPartialConfig`.
///
/// ## Examples
///
/// The following are examples of different possible configurations.
/// Note that because of the recursive nature of compound near-link
/// configurations, there are many more possibilities.
///
/// ### TLS Over Local SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a Unix socket:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     root-certs:
///       - /etc/ssl/certs/server-ca-cert.pem
///     crls:
///       - /etc/ssl/crls/server-ca-crl.pem
///   socks5-tcp:
///     proxy:
///       unix-stream:
///         path: /var/run/proxy/proxy.sock
/// ```
///
/// ### TLS Over Secured Remote SOCKS5
///
/// The following configuration shows a TLS connection going through a
/// SOCKS5 proxy, which is reached via a second TLS connection over TCP:
///
/// ```yaml
/// tls:
///   cipher-suites:
///     - TLS_AES_256_GCM_SHA384
///   key-exchange-groups:
///     - P-521
///     - P-384
///   signature-algorithms:
///     - ecdsa_secp521r1_sha512
///     - ecdsa_secp384r1_sha384
///   client-cert: /etc/ssl/certs/client-cert.pem
///   client-cert-chain: /etc/ssl/certs/client-chain.pem
///   client-key: /etc/ssl/private/client-key.pem
///   trust-root:
///     dirs:
///       - /etc/ssl/CA/
///   socks5:
///     proxy:
///       tls:
///         cipher-suites:
///           - TLS_AES_256_GCM_SHA384
///         key-exchange-groups:
///           - P-521
///           - P-384
///         signature-algorithms:
///           - ecdsa_secp521r1_sha512
///           - ecdsa_secp384r1_sha384
///         verify-endpoint: test.example.com
///         trust-root:
///           root-certs:
///             - /etc/ssl/certs/proxy-ca-cert.pem
///           crls:
///             - /etc/ssl/crls/proxy-ca-crl.pem
///         tcp:
///           addr: 127.0.0.1
///           port: 9050
/// ```
///
/// ### Double SOCKS5 Proxies
///
/// The following configuration shows a connection going through *two*
/// SOCKS5 proxies (no TLS configurations are included here), the
/// first layer being a GSSAPI-authenticated proxy at
/// `proxy.example.com`, and the second being a password-authenticated
/// proxy at `tor.nowhere.com`:
///
/// ```yaml
/// socks5:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   auth:
///     username: test
///     password: abc123
/// ```
#[derive(Clone, Debug, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum CompoundNearConnectorPartialConfig<TLS: TLSLoadClient> {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix_stream: Option<UnixNearConnectorPartialConfig>
    },
    /// TCP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TCP connection.
    #[serde(rename_all = "kebab-case")]
    TCP {
        /// TCP socket configuration.
        tcp: Option<TCPNearConnectorPartialConfig>
    },
    /// TLS channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TLS connection.
    #[serde(rename_all = "kebab-case")]
    TLS {
        /// TLS session negotiation configuration.
        tls: TLSChannelConfig<TLS, Box<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5_tcp: SOCKS5ConnectPartialConfig<
            Box<CompoundResolvingNearConnectorConfig<TLS>>
        >
    }
}

/// DTLS far-link channel configuration.
///
/// This holds common configuration information for far-link channels
/// over Datagram Transport-Layer Security (DTLS) over an underlying
/// channel given by the type parameter `Inner`.
///
/// # YAML Format
///
/// The YAML format has two groups of fields:
///
/// - A [TLSChannelConfig] structure with [TLSPeerConfig] as its `TLS`
///   parameter, which is flattened.
///
/// - An optional [Retry] configuration, describing how to retry failed
///   negotiation attempts.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with a
/// [UDPFarChannelConfig] as the underlying channel configuration
/// with all fields represented:
///
/// ```yaml
/// cipher-suites:
///   - TLS_AES_256_GCM_SHA384
/// key-exchange-groups:
///   - P-521
///   - P-384
/// signature-algorithms:
///   - ecdsa_secp521r1_sha512
///   - ecdsa_secp384r1_sha384
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/peer-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/peer-ca-crl.pem
/// cert: /etc/ssl/certs/peer-cert.pem
/// cert-chain: /etc/ssl/certs/peer-cert-chain.pem
/// key: /etc/ssl/private/key.pem
/// addr: ::0
/// port: 5002
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration:
///
/// ```yaml
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/peer-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/peer-ca-crl.pem
/// cert: /etc/ssl/certs/peer-cert.pem
/// key: /etc/ssl/private/key.pem
/// addr: ::0
/// port: 5003
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "dtls")]
#[serde(rename_all = "kebab-case")]
pub struct DTLSFarChannelConfig<Inner> {
    #[serde(flatten)]
    tls: TLSChannelConfig<TLSPeerConfig, Inner>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "dtls-param")]
#[serde(rename_all = "kebab-case")]
pub struct DTLSOutboundParam<Inner> {
    verify_endpoint: IPEndpointAddr,
    #[serde(default)]
    inner: Inner
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "dtls")]
#[serde(rename_all = "kebab-case")]
pub struct FlowsConfig {
    msg_size: usize,
    #[serde(default)]
    buf_size: Option<usize>,
    #[serde(default)]
    num_flows: Option<usize>,
    #[serde(default)]
    num_negotiations: Option<usize>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "near-channels-outbound-entry")]
#[serde(rename_all = "kebab-case")]
pub struct NearChannelOutboundEntryConfig<Out, AuthN> {
    /// Channel ID.
    id: String,
    /// Outbound connector configuration.
    #[serde(flatten)]
    connect: Out,
    /// Entry-specific authenticator configuration.
    #[serde(
        default = "NearChannelOutboundEntryConfig::<Out, AuthN>::default_authn"
    )]
    authn: Option<AuthN>,
    /// Retry configuration for connections.
    #[serde(default)]
    retry: Option<Retry>,
    /// Size hint for number of sessions.
    #[serde(default)]
    num_sessions: Option<usize>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "near-channels-inbound-entry")]
#[serde(rename_all = "kebab-case")]
pub struct NearChannelInboundEntryConfig<In, AuthN> {
    /// Channel ID.
    id: String,
    /// Inbound acceptor configuration.
    #[serde(flatten)]
    listen: In,
    /// Entry-specific authenticator configuration.
    #[serde(
        default = "NearChannelInboundEntryConfig::<In, AuthN>::default_authn"
    )]
    authn: Option<AuthN>,
    /// Retry configuration for connections.
    #[serde(default)]
    retry: Option<Retry>,
    /// Size hint for number of sessions.
    #[serde(default)]
    num_sessions: Option<usize>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "near-channels-duplex-entry")]
#[serde(rename_all = "kebab-case")]
pub struct NearChannelDuplexEntryConfig<In, Out, InAuthN, OutAuthN> {
    /// Channel ID.
    id: String,
    /// Inbound acceptor configuration.
    listen: In,
    /// Outbound connector configuration.
    connect: Out,
    /// Entry-specific authenticator configuration.
    #[serde(
        default = "NearChannelDuplexEntryConfig::<In, Out, InAuthN, OutAuthN>::default_in_authn"
    )]
    inbound_authn: Option<InAuthN>,
    /// Entry-specific authenticator configuration.
    #[serde(
        default = "NearChannelDuplexEntryConfig::<In, Out, InAuthN, OutAuthN>::default_out_authn"
    )]
    outbound_authn: Option<OutAuthN>,
    /// Retry configuration for connections.
    #[serde(default)]
    retry: Option<Retry>,
    /// Size hint for number of sessions.
    #[serde(default)]
    num_sessions: Option<usize>
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "near-channels-entry")]
#[serde(untagged)]
pub enum NearChannelEntryConfig<In, Out, InAuthN, OutAuthN> {
    Inbound {
        inbound: NearChannelInboundEntryConfig<In, InAuthN>
    },
    Outbound {
        outbound: NearChannelOutboundEntryConfig<Out, OutAuthN>
    },
    Duplex {
        duplex: NearChannelDuplexEntryConfig<In, Out, InAuthN, OutAuthN>
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "near-channels-config")]
#[serde(rename_all = "kebab-case")]
pub struct NearChannelsConfig<In, Out, InAuthN, OutAuthN> {
    /// Configuration of all channels.
    channels: Vec<NearChannelEntryConfig<In, Out, InAuthN, OutAuthN>>,
    /// Default authentication configuration.
    #[serde(default)]
    default_inbound_authn: InAuthN,
    #[serde(default)]
    default_outbound_authn: OutAuthN,
    /// Default retry configuration.
    #[serde(
        default = "NearChannelsConfig::<In, Out, InAuthN, OutAuthN>::default_retry_value"
    )]
    default_retry: Retry,
    #[serde(default)]
    default_num_sessions: Option<usize>
}

/// Name resolution configuration.
///
/// This controls how often DNS names are resolved, how retries work,
/// and what the address preference is.  This is used primarily to
/// configure a [Resolver](crate::resolve::Resolver).
///
/// # YAML Format
///
/// The YAML format has three fields.  There is also a [Default]
/// instance, which provides default values.  The fields are:
///
/// - `renewal`: The renewal period in seconds, after which names will be
///   re-resolved.  The default is 10800 seconds, or 3 hours.
///
/// - `retry`: The [Retry] configuration for failed resolutions.  The default
///   instance for `Retry` will be used if this field is absent.
///
/// ## Examples
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// addr-policy:
///   - ipv6
/// renewal: 3600
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct ResolverConfig {
    /// Renewal period in seconds.
    renewal: usize,
    /// Retry configuration.
    #[serde(default)]
    retry: Retry
}

/// Client authentication configurations for SOCKS5.
///
/// This controls how a SOCKS5 client will authenticate to the proxy,
/// and provides the authentication materials.
///
/// # YAML Format
///
/// There are three options for SOCKS5 authentication, each of which
/// has a different YAML format:
///
/// - No authentication: this is the default option, and an empty specification
///   will yield this.
///
/// - Password authentication: a specification for password authentication has
///   two fields, both of which are mandatory:
///
///   - `username`: The username, as a string.
///   - `password`: The password, as a string.
///
/// - GSSAPI authentication: a GSSAPI specification can be given in one of two
///   ways.
///
///   - A field named `gssapi`, which contains a [ClientGSSAPIConfig].
///
///   - The string `gssapi`, which will yield the [Default] configuration for a
///     `ClientGSSAPIConfig`.
///
/// ## Examples
///
/// The following are example YAML specifications.
///
/// ### Password Authentication
///
/// The following is an example of a password authentication
/// specification:
///
/// ```yaml
/// username: user
/// password: abc123
/// ```
///
/// ### GSSAPI
///
/// The following is an example of a GSSAPI authentication
/// specification:
///
/// ```yaml
/// gssapi:
///   name: test
///   service: service
///   security:
///     required: 128
/// ```
///
/// # GSSAPI Defaults
///
/// The following specification gives the GSSAPI defaults:
///
/// ```yaml
/// gssapi
/// ```
#[derive(
    Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
#[serde(rename = "authn")]
#[serde(untagged)]
#[serde(try_from = "SOCKS5AuthNIntermediate")]
pub enum SOCKS5AuthNConfig {
    /// No authentication.
    #[serde(rename_all = "kebab-case")]
    #[default]
    None,
    /// Username/password authentication.
    #[serde(rename_all = "kebab-case")]
    Password {
        /// The username.
        username: String,
        /// The password.
        password: String
    },
    #[cfg(feature = "gssapi")]
    #[serde(rename_all = "kebab-case")]
    GSSAPI {
        /// Client-side GSSAPI configuration.
        gssapi: ClientGSSAPIConfig
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename = "authn")]
#[serde(untagged)]
enum SOCKS5AuthNIntermediate {
    /// No authentication.
    #[serde(rename_all = "kebab-case")]
    Name(String),
    /// Username/password authentication.
    #[serde(rename_all = "kebab-case")]
    Password { username: String, password: String },
    #[cfg(feature = "gssapi")]
    #[serde(rename_all = "kebab-case")]
    GSSAPI { gssapi: ClientGSSAPIConfig }
}

/// SOCKS5 far-link channel configuration.
///
/// This holds common configuration information for client-side
/// far-link channels over a SOCKS5 proxy using UDP association.
///
/// # YAML Format
///
/// The YAML format has three fields:
///
/// - `proxy`: The underlying channel configuration for connecting to the SOCKS5
///   proxy.  Note that this is a *near*-link, not a far-link.
///
/// - `forward`: A [SocketAddr], specifying the datagram channel through which
///   forwarded traffic will be sent to the proxy.  This field is flattened
///
/// - `auth`: A [SOCKS5AuthNConfig], specifying how to authenticate to the
///   SOCKS5 proxy.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with a
/// [TCPNearAcceptorConfig] as the proxy channel configuration
/// with all fields represented:
///
/// ```yaml
/// proxy:
///   retry:
///     factor: 100
///     exp-base: 2.0
///     exp-factor: 1.0
///     exp-rounds-cap: 20
///     linear-factor: 1.0
///     linear-rounds-cap: 50
///     max-random: 100
///     addend: 50
///   resolve:
///     addr-policy:
///       - ipv6
///     renewal: 3600000
///     retry:
///       factor: 400
///       exp-base: 2.0
///       exp-factor: 2.0
///   addr: proxy.example.com
///   port: 9050
/// password:
///   username: user
///   password: abc123
/// addr: ::0
/// port: 0
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration:
///
/// ```yaml
/// proxy:
///   addr: proxy.example.com
///   port: 9050
/// auth:
///   password:
///     username: user
///     password: abc123
/// addr: ::0
/// port: 0
/// ```
///
/// ## Nested SOCKS5 Configurations
///
/// `SOCKS5AssocConfig` involves *two* sub-channels, one of which is a
/// near-link (the connection to the proxy), and the other a far-link
/// (the UDP forwarding channel).  There is *no* automatic translation
/// or coupling between these two sub-channels that is not established
/// by the configuration, which has significant implications for
/// configurations that describe nested channels.
///
/// In particular, in the case of a double-layer SOCKS5 connection-
/// where the client forwards to the first, which then forwards to the
/// second, it is likely necessary for *both* sub-channels to describe
/// the second SOCKS5 proxy.  The reason for this is that the TCP
/// connection to the second proxy will likely have to be made through
/// the first as well.
///
/// The following configuration (using [CompoundFarChannelConfig])
/// shows the correct way to configure a double-proxy configuration
/// where the first proxy must be used for both TCP *and* UDP:
///
/// ```yaml
/// socks5:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   auth:
///     username: test
///     password: abc123
///   socks5:
///     proxy:
///       tcp:
///         addr: proxy.example.com
///         port: 8888
///     auth: gssapi
///     udp:
///       addr: ::0
///       port: 0
/// ```
///
/// Note that *both* the TCP and UDP components negotiate through the
/// proxy at `proxy.example.com`.  Omitting one of these results in a
/// situation that is very likely a misconfiguration.  For example,
/// the following configuration omits the proxy on the TCP side:
///
/// ```yaml
/// ## THIS IS WRONG; DO NOT USE
/// socks5:
///   proxy:
///     tcp:
///       addr: tor.nowhere.com
///       port: 9050
///   auth:
///     username: test
///     password: abc123
///   socks5:
///     proxy:
///       tcp:
///         addr: proxy.example.com
///         port: 8888
///     auth: gssapi
///     udp:
///       addr: ::0
///       port: 0
/// ## THIS IS WRONG; DO NOT USE
/// ```
///
/// In this case the TCP side will attempt to connect *directly* to
/// `tor.nowhere.com`, which will be blocked in most situations where
/// such a double-layer proxy is necessary.  ***In a situation where
/// the first proxy is providing anonymity, this misconfiguration will
/// leak information via the TCP connection!***
///
/// A similar misconfiguration omits the proxy on the UDP side:
///
/// ```yaml
/// ## THIS IS WRONG; DO NOT USE
/// socks5:
///   proxy:
///     socks5:
///       proxy:
///         tcp:
///           addr: proxy.example.com
///           port: 8888
///       target:
///         addr: tor.nowhere.com
///         port: 9050
///       auth: gssapi
///   auth:
///     username: test
///     password: abc123
///   udp:
///     addr: ::0
///     port: 0
/// ## THIS IS WRONG; DO NOT USE
/// ```
///
/// This will connect to `tor.nowhere.com` through `proxy.example.com`
/// through SOCKS5, but will attempt to send UDP packets directly to
/// the forwarding UDP address obtained from that negotiation.  As
/// with the previous misconfiguration, this traffic will be blocked
/// in most situations that require such a double-proxy.  Similarly,
/// if the first proxy is providing anonymity, this misconfiguratiow
/// will bypass any such protections.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "socks5")]
#[serde(rename_all = "kebab-case")]
pub struct SOCKS5AssocConfig<Proxy, Datagram> {
    /// Address to which to bind the UDP socket for sending forwarded
    /// messages.
    #[serde(flatten)]
    forward: Datagram,
    /// Authentication mechanism to use.
    #[serde(default)]
    auth: SOCKS5AuthNConfig,
    /// Connection to the SOCKS5 proxy itself.
    proxy: Proxy
}

/// SOCKS5 near-link connector configuration.
///
/// This holds common configuration information for client-side
/// near-link channels over a SOCKS5 proxy.
///
/// # YAML Format
///
/// The YAML format has three fields:
///
/// - `proxy`: The underlying channel configuration for connecting to the SOCKS5
///   proxy.
///
/// - `target`: An [IPEndpoint], specifying the endpoint to which the proxy will
///   connect.
///
/// - `auth`: A [SOCKS5AuthNConfig], specifying how to authenticate to the
///   SOCKS5 proxy.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with a
/// [TCPNearAcceptorConfig] as the proxy channel configuration
/// with all fields represented:
///
/// ```yaml
/// proxy:
///   retry:
///     factor: 100
///     exp-base: 2.0
///     exp-factor: 1.0
///     exp-rounds-cap: 20
///     linear-factor: 1.0
///     linear-rounds-cap: 50
///     max-random: 100
///     addend: 50
///   resolve:
///     addr-policy:
///       - ipv6
///     renewal: 3600000
///     retry:
///       factor: 400
///       exp-base: 2.0
///       exp-factor: 2.0
///   addr: proxy.example.com
///   port: 9050
/// target:
///   addr: en.wikipedia.org
///   port: 443
/// password:
///   username: user
///   password: abc123
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration:
///
/// ```yaml
/// proxy:
///   addr: proxy.example.com
///   port: 9050
/// target:
///   addr: en.wikipedia.org
///   port: 443
/// auth:
///   password:
///     username: user
///     password: abc123
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "socks5")]
#[serde(rename_all = "kebab-case")]
pub struct SOCKS5ConnectConfig<Proxy> {
    /// Authentication mechanism to use.
    #[serde(default)]
    auth: SOCKS5AuthNConfig,
    /// Endpoint to of the proxied connection.
    target: IPEndpoint,
    /// Connection to the SOCKS5 proxy itself.
    proxy: Proxy
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "socks5")]
#[serde(rename_all = "kebab-case")]
pub struct SOCKS5ConnectPartialConfig<Proxy> {
    /// Authentication mechanism to use.
    #[serde(default)]
    auth: SOCKS5AuthNConfig,
    /// Connection to the SOCKS5 proxy itself.
    proxy: Proxy
}

/// Parameters used to create a
/// [ThreadedFlows](crate::far::flows::ThreadedFlows).
///
/// This allows the size of the various components of `ThreadedFlows`
/// to be configured.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
///  - `flows-size-hint`: Estimate of the number of live flows.  This does not
///    need to be completely accurate, and will only affect the number of
///    allocations performed.
///
///  - `packet-size`: Maximum size of incoming messages.  Incoming messages will
///    be truncated to this size.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "threaded-flows-params")]
#[serde(rename_all = "kebab-case")]
pub struct ThreadedFlowsParams {
    /// Size hint, should be roughly equal to the maximum number of live flows.
    #[serde(default)]
    flows_size_hint: Option<usize>,
    /// Maximum size of incoming messages.
    #[serde(default = "ThreadedFlowsParams::default_packet_size")]
    packet_size: usize
}

/// Parameters used to create a
/// [ThreadedNSNameCaches](crate::resolve::cache::ThreadedNSNameCaches).
///
/// All fields of this configuration object are optional, and this
/// does not need to be configured in most uses.
///
/// # YAML Format
///
/// The YAML format has three fields, all of which are optional:
///
///  - `size-hint`: Estimate of the number of live names to be resolved.  This
///    does not need to be completely accurate, and will only affect the number
///    of allocations performed.
///
///  - `renewal`: Period of time at which name resolutions should be renewed.
///
///  - `retry`: [Retry] configuration for retrying failed resolutions.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "threaded-name-caches")]
#[serde(rename_all = "kebab-case")]
pub struct ThreadedNSNameCachesConfig {
    /// Size hint, should be roughly equal to the maximum number of
    /// live names to be resolved.
    #[serde(default)]
    size_hint: Option<usize>,
    /// Interval at which the renewer thread will periodically try to
    /// refresh names.
    #[serde(default = "ThreadedNSNameCachesConfig::default_renewal")]
    #[serde(deserialize_with = "Retry::deserialize_time")]
    #[serde(serialize_with = "Retry::serialize_time")]
    renewal: Duration,
    /// Retry configuration for the renewer thread.
    #[serde(default)]
    retry: Retry
}

/// Unsafe configuration options for TCP near-link channels.
///
/// # YAML Format
///
/// The YAML format has one parameter:
///
/// - `unsafe-allow-ip-addr-creds`: Allow IP addresses to be harvested as
///   credentials.  This is unsafe as IP addresses can be easily spoofed.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "udp-channel-unsafe")]
#[serde(rename_all = "kebab-case")]
pub struct TCPNearChannelConfigUnsafe {
    /// Allow IP addresses as credentials on this channel.
    unsafe_allow_ip_addr_creds: bool
}

/// TCP socket near-link acceptor configuration.
///
/// This holds common configuration information for server-side
/// near-link channels over TCP sockets.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
/// - `addr`: The IP address at which to listen.  Note that this cannot be a
///   domain name.
///
/// - `port`: The port on which to listen.
///
/// ## Examples
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// addr: 0.0.0.0
/// port: 5004
/// ```
///
/// The following is an IPv6-based configuration:
///
/// ```yaml
/// addr: ::0
/// port: 5005
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TCPNearAcceptorConfig {
    #[serde(rename = "unsafe")]
    #[serde(default)]
    unsafe_opts: TCPNearChannelConfigUnsafe,
    addr: IpAddr,
    port: u16
}

/// TCP socket near-link connector configuration.
///
/// This holds common configuration information for client-side
/// near-link channels over TCP sockets.
///
/// # YAML Format
///
/// The YAML format has four fields:
///
/// - The connection endpoint, which is flattened, giving two fields:
///
///   - `addr`: The address at which to connect. (See
///     [IPEndpointAddr](constellation_common::net::IPEndpointAddr).)
///
///   - `port`: The port on which to listen.
///
/// - `retry`: A [Retry] configuration, specifying the policy for retrying
///   failed connections.
///
/// - `resolve`: As [AddrsConfig], specifying how to resolve names.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with all fields
/// represented:
///
/// ```yaml
/// addr: test.example.com
/// port: 5006
/// retry:
///   factor: 100
///   exp-base: 2.0
///   exp-factor: 1.0
///   exp-rounds-cap: 20
///   linear-factor: 1.0
///   linear-rounds-cap: 50
///   max-random: 100
///   addend: 50
/// resolve:
///   addr-policy:
///     - ipv6
///   renewal: 3600000
///   retry:
///     factor: 400
///     exp-base: 2.0
///     exp-factor: 2.0
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration:
///
/// ```yaml
/// addr: test.example.com
/// port: 5007
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TCPResolvingNearConnectorConfig {
    #[serde(rename = "unsafe")]
    #[serde(default)]
    unsafe_opts: TCPNearChannelConfigUnsafe,
    #[serde(flatten)]
    endpoint: IPEndpoint,
    /// Retry spec.
    #[serde(default)]
    retry: Retry,
    /// DNS resolution configuration.
    #[serde(default)]
    resolve: AddrsConfig
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct TCPResolvingNearConnectorPartialConfig {
    #[serde(rename = "unsafe")]
    #[serde(default)]
    unsafe_opts: TCPNearChannelConfigUnsafe,
    /// Retry spec.
    #[serde(default)]
    retry: Retry,
    /// DNS resolution configuration.
    #[serde(default)]
    resolve: AddrsConfig
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct TCPNearConnectorPartialConfig {
    #[serde(rename = "unsafe")]
    #[serde(default)]
    unsafe_opts: TCPNearChannelConfigUnsafe
}

/// TLS near-link channel configuration meta-type.
///
/// This is largely a parameterized type.  See the two main
/// instantiations, [TLSNearAcceptorConfig] and
/// [TLSNearConnectorConfig].
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "tls")]
#[serde(rename_all = "kebab-case")]
pub struct TLSChannelConfig<TLS, Underlying> {
    /// Configuration for the TLS session.
    #[serde(flatten)]
    tls: TLS,
    #[serde(flatten)]
    /// Configuration for the underlying channel.
    underlying: Underlying,
    /// Retry configuration for shutdown negotiations.
    #[serde(
        default = "TLSChannelConfig::<TLS, Underlying>::default_shutdown_retry"
    )]
    shutdown_retry: Retry,
    /// Maximum duration of shutdown negotiations.
    #[serde(
        default = "TLSChannelConfig::<TLS, Underlying>::default_shutdown_timeout"
    )]
    #[serde(deserialize_with = "Retry::deserialize_time")]
    #[serde(serialize_with = "Retry::serialize_time")]
    shutdown_timeout: Duration
}

/// TLS server-side near-link channel configuration.
///
/// This is a type alias for [TLSChannelConfig] with [TLSServerConfig]
/// as the TLS-specific portion.  This holds common configuration
/// information for server-side near-link TLS channels.
///
/// # YAML Format
///
/// The YAML format has two groups of fields:
///
/// - The underlying channel, which is flattened.  The fields that arise from
///   this will depend on the exact kind of channel.
///
/// - A [TLSServerConfig] structure, which is also flattened.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration
/// with all fields represented:
///
/// ```yaml
/// cipher-suites:
///   - TLS_AES_256_GCM_SHA384
/// key-exchange-groups:
///   - P-521
///   - P-384
/// signature-algorithms:
///   - ecdsa_secp521r1_sha512
///   - ecdsa_secp384r1_sha384
/// client-auth:
///   verify: optional
///   trust-root:
///     root-certs:
///       - /etc/ssl/certs/client-ca-cert.pem
///     crls:
///       - /etc/ssl/crls/client-ca-crl.pem
/// cert: /etc/ssl/certs/server-cert.pem
/// cert-chain: /etc/ssl/certs/server-cert-chain.pem
/// key: /etc/ssl/private/key.pem
/// addr: ::0
/// port: 5008
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration:
///
/// ```yaml
/// cert: /etc/ssl/certs/server-cert.pem
/// key: /etc/ssl/private/key.pem
/// addr: ::0
/// port: 5009
/// ```
pub type TLSNearAcceptorConfig<Endpoint> =
    TLSChannelConfig<TLSServerConfig, Endpoint>;

/// TLS client-side configuration.
///
/// This is a type alias for [TLSChannelConfig] with [TLSClientConfig]
/// as the TLS-specific portion.  This holds common configuration
/// information for client-side near-link TLS channels.
///
/// # YAML Format
///
/// The YAML format has two groups of fields:
///
/// - The underlying channel, which is flattened.  The fields that arise from
///   this will depend on the exact kind of channel.
///
/// - A [TLSClientConfig] structure, which is also flattened.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration
/// with all fields represented:
///
/// ```yaml
/// cipher-suites:
///   - TLS_AES_256_GCM_SHA384
/// key-exchange-groups:
///   - P-521
///   - P-384
/// signature-algorithms:
///   - ecdsa_secp521r1_sha512
///   - ecdsa_secp384r1_sha384
/// client-cert: /etc/ssl/certs/client-cert.pem
/// client-cert-chain: /etc/ssl/certs/client-chain.pem
/// client-key: /etc/ssl/private/client-key.pem
/// verify-endpoint: test.example.com
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/server-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/server-ca-crl.pem
/// addr: test.example.com
/// port: 5010
/// retry:
///   factor: 100
///   exp-base: 2.0
///   exp-factor: 1.0
///   exp-rounds-cap: 20
///   linear-factor: 1.0
///   linear-rounds-cap: 50
///   max-random: 100
///   addend: 50
/// resolve:
///   addr-policy:
///     - ipv6
///   renewal: 3600000
///   retry:
///     factor: 400
///     exp-base: 2.0
///     exp-factor: 2.0
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal configuration with a
/// [TCPNearAcceptorConfig] as the underlying channel configuration:
///
/// ```yaml
/// cert: /etc/ssl/certs/server-cert.pem
/// key: /etc/ssl/private/key.pem
/// addr: test.example.com
/// port: 5011
/// ```
pub type TLSNearConnectorConfig<Endpoint> =
    TLSChannelConfig<TLSClientConfig, Endpoint>;

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct TLSParam<Inner> {
    #[serde(default)]
    verify_endpoint: Option<IPEndpointAddr>,
    #[serde(default)]
    #[serde(flatten)]
    inner: Inner
}

/// Unsafe options for UDP far-link channels.
///
/// # YAML Format
///
/// The YAML format has one parameter:
///
/// - `unsafe-allow-ip-addr-creds`: Allow IP addresses to be harvested as
///   credentials.  This is unsafe as IP addresses can be easily spoofed.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "udp-channel-unsafe")]
#[serde(rename_all = "kebab-case")]
pub struct UDPFarChannelConfigUnsafe {
    /// Allow IP addresses as credentials on this channel.
    unsafe_allow_ip_addr_creds: bool
}

/// UDP socket far-link channel configuration.
///
/// This holds common configuration information for server-side
/// far-link channels over UDP sockets.
///
/// # YAML Format
///
/// The YAML format has two fields:
///
/// - `addr`: The IP address at which to listen.  Note that this cannot be a
///   domain name.
///
/// - `port`: The port on which to listen.
///
/// ## Examples
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// addr: 0.0.0.0
/// port: 5012
/// ```
///
/// The following is an IPv6-based configuration:
///
/// ```yaml
/// addr: ::0
/// port: 5013
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "udp-channel")]
#[serde(rename_all = "kebab-case")]
pub struct UDPFarChannelConfig {
    #[serde(rename = "unsafe")]
    #[serde(default)]
    unsafe_opts: UDPFarChannelConfigUnsafe,
    addr: IpAddr,
    port: u16
}

/// Unix socket far-link configuration.
///
/// This holds common configuration information for far-link channels
/// over Unix domain sockets.
///
/// # YAML Format
///
/// The YAML format has one field:
///
/// - `path`: The path at which the Unix socket exists in the filesystem.
///
/// ## Example
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// path: /var/run/test/test.sock
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unix-channel")]
#[serde(rename_all = "kebab-case")]
pub struct UnixFarChannelConfig {
    /// Path to the UNIX socket.
    path: PathBuf
}

/// Unix socket near-link configuration.
///
/// This holds common configuration information for near-link channels
/// over Unix domain sockets.  By itself, this serves as the
/// configuration for an acceptor (server-side); the client side
/// carries additional information (see [UnixNearConnectorConfig]).
///
/// # YAML Format
///
/// The YAML format has one field:
///
/// - `path`: The path at which the Unix socket exists in the filesystem.
///
/// ## Example
///
/// The following is an example of the YAML format:
///
/// ```yaml
/// path: /var/run/test/test.sock
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unix-channel")]
#[serde(rename_all = "kebab-case")]
pub struct UnixNearChannelConfig {
    /// Path to the UNIX socket.
    path: PathBuf
}

#[derive(
    Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "unix-connector-partial")]
#[serde(rename_all = "kebab-case")]
#[serde(default)]
pub struct UnixNearConnectorPartialConfig {
    #[serde(skip)]
    placeholder: ()
}

#[derive(Clone)]
struct CompoundNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient {
    tls: PhantomData<TLS>
}

#[derive(Clone)]
struct CompoundResolvingNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient {
    tls: PhantomData<TLS>
}

#[derive(Clone, Default)]
struct CompoundNearChannelVariantVisitor;

enum CompoundNearChannelVariant {
    Unix,
    TCP,
    TLS,
    SOCKS5
}

const COMPOUND_NEAR_CHANNEL_TYPES: &[&str] =
    &["unix-stream", "tcp", "tls", "socks5-tcp"];

impl<TLS> Default for CompoundNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient
{
    #[inline]
    fn default() -> Self {
        CompoundNearConnectorPartialConfigVisitor { tls: PhantomData }
    }
}

impl<TLS> Default for CompoundResolvingNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient
{
    #[inline]
    fn default() -> Self {
        CompoundResolvingNearConnectorPartialConfigVisitor { tls: PhantomData }
    }
}

impl Default for CompoundOutboundNegotiatorParam {
    #[inline]
    fn default() -> Self {
        CompoundOutboundNegotiatorParam::Basic
    }
}

impl<'de> Visitor<'de> for CompoundNearChannelVariantVisitor {
    type Value = CompoundNearChannelVariant;

    fn expecting(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "unix-stream, tcp, tls, or socks5-tcp")
    }

    fn visit_str<E>(
        self,
        s: &str
    ) -> Result<Self::Value, E>
    where
        E: serde::de::Error {
        match s {
            "unix-stream" => Ok(CompoundNearChannelVariant::Unix),
            "tcp" => Ok(CompoundNearChannelVariant::TCP),
            "tls" => Ok(CompoundNearChannelVariant::TLS),
            "socks5-tcp" => Ok(CompoundNearChannelVariant::SOCKS5),
            _ => Err(serde::de::Error::unknown_variant(
                s,
                COMPOUND_NEAR_CHANNEL_TYPES
            ))
        }
    }

    #[inline]
    fn visit_borrowed_str<E>(
        self,
        s: &'de str
    ) -> Result<Self::Value, E>
    where
        E: serde::de::Error {
        self.visit_str(s)
    }

    #[inline]
    fn visit_string<E>(
        self,
        s: String
    ) -> Result<Self::Value, E>
    where
        E: serde::de::Error {
        self.visit_str(s.as_str())
    }
}

impl<'de> Deserialize<'de> for CompoundNearChannelVariant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de> {
        deserializer.deserialize_identifier(CompoundNearChannelVariantVisitor)
    }
}

impl<'de, TLS> Visitor<'de> for CompoundNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient + Deserialize<'de>
{
    type Value = CompoundNearConnectorPartialConfig<TLS>;

    fn expecting(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "unix-stream, tcp, tls, or socks5-tcp and configurations")
    }

    fn visit_map<V>(
        self,
        mut map: V
    ) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de> {
        match map.next_key()? {
            Some(CompoundNearChannelVariant::Unix) => {
                Ok(CompoundNearConnectorPartialConfig::Unix {
                    unix_stream: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::TCP) => {
                Ok(CompoundNearConnectorPartialConfig::TCP {
                    tcp: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::TLS) => {
                Ok(CompoundNearConnectorPartialConfig::TLS {
                    tls: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::SOCKS5) => {
                Ok(CompoundNearConnectorPartialConfig::SOCKS5 {
                    socks5_tcp: map.next_value()?
                })
            }
            None => Err(serde::de::Error::invalid_length(0, &self))
        }
    }
}

impl<'de, TLS> Deserialize<'de> for CompoundNearConnectorPartialConfig<TLS>
where
    TLS: TLSLoadClient + Deserialize<'de>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de> {
        deserializer.deserialize_struct(
            "compound-near-connector-partial",
            COMPOUND_NEAR_CHANNEL_TYPES,
            CompoundNearConnectorPartialConfigVisitor::default()
        )
    }
}

impl<'de, TLS> Visitor<'de>
    for CompoundResolvingNearConnectorPartialConfigVisitor<TLS>
where
    TLS: TLSLoadClient + Deserialize<'de>
{
    type Value = CompoundResolvingNearConnectorPartialConfig<TLS>;

    fn expecting(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "unix-stream, tcp, tls, or socks5-tcp and configurations")
    }

    fn visit_map<V>(
        self,
        mut map: V
    ) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de> {
        match map.next_key()? {
            Some(CompoundNearChannelVariant::Unix) => {
                Ok(CompoundResolvingNearConnectorPartialConfig::Unix {
                    unix_stream: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::TCP) => {
                Ok(CompoundResolvingNearConnectorPartialConfig::TCP {
                    tcp: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::TLS) => {
                Ok(CompoundResolvingNearConnectorPartialConfig::TLS {
                    tls: map.next_value()?
                })
            }
            Some(CompoundNearChannelVariant::SOCKS5) => {
                Ok(CompoundResolvingNearConnectorPartialConfig::SOCKS5 {
                    socks5_tcp: map.next_value()?
                })
            }
            None => Err(serde::de::Error::invalid_length(0, &self))
        }
    }
}

impl<'de, TLS> Deserialize<'de>
    for CompoundResolvingNearConnectorPartialConfig<TLS>
where
    TLS: TLSLoadClient + Deserialize<'de>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de> {
        deserializer.deserialize_struct(
            "compound-near-resolving-connector-partial",
            COMPOUND_NEAR_CHANNEL_TYPES,
            CompoundResolvingNearConnectorPartialConfigVisitor::default()
        )
    }
}

impl AddrsConfig {
    /// Create a new `AddrsConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::ResolverConfig;
    /// #
    /// let yaml = concat!("addr-policy: [ ipv6 ]\n",
    ///                    "renewal: 3600000");
    ///
    /// assert_eq!(
    ///     AddrsConfig::new(vec![ AddrKind::IPv6 ],
    ///                      ResolverConfig::new(1000 * 60 * 60,
    ///                                          Retry::default())),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        addr_policy: Vec<AddrKind>,
        resolver: ResolverConfig
    ) -> Self {
        AddrsConfig {
            addr_policy: addr_policy,
            resolver: resolver
        }
    }

    /// Get the address selection policy.
    #[inline]
    pub fn addr_policy(&self) -> &[AddrKind] {
        &self.addr_policy
    }

    /// Get the resolver configuration.
    #[inline]
    pub fn resolver(&self) -> &ResolverConfig {
        &self.resolver
    }

    /// Decompose an `AddrsConfig` into its components.
    #[inline]
    pub(crate) fn take(self) -> (Vec<AddrKind>, ResolverConfig) {
        (self.addr_policy, self.resolver)
    }
}

impl<Channel, AuthN, Xfrm> FarChannelEntryConfig<Channel, AuthN, Xfrm>
where
    Xfrm: Default
{
    /// Create a new `ChannelRegistryEntryConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(
        id: String,
        channel: Channel,
        resolve: Option<AddrsConfig>,
        authn_config: Option<AuthN>,
        flows_params: Option<FlowsConfig>,
        xfrm_params: Option<Xfrm>,
        retry: Option<Retry>,
        flows_size_hint: Option<usize>
    ) -> Self {
        FarChannelEntryConfig {
            id: id,
            channel: channel,
            resolve: resolve,
            authn: authn_config,
            flows_params: flows_params,
            xfrm_params: xfrm_params,
            retry: retry,
            flows_size_hint: flows_size_hint
        }
    }

    /// Get the name of the registry entry.
    #[inline]
    pub fn name(&self) -> &str {
        self.id.as_ref()
    }

    #[inline]
    pub fn authn(&self) -> Option<&AuthN> {
        self.authn.as_ref()
    }

    /// Get the channel configuration.
    #[inline]
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Get the retry configuration.
    #[inline]
    pub fn retry(&self) -> Option<&Retry> {
        self.retry.as_ref()
    }

    #[inline]
    pub fn flows_size_hint(&self) -> Option<usize> {
        self.flows_size_hint
    }

    /// Get the resolver configuration.
    #[inline]
    pub fn resolve(&self) -> Option<&AddrsConfig> {
        self.resolve.as_ref()
    }

    /// Get the [Flows] creation parameters.
    #[inline]
    pub fn flows_params(&self) -> Option<&FlowsConfig> {
        self.flows_params.as_ref()
    }

    /// Get the [DatagramXfrm] creation parameters.
    #[inline]
    pub fn xfrm_params(&self) -> Option<&Xfrm> {
        self.xfrm_params.as_ref()
    }

    /// Decompose a `FarChannelEntryConfig` into its components.
    #[inline]
    pub fn take(
        self
    ) -> (
        String,
        Channel,
        Option<AddrsConfig>,
        Option<AuthN>,
        Option<FlowsConfig>,
        Option<Xfrm>,
        Option<Retry>,
        Option<usize>
    ) {
        (
            self.id,
            self.channel,
            self.resolve,
            self.authn,
            self.flows_params,
            self.xfrm_params,
            self.retry,
            self.flows_size_hint
        )
    }

    fn default_authn() -> Option<AuthN> {
        None
    }
}

impl<Codec> FarChannelRegistryChannelsConfig<Codec>
where
    Codec: Default
{
    /// Create a [ChannelRegistryChannelsConfig] from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(codec: Codec) -> Self {
        FarChannelRegistryChannelsConfig { codec: codec }
    }

    /// Get the configuration parameters used to create
    /// [DatagramCodec](constellation_common::codec::DatagramCodec)s.
    #[inline]
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Decompose this into its components.
    ///
    /// This produces the codec parameters.
    #[inline]
    pub fn take(self) -> Codec {
        self.codec
    }
}

impl<Channel, AuthN, Xfrm> FarChannelsConfig<Channel, AuthN, Xfrm>
where
    Xfrm: Default
{
    /// Create a new `ChannelRegistryConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(
        channels: Vec<FarChannelEntryConfig<Channel, AuthN, Xfrm>>,
        resolve: AddrsConfig,
        authn_config: AuthN,
        flows_params: FlowsConfig,
        xfrm_params: Xfrm,
        retry: Retry,
        flows_size_hint: Option<usize>
    ) -> Self {
        FarChannelsConfig {
            channels: channels,
            default_resolve: resolve,
            default_authn: authn_config,
            default_flows_params: flows_params,
            default_xfrm_params: xfrm_params,
            default_retry: retry,
            default_flows_size_hint: flows_size_hint
        }
    }

    /// Get the channel configurations.
    #[inline]
    pub fn channels(&self) -> &[FarChannelEntryConfig<Channel, AuthN, Xfrm>] {
        &self.channels
    }

    /// Get the resolver configuration.
    #[inline]
    pub fn resolve(&self) -> &AddrsConfig {
        &self.default_resolve
    }

    /// Get the flows creation parameters.
    #[inline]
    pub fn flows_params(&self) -> &FlowsConfig {
        &self.default_flows_params
    }

    /// Get the context creation parameters.
    #[inline]
    pub fn xfrm_params(&self) -> &Xfrm {
        &self.default_xfrm_params
    }

    /// Get the retry configuration.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.default_retry
    }

    #[inline]
    pub fn flows_size_hint(&self) -> Option<usize> {
        self.default_flows_size_hint
    }

    /// Decompose a `FarChannelRegistryConfig` into its components.
    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<FarChannelEntryConfig<Channel, AuthN, Xfrm>>,
        AddrsConfig,
        AuthN,
        FlowsConfig,
        Xfrm,
        Retry,
        Option<usize>
    ) {
        (
            self.channels,
            self.default_resolve,
            self.default_authn,
            self.default_flows_params,
            self.default_xfrm_params,
            self.default_retry,
            self.default_flows_size_hint
        )
    }

    fn default_retry_value() -> Retry {
        Retry::TERRESTRIAL_NETWORK_DEFAULT.clone()
    }
}

impl<Unix, UDP> Default for CompoundXfrmCreateParam<Unix, UDP>
where
    Unix: Default,
    UDP: Default
{
    #[inline]
    fn default() -> Self {
        CompoundXfrmCreateParam::create(Unix::default(), UDP::default())
    }
}

impl<Unix, UDP> CompoundXfrmCreateParam<Unix, UDP> {
    /// Create a new `ChannelRegistryConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn create(
        unix: Unix,
        udp: UDP
    ) -> Self {
        CompoundXfrmCreateParam {
            unix: unix,
            udp: udp
        }
    }

    /// Get the
    /// [DatagramXfrm](constellation_common::net::DatagramXfrm)
    /// creation parameters for Unix socket channels.
    #[inline]
    pub fn unix(&self) -> &Unix {
        &self.unix
    }

    /// Get the
    /// [DatagramXfrm](constellation_common::net::DatagramXfrm)
    /// creation parameters for UDP socket channels.
    #[inline]
    pub fn udp(&self) -> &UDP {
        &self.udp
    }

    /// Decompose this into its components.
    ///
    /// This produces the
    /// [DatagramXfrm](constellation_common::net::DatagramXfrm)
    /// creation parameters for Unix socket channels and UDP socket
    /// channels respectively.
    pub fn take(self) -> (Unix, UDP) {
        (self.unix, self.udp)
    }
}

impl From<IPEndpoint> for CompoundFarEndpoint {
    #[inline]
    fn from(val: IPEndpoint) -> Self {
        CompoundFarEndpoint::UDP { udp: val }
    }
}

impl<Inner> DTLSOutboundParam<Inner> {
    #[inline]
    pub fn new(
        verify_endpoint: IPEndpointAddr,
        inner: Inner
    ) -> Self {
        DTLSOutboundParam {
            verify_endpoint: verify_endpoint,
            inner: inner
        }
    }

    #[inline]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[inline]
    pub fn verify_endpoint(&self) -> &IPEndpointAddr {
        &self.verify_endpoint
    }

    #[inline]
    pub fn take(self) -> (IPEndpointAddr, Inner) {
        (self.verify_endpoint, self.inner)
    }
}

impl Default for FlowsConfig {
    #[inline]
    fn default() -> Self {
        FlowsConfig {
            msg_size: 1500,
            buf_size: None,
            num_flows: None,
            num_negotiations: None
        }
    }
}

impl FlowsConfig {
    #[inline]
    pub fn new(
        msg_size: usize,
        buf_size: Option<usize>,
        num_flows: Option<usize>,
        num_negotiations: Option<usize>
    ) -> Self {
        FlowsConfig {
            num_negotiations: num_negotiations,
            num_flows: num_flows,
            msg_size: msg_size,
            buf_size: buf_size
        }
    }

    #[inline]
    pub fn msgsize(&self) -> usize {
        self.msg_size
    }

    #[inline]
    pub fn bufsize(&self) -> Option<usize> {
        self.buf_size
    }

    #[inline]
    pub fn nflows(&self) -> Option<usize> {
        self.num_flows
    }

    #[inline]
    pub fn nnegos(&self) -> Option<usize> {
        self.num_negotiations
    }

    #[inline]
    pub fn take(self) -> (usize, Option<usize>, Option<usize>, Option<usize>) {
        (
            self.msg_size,
            self.buf_size,
            self.num_flows,
            self.num_negotiations
        )
    }
}

impl<In, Out, InAuthN, OutAuthN>
    NearChannelEntryConfig<In, Out, InAuthN, OutAuthN>
{
    pub fn name(&self) -> &str {
        match self {
            NearChannelEntryConfig::Outbound { outbound } => outbound.id(),
            NearChannelEntryConfig::Inbound { inbound } => inbound.id(),
            NearChannelEntryConfig::Duplex { duplex } => duplex.id()
        }
    }
}

impl<In, Out, InAuthN, OutAuthN>
    NearChannelsConfig<In, Out, InAuthN, OutAuthN>
{
    #[inline]
    pub fn new(
        channels: Vec<NearChannelEntryConfig<In, Out, InAuthN, OutAuthN>>,
        default_inbound_authn: InAuthN,
        default_outbound_authn: OutAuthN,
        default_retry: Retry,
        default_num_sessions: Option<usize>
    ) -> Self {
        NearChannelsConfig {
            channels: channels,
            default_inbound_authn: default_inbound_authn,
            default_outbound_authn: default_outbound_authn,
            default_retry: default_retry,
            default_num_sessions: default_num_sessions
        }
    }

    #[inline]
    pub fn channels(
        &self
    ) -> &[NearChannelEntryConfig<In, Out, InAuthN, OutAuthN>] {
        &self.channels
    }

    #[inline]
    pub fn default_outbound_authn(&self) -> &OutAuthN {
        &self.default_outbound_authn
    }

    #[inline]
    pub fn default_inbound_authn(&self) -> &InAuthN {
        &self.default_inbound_authn
    }

    #[inline]
    pub fn default_retry(&self) -> &Retry {
        &self.default_retry
    }

    #[inline]
    pub fn default_num_sessions(&self) -> Option<usize> {
        self.default_num_sessions
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<NearChannelEntryConfig<In, Out, InAuthN, OutAuthN>>,
        InAuthN,
        OutAuthN,
        Retry,
        Option<usize>
    ) {
        (
            self.channels,
            self.default_inbound_authn,
            self.default_outbound_authn,
            self.default_retry,
            self.default_num_sessions
        )
    }

    fn default_retry_value() -> Retry {
        Retry::TERRESTRIAL_NETWORK_DEFAULT.clone()
    }
}

impl<In, Out, InAuthN, OutAuthN>
    NearChannelDuplexEntryConfig<In, Out, InAuthN, OutAuthN>
{
    #[inline]
    pub fn new(
        id: String,
        listen: In,
        connect: Out,
        inbound_authn: Option<InAuthN>,
        outbound_authn: Option<OutAuthN>,
        retry: Option<Retry>,
        num_sessions: Option<usize>
    ) -> Self {
        NearChannelDuplexEntryConfig {
            id: id,
            listen: listen,
            connect: connect,
            inbound_authn: inbound_authn,
            outbound_authn: outbound_authn,
            num_sessions: num_sessions,
            retry: retry
        }
    }

    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[inline]
    pub fn listen(&self) -> &In {
        &self.listen
    }

    #[inline]
    pub fn connect(&self) -> &Out {
        &self.connect
    }

    #[inline]
    pub fn inbound_authn(&self) -> Option<&InAuthN> {
        self.inbound_authn.as_ref()
    }

    #[inline]
    pub fn outbound_authn(&self) -> Option<&OutAuthN> {
        self.outbound_authn.as_ref()
    }

    #[inline]
    pub fn retry(&self) -> Option<&Retry> {
        self.retry.as_ref()
    }

    #[inline]
    pub fn num_sessions(&self) -> Option<usize> {
        self.num_sessions
    }

    #[inline]
    pub fn take(
        self
    ) -> (
        String,
        In,
        Out,
        Option<InAuthN>,
        Option<OutAuthN>,
        Option<Retry>,
        Option<usize>
    ) {
        (
            self.id,
            self.listen,
            self.connect,
            self.inbound_authn,
            self.outbound_authn,
            self.retry,
            self.num_sessions
        )
    }

    fn default_in_authn() -> Option<InAuthN> {
        None
    }

    fn default_out_authn() -> Option<OutAuthN> {
        None
    }
}

impl<In, AuthN> NearChannelInboundEntryConfig<In, AuthN> {
    #[inline]
    pub fn new(
        id: String,
        listen: In,
        authn: Option<AuthN>,
        retry: Option<Retry>,
        num_sessions: Option<usize>
    ) -> Self {
        NearChannelInboundEntryConfig {
            id: id,
            listen: listen,
            authn: authn,
            num_sessions: num_sessions,
            retry: retry
        }
    }

    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[inline]
    pub fn listen(&self) -> &In {
        &self.listen
    }

    #[inline]
    pub fn authn(&self) -> Option<&AuthN> {
        self.authn.as_ref()
    }

    #[inline]
    pub fn retry(&self) -> Option<&Retry> {
        self.retry.as_ref()
    }

    #[inline]
    pub fn num_sessions(&self) -> Option<usize> {
        self.num_sessions
    }

    #[inline]
    pub fn take(
        self
    ) -> (String, In, Option<AuthN>, Option<Retry>, Option<usize>) {
        (
            self.id,
            self.listen,
            self.authn,
            self.retry,
            self.num_sessions
        )
    }

    fn default_authn() -> Option<AuthN> {
        None
    }
}

impl<Out, AuthN> NearChannelOutboundEntryConfig<Out, AuthN> {
    #[inline]
    pub fn new(
        id: String,
        connect: Out,
        authn: Option<AuthN>,
        retry: Option<Retry>,
        num_sessions: Option<usize>
    ) -> Self {
        NearChannelOutboundEntryConfig {
            id: id,
            connect: connect,
            authn: authn,
            num_sessions: num_sessions,
            retry: retry
        }
    }

    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[inline]
    pub fn connect(&self) -> &Out {
        &self.connect
    }

    #[inline]
    pub fn authn(&self) -> Option<&AuthN> {
        self.authn.as_ref()
    }

    #[inline]
    pub fn retry(&self) -> Option<&Retry> {
        self.retry.as_ref()
    }

    #[inline]
    pub fn num_sessions(&self) -> Option<usize> {
        self.num_sessions
    }

    #[inline]
    pub fn take(
        self
    ) -> (String, Out, Option<AuthN>, Option<Retry>, Option<usize>) {
        (
            self.id,
            self.connect,
            self.authn,
            self.retry,
            self.num_sessions
        )
    }

    fn default_authn() -> Option<AuthN> {
        None
    }
}

impl ResolverConfig {
    /// Create a new `ResolverConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::ResolverConfig;
    /// #
    /// let yaml = concat!("renewal: 3600000");
    ///
    /// assert_eq!(
    ///     ResolverConfig::new(1000 * 60 * 60, Retry::default()),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        renewal: usize,
        retry: Retry
    ) -> Self {
        ResolverConfig {
            renewal: renewal,
            retry: retry
        }
    }

    /// Get the renewal time in seconds.
    #[inline]
    pub fn renewal(&self) -> usize {
        self.renewal
    }

    /// Get the retry policy.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Decompose a `ResolverConfig` into its components.
    #[inline]
    pub(crate) fn take(self) -> (usize, Retry) {
        (self.renewal, self.retry)
    }
}

impl ThreadedFlowsParams {
    /// Create a [ThreadedFlowsParams] from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::ThreadedFlowsParams;
    /// #
    /// let yaml = concat!("flows-size-hint: 36\n",
    ///                    "packet-size: 1500\n");
    ///
    /// assert_eq!(
    ///     ThreadedFlowsParams::new(Some(36), 1500),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        flows_size_hint: Option<usize>,
        packet_size: usize
    ) -> ThreadedFlowsParams {
        ThreadedFlowsParams {
            flows_size_hint: flows_size_hint,
            packet_size: packet_size
        }
    }

    /// Get the size hint, which should roughly equal the number of
    /// live flows.
    #[inline]
    pub fn flows_size_hint(&self) -> Option<usize> {
        self.flows_size_hint
    }

    /// Get the maximum packet size.
    #[inline]
    pub fn packet_size(&self) -> usize {
        self.packet_size
    }

    #[inline]
    fn default_packet_size() -> usize {
        1536
    }
}

impl ThreadedNSNameCachesConfig {
    /// Create a [ThreadedNSNameCachesConfig] from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::ThreadedNSNameCachesConfig;
    /// # use constellation_common::retry::Retry;
    /// # use std::time::Duration;
    /// #
    /// let yaml = concat!("size-hint: 36\n");
    /// let refresh = Duration::from_secs(3600);
    ///
    /// assert_eq!(
    ///     ThreadedNSNameCachesConfig::new(Some(36), refresh,
    ///                                     Retry::default()),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    pub fn new(
        size_hint: Option<usize>,
        renewal: Duration,
        retry: Retry
    ) -> Self {
        ThreadedNSNameCachesConfig {
            size_hint: size_hint,
            renewal: renewal,
            retry: retry
        }
    }

    /// Get the size hint, should be roughly equal to the maximum
    /// number of live names to be resolved.
    #[inline]
    pub fn size_hint(&self) -> Option<usize> {
        self.size_hint
    }

    /// Get the interval at which the renewer thread will periodically
    /// try to refresh names.
    #[inline]
    pub fn renewal(&self) -> Duration {
        self.renewal
    }

    /// Retry configuration for the renewer thread.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Decompose this into its components.
    ///
    /// This produces the size hint, the refresh interval, and the
    /// [Retry] configuration.
    #[inline]
    pub fn take(self) -> (Option<usize>, Duration, Retry) {
        (self.size_hint, self.renewal, self.retry)
    }

    #[inline]
    fn default_renewal() -> Duration {
        Duration::from_secs(3600)
    }
}

impl<Inner> TLSParam<Inner> {
    #[inline]
    pub fn new(
        verify_endpoint: Option<IPEndpointAddr>,
        inner: Inner
    ) -> Self {
        TLSParam {
            verify_endpoint: verify_endpoint,
            inner: inner
        }
    }

    #[inline]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    #[inline]
    pub fn verify_endpoint(&self) -> Option<&IPEndpointAddr> {
        self.verify_endpoint.as_ref()
    }

    #[inline]
    pub fn take(self) -> (Option<IPEndpointAddr>, Inner) {
        (self.verify_endpoint, self.inner)
    }
}

/// Errors that can occur loading SOCKS5 authentication configuration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SOCKS5AuthNError {
    /// Unknown authentication kind.
    BadKind {
        /// The name of the unknown kind.
        name: String
    }
}

impl Default for AddrsConfig {
    #[inline]
    fn default() -> Self {
        AddrsConfig {
            addr_policy: vec![AddrKind::IPv6, AddrKind::IPv4],
            resolver: ResolverConfig::default()
        }
    }
}

impl Default for ThreadedNSNameCachesConfig {
    #[inline]
    fn default() -> Self {
        ThreadedNSNameCachesConfig {
            renewal: ThreadedNSNameCachesConfig::default_renewal(),
            size_hint: Option::default(),
            retry: Retry::default()
        }
    }
}

impl Default for ThreadedFlowsParams {
    #[inline]
    fn default() -> Self {
        ThreadedFlowsParams {
            packet_size: ThreadedFlowsParams::default_packet_size(),
            flows_size_hint: None
        }
    }
}

impl Default for ResolverConfig {
    #[inline]
    fn default() -> Self {
        ResolverConfig {
            renewal: 60 * 60 * 3,
            retry: Retry::default()
        }
    }
}

impl Display for SOCKS5AuthNError {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        match self {
            SOCKS5AuthNError::BadKind { name } => {
                write!(f, "unknown authentication type {}", name)
            }
        }
    }
}
impl Display for UnixFarChannelConfig {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "unix://{}", self.path().to_string_lossy())
    }
}

impl Display for UnixNearChannelConfig {
    #[inline]
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), Error> {
        write!(f, "unix://{}", self.path().to_string_lossy())
    }
}

impl<'a> TryFrom<&'a str> for AddrKind {
    type Error = &'a str;

    #[inline]
    fn try_from(val: &'a str) -> Result<AddrKind, &'a str> {
        match val {
            "ipv6" => Ok(AddrKind::IPv6),
            "ipv4" => Ok(AddrKind::IPv4),
            err => Err(err)
        }
    }
}

impl Serialize for AddrKind {
    #[inline]
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            AddrKind::IPv6 => serializer.serialize_str("ipv6"),
            AddrKind::IPv4 => serializer.serialize_str("ipv4")
        }
    }
}

impl Serialize for SOCKS5AuthNConfig {
    #[inline]
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            SOCKS5AuthNConfig::None => serializer.serialize_str("none"),
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNConfig::GSSAPI { gssapi }
                if gssapi == &ClientGSSAPIConfig::default() =>
            {
                serializer.serialize_str("gssapi")
            }
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNConfig::GSSAPI { gssapi } => {
                let mut state = serializer.serialize_struct("gssapi", 1)?;

                state.serialize_field("gssapi", gssapi)?;

                state.end()
            }
            SOCKS5AuthNConfig::Password { username, password } => {
                let mut state = serializer.serialize_struct("password", 2)?;

                state.serialize_field("username", username)?;
                state.serialize_field("password", password)?;

                state.end()
            }
        }
    }
}

impl TryFrom<SOCKS5AuthNIntermediate> for SOCKS5AuthNConfig {
    type Error = SOCKS5AuthNError;

    fn try_from(
        val: SOCKS5AuthNIntermediate
    ) -> Result<SOCKS5AuthNConfig, SOCKS5AuthNError> {
        match val {
            SOCKS5AuthNIntermediate::Name(name) => match name.as_str() {
                "none" => Ok(SOCKS5AuthNConfig::None),
                #[cfg(feature = "gssapi")]
                "gssapi" => Ok(SOCKS5AuthNConfig::GSSAPI {
                    gssapi: ClientGSSAPIConfig::default()
                }),
                _ => Err(SOCKS5AuthNError::BadKind { name: name })
            },
            SOCKS5AuthNIntermediate::Password { username, password } => {
                Ok(SOCKS5AuthNConfig::Password {
                    username: username,
                    password: password
                })
            }
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNIntermediate::GSSAPI { gssapi } => {
                Ok(SOCKS5AuthNConfig::GSSAPI { gssapi: gssapi })
            }
        }
    }
}

impl<Endpoint> DTLSFarChannelConfig<Endpoint> {
    #[inline]
    pub fn new(tls: TLSChannelConfig<TLSPeerConfig, Endpoint>) -> Self {
        DTLSFarChannelConfig { tls: tls }
    }

    /// Get the TLS channel configuration.
    #[inline]
    pub fn tls(&self) -> &TLSChannelConfig<TLSPeerConfig, Endpoint> {
        &self.tls
    }

    #[inline]
    pub fn take(self) -> TLSChannelConfig<TLSPeerConfig, Endpoint> {
        self.tls
    }
}

impl<Proxy> SOCKS5ConnectConfig<Proxy> {
    /// Create a `SOCKS5ConnectConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_common::config::authn::ClientGSSAPIConfig;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_common::net::IPEndpoint;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::SOCKS5AuthNConfig;
    /// # use constellation_channels::config::SOCKS5ConnectConfig;
    /// # use constellation_channels::config::TCPResolvingNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!("proxy:\n",
    ///                    "  addr: test.example.com\n",
    ///                    "  port: 9050\n",
    ///                    "target:\n",
    ///                    "  addr: en.wikipedia.org\n",
    ///                    "  port: 443\n",
    ///                    "auth:\n",
    ///                    "  username: user\n",
    ///                    "  password: pass\n");
    /// let proxy = IPEndpointAddr::name(String::from("test.example.com"));
    /// let proxy = IPEndpoint::new(proxy, 9050);
    /// let proxy = TCPResolvingNearConnectorConfig::new(proxy,
    ///                                                  AddrsConfig::default(),
    ///                                                  Retry::default());
    /// let target = IPEndpointAddr::name(String::from("en.wikipedia.org"));
    /// let target = IPEndpoint::new(target, 443);
    /// let auth = SOCKS5AuthNConfig::Password {
    ///     username: String::from("user"),
    ///     password: String::from("pass")
    /// };
    ///
    /// assert_eq!(
    ///     SOCKS5ConnectConfig::new(auth, target, proxy),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        auth: SOCKS5AuthNConfig,
        target: IPEndpoint,
        proxy: Proxy
    ) -> Self {
        SOCKS5ConnectConfig {
            auth: auth,
            target: target,
            proxy: proxy
        }
    }

    /// Get the proxy authentication configuration.
    #[inline]
    pub fn auth(&self) -> &SOCKS5AuthNConfig {
        &self.auth
    }

    /// Get the [IPEndpoint] to which the proxy will connect.
    #[inline]
    pub fn target(&self) -> &IPEndpoint {
        &self.target
    }

    /// Get the channel configuration for the connection with the proxy.
    #[inline]
    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// Decompose this `SOCKS5ConnectConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The authentication configuration for authenticating to the proxy
    ///   ([retry](SOCKS5ConnectConfig::auth))
    /// - The [IPEndpoint] to which the proxy will attempt to connect
    ///   ([endpoint](SOCKS5ConnectConfig::endpoint))
    /// - The configuration for the channel for connecting to the proxy
    ///   ([resolve](SOCKS5ConnectConfig::proxy))
    #[inline]
    pub(crate) fn take(self) -> (SOCKS5AuthNConfig, IPEndpoint, Proxy) {
        (self.auth, self.target, self.proxy)
    }
}

impl<Proxy> SOCKS5ConnectPartialConfig<Proxy> {
    /// Create a `SOCKS5ConnectPartialConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_common::config::authn::ClientGSSAPIConfig;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_common::net::IPEndpoint;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::SOCKS5AuthNConfig;
    /// # use constellation_channels::config::SOCKS5ConnectPartialConfig;
    /// # use constellation_channels::config::TCPResolvingNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!("proxy:\n",
    ///                    "  addr: test.example.com\n",
    ///                    "  port: 9050\n",
    ///                    "auth:\n",
    ///                    "  username: user\n",
    ///                    "  password: pass\n");
    /// let proxy = IPEndpointAddr::name(String::from("test.example.com"));
    /// let proxy = IPEndpoint::new(proxy, 9050);
    /// let proxy = TCPResolvingNearConnectorConfig::new(proxy,
    ///                                                  AddrsConfig::default(),
    ///                                                  Retry::default());
    /// let auth = SOCKS5AuthNConfig::Password {
    ///     username: String::from("user"),
    ///     password: String::from("pass")
    /// };
    ///
    /// assert_eq!(
    ///     SOCKS5ConnectPartialConfig::new(auth, proxy),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        auth: SOCKS5AuthNConfig,
        proxy: Proxy
    ) -> Self {
        SOCKS5ConnectPartialConfig {
            auth: auth,
            proxy: proxy
        }
    }

    /// Get the proxy authentication configuration.
    #[inline]
    pub fn auth(&self) -> &SOCKS5AuthNConfig {
        &self.auth
    }

    /// Get the channel configuration for the connection with the proxy.
    #[inline]
    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// Decompose this `SOCKS5ConnectConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The authentication configuration for authenticating to the proxy
    ///   ([retry](SOCKS5ConnectConfig::auth))
    /// - The [IPEndpoint] to which the proxy will attempt to connect
    ///   ([endpoint](SOCKS5ConnectConfig::endpoint))
    /// - The configuration for the channel for connecting to the proxy
    ///   ([resolve](SOCKS5ConnectConfig::proxy))
    #[inline]
    pub(crate) fn take(self) -> (SOCKS5AuthNConfig, Proxy) {
        (self.auth, self.proxy)
    }
}

impl<Proxy, Datagram> SOCKS5AssocConfig<Proxy, Datagram> {
    /// Create a `SOCKS5AssocConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_common::config::authn::ClientGSSAPIConfig;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_common::net::IPEndpoint;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::SOCKS5AuthNConfig;
    /// # use constellation_channels::config::SOCKS5AssocConfig;
    /// # use constellation_channels::config::TCPResolvingNearConnectorConfig;
    /// # use constellation_channels::config::UDPFarChannelConfig;
    /// # use std::path::PathBuf;
    /// # use std::net::SocketAddr;
    /// #
    /// let yaml = concat!("addr: 0.0.0.0\n",
    ///                    "port: 0\n",
    ///                    "proxy:\n",
    ///                    "  addr: test.example.com\n",
    ///                    "  port: 9050\n",
    ///                    "auth:\n",
    ///                    "  username: user\n",
    ///                    "  password: pass\n");
    /// let proxy = IPEndpointAddr::name(String::from("test.example.com"));
    /// let proxy = IPEndpoint::new(proxy, 9050);
    /// let proxy = TCPResolvingNearConnectorConfig::new(proxy,
    ///                                                  AddrsConfig::default(),
    ///                                                  Retry::default());
    /// let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    /// let bind = UDPFarChannelConfig::new(addr.ip(), addr.port());
    /// let auth = SOCKS5AuthNConfig::Password {
    ///     username: String::from("user"),
    ///     password: String::from("pass")
    /// };
    ///
    /// assert_eq!(
    ///     SOCKS5AssocConfig::new(bind, auth, proxy),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        forward: Datagram,
        auth: SOCKS5AuthNConfig,
        proxy: Proxy
    ) -> Self {
        SOCKS5AssocConfig {
            forward: forward,
            auth: auth,
            proxy: proxy
        }
    }

    /// Get the proxy authentication configuration.
    #[inline]
    pub fn auth(&self) -> &SOCKS5AuthNConfig {
        &self.auth
    }

    /// Get the channel configuration for the connection with the proxy.
    #[inline]
    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// Decompose this `SOCKS5AssocConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The channel through which UDP traffic will be forwarded to the proxy.
    /// - The authentication configuration for authenticating to the proxy
    ///   ([retry](SOCKS5AssocConfig::auth))
    /// - The configuration for the channel for connecting to the proxy
    ///   ([resolve](SOCKS5ConnectConfig::proxy))
    #[inline]
    pub(crate) fn take(self) -> (Datagram, SOCKS5AuthNConfig, Proxy) {
        (self.forward, self.auth, self.proxy)
    }
}

impl TCPNearChannelConfigUnsafe {
    #[inline]
    pub fn create(unsafe_allow_ip_addr_creds: bool) -> Self {
        TCPNearChannelConfigUnsafe {
            unsafe_allow_ip_addr_creds: unsafe_allow_ip_addr_creds
        }
    }

    /// Get whether IP addresses can be harvested as credentials.
    #[inline]
    pub fn allow_ip_addr_creds(&self) -> bool {
        self.unsafe_allow_ip_addr_creds
    }
}

impl Default for TCPNearChannelConfigUnsafe {
    #[inline]
    fn default() -> Self {
        TCPNearChannelConfigUnsafe {
            unsafe_allow_ip_addr_creds: false
        }
    }
}

impl TCPNearAcceptorConfig {
    /// Create a new `TCPNearAcceptorConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::TCPNearAcceptorConfig;
    /// # use std::net::IpAddr;
    /// # use std::net::Ipv6Addr;
    /// #
    /// let yaml = concat!("addr: ::0\n",
    ///                    "port: 5014\n");
    ///
    /// assert_eq!(
    ///     TCPNearAcceptorConfig::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5014),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        addr: IpAddr,
        port: u16
    ) -> Self {
        Self::new_with_unsafe(addr, port, TCPNearChannelConfigUnsafe::default())
    }

    #[inline]
    pub fn new_with_unsafe(
        addr: IpAddr,
        port: u16,
        unsafe_opts: TCPNearChannelConfigUnsafe
    ) -> Self {
        TCPNearAcceptorConfig {
            unsafe_opts: unsafe_opts,
            addr: addr,
            port: port
        }
    }

    /// Get the listen address as a [SocketAddr].
    #[inline]
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }

    /// Get the IP address at which this acceptor listens.
    #[inline]
    pub fn ip_addr(&self) -> IpAddr {
        self.addr
    }

    /// Get the port on which this acceptor listens.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &TCPNearChannelConfigUnsafe {
        &self.unsafe_opts
    }
}

impl TCPResolvingNearConnectorConfig {
    /// Create a new `TCPNearConnectorConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_common::net::IPEndpoint;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::ResolverConfig;
    /// # use constellation_channels::config::TCPResolvingNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// # use std::time::Duration;
    /// #
    /// let yaml = concat!("addr: test.example.com\n",
    ///                    "port: 5015\n",
    ///                    "resolve:\n",
    ///                    "  addr-policy:\n",
    ///                    "    - ipv6\n",
    ///                    "  renewal: 10800\n",
    ///                    "  retry:\n",
    ///                    "    factor: 400ms\n",
    ///                    "    exp-base: 2.0\n",
    ///                    "    exp-factor: 2.0\n",
    ///                    "    exp-rounds-cap: 40\n",
    ///                    "    linear-factor: 2.0\n",
    ///                    "    max-random: 500ms\n",
    ///                    "    addend: 25ms\n",
    ///                    "retry:\n",
    ///                    "  factor: 100ms\n",
    ///                    "  exp-base: 2.0\n",
    ///                    "  exp-factor: 1.0\n",
    ///                    "  exp-rounds-cap: 20\n",
    ///                    "  linear-factor: 1.0\n",
    ///                    "  linear-rounds-cap: 50\n",
    ///                    "  max-random: 100ms\n",
    ///                    "  addend: 50ms\n");
    /// let endpoint = IPEndpointAddr::name(String::from("test.example.com"));
    /// let endpoint = IPEndpoint::new(endpoint, 5015);
    /// let retry = Retry::new(Duration::from_millis(400), 2.0, 2.0,
    ///                        40, 2.0, None, Duration::from_millis(500),
    ///                        Duration::from_millis(25));
    /// let resolve = AddrsConfig::new(vec![ AddrKind::IPv6 ],
    ///                                ResolverConfig::new(10800, retry));
    /// let retry = Retry::new(Duration::from_millis(100), 2.0, 1.0,
    ///                        20, 1.0, Some(50), Duration::from_millis(100),
    ///                        Duration::from_millis(50));
    ///
    /// assert_eq!(
    ///     TCPResolvingNearConnectorConfig::new(endpoint, resolve, retry),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        endpoint: IPEndpoint,
        resolve: AddrsConfig,
        retry: Retry
    ) -> Self {
        Self::new_with_unsafe(
            endpoint,
            resolve,
            retry,
            TCPNearChannelConfigUnsafe::default()
        )
    }

    #[inline]
    pub fn new_with_unsafe(
        endpoint: IPEndpoint,
        resolve: AddrsConfig,
        retry: Retry,
        unsafe_opts: TCPNearChannelConfigUnsafe
    ) -> Self {
        TCPResolvingNearConnectorConfig {
            unsafe_opts: unsafe_opts,
            endpoint: endpoint,
            resolve: resolve,
            retry: retry
        }
    }

    /// Get the [IPEndpoint] to which this `TCPConnectorConfig`
    /// attempts to connect.
    #[inline]
    pub fn endpoint(&self) -> &IPEndpoint {
        &self.endpoint
    }

    /// Get the [AddrsConfig] for resolving names into IP addresses.
    #[inline]
    pub fn resolve(&self) -> &AddrsConfig {
        &self.resolve
    }

    /// Get the [Retry] configuration for backoff delays for failed
    /// connection attempt.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &TCPNearChannelConfigUnsafe {
        &self.unsafe_opts
    }

    /// Decompose this `TCPNearConnectorConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The [IPEndpoint] to which this attempts to connect
    ///   ([endpoint](TCPNearConnectorConfig::endpoint))
    /// - The name resolution configuration
    ///   ([resolve](TCPNearConnectorConfig::resolve))
    /// - The retry configuration for failed connection attempts
    ///   ([retry](TCPNearConnectorConfig::retry))
    #[inline]
    pub(crate) fn take(
        self
    ) -> (IPEndpoint, AddrsConfig, Retry, TCPNearChannelConfigUnsafe) {
        (self.endpoint, self.resolve, self.retry, self.unsafe_opts)
    }
}

impl TCPResolvingNearConnectorPartialConfig {
    /// Create a new `TCPNearConnectorPartialConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::retry::Retry;
    /// # use constellation_channels::config::AddrKind;
    /// # use constellation_channels::config::AddrsConfig;
    /// # use constellation_channels::config::ResolverConfig;
    /// # use constellation_channels::config::TCPResolvingNearConnectorPartialConfig;
    /// # use std::path::PathBuf;
    /// # use std::time::Duration;
    /// #
    /// let yaml = concat!("resolve:\n",
    ///                    "  addr-policy:\n",
    ///                    "    - ipv6\n",
    ///                    "  renewal: 10800\n",
    ///                    "  retry:\n",
    ///                    "    factor: 400ms\n",
    ///                    "    exp-base: 2.0\n",
    ///                    "    exp-factor: 2.0\n",
    ///                    "    exp-rounds-cap: 40\n",
    ///                    "    linear-factor: 2.0\n",
    ///                    "    max-random: 500ms\n",
    ///                    "    addend: 25ms\n",
    ///                    "retry:\n",
    ///                    "  factor: 100ms\n",
    ///                    "  exp-base: 2.0\n",
    ///                    "  exp-factor: 1.0\n",
    ///                    "  exp-rounds-cap: 20\n",
    ///                    "  linear-factor: 1.0\n",
    ///                    "  linear-rounds-cap: 50\n",
    ///                    "  max-random: 100ms\n",
    ///                    "  addend: 50ms\n");
    /// let retry = Retry::new(Duration::from_millis(400), 2.0, 2.0,
    ///                        40, 2.0, None, Duration::from_millis(500),
    ///                        Duration::from_millis(25));
    /// let resolve = AddrsConfig::new(vec![ AddrKind::IPv6 ],
    ///                                ResolverConfig::new(10800, retry));
    /// let retry = Retry::new(Duration::from_millis(100), 2.0, 1.0,
    ///                        20, 1.0, Some(50), Duration::from_millis(100),
    ///                        Duration::from_millis(50));
    ///
    /// assert_eq!(
    ///     TCPResolvingNearConnectorPartialConfig::new(resolve, retry),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        resolve: AddrsConfig,
        retry: Retry
    ) -> Self {
        Self::new_with_unsafe(
            resolve,
            retry,
            TCPNearChannelConfigUnsafe::default()
        )
    }

    #[inline]
    pub fn new_with_unsafe(
        resolve: AddrsConfig,
        retry: Retry,
        unsafe_opts: TCPNearChannelConfigUnsafe
    ) -> Self {
        TCPResolvingNearConnectorPartialConfig {
            unsafe_opts: unsafe_opts,
            resolve: resolve,
            retry: retry
        }
    }

    /// Get the [AddrsConfig] for resolving names into IP addresses.
    #[inline]
    pub fn resolve(&self) -> &AddrsConfig {
        &self.resolve
    }

    /// Get the [Retry] configuration for backoff delays for failed
    /// connection attempt.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &TCPNearChannelConfigUnsafe {
        &self.unsafe_opts
    }

    /// Decompose this `TCPNearConnectorConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The name resolution configuration
    ///   ([resolve](TCPNearConnectorConfig::resolve))
    /// - The retry configuration for failed connection attempts
    ///   ([retry](TCPNearConnectorConfig::retry))
    #[inline]
    pub(crate) fn take(
        self
    ) -> (AddrsConfig, Retry, TCPNearChannelConfigUnsafe) {
        (self.resolve, self.retry, self.unsafe_opts)
    }
}

impl TCPNearConnectorPartialConfig {
    /// Create a new `TCPNearConnectorPartialConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new() -> Self {
        Self::new_with_unsafe(TCPNearChannelConfigUnsafe::default())
    }

    #[inline]
    pub fn new_with_unsafe(unsafe_opts: TCPNearChannelConfigUnsafe) -> Self {
        TCPNearConnectorPartialConfig {
            unsafe_opts: unsafe_opts
        }
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &TCPNearChannelConfigUnsafe {
        &self.unsafe_opts
    }

    /// Decompose this `TCPNearConnectorConfig` into its components.
    ///
    /// The components in order are:
    ///
    /// - The name resolution configuration
    ///   ([resolve](TCPNearConnectorConfig::resolve))
    /// - The retry configuration for failed connection attempts
    ///   ([retry](TCPNearConnectorConfig::retry))
    #[inline]
    pub(crate) fn take(self) -> TCPNearChannelConfigUnsafe {
        self.unsafe_opts
    }
}

impl<TLS, Underlying> TLSChannelConfig<TLS, Underlying> {
    /// Create a [TLSChannelConfig] from its components.
    ///
    /// The exact nature of the arguments will depend on the
    /// instantiation of the type parameters (see
    /// [TLSNearAcceptorConfig] and [TLSNearConnectorConfig] for
    /// details)
    #[inline]
    pub fn new(
        tls: TLS,
        underlying: Underlying,
        shutdown_retry: Retry,
        shutdown_timeout: Duration
    ) -> Self {
        TLSChannelConfig {
            tls: tls,
            underlying: underlying,
            shutdown_retry: shutdown_retry,
            shutdown_timeout: shutdown_timeout
        }
    }

    /// Get the TLS configuration.
    #[inline]
    pub fn tls(&self) -> &TLS {
        &self.tls
    }

    /// Get the underlying channel configuration.
    #[inline]
    pub fn underlying(&self) -> &Underlying {
        &self.underlying
    }

    #[inline]
    pub fn shutdown_retry(&self) -> &Retry {
        &self.shutdown_retry
    }

    #[inline]
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Decompose this `TLSChannelConfig` into its components.
    ///
    /// This will decompose into the following components, in order:
    /// - The TLS configuration ([config](TLSChannelConfig::tls))
    /// - The underlying channel configuration
    ///   ([endpoint](TLSChannelConfig::endpoint))
    #[inline]
    pub(crate) fn take(self) -> (TLS, Underlying, Retry, Duration) {
        (
            self.tls,
            self.underlying,
            self.shutdown_retry,
            self.shutdown_timeout
        )
    }

    fn default_shutdown_retry() -> Retry {
        Retry::TERRESTRIAL_NETWORK_DEFAULT.clone()
    }

    fn default_shutdown_timeout() -> Duration {
        Duration::from_secs(15)
    }
}

impl UDPFarChannelConfigUnsafe {
    #[inline]
    pub fn create(unsafe_allow_ip_addr_creds: bool) -> Self {
        UDPFarChannelConfigUnsafe {
            unsafe_allow_ip_addr_creds: unsafe_allow_ip_addr_creds
        }
    }

    #[inline]
    pub fn allow_ip_addr_creds(&self) -> bool {
        self.unsafe_allow_ip_addr_creds
    }
}

impl Default for UDPFarChannelConfigUnsafe {
    #[inline]
    fn default() -> Self {
        UDPFarChannelConfigUnsafe {
            unsafe_allow_ip_addr_creds: false
        }
    }
}

impl UDPFarChannelConfig {
    /// Create a new `TCPNearConnectorConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::UDPFarChannelConfig;
    /// # use constellation_channels::config::UDPFarChannelConfigUnsafe;
    /// # use std::net::SocketAddr;
    /// #
    /// let yaml = concat!("addr: 0.0.0.0\n",
    ///                    "port: 5016\n");
    /// let addr: SocketAddr = "0.0.0.0:5016".parse().unwrap();
    ///
    /// assert_eq!(
    ///     UDPFarChannelConfig::new(addr.ip(), addr.port()),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        addr: IpAddr,
        port: u16
    ) -> Self {
        Self::new_with_unsafe(addr, port, UDPFarChannelConfigUnsafe::default())
    }

    #[inline]
    pub fn new_with_unsafe(
        addr: IpAddr,
        port: u16,
        unsafe_opts: UDPFarChannelConfigUnsafe
    ) -> Self {
        UDPFarChannelConfig {
            unsafe_opts: unsafe_opts,
            addr: addr,
            port: port
        }
    }

    /// Get the IP address to which the socket will be bound.
    #[inline]
    pub fn addr(&self) -> &IpAddr {
        &self.addr
    }

    /// Get the port to which the socket will be bound.
    #[inline]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the unsafe options.
    #[inline]
    pub fn unsafe_opts(&self) -> &UDPFarChannelConfigUnsafe {
        &self.unsafe_opts
    }

    /// Decompose this `UDPFarChannelConfig` into its components.
    #[inline]
    pub(crate) fn take(self) -> (IpAddr, u16, UDPFarChannelConfigUnsafe) {
        (self.addr, self.port, self.unsafe_opts)
    }
}

impl UnixFarChannelConfig {
    /// Create a new `UnixFarChannelConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::UnixFarChannelConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = "path: /var/run/test/test.sock";
    /// let path = PathBuf::from("/var/run/test/test.sock");
    ///
    /// assert_eq!(
    ///     UnixFarChannelConfig::new(path),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(path: PathBuf) -> Self {
        UnixFarChannelConfig { path: path }
    }

    /// Get the path at which the socket is located.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decompose this `UnixFarChannelConfig` into its components.
    #[inline]
    pub fn take(self) -> PathBuf {
        self.path
    }
}

impl UnixNearChannelConfig {
    /// Create a new `UnixNearChannelConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_channels::config::UnixNearChannelConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = "path: /var/run/test/test.sock";
    /// let path = PathBuf::from("/var/run/test/test.sock");
    ///
    /// assert_eq!(
    ///     UnixNearChannelConfig::new(path),
    ///     yaml_serde::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(path: PathBuf) -> Self {
        UnixNearChannelConfig { path: path }
    }

    /// Get the path at which the socket is located.
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decompose this `UnixNearChannelConfig` into its components.
    #[inline]
    pub(crate) fn take(self) -> PathBuf {
        self.path
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

#[cfg(test)]
use std::net::Ipv4Addr;

#[cfg(test)]
use constellation_common::config::authn::GSSAPISecurity;

#[test]
fn test_deserialize_unix_cfg() {
    let yaml = concat!("path: \"/var/run/test/socket.sock\"");
    let expected = UnixNearChannelConfig {
        path: PathBuf::from("/var/run/test/socket.sock")
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tcp_cfg() {
    let yaml = concat!("addr: 10.10.10.10\n", "port: 6000");
    let expected = TCPNearAcceptorConfig {
        unsafe_opts: TCPNearChannelConfigUnsafe::default(),
        addr: IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
        port: 6000
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tcp_connector_cfg() {
    let yaml = concat!(
        "addr: example.com\n",
        "port: 6001\n",
        "resolve:\n",
        "  addr-policy: [ ipv6 ]\n",
        "  renewal: 3600000"
    );
    let expected = TCPResolvingNearConnectorConfig {
        unsafe_opts: TCPNearChannelConfigUnsafe::default(),
        endpoint: IPEndpoint::new(
            IPEndpointAddr::Name(String::from("example.com")),
            6001
        ),
        resolve: AddrsConfig {
            addr_policy: vec![AddrKind::IPv6],
            resolver: ResolverConfig {
                renewal: 1000 * 60 * 60,
                retry: Retry::default()
            }
        },
        retry: Retry::default()
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_dns_resolve() {
    let yaml = concat!("addr-policy: [ ipv6 ]\n", "renewal: 3600000");
    let expected = AddrsConfig {
        addr_policy: vec![AddrKind::IPv6],
        resolver: ResolverConfig {
            renewal: 1000 * 60 * 60,
            retry: Retry::default()
        }
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_none() {
    let yaml = concat!("none\n");
    let expected = SOCKS5AuthNConfig::None;
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_password() {
    let yaml = concat!("username: \"user\"\n", "password: \"password\"\n");
    let expected = SOCKS5AuthNConfig::Password {
        username: String::from("user"),
        password: String::from("password")
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_default() {
    let yaml = concat!("gssapi\n");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::default()
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_name() {
    let yaml = concat!("gssapi:\n", "  name: test");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::new(
            Some(String::from("test")),
            None,
            None,
            GSSAPISecurity::default()
        )
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_service() {
    let yaml = concat!("gssapi:\n", "  service: test");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::new(
            None,
            Some(String::from("test")),
            None,
            GSSAPISecurity::default()
        )
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_optional_seclvl() {
    let yaml = concat!("gssapi:\n", "  security:\n", "    optional: 128");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::new(
            None,
            None,
            None,
            GSSAPISecurity::optional(128)
        )
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_required_seclvl() {
    let yaml = concat!("gssapi:\n", "  security:\n", "    required: 128");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::new(
            None,
            None,
            None,
            GSSAPISecurity::required(128)
        )
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_full() {
    let yaml = concat!(
        "gssapi:\n",
        "  name: test\n",
        "  service: service\n",
        "  security:\n",
        "    required: 128"
    );
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::new(
            Some(String::from("test")),
            Some(String::from("service")),
            None,
            GSSAPISecurity::required(128)
        )
    };
    let actual = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
