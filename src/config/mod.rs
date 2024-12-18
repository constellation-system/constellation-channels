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

//! Configuration structures.
//!
//! This module contains definitions of types that supply
//! configuration information.  Each of these types has a YAML format,
//! which can be parsed using `serde_yaml`, thus allowing
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
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "gssapi")]
use constellation_common::config::authn::ClientGSSAPIConfig;
use constellation_common::net::IPEndpoint;
use constellation_common::retry::Retry;
use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

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

/// Parameters used to create a
/// [BufferedFlows](crate::far::flows::BufferedFlows).
///
/// This allows the size of the various components of `BufferedFlows`
/// to be configured.
///
/// All fields of this configuration object are optional, and in most
/// use cases, this object does not need to be configured.
///
/// # YAML Format
///
/// The YAML format has four fields, all of which are optional:
///
///  - `flow-buf-size`: Size of ring buffers that will be created for each flow.
///
///  - `backlog-size`: Size of the ring buffer for storing new incoming flows.
///
///  - `flows-size-hint`: Size hint, should be roughly equal to the maximum
///    number of live flows.
///
///  - `packet-size`: Maximum size of incoming messages.
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "buffered-flows-params")]
#[serde(rename_all = "kebab-case")]
pub struct BufferedFlowsParams {
    /// Size of ring buffers that will be created for each flow.
    #[serde(default = "BufferedFlowsParams::default_flow_buf_size")]
    flow_buf_size: usize,
    /// Size of the ring buffer for storing new incoming flows.
    #[serde(default = "BufferedFlowsParams::default_backlog_size")]
    backlog_size: usize,
    /// Size hint, should be roughly equal to the maximum number of live flows.
    #[serde(default)]
    flows_size_hint: Option<usize>,
    /// Maximum size of incoming messages.
    #[serde(default = "BufferedFlowsParams::default_packet_size")]
    packet_size: usize
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
///  - `resolve`: An [AddrsConfig] structure.  This is optional, and set to the
///    default value if not present.
///
///  - `flows-params`: A configuration object for creating the type of base
///    [Flows](crate::far::flows::Flows) used for managing flows. This is
///    optional, and set to the default value if not present.
///
///  - `context-params`: A configuration object for creating the type of base
///    [DatagramXfrm](constellation_common::net::DatagramXfrm) used to create
///    flows.  This is optional, and set to the default value if not present.
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
pub struct ChannelRegistryConfig<
    Channel,
    FlowsParams: Default,
    ContextParams: Default
> {
    /// Configuration of all channels.
    channels: Vec<ChannelRegistryEntryConfig<Channel>>,
    /// Resolver configuration.
    #[serde(default)]
    resolve: AddrsConfig,
    /// Context creation parameters.
    #[serde(default)]
    #[serde(rename = "context-params")]
    ctx_params: ContextParams,
    /// Flows creation parameters.
    #[serde(default)]
    flows_params: FlowsParams
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
pub struct ChannelRegistryChannelsConfig<Codec>
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
#[serde(rename = "entry")]
#[serde(rename_all = "kebab-case")]
pub struct ChannelRegistryEntryConfig<Channel> {
    /// Unique name of the channel.
    id: String,
    /// Channel configuration.
    #[serde(flatten)]
    channel: Channel,
    /// Retry configuration.
    #[serde(default)]
    retry: Retry
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
pub enum CompoundEndpoint {
    /// Unix socket address.
    Unix {
        /// Path to the Unix socket.
        unix: PathBuf
    },
    /// IP endpoint.
    IP {
        /// IP address and port
        ip: IPEndpoint
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
        dtls: DTLSFarChannelConfig<Box<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5: SOCKS5AssocConfig<
            Box<CompoundNearConnectorConfig<TLSPeerConfig>>,
            Box<CompoundFarIPChannelConfig>
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
/// - `unix`: Contains a [UnixFarChannelConfig], and creates a
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
/// - `socks5`: Contains a [SOCKS5AssocConfig], and creates a
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
///       unix:
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
        unix: UnixFarChannelConfig
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
        dtls: DTLSFarChannelConfig<Box<Self>>
    },
    /// SOCKS5 proxy channel.
    #[serde(rename_all = "kebab-case")]
    SOCKS5 {
        /// SOCKS5 session negotiation configuration.
        socks5: SOCKS5AssocConfig<
            Box<CompoundNearConnectorConfig<TLSPeerConfig>>,
            Box<CompoundFarIPChannelConfig>
        >
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
/// - `unix`: Contains a [UnixNearChannelConfig], and creates a
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
        unix: UnixNearChannelConfig
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
/// - `unix`: Contains a [UnixNearConnectorConfig], and creates a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector).
///
/// - `tcp`: Contains a [TCPNearConnectorConfig], and creates a
///   [TCPNearConnector](crate::near::tcp::TCPNearConnector).
///
/// - `tls`: Contains a [TLSNearConnectorConfig], and creates a
///   [TLSNearConnector](crate::near::tls::TLSNearConnector).  The underlying
///   channel configuration of this structure is another instance of
///   `CompoundNearConnectorConfig`.
///
/// - `socks5`: Contains a [SOCKS5ConnectConfig], and creates a
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
///   socks5:
///     proxy:
///       unix:
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
pub enum CompoundNearConnectorConfig<TLS: TLSLoadClient> {
    /// UNIX socket channel.
    ///
    /// The service will run as a separate process, and will
    /// communicate via a UNIX domain socket.
    #[serde(rename_all = "kebab-case")]
    Unix {
        /// Unix socket configuration.
        unix: UnixNearConnectorConfig
    },
    /// TCP Channel.
    ///
    /// The service will run separately, and will communicate via a
    /// TCP connection.
    TCP {
        /// TCP socket configuration.
        tcp: TCPNearConnectorConfig
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
        socks5: SOCKS5ConnectConfig<Box<Self>>
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
    #[serde(default)]
    retry: Retry,
    #[serde(flatten)]
    tls: TLSChannelConfig<TLSPeerConfig, Inner>
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
pub struct TCPNearConnectorConfig {
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
    underlying: Underlying
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

/// Unix socket near-link client-side configuration.
///
/// This holds configuration information for near-link clients
/// communicating over Unix domain sockets.
///
/// # YAML Format
///
/// The YAML format has two fields, one of which is mandatory:
///
/// - A [UnixNearChannelConfig] flattened, so its fields will be directly
///   incorporated.  These are:
///
///   - `path`: The path at which the Unix socket exists in the filesystem.
///
/// - `retry`: A [Retry] configuration, describing the retry delay policy when
///   connection attempts fail.  The default values will be used if this field
///   is not present.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example of the YAML format with all fields
/// present:
///
/// ```yaml
/// path: /var/run/test/test.sock
/// retry:
///   factor: 100
///   exp-base: 2.0
///   exp-factor: 1.0
///   exp-rounds-cap: 20
///   linear-factor: 1.0
///   linear-rounds-cap: 50
///   max-random: 100
///   addend: 50
/// ```
///
/// ### Minimal Specification
///
/// The following is a minimal YAML format:
///
/// ```yaml
/// path: /var/run/test/test.sock
/// ```
#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
#[serde(rename = "unix-connector")]
#[serde(rename_all = "kebab-case")]
pub struct UnixNearConnectorConfig {
    /// Channel configuration.
    #[serde(flatten)]
    channel: UnixNearChannelConfig,
    /// Retry configuration.
    #[serde(default)]
    retry: Retry
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
    ///     serde_yaml::from_str(yaml).unwrap()
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

impl<Channel> ChannelRegistryEntryConfig<Channel> {
    /// Create a new `ChannelRegistryEntryConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(
        id: String,
        channel: Channel,
        retry: Retry
    ) -> Self {
        ChannelRegistryEntryConfig {
            id: id,
            channel: channel,
            retry: retry
        }
    }

    /// Get the name of the registry entry.
    #[inline]
    pub fn id(&self) -> &str {
        self.id.as_ref()
    }

    /// Get the channel configuration.
    #[inline]
    pub fn channel(&self) -> &Channel {
        &self.channel
    }

    /// Get the retry configuration.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Decompose a `ChannelRegistryEntryConfig` into its components.
    #[inline]
    pub fn take(self) -> (String, Channel, Retry) {
        (self.id, self.channel, self.retry)
    }
}

impl<Codec> ChannelRegistryChannelsConfig<Codec>
where
    Codec: Default
{
    /// Create a [ChannelRegistryChannelsConfig] from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(codec: Codec) -> Self {
        ChannelRegistryChannelsConfig { codec: codec }
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

impl<Channel, FlowsParams, ContextParams>
    ChannelRegistryConfig<Channel, FlowsParams, ContextParams>
where
    FlowsParams: Default,
    ContextParams: Default
{
    /// Create a new `ChannelRegistryConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format.  See documentation for details.
    #[inline]
    pub fn new(
        channels: Vec<ChannelRegistryEntryConfig<Channel>>,
        resolve: AddrsConfig,
        flows_params: FlowsParams,
        ctx_params: ContextParams
    ) -> Self {
        ChannelRegistryConfig {
            channels: channels,
            resolve: resolve,
            flows_params: flows_params,
            ctx_params: ctx_params
        }
    }

    /// Get the channel configurations.
    #[inline]
    pub fn channels(&self) -> &[ChannelRegistryEntryConfig<Channel>] {
        &self.channels
    }

    /// Get the resolver configuration.
    #[inline]
    pub fn resolve(&self) -> &AddrsConfig {
        &self.resolve
    }

    /// Get the flows creation parameters.
    #[inline]
    pub fn flows_params(&self) -> &FlowsParams {
        &self.flows_params
    }

    /// Get the context creation parameters.
    #[inline]
    pub fn ctx_params(&self) -> &ContextParams {
        &self.ctx_params
    }

    /// Decompose a `ChannelRegistryEntryConfig` into its components.
    #[inline]
    pub fn take(
        self
    ) -> (
        Vec<ChannelRegistryEntryConfig<Channel>>,
        AddrsConfig,
        FlowsParams,
        ContextParams
    ) {
        (
            self.channels,
            self.resolve,
            self.flows_params,
            self.ctx_params
        )
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

impl From<IPEndpoint> for CompoundEndpoint {
    #[inline]
    fn from(val: IPEndpoint) -> Self {
        CompoundEndpoint::IP { ip: val }
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
    ///     serde_yaml::from_str(yaml).unwrap()
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

impl BufferedFlowsParams {
    /// Create a [BufferedFlowsParams] from its components.
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
    /// # use constellation_channels::config::BufferedFlowsParams;
    /// #
    /// let yaml = concat!("flows-size-hint: 36\n",
    ///                    "backlog-size: 64\n",
    ///                    "flow-buf-size: 128\n",
    ///                    "packet-size: 1500\n");
    ///
    /// assert_eq!(
    ///     BufferedFlowsParams::new(128, 64, Some(36), 1500),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        flow_buf_size: usize,
        backlog_size: usize,
        flows_size_hint: Option<usize>,
        packet_size: usize
    ) -> Self {
        BufferedFlowsParams {
            flows_size_hint: flows_size_hint,
            flow_buf_size: flow_buf_size,
            backlog_size: backlog_size,
            packet_size: packet_size
        }
    }

    /// Get the size of ring buffers that will be created for each
    /// flow.
    #[inline]
    pub fn flows_size_hint(&self) -> Option<usize> {
        self.flows_size_hint
    }

    /// Get the maximum size of incoming messages.
    #[inline]
    pub fn packet_size(&self) -> usize {
        self.packet_size
    }

    /// Get the size of the ring buffer for storing new incoming
    /// flows.
    #[inline]
    pub fn backlog_size(&self) -> usize {
        self.backlog_size
    }

    /// Get the size hint for the live flows.
    #[inline]
    pub fn flow_buf_size(&self) -> usize {
        self.flow_buf_size
    }

    #[inline]
    fn default_flow_buf_size() -> usize {
        128
    }

    #[inline]
    fn default_packet_size() -> usize {
        1536
    }

    #[inline]
    fn default_backlog_size() -> usize {
        256
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
    ///     serde_yaml::from_str(yaml).unwrap()
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
    ///     serde_yaml::from_str(yaml).unwrap()
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

impl Default for BufferedFlowsParams {
    #[inline]
    fn default() -> Self {
        BufferedFlowsParams {
            flow_buf_size: BufferedFlowsParams::default_flow_buf_size(),
            backlog_size: BufferedFlowsParams::default_backlog_size(),
            packet_size: ThreadedFlowsParams::default_packet_size(),
            flows_size_hint: None
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
    pub fn new(
        tls: TLSChannelConfig<TLSPeerConfig, Endpoint>,
        retry: Retry
    ) -> Self {
        DTLSFarChannelConfig {
            tls: tls,
            retry: retry
        }
    }

    /// Get the TLS channel configuration.
    #[inline]
    pub fn tls(&self) -> &TLSChannelConfig<TLSPeerConfig, Endpoint> {
        &self.tls
    }

    /// Get the retry configuration.
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    #[inline]
    pub fn take(self) -> (TLSChannelConfig<TLSPeerConfig, Endpoint>, Retry) {
        (self.tls, self.retry)
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
    /// # use constellation_channels::config::TCPNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!("proxy:\n",
    ///                    "  addr: test.example.com\n",
    ///                    "  port: 9050\n",
    ///                    "target:\n",
    ///                    "  addr: en.wikipedia.org\n",
    ///                    "  port: 443\n",
    ///                    "auth: gssapi");
    /// let proxy = IPEndpointAddr::name(String::from("test.example.com"));
    /// let proxy = IPEndpoint::new(proxy, 9050);
    /// let proxy = TCPNearConnectorConfig::new(proxy,
    ///                                         AddrsConfig::default(),
    ///                                         Retry::default());
    /// let target = IPEndpointAddr::name(String::from("en.wikipedia.org"));
    /// let target = IPEndpoint::new(target, 443);
    /// let auth = SOCKS5AuthNConfig::GSSAPI {
    ///     gssapi: ClientGSSAPIConfig::default()
    /// };
    ///
    /// assert_eq!(
    ///     SOCKS5ConnectConfig::new(auth, target, proxy),
    ///     serde_yaml::from_str(yaml).unwrap()
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
    /// # use constellation_channels::config::TCPNearConnectorConfig;
    /// # use constellation_channels::config::UDPFarChannelConfig;
    /// # use std::path::PathBuf;
    /// # use std::net::SocketAddr;
    /// #
    /// let yaml = concat!("addr: 0.0.0.0\n",
    ///                    "port: 0\n",
    ///                    "proxy:\n",
    ///                    "  addr: test.example.com\n",
    ///                    "  port: 9050\n",
    ///                    "auth: gssapi");
    /// let proxy = IPEndpointAddr::name(String::from("test.example.com"));
    /// let proxy = IPEndpoint::new(proxy, 9050);
    /// let proxy = TCPNearConnectorConfig::new(proxy,
    ///                                         AddrsConfig::default(),
    ///                                         Retry::default());
    /// let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    /// let bind = UDPFarChannelConfig::new(addr.ip(), addr.port());
    /// let auth = SOCKS5AuthNConfig::GSSAPI {
    ///     gssapi: ClientGSSAPIConfig::default()
    /// };
    ///
    /// assert_eq!(
    ///     SOCKS5AssocConfig::new(bind, auth, proxy),
    ///     serde_yaml::from_str(yaml).unwrap()
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
    ///     serde_yaml::from_str(yaml).unwrap()
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

impl TCPNearConnectorConfig {
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
    /// # use constellation_channels::config::TCPNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!("addr: test.example.com\n",
    ///                    "port: 5015\n",
    ///                    "resolve:\n",
    ///                    "  addr-policy:\n",
    ///                    "    - ipv6\n",
    ///                    "  renewal: 10800\n",
    ///                    "  retry:\n",
    ///                    "    factor: 400\n",
    ///                    "    exp-base: 2.0\n",
    ///                    "    exp-factor: 2.0\n",
    ///                    "    exp-rounds-cap: 40\n",
    ///                    "    linear-factor: 2.0\n",
    ///                    "    max-random: 500\n",
    ///                    "    addend: 25\n",
    ///                    "retry:\n",
    ///                    "  factor: 100\n",
    ///                    "  exp-base: 2.0\n",
    ///                    "  exp-factor: 1.0\n",
    ///                    "  exp-rounds-cap: 20\n",
    ///                    "  linear-factor: 1.0\n",
    ///                    "  linear-rounds-cap: 50\n",
    ///                    "  max-random: 100\n",
    ///                    "  addend: 50\n");
    /// let endpoint = IPEndpointAddr::name(String::from("test.example.com"));
    /// let endpoint = IPEndpoint::new(endpoint, 5015);
    /// let retry = Retry::new(400, 2.0, 2.0, 40, 2.0, None, 500, 25);
    /// let resolve = AddrsConfig::new(vec![ AddrKind::IPv6 ],
    ///                                ResolverConfig::new(10800, retry));
    /// let retry = Retry::new(100, 2.0, 1.0, 20, 1.0, Some(50), 100, 50);
    ///
    /// assert_eq!(
    ///     TCPNearConnectorConfig::new(endpoint, resolve, retry),
    ///     serde_yaml::from_str(yaml).unwrap()
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
        TCPNearConnectorConfig {
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
        underlying: Underlying
    ) -> Self {
        TLSChannelConfig {
            tls: tls,
            underlying: underlying
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

    /// Decompose this `TLSChannelConfig` into its components.
    ///
    /// This will decompose into the following components, in order:
    /// - The TLS configuration ([config](TLSChannelConfig::tls))
    /// - The underlying channel configuration
    ///   ([endpoint](TLSChannelConfig::endpoint))
    #[inline]
    pub(crate) fn take(self) -> (TLS, Underlying) {
        (self.tls, self.underlying)
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
    ///     serde_yaml::from_str(yaml).unwrap()
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
    ///     serde_yaml::from_str(yaml).unwrap()
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
    ///     serde_yaml::from_str(yaml).unwrap()
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

impl UnixNearConnectorConfig {
    /// Create a new `UnixNearConnectorConfig` from its components.
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
    /// # use constellation_channels::config::UnixNearChannelConfig;
    /// # use constellation_channels::config::UnixNearConnectorConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!("path: /var/run/test/test.sock\n",
    ///                    "retry:\n",
    ///                    "  factor: 100\n",
    ///                    "  exp-base: 2.0\n",
    ///                    "  exp-factor: 1.0\n",
    ///                    "  exp-rounds-cap: 20\n",
    ///                    "  linear-factor: 1.0\n",
    ///                    "  linear-rounds-cap: 50\n",
    ///                    "  max-random: 100\n",
    ///                    "  addend: 50\n");
    /// let path = PathBuf::from("/var/run/test/test.sock");
    /// let channel = UnixNearChannelConfig::new(path);
    /// let retry = Retry::new(100, 2.0, 1.0, 20, 1.0, Some(50), 100, 50);
    ///
    /// assert_eq!(
    ///     UnixNearConnectorConfig::new(channel, retry),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// );
    /// ```
    #[inline]
    pub fn new(
        channel: UnixNearChannelConfig,
        retry: Retry
    ) -> Self {
        UnixNearConnectorConfig {
            channel: channel,
            retry: retry
        }
    }

    /// Get the underlying channel configuration.
    #[inline]
    pub fn channel(&self) -> &UnixNearChannelConfig {
        &self.channel
    }

    /// Get the retry configuration
    #[inline]
    pub fn retry(&self) -> &Retry {
        &self.retry
    }

    /// Decompose this `UnixNearConnectorConfig` into its components.
    ///
    /// This will decompose into the following components, in order:
    /// - The channel configuration ([config](UnixNearConnectorConfig::channel))
    /// - The retry configuration ([retry](UnixNearConnectorConfig::retry))
    #[inline]
    pub(crate) fn take(self) -> (UnixNearChannelConfig, Retry) {
        (self.channel, self.retry)
    }
}

#[cfg(test)]
use std::net::Ipv4Addr;

#[cfg(test)]
use constellation_common::config::authn::GSSAPISecurity;
#[cfg(test)]
use constellation_common::net::IPEndpointAddr;

#[test]
fn test_deserialize_unix_cfg() {
    let yaml = concat!("path: \"/var/run/test/socket.sock\"");
    let expected = UnixNearChannelConfig {
        path: PathBuf::from("/var/run/test/socket.sock")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_unix_connector_cfg() {
    let yaml = concat!("path: \"/var/run/test/socket.sock\"\n");
    let expected = UnixNearConnectorConfig {
        channel: UnixNearChannelConfig {
            path: PathBuf::from("/var/run/test/socket.sock")
        },
        retry: Retry::default()
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let expected = TCPNearConnectorConfig {
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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_none() {
    let yaml = concat!("none\n");
    let expected = SOCKS5AuthNConfig::None;
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_password() {
    let yaml = concat!("username: \"user\"\n", "password: \"password\"\n");
    let expected = SOCKS5AuthNConfig::Password {
        username: String::from("user"),
        password: String::from("password")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "gssapi")]
#[test]
fn test_deserialize_client_gssapi_default() {
    let yaml = concat!("gssapi\n");
    let expected = SOCKS5AuthNConfig::GSSAPI {
        gssapi: ClientGSSAPIConfig::default()
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

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
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}
