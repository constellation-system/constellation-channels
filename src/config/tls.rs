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

//! Configuration structures for TLS contexts.
//!
//! This module provides several structures that can be readily
//! converted into TLS contexts for establishing and running TLS
//! sessions.  The primary structures are as follows:
//!
//! - [TLSClientConfig] represents configuration information for
//!   client-side TLS contexts.
//!
//! - [TLSServerConfig] represents configuration information for
//!   server-side TLS contexts.
//!
//! - [TLSPeerConfig] represents configuration information for
//!   peer-to-peer TLS contexts.
//!
//! Each of these structures has a YAML format, which can be parsed
//! using `serde_yaml` to load configurations from plaintext.  See the
//! documentation for each structure for examples.
use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "openssl")]
use std::time::SystemTime;

use constellation_common::config::pki::PKITrustRoot;
use constellation_common::config::pki::PKITrustRootLoadError;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
#[cfg(feature = "openssl")]
use constellation_common::net::IPEndpointAddr;
use log::debug;
use log::trace;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack;
#[cfg(feature = "openssl")]
use openssl::ssl::SslAcceptor;
#[cfg(feature = "openssl")]
use openssl::ssl::SslConnector;
#[cfg(feature = "openssl")]
use openssl::ssl::SslFiletype;
#[cfg(feature = "openssl")]
use openssl::ssl::SslMethod;
#[cfg(feature = "openssl")]
use openssl::ssl::SslVerifyMode;
#[cfg(feature = "openssl")]
use openssl::ssl::SslVersion;
use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

/// Trait for TLS configurations that can be loaded as a client
/// configuration.
pub trait TLSLoadClient {
    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [SslConnector] from this configuration.
    ///
    /// This create a new [SslConnector] and then use the
    /// configuration information in this object as arguments to its
    /// corresponding configuration functions.  The resulting object
    /// is then usable for establishing TLS connections.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.  The
    /// `endpoint` parameter supplied an [IPEndpointAddr] implied by the
    /// underlying channel, if one exists.  This will be overridden by
    /// the `verify_endpoint` field on the configuration, if that
    /// exists.  If both `endpoint` and the `verify_endpoint` field
    /// are `None`, then an error will be returned.
    ///
    /// Additionally, the [SslConnector] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    fn load_client(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: &IPEndpointAddr,
        dtls: bool
    ) -> Result<SslConnector, TLSLoadConfigError>;

    /// Get the endpoint checked against server CN or SAN fields.
    #[inline]
    fn verify_endpoint(&self) -> Option<&IPEndpointAddr> {
        None
    }
}

/// Trait for TLS configurations that can be loaded as a server
/// configuration.
pub trait TLSLoadServer {
    #[cfg(feature = "openssl")]
    /// Generate an OpenSSL [SslAcceptor] from this configuration.
    ///
    /// This create a new [SslAcceptor] and then use the
    /// configuration information in this object as arguments to its
    /// corresponding configuration functions.  The resulting object
    /// is then usable for accepting TLS connections.
    ///
    /// The `verify_time` parameter optionally sets the time that will
    /// be checked against certificate validity and expiry times.
    ///
    /// Additionally, the [SslAcceptor] will be configured in the
    /// following ways:
    ///
    /// - The minimum protocol version will be set to TLS 1.3
    fn load_server(
        &self,
        verify_time: Option<SystemTime>,
        dtls: bool
    ) -> Result<SslAcceptor, TLSLoadConfigError>;
}

/// Errors that can occur when converting a configuration into an
/// implementation-specfic TLS context.
#[derive(Debug)]
pub enum TLSLoadConfigError {
    /// An error occured loading a [PKITrustRoot].
    PKITrustRoot {
        /// The error from loading the [PKITrustRoot].
        error: PKITrustRootLoadError
    },
    /// A low-level I/O error occurred.
    IO {
        /// The low-level I/O error
        error: std::io::Error
    },
    #[cfg(feature = "openssl")]
    /// An OpenSSL-specific error occurred.
    ///
    /// This applies only when the `openssl` feature is enabled.
    OpenSSL {
        /// The OpenSSL [ErrorStack].
        error: ErrorStack
    },
}

/// Client authentication mode.
///
/// This is used to set how servers check client certificates, if
/// client authentication is enabled.  The [Default] value is
/// [Required](TLSClientAuthMode::Required).
///
/// # YAML Format
///
/// The YAML format for this type is simply a string specifying the mode:
/// - [Required](TLSClientAuthMode::Required) is encoded as `required`.
/// - [Optional](TLSClientAuthMode::Optional) is encoded as `optional`.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum TLSClientAuthMode {
    /// Require client authentication.
    ///
    /// This will request a client certificate, and will cause
    /// negotiation to fail if one is not provided.
    ///
    /// This option is necessary in any configuration where client
    /// certificates are used as a broader authentication mechanism.
    ///
    /// The YAML format for this option is the string `required`.
    #[default]
    Required,
    /// Check client certificates, but don't require them.
    ///
    /// This will request a client certificate, and will fail
    /// negotiation if one is provided that does not check out;
    /// however, it will allow negotiation to succeed if the client
    /// does not provide any certificate at all.
    ///
    /// This option is typically used as a security enhancement, and
    /// can also be used as an authentication mechanism where
    /// anonymous roles are allowed.
    ///
    /// The YAML format for this option is the string `optional`.
    Optional
}

/// Client-side client certificate authentication configuration.
///
/// This is used to configure client certificate authentication on the
/// client.  Its function is to provide the client certificate,
/// additional verification chain, and key that will be used.
///
/// # YAML Format
///
/// The YAML format has three fields:
///
/// - `client-cert`: A path to a file containing a PEM-encoded client
///   certificate.
/// - `client-cert-chain`: A path to a file containing a PEM-encoded certificate
///   chain.  This field is optional, and the default is to specify no
///   certificate chain.
/// - `client-key`: A path to a PEM-encoded private key.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following YAML example shows a full client certificate
/// authentication configuration:
///
/// ```yaml
/// client-cert: /etc/ssl/certs/client-cert.pem
/// client-cert-chain: /etc/ssl/certs/client-chain.pem
/// client-key: /etc/ssl/private/client-key.pem
/// ```
///
/// ### Minimal Specification
///
/// The `client-cert-chain` option can be omitted, in which case no
/// certificate chain will be configured:
///
/// ```yaml
/// client-cert: /etc/ssl/certs/client-cert.pem
/// client-key: /etc/ssl/private/client-key.pem
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(rename = "client-auth-client")]
pub struct TLSClientClientAuthConfig {
    /// Path to a PEM-encoded client certificate.
    client_cert: PathBuf,
    /// Optional path to a PEM-encoded client certificate chain.
    ///
    /// If omitted, no certificate chain will be used.
    #[serde(default)]
    client_cert_chain: Option<PathBuf>,
    /// Path to a PEM-encoded client authentication key.
    client_key: PathBuf
}

/// Server-side client certificate authentication configuration.
///
/// This is used to configure client certificate authentication on the
/// server.  Its function is to establish a root of trust for client
/// certificates, as well as the mode for verifying client
/// certificates.
///
/// # YAML Format
///
/// The YAML format has two fields:
/// - `verify`: A [TLSClientAuthMode], describing how to verify client
///   certificates.  This field is optional, and will default to `required`.
/// - `trust-root`: A [PKITrustRoot], providing the trust root used to verify
///   client certificates.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following YAML example shows a full client certificate
/// authentication configuration, with optional certificate
/// authentication (see [PKITrustRoot] for details on its YAML
/// format):
///
/// ```yaml
/// verify: optional
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/client-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/client-ca-crl.pem
/// ```
///
/// ### Minimal Specification
///
/// The `verify` option can be omitted, in which case it will default
/// to `required`:
///
/// ```yaml
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/client-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/client-ca-crl.pem
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[serde(rename = "client-auth-server")]
pub struct TLSServerClientAuthConfig {
    /// Client certificate verification mode.
    ///
    /// This specifies how to verify client certificates.  See
    /// [TLSClientAuthMode] for details.
    #[serde(default)]
    verify: TLSClientAuthMode,
    /// The root of trust used to verify client certificates.
    trust_root: PKITrustRoot
}

/// Client-side TLS configuration.
///
/// This is used to configure a TLS context on the client side.  It
/// provides the following:
/// - Cryptographic primitive selections, consisting of the following:
///   - Cipher suites, used to encrypt data in transit.
///   - Key-exchange groups, used to establish session keys
///   - Acceptable signature algorithms, used to verify client and server
///     certificates
/// - Client authentication configuration, providing the client certificate and
///   other cryptographic materials (see [TLSClientClientAuthConfig])
/// - Trust root and other information used for verifying the server certificate
///
/// This configuration can be converted into an
/// implementation-specific context using the
/// [load_client](TLSLoadClient::load_client) function.  See the function
/// documentation for details.
///
/// # YAML Format
///
/// The YAML format has six fields, broken down into three categories.
/// Of these categories, only the verification information is
/// mandatory:
///
/// - Cryptographic primitives.  These specify what cryptographic primitives to
///   use, and in what order of preference.
///
///   - `cipher-suites`: A list of cipher suites in order of preference.  Only
///     the following are guaranteed to be supported:
///
///     - `TLS_CHACHA20_POLY1305_SHA256`
///     - `TLS_AES_256_GCM_SHA384`
///     - `TLS_AES_128_GCM_SHA256`
///
///   - `key-exchange-groups`: A list of key-exchange groups in order of
///     preference.  In general, only elliptic-curve groups are supported, and
///     only post-quantum groups will be added in the future.  Only the
///     following are guaranteed to be supported:
///
///     - `P-521` (OpenSSL only)
///     - `P-384`
///     - `P-256`
///     - `X448` (OpenSSL only)
///     - `X25519`
///
///   - `signature-algorithms`: A list of signature algorithms in order of
///     preference.  In general, only elliptic-curve algorithms are supported,
///     and only post-quantum signature algorithms will be supported in the
///     future.  Only the following are guaranteed to be supported:
///
///     - `ecdsa_secp521r1_sha512`
///     - `ed448`
///     - `ecdsa_secp384r1_sha384`
///     - `ecdsa_secp256r1_sha256`
///     - `ed25519`
///
/// - Client certificate authentication configuration.  This consists of a
///   single [TLSClientClientAuthConfig] object, but flattened, producing three
///   fields:
///
///   - `client-cert`: A path to a file containing a PEM-encoded client
///     certificate.
///   - `client-cert-chain`: A path to a file containing a PEM-encoded
///     certificate chain.  This field is optional, and the default is to
///     specify no certificate chain.
///   - `client-key`: A path to a PEM-encoded private key.
///
/// - Verification information.  These fields provide the information necessary
///   to verify the server certificate.
///
///   - `trust-root`: A [PKITrustRoot] structure providing the trust root that
///     will be used to verify the serer certificate.  This field is mandatory.
///
///   - `verify-endpoint`: An [IPEndpointAddr] that will be checked against the
///     CN or SAN fields of the server certificate.  If present, this field will
///     override any such endpoint implied by the underlying channel.  If this
///     field is absent, then the underlying channel's endpoint will be used;
///     however, if the channel has no such implied endpoint, then this field is
///     mandatory.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example with every field specified.  The
/// default values are shown for the `cipher-suites`,
/// `key-exchange-groups`, and `signature-algorithms` parameters.
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
/// ```
///
/// ### Minimal Specification
///
/// The following shows a minimal specification, with all optional
/// fields omitted:
///
/// ```yaml
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/server-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/server-ca-crl.pem
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "tls-client")]
#[serde(rename_all = "kebab-case")]
pub struct TLSClientConfig {
    /// TLS cipher suites.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_cipher_suites")]
    cipher_suites: Vec<String>,
    /// TLS key exchange groups.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_kx_groups")]
    key_exchange_groups: Vec<String>,
    /// TLS signature algorithms.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_signature_algs")]
    signature_algorithms: Vec<String>,
    /// TLS client certificate and key.
    #[serde(flatten)]
    client_auth: Option<TLSClientClientAuthConfig>,
    /// TLS trust root for verifying server certs.
    trust_root: PKITrustRoot,
    /// Endpoint override to use for verification.
    ///
    /// This will override the endpoint obtained from the
    /// communications layer, if present.
    #[serde(default)]
    verify_endpoint: Option<IPEndpointAddr>
}

/// Server-side TLS configuration.
///
/// This is used to configure a TLS context on the server side.  It
/// provides the following:
/// - Cryptographic primitive selections, consisting of the following:
///   - Cipher suites, used to encrypt data in transit.
///   - Key-exchange groups, used to establish session keys
///   - Acceptable signature algorithms, used to verify client and server
///     certificates
/// - Client authentication configuration, used to verify clients (see
///   [TLSServerClientAuthConfig])
/// - Cryptographic materials, consisting of the following:
///   - The server certificate (public key)
///   - An optional certificate chain
///   - The private key corresponding to the certificate
///
/// This configuration can be converted into an
/// implementation-specific context using the
/// [load_server](TLSLoadServer::load_server) function.  See the function
/// documentation for details.
///
/// # YAML Format
///
/// The YAML format has seven fields, broken down into three
/// categories.  Of these categories, only the cryptographic materials
/// are mandatory:
///
/// - Cryptographic primitives.  These specify what cryptographic primitives to
///   use, and in what order of preference.
///
///   - `cipher-suites`: A list of cipher suites in order of preference.  Only
///     the following are guaranteed to be supported:
///
///     - `TLS_CHACHA20_POLY1305_SHA256`
///     - `TLS_AES_256_GCM_SHA384`
///     - `TLS_AES_128_GCM_SHA256`
///
///   - `key-exchange-groups`: A list of key-exchange groups in order of
///     preference.  In general, only elliptic-curve groups are supported, and
///     only post-quantum groups will be added in the future.  Only the
///     following are guaranteed to be supported:
///
///     - `P-521` (OpenSSL only)
///     - `P-384`
///     - `P-256`
///     - `X448` (OpenSSL only)
///     - `X25519`
///
///   - `signature-algorithms`: A list of signature algorithms in order of
///     preference.  In general, only elliptic-curve algorithms are supported,
///     and only post-quantum signature algorithms will be supported in the
///     future.  Only the following are guaranteed to be supported:
///
///     - `ecdsa_secp521r1_sha512`
///     - `ed448`
///     - `ecdsa_secp384r1_sha384`
///     - `ecdsa_secp256r1_sha256`
///     - `ed25519`
///
/// - Client certificate authentication configuration.  This specifies whether
///   and how to authenticate client certificates.  If omitted, this section
///   defaults to no client certificate authentication.
///
///   - `client-auth`: An optional structure describing a
///     [TLSServerClientAuthConfig].  If omitted, this field will disable all
///     client certificate authentication, and will request no certificate from
///     the client.
///
/// - Cryptographic materials.  These fields specify the materials used by the
///   server to set up TLS sessions.
///
///   - `cert`: Path to a file containing the PEM-encoded server certificate.
///   - `cert-chain`: Optional path to a file containing a PEM-encoded
///     certificate chain.  If this field is omitted, no certificate chain will
///     be used.
///   - `key`: Path to a file containing the PEM-encoded private key.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example with every field specified.  The
/// default values are shown for the `cipher-suites`,
/// `key-exchange-groups`, and `signature-algorithms` parameters.
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
/// ```
///
/// ### Minimal Specification
///
/// The following shows a minimal specification, with all optional
/// fields omitted:
///
/// ```yaml
/// cert: /etc/ssl/certs/server-cert.pem
/// key: /etc/ssl/private/key.pem
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "tls-server")]
#[serde(rename_all = "kebab-case")]
pub struct TLSServerConfig {
    /// TLS cipher suites.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_cipher_suites")]
    cipher_suites: Vec<String>,
    /// TLS key exchange groups.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_kx_groups")]
    key_exchange_groups: Vec<String>,
    /// TLS signature algorithms.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_signature_algs")]
    signature_algorithms: Vec<String>,
    /// TLS trust root for verifying client certs.
    #[serde(default)]
    client_auth: Option<TLSServerClientAuthConfig>,
    /// TLS certificate chain.
    #[serde(default)]
    cert_chain: Option<PathBuf>,
    /// TLS certificate.
    cert: PathBuf,
    /// TLS private key.
    key: PathBuf
}

/// Peer-to-peer TLS configuration.
///
/// This is used to configure a TLS context for peer-to-peer
/// operation, where it is necessary to extract both a client and server
/// configuration.  It provides the following:
/// - Cryptographic primitive selections, consisting of the following:
///   - Cipher suites, used to encrypt data in transit.
///   - Key-exchange groups, used to establish session keys
///   - Acceptable signature algorithms, used to verify client and server
///     certificates
/// - Cryptographic materials, consisting of the following:
///   - The PKI certificate (public key)
///   - An optional certificate chain
///   - The private key corresponding to the certificate
/// - Trust root and other information used for verifying the peer certificate
///
/// This configuration can be converted into an
/// implementation-specific context using both the
/// [load_client](TLSLoadClient::load_client) and
/// [load_server](TLSLoadServer::load_server) functions.  See the
/// function documentation for details.
///
/// Note that a `verify-endpoint` *cannot* be specified for this
/// configuration format, unlike with [TLSClientConfig].
///
/// # YAML Format
///
/// The YAML format has six fields, broken down into three categories.
/// Of these categories, only the verification information is
/// mandatory:
///
/// - Cryptographic primitives.  These specify what cryptographic primitives to
///   use, and in what order of preference.
///
///   - `cipher-suites`: A list of cipher suites in order of preference.  Only
///     the following are guaranteed to be supported:
///
///     - `TLS_CHACHA20_POLY1305_SHA256`
///     - `TLS_AES_256_GCM_SHA384`
///     - `TLS_AES_128_GCM_SHA256`
///
///   - `key-exchange-groups`: A list of key-exchange groups in order of
///     preference.  In general, only elliptic-curve groups are supported, and
///     only post-quantum groups will be added in the future.  Only the
///     following are guaranteed to be supported:
///
///     - `P-521` (OpenSSL only)
///     - `P-384`
///     - `P-256`
///     - `X448` (OpenSSL only)
///     - `X25519`
///
///   - `signature-algorithms`: A list of signature algorithms in order of
///     preference.  In general, only elliptic-curve algorithms are supported,
///     and only post-quantum signature algorithms will be supported in the
///     future.  Only the following are guaranteed to be supported:
///
///     - `ecdsa_secp521r1_sha512`
///     - `ed448`
///     - `ecdsa_secp384r1_sha384`
///     - `ecdsa_secp256r1_sha256`
///     - `ed25519`
///
/// - Cryptographic materials.  These fields specify the materials used by the
///   server to set up TLS sessions.
///
///   - `cert`: Path to a file containing the PEM-encoded server certificate.
///   - `cert-chain`: Optional path to a file containing a PEM-encoded
///     certificate chain.  If this field is omitted, no certificate chain will
///     be used.
///   - `key`: Path to a file containing the PEM-encoded private key.
///
/// - Verification information.  These fields provide the information necessary
///   to verify the server certificate.
///
///   - `trust-root`: A [PKITrustRoot] structure providing the trust root that
///     will be used to verify the serer certificate.  This field is mandatory.
///
/// ## Examples
///
/// The following are example YAML configurations.
///
/// ### Full Specification
///
/// The following is an example with every field specified.  The
/// default values are shown for the `cipher-suites`,
/// `key-exchange-groups`, and `signature-algorithms` parameters.
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
/// cert: /etc/ssl/certs/peer-cert.pem
/// cert-chain: /etc/ssl/certs/peer-chain.pem
/// key: /etc/ssl/private/peer-key.pem
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/peer-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/peer-ca-crl.pem
/// ```
///
/// ### Minimal Specification
///
/// The following shows a minimal specification, with all optional
/// fields omitted:
///
/// ```yaml
/// cert: /etc/ssl/certs/peer-cert.pem
/// key: /etc/ssl/private/peer-key.pem
/// trust-root:
///   root-certs:
///     - /etc/ssl/certs/peer-ca-cert.pem
///   crls:
///     - /etc/ssl/crls/peer-ca-crl.pem
/// ```
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename = "tls-peer")]
#[serde(rename_all = "kebab-case")]
pub struct TLSPeerConfig {
    /// TLS cipher suites.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_cipher_suites")]
    cipher_suites: Vec<String>,
    /// TLS key exchange groups.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_kx_groups")]
    key_exchange_groups: Vec<String>,
    /// TLS signature algorithms.
    ///
    /// If this is an empty vector, the defaults are used.
    #[serde(default = "default_signature_algs")]
    signature_algorithms: Vec<String>,
    /// TLS certificate chain.
    #[serde(default)]
    cert_chain: Option<PathBuf>,
    /// TLS certificate.
    cert: PathBuf,
    /// TLS private key.
    key: PathBuf,
    /// TLS trust root for verifying server certs.
    trust_root: PKITrustRoot
}

fn default_cipher_suites() -> Vec<String> {
    vec![String::from("TLS_AES_256_GCM_SHA384")]
}

fn default_kx_groups() -> Vec<String> {
    vec![
        #[cfg(feature = "openssl")]
        String::from("P-521"),
        String::from("P-384"),
    ]
}

fn default_signature_algs() -> Vec<String> {
    vec![
        #[cfg(feature = "openssl")]
        String::from("ecdsa_secp521r1_sha512"),
        String::from("ecdsa_secp384r1_sha384"),
    ]
}

impl ScopedError for TLSLoadConfigError {
    fn scope(&self) -> ErrorScope {
        match self {
            TLSLoadConfigError::PKITrustRoot { error } => error.scope(),
            TLSLoadConfigError::IO { error } => error.scope(),
            #[cfg(feature = "openssl")]
            TLSLoadConfigError::OpenSSL { .. } => ErrorScope::System
        }
    }
}

impl TLSServerClientAuthConfig {
    /// Create a `TLSServerClientAuthConfig` from its components.
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
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_channels::config::tls::TLSClientAuthMode;
    /// # use constellation_channels::config::tls::TLSServerClientAuthConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!(
    ///     "verify: optional\n",
    ///     "trust-root:\n",
    ///     "  root-certs:\n",
    ///     "    - /etc/ssl/certs/client-ca-cert.pem\n",
    ///     "  crls:\n",
    ///     "    - /etc/ssl/crls/client-ca-crl.pem\n"
    /// );
    ///
    /// assert_eq!(
    ///     TLSServerClientAuthConfig::new(
    ///         TLSClientAuthMode::Optional,
    ///         PKITrustRoot::new(
    ///             vec![],
    ///             vec![PathBuf::from("/etc/ssl/certs/client-ca-cert.pem")],
    ///             vec![PathBuf::from("/etc/ssl/crls/client-ca-crl.pem")],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             None,
    ///             #[cfg(feature = "openssl")]
    ///             None
    ///         ),
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// )
    /// ```
    #[inline]
    pub fn new(
        verify: TLSClientAuthMode,
        trust_root: PKITrustRoot
    ) -> Self {
        TLSServerClientAuthConfig {
            verify: verify,
            trust_root: trust_root
        }
    }

    /// Get the client certificate verification mode.
    #[inline]
    pub fn verify_mode(&self) -> TLSClientAuthMode {
        self.verify
    }

    /// Get the trust root configuration.
    #[inline]
    pub fn trust_root(&self) -> &PKITrustRoot {
        &self.trust_root
    }
}

impl TLSClientClientAuthConfig {
    /// Create a new `TLSClientClientAuthConfig` from its components.
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
    /// # use constellation_channels::config::tls::TLSClientClientAuthConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!(
    ///     "client-cert: /etc/ssl/certs/client-cert.pem\n",
    ///     "client-cert-chain: /etc/ssl/certs/client-cert-chain.pem\n",
    ///     "client-key: /etc/ssl/private/client-key.pem\n",
    /// );
    ///
    /// assert_eq!(
    ///     TLSClientClientAuthConfig::new(
    ///         PathBuf::from("/etc/ssl/certs/client-cert.pem"),
    ///         Some(PathBuf::from("/etc/ssl/certs/client-cert-chain.pem")),
    ///         PathBuf::from("/etc/ssl/private/client-key.pem")
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// )
    /// ```
    #[inline]
    pub fn new(
        client_cert: PathBuf,
        client_cert_chain: Option<PathBuf>,
        client_key: PathBuf
    ) -> Self {
        TLSClientClientAuthConfig {
            client_cert: client_cert,
            client_key: client_key,
            client_cert_chain: client_cert_chain
        }
    }

    /// Get the path to the client certficate file.
    #[inline]
    pub fn client_cert(&self) -> &Path {
        &self.client_cert
    }

    /// Get the path to the client certficate chain file.
    #[inline]
    pub fn client_cert_chain(&self) -> Option<&Path> {
        self.client_cert_chain.as_ref().map(|x| x.as_ref())
    }

    /// Get the path to the client key file.
    #[inline]
    pub fn client_key(&self) -> &Path {
        &self.client_key
    }
}

impl TLSPeerConfig {
    /// Create a new `TLSPeerConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format (except that `client_auth` is not
    /// flattened).  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_channels::config::tls::TLSPeerConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!(
    ///     "cipher-suites:\n",
    ///     "  - TLS_AES_256_GCM_SHA384\n",
    ///     "  - TLS_CHACHA20_POLY1305_SHA256\n",
    ///     "key-exchange-groups:\n",
    ///     "  - X25519\n",
    ///     "  - P-256\n",
    ///     "signature-algorithms:\n",
    ///     "  - ecdsa_secp521r1_sha512\n",
    ///     "  - ecdsa_secp384r1_sha384\n",
    ///     "trust-root:\n",
    ///     "  dirs:\n",
    ///     "    - /etc/ssl/certs/CAs\n",
    ///     "  crls: []\n",
    ///     "cert: /etc/ssl/certs/server-cert.pem\n",
    ///     "key: /etc/ssl/private/server-key.pem\n"
    /// );
    ///
    /// assert_eq!(
    ///     TLSPeerConfig::new(
    ///         vec![String::from("TLS_AES_256_GCM_SHA384"),
    ///              String::from("TLS_CHACHA20_POLY1305_SHA256")],
    ///         vec![String::from("X25519"),
    ///              String::from("P-256")],
    ///         vec![String::from("ecdsa_secp521r1_sha512"),
    ///              String::from("ecdsa_secp384r1_sha384")],
    ///         PKITrustRoot::new(
    ///             vec![PathBuf::from("/etc/ssl/certs/CAs")],
    ///             vec![], vec![],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             None,
    ///             #[cfg(feature = "openssl")]
    ///             None
    ///         ),
    ///         None,
    ///         PathBuf::from("/etc/ssl/certs/server-cert.pem"),
    ///         PathBuf::from("/etc/ssl/private/server-key.pem")
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// )
    /// ```
    #[inline]
    pub fn new(
        cipher_suites: Vec<String>,
        key_exchange_groups: Vec<String>,
        signature_algorithms: Vec<String>,
        trust_root: PKITrustRoot,
        cert_chain: Option<PathBuf>,
        cert: PathBuf,
        key: PathBuf
    ) -> Self {
        TLSPeerConfig {
            cipher_suites: cipher_suites,
            trust_root: trust_root,
            key_exchange_groups: key_exchange_groups,
            signature_algorithms: signature_algorithms,
            cert_chain: cert_chain,
            cert: cert,
            key: key
        }
    }

    /// Get the names of the allowed cipher suites.
    #[inline]
    pub fn cipher_suites(&self) -> &[String] {
        &self.cipher_suites
    }

    /// Get the names of the allowed key-exchange groups.
    #[inline]
    pub fn key_exchange_groups(&self) -> &[String] {
        &self.key_exchange_groups
    }

    /// Get the names of the allowed signature algorithms.
    #[inline]
    pub fn signature_algorithms(&self) -> &[String] {
        &self.signature_algorithms
    }

    /// Get the trust root used to verify server certificates.
    #[inline]
    pub fn trust_root(&self) -> &PKITrustRoot {
        &self.trust_root
    }

    /// Get the path to the file containing the PEM-encoded
    /// certificate chain for the server certificate.
    #[inline]
    pub fn cert_chain(&self) -> Option<&Path> {
        self.cert_chain.as_ref().map(|x| x.as_ref())
    }

    /// Get the path to the file containing the PEM-encoded server
    /// certificate.
    #[inline]
    pub fn cert(&self) -> &Path {
        &self.cert
    }

    /// Get the path to the file containing the PEM-encoded server
    /// private key.
    #[inline]
    pub fn key(&self) -> &Path {
        &self.key
    }
}

impl TLSLoadClient for TLSPeerConfig {
    #[cfg(feature = "openssl")]
    fn load_client(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: &IPEndpointAddr,
        dtls: bool
    ) -> Result<SslConnector, TLSLoadConfigError> {
        debug!(target: "tls-peer-config",
               "initializing {} peer from configuration",
               if dtls { "DTLS" } else { "TLS" });

        let method = if dtls {
            SslMethod::dtls()
        } else {
            SslMethod::tls_client()
        };
        let mut builder = SslConnector::builder(method)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Basic protocol options.
        trace!(target: "tls-peer-config",
               "setting protocol version to {} 1.3",
               if dtls { "DTLS" } else { "TLS" });

        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Set up verification, using the provided trust root.
        let mut verify = SslVerifyMode::empty();

        verify.insert(SslVerifyMode::PEER);
        verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        trace!(target: "tls-peer-config",
               "loading trust root");

        let store = self
            .trust_root
            .load_client(verify_time, endpoint)
            .map_err(|err| TLSLoadConfigError::PKITrustRoot { error: err })?;

        trace!(target: "tls-peer-config",
               "setting verify flags");

        builder.set_verify(verify);
        builder
            .set_verify_cert_store(store)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Certificate and key.
        trace!(target: "tls-server-config",
               "setting certificate to {}",
               self.cert.to_string_lossy());

        builder
            .set_certificate_file(&self.cert, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        if let Some(chain) = &self.cert_chain {
            trace!(target: "tls-server-config",
                   "setting certificate chain to {}",
                   chain.to_string_lossy());

            builder
                .set_certificate_chain_file(chain)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?
        }

        trace!(target: "tls-server-config",
               "setting key to {}",
               self.key.to_string_lossy());

        builder
            .set_private_key_file(&self.key, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Cryptographic options.
        if !self.cipher_suites.is_empty() {
            let ciphers = self.cipher_suites.join(":");

            trace!(target: "tls-peer-config",
                   "setting cipher suites to {}",
                   ciphers);

            builder
                .set_ciphersuites(&ciphers)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.key_exchange_groups.is_empty() {
            let groups = self.key_exchange_groups.join(":");

            trace!(target: "tls-peer-config",
                   "setting key exchange groups to {}",
                   groups);

            builder
                .set_groups_list(&groups)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.signature_algorithms.is_empty() {
            let signatures = self.signature_algorithms.join(":");

            trace!(target: "tls-peer-config",
                   "setting signature algorithms to {}",
                   signatures);

            builder
                .set_sigalgs_list(&signatures)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        Ok(builder.build())
    }
}

impl TLSLoadServer for TLSPeerConfig {
    #[cfg(feature = "openssl")]
    fn load_server(
        &self,
        verify_time: Option<SystemTime>,
        dtls: bool
    ) -> Result<SslAcceptor, TLSLoadConfigError> {
        debug!(target: "tls-server-config",
               "initializing {} server from configuration",
               if dtls { "DTLS" } else { "TLS" });

        let method = if dtls {
            SslMethod::dtls()
        } else {
            SslMethod::tls_server()
        };
        let mut builder = SslAcceptor::mozilla_modern_v5(method)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Basic protocol options.
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Client authentication: mandatory, and using the provided
        // trust root.
        let mut verify = SslVerifyMode::empty();

        verify.insert(SslVerifyMode::PEER);
        verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        trace!(target: "tls-peer-config",
               "loading trust root");

        let store = self
            .trust_root
            .load_server(verify_time)
            .map_err(|err| TLSLoadConfigError::PKITrustRoot { error: err })?;

        builder.set_verify(verify);
        builder
            .set_verify_cert_store(store)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Certificate and key.
        trace!(target: "tls-server-config",
               "setting certificate to {}",
               self.cert.to_string_lossy());

        builder
            .set_certificate_file(&self.cert, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        if let Some(chain) = &self.cert_chain {
            trace!(target: "tls-server-config",
                   "setting certificate chain to {}",
                   chain.to_string_lossy());

            builder
                .set_certificate_chain_file(chain)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?
        }

        trace!(target: "tls-server-config",
               "setting key to {}",
               self.key.to_string_lossy());

        builder
            .set_private_key_file(&self.key, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Cryptographic options.
        if !self.cipher_suites.is_empty() {
            let ciphers = self.cipher_suites.join(":");

            trace!(target: "tls-server-config",
                   "setting cipher suites to {}",
                   ciphers);

            builder
                .set_ciphersuites(&ciphers)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.key_exchange_groups.is_empty() {
            let groups = self.key_exchange_groups.join(":");

            trace!(target: "tls-server-config",
                   "setting key exchange groups to {}",
                   groups);

            builder
                .set_groups_list(&groups)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.signature_algorithms.is_empty() {
            let signatures = self.signature_algorithms.join(":");

            trace!(target: "tls-server-config",
                   "setting signature algorithms to {}",
                   signatures);

            builder
                .set_sigalgs_list(&signatures)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        Ok(builder.build())
    }
}

impl TLSClientConfig {
    /// Create a new `TLSClientConfig` from its components.
    ///
    /// The arguments of this function correspond to similarly-named
    /// fields in the YAML format (except that `client_auth` is not
    /// flattened).  See documentation for details.
    ///
    /// # Examples
    ///
    /// The following example shows the equivalence between this
    /// function and parsing a YAML configuration:
    ///
    /// ```
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_channels::config::tls::TLSClientConfig;
    /// # use constellation_channels::config::tls::TLSClientClientAuthConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let yaml = concat!(
    ///     "cipher-suites:\n",
    ///     "  - TLS_AES_256_GCM_SHA384\n",
    ///     "  - TLS_CHACHA20_POLY1305_SHA256\n",
    ///     "key-exchange-groups:\n",
    ///     "  - X25519\n",
    ///     "  - P-256\n",
    ///     "signature-algorithms:\n",
    ///     "  - ecdsa_secp521r1_sha512\n",
    ///     "  - ecdsa_secp384r1_sha384\n",
    ///     "client-cert: /etc/ssl/certs/client-cert.pem\n",
    ///     "client-key: /etc/ssl/private/client-key.pem\n",
    ///     "trust-root:\n",
    ///     "  dirs:\n",
    ///     "    - /etc/ssl/certs/CAs\n",
    ///     "  crls: []\n",
    ///     "verify-endpoint: test.example.com"
    /// );
    ///
    /// assert_eq!(
    ///     TLSClientConfig::new(
    ///         vec![String::from("TLS_AES_256_GCM_SHA384"),
    ///              String::from("TLS_CHACHA20_POLY1305_SHA256")],
    ///         vec![String::from("X25519"),
    ///              String::from("P-256")],
    ///         vec![String::from("ecdsa_secp521r1_sha512"),
    ///              String::from("ecdsa_secp384r1_sha384")],
    ///         Some(
    ///             TLSClientClientAuthConfig::new(
    ///                 PathBuf::from("/etc/ssl/certs/client-cert.pem"), None,
    ///                 PathBuf::from("/etc/ssl/private/client-key.pem")
    ///             )
    ///         ),
    ///         PKITrustRoot::new(
    ///             vec![PathBuf::from("/etc/ssl/certs/CAs")],
    ///             vec![], vec![],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             vec![],
    ///             #[cfg(feature = "openssl")]
    ///             None,
    ///             #[cfg(feature = "openssl")]
    ///             None
    ///         ),
    ///         Some(IPEndpointAddr::name(String::from("test.example.com"))),
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// )
    /// ```
    #[inline]
    pub fn new(
        cipher_suites: Vec<String>,
        key_exchange_groups: Vec<String>,
        signature_algorithms: Vec<String>,
        client_auth: Option<TLSClientClientAuthConfig>,
        trust_root: PKITrustRoot,
        verify_endpoint: Option<IPEndpointAddr>
    ) -> Self {
        TLSClientConfig {
            cipher_suites: cipher_suites,
            trust_root: trust_root,
            key_exchange_groups: key_exchange_groups,
            signature_algorithms: signature_algorithms,
            client_auth: client_auth,
            verify_endpoint: verify_endpoint
        }
    }

    /// Get the names of the allowed cipher suites.
    #[inline]
    pub fn cipher_suites(&self) -> &[String] {
        &self.cipher_suites
    }

    /// Get the names of the allowed key-exchange groups.
    #[inline]
    pub fn key_exchange_groups(&self) -> &[String] {
        &self.key_exchange_groups
    }

    /// Get the names of the allowed signature algorithms.
    #[inline]
    pub fn signature_algorithms(&self) -> &[String] {
        &self.signature_algorithms
    }

    /// Get the client authentication information.
    #[inline]
    pub fn client_auth(&self) -> Option<&TLSClientClientAuthConfig> {
        self.client_auth.as_ref()
    }

    /// Get the trust root used to verify server certificates.
    #[inline]
    pub fn trust_root(&self) -> &PKITrustRoot {
        &self.trust_root
    }
}

impl TLSLoadClient for TLSClientConfig {
    #[cfg(feature = "openssl")]
    fn load_client(
        &self,
        verify_time: Option<SystemTime>,
        endpoint: &IPEndpointAddr,
        dtls: bool
    ) -> Result<SslConnector, TLSLoadConfigError> {
        debug!(target: "tls-client-config",
               "initializing {} client from configuration",
               if dtls { "DTLS" } else { "TLS" });

        let method = if dtls {
            SslMethod::dtls()
        } else {
            SslMethod::tls_client()
        };
        let mut builder = SslConnector::builder(method)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Basic protocol options.
        trace!(target: "tls-peer-config",
               "setting protocol version to {} 1.3",
               if dtls { "DTLS" } else { "TLS" });

        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Set up verification: manditory, and using the provided
        // trust root.
        let mut verify = SslVerifyMode::empty();

        verify.insert(SslVerifyMode::PEER);
        verify.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        trace!(target: "tls-peer-config",
               "loading trust root");

        let store = self
            .trust_root
            .load_client(verify_time, endpoint)
            .map_err(|err| TLSLoadConfigError::PKITrustRoot { error: err })?;

        builder.set_verify(verify);
        builder
            .set_verify_cert_store(store)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Client certificates.
        if let Some(TLSClientClientAuthConfig {
            client_cert,
            client_cert_chain,
            client_key
        }) = &self.client_auth
        {
            trace!(target: "tls-config",
                   "setting client certificate to {}",
                   client_cert.to_string_lossy());

            builder
                .set_certificate_file(client_cert, SslFiletype::PEM)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

            if let Some(chain) = client_cert_chain {
                trace!(target: "tls-client-config",
                       "setting client certificate chain to {}",
                       chain.to_string_lossy());

                builder
                    .set_certificate_chain_file(chain)
                    .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?
            }

            trace!(target: "tls-client-config",
                   "setting client key to {}",
                   client_key.to_string_lossy());

            builder
                .set_private_key_file(client_key, SslFiletype::PEM)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        // Cryptographic options.
        if !self.cipher_suites.is_empty() {
            let ciphers = self.cipher_suites.join(":");

            trace!(target: "tls-client-config",
                   "setting cipher suites to {}",
                   ciphers);

            builder
                .set_ciphersuites(&ciphers)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.key_exchange_groups.is_empty() {
            let groups = self.key_exchange_groups.join(":");

            trace!(target: "tls-client-config",
                   "setting key exchange groups to {}",
                   groups);

            builder
                .set_groups_list(&groups)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.signature_algorithms.is_empty() {
            let signatures = self.signature_algorithms.join(":");

            trace!(target: "tls-client-config",
                   "setting signature algorithms to {}",
                   signatures);

            builder
                .set_sigalgs_list(&signatures)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        Ok(builder.build())
    }

    #[inline]
    fn verify_endpoint(&self) -> Option<&IPEndpointAddr> {
        self.verify_endpoint.as_ref()
    }
}

impl TLSServerConfig {
    /// Create a new `TLSServerConfig` from its components.
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
    /// # use constellation_common::config::pki::PKITrustRoot;
    /// # use constellation_common::net::IPEndpointAddr;
    /// # use constellation_channels::config::tls::TLSClientAuthMode;
    /// # use constellation_channels::config::tls::TLSServerConfig;
    /// # use constellation_channels::config::tls::TLSServerClientAuthConfig;
    /// # use std::path::PathBuf;
    /// #
    /// let client_auth = TLSServerClientAuthConfig::new(
    ///     TLSClientAuthMode::Optional,
    ///     PKITrustRoot::new(
    ///         vec![],
    ///         vec![PathBuf::from("/etc/ssl/certs/client-ca-cert.pem")],
    ///         vec![PathBuf::from("/etc/ssl/crls/client-ca-crl.pem")],
    ///         #[cfg(feature = "openssl")]
    ///         vec![],
    ///         #[cfg(feature = "openssl")]
    ///         vec![],
    ///         #[cfg(feature = "openssl")]
    ///         None,
    ///         #[cfg(feature = "openssl")]
    ///         None
    ///     )
    /// );
    ///
    /// let yaml = concat!(
    ///     "cipher-suites:\n",
    ///     "  - TLS_CHACHA20_POLY1305_SHA256\n",
    ///     "  - TLS_AES_128_GCM_SHA256\n",
    ///     "key-exchange-groups:\n",
    ///     "  - X25519\n",
    ///     "  - P-256\n",
    ///     "signature-algorithms:\n",
    ///     "  - ecdsa_secp521r1_sha512\n",
    ///     "  - ecdsa_secp384r1_sha384\n",
    ///     "client-auth:\n",
    ///     "  verify: optional\n",
    ///     "  trust-root:\n",
    ///     "    root-certs:\n",
    ///     "      - /etc/ssl/certs/client-ca-cert.pem\n",
    ///     "    crls:\n",
    ///     "      - /etc/ssl/crls/client-ca-crl.pem\n",
    ///     "cert: /etc/ssl/certs/server-cert.pem\n",
    ///     "key: /etc/ssl/private/server-key.pem\n"
    /// );
    ///
    /// assert_eq!(
    ///     TLSServerConfig::new(
    ///         vec![String::from("TLS_CHACHA20_POLY1305_SHA256"),
    ///              String::from("TLS_AES_128_GCM_SHA256")],
    ///         vec![String::from("X25519"),
    ///              String::from("P-256")],
    ///         vec![String::from("ecdsa_secp521r1_sha512"),
    ///              String::from("ecdsa_secp384r1_sha384")],
    ///         Some(client_auth),
    ///         None,
    ///         PathBuf::from("/etc/ssl/certs/server-cert.pem"),
    ///         PathBuf::from("/etc/ssl/private/server-key.pem")
    ///     ),
    ///     serde_yaml::from_str(yaml).unwrap()
    /// )
    /// ```
    #[inline]
    pub fn new(
        cipher_suites: Vec<String>,
        key_exchange_groups: Vec<String>,
        signature_algorithms: Vec<String>,
        client_auth: Option<TLSServerClientAuthConfig>,
        cert_chain: Option<PathBuf>,
        cert: PathBuf,
        key: PathBuf
    ) -> Self {
        TLSServerConfig {
            cipher_suites: cipher_suites,
            key_exchange_groups: key_exchange_groups,
            signature_algorithms: signature_algorithms,
            client_auth: client_auth,
            cert: cert,
            cert_chain: cert_chain,
            key: key
        }
    }

    /// Get the names of the allowed cipher suites.
    #[inline]
    pub fn cipher_suites(&self) -> &[String] {
        &self.cipher_suites
    }

    /// Get the names of the allowed key-exchange groups.
    #[inline]
    pub fn key_exchange_groups(&self) -> &[String] {
        &self.key_exchange_groups
    }

    /// Get the names of the allowed signature algorithms.
    #[inline]
    pub fn signature_algorithms(&self) -> &[String] {
        &self.signature_algorithms
    }

    /// Get the client authentication information.
    #[inline]
    pub fn client_auth(&self) -> Option<&TLSServerClientAuthConfig> {
        self.client_auth.as_ref()
    }

    /// Get the path to the file containing the PEM-encoded
    /// certificate chain for the server certificate.
    #[inline]
    pub fn cert_chain(&self) -> Option<&Path> {
        self.cert_chain.as_ref().map(|x| x.as_ref())
    }

    /// Get the path to the file containing the PEM-encoded server
    /// certificate.
    #[inline]
    pub fn cert(&self) -> &Path {
        &self.cert
    }

    /// Get the path to the file containing the PEM-encoded server
    /// private key.
    #[inline]
    pub fn key(&self) -> &Path {
        &self.key
    }
}

impl TLSLoadServer for TLSServerConfig {
    #[cfg(feature = "openssl")]
    fn load_server(
        &self,
        verify_time: Option<SystemTime>,
        dtls: bool
    ) -> Result<SslAcceptor, TLSLoadConfigError> {
        debug!(target: "tls-server-config",
               "initializing {} server from configuration",
               if dtls { "DTLS" } else { "TLS" });

        let method = if dtls {
            SslMethod::dtls()
        } else {
            SslMethod::tls_server()
        };
        let mut builder = SslAcceptor::mozilla_modern_v5(method)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        trace!(target: "tls-peer-config",
               "setting protocol version to {} 1.3",
               if dtls { "DTLS" } else { "TLS" });

        // Basic protocol options.
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Client authentication.
        match &self.client_auth {
            Some(TLSServerClientAuthConfig { trust_root, verify }) => {
                trace!(target: "tls-server-config",
                       "initializing client verification");

                let verify = match verify {
                    TLSClientAuthMode::Required => {
                        debug!(target: "tls-server-config",
                               "setting client verification to mandatory");

                        let mut mode = SslVerifyMode::empty();

                        mode.insert(SslVerifyMode::PEER);
                        mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);

                        mode
                    }
                    TLSClientAuthMode::Optional => {
                        debug!(target: "tls-server-config",
                               "setting client verification to optional");

                        SslVerifyMode::PEER
                    }
                };
                let store =
                    trust_root.load_server(verify_time).map_err(|err| {
                        TLSLoadConfigError::PKITrustRoot { error: err }
                    })?;

                builder.set_verify(verify);
                builder.set_verify_cert_store(store).map_err(|err| {
                    TLSLoadConfigError::OpenSSL { error: err }
                })?;
            }
            None => {
                trace!(target: "tls-server-config",
                       "no client verification");

                builder.set_verify(SslVerifyMode::empty());
            }
        }

        // Certificate and key.
        trace!(target: "tls-server-config",
               "setting certificate to {}",
               self.cert.to_string_lossy());

        builder
            .set_certificate_file(&self.cert, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        if let Some(chain) = &self.cert_chain {
            trace!(target: "tls-server-config",
                   "setting certificate chain to {}",
                   chain.to_string_lossy());

            builder
                .set_certificate_chain_file(chain)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?
        }

        trace!(target: "tls-server-config",
               "setting key to {}",
               self.key.to_string_lossy());

        builder
            .set_private_key_file(&self.key, SslFiletype::PEM)
            .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;

        // Cryptographic options.
        if !self.cipher_suites.is_empty() {
            let ciphers = self.cipher_suites.join(":");

            trace!(target: "tls-server-config",
                   "setting cipher suites to {}",
                   ciphers);

            builder
                .set_ciphersuites(&ciphers)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.key_exchange_groups.is_empty() {
            let groups = self.key_exchange_groups.join(":");

            trace!(target: "tls-server-config",
                   "setting key exchange groups to {}",
                   groups);

            builder
                .set_groups_list(&groups)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        if !self.signature_algorithms.is_empty() {
            let signatures = self.signature_algorithms.join(":");

            trace!(target: "tls-server-config",
                   "setting signature algorithms to {}",
                   signatures);

            builder
                .set_sigalgs_list(&signatures)
                .map_err(|err| TLSLoadConfigError::OpenSSL { error: err })?;
        }

        Ok(builder.build())
    }
}

impl Display for TLSLoadConfigError {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSLoadConfigError::PKITrustRoot { error } => error.fmt(f),
            TLSLoadConfigError::IO { error } => error.fmt(f),
            #[cfg(feature = "openssl")]
            TLSLoadConfigError::OpenSSL { error } => error.fmt(f),
        }
    }
}

impl Serialize for TLSClientAuthMode {
    #[inline]
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        match self {
            TLSClientAuthMode::Required => serializer.serialize_str("required"),
            TLSClientAuthMode::Optional => serializer.serialize_str("optional")
        }
    }
}

impl TryFrom<String> for TLSClientAuthMode {
    type Error = &'static str;

    #[inline]
    fn try_from(val: String) -> Result<TLSClientAuthMode, &'static str> {
        match val.as_str() {
            "required" => Ok(TLSClientAuthMode::Required),
            "optional" => Ok(TLSClientAuthMode::Optional),
            _ => Err("expected \"required\", \"optional\"")
        }
    }
}

#[cfg(test)]
use crate::init;

#[test]
fn test_deserialize_server_tls_cfg_certs_dir() {
    init();

    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "  - TLS_AES_128_GCM_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "client-auth:\n",
        "  trust-root:\n",
        "    dirs:\n",
        "      - \"/usr/local/etc/test/certs\"\n",
        "    crls: []\n",
        "cert: \"/usr/local/etc/test/tls.cert\"\n",
        "key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSServerConfig {
        cipher_suites: vec![
            String::from("TLS_CHACHA20_POLY1305_SHA256"),
            String::from("TLS_AES_128_GCM_SHA256"),
        ],
        key_exchange_groups: vec![
            String::from("X25519"),
            String::from("P-256"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSServerClientAuthConfig {
            trust_root: PKITrustRoot::new(
                vec![PathBuf::from("/usr/local/etc/test/certs")],
                vec![],
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                None,
                #[cfg(feature = "openssl")]
                None
            ),
            verify: TLSClientAuthMode::Required
        }),
        cert_chain: None,
        cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
        key: PathBuf::from("/usr/local/etc/test/tls.key")
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_server_tls_cfg_certs_dir_no_ciphers() {
    let yaml = concat!(
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "client-auth:\n",
        "  verify: required\n",
        "  trust-root:\n",
        "    dirs:\n",
        "      - \"/usr/local/etc/test/certs\"\n",
        "    crls: []\n",
        "cert: \"/usr/local/etc/test/tls.cert\"\n",
        "key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSServerConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            String::from("X25519"),
            String::from("P-256"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSServerClientAuthConfig {
            trust_root: PKITrustRoot::new(
                vec![PathBuf::from("/usr/local/etc/test/certs")],
                vec![],
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                None,
                #[cfg(feature = "openssl")]
                None
            ),
            verify: TLSClientAuthMode::Required
        }),
        cert_chain: None,
        cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
        key: PathBuf::from("/usr/local/etc/test/tls.key")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_server_tls_cfg_certs_dir_no_kex() {
    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "client-auth:\n",
        "  verify: optional\n",
        "  trust-root:\n",
        "    dirs:\n",
        "      - \"/usr/local/etc/test/certs\"\n",
        "    crls: []\n",
        "cert: \"/usr/local/etc/test/tls.cert\"\n",
        "key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSServerConfig {
        cipher_suites: vec![
            String::from("TLS_AES_256_GCM_SHA384"),
            String::from("TLS_CHACHA20_POLY1305_SHA256"),
        ],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSServerClientAuthConfig {
            trust_root: PKITrustRoot::new(
                vec![PathBuf::from("/usr/local/etc/test/certs")],
                vec![],
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                None,
                #[cfg(feature = "openssl")]
                None
            ),
            verify: TLSClientAuthMode::Optional
        }),
        cert_chain: None,
        cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
        key: PathBuf::from("/usr/local/etc/test/tls.key")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_server_tls_cfg_certs_dir_no_ciphers_no_kex() {
    let yaml = concat!(
        "client-auth:\n",
        "  trust-root:\n",
        "    dirs:\n",
        "      - \"/usr/local/etc/test/certs\"\n",
        "    crls: []\n",
        "cert: \"/usr/local/etc/test/tls.cert\"\n",
        "key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSServerConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSServerClientAuthConfig {
            trust_root: PKITrustRoot::new(
                vec![PathBuf::from("/usr/local/etc/test/certs")],
                vec![],
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                vec![],
                #[cfg(feature = "openssl")]
                None,
                #[cfg(feature = "openssl")]
                None
            ),
            verify: TLSClientAuthMode::Required
        }),
        cert_chain: None,
        cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
        key: PathBuf::from("/usr/local/etc/test/tls.key")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tls_server_cfg_no_ciphers_no_kex_no_client_auth() {
    let yaml = concat!(
        "cert: \"/usr/local/etc/test/tls.cert\"\n",
        "key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSServerConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: None,
        cert_chain: None,
        cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
        key: PathBuf::from("/usr/local/etc/test/tls.key")
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_client_tls_cfg_certs_dir() {
    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "trust-root:\n",
        "  dirs:\n",
        "    - \"/usr/local/etc/test/certs\"\n",
        "  crls: []\n",
        "client-cert: \"/usr/local/etc/test/tls.cert\"\n",
        "client-key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSClientConfig {
        cipher_suites: vec![
            String::from("TLS_AES_256_GCM_SHA384"),
            String::from("TLS_CHACHA20_POLY1305_SHA256"),
        ],
        key_exchange_groups: vec![
            String::from("X25519"),
            String::from("P-256"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSClientClientAuthConfig {
            client_cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
            client_cert_chain: None,
            client_key: PathBuf::from("/usr/local/etc/test/tls.key")
        }),
        trust_root: PKITrustRoot::new(
            vec![PathBuf::from("/usr/local/etc/test/certs")],
            vec![],
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            None,
            #[cfg(feature = "openssl")]
            None
        ),
        verify_endpoint: None
    };

    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_client_tls_cfg_certs_dir_no_ciphers() {
    let yaml = concat!(
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "trust-root:\n",
        "  dirs:\n",
        "    - \"/usr/local/etc/test/certs\"\n",
        "  crls: []\n",
        "client-cert: \"/usr/local/etc/test/tls.cert\"\n",
        "client-key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSClientConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            String::from("X25519"),
            String::from("P-256"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSClientClientAuthConfig {
            client_cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
            client_cert_chain: None,
            client_key: PathBuf::from("/usr/local/etc/test/tls.key")
        }),
        trust_root: PKITrustRoot::new(
            vec![PathBuf::from("/usr/local/etc/test/certs")],
            vec![],
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            None,
            #[cfg(feature = "openssl")]
            None
        ),
        verify_endpoint: None
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_client_tls_cfg_certs_dir_no_kex() {
    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "client-auth: optional\n",
        "trust-root:\n",
        "  dirs:\n",
        "    - \"/usr/local/etc/test/certs\"\n",
        "  crls: []\n",
        "client-cert: \"/usr/local/etc/test/tls.cert\"\n",
        "client-key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSClientConfig {
        cipher_suites: vec![
            String::from("TLS_AES_256_GCM_SHA384"),
            String::from("TLS_CHACHA20_POLY1305_SHA256"),
        ],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSClientClientAuthConfig {
            client_cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
            client_cert_chain: None,
            client_key: PathBuf::from("/usr/local/etc/test/tls.key")
        }),
        trust_root: PKITrustRoot::new(
            vec![PathBuf::from("/usr/local/etc/test/certs")],
            vec![],
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            None,
            #[cfg(feature = "openssl")]
            None
        ),
        verify_endpoint: None
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_client_tls_cfg_certs_dir_no_ciphers_no_kex() {
    let yaml = concat!(
        "trust-root:\n",
        "  dirs:\n",
        "    - \"/usr/local/etc/test/certs\"\n",
        "  crls: []\n",
        "client-cert: \"/usr/local/etc/test/tls.cert\"\n",
        "client-key: \"/usr/local/etc/test/tls.key\"\n"
    );
    let expected = TLSClientConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: Some(TLSClientClientAuthConfig {
            client_cert: PathBuf::from("/usr/local/etc/test/tls.cert"),
            client_cert_chain: None,
            client_key: PathBuf::from("/usr/local/etc/test/tls.key")
        }),
        trust_root: PKITrustRoot::new(
            vec![PathBuf::from("/usr/local/etc/test/certs")],
            vec![],
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            None,
            #[cfg(feature = "openssl")]
            None
        ),
        verify_endpoint: None
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[test]
fn test_deserialize_tls_client_cfg_no_ciphers_no_kex_no_client_auth() {
    let yaml = concat!(
        "trust-root:\n",
        "  dirs:\n",
        "    - \"/usr/local/etc/test/certs\"\n",
        "  crls: []\n"
    );
    let expected = TLSClientConfig {
        cipher_suites: vec![String::from("TLS_AES_256_GCM_SHA384")],
        key_exchange_groups: vec![
            #[cfg(feature = "openssl")]
            String::from("P-521"),
            String::from("P-384"),
        ],
        signature_algorithms: vec![
            #[cfg(feature = "openssl")]
            String::from("ecdsa_secp521r1_sha512"),
            String::from("ecdsa_secp384r1_sha384"),
        ],
        client_auth: None,
        trust_root: PKITrustRoot::new(
            vec![PathBuf::from("/usr/local/etc/test/certs")],
            vec![],
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            vec![],
            #[cfg(feature = "openssl")]
            None,
            #[cfg(feature = "openssl")]
            None
        ),
        verify_endpoint: None
    };
    let actual = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(expected, actual)
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_server_cfg() {
    init();

    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "client-auth:\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - test/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "key: test/data/certs/server/private/test_server_key.pem\n"
    );
    let conf: TLSServerConfig = serde_yaml::from_str(yaml).unwrap();

    conf.load_server(None, false).expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_client_cfg() {
    init();

    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "trust-root:\n",
        "  root-certs:\n",
        "    - test/data/certs/server/ca_cert.pem\n",
        "  crls: []\n",
        "client-cert: test/data/certs/client/certs/test_client_cert.pem\n",
        "client-key: test/data/certs/client/private/test_client_key.pem\n"
    );
    let conf: TLSClientConfig = serde_yaml::from_str(yaml).unwrap();

    conf.load_client(None, &IPEndpointAddr::name(String::from("test")), false)
        .expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_peer_cfg_connector() {
    init();

    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "trust-root:\n",
        "  root-certs:\n",
        "    - test/data/certs/server/ca_cert.pem\n",
        "  crls: []\n",
        "cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "key: test/data/certs/server/private/test_server_key.pem\n"
    );
    let conf: TLSPeerConfig = serde_yaml::from_str(yaml).unwrap();

    conf.load_client(None, &IPEndpointAddr::name(String::from("test")), false)
        .expect("Expected success");
}

#[cfg(feature = "openssl")]
#[test]
fn test_load_peer_cfg_acceptor() {
    init();

    let yaml = concat!(
        "cipher-suites:\n",
        "  - TLS_AES_256_GCM_SHA384\n",
        "  - TLS_CHACHA20_POLY1305_SHA256\n",
        "key-exchange-groups:\n",
        "  - X25519\n",
        "  - P-256\n",
        "trust-root:\n",
        "  root-certs:\n",
        "    - test/data/certs/server/ca_cert.pem\n",
        "  crls: []\n",
        "cert: test/data/certs/server/certs/test_server_cert.pem\n",
        "key: test/data/certs/server/private/test_server_key.pem\n"
    );
    let conf: TLSPeerConfig = serde_yaml::from_str(yaml).unwrap();

    conf.load_server(None, false).expect("Expected success");
}
