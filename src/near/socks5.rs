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
//! This module provides a [NearChannel](crate::near::NearChannel) and
//! [NearConnector] implementation over SOCKS5 proxies.  Among other
//! things, this allows a near-link to be established through the Tor
//! network.
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
//! # Functionality
//!
//! This module only supports client-side SOCKS5 near-links, through
//! [SOCKS5NearConnector].  This is the only TCP mode supported by RFC
//! 1928.  While a "bind" command is provided for TCP, RFC 1928
//! indicates that this is intended to support protocols like FTP,
//! which establish a two-way connection, and *not* intended for
//! servers to effectively "listen" for connections that will be
//! forwarded by a proxy.  (This is distinct from the "UDP associate"
//! command, which necessarily operates that way.)
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
//! SOCKS5 near-links involve two *separate* logical connections: the
//! one to the proxy, and the one through the proxy to the target.
//! Both of these have separate security concerns.  Additionally, the
//! SOCKS5 proxy itself potentially represents an inherent middleman.
//!
//! Security-sensitive applications must take steps to protect both
//! the connection *to* the proxy, and the connection *through* the
//! proxy.
//!
//! Additionally, note that while GSSAPI does provide message
//! security, the level of security provided by the Kerberos instance
//! (the primary use of GSSAPI) is inadequate by modern standards.
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;
use std::io::Read;
use std::io::Write;

use constellation_common::error::ErrorScope;
use constellation_common::error::RecoverableError;
use constellation_common::error::ScopedError;
use constellation_common::net::IPEndpoint;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use constellation_common::retry::RetryResult;
use constellation_socks5::comm::SOCKS5Stream;
use constellation_socks5::error::SOCKS5Error;
use constellation_socks5::params::SOCKS5Params;
use constellation_socks5::state::SOCKS5State;
use constellation_streams::state_machine::RawStateMachine;
use constellation_streams::state_machine::RawStateMachineError;
use mio::event::Source;
use mio::Registry;
use mio::Token;

use crate::config::SOCKS5AuthNConfig;
use crate::config::SOCKS5ConnectConfig;
use crate::config::SOCKS5ConnectPartialConfig;
use crate::near::NearChannel;
use crate::near::NearChannelCreate;
use crate::near::NearChannelCreateWithEndpoint;
use crate::near::NearConnector;
use crate::resolve::cache::NSNameCachesCtx;

/// Client side of a near-link channel that communicates through a
/// SOCKS5 proxy.
///
/// This is a [NearChannel](crate::near::NearChannel) and
/// [NearConnector] instance that attempts to connect to a SOCKS5
/// proxy using a separate `NearConnector`-based channel, which then
/// establishes a proxied connection to a target endpoint.  The proxy
/// channel can be any `NearConnector` instance, which may talk over a
/// separate set of protocols than the main connection.
///
/// Connections to the endpoint through the proxy are not inherently
/// secure or authenticated, and by their very nature, involve a
/// middleman (the proxy).  Separately, connections *to* the proxy are
/// not inherently secure either.
///
/// # Usage
///
/// The primary use of a `SOCKS5NearConnector` takes place through its
/// [NearChannel](crate::near::NearChannel) and [NearConnector]
/// instances.
///
/// ## Configuration and Creation
///
/// A `SOCKS5NearConnector` is created using the
/// [new](crate::near::NearChannelCreate::new) function from its
/// [NearChannel](crate::near::NearChannel) instance.  This function
/// takes a [SOCKS5ConnectConfig] as its principal argument, which
/// supplies all configuration information.
///
/// ### Example
///
/// The following example shows how to create a `SOCKS5NearConnector`,
/// using a [TCPNearConnector](crate::near::tcp::TCPNearConnector) as
/// the underlying channel:
///
/// ```
/// # use constellation_channels::near::NearChannelCreate;
/// # use constellation_channels::near::tcp::TCPResolvingNearConnector;
/// # use constellation_channels::near::socks5::SOCKS5NearConnector;
/// # use constellation_channels::resolve::cache::SharedNSNameCaches;
/// #
/// const CONFIG: &'static str = concat!(
///     "target:\n",
///     "  addr: en.wikipedia.org\n",
///     "  port: 443\n",
///     "proxy:\n",
///     "  addr: test.example.com\n",
///     "  port: 9050\n",
///     "auth:\n",
///     "  username: test\n",
///     "  password: abc123\n"
/// );
/// let accept_config = serde_yaml::from_str(CONFIG).unwrap();
/// let mut nscaches = SharedNSNameCaches::new();
///
/// let connector: SOCKS5NearConnector<TCPResolvingNearConnector> =
///     SOCKS5NearConnector::create(&mut nscaches, accept_config).unwrap();
/// ```
///
/// ## Establishing Connections
///
/// Once a `SOCKS5NearConnector` has been created, connections can be
/// established using the
/// [take_connection](crate::near::NearChannel::take_connection) or
/// [connection](NearConnector::connection) functions.  These will
/// block until a connection has been successfully established.  Note
/// that depending on the circumstances, this may involve many retries
/// and/or name resolutions.
///
/// The SOCKS5 proxy establishment will occur transparently, and the
/// `SOCKS5NearConnector` will also automatically retry if it fails.  Errors
/// occurring during connection will be logged, but will not cause
/// [take_connection](crate::near::NearChannel::take_connection) or
/// [connection](NearConnector::connection) to fail.
///
/// ## Complex Configurations
///
/// A `SOCKS5NearConnector` provides a [NearConnector] instance, which
/// resembles a [TCPNearConnector](crate::near::tcp::TCPNearConnector).
/// Additionally, it makes use of a separate `NearConnector` to
/// establish the connection to the proxy itself, which need not be a
/// `TCPNearConnector`.  Depending on the needs of the application, it is
/// possible to engineer any of the following:
///
/// - Local SOCKS5 proxy: connecting to a local SOCKS5 proxy via a
///   [UnixNearConnector](crate::near::unix::UnixNearConnector), which then
///   connects to a remote site.
///
/// - Secure SOCKS5 proxy connection: connecting to a remote SOCKS5 proxy via a
///   [TLSNearConnector](crate::near::tls::TLSNearConnector).  Note that traffic
///   is only protected in transit to the proxy using this method, but will be
///   unencrypted once the proxy forwards it. In order to achieve complete
///   security, it would be necessary to wrap this connector with a *second*
///   `TLSNearConnector`.
///
/// - Double-layer SOCKS5 proxy: connecting to a remote SOCKS5 proxy via a
///   connection made through a *different* SOCKS5 proxy.  This could be
///   extended to any number of layered proxy connections.
pub struct SOCKS5NearConnector<Conn: NearConnector> {
    /// SOCKS5 protocol parameters.
    params: SOCKS5Params,
    proxy: Conn
}

pub struct SOCKS5ShutdownNegotiator<Inner> {
    inner: Inner
}

pub struct SOCKS5SessionNegotiation<Proxy> {
    params: SOCKS5Params,
    proxy: Proxy
}

#[derive(Debug)]
pub enum SOCKS5NegotiateError<Inner, Proxy> {
    Inner {
        endpoint: IPEndpoint,
        err: Inner,
    },
    SOCKS5 {
        endpoint: IPEndpoint,
        proxy: Proxy,
        err: SOCKS5Error
    },
    BadSplit
}

pub enum SOCKS5NegotiatePending<Inner, Proxy> {
    Inner {
        endpoint: IPEndpoint,
        pending: Inner,
    },
    SOCKS5 {
        endpoint: IPEndpoint,
        proxy: Proxy,
        err: <RawStateMachineError<SOCKS5State> as RecoverableError>::Completable
    }
}

impl<Inner> Negotiator<(SOCKS5Stream<Inner::Conn>, IPEndpoint)>
    for SOCKS5NearConnector<Inner>
where
    Inner: NearConnector + NearChannelCreate
{
    type State = SOCKS5SessionNegotiation<Inner::State>;
    type NegotiateError = SOCKS5NegotiateError<
        Inner::NegotiateError,
        Inner::Conn
    >;
    type Pending = SOCKS5NegotiatePending<
        Inner::Pending,
        Inner::Conn,
     >;

    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<(SOCKS5Stream<Inner::Conn>, IPEndpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        let endpoint = state.params.target();

        self.proxy.negotiate(state.proxy)
            .map_err(|err| SOCKS5NegotiateError::Inner {
                endpoint: endpoint.clone(),
                err: err
            })?
            .map_pending(|pending| SOCKS5NegotiatePending::Inner {
                endpoint: endpoint.clone(),
                pending: pending
            })
            .flat_map_ok(|(mut stream, _)| {
                let machine: RawStateMachine<SOCKS5State> =
                    RawStateMachine::new(self.params.clone());

                match machine.run(&mut stream) {
                    Ok(socks5) => Ok(NegotiatorResult::Complete(
                        (socks5.wrap_stream(stream, endpoint.clone()),
                         endpoint.clone())
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) => Ok(NegotiatorResult::Pending(
                            SOCKS5NegotiatePending::SOCKS5 {
                                endpoint: endpoint.clone(),
                                proxy: stream,
                                err: pending
                            }
                        )),
                        (None, Some(err)) => Err(SOCKS5NegotiateError::SOCKS5 {
                            endpoint: endpoint.clone(),
                            proxy: stream,
                            err: err
                        }),
                        _ => Err(SOCKS5NegotiateError::BadSplit)
                    }
                }
            })
    }

    fn complete_negotiate(
        &self,
        err: SOCKS5NegotiatePending<
            Inner::Pending,
            Inner::Conn,
        >
    ) -> Result<NegotiatorResult<(SOCKS5Stream<Inner::Conn>, IPEndpoint),
                                 Self::Pending>,
                Self::NegotiateError> {
        match err {
            SOCKS5NegotiatePending::Inner { pending, endpoint } => self.proxy
                .complete_negotiate(pending)
                .map_err(|err| SOCKS5NegotiateError::Inner {
                    endpoint: endpoint.clone(),
                    err: err
                })?
                .map_pending(|pending| SOCKS5NegotiatePending::Inner {
                    endpoint: endpoint.clone(),
                    pending: pending
                })
                .flat_map_ok(|(mut stream, _)| {
                    let machine: RawStateMachine<SOCKS5State> =
                        RawStateMachine::new(self.params.clone());

                    match machine.run(&mut stream) {
                        Ok(socks5) => Ok(NegotiatorResult::Complete(
                            (socks5.wrap_stream(stream, endpoint.clone()),
                             endpoint)
                        )),
                        Err(err) => match err.split() {
                            (Some(pending), None) => Ok(
                                NegotiatorResult::Pending(
                                    SOCKS5NegotiatePending::SOCKS5 {
                                        endpoint: endpoint.clone(),
                                        proxy: stream,
                                        err: pending
                                    }
                                )
                            ),
                            (None, Some(err)) => Err(
                                SOCKS5NegotiateError::SOCKS5 {
                                    endpoint: endpoint.clone(),
                                    proxy: stream,
                                    err: err
                                }
                            ),
                            _ => Err(SOCKS5NegotiateError::BadSplit)
                        }
                    }
                }),
            SOCKS5NegotiatePending::SOCKS5 { endpoint, mut proxy, err } => {
                let machine: RawStateMachine<SOCKS5State> =
                    RawStateMachine::complete(err);

                match machine.run(&mut proxy) {
                    Ok(socks5) => Ok(NegotiatorResult::Complete(
                        (socks5.wrap_stream(proxy, endpoint.clone()),
                         endpoint)
                    )),
                    Err(err) => match err.split() {
                        (Some(pending), None) => Ok(NegotiatorResult::Pending(
                            SOCKS5NegotiatePending::SOCKS5 {
                                endpoint: endpoint.clone(),
                                proxy: proxy,
                                err: pending
                            }
                        )),
                        (None, Some(err)) => Err(SOCKS5NegotiateError::SOCKS5 {
                            endpoint: endpoint.clone(),
                            proxy: proxy,
                            err: err
                        }),
                        _ => Err(SOCKS5NegotiateError::BadSplit)
                    }
                }
            }
        }
    }
}

impl<Value, Inner> Negotiator<Value>
    for SOCKS5ShutdownNegotiator<Inner>
where
    Inner: Negotiator<Value>
{
    type State = Inner::State;
    type Pending = Inner::Pending;
    type NegotiateError = Inner::NegotiateError;

    #[inline]
    fn negotiate(
        &self,
        state: Self::State
    ) -> Result<NegotiatorResult<Value, Self::Pending>, Self::NegotiateError> {
        self.inner.negotiate(state)
    }

    #[inline]
    fn complete_negotiate(
        &self,
        pending: Self::Pending
    ) -> Result<NegotiatorResult<Value, Self::Pending>, Self::NegotiateError> {
        self.inner.complete_negotiate(pending)
    }
}

impl<Inner, Stream, Value> NegotiatorStart<Value, SOCKS5Stream<Stream>>
    for SOCKS5ShutdownNegotiator<Inner>
where
    Inner: NegotiatorStart<Value, Stream>,
    Stream: Session + Source + Read + Write {
    type Param = Inner::Param;
    type StartError = Inner::StartError;

    #[inline]
    fn start(
        &self,
        param: &Self::Param,
        stream: SOCKS5Stream<Stream>
    ) -> Result<Self::State, Self::StartError> {
        self.inner.start(param, stream.take())
    }
}

impl<Conn> NearChannel for SOCKS5NearConnector<Conn>
where
    Conn: NearConnector + NearChannelCreate
{
    type Endpoint = IPEndpoint;
    type StartError = Conn::StartError;
    type ShutdownNego = SOCKS5ShutdownNegotiator<Conn::ShutdownNego>;
    type ShutdownValue = Conn::ShutdownValue;
    type Conn = SOCKS5Stream<Conn::Conn>;

    #[inline]
    fn start(
        &mut self,
        registry: &Registry,
        token: Token
    ) -> Result<RetryResult<Self::State>, Self::StartError> {
        Ok(self.proxy.start(registry, token)?.map(|proxy| {
            SOCKS5SessionNegotiation {
                params: self.params.clone(),
                proxy: proxy
            }
        }))
    }

    #[inline]
    fn shutdown_nego(
        &self
    ) -> Self::ShutdownNego {
        let inner = self.proxy.shutdown_nego();

        SOCKS5ShutdownNegotiator {
            inner: inner
        }
    }

    #[inline]
    fn shutdown_param(
        &self
    ) -> <Conn::ShutdownNego as NegotiatorStart<Conn::ShutdownValue, Conn::Conn>>::Param {
        self.proxy.shutdown_param()
    }

    fn cleanup(
        &mut self,
        registry: &Registry,
        err: SOCKS5NegotiateError<
            Conn::NegotiateError,
            Conn::Conn,
        >
    ) -> Result<(), Error> {
        match err {
            SOCKS5NegotiateError::Inner { err, .. } =>
                self.proxy.cleanup(registry, err),
            SOCKS5NegotiateError::SOCKS5 { mut proxy, .. } =>
                registry.deregister(&mut proxy),
            SOCKS5NegotiateError::BadSplit => Ok(())
        }
    }
}

impl<Conn> NearConnector for SOCKS5NearConnector<Conn>
where
    Conn: NearConnector + NearChannelCreate
{
    /// Type of endpoint references.
    type EndpointRef<'a> = &'a IPEndpoint
    where
        Self: 'a;

    #[inline]
    fn endpoint(&self) -> Self::EndpointRef<'_> {
        self.params.target()
    }

    #[inline]
    fn shutdown(&mut self) -> Result<(), Error> {
        self.proxy.shutdown()
    }
}

impl<Conn> NearChannelCreate for SOCKS5NearConnector<Conn>
where
    Conn: NearConnector + NearChannelCreate
{
    type Config = SOCKS5ConnectConfig<Conn::Config>;
    type CreateError = Conn::CreateError;

    #[inline]
    fn create<Ctx>(
        caches: &mut Ctx,
        config: Self::Config
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (auth, target, proxy) = config.take();
        let params = match auth {
            SOCKS5AuthNConfig::None => SOCKS5Params::connect_no_auth(target),
            SOCKS5AuthNConfig::Password { username, password } => {
                SOCKS5Params::connect_password_auth(target, username, password)
            }
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNConfig::GSSAPI { gssapi } => {
                SOCKS5Params::connect_gssapi_auth(target, gssapi, None)
            }
        };
        let proxy = Conn::create(caches, proxy)?;

        Ok(SOCKS5NearConnector {
            params: params,
            proxy: proxy
        })
    }

    #[inline]
    fn verify_endpoint(config: &Self::Config) -> Option<&IPEndpointAddr> {
        Some(config.target().ip_addr())
    }
}

impl<Conn> NearChannelCreateWithEndpoint for SOCKS5NearConnector<Conn>
where
    Conn: NearConnector + NearChannelCreate
{
    type Config = SOCKS5ConnectPartialConfig<Conn::Config>;
    type EndpointConfig = IPEndpoint;
    type CreateError = Conn::CreateError;

    #[inline]
    fn create_with_endpoint<Ctx>(
        caches: &mut Ctx,
        config: Self::Config,
        target: IPEndpoint,
        _verify_endpoint: Option<&IPEndpointAddr>
    ) -> Result<Self, Self::CreateError>
    where
        Ctx: NSNameCachesCtx {
        let (auth, proxy) = config.take();
        let params = match auth {
            SOCKS5AuthNConfig::None => SOCKS5Params::connect_no_auth(target),
            SOCKS5AuthNConfig::Password { username, password } => {
                SOCKS5Params::connect_password_auth(target, username, password)
            }
            #[cfg(feature = "gssapi")]
            SOCKS5AuthNConfig::GSSAPI { gssapi } => {
                SOCKS5Params::connect_gssapi_auth(target, gssapi, None)
            }
        };
        let proxy = Conn::create(caches, proxy)?;

        Ok(SOCKS5NearConnector {
            params: params,
            proxy: proxy
        })
    }
}

impl<Inner, Proxy> ScopedError for SOCKS5NegotiateError<Inner, Proxy>
where Inner: ScopedError {
    fn scope(&self) -> ErrorScope {
        match self {
            SOCKS5NegotiateError::Inner { err, .. } => err.scope(),
            SOCKS5NegotiateError::SOCKS5 { err, .. } => err.scope(),
            SOCKS5NegotiateError::BadSplit => ErrorScope::Unrecoverable
        }
    }
}

impl<Inner, Proxy> Display for SOCKS5NegotiateError<Inner, Proxy>
where Inner: Display {
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            SOCKS5NegotiateError::Inner { err, .. } => err.fmt(f),
            SOCKS5NegotiateError::SOCKS5 { err, .. } =>
                write!(f, "{}", err),
            SOCKS5NegotiateError::BadSplit =>
                write!(f, "invalid result from split()")
        }
    }
}
