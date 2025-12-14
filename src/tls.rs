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

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::io::Write;
use std::marker::PhantomData;
use std::time::Duration;
use std::time::Instant;

use constellation_auth::cred::Credentials;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::Negotiator;
use constellation_common::net::NegotiatorResult;
use constellation_common::net::NegotiatorStart;
use constellation_common::net::Session;
use constellation_common::retry::Retry;
use log::debug;
use log::info;
use log::trace;
use openssl::ssl::Error;
use openssl::ssl::ErrorCode;
use openssl::ssl::ShutdownResult;
use openssl::ssl::SslStream;

/// [Negotiator] state for shutting down sessions for
/// [TLSNearChannel].
#[derive(Clone)]
pub struct TLSShutdownNegotiator<Stream, Inner> {
    stream: PhantomData<Stream>,
    /// Total maximum duration.
    timeout: Duration,
    /// Retry configuration for sending shutdown messages.
    retry: Retry,
    inner: Inner
}

/// [Negotiator] state for shutting down sessions for [TLSNearChannel].
pub struct TLSShutdownNegotiatorState<Stream, Inner>
where Stream: Session + Read + Write {
    inner: PhantomData<Inner>,
    /// The underlying SSL stream.
    ssl: SslStream<Stream>,
}

pub enum TLSShutdownNegoPending<Stream, InnerState>
where Stream: Session + Read + Write {
    /// Shutting down the TLS session.
    TLS {
        inner: PhantomData<InnerState>,
        /// Stream to shut down.
        ssl: SslStream<Stream>,
        /// Maximum time for attempting to shut down.
        timeout: Instant,
        /// Number of shutdown messages sent.
        nretries: usize,
        /// When to send the next message.
        when: Instant,
    }
    // XXX This does not shut down the inner stream, due to a
    // limitation in the OpenSSL bindings library.
}

/// Errors that can occur during TLS session negotiation.
#[derive(Debug)]
pub enum TLSShutdownError<Inner> {
    /// An error occurred on the underlying channel.
    Inner {
        /// The underlying channel error.
        inner: Inner
    },
    /// Error during .
    OpenSSL {
        /// The handshake error.
        err: Error
    },
    IO {
        err: std::io::Error
    },
    /// Shutdown timed out.
    Timeout
}

impl <Stream, Inner> TLSShutdownNegotiator<Stream, Inner>
where
    Stream: Credentials + Session + Read + Write,
    Inner: Negotiator<()>
{
    #[inline]
    pub fn new(
        inner: Inner,
        retry: Retry,
        timeout: Duration
    ) -> Self {
        TLSShutdownNegotiator {
            stream: PhantomData,
            timeout: timeout,
            retry: retry,
            inner: inner
        }
    }
}

impl <Stream, Inner> Negotiator<()> for TLSShutdownNegotiator<Stream, Inner>
where
    Stream: Credentials + Session + Read + Write,
    Inner: Negotiator<()>
{
    type State = TLSShutdownNegotiatorState<Stream, Inner::State>;
    type Pending = TLSShutdownNegoPending<Stream, Inner::Pending>;
    type NegotiateError = TLSShutdownError<Inner::NegotiateError>;

    fn negotiate(
        &self,
        mut state: Self::State
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        let addr = state.ssl.get_ref().peer_addr()
            .map_err(|err| TLSShutdownError::IO { err: err })?;

        debug!(target: "tls-shutdown",
               "shutting down TLS session with {}",
               addr);

        match state.ssl.shutdown() {
            Ok(ShutdownResult::Sent) => {
                let now = Instant::now();
                let timeout = now + self.timeout;
                let delay = self.retry.retry_delay(0);
                let when = now + delay;

                Ok(NegotiatorResult::Pending(
                    TLSShutdownNegoPending::TLS {
                        inner: PhantomData,
                        ssl: state.ssl,
                        timeout: timeout,
                        when: when,
                        nretries: 1,
                    }
                ))
            }
            Ok(ShutdownResult::Received) => {
                info!(target: "tls-shutdown",
                      "TLS session with {} shut down successfully",
                      addr);

                // XXX Need to shut down the inner stream here, but
                // we'd need to deconstruct the SSL stream to do that.
                //
                // Ok(self.inner.negotiate(state.inner)?
                //    .map_pending(|inner| TLSShutdownNegoPending::Inner {
                //        pending: inner
                //    }))

                Ok(NegotiatorResult::Complete(()))
            }
            Err(err) => match err.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                    let now = Instant::now();
                    let timeout = now + self.timeout;
                    let delay = self.retry.retry_delay(0);
                    let when = now + delay;

                    trace!(target: "tls-shutdown",
                           "pausing TLS negotiation with {}",
                           addr);

                    Ok(NegotiatorResult::Pending(
                        TLSShutdownNegoPending::TLS {
                            inner: PhantomData,
                            ssl: state.ssl,
                            timeout: timeout,
                            when: when,
                            nretries: 1,
                        }
                    ))
                },
                _ => Err(TLSShutdownError::OpenSSL { err: err })
            }
        }
    }

    fn complete_negotiate(
        &self,
        pending: TLSShutdownNegoPending<Stream, Inner::Pending>
    ) -> Result<NegotiatorResult<(), Self::Pending>, Self::NegotiateError> {
        let now = Instant::now();

        match pending {
            TLSShutdownNegoPending::TLS {
                mut ssl, inner, timeout, nretries, ..
            } => match ssl.shutdown() {
                Ok(ShutdownResult::Sent) => {
                    let delay = self.retry.retry_delay(nretries);
                    let when = now + delay;

                    Ok(NegotiatorResult::Pending(
                        TLSShutdownNegoPending::TLS {
                            inner: inner,
                            ssl: ssl,
                            timeout: timeout,
                            when: when,
                            nretries: nretries + 1,
                        }
                    ))
                }
                Ok(ShutdownResult::Received) => {
                    let addr = ssl.get_ref().peer_addr()
                        .map_err(|err| TLSShutdownError::IO { err: err })?;

                    info!(target: "tls-shutdown",
                          "TLS session with {} shut down successfully",
                          addr);

                    // XXX Need to shut down the inner stream here, but
                    // we'd need to deconstruct the SSL stream to do that.
                    //
                    // Ok(self.inner.negotiate(state.inner)?
                    //    .map_pending(|inner| TLSShutdownNegoPending::Inner {
                    //        pending: inner
                    //    }))

                    Ok(NegotiatorResult::Complete(()))
                }
                Err(err) => match err.code() {
                    ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => {
                        let addr = ssl.get_ref().peer_addr()
                            .map_err(|err| TLSShutdownError::IO { err: err })?;
                        let delay = self.retry.retry_delay(nretries);
                        let when = now + delay;

                        trace!(target: "tls-shutdown",
                               "pausing TLS negotiation with {}",
                               addr);

                        Ok(NegotiatorResult::Pending(
                            TLSShutdownNegoPending::TLS {
                                inner: inner,
                                ssl: ssl,
                                timeout: timeout,
                                when: when,
                                nretries: nretries + 1,
                            }
                        ))
                    },
                    _ => Err(TLSShutdownError::OpenSSL { err: err })
                }
            }
        }
    }
}


impl <Stream, Inner> NegotiatorStart<(), SslStream<Stream>>
    for TLSShutdownNegotiator<Stream, Inner>
where
    Inner: NegotiatorStart<(), Stream>,
    Stream: Credentials + Session + Read + Write,
{
    type Param = ();
    type StartError = Inner::StartError;

    #[inline]
    fn start(
        &self,
        _param: &(),
        stream: SslStream<Stream>
    ) -> Result<Self::State, Self::StartError> {
        Ok(TLSShutdownNegotiatorState {
            inner: PhantomData,
            ssl: stream,
        })
    }
}

impl<Inner> ScopedError for TLSShutdownError<Inner>
where Inner: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            TLSShutdownError::Inner { inner } => inner.scope(),
            TLSShutdownError::IO { err } => err.scope(),
            TLSShutdownError::OpenSSL { err } => err.scope(),
            TLSShutdownError::Timeout => ErrorScope::Session
        }
    }
}

impl<Inner> Display for TLSShutdownError<Inner>
where
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter
    ) -> Result<(), std::fmt::Error> {
        match self {
            TLSShutdownError::Inner { inner } => write!(f, "{}", inner),
            TLSShutdownError::IO { err } => write!(f, "{}", err),
            TLSShutdownError::OpenSSL { err } => write!(f, "{}", err),
            TLSShutdownError::Timeout =>
                write!(f, "shutdown negotiations timed out")
        }
    }
}
