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

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Error;

use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;

#[derive(Debug)]
pub enum SessionNegoToAuthError<AuthN, Start> {
    /// An error occurred during authentication negotiations.
    AuthN {
        /// The error that occurred during authentication negotiations.
        err: AuthN
    },
    /// An error occurred starting authentication negotiation.
    Start {
        /// The error that occurred starting authentication negotiations.
        err: Start
    },
    /// An error occurred clearing the backlog.
    IO {
        /// The error that occurred clearing the backlog.
        err: Error
    }
}

#[derive(Debug)]
pub enum ShutdownError<Start, Negotiate> {
    /// Error occurred starting negotiations.
    Start { err: Start },
    /// Error occurred during negotiation.
    Negotiate { err: Negotiate }
}

#[derive(Debug)]
pub enum WithShutdownError<Inner, Start, Negotiate> {
    /// Error occurred starting negotiations.
    Shutdown {
        err: ShutdownError<Start, Negotiate>
    },
    Inner {
        err: Inner
    }
}

impl<AuthN, Start> ScopedError for SessionNegoToAuthError<AuthN, Start>
where
    AuthN: ScopedError,
    Start: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            SessionNegoToAuthError::AuthN { err } => err.scope(),
            SessionNegoToAuthError::Start { err } => err.scope(),
            SessionNegoToAuthError::IO { err } => err.scope()
        }
    }
}

impl<Start, Negotiate> ScopedError for ShutdownError<Start, Negotiate>
where
    Negotiate: ScopedError,
    Start: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            ShutdownError::Start { err } => err.scope(),
            ShutdownError::Negotiate { err } => err.scope()
        }
    }
}

impl<Inner, Start, Negotiate> ScopedError
    for WithShutdownError<Inner, Start, Negotiate>
where
    Inner: ScopedError,
    Negotiate: ScopedError,
    Start: ScopedError
{
    fn scope(&self) -> ErrorScope {
        match self {
            WithShutdownError::Shutdown { err } => err.scope(),
            WithShutdownError::Inner { err } => err.scope()
        }
    }
}

impl<AuthN, Start> Display for SessionNegoToAuthError<AuthN, Start>
where
    Start: Display,
    AuthN: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            SessionNegoToAuthError::AuthN { err } => err.fmt(f),
            SessionNegoToAuthError::Start { err } => err.fmt(f),
            SessionNegoToAuthError::IO { err } => err.fmt(f)
        }
    }
}

impl<Start, Negotiate> Display for ShutdownError<Start, Negotiate>
where
    Negotiate: Display,
    Start: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            ShutdownError::Start { err } => err.fmt(f),
            ShutdownError::Negotiate { err } => err.fmt(f)
        }
    }
}

impl<Inner, Start, Negotiate> Display
    for WithShutdownError<Inner, Start, Negotiate>
where
    Negotiate: Display,
    Start: Display,
    Inner: Display
{
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self {
            WithShutdownError::Shutdown { err } => err.fmt(f),
            WithShutdownError::Inner { err } => err.fmt(f)
        }
    }
}
