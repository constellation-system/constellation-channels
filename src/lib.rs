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

#![allow(clippy::redundant_field_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::upper_case_acronyms)]
#![allow(incomplete_features)]
#![feature(peer_credentials_unix_socket)]
#![feature(generic_const_exprs)]
#![feature(get_mut_unchecked)]
#![feature(let_chains)]
#![feature(unix_socket_peek)]

//! Low-level communications API for Constellation.
//!
//! This package provides *channels*- a low-level abstraction for
//! network/IPC communications used by the Constellation distributed
//! systems platform.  The channel abstractions provided by this
//! package are usable in their own right as well.
//!
//! Channels are configurable; each channel type has an associated
//! configuration object that can be parsed from YAML using
//! `serde_yaml`.  This allows channels to be easily created from
//! information in configuration files.
//!
//! # Near vs. Far Channels
//!
//! Channels provided by this package come in two varieties:
//!
//!  - **Far**: "Far" channels represent unreliable datagram
//!    communications over an uncooperative network.  The common
//!    example is UDP commuincations.  Far channels are intended for
//!    general network communications.  See the [far] module for more
//!    details.
//!
//!  - **Near**: "Near" channels represent reliable, connection-based
//!    stream protocols over generally reliable networks.  The common
//!    example is TCP commuincations.  Near channels are intended for
//!    "local" connections, or for a friendly network environment.
//!    See the [near] module for more details.
pub mod addrs;
pub mod config;
pub mod far;
pub mod near;
pub mod resolve;
#[cfg(feature = "unix")]
pub mod unix;

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
use log::LevelFilter;

#[cfg(test)]
static INIT: Once = Once::new();

#[cfg(test)]
fn init() {
    INIT.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(LevelFilter::Trace)
            .init()
    })
}
