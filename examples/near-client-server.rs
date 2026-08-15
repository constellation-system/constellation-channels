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

use std::net::Shutdown;

use constellation_channels::near::NearChannel;
use constellation_channels::near::NearChannelCreate;
use constellation_channels::near::accept_one;
use constellation_channels::near::negotiate_one;
use constellation_channels::near::read_one;
use constellation_channels::near::tcp::TCPNearAcceptor;
use constellation_channels::near::tcp::TCPResolvingNearConnector;
use constellation_channels::near::write_one;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::retry::RetryResult;
use log::LevelFilter;
use log::info;
use mio::Interest;
use mio::Poll;
use mio::Token;

const SERVER_CONFIG: &'static str = concat!("addr: ::1\n", "port: 8006\n");
const CLIENT_CONFIG: &'static str =
    concat!("addr: localhost\n", "port: 8006\n");
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

fn server() {
    let accept_config = yaml_serde::from_str(SERVER_CONFIG).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let listen = Token(0);
    let session = Token(1);
    let mut poll = Poll::new().expect("Expected success");

    info!("creating channel");

    let mut acceptor = TCPNearAcceptor::create(&mut nscaches, accept_config)
        .expect("Expected success");

    poll.registry()
        .register(&mut acceptor, listen, Interest::READABLE)
        .expect("Expected success");

    info!("waiting for incoming");

    let start = accept_one(&mut acceptor, &mut poll, listen, session)
        .expect("Expected success");

    info!("got connection, negotiating");

    let (mut stream, _) =
        negotiate_one(&mut acceptor, &mut poll, start, session)
            .expect("Expected success");

    info!("negotiated, waiting on message");

    let mut buf = [0; FIRST_BYTES.len()];

    read_one(&mut stream, &mut poll, session, &mut buf)
        .expect("Expected success");

    info!("got message {:?}, sending {:?}", buf, SECOND_BYTES);

    write_one(&mut stream, &mut poll, session, &SECOND_BYTES)
        .expect("Expected success");

    info!("finished, shutting down");

    stream.shutdown(Shutdown::Both).unwrap();

    assert_eq!(FIRST_BYTES, buf);
}

fn client() {
    let connect_config = yaml_serde::from_str(CLIENT_CONFIG).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let session = Token(0);
    let mut poll = Poll::new().expect("Expected success");
    let mut conn =
        TCPResolvingNearConnector::create(&mut nscaches, connect_config)
            .expect("expected success");

    info!("created channel");

    let start = match conn
        .start(poll.registry(), session)
        .expect("expected success")
    {
        RetryResult::Success(start) => start,
        RetryResult::Retry(_) => panic!("shouldn't see retry")
    };

    info!("connected, negotiating");

    let (mut stream, _) = negotiate_one(&mut conn, &mut poll, start, session)
        .expect("Expected success");

    info!("negotiated, sending {:?}", FIRST_BYTES);

    write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
        .expect("Expected success");

    let mut buf = [0; SECOND_BYTES.len()];

    info!("waiting for message");

    read_one(&mut stream, &mut poll, session, &mut buf)
        .expect("Expected success");

    info!("got message {:?}, shutting down", buf);

    assert_eq!(SECOND_BYTES, buf);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} [client | server]", args[0]);
        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    match args[1].as_str() {
        "client" => client(),
        "server" => server(),
        _ => {
            eprintln!("Usage: {} [client | server]", args[0]);
            std::process::exit(1);
        }
    }
}
