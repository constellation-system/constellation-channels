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

use constellation_channels::config::CompoundNearAcceptorConfig;
use constellation_channels::config::CompoundResolvingNearConnectorConfig;
use constellation_channels::config::tls::TLSClientConfig;
use constellation_channels::config::tls::TLSServerConfig;
use constellation_channels::near::NearChannel;
use constellation_channels::near::NearChannelCreate;
use constellation_channels::near::accept_one;
use constellation_channels::near::compound::CompoundNearAcceptor;
use constellation_channels::near::compound::CompoundResolvingNearConnector;
use constellation_channels::near::negotiate_one;
use constellation_channels::near::read_one;
use constellation_channels::near::write_one;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::retry::RetryResult;
use log::LevelFilter;
use log::info;
use mio::Interest;
use mio::Poll;
use mio::Token;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

fn server(conf: &str) {
    let server_conf: CompoundNearAcceptorConfig<TLSServerConfig> =
        yaml_serde::from_str(conf).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let listen = Token(0);
    let session = Token(1);
    let mut poll = Poll::new().expect("Expected success");

    info!("creating channel");

    let mut acceptor = CompoundNearAcceptor::create(&mut nscaches, server_conf)
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

    assert_eq!(FIRST_BYTES, buf);
}

fn client(conf: &str) {
    let client_conf: CompoundResolvingNearConnectorConfig<TLSClientConfig> =
        yaml_serde::from_str(conf).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let session = Token(0);
    let mut poll = Poll::new().expect("Expected success");
    let mut conn =
        CompoundResolvingNearConnector::create(&mut nscaches, client_conf)
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

    if args.len() != 3 {
        eprintln!("Usage: {} [client | server] <config>", args[0]);
        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    let conf = std::fs::read_to_string(&args[2]).unwrap();

    match args[1].as_str() {
        "client" => client(conf.as_str()),
        "server" => server(conf.as_str()),
        _ => {
            eprintln!("Usage: {} [client | server]", args[0]);
            std::process::exit(1);
        }
    }
}
