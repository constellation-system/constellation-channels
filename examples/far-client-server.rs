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

use std::net::SocketAddr;

use constellation_channels::config::FlowsConfig;
use constellation_channels::config::UDPFarChannelConfig;
use constellation_channels::far::FarChannel;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlows;
use constellation_channels::far::flows::accept_one;
use constellation_channels::far::flows::read_one;
use constellation_channels::far::flows::write_one;
use constellation_channels::far::udp::UDPFarChannel;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::retry::RetryResult;
use log::info;
use log::LevelFilter;
use mio::Interest;
use mio::Poll;
use mio::Token;

const SERVER_CONFIG: &'static str = concat!("addr: ::1\n", "port: 7007\n");
const CLIENT_CONFIG: &'static str = concat!("addr: ::1\n", "port: 7008\n");
//const SERVER_CONFIG: &'static str =
//    concat!("path: test_far_send_recv_channel.sock\n",);
//const CLIENT_CONFIG: &'static str =
//    concat!("path: test_far_send_recv_client.sock\n");
const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

fn server() {
    let server_config = serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let mut listener =
        UDPFarChannel::new(&mut nscaches, server_config)
        .expect("Expected success");
    let config = FlowsConfig::default();
    let param = match listener.acquire()
        .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
    let xfrm = PassthruDatagramXfrm::new();
    let mut flows = listener.flows(config, param, xfrm)
        .expect("Expected success");
    let mut poll = Poll::new().expect("Expected success");
    let token = Token(0);

    poll.registry().register(&mut flows, token,
                             Interest::READABLE | Interest::WRITABLE)
        .expect("Expected success");

    let (mut flow, peer_addr) = accept_one(&mut flows, &mut poll, token)
        .expect("Expected success");

    let mut buf = [0; FIRST_BYTES.len()];
    let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                          &mut buf, &peer_addr, token)
        .expect("Expected success");

    write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
        .expect("Expected success");

    assert_eq!(FIRST_BYTES.len(), nbytes);
    assert_eq!(FIRST_BYTES, buf);
}

fn client() {
    let server_config: UDPFarChannelConfig =
        serde_yaml::from_str(SERVER_CONFIG).unwrap();
    let server_addr =
        SocketAddr::new(server_config.addr().clone(), server_config.port());
    let client_config = serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let mut nscaches = SharedNSNameCaches::new();
    let mut conn =
        UDPFarChannel::new(&mut nscaches, client_config)
        .expect("expected success");
    let config = FlowsConfig::default();
    let param = match conn.acquire()
        .expect("Expected success") {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
    let xfrm = PassthruDatagramXfrm::new();
    let mut flows = conn.flows(config, param, xfrm)
        .expect("Expected success");
    let mut poll = Poll::new().expect("Expected success");
    let token = Token(0);

    poll.registry().register(&mut flows, token,
                             Interest::READABLE | Interest::WRITABLE)
        .expect("Expected success");

    let mut flow = flows.flow(server_addr.clone())
        .expect("Expected success")
        .expect("Expected some");

    write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
        .expect("Expected success");

    let mut buf = [0; SECOND_BYTES.len()];

    let nbytes = read_one(&mut flows, &mut poll, &mut flow,
                          &mut buf, &server_addr, token)
        .expect("Expected success");

    assert_eq!(SECOND_BYTES.len(), nbytes);
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
