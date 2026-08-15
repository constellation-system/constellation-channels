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

use std::fs::metadata;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread::spawn;

use constellation_channels::config::FlowsConfig;
use constellation_channels::config::UnixFarChannelConfig;
use constellation_channels::far::FarChannel;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlows;
use constellation_channels::far::flows::accept_one;
use constellation_channels::far::flows::connect_one;
use constellation_channels::far::flows::read_one;
use constellation_channels::far::flows::write_one;
use constellation_channels::far::unix::UnixFarChannel;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketPath;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::api::ExampleCtx;
use crate::init;

#[test]
fn test_send_recv() {
    init();

    const CHANNEL_CONFIG: &'static str =
        concat!("path: test_far_send_recv_channel.sock\n",);
    const CLIENT_CONFIG: &'static str =
        concat!("path: test_far_send_recv_client.sock\n");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let client_config: UnixFarChannelConfig =
        yaml_serde::from_str(CLIENT_CONFIG).unwrap();
    let server_config: UnixFarChannelConfig =
        yaml_serde::from_str(CHANNEL_CONFIG).unwrap();
    let server_path = server_config.path().to_path_buf();
    let client_path = client_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&server_path).is_err());
    assert!(metadata(&client_path).is_err());

    let client_addr = UnixSocketPath::from(&client_path);
    let server_barrier = barrier.clone();
    let server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(server_nscaches);
        let mut listener = UnixFarChannel::create(&mut ctx, server_config)
            .expect("Expected success");
        let config = FlowsConfig::default();
        let param = match listener
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows = listener
            .flows(config, param, xfrm)
            .expect("Expected success");
        let token = Token(0);

        poll.registry()
            .register(
                &mut flows,
                token,
                Interest::READABLE | Interest::WRITABLE
            )
            .expect("Expected success");

        server_barrier.wait();

        let (mut flow, peer_addr) =
            accept_one(&mut flows, &mut poll, &(), token)
                .expect("Expected success");

        server_barrier.wait();

        let mut buf = [0; FIRST_BYTES.len()];
        let nbytes = read_one(
            &mut flows,
            &mut poll,
            &mut flow,
            &mut buf,
            &peer_addr,
            &(),
            token
        )
        .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &SECOND_BYTES, token)
            .expect("Expected success");

        server_barrier.wait();

        assert_eq!(peer_addr, client_addr);
        assert_eq!(FIRST_BYTES.len(), nbytes);
        assert_eq!(FIRST_BYTES, buf);
    });

    let server_addr = UnixSocketPath::from(&server_path);
    let client_barrier = barrier;
    let client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(client_nscaches);
        let mut conn = UnixFarChannel::create(&mut ctx, client_config)
            .expect("expected success");
        let config = FlowsConfig::default();
        let param = match conn
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let xfrm = PassthruDatagramXfrm::new();
        let mut flows =
            conn.flows(config, param, xfrm).expect("Expected success");
        let token = Token(0);

        poll.registry()
            .register(
                &mut flows,
                token,
                Interest::READABLE | Interest::WRITABLE
            )
            .expect("Expected success");

        client_barrier.wait();

        let mut flow = connect_one(
            &mut flows,
            &mut poll,
            &(),
            &(),
            server_addr.clone(),
            token
        )
        .expect("Expected success");

        write_one(&mut flows, &mut poll, &mut flow, &FIRST_BYTES, token)
            .expect("Expected success");

        client_barrier.wait();
        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let nbytes = read_one(
            &mut flows,
            &mut poll,
            &mut flow,
            &mut buf,
            &server_addr,
            &(),
            token
        )
        .expect("Expected success");

        assert_eq!(SECOND_BYTES.len(), nbytes);
        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&server_path).is_err());
    assert!(metadata(&client_path).is_err());
}
