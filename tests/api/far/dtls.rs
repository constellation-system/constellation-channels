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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread::spawn;

use constellation_channels::config::DTLSFarChannelConfig;
use constellation_channels::config::FlowsConfig;
use constellation_channels::config::UDPFarChannelConfig;
use constellation_channels::far::dtls::DTLSFarChannel;
use constellation_channels::far::dtls::DTLSOutboundParam;
use constellation_channels::far::flows::accept_one;
use constellation_channels::far::flows::connect_one;
use constellation_channels::far::flows::read_one;
use constellation_channels::far::flows::write_one;
use constellation_channels::far::udp::UDPFarChannel;
use constellation_channels::far::FarChannel;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlows;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::net::IPEndpointAddr;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::retry::RetryResult;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::api::ExampleCtx;
use crate::init;

#[cfg(test)]
const CHANNEL_CONFIG: &'static str = concat!(
    "addr: ::1\n",
    "port: 8281\n",
    "cipher-suites:\n",
    "  - TLS_AES_256_GCM_SHA384\n",
    "  - TLS_CHACHA20_POLY1305_SHA256\n",
    "key-exchange-groups:\n",
    "  - P-384\n",
    "  - X25519\n",
    "  - P-256\n",
    "trust-root:\n",
    "  root-certs:\n",
    "    - tests/data/certs/client/ca_cert.pem\n",
    "  crls: []\n",
    "cert: tests/data/certs/server/certs/test_server_cert.pem\n",
    "key: tests/data/certs/server/private/test_server_key.pem\n",
);

#[cfg(test)]
const CLIENT_CONFIG: &'static str = concat!(
    "addr: ::1\n",
    "port: 8282\n",
    "cipher-suites:\n",
    "  - TLS_AES_256_GCM_SHA384\n",
    "  - TLS_CHACHA20_POLY1305_SHA256\n",
    "key-exchange-groups:\n",
    "  - P-384\n",
    "  - X25519\n",
    "  - P-256\n",
    "trust-root:\n",
    "  root-certs:\n",
    "    - tests/data/certs/server/ca_cert.pem\n",
    "  crls: []\n",
    "cert: tests/data/certs/client/certs/test_client_cert.pem\n",
    "key: tests/data/certs/client/private/test_client_key.pem\n",
);

#[test]
fn test_send_recv() {
    init();

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CHANNEL_CONFIG).unwrap();
    let client_config: DTLSFarChannelConfig<UDPFarChannelConfig> =
        serde_yaml::from_str(CLIENT_CONFIG).unwrap();
    let server_addr = SocketAddr::new(
        server_config.tls().underlying().addr().clone(),
        server_config.tls().underlying().port()
    );
    let client_addr = SocketAddr::new(
        client_config.tls().underlying().addr().clone(),
        client_config.tls().underlying().port()
    );
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(server_nscaches);
        let mut listener =
            DTLSFarChannel::<UDPFarChannel>::create(&mut ctx, server_config)
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

    let client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let dtlsparam = DTLSOutboundParam::new(endpoint, ());
        let mut ctx = ExampleCtx::new(client_nscaches);
        let mut conn =
            DTLSFarChannel::<UDPFarChannel>::create(&mut ctx, client_config)
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
            &dtlsparam,
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

    send.join().unwrap();
    listen.join().unwrap();
}
