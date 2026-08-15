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

use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread::spawn;

use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::FlowsConfig;
use constellation_channels::far::FarChannel;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlows;
use constellation_channels::far::compound::CompoundFarChannel;
use constellation_channels::far::compound::CompoundFarChannelAcquireState;
use constellation_channels::far::compound::CompoundFarChannelParam;
use constellation_channels::far::compound::CompoundFarChannelXfrm;
use constellation_channels::far::compound::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::far::compound::CompoundFarIPChannelAcquireState;
use constellation_channels::far::compound::CompoundFarIPChannelParam;
use constellation_channels::far::compound::CompoundOutboundNegotiatorParam;
use constellation_channels::far::dtls::DTLSOutboundParam;
use constellation_channels::far::flows::accept_one;
use constellation_channels::far::flows::connect_one;
use constellation_channels::far::flows::read_one;
use constellation_channels::far::flows::write_one;
use constellation_channels::far::udp::UDPDatagramXfrm;
use constellation_channels::far::unix::UnixDatagramXfrm;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::net::IPEndpointAddr;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketPath;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::api::ExampleCtx;
use crate::init;

#[test]
fn test_compound_dtls_unix() {
    init();

    const CHANNEL_PATH: &'static str = "test_compound_dtls_unix_server.sock";
    const CLIENT_PATH: &'static str = "test_compound_dtls_unix_client.sock";

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_compound_dtls_unix_server.sock\n",
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  key: tests/data/certs/client/private/test_client_key.pem\n",
        "  unix-datagram:\n",
        "    path: test_compound_dtls_unix_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        yaml_serde::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        yaml_serde::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CLIENT_PATH).unwrap()
    );
    let server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(server_nscaches);
        let mut listener = CompoundFarChannel::create(&mut ctx, server_config)
            .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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

    let server_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CHANNEL_PATH).unwrap()
    );
    let client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(
                endpoint,
                CompoundOutboundNegotiatorParam::Basic
            ))
        };
        let mut ctx = ExampleCtx::new(client_nscaches);
        let mut conn = CompoundFarChannel::create(&mut ctx, client_config)
            .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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
            &negoparam,
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

#[test]
fn test_compound_dtls_udp() {
    init();

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  udp:\n",
        "    addr: ::1\n",
        "    port: 7003\n"
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  key: tests/data/certs/client/private/test_client_key.pem\n",
        "  udp:\n",
        "    addr: ::1\n",
        "    port: 7004\n"
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        yaml_serde::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        yaml_serde::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7004".parse().unwrap());
    let server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(server_nscaches);
        let mut listener = CompoundFarChannel::create(&mut ctx, server_config)
            .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::IP {
                ip: CompoundFarIPChannelAcquireState::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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

    let server_addr =
        CompoundFarChannelXfrmPeerAddr::udp("[::1]:7003".parse().unwrap());
    let client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(
                endpoint,
                CompoundOutboundNegotiatorParam::Basic
            ))
        };
        let mut ctx = ExampleCtx::new(client_nscaches);
        let mut conn = CompoundFarChannel::create(&mut ctx, client_config)
            .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::IP {
                ip: CompoundFarIPChannelAcquireState::UDP { udp }
            } => CompoundFarChannelParam::IP {
                ip: CompoundFarIPChannelParam::UDP { udp: udp }
            },
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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
            &negoparam,
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

#[test]
fn test_compound_dtls_double() {
    init();

    const CHANNEL_PATH: &'static str = "test_compound_dtls_double_server.sock";
    const CLIENT_PATH: &'static str = "test_compound_dtls_double_client.sock";

    const SERVER_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/client/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "  key: tests/data/certs/server/private/test_server_key.pem\n",
        "  dtls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - P-384\n",
        "      - X25519\n",
        "      - P-256\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/client/ca_cert.pem\n",
        "      crls: []\n",
        "    cert: tests/data/certs/server/certs/test_server_cert.pem\n",
        "    key: tests/data/certs/server/private/test_server_key.pem\n",
        "    unix-datagram:\n",
        "      path: test_compound_dtls_double_server.sock\n",
    );

    const CLIENT_CONFIG: &'static str = concat!(
        "dtls:\n",
        "  cipher-suites:\n",
        "    - TLS_AES_256_GCM_SHA384\n",
        "    - TLS_CHACHA20_POLY1305_SHA256\n",
        "  key-exchange-groups:\n",
        "    - P-384\n",
        "    - X25519\n",
        "    - P-256\n",
        "  trust-root:\n",
        "    root-certs:\n",
        "      - tests/data/certs/server/ca_cert.pem\n",
        "    crls: []\n",
        "  cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "  key: tests/data/certs/client/private/test_client_key.pem\n",
        "  dtls:\n",
        "    cipher-suites:\n",
        "      - TLS_AES_256_GCM_SHA384\n",
        "      - TLS_CHACHA20_POLY1305_SHA256\n",
        "    key-exchange-groups:\n",
        "      - P-384\n",
        "      - X25519\n",
        "      - P-256\n",
        "    trust-root:\n",
        "      root-certs:\n",
        "        - tests/data/certs/server/ca_cert.pem\n",
        "      crls: []\n",
        "    cert: tests/data/certs/client/certs/test_client_cert.pem\n",
        "    key: tests/data/certs/client/private/test_client_key.pem\n",
        "    unix-datagram:\n",
        "      path: test_compound_dtls_double_client.sock\n",
    );

    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let server_config: CompoundFarChannelConfig =
        yaml_serde::from_str(SERVER_CONFIG).unwrap();
    let client_config: CompoundFarChannelConfig =
        yaml_serde::from_str(CLIENT_CONFIG).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let client_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CLIENT_PATH).unwrap()
    );
    let server_nscaches = nscaches.clone();
    let server_barrier = barrier.clone();
    let listen = spawn(move || {
        let mut poll = Poll::new().expect("Expected success");
        let mut ctx = ExampleCtx::new(server_nscaches);
        let mut listener = CompoundFarChannel::create(&mut ctx, server_config)
            .expect("Expected success");
        let config = FlowsConfig::default();
        let acquire = match listener
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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

    let server_addr = CompoundFarChannelXfrmPeerAddr::unix(
        UnixSocketPath::try_from(CHANNEL_PATH).unwrap()
    );
    let client_nscaches = nscaches.clone();
    let client_barrier = barrier;
    let send = spawn(move || {
        let servername = "test-server.nowhere.com";
        let endpoint = IPEndpointAddr::name(String::from(servername));
        let mut poll = Poll::new().expect("Expected success");
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(
                endpoint.clone(),
                CompoundOutboundNegotiatorParam::Basic
            ))
        };
        let negoparam = CompoundOutboundNegotiatorParam::DTLS {
            dtls: Box::new(DTLSOutboundParam::new(endpoint, negoparam))
        };
        let mut ctx = ExampleCtx::new(client_nscaches);
        let mut conn = CompoundFarChannel::create(&mut ctx, client_config)
            .expect("expected success");
        let config = FlowsConfig::default();
        let acquire = match conn
            .acquire(&mut vec![], poll.registry())
            .expect("Expected success")
        {
            RetryResult::Success(val) => val,
            RetryResult::Retry(_) => panic!("should not see retry")
        };
        let param = match acquire {
            CompoundFarChannelAcquireState::Unix { unix } => {
                CompoundFarChannelParam::Unix { unix: unix }
            }
            _ => panic!("Expected Unix acquired")
        };
        let create_param: CompoundXfrmCreateParam<(), ()> =
            CompoundXfrmCreateParam::default();
        let xfrm: CompoundFarChannelXfrm<
            UnixDatagramXfrm<UnixSocketPath>,
            UDPDatagramXfrm<SocketAddr>
        > = CompoundFarChannelXfrm::create(&param, &create_param);
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
            &negoparam,
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
