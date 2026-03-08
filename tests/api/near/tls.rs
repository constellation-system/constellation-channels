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

use std::sync::Arc;
use std::sync::Barrier;
use std::thread::spawn;

use constellation_channels::config::tls::TLSClientConfig;
use constellation_channels::config::tls::TLSServerConfig;
use constellation_channels::config::TLSNearAcceptorConfig;
use constellation_channels::config::TLSNearConnectorConfig;
use constellation_channels::config::UnixNearChannelConfig;
use constellation_channels::near::accept_one;
use constellation_channels::near::negotiate_one;
use constellation_channels::near::read_one;
use constellation_channels::near::write_one;
use constellation_channels::near::NearChannel;
use constellation_channels::near::NearChannelCreate;
use constellation_channels::near::tls::TLSNearAcceptor;
use constellation_channels::near::tls::TLSNearConnector;
use constellation_channels::near::unix::UnixNearAcceptor;
use constellation_channels::near::unix::UnixNearConnector;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::retry::RetryResult;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::init;

fn server_conf(path: &str) -> String {
    format!(
        concat!(
            "cipher-suites:\n",
            "  - TLS_AES_256_GCM_SHA384\n",
            "  - TLS_CHACHA20_POLY1305_SHA256\n",
            "key-exchange-groups:\n",
            "  - X25519\n",
            "  - P-256\n",
            "client-auth:\n",
            "  verify: required\n",
            "  trust-root:\n",
            "    root-certs:\n",
            "      - tests/data/certs/client/ca_cert.pem\n",
            "    crls: []\n",
            "cert: tests/data/certs/server/certs/test_server_cert.pem\n",
            "key: tests/data/certs/server/private/test_server_key.pem\n",
            "path: {}"
        ),
        path
    )
}

fn client_conf(path: &str) -> String {
    format!(
        concat!(
            "cipher-suites:\n",
            "  - TLS_AES_256_GCM_SHA384\n",
            "  - TLS_CHACHA20_POLY1305_SHA256\n",
            "key-exchange-groups:\n",
            "  - X25519\n",
            "  - P-256\n",
            "trust-root:\n",
            "  root-certs:\n",
            "    - tests/data/certs/server/ca_cert.pem\n",
            "  crls: []\n",
            "client-cert: tests/data/certs/client/certs/test_client_cert.pem\n",
            "client-key: tests/data/certs/client/private/test_client_key.pem\n",
            "verify-endpoint: test-server.nowhere.com\n",
            "path: {}"
        ),
        path
    )
}

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[test]
fn test_negotiate() {
    init();

    const PATH: &'static str = "test-tls-negotiate.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let _ = negotiate_one(&mut acceptor, &mut poll, start, session)
            .expect("Expected success");
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn
            .start(poll.registry(), session)
            .expect("expected success")
        {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };
        let _ = negotiate_one(&mut conn, &mut poll, start, session)
            .expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_send() {
    init();

    const PATH: &'static str = "test-tls-send.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) =
            negotiate_one(&mut acceptor, &mut poll, start, session)
                .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn
            .start(poll.registry(), session)
            .expect("expected success")
        {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) =
            negotiate_one(&mut conn, &mut poll, start, session)
                .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_recv() {
    init();

    const PATH: &'static str = "test-tls-recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) =
            negotiate_one(&mut acceptor, &mut poll, start, session)
                .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn
            .start(poll.registry(), session)
            .expect("expected success")
        {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) =
            negotiate_one(&mut conn, &mut poll, start, session)
                .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}

#[test]
fn test_send_recv() {
    init();

    const PATH: &'static str = "test-tls-send-recv.sock";

    let client_conf: TLSNearConnectorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&client_conf(PATH)).unwrap();
    let server_conf: TLSNearAcceptorConfig<UnixNearChannelConfig> =
        serde_yaml::from_str(&server_conf(PATH)).unwrap();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor: TLSNearAcceptor<UnixNearAcceptor, TLSServerConfig> =
            TLSNearAcceptor::create(&mut server_nscaches, server_conf)
                .expect("Expected success");

        server_barrier.wait();

        poll.registry()
            .register(&mut acceptor, listen, Interest::READABLE)
            .expect("Expected success");

        let start = accept_one(&mut acceptor, &mut poll, listen, session)
            .expect("Expected success");

        let (mut stream, _) =
            negotiate_one(&mut acceptor, &mut poll, start, session)
                .expect("Expected success");

        let mut buf = [0; FIRST_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &SECOND_BYTES)
            .expect("Expected success");

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn: TLSNearConnector<UnixNearConnector, TLSClientConfig> =
            TLSNearConnector::create(&mut client_nscaches, client_conf)
                .expect("expected success");

        client_barrier.wait();

        let start = match conn
            .start(poll.registry(), session)
            .expect("expected success")
        {
            RetryResult::Success(start) => start,
            RetryResult::Retry(_) => panic!("shouldn't see retry")
        };

        let (mut stream, _) =
            negotiate_one(&mut conn, &mut poll, start, session)
                .expect("Expected success");

        write_one(&mut stream, &mut poll, session, &FIRST_BYTES)
            .expect("Expected success");

        let mut buf = [0; SECOND_BYTES.len()];

        read_one(&mut stream, &mut poll, session, &mut buf)
            .expect("Expected success");

        assert_eq!(SECOND_BYTES, buf);
    });

    listen.join().unwrap();
    send.join().unwrap();
}
