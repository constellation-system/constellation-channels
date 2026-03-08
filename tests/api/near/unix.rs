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
use std::fs::metadata;
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread::spawn;

use constellation_channels::config::UnixNearChannelConfig;
use constellation_channels::near::accept_one;
use constellation_channels::near::negotiate_one;
use constellation_channels::near::read_one;
use constellation_channels::near::write_one;
use constellation_channels::near::NearChannel;
use constellation_channels::near::NearChannelCreate;
use constellation_channels::near::NearChannelCreateWithEndpoint;
use constellation_channels::near::unix::UnixNearAcceptor;
use constellation_channels::near::unix::UnixNearConnector;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketAddr;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::init;

#[test]
fn test_send_recv() {
    init();

    const CONNECT_CONFIG: &'static str = concat!("");
    const ACCEPT_CONFIG: &'static str = concat!("path: test-send-recv.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONNECT_CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(ACCEPT_CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor =
            UnixNearAcceptor::create(&mut server_nscaches, accept_config)
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

        stream.shutdown(Shutdown::Both).unwrap();

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let endpoint = UnixSocketAddr::try_from(&path).expect("Expected success");
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn = UnixNearConnector::create_with_endpoint(
            &mut client_nscaches,
            connect_config,
            endpoint,
            ()
        )
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

    assert!(metadata(&path).is_err());
}

#[test]
fn test_send_close() {
    init();

    const CONFIG: &'static str = concat!("path: test-send-close.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor =
            UnixNearAcceptor::create(&mut server_nscaches, accept_config)
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
        stream.shutdown(Shutdown::Both).unwrap();

        server_barrier.wait();

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let endpoint = UnixSocketAddr::try_from(&path).expect("Expected success");
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn = UnixNearConnector::create_with_endpoint(
            &mut client_nscaches,
            connect_config,
            endpoint,
            ()
        )
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

        client_barrier.wait();

        let err = write_one(&mut stream, &mut poll, session, &SECOND_BYTES);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}

#[test]
fn test_recv_close() {
    init();

    const CONFIG: &'static str = concat!("path: test-recv-close.sock");
    const FIRST_BYTES: [u8; 8] =
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SECOND_BYTES: [u8; 8] =
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let connect_config = serde_yaml::from_str(CONFIG).unwrap();
    let accept_config: UnixNearChannelConfig =
        serde_yaml::from_str(CONFIG).unwrap();
    let path = accept_config.path().to_path_buf();
    let nscaches = SharedNSNameCaches::new();
    let barrier = Arc::new(Barrier::new(2));

    assert!(metadata(&path).is_err());

    let server_barrier = barrier.clone();
    let mut server_nscaches = nscaches.clone();
    let listen = spawn(move || {
        let listen = Token(0);
        let session = Token(1);
        let mut poll = Poll::new().expect("Expected success");
        let mut acceptor =
            UnixNearAcceptor::create(&mut server_nscaches, accept_config)
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
        stream.shutdown(Shutdown::Both).unwrap();

        server_barrier.wait();

        assert_eq!(FIRST_BYTES, buf);
    });

    let client_barrier = barrier.clone();
    let mut client_nscaches = nscaches.clone();
    let endpoint = UnixSocketAddr::try_from(&path).expect("Expected success");
    let send = spawn(move || {
        let session = Token(0);
        let mut poll = Poll::new().expect("Expected success");
        let mut conn = UnixNearConnector::create_with_endpoint(
            &mut client_nscaches,
            connect_config,
            endpoint,
            ()
        )
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

        client_barrier.wait();

        let mut buf = [0; SECOND_BYTES.len()];

        let err = read_one(&mut stream, &mut poll, session, &mut buf);

        assert!(err.is_err());
    });

    listen.join().unwrap();
    send.join().unwrap();

    assert!(metadata(&path).is_err());
}
