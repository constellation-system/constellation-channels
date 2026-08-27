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

use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundOutboundNegotiatorParam;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::FlowsConfig;
use constellation_channels::far::FarChannel;
use constellation_channels::far::FarChannelCreate;
use constellation_channels::far::FarChannelFlows;
use constellation_channels::far::compound::CompoundFarChannel;
use constellation_channels::far::compound::CompoundFarChannelAcquireState;
use constellation_channels::far::compound::CompoundFarChannelParam;
use constellation_channels::far::compound::CompoundFarChannelXfrm;
use constellation_channels::far::flows::accept_one;
use constellation_channels::far::flows::connect_one;
use constellation_channels::far::flows::read_one;
use constellation_channels::far::flows::write_one;
use constellation_channels::far::udp::UDPDatagramXfrm;
use constellation_channels::far::unix::UnixDatagramXfrm;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::net::DatagramXfrmCreate;
use constellation_common::retry::RetryResult;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use log::LevelFilter;
use mio::Interest;
use mio::Poll;
use mio::Token;
use serde::Deserialize;
use serde::Serialize;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[derive(Deserialize, Serialize)]
struct ClientEndpoint {
    endpoint: CompoundFarChannelXfrmPeerAddr,
    #[serde(default)]
    param: CompoundOutboundNegotiatorParam
}

struct ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens
}

impl<Ctx> NSNameCachesCtx for ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx
{
    type NameCaches = Ctx::NameCaches;

    #[inline]
    fn name_caches(&mut self) -> &mut Self::NameCaches {
        self.inner.name_caches()
    }
}

impl<Ctx> TokensCtx for ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx
{
    #[inline]
    fn token(&mut self) -> Token {
        self.tokens.token()
    }

    #[inline]
    fn free_token(
        &mut self,
        token: Token
    ) {
        self.tokens.free_token(token)
    }
}

fn server(conf: &str) {
    let mut poll = Poll::new().expect("Expected success");
    let server_config: CompoundFarChannelConfig =
        yaml_serde::from_str(conf).unwrap();
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new()
    };
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
        .register(&mut flows, token, Interest::READABLE | Interest::WRITABLE)
        .expect("Expected success");

    let (mut flow, peer_addr) = accept_one(&mut flows, &mut poll, &(), token)
        .expect("Expected success");

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

    assert_eq!(FIRST_BYTES.len(), nbytes);
    assert_eq!(FIRST_BYTES, buf);
}

fn client(
    conf: &str,
    endpoint: &str
) {
    let endpoint: ClientEndpoint = yaml_serde::from_str(endpoint).unwrap();
    let ClientEndpoint { endpoint: server_addr, param: negoparam } = endpoint;
    let client_config: CompoundFarChannelConfig =
        yaml_serde::from_str(conf).unwrap();
    let mut poll = Poll::new().expect("Expected success");
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new()
    };
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
    let mut flows = conn.flows(config, param, xfrm).expect("Expected success");
    let token = Token(0);

    poll.registry()
        .register(&mut flows, token, Interest::READABLE | Interest::WRITABLE)
        .expect("Expected success");

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
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [client <config> <endpoint>| server <config>]",
                  args[0]);
        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    let conf = std::fs::read_to_string(&args[2]).unwrap();

    match args[1].as_str() {
        "client" => if args.len() != 4 {
        } else {
            let endpoint = std::fs::read_to_string(&args[3]).unwrap();

            client(&conf, &endpoint)
        },
        "server" => server(&conf),
        _ => {
            eprintln!("Usage: {} [client | server]", args[0]);
            std::process::exit(1);
        }
    }
}
