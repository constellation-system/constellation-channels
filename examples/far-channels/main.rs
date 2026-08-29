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

use std::collections::HashSet;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Instant;

use constellation_auth::authn::AuthNed;
use constellation_auth::authn::BasicAuthNed;
use constellation_auth::authn::TrivialAuthN;
use constellation_auth::cred::NullCred;
use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundOutboundNegotiatorParam;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::FarChannelsConfig;
use constellation_channels::far::types::CompoundFarChannelsTypes;
use constellation_channels::far::channels::FarChannels;
use constellation_channels::far::channels::FarChannelID;
use constellation_channels::far::compound::CompoundFlow;
use constellation_channels::far::compound::CompoundFarChannelParam;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_common::retry::RetryResult;
use constellation_common::retry::RetryWhen;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::channels::Channels;
use constellation_streams::channels::ChannelsID;
use constellation_streams::channels::ChannelsListen;
use constellation_streams::threads::RegistryCtx;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use log::LevelFilter;
use log::info;
use log::trace;
use mio::Events;
use mio::Poll;
use mio::Registry;
use mio::Token;
use serde::Deserialize;
use serde::Serialize;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

#[derive(Deserialize, Serialize)]
struct ClientEndpoint {
    addr: CompoundFarChannelXfrmPeerAddr,
    channel: String,
    #[serde(default)]
    param: CompoundOutboundNegotiatorParam
}

struct ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens,
    poll: Poll
}

type ExampleFarChannelsTypes = CompoundFarChannelsTypes<
    TrivialAuthN<
        NullCred,
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >
    >,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>
>;

impl<Ctx> RegistryCtx for ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx
{
    #[inline]
    fn registry(&self) -> &Registry {
        self.poll.registry()
    }
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

fn read<R>(
    ctx: &mut ExampleCtx<SharedNSNameCaches>,
    events: &mut Events,
    channels: &mut FarChannels<ExampleFarChannelsTypes>,
    stream: &mut BasicAuthNed<NullCred, R>,
    buf: &mut [u8],
    addr: CompoundFarChannelXfrmPeerAddr,
    channel_id: FarChannelID,
    channel_param: CompoundFarChannelParam
) -> usize
where R: Read
{
    let mut nbytes = 0;

    while {
        trace!(target: "read",
               "attempting to read");

        match stream.get_mut().read(buf) {
            Ok(n) => {
                nbytes = n;

                false
            }
            Err(err) => if err.scope() != ErrorScope::WouldBlock {
                panic!("{}", err)
            } else {
                // Obtain the incoming session
                while {
                    let mut ready = false;

                    trace!(target: "read",
                           "poll wait");

                    ctx.poll.poll(events, None).unwrap();

                    let live: HashSet<Token> =
                        events.iter().map(|event| event.token()).collect();

                    match channels.listen(ctx, &live).unwrap() {
                        RetryResult::Success((streams, endpoints, _, _)) => {
                            for _ in streams {
                                panic!("Should not see incoming sessions")
                            }

                            for (in_addr, in_chan_id, in_param) in endpoints {
                                if addr == in_addr &&
                                    channel_param == in_param &&
                                    channel_id == in_chan_id {
                                    ready = true;
                                } else {
                                    panic!("Unexpected messages")
                                }
                            }
                        }
                        RetryResult::Retry(retry) => {
                            let when = retry.when();
                            let now = Instant::now();

                            if now < when {
                                std::thread::sleep(when - now)
                            }
                        }
                    }

                    !ready
                } {}

                true
            }
        }
    } {}

    nbytes
}

fn server(conf: &str) {
    let server_config: FarChannelsConfig<
        CompoundFarChannelConfig, (),
        CompoundXfrmCreateParam<PassthruDatagramXfrmParam,
                                PassthruDatagramXfrmParam>
    > = yaml_serde::from_str(conf).unwrap();
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
        poll: Poll::new().expect("Expected success")
    };
    let mut events = Events::with_capacity(2);
    let mut channels: FarChannels<ExampleFarChannelsTypes> =
        FarChannels::create(server_config, &mut ctx).unwrap();
    let mut session = None;

    info!(target: "server",
          "listening");

    // Obtain the incoming session
    while session.is_none() {
        trace!(target: "server",
               "poll wait");

        ctx.poll.poll(&mut events, None).unwrap();

        let live: HashSet<Token> =
            events.iter().map(|event| event.token()).collect();

        match channels.listen(&mut ctx, &live).unwrap() {
            RetryResult::Success((streams, _, _, _)) => {
                for info in streams {
                    assert!(session.is_none());

                    session = Some(info);
                }
            }
            RetryResult::Retry(retry) => {
                let when = retry.when();
                let now = Instant::now();

                if now < when {
                    std::thread::sleep(when - now)
                }
            }
        }
    }

    info!(target: "server",
          "reading message");

    let (addr, channel_id, channel_param, mut stream) = session.unwrap();
    let mut buf = [0; FIRST_BYTES.len()];

    let nbytes = read(&mut ctx, &mut events, &mut channels, &mut stream,
                      &mut buf, addr, channel_id, channel_param);

    info!(target: "server",
          "received {:?}", buf);

    info!(target: "server",
          "sending message {:?}", &SECOND_BYTES);

    stream.get_mut().write(&SECOND_BYTES)
        .expect("Expected success");

    assert_eq!(FIRST_BYTES.len(), nbytes);
    assert_eq!(FIRST_BYTES, buf);
}

fn client(
    conf: &str,
    endpoint: &str
) {
    let endpoint: ClientEndpoint = yaml_serde::from_str(endpoint).unwrap();
    let ClientEndpoint { channel, addr, param: negoparam } = endpoint;
    let client_config: FarChannelsConfig<
        CompoundFarChannelConfig, (),
        CompoundXfrmCreateParam<PassthruDatagramXfrmParam,
                                PassthruDatagramXfrmParam>
    > = yaml_serde::from_str(conf).unwrap();
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
        poll: Poll::new().expect("Expected success")
    };
    let mut events = Events::with_capacity(2);
    let mut channels: FarChannels<ExampleFarChannelsTypes> =
        FarChannels::create(client_config, &mut ctx).unwrap();
    let channel_id = channels.channel_id(&channel).unwrap();
    let mut session = None;
    let mut channel_param = None;

    for (id, params) in channels
        .params(&mut ctx, [channel_id.clone()].into_iter())
        .unwrap() {
        assert_eq!(id, channel_id);

        let params = if let RetryResult::Success((params, _)) = params {
            params
        } else {
            panic!("Expected success")
        };

        for param in params {
            assert!(channel_param.is_none());

            channel_param = Some(param)
        }
    }

    let channel_param = channel_param.unwrap();

    info!(target: "client",
          "requesting stream");

    while session.is_none() {
        match channels.req_stream(&mut ctx, &channel_id, &channel_param,
                                  &addr, &negoparam).unwrap() {
            RetryResult::Success((newsession, _, _)) => {
                session = newsession;
            }
            RetryResult::Retry(retry) => {
                let when = retry.when();
                let now = Instant::now();

                if now < when {
                    std::thread::sleep(when - now)
                }
            }
        }
    }

    let mut stream = session.unwrap();

    info!(target: "client",
          "sending message {:?}", FIRST_BYTES);

    stream.get_mut().write(&FIRST_BYTES)
        .expect("Expected success");

    info!(target: "client",
          "reading message");

    let mut buf = [0; SECOND_BYTES.len()];

    let nbytes = read(&mut ctx, &mut events, &mut channels, &mut stream,
                      &mut buf, addr, channel_id, channel_param);

    info!(target: "server",
          "received {:?}", buf);

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
