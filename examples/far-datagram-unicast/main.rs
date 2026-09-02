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

use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Instant;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::AuthNed;
use constellation_auth::authn::BasicAuthNed;
use constellation_auth::authn::basic::BasicAuthN;
use constellation_auth::authn::PassthruMsgAuthN;
use constellation_channels::config::FarChannelsConfig;
use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::ResolverConfig;
use constellation_channels::far::types::CompoundFarChannelsDatagramSelectorPollTypes;
use constellation_channels::resolve::MixedResolver;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::codec::test::TestBytesCodec;
use constellation_common::error::MutexPoison;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::ids::AscendingCount;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_common::net::PrivateMsgs;
use constellation_common::retry::Retry;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PollThreadConfig;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::threads::RegistryCtx;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use constellation_streams::threads::poll::PollThread;
use log::LevelFilter;
use log::debug;
use log::info;
use mio::Poll;
use mio::Registry;
use mio::Token;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

struct ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens,
    poll: Poll
}

struct ExampleClientMsgs {
    retry: Retry,
    nretries: usize,
    live: Arc<AtomicBool>
}

struct ExampleServerMsgs {
    live: Arc<AtomicBool>,
    sent: bool
}

struct ExampleClientRecv {
    live: Arc<AtomicBool>
}

struct ExampleServerRecv {
    live: Arc<AtomicBool>
}

#[derive(Debug)]
struct FinishedErr;

impl PrivateMsgs<Vec<u8>> for ExampleClientMsgs {
    type MsgsError = FinishedErr;

    fn msgs(
        &mut self,
        now: Instant
    ) -> Result<(Option<Vec<Vec<u8>>>, Option<Instant>), Self::MsgsError> {
        if self.live.load(Ordering::Acquire) {
            let next = self.retry.retry_delay(self.nretries);
            let msg = FIRST_BYTES.to_vec();

            self.nretries += 1;

            info!(target: "client-msgs",
                  "sending {:?}", msg);

            Ok((Some(vec![msg]), Some(now + next)))
        } else {
            debug!(target: "client-msgs",
                  "msgs are finished");

            Err(FinishedErr)
        }
    }
}

impl PrivateMsgs<Vec<u8>> for ExampleServerMsgs {
    type MsgsError = FinishedErr;

    fn msgs(
        &mut self,
        now: Instant
    ) -> Result<(Option<Vec<Vec<u8>>>, Option<Instant>), Self::MsgsError> {
        if self.live.load(Ordering::Acquire) {
            if !self.sent {
                let msg = SECOND_BYTES.to_vec();

                self.sent = true;

                info!(target: "server-msgs",
                      "sending {:?}", msg);

                Ok((Some(vec![msg]), Some(now)))
            } else {
                debug!(target: "server-msgs",
                      "msgs are finished");

                Err(FinishedErr)
            }
        } else {
            debug!(target: "server-msgs",
                   "msgs are not started");

            Ok((None, None))
        }
    }
}

impl<AuthMsg> AuthNMsgRecv<String, Vec<u8>, AuthMsg>
    for ExampleClientRecv
where
    AuthMsg: AuthNed<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        info!(target: "client-recv",
              "received {:?} from {}", msg.get(), msg.prin());

        self.live.store(false, Ordering::Release);

        assert_eq!(msg.get(), &FIRST_BYTES[..]);

        Ok(())
    }
}

impl<AuthMsg> AuthNMsgRecv<String, Vec<u8>, AuthMsg>
    for ExampleServerRecv
where
    AuthMsg: AuthNed<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        info!(target: "server-recv",
              "received {:?} from {}", msg.get(), msg.prin());

        self.live.store(true, Ordering::Release);

        assert_eq!(msg.get(), &FIRST_BYTES[..]);

        Ok(())
    }
}

impl ScopedError for FinishedErr {
    #[inline]
    fn scope(&self) -> ErrorScope {
        ErrorScope::Shutdown
    }
}

impl Display for FinishedErr {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        write!(f, "finished")
    }
}

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

type ExampleServerPollTypes = CompoundFarChannelsDatagramSelectorPollTypes<
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    BasicAuthN<String>,
    PassthruMsgAuthN<Vec<u8>, String>,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>,
    AscendingCount<u128>,
    MixedResolver<CompoundFarChannelXfrmPeerAddr,
                  CompoundFarEndpoint>,
    ExampleServerMsgs,
    ExampleServerRecv,
    ExampleCtx<SharedNSNameCaches>
>;

type ExampleClientPollTypes = CompoundFarChannelsDatagramSelectorPollTypes<
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    BasicAuthN<String>,
    PassthruMsgAuthN<Vec<u8>, String>,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>,
    AscendingCount<u128>,
    MixedResolver<CompoundFarChannelXfrmPeerAddr,
                  CompoundFarEndpoint>,
    ExampleClientMsgs,
    ExampleClientRecv,
    ExampleCtx<SharedNSNameCaches>
>;

fn server(conf: &str) {
    let poll_config: PollThreadConfig<
        FarChannelsConfig<
            CompoundFarChannelConfig, (),
            CompoundXfrmCreateParam<PassthruDatagramXfrmParam,
                                    PassthruDatagramXfrmParam>
        >,
        PrivateDatagramModeConfig,
        PartyConfig<ResolverConfig, (), String, CompoundFarEndpoint>,
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(false));
    let recv = ExampleServerRecv {
        live: live.clone()
    };
    let msgs = ExampleServerMsgs {
        live: live,
        sent: false
    };
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
        poll: Poll::new().expect("Expected success")
    };
    let self_party: Option<String> = None;
    let poll: JoinHandle<()> =
        PollThread::<ExampleCtx<SharedNSNameCaches>,
                     ExampleServerPollTypes>::start(
            poll_config, self_party, ctx, recv, msgs
        ).unwrap();

    poll.join().unwrap();
}

fn client(conf: &str) {
    let poll_config: PollThreadConfig<
        FarChannelsConfig<
            CompoundFarChannelConfig, (),
            CompoundXfrmCreateParam<PassthruDatagramXfrmParam,
                                    PassthruDatagramXfrmParam>
        >,
        PrivateDatagramModeConfig,
        PartyConfig<ResolverConfig, (), String, CompoundFarEndpoint>,
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(true));
    let recv = ExampleServerRecv {
        live: live.clone()
    };
    let msgs = ExampleClientMsgs {
        live: live,
        retry: Retry::default(),
        nretries: 0
    };
    let mut ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
        poll: Poll::new().expect("Expected success")
    };
    let self_party: Option<String> = None;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [client| server] <config>",
                  args[0]);

        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    let conf = std::fs::read_to_string(&args[2]).unwrap();

    match args[1].as_str() {
        "client" => client(&conf),
        "server" => server(&conf),
        _ => {
            eprintln!("Usage: {} [client | server]", args[0]);
            std::process::exit(1);
        }
    }
}
