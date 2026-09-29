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
use constellation_auth::authn::AuthNedDestruct;
use constellation_auth::authn::BasicAuthNed;
use constellation_auth::authn::PassthruMsgAuthN;
use constellation_auth::authn::basic::BasicAuthN;
use constellation_auth::config::BasicAuthNConfig;
use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::FarChannelsConfig;
use constellation_channels::far::channels::FarChannels;
use constellation_channels::far::compound::CompoundFlow;
use constellation_channels::far::types::CompoundFarChannelsDatagramDispatchTypes;
use constellation_channels::far::types::CompoundFarChannelsTypes;
use constellation_channels::resolve::MixedResolver;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::codec::test::TestBytesCodec;
use constellation_common::config::CreateWithParam;
use constellation_common::error::ErrorScope;
use constellation_common::error::ScopedError;
use constellation_common::ids::AscendingCount;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_common::net::PrivateMsgs;
use constellation_common::shutdown::ShutdownFlag;
use constellation_common::sync::Notify;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::config::DispatchConfig;
use constellation_streams::config::DispatchThreadConfig;
use constellation_streams::config::PrivateDatagramModeConfig;
use constellation_streams::select::dispatch::DispatchSelector;
use constellation_streams::select::dispatch::DispatchSelectorCreateError;
use constellation_streams::stream::RefCellStream;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use constellation_streams::threads::dispatch::Dispatch;
use constellation_streams::threads::dispatch::DispatchThread;
use constellation_streams::threads::dispatch::DispatchThreadCtx;
use constellation_streams::threads::dispatch::Dispatched;
use log::LevelFilter;
use log::debug;
use log::info;
use mio::Token;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

struct ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens
}

struct ExampleMsgs {
    live: Arc<AtomicBool>,
    sent: bool
}

struct ExampleRecv {
    notify: Notify,
    live: Arc<AtomicBool>
}

struct ExampleDispatch;

#[derive(Debug)]
struct FinishedErr;

impl PrivateMsgs<Vec<u8>> for ExampleMsgs {
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

impl<AuthMsg> AuthNMsgRecv<String, AuthMsg> for ExampleRecv
where
    AuthMsg: AuthNedDestruct<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        let (prin, msg) = msg.take();

        info!(target: "server-recv",
              "received {:?} from {}", msg, prin);

        self.live.store(true, Ordering::Release);

        if let Err(err) = self.notify.notify() {
            panic!("error waking: {}", err)
        }

        assert_eq!(msg, &FIRST_BYTES[..]);

        Ok(())
    }
}

impl Dispatch<ExampleDispatchTypes, ExampleCtx<SharedNSNameCaches>>
    for ExampleDispatch
{
    type DispatchError = DispatchSelectorCreateError<Infallible>;

    fn dispatch(
        &mut self,
        ctx: &mut DispatchThreadCtx<
            FarChannels<
                CompoundFarChannelsTypes<
                    BasicAuthN<String>,
                    BasicAuthNed<
                        String,
                        RefCellStream<
                            DatagramCodecStream<
                                Vec<u8>,
                                Vec<u8>,
                                CompoundFlow<
                                    PassthruDatagramXfrm<UnixSocketPath>,
                                    PassthruDatagramXfrm<SocketAddr>
                                >,
                                TestBytesCodec,
                                TestBytesCodec
                            >
                        >
                    >,
                    PassthruDatagramXfrm<UnixSocketPath>,
                    PassthruDatagramXfrm<SocketAddr>,
                    Vec<u8>,
                    Vec<u8>,
                    TestBytesCodec,
                    TestBytesCodec
                >
            >,
            ExampleCtx<SharedNSNameCaches>
        >,
        _prin: &String,
        shutdown: ShutdownFlag,
        notify: Notify
    ) -> Result<
        Dispatched<ExampleDispatchTypes, ExampleCtx<SharedNSNameCaches>>,
        Self::DispatchError
    > {
        let live = Arc::new(AtomicBool::new(false));
        let recv = ExampleRecv {
            notify: notify.clone(),
            live: live.clone()
        };
        let msgs = ExampleMsgs {
            live: live,
            sent: false
        };
        let auth = PassthruMsgAuthN::default();
        let config = DispatchConfig::default();
        let stream = DispatchSelector::create(config, ctx)?;
        let dispatched = Dispatched::new(shutdown, stream, msgs, auth, recv);

        Ok(dispatched)
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

type ExampleDispatchTypes = CompoundFarChannelsDatagramDispatchTypes<
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    TestBytesCodec,
    TestBytesCodec,
    BasicAuthNed<
        String,
        RefCellStream<
            DatagramCodecStream<
                Vec<u8>,
                Vec<u8>,
                CompoundFlow<
                    PassthruDatagramXfrm<UnixSocketPath>,
                    PassthruDatagramXfrm<SocketAddr>
                >,
                TestBytesCodec,
                TestBytesCodec
            >
        >
    >,
    BasicAuthN<String>,
    PassthruMsgAuthN<Vec<u8>, String>,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>,
    AscendingCount<u128>,
    MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>,
    ExampleMsgs,
    ExampleRecv,
    ExampleCtx<SharedNSNameCaches>
>;

fn run(conf: &str) {
    let poll_config: DispatchThreadConfig<
        FarChannelsConfig<
            CompoundFarChannelConfig,
            BasicAuthNConfig<String>,
            CompoundXfrmCreateParam<
                PassthruDatagramXfrmParam,
                PassthruDatagramXfrmParam
            >,
            (),
            ()
        >,
        PrivateDatagramModeConfig
    > = yaml_serde::from_str(conf).unwrap();
    let ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new()
    };
    let poll: JoinHandle<()> = DispatchThread::<
        ExampleDispatchTypes,
        ExampleDispatch,
        ExampleCtx<SharedNSNameCaches>
    >::start(poll_config, ExampleDispatch, ctx)
    .unwrap();

    poll.join().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <config>", args[0]);

        std::process::exit(1);
    }

    env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .init();

    let conf = std::fs::read_to_string(&args[1]).unwrap();

    run(&conf)
}
