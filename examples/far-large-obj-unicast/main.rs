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
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Instant;

use constellation_auth::authn::AuthNMsgRecv;
use constellation_auth::authn::AuthNedDestruct;
use constellation_auth::authn::AuthNTypes;
use constellation_auth::authn::BasicAuthNed;
use constellation_auth::authn::PassthruMsgAuthN;
use constellation_auth::authn::MsgAuthNTypes;
use constellation_auth::authn::basic::BasicAuthN;
use constellation_auth::config::BasicAuthNConfig;
use constellation_channels::config::CompoundFarChannelConfig;
use constellation_channels::config::CompoundFarChannelXfrmPeerAddr;
use constellation_channels::config::CompoundFarEndpoint;
use constellation_channels::config::CompoundOutboundNegotiatorParam;
use constellation_channels::config::CompoundXfrmCreateParam;
use constellation_channels::config::FarChannelsConfig;
use constellation_channels::config::ResolverConfig;
use constellation_channels::far::compound::CompoundFlow;
use constellation_channels::far::types::CompoundFarChannelsLargeObjSelectorPollTypes;
use constellation_channels::resolve::MixedResolver;
use constellation_channels::resolve::cache::NSNameCachesCtx;
use constellation_channels::resolve::cache::SharedNSNameCaches;
use constellation_common::codec::Encoder;
use constellation_common::codec::test::TestBytesCodec;
use constellation_common::codec::test::TestDecodeError;
use constellation_common::codec::test::TooShort;
use constellation_common::config::Create;
use constellation_common::error::ErrorScope;
use constellation_common::error::MutexPoison;
use constellation_common::error::ScopedError;
use constellation_common::hashid::SHA3ID;
use constellation_common::hashid::SHA3Algo;
use constellation_common::ids::AscendingCount;
use constellation_common::net::PassthruDatagramXfrm;
use constellation_common::net::PassthruDatagramXfrmParam;
use constellation_common::retry::Retry;
use constellation_common::sync::Notify;
use constellation_common::unix::UnixSocketPath;
use constellation_streams::codec::DatagramCodecStream;
use constellation_streams::config::LargeObjProtoConfig;
use constellation_streams::config::PartyConfig;
use constellation_streams::config::PollThreadConfig;
use constellation_streams::config::PrivateLargeObjModeConfig;
use constellation_streams::frags::Frags;
use constellation_streams::large_obj::LargeObjID;
use constellation_streams::large_obj::LargeObjMsg;
use constellation_streams::large_obj::LargeObjMsgCodec;
use constellation_streams::large_obj::LargeObjMsgs;
use constellation_streams::large_obj::LargeObjProto;
use constellation_streams::large_obj::LargeObjProtoAddOutboundError;
use constellation_streams::large_obj::LargeObjProtoTypes;
use constellation_streams::large_obj::LargeObjSender;
use constellation_streams::stream::RefCellStream;
use constellation_streams::threads::Tokens;
use constellation_streams::threads::TokensCtx;
use constellation_streams::threads::poll::MsgsWaker;
use constellation_streams::threads::poll::PollThread;
use log::LevelFilter;
use log::debug;
use log::info;
use mio::Token;
use mio::Waker;

const FIRST_BYTES: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
const SECOND_BYTES: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];

struct ExampleCtx<Ctx>
where
    Ctx: NSNameCachesCtx {
    inner: Ctx,
    tokens: Tokens,
}

struct ExampleClientMsgs {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
    nretries: usize,
    retry: Retry,
}

struct ExampleServerMsgs {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
    sent: bool
}

#[derive(Clone)]
struct ExampleClientRecv {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ExampleServerRecv {
    waker: Arc<Mutex<Option<Arc<Waker>>>>,
    live: Arc<AtomicBool>,
}

#[derive(Debug)]
enum LargeObjMsgsErr<Encode> {
    Add {
        err: LargeObjProtoAddOutboundError<Encode>
    },
    Finished
}

struct LargeObjServer;

struct LargeObjClient;

struct ExampleAuthN;


impl MsgsWaker for ExampleServerMsgs {
    type Error = MutexPoison;

    fn set_waker(
        &mut self,
        waker: Arc<Waker>
    ) -> Result<(), Self::Error> {
        let mut guard = self.waker.lock()
            .map_err(|_| MutexPoison)?;

        *guard = Some(waker);

        Ok(())
    }
}

impl MsgsWaker for ExampleClientMsgs {
    type Error = MutexPoison;

    fn set_waker(
        &mut self,
        waker: Arc<Waker>
    ) -> Result<(), Self::Error> {
        let mut guard = self.waker.lock()
            .map_err(|_| MutexPoison)?;

        *guard = Some(waker);

        Ok(())
    }
}

impl LargeObjMsgs<SHA3Algo, Vec<u8>> for ExampleClientMsgs {
    type AddMsgsError<Encode> = LargeObjMsgsErr<Encode>
    where
        Encode: Debug + Display + ScopedError;

    fn add_msgs<Enc, F>(
        &mut self,
        sender: &mut LargeObjSender<SHA3Algo, Vec<u8>, Enc, F>
    ) -> Result<Option<Instant>, Self::AddMsgsError<Enc::EncodeError>>
    where
        Enc: Clone + Create + Encoder<Vec<u8>>,
        Enc::Config: Default,
        F: Frags {
        if self.live.load(Ordering::Acquire) {
            let next = self.retry.retry_delay(self.nretries);
            let msg = FIRST_BYTES.to_vec();

            self.nretries += 1;

            info!(target: "client-msgs",
                  "sending {:?}", msg);

            sender.add_outbound(&msg)
                .map_err(|err| LargeObjMsgsErr::Add { err: err })?;

            Ok(Some(Instant::now() + next))
        } else {
            debug!(target: "client-msgs",
                  "msgs are finished");

            Err(LargeObjMsgsErr::Finished)
        }
    }
}

impl LargeObjMsgs<SHA3Algo, Vec<u8>> for ExampleServerMsgs {
    type AddMsgsError<Encode> = LargeObjMsgsErr<Encode>
    where
        Encode: Debug + Display + ScopedError;

    fn add_msgs<Enc, F>(
        &mut self,
        sender: &mut LargeObjSender<SHA3Algo, Vec<u8>, Enc, F>
    ) -> Result<Option<Instant>, Self::AddMsgsError<Enc::EncodeError>>
    where
        Enc: Clone + Create + Encoder<Vec<u8>>,
        Enc::Config: Default,
        F: Frags {
        if self.live.load(Ordering::Acquire) {
            if !self.sent {
                let msg = SECOND_BYTES.to_vec();

                self.sent = true;

                info!(target: "server-msgs",
                      "sending {:?}", msg);

                sender.add_outbound(&msg)
                    .map_err(|err| LargeObjMsgsErr::Add { err: err })?;

                Ok(Some(Instant::now()))
            } else {
                debug!(target: "server-msgs",
                      "msgs are finished");

                Err(LargeObjMsgsErr::Finished)
            }
        } else {
            debug!(target: "server-msgs",
                   "msgs are not started");

            Ok(None)
        }
    }
}

impl<AuthMsg> AuthNMsgRecv<String, AuthMsg> for ExampleClientRecv
where
    AuthMsg: AuthNedDestruct<String, Vec<u8>>
{
    type RecvError = Infallible;

    fn recv_auth_msg(
        &mut self,
        msg: AuthMsg
    ) -> Result<(), Self::RecvError> {
        let (prin, msg) = msg.take();

        info!(target: "client-recv",
              "received {:?} from {}", msg, prin);

        self.live.store(false, Ordering::Release);

        if let Ok(mut guard) = self.waker.lock() {
            if let Some(waker) = &mut *guard {
                if let Err(err) = waker.wake() {
                    panic!("error waking: {}", err)
                }
            } else {
                panic!("waker should not be None")
            }
        } else {
            panic!("lock failed")
        }

        assert_eq!(msg, &SECOND_BYTES[..]);

        Ok(())
    }
}

impl<AuthMsg> AuthNMsgRecv<String, AuthMsg> for ExampleServerRecv
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

        if let Ok(mut guard) = self.waker.lock() {
            if let Some(waker) = &mut *guard {
                if let Err(err) = waker.wake() {
                    panic!("error waking: {}", err)
                }
            } else {
                panic!("waker should not be None")
            }
        } else {
            panic!("lock failed")
        }

        assert_eq!(msg, &FIRST_BYTES[..]);

        Ok(())
    }
}

impl<Encode> ScopedError for LargeObjMsgsErr<Encode>
where Encode: ScopedError {
    #[inline]
    fn scope(&self) -> ErrorScope {
        match self {
            LargeObjMsgsErr::Add { err } => err.scope(),
            LargeObjMsgsErr::Finished => ErrorScope::Unrecoverable,
        }
    }
}

impl<Encode> Display for LargeObjMsgsErr<Encode>
where Encode: Display {
    fn fmt(
        &self,
        f: &mut Formatter<'_>
    ) -> Result<(), Error> {
        match self {
            LargeObjMsgsErr::Add { err } => err.fmt(f),
            LargeObjMsgsErr::Finished => write!(f, "finished")
        }
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

impl MsgAuthNTypes<Vec<u8>> for ExampleAuthN {
    type Wrapper = Vec<u8>;
    type Prin = String;
    type SessionPrin = String;
    type DecoderConfig = ();
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type AuthNError = Infallible;
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
}

impl AuthNTypes<
        CompoundFlow<
            PassthruDatagramXfrm<UnixSocketPath>,
            PassthruDatagramXfrm<SocketAddr>
        >,
        Vec<u8>
     > for ExampleAuthN {
    type MsgAuthNTypes = ExampleAuthN;
    type SessionAuthN = BasicAuthN<String>;
}

impl LargeObjProtoTypes<Vec<u8>, Vec<u8>> for LargeObjServer {
    type Prin = String;
    type SessionPrin = String;
    type IDsConfig = ();
    type IDs = AscendingCount<LargeObjID>;
    type HashID = SHA3ID;
    type Hash = SHA3Algo;
    type Wrapper = Vec<u8>;
    type DecoderConfig = ();
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type EncoderConfig = ();
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNError = Infallible;
    type Msgs = ExampleServerMsgs;
    type Recv = ExampleServerRecv;
    type AuthNTypes = ExampleAuthN;
}

impl LargeObjProtoTypes<Vec<u8>, Vec<u8>> for LargeObjClient {
    type Prin = String;
    type SessionPrin = String;
    type IDsConfig = ();
    type IDs = AscendingCount<LargeObjID>;
    type HashID = SHA3ID;
    type Hash = SHA3Algo;
    type Wrapper = Vec<u8>;
    type DecoderConfig = ();
    type DecodeError = TestDecodeError;
    type Decoder = TestBytesCodec;
    type EncoderConfig = ();
    type EncodeError = TooShort;
    type Encoder = TestBytesCodec;
    type MsgAuthN = PassthruMsgAuthN<Vec<u8>, String>;
    type AuthNMsg = BasicAuthNed<String, Vec<u8>>;
    type AuthNError = Infallible;
    type Msgs = ExampleClientMsgs;
    type Recv = ExampleClientRecv;
    type AuthNTypes = ExampleAuthN;
}

type ExampleServerPollTypes = CompoundFarChannelsLargeObjSelectorPollTypes<
    Vec<u8>,
    Vec<u8>,
    LargeObjMsg<SHA3ID>,
    PassthruMsgAuthN<LargeObjMsg<SHA3ID>, String>,
    BasicAuthNed<
        String,
        RefCellStream<
            DatagramCodecStream<
                LargeObjMsg<SHA3ID>,
                LargeObjMsg<SHA3ID>,
                CompoundFlow<
                    PassthruDatagramXfrm<UnixSocketPath>,
                    PassthruDatagramXfrm<SocketAddr>
                >,
                LargeObjMsgCodec<SHA3Algo>,
                LargeObjMsgCodec<SHA3Algo>,
            >
        >
    >,
    BasicAuthN<String>,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>,
    AscendingCount<u128>,
    MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>,
    LargeObjServer,
    ExampleCtx<SharedNSNameCaches>
>;

type ExampleClientPollTypes = CompoundFarChannelsLargeObjSelectorPollTypes<
    Vec<u8>,
    Vec<u8>,
    LargeObjMsg<SHA3ID>,
    PassthruMsgAuthN<LargeObjMsg<SHA3ID>, String>,
    BasicAuthNed<
        String,
        RefCellStream<
            DatagramCodecStream<
                LargeObjMsg<SHA3ID>,
                LargeObjMsg<SHA3ID>,
                CompoundFlow<
                    PassthruDatagramXfrm<UnixSocketPath>,
                    PassthruDatagramXfrm<SocketAddr>
                >,
                LargeObjMsgCodec<SHA3Algo>,
                LargeObjMsgCodec<SHA3Algo>,
            >
        >
    >,
    BasicAuthN<String>,
    PassthruDatagramXfrm<UnixSocketPath>,
    PassthruDatagramXfrm<SocketAddr>,
    AscendingCount<u128>,
    MixedResolver<CompoundFarChannelXfrmPeerAddr, CompoundFarEndpoint>,
    LargeObjClient,
    ExampleCtx<SharedNSNameCaches>
>;

fn server(conf: &str) {
    let poll_config: PollThreadConfig<
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
        PrivateLargeObjModeConfig,
        PartyConfig<
            ResolverConfig,
            (),
            String,
            CompoundOutboundNegotiatorParam,
            CompoundFarEndpoint
        >,
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let recv = ExampleServerRecv { waker: waker.clone(), live: live.clone() };
    let msgs = ExampleServerMsgs {
        waker: waker,
        live: live,
        sent: false
    };
    let ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
    };
    let self_party: Option<String> = None;
    let proto_config = LargeObjProtoConfig::default();
    let msgauth = PassthruMsgAuthN::default();
    let hash = SHA3Algo::default();
    let large_obj = LargeObjProto::create(proto_config, recv.clone(),
                                          msgs, msgauth, hash)
        .expect("Expected success");
    let large_obj = Arc::new(Mutex::new(large_obj));
    let poll: JoinHandle<()> = PollThread::<
        ExampleCtx<SharedNSNameCaches>,
        ExampleServerPollTypes
    >::start(
        poll_config, self_party, ctx, large_obj.clone(), large_obj
    )
    .unwrap();

    poll.join().unwrap();
}

fn client(conf: &str) {
    let poll_config: PollThreadConfig<
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
        PrivateLargeObjModeConfig,
        PartyConfig<
            ResolverConfig,
            (),
            String,
            CompoundOutboundNegotiatorParam,
            CompoundFarEndpoint
        >,
        ()
    > = yaml_serde::from_str(conf).unwrap();
    let live = Arc::new(AtomicBool::new(true));
    let waker = Arc::new(Mutex::new(None));
    let recv = ExampleClientRecv { waker: waker.clone(), live: live.clone() };
    let msgs = ExampleClientMsgs {
        live: live,
        waker: waker,
        retry: Retry::TERRESTRIAL_NETWORK_DEFAULT.clone(),
        nretries: 0
    };
    let ctx = ExampleCtx {
        inner: SharedNSNameCaches::new(),
        tokens: Tokens::new(),
    };
    let self_party: Option<String> = None;
    let proto_config = LargeObjProtoConfig::default();
    let msgauth = PassthruMsgAuthN::default();
    let hash = SHA3Algo::default();
    let large_obj = LargeObjProto::create(proto_config, recv.clone(),
                                          msgs, msgauth, hash)
        .expect("Expected success");
    let large_obj = Arc::new(Mutex::new(large_obj));
    let poll: JoinHandle<()> = PollThread::<
        ExampleCtx<SharedNSNameCaches>,
        ExampleClientPollTypes
    >::start(
        poll_config, self_party, ctx, large_obj.clone(), large_obj
    )
    .unwrap();

    poll.join().unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [client| server] <config>", args[0]);

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
