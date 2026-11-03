//! L2: 실제 relay 라우터를 in-process 로 올리고 relay-client 둘·셋으로 두드린다 (U5, #57).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lodelai_crypto::DeviceKeys;
use lodelai_effects::{Clock, IdGen, UnixMillis};
use lodelai_protocol::states::SenderViewState;
use lodelai_relay::{bind_local, db::Db, serve, Config as RelayConfig, Effects, Relay};
use lodelai_relay_client::register::{register_device, DeviceInfo, Registered};
use lodelai_relay_client::{Config, Inbound, Outgoing, RelayClient};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::sync::mpsc::Receiver;

const TOKEN: &str = "reg-token";
const SERVER: &str = "local";
const START_MS: i64 = 1_792_728_776_000;

struct Harness {
    addr: SocketAddr,
    fx: TestEffects,
    /// relay 를 직접 움직이는 시험(조직 빠짐 — 묶음 16 §3a ④)용.
    _app: lodelai_relay::App,
    _dir: tempfile::TempDir,
}

async fn relay() -> Harness {
    relay_with(|_| {}).await
}

async fn relay_with(tweak: impl FnOnce(&mut RelayConfig)) -> Harness {
    relay_full(tweak, None).await
}

async fn relay_full(
    tweak: impl FnOnce(&mut RelayConfig),
    mailer: Option<Arc<dyn lodelai_relay::mail::Mailer>>,
) -> Harness {
    let fx = TestEffects::new(START_MS, 3);
    let dir = tempfile::tempdir().unwrap();
    let (listener, addr) = bind_local(0).await.unwrap();
    let mut config = RelayConfig::local(SERVER);
    config.blob_dir = Some(dir.path().join("relay-blobs"));
    config.blob_min_free = 0;
    // 그룹 시험은 플래그를 켠 relay 로(묶음 16 §3b — 기본은 꺼짐).
    config.groups = true;
    tweak(&mut config);
    config.port = addr.port();
    config.registration_token = Some(TOKEN.into());
    let effects = Effects {
        clock: fx.clock.clone(),
        ids: fx.ids.clone(),
        rng: fx.rng.clone(),
    };
    // 파일 DB — 그룹 시험이 relay 표를 직접 바꿔(서버가 멤버를 끼워 넣음) 클라이언트 검증을 본다.
    let app = Relay::with_mailer(
        config,
        effects,
        Db::open(&dir.path().join("relay.db")).unwrap(),
        mailer,
    );
    tokio::spawn(serve(app.clone(), listener));
    Harness {
        addr,
        fx,
        _app: app,
        _dir: dir,
    }
}

impl Harness {
    fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/v1/ws", self.addr.port())
    }

    async fn user(&self, name: &str, seed: u8) -> DeviceKeys {
        let keys = DeviceKeys::generate(&[seed; 64]);
        let r = register_device(self.addr, TOKEN, &DeviceInfo::of(name, Some(name), &keys))
            .await
            .unwrap();
        assert!(matches!(r, Registered::Created { .. }));
        // 두 번째 등록은 이미 있음(성공으로 본다)
        let r = register_device(self.addr, TOKEN, &DeviceInfo::of(name, Some(name), &keys))
            .await
            .unwrap();
        assert!(matches!(r, Registered::AlreadyRegistered { .. }));
        keys
    }

    fn config(&self, url: &str, user: &str, keys: &DeviceKeys) -> Config {
        let mut c = Config::new(
            url,
            SERVER,
            user,
            keys.clone(),
            zeroize::Zeroizing::new([7; 32]),
        );
        c.send_interval = Duration::from_millis(5);
        c.backoff_max = Duration::from_millis(200);
        c.unknown_device_wait = Duration::from_millis(800);
        // 그룹 시험은 켠 설정으로(묶음 16 §3b — 기본은 꺼짐).
        c.groups = true;
        c.key_package_target = 4;
        // 사진 PUT 이 부하로 한 번 일시 실패해도 시험 대기(15초) 안에 다시 올린다(#530 — 실제 5초~30초).
        c.avatar_retry_first = Duration::from_millis(100);
        c.avatar_retry_max = Duration::from_millis(400);
        c
    }

    fn start(&self, user: &str, keys: &DeviceKeys, db: &str) -> (RelayClient, Receiver<Inbound>) {
        self.start_at(&self.ws_url(), user, keys, db)
    }

    fn start_at(
        &self,
        url: &str,
        user: &str,
        keys: &DeviceKeys,
        db: &str,
    ) -> (RelayClient, Receiver<Inbound>) {
        self.start_with(self.config(url, user, keys), db)
    }

    fn start_with(&self, config: Config, db: &str) -> (RelayClient, Receiver<Inbound>) {
        let clock: Arc<dyn Clock> = self.fx.clock.clone();
        RelayClient::start(
            config,
            &self._dir.path().join(db),
            clock,
            self.fx.rng.clone(),
        )
        .unwrap()
    }

    /// core 가 만드는 서명 전 메시지.
    fn message(&self, from: &str, kind: &str, to: &str, extra: Value, text: &str) -> Value {
        let id = self.fx.ids.next_ulid();
        let now = self.fx.clock.now();
        let author = if from.contains('/') { "agent" } else { "human" };
        let mut from_obj =
            json!({"address": from, "author": author, "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"});
        if author == "agent" {
            from_obj["session_id"] = json!("cee3f37e-0000-0000-0000-000000000000");
        }
        let mut m = json!({
            "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": id, "thread_id": id, "kind": kind, "from": from_obj, "to": {"address": to},
            "body": {"enc": "plain", "text": text},
            "created_at": now.to_rfc3339().unwrap(),
            "expires_at": UnixMillis(now.0 + 86_400_000).to_rfc3339().unwrap(),
        });
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        m
    }
}

/// 디렉터리를 받기 전에(오프라인 등) 상대 기기를 이미 신뢰한 것처럼 심는다 — 봉투로 감쌀 대상이 있어야 큐에 들어간다.
fn plant(c: &RelayClient, user: &str, k: &DeviceKeys) {
    c.store()
        .add_peer(&lodelai_relay_client::Peer {
            device_id: k.device_id().as_str().to_owned(),
            user: user.to_owned(),
            ed25519: k.signing.verifying_key().to_b64(),
            x25519: lodelai_crypto::encoding::encode(&k.exchange.public_key()),
            trust: lodelai_relay_client::Trust::Trusted,
            first_contact: true,
        })
        .unwrap();
}

/// 조건에 맞는 다음 Inbound 를 기다린다(그 사이 것은 버린다). 시험이 나란히 돌면 1:1 MLS 준비(KeyPackage·start·Commit)가
/// 5초를 넘을 때가 있다(#519). 다른 세션의 빌드와 겹친 전체 검사에서는 15초도 넘어 거짓 실패가 났다(#536) — 조건 대기라
/// 통과 속도엔 상관없으니 [`WAIT`]. 시간 초과면 그 사이 받은 것을 찍는다(멈춤과 느림을 가르게).
async fn wait(rx: &mut Receiver<Inbound>, what: &str, f: impl Fn(&Inbound) -> bool) -> Inbound {
    let t0 = std::time::Instant::now();
    let mut seen = Vec::new();
    tokio::time::timeout(WAIT, async {
        loop {
            let i = rx.recv().await.expect("채널 닫힘");
            if f(&i) {
                return i;
            }
            seen.push(format!("{:?} {:.120?}", t0.elapsed(), i));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} 를 기다리다 시간 초과 — 그 사이 받은 것: {seen:#?}"))
}

/// [`wait`] 의 상한(#536).
const WAIT: Duration = Duration::from_secs(60);

async fn ready(rx: &mut Receiver<Inbound>) {
    wait(rx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    wait(rx, "directory", |i| matches!(i, Inbound::Directory(_))).await;
}

fn id(m: &Value) -> String {
    m["msg_id"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_round_trip_with_core_ack_and_received_status() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    let m = h.message(
        "alice@local",
        "chat",
        "bob@local",
        json!({}),
        "점심? 🍜\n두 번째 줄",
    );
    alice
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    let ack = wait(&mut arx, "ack", |i| matches!(i, Inbound::Ack { .. })).await;
    assert!(matches!(ack, Inbound::Ack { msg_id } if msg_id == id(&m)));

    let Inbound::Deliver { message, ack } = wait(&mut brx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(message["body"]["text"], "점심? 🍜\n두 번째 줄");
    assert_eq!(
        message["from"]["device_id"],
        ak.device_id().as_str(),
        "relay-client 가 자기 기기로 채워 서명"
    );
    // core 가 저장했다고 가정하고 ack → 발신자에게 received
    ack.ack();
    let st = wait(&mut arx, "status", |i| matches!(i, Inbound::Status { .. })).await;
    assert!(matches!(st, Inbound::Status { state, .. } if state == "received"));
    // 큐가 비었다
    assert!(alice.store().is_empty().unwrap());
    assert!(alice.directory()["people"].is_array(), "디렉터리 캐시");
}

#[tokio::test(flavor = "multi_thread")]
async fn same_msg_id_statuses_all_go_out_in_order_and_reply_passes_reply_to_check() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    bob.enqueue(&Outgoing::Publish {
        slug: "be".into(),
        grade: "task".into(),
        liveness: "live:pty".into(),
        display: None,
        // 세션 이름(m1-spec §2) — relay 가 검사해 directory 에 그대로 싣는다
        title: Some("인사 테스트".into()),
        folder: Some("api".into()),
        // 처리 중(A15) — relay 가 저장해 directory 세션 항목에 busy 로 싣는다
        busy: true,
        audience: None,
        project: None,
        agent: None,
        no: None,
    })
    .unwrap();
    let d = wait(&mut arx, "directory.update", |i| matches!(i, Inbound::Directory(d) if d["sessions"].as_array().is_some_and(|s| !s.is_empty()))).await;
    if let Inbound::Directory(d) = &d {
        assert_eq!(d["sessions"][0]["title"], "인사 테스트");
        assert_eq!(d["sessions"][0]["folder"], "api");
        assert_eq!(d["sessions"][0]["busy"], true);
    }

    let req = h.message(
        "alice@local/fe",
        "request",
        "bob@local/be",
        json!({"grade": "question"}),
        "질문",
    );
    alice
        .enqueue(&Outgoing::Send {
            message: req.clone(),
        })
        .unwrap();
    wait(&mut arx, "ack", |i| matches!(i, Inbound::Ack { .. })).await;
    let Inbound::Deliver { ack, .. } = wait(&mut brx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    ack.ack();
    let rid = id(&req);
    wait(
        &mut arx,
        "received",
        |i| matches!(i, Inbound::Status { msg_id, state, .. } if state == "received" && *msg_id == rid),
    )
    .await;

    for st in [
        SenderViewState::Accepted,
        SenderViewState::Consumed,
        SenderViewState::Replied,
    ] {
        bob.enqueue(&Outgoing::SenderStatus {
            msg_id: id(&req),
            state: st,
            abort_reason: None,
            fail_reason: None,
        })
        .unwrap();
    }
    let mut got = Vec::new();
    while got.len() < 3 {
        if let Inbound::Status { state, .. } = wait(
            &mut arx,
            "status",
            |i| matches!(i, Inbound::Status { msg_id, .. } if *msg_id == rid),
        )
        .await
        {
            got.push(state);
        }
    }
    assert_eq!(got, ["accepted", "consumed", "replied"]);

    // 회신: alice 는 req 를 보냈으므로(sent 기록) reply_to 검사 통과. 머리 `need`(묶음 26 §5)가 MLS 1:1(22 — relay 는 1:1
    // box 를 늘 거절하므로 이 길은 MLS 다)로 서명째 건너가 받는 쪽이 서명을 통과시킨다(22 merge 조건).
    let reply = h.message(
        "bob@local/be",
        "reply",
        "alice@local/fe",
        json!({"reply_to": id(&req), "thread_id": id(&req), "need": "task"}),
        "답",
    );
    bob.enqueue(&Outgoing::Send { message: reply }).unwrap();
    let d = wait(&mut arx, "reply deliver", |i| {
        matches!(i, Inbound::Deliver { .. } | Inbound::Rejected { .. })
    })
    .await;
    assert!(
        matches!(&d, Inbound::Deliver { message, .. } if message["kind"] == "reply" && message["need"] == "task"),
        "{d:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nack_and_format_error_are_removed_from_queue() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    // 디렉터리에 없는 사람 — 잎으로 넣을 기기가 없어 보내기 전에 unroutable(묶음 22: relay 의 unroutable 과 같은 실패).
    let m = h.message("alice@local", "chat", "nobody@local", json!({}), "x");
    alice
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    let n = wait(&mut arx, "nack", |i| matches!(i, Inbound::Nack { .. })).await;
    assert!(
        matches!(n, Inbound::Nack { msg_id, reason } if msg_id == id(&m) && reason == "unroutable")
    );

    // 스키마 위반(비정규 시각) → relay 가 ref=msg_id 로 알려 주고 클라이언트는 nack 처리(큐가 막히지 않는다)
    let mut bad = h.message("alice@local", "chat", "bob@local", json!({}), "x");
    bad["created_at"] = json!("2026-10-23T04:12:56Z");
    alice
        .enqueue(&Outgoing::Send {
            message: bad.clone(),
        })
        .unwrap();
    let ok = h.message("alice@local", "chat", "bob@local", json!({}), "다음 것");
    alice
        .enqueue(&Outgoing::Send {
            message: ok.clone(),
        })
        .unwrap();
    let n = wait(&mut arx, "format nack", |i| {
        matches!(i, Inbound::Nack { .. })
    })
    .await;
    assert!(
        matches!(n, Inbound::Nack { msg_id, reason } if msg_id == id(&bad) && reason == "protocol")
    );
    let a = wait(&mut arx, "next ack", |i| matches!(i, Inbound::Ack { .. })).await;
    assert!(
        matches!(a, Inbound::Ack { msg_id } if msg_id == id(&ok)),
        "뒤의 메시지가 막히지 않는다"
    );
    assert!(alice.store().is_empty().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn queue_survives_restart_and_is_delivered_once() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    // 닿지 않는 주소로 띄워 큐에만 쌓는다
    let (offline, _orx) = h.start_at("ws://127.0.0.1:1/v1/ws", "alice", &ak, "a.db");
    plant(&offline, "bob", &bk);
    let m = h.message("alice@local", "chat", "bob@local", json!({}), "재기동 뒤");
    offline
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    offline
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    assert_eq!(offline.store().len().unwrap(), 1);
    offline.shutdown().await;

    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut brx).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    wait(&mut arx, "ack", |i| matches!(i, Inbound::Ack { .. })).await;
    let Inbound::Deliver { message, ack } = wait(&mut brx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(id(&message), id(&m));
    ack.ack();
    assert!(alice.store().is_empty().unwrap());
    // 한 번만
    let extra = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Some(Inbound::Deliver { .. }) = brx.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(extra.is_err(), "같은 메시지가 두 번 오지 않는다");
}

#[tokio::test(flavor = "multi_thread")]
async fn unacked_delivery_comes_back_after_reconnect() {
    // core 가 저장 전에 죽은 경우: ack 핸들을 버리면 다음 접속 때 다시 온다(유실 없음).
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let m = h.message("alice@local", "chat", "bob@local", json!({}), "x");
    alice
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    let Inbound::Deliver { ack, .. } = wait(&mut brx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    drop(ack);
    bob.shutdown().await;
    drop(brx);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_bob2, mut brx2) = h.start("bob", &bk, "b.db");
    let Inbound::Deliver { message, .. } = wait(&mut brx2, "redeliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(id(&message), id(&m));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_device_triggers_directory_refresh() {
    // bob 이 접속한 뒤 carol 이 등록 → bob 의 디렉터리에 carol 이 없다 → deliver 에서 새로고침 후 검증
    let h = relay().await;
    let bk = h.user("bob", 2).await;
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut brx).await;
    let ck = h.user("carol", 3).await;
    let (carol, mut crx) = h.start("carol", &ck, "c.db");
    ready(&mut crx).await;
    let m = h.message(
        "carol@local",
        "chat",
        "bob@local",
        json!({}),
        "처음 뵙겠습니다",
    );
    carol
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    let d = wait(&mut brx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. } | Inbound::Rejected { .. })
    })
    .await;
    assert!(matches!(d, Inbound::Deliver { message, .. } if id(&message) == id(&m)));
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_server_ping_so_connection_stays_up() {
    // 서버는 100ms 마다 ping, 350ms 말이 없으면 끊는다. 클라이언트 자기 ping 은 30초라 pong 만이 연결을 살린다.
    let h = relay_with(|c| {
        c.ping_interval = Duration::from_millis(100);
        c.idle_timeout = Duration::from_millis(350);
    })
    .await;
    let ak = h.user("alice", 1).await;
    let (_a, mut arx) = h.start("alice", &ak, "a.db");
    ready(&mut arx).await;
    let dropped = tokio::time::timeout(Duration::from_millis(1500), async {
        loop {
            if matches!(arx.recv().await, Some(Inbound::Disconnected) | None) {
                return;
            }
        }
    })
    .await;
    assert!(dropped.is_err(), "pong 을 보냈는데 끊겼다");
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_when_server_goes_silent() {
    // 서버 ping 이 끊긴 것(idle_timeout)으로 — 내 ping 의 답 기한은 길게.
    reconnect_after_silence(Duration::from_secs(60), Duration::from_millis(300)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_when_my_ping_gets_no_answer() {
    // 멈춘 relay: 내 ping 뒤 pong_timeout 안에 아무것도 안 온다 — idle_timeout(길게)을 기다리지 않는다.
    reconnect_after_silence(Duration::from_millis(200), Duration::from_secs(60)).await;
}

async fn reconnect_after_silence(pong_timeout: Duration, idle_timeout: Duration) {
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_tungstenite::tungstenite::Message;

    // 핸드셰이크까지만 답하고 그 뒤로는 읽기만 하는 서버(조용히 죽은 relay 흉내).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let _hello = ws.next().await;
                let challenge =
                    json!({"t": "challenge", "nonce": lodelai_crypto::encoding::encode(&[0u8; 32])})
                        .to_string();
                ws.send(Message::Text(challenge.into())).await.unwrap();
                let _auth = ws.next().await;
                let ready = json!({"t": "ready", "server": SERVER, "now": "2026-10-23T04:12:56Z", "pending": 0});
                ws.send(Message::Text(ready.to_string().into()))
                    .await
                    .unwrap();
                while let Some(Ok(_)) = ws.next().await {}
            });
        }
    });

    let h = relay().await;
    let ak = DeviceKeys::generate(&[1; 64]);
    let mut config = h.config(&format!("ws://127.0.0.1:{port}/v1/ws"), "alice", &ak);
    config.ping_interval = Duration::from_millis(100);
    config.idle_timeout = idle_timeout;
    config.pong_timeout = pong_timeout;
    let (_a, mut arx) = h.start_with(config, "a.db");
    wait(&mut arx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    wait(&mut arx, "끊김", |i| matches!(i, Inbound::Disconnected)).await;
    wait(&mut arx, "다시 ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    assert!(accepted.load(Ordering::SeqCst) >= 2);
}

/// #537: 첫 연결은 `send` 를 받고도 답하지 않거나(`swallow`) ref 달린 internal 로 답하는 relay — 클라이언트는 행을 빼지 않고
/// 끊은 뒤 다시 접속해 **같은 msg_id** 를 다시 보낸다. 두 번째 연결은 ack.
async fn resend_same_msg_id_after(first: &'static str) {
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let sent: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let (count, got) = (accepted.clone(), sent.clone());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            let got = got.clone();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let _hello = ws.next().await;
                let challenge =
                    json!({"t": "challenge", "nonce": lodelai_crypto::encoding::encode(&[0u8; 32])})
                        .to_string();
                ws.send(Message::Text(challenge.into())).await.unwrap();
                let _auth = ws.next().await;
                let ready = json!({"t": "ready", "server": SERVER, "now": "2026-10-23T04:12:56Z", "pending": 0});
                ws.send(Message::Text(ready.to_string().into()))
                    .await
                    .unwrap();
                while let Some(Ok(Message::Text(t))) = ws.next().await {
                    let f: Value = serde_json::from_str(&t).unwrap();
                    // 살아 있는 relay — ping 에는 답한다(끊김은 send 상한 때문이어야 한다).
                    if f["t"] == "ping" {
                        let _ = ws
                            .send(Message::Text(json!({"t": "pong"}).to_string().into()))
                            .await;
                        continue;
                    }
                    if f["t"] != "send" {
                        continue;
                    }
                    let id = f["message"]["msg_id"].as_str().unwrap().to_owned();
                    got.lock().unwrap().push(id.clone());
                    let reply = match (n, first) {
                        (1, "swallow") => continue,
                        (1, _) => {
                            json!({"t": "error", "code": "internal", "message": "internal", "ref": id})
                        }
                        _ => json!({"t": "ack", "msg_id": id}),
                    };
                    let _ = ws.send(Message::Text(reply.to_string().into())).await;
                }
            });
        }
    });

    let h = relay().await;
    let ak = DeviceKeys::generate(&[1; 64]);
    let mut config = h.config(&format!("ws://127.0.0.1:{port}/v1/ws"), "alice", &ak);
    config.send_ack_wait = Duration::from_millis(300);
    let (alice, mut arx) = h.start_with(config, "a.db");
    wait(&mut arx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    let m = h.message("alice@local", "system", "bob@local", json!({}), "");
    alice
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    wait(
        &mut arx,
        "다시 보낸 뒤 ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == id(&m)),
    )
    .await;
    let got = sent.lock().unwrap().clone();
    assert!(got.len() >= 2, "{got:?}");
    assert!(
        got.iter().all(|g| *g == id(&m)),
        "같은 msg_id 그대로: {got:?}"
    );
    assert!(accepted.load(Ordering::SeqCst) >= 2);
    assert!(alice.store().is_empty().unwrap(), "ack 뒤 큐에서 빠짐");
}

#[tokio::test(flavor = "multi_thread")]
async fn unanswered_send_reconnects_and_resends_same_msg_id() {
    resend_same_msg_id_after("swallow").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn internal_error_with_ref_keeps_row_and_resends() {
    resend_same_msg_id_after("internal").await;
}

// ------------------------------------------------------------------ 기기 폐기 (#325)

#[tokio::test(flavor = "multi_thread")]
async fn revoke_goes_after_queued_frames_and_stops_reconnecting() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (_alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    // 로그아웃처럼: 큐에 넣고 곧바로 폐기. 폐기가 먼저 나가면 이 chat 은 모르는 기기라 auth nack 이 된다.
    let m = h.message("bob@local", "chat", "alice@local", json!({}), "마지막 인사");
    bob.enqueue(&Outgoing::Send { message: m.clone() }).unwrap();
    bob.enqueue(&Outgoing::Unpublish {
        slug: "backend".into(),
    })
    .unwrap();
    bob.revoke_device(Duration::from_secs(5)).await.unwrap();
    assert!(bob.store().is_empty().unwrap(), "큐가 다 나간 뒤에 폐기");

    let Inbound::Deliver { message, .. } = wait(&mut arx, "deliver", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(message["msg_id"], id(&m));
    // 동료 디렉터리에서 bob 의 기기가 빠진다.
    wait(&mut arx, "bob 기기 없는 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["people"].as_array().is_some_and(|p| p.iter().any(|x| x["address"] == "bob@local" && x["devices"] == json!([]))))
    })
    .await;

    // 폐기 뒤 연결 루프는 끝난다 — 다시 접속(Ready)하지 않고 채널이 닫힌다.
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(i) = brx.recv().await {
            assert!(!matches!(i, Inbound::Ready { .. }), "폐기 뒤 재접속");
        }
    })
    .await;
    assert!(closed.is_ok(), "연결 루프가 끝나지 않음");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_while_offline_is_unreachable() {
    let h = relay().await;
    let bk = h.user("bob", 2).await;
    // 아무도 듣지 않는 주소.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://127.0.0.1:{}/v1/ws", dead.local_addr().unwrap().port());
    drop(dead);
    let (bob, _brx) = h.start_at(&url, "bob", &bk, "b.db");
    let r = bob.revoke_device(Duration::from_millis(300)).await;
    assert!(
        matches!(r, Err(lodelai_relay_client::Error::Unreachable)),
        "{r:?}"
    );
}

/// 계정 흐름 11-02 폐기 대기: 클라이언트 없이 그 키로 한 번 붙어 자기 폐기 — 동료 디렉터리에서 빠지고, 다시 부르면 이미 끊김이라
/// 성공, 닿지 않는 주소는 Unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_with_key_revokes_once_and_is_idempotent() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (_alice, mut arx) = h.start("alice", &ak, "a.db");
    ready(&mut arx).await;
    let wait_s = Duration::from_secs(5);
    lodelai_relay_client::conn::revoke_with_key(
        &h.ws_url(),
        SERVER,
        "bob",
        &bk,
        h.fx.clock.now(),
        wait_s,
    )
    .await
    .unwrap();
    wait(&mut arx, "bob 기기 없는 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["people"].as_array().is_some_and(|p| p.iter().any(|x| x["address"] == "bob@local" && x["devices"] == json!([]))))
    })
    .await;
    lodelai_relay_client::conn::revoke_with_key(
        &h.ws_url(),
        SERVER,
        "bob",
        &bk,
        h.fx.clock.now(),
        wait_s,
    )
    .await
    .unwrap();
    // 서버가 모르는 기기(등록 안 된 키) — 다시 해도 같은 영구 거절이라 UnknownDevice(앱은 줄을 지운다).
    let stranger = DeviceKeys::generate(&[9; 64]);
    let r = lodelai_relay_client::conn::revoke_with_key(
        &h.ws_url(),
        SERVER,
        "carol",
        &stranger,
        h.fx.clock.now(),
        wait_s,
    )
    .await;
    assert!(
        matches!(r, Err(lodelai_relay_client::Error::UnknownDevice)),
        "{r:?}"
    );
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://127.0.0.1:{}/v1/ws", dead.local_addr().unwrap().port());
    drop(dead);
    let r = lodelai_relay_client::conn::revoke_with_key(
        &url,
        SERVER,
        "alice",
        &ak,
        h.fx.clock.now(),
        Duration::from_millis(500),
    )
    .await;
    assert!(
        matches!(r, Err(lodelai_relay_client::Error::Unreachable)),
        "{r:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn discard_unsent_drops_only_sends_and_returns_ids_in_order() {
    let h = relay().await;
    let bk = h.user("bob", 2).await;
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://127.0.0.1:{}/v1/ws", dead.local_addr().unwrap().port());
    drop(dead);
    let (bob, _brx) = h.start_at(&url, "bob", &bk, "b.db");
    plant(&bob, "alice", &DeviceKeys::generate(&[31; 64]));
    let m1 = h.message("bob@local", "chat", "alice@local", json!({}), "하나");
    let m2 = h.message("bob@local", "chat", "alice@local", json!({}), "둘");
    bob.enqueue(&Outgoing::Send {
        message: m1.clone(),
    })
    .unwrap();
    bob.enqueue(&Outgoing::Unpublish {
        slug: "backend".into(),
    })
    .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: m2.clone(),
    })
    .unwrap();
    assert_eq!(bob.unsent_count().unwrap(), 2);
    assert_eq!(bob.discard_unsent().unwrap(), vec![id(&m1), id(&m2)]);
    assert_eq!(bob.unsent_count().unwrap(), 0);
    assert_eq!(bob.store().len().unwrap(), 1, "unpublish 는 남는다");
    assert!(bob.discard_unsent().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn connected_users_and_wipe_relay_helpers() {
    use lodelai_relay_client::register::{connected_users, wipe_relay};
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let _bk = h.user("bob", 2).await;
    let (_alice, mut arx) = h.start("alice", &ak, "a.db");
    ready(&mut arx).await;
    assert_eq!(
        connected_users(h.addr, TOKEN).await.unwrap(),
        vec!["alice".to_owned()]
    );
    assert!(connected_users(h.addr, "wrong").await.is_err());
    assert!(wipe_relay(h.addr, "wrong").await.is_err());

    wipe_relay(h.addr, TOKEN).await.unwrap();
    wait(&mut arx, "끊김", |i| matches!(i, Inbound::Disconnected)).await;
}

// ------------------------------------------------------------------ E2E 봉투(#313 ③, e2e-envelope §10 L2)

// ------------------------------------------------------------------ hosted 기기 추가·내 기기 알림·대상 지정 폐기 (#339)

#[derive(Default)]
struct CaptureMailer(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl lodelai_relay::mail::Mailer for CaptureMailer {
    fn send_code(&self, email: &str, code: &str, _locale: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(email.into(), code.into());
        Ok(())
    }

    fn send_text(&self, _email: &str, _subject: &str, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

/// 이메일 코드만으로 기기 등록(가입 또는 추가).
async fn email_device(
    h: &Harness,
    mail: &CaptureMailer,
    email: &str,
    user: Option<&str>,
    seed: u8,
) -> (DeviceKeys, lodelai_relay_client::register::HostedRegistered) {
    use lodelai_relay_client::register::{register_device_hosted, signup_start, signup_verify};
    let url = h.ws_url();
    signup_start(&url, email, Some("ko"), "test").await.unwrap();
    let code = mail.0.lock().unwrap()[email].clone();
    assert!(matches!(
        signup_verify(&url, email, "999999x").await,
        Err(lodelai_relay_client::Error::InvalidCode)
    ));
    let token = signup_verify(&url, email, &code)
        .await
        .unwrap()
        .signup_token;
    let keys = DeviceKeys::generate(&[seed; 64]);
    // 새 계정은 조직이 있어야 한다(#355) — 기존 계정이면 relay 가 무시한다.
    let org = lodelai_relay_client::register::HostedOrg::Create {
        name: "루이보스".into(),
        setup_code: String::new(),
    };
    let reg = register_device_hosted(
        &url,
        &token,
        &DeviceInfo::of(user.unwrap_or("ignored"), None, &keys),
        user,
        user.map(|_| &org),
        &[],
    )
    .await
    .unwrap();
    (keys, reg)
}

#[tokio::test(flavor = "multi_thread")]
async fn email_added_device_shows_up_pending_on_my_other_device() {
    let mail = Arc::new(CaptureMailer::default());
    let h = relay_full(|_| {}, Some(mail.clone())).await;
    let (home_k, reg) = email_device(&h, &mail, "dana@x.io", Some("dana"), 1).await;
    assert_eq!((reg.user.as_str(), reg.added), ("dana", false));
    let (home, mut hrx) = h.start("dana", &home_k, "home.db");
    ready(&mut hrx).await;
    // 이 기기 자신은 trusted, 알리지 않는다.
    let me = home
        .store()
        .peer(home_k.device_id().as_str())
        .unwrap()
        .unwrap();
    assert_eq!(me.trust, lodelai_relay_client::Trust::Trusted);

    // 회사 맥: 코드만으로 같은 계정에 추가(아이디는 서버가 정한다).
    h.fx.clock.advance(1000);
    let (work_k, reg) = email_device(&h, &mail, "dana@x.io", None, 2).await;
    assert_eq!((reg.user.as_str(), reg.added), ("dana", true));
    let work_id = work_k.device_id().as_str().to_owned();

    // 집 맥: 내 새 기기 = pending(“새 기기 추가됨” 카드 근거).
    let Inbound::DeviceTrust(p) = wait(
        &mut hrx,
        "내 새 기기",
        |i| matches!(i, Inbound::DeviceTrust(p) if p.device_id == work_id),
    )
    .await
    else {
        unreachable!()
    };
    assert_eq!(
        (p.user.as_str(), p.trust),
        ("dana", lodelai_relay_client::Trust::Pending)
    );

    // 회사 맥: 첫 디렉터리의 집 맥 = 뿌리(trusted).
    let (work, mut wrx) = h.start("dana", &work_k, "work.db");
    ready(&mut wrx).await;
    assert_eq!(
        work.store()
            .peer(home_k.device_id().as_str())
            .unwrap()
            .unwrap()
            .trust,
        lodelai_relay_client::Trust::Trusted
    );

    // 나중 기기(회사, pending) → 먼저 기기(집): relay 가 protocol 로 거절(#577 — 메일 확인 끊기로만, too_early 아님).
    let r = work
        .revoke_other_device(home_k.device_id().as_str(), Duration::from_secs(3))
        .await;
    assert!(
        matches!(r, Err(lodelai_relay_client::Error::UnknownDevice)),
        "{r:?}"
    );
    // 이 기기 자신·모르는 기기는 relay 에 묻지 않고 거른다.
    assert!(matches!(
        work.revoke_other_device(&work_id, Duration::from_secs(1))
            .await,
        Err(lodelai_relay_client::Error::ThisDevice)
    ));
    assert!(matches!(
        work.revoke_other_device("k1_AAAAAAAAAAAAAAAAAAAAAA", Duration::from_secs(1))
            .await,
        Err(lodelai_relay_client::Error::UnknownDevice)
    ));

    // 먼저 기기(집) → 나중 기기(회사): 바로. 집은 연결 유지, 회사 연결은 닫히고 집 디렉터리에서 revoked.
    home.revoke_other_device(&work_id, Duration::from_secs(3))
        .await
        .unwrap();
    wait(&mut hrx, "회사 맥 revoked", |i| {
        matches!(i, Inbound::DeviceTrust(p) if p.device_id == work_id && p.trust == lodelai_relay_client::Trust::Revoked)
    })
    .await;
    wait(&mut wrx, "회사 맥 끊김", |i| {
        matches!(i, Inbound::Disconnected)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_device_revokes_older_after_24h() {
    let mail = Arc::new(CaptureMailer::default());
    let h = relay_full(|_| {}, Some(mail.clone())).await;
    let (old_k, _) = email_device(&h, &mail, "dana@x.io", Some("dana"), 1).await;
    h.fx.clock.advance(1000);
    let (new_k, _) = email_device(&h, &mail, "dana@x.io", None, 2).await;
    let (_old, mut orx) = h.start("dana", &old_k, "old.db");
    let (new, mut nrx) = h.start("dana", &new_k, "new.db");
    ready(&mut orx).await;
    ready(&mut nrx).await;
    h.fx.clock.advance(24 * 60 * 60 * 1000);
    new.revoke_other_device(old_k.device_id().as_str(), Duration::from_secs(3))
        .await
        .unwrap();
    wait(&mut orx, "먼저 기기 끊김", |i| {
        matches!(i, Inbound::Disconnected)
    })
    .await;
    // 다시 붙으면 자기 키로 맞게 서명했으니 device_revoked → 알리고 다시 접속하지 않는다(채널이 닫힌다).
    wait(&mut orx, "계정에서 끊김", |i| {
        matches!(i, Inbound::RemovedFromAccount { .. })
    })
    .await;
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(i) = orx.recv().await {
            assert!(!matches!(i, Inbound::Ready { .. }), "끊긴 뒤 재접속");
        }
    })
    .await;
    assert!(closed.is_ok(), "연결 루프가 끝나지 않음");
}

#[tokio::test(flavor = "multi_thread")]
async fn planted_own_device_does_not_come_back_pending() {
    // M1 주인 앱이 연결 코드로 자기 다른 기기를 승인 — 등록 전에 심어 두면 directory.update 에서 pending 이 되지 않는다.
    let h = relay().await;
    let ak = h.user("dana", 1).await;
    let (owner, mut orx) = h.start("dana", &ak, "o.db");
    ready(&mut orx).await;
    let k2 = DeviceKeys::generate(&[2; 64]);
    let info = DeviceInfo::of("dana", None, &k2);
    assert!(owner.plant_own_device(&info).unwrap());
    assert!(
        !owner.plant_own_device(&info).unwrap(),
        "이미 있으면 그대로"
    );
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &info, true)
        .await
        .unwrap();
    wait(
        &mut orx,
        "디렉터리",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&info.device_id)),
    )
    .await;
    assert_eq!(
        owner.store().peer(&info.device_id).unwrap().unwrap().trust,
        lodelai_relay_client::Trust::Trusted
    );
    // 남의 아이디는 심지 않는다.
    let other = DeviceInfo::of("bob", None, &DeviceKeys::generate(&[3; 64]));
    assert!(matches!(
        owner.plant_own_device(&other),
        Err(lodelai_relay_client::Error::UnknownDevice)
    ));
    // 등록하지 못한 기기는 지운다.
    let k4 = DeviceInfo::of("dana", None, &DeviceKeys::generate(&[4; 64]));
    owner.plant_own_device(&k4).unwrap();
    owner.forget_planted_device(&k4.device_id).unwrap();
    assert!(owner.store().peer(&k4.device_id).unwrap().is_none());
}

// ------------------------------------------------------------------ 조직 관리자·초대·팀 (#355)

#[tokio::test(flavor = "multi_thread")]
async fn org_admin_invite_and_team_choice_through_client() {
    use lodelai_relay_client::register::{
        register_device_hosted, signup_start, signup_verify, HostedOrg,
    };
    use lodelai_relay_client::OrgAdmin;
    let mail = Arc::new(CaptureMailer::default());
    let h = relay_full(|_| {}, Some(mail.clone())).await;
    let (boss_k, _) = email_device(&h, &mail, "boss@x.io", Some("boss"), 1).await;
    let (boss, mut brx) = h.start("boss", &boss_k, "boss.db");
    ready(&mut brx).await;
    let t = Duration::from_secs(3);
    boss.org_admin(OrgAdmin::CreateTeam("web".into()), t)
        .await
        .unwrap();
    // 같은 이름은 NameTaken — 연결은 그대로.
    assert!(matches!(
        boss.org_admin(OrgAdmin::CreateTeam("web".into()), t).await,
        Err(lodelai_relay_client::Error::NameTaken)
    ));
    let dir = wait(&mut brx, "팀이 있는 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["teams"].as_array().is_some_and(|ts| !ts.is_empty()))
    })
    .await;
    let Inbound::Directory(d) = dir else {
        unreachable!()
    };
    let web = d["teams"][0]["id"].as_str().unwrap().to_owned();
    let (token, expires_at) = boss.create_invite(t).await.unwrap();
    assert_eq!(token.len(), 43);
    assert!(!expires_at.is_empty());

    // 초대로 가입하며 팀을 고른다(M1 초대는 이메일에 묶지 않는다, 묶음 5). 모르는 초대 코드는 InvalidInvite.
    let join = |email: &'static str, seed: u8, token: String| {
        let (h, mail, web) = (&h, mail.clone(), web.clone());
        async move {
            let url = h.ws_url();
            signup_start(&url, email, None, "test").await.unwrap();
            let code = mail.0.lock().unwrap()[email].clone();
            let st = signup_verify(&url, email, &code)
                .await
                .unwrap()
                .signup_token;
            let keys = DeviceKeys::generate(&[seed; 64]);
            let user = email.split('@').next().unwrap();
            let r = register_device_hosted(
                &url,
                &st,
                &DeviceInfo::of(user, None, &keys),
                Some(user),
                Some(&HostedOrg::Invite(token)),
                &[web],
            )
            .await;
            (r, keys)
        }
    };
    assert!(matches!(
        join("eve@x.io", 2, "x".repeat(43)).await.0,
        Err(lodelai_relay_client::Error::InvalidInvite)
    ));
    let (r, minji_k) = join("minji@x.io", 3, token).await;
    assert!(!r.unwrap().added);

    // 멤버의 관리자 동작은 거절, 팀 바꾸기는 큐(profile.teams)로.
    let (minji, mut mrx) = h.start("minji", &minji_k, "minji.db");
    ready(&mut mrx).await;
    assert!(matches!(
        minji.create_invite(t).await,
        Err(lodelai_relay_client::Error::Refused)
    ));
    minji
        .enqueue(&Outgoing::ProfileUpdate {
            display_name: Some("민지".into()),
            teams: Some(vec![]),
        })
        .unwrap();
    wait(&mut brx, "민지 팀 없음·이름 바뀜", |i| {
        matches!(i, Inbound::Directory(d) if d["people"].as_array().is_some_and(|ps| ps.iter().any(|p| p["address"] == "minji@local" && p["display"] == "민지" && p["teams"] == json!([]))))
    })
    .await;
}

/// 원격 relay(묶음 5)를 in-process 로: 등록 토큰 없음, 처리방침 판, 가짜 메일, 조직 만들기 코드를 미리 낸다.
async fn remote_relay() -> (Harness, Arc<CaptureMailer>, String) {
    remote_relay_with(|_| {}).await
}

async fn remote_relay_with(
    tweak: impl FnOnce(&mut RelayConfig),
) -> (Harness, Arc<CaptureMailer>, String) {
    let fx = TestEffects::new(START_MS, 3);
    let (listener, addr) = bind_local(0).await.unwrap();
    let mut config = RelayConfig::local("lodelai-api.example");
    config.port = addr.port();
    config.remote = true;
    config.public_host = Some("lodelai-api.example".into());
    config.privacy_version = Some("2026-10-25".into());
    tweak(&mut config);
    let db = Db::memory().unwrap();
    // 원격 relay 는 이메일 HMAC 키 없이 뜨지 않는다(main) — 조직 만들기 이메일 셈(묶음 18)이 쓴다.
    db.set_email_key(b"test-email-hmac-key-0123456789abcdef".to_vec());
    let code = lodelai_relay::http::bootstrap_setup_code(&db, fx.rng.as_ref(), START_MS).unwrap();
    let effects = Effects {
        clock: fx.clock.clone(),
        ids: fx.ids.clone(),
        rng: fx.rng.clone(),
    };
    let mail = Arc::new(CaptureMailer::default());
    let app = Relay::with_mailer(config, effects, db, Some(mail.clone()));
    tokio::spawn(serve(app.clone(), listener));
    (
        Harness {
            addr,
            fx,
            _app: app,
            _dir: tempfile::tempdir().unwrap(),
        },
        mail,
        code,
    )
}

/// 묶음 29 §1-4: 처리방침 응답의 운영자 url — 있으면 그대로, 없으면 없음(앱이 hosted 기본).
#[tokio::test(flavor = "multi_thread")]
async fn privacy_carries_operator_url_when_set() {
    use lodelai_relay_client::register::{privacy, Privacy};
    let (h, _, _) = remote_relay().await;
    assert_eq!(
        privacy(&h.ws_url()).await.unwrap(),
        Privacy {
            version: "2026-10-25".into(),
            url: None
        }
    );
    let (h, _, _) =
        remote_relay_with(|c| c.privacy_url = Some("https://corp.example/p".into())).await;
    assert_eq!(
        privacy(&h.ws_url()).await.unwrap().url.as_deref(),
        Some("https://corp.example/p")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_signup_creates_org_then_invite_and_my_other_mac() {
    use lodelai_relay_client::register::{
        invites_check, privacy_version, register_device_hosted, signup_start, signup_verify,
        HostedOrg,
    };
    use lodelai_relay_client::Error;
    let (h, mail, setup) = remote_relay().await;
    let url = h.ws_url();
    let t = Duration::from_secs(3);
    let pv = privacy_version(&url).await.unwrap();
    assert_eq!(pv, "2026-10-25");
    // 옛 판은 메일 전에 막힌다.
    assert!(matches!(
        signup_start(&url, "boss@x.io", Some("ko"), "2020-01-01").await,
        Err(Error::PrivacyRequired)
    ));
    assert!(matches!(
        signup_start(&url, "nobody", None, &pv).await,
        Err(Error::InvalidEmail)
    ));
    let verified = |email: &'static str| {
        let (url, mail, pv) = (url.clone(), mail.clone(), pv.clone());
        async move {
            signup_start(&url, email, Some("ko"), &pv).await.unwrap();
            let code = mail.0.lock().unwrap()[email].clone();
            signup_verify(&url, email, &code).await.unwrap()
        }
    };

    // 첫 관리자: 조직 만들기 코드로 새 조직. 대소문자·`-` 는 가리지 않는다.
    let v = verified("boss@x.io").await;
    assert!(v.existing.is_none());
    let boss_k = DeviceKeys::generate(&[1; 64]);
    let wrong = HostedOrg::Create {
        name: "루이보스".into(),
        setup_code: "0000-0000-0000-0000".into(),
    };
    assert!(matches!(
        register_device_hosted(
            &url,
            &v.signup_token,
            &DeviceInfo::of("boss", Some("보스"), &boss_k),
            Some("boss"),
            Some(&wrong),
            &[],
        )
        .await,
        Err(Error::InvalidInvite)
    ));
    let create = HostedOrg::Create {
        name: "루이보스".into(),
        setup_code: setup.to_lowercase().replace('-', ""),
    };
    let reg = register_device_hosted(
        &url,
        &v.signup_token,
        &DeviceInfo::of("boss", Some("보스"), &boss_k),
        Some("boss"),
        Some(&create),
        &[],
    )
    .await
    .unwrap();
    assert_eq!((reg.user.as_str(), reg.added), ("boss", false));
    let remote = |user: &str, keys: &DeviceKeys, db: &str| {
        let mut c = Config::new(
            &url,
            "lodelai-api.example",
            user,
            keys.clone(),
            zeroize::Zeroizing::new([7; 32]),
        );
        c.send_interval = Duration::from_millis(5);
        h.start_with(c, db)
    };
    let (boss, mut brx) = remote("boss", &boss_k, "boss.sqlite3");
    let r = wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(matches!(r, Inbound::Ready { admin: true, .. }), "{r:?}");

    // 동료: 관리자의 초대 코드 → 확인(토큰을 쓰지 않음) → 가입. 관리자가 아니다.
    let (invite, _) = boss.create_invite(t).await.unwrap();
    let v = verified("minji@x.io").await;
    assert!(matches!(
        invites_check(&url, &v.signup_token, &"x".repeat(43)).await,
        Err(Error::InvalidInvite)
    ));
    let info = invites_check(&url, &v.signup_token, &invite).await.unwrap();
    assert_eq!(info.org_name, "루이보스");
    assert_eq!(
        (
            info.inviter.user.as_str(),
            info.inviter.display_name.as_str()
        ),
        ("boss", "보스")
    );
    let minji_k = DeviceKeys::generate(&[2; 64]);
    register_device_hosted(
        &url,
        &v.signup_token,
        &DeviceInfo::of("minji", None, &minji_k),
        Some("minji"),
        Some(&HostedOrg::Invite(invite)),
        &[],
    )
    .await
    .unwrap();
    let (minji, mut mrx) = remote("minji", &minji_k, "minji.sqlite3");
    let r = wait(&mut mrx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(matches!(r, Inbound::Ready { admin: false, .. }), "{r:?}");

    // 내 다른 맥: 같은 이메일 → existing → 조직 없이 그 계정에 기기 추가.
    let v = verified("boss@x.io").await;
    let acct = v.existing.clone().unwrap();
    assert_eq!(
        (acct.user.as_str(), acct.display_name.as_str()),
        ("boss", "보스")
    );
    let other_k = DeviceKeys::generate(&[3; 64]);
    let reg = register_device_hosted(
        &url,
        &v.signup_token,
        &DeviceInfo::of("boss", None, &other_k),
        None,
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!((reg.user.as_str(), reg.added), ("boss", true));

    // #389 같은 기기로 다시 가입(서버 A→B→A): 그 계정의 기기면 200 added:false = 성공, 남의 기기면 DeviceTaken
    // 이고 가입 토큰은 남아 다른 기기로 이어 갈 수 있다.
    let v = verified("boss@x.io").await;
    let reg = register_device_hosted(
        &url,
        &v.signup_token,
        &DeviceInfo::of("boss", None, &other_k),
        None,
        None,
        &[],
    )
    .await
    .unwrap();
    assert_eq!((reg.user.as_str(), reg.added), ("boss", false));
    let (invite, _) = boss.create_invite(t).await.unwrap();
    let v = verified("ara@x.io").await;
    assert!(matches!(
        register_device_hosted(
            &url,
            &v.signup_token,
            &DeviceInfo::of("ara", None, &minji_k),
            Some("ara"),
            Some(&HostedOrg::Invite(invite.clone())),
            &[],
        )
        .await,
        Err(Error::DeviceTaken)
    ));
    let ara_k = DeviceKeys::generate(&[4; 64]);
    let reg = register_device_hosted(
        &url,
        &v.signup_token,
        &DeviceInfo::of("ara", None, &ara_k),
        Some("ara"),
        Some(&HostedOrg::Invite(invite)),
        &[],
    )
    .await
    .unwrap();
    assert_eq!(reg.user, "ara");
    minji.shutdown().await;
    boss.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn local_relay_ready_has_no_admin() {
    let h = relay().await;
    let k = h.user("solo", 9).await;
    let (c, mut rx) = h.start("solo", &k, "solo.sqlite3");
    let r = wait(&mut rx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(matches!(r, Inbound::Ready { admin: false, .. }));
    c.shutdown().await;
}

// ------------------------------------------------------------------ 묶음 14

async fn deliver(rx: &mut Receiver<Inbound>) -> Value {
    let Inbound::Deliver { message, ack } =
        wait(rx, "deliver", |i| matches!(i, Inbound::Deliver { .. })).await
    else {
        unreachable!()
    };
    ack.ack();
    message
}

/// 고치기(edits)·인용(reply_to)은 헤더 그대로 서명돼 가고, 거두기(system withdrawn, 빈 평문)는 X 를 보낸 쪽에서 받는 쪽으로
/// 재검증을 통과해 넘어간다. 확인함은 보낸 사람에게 status acknowledged, 숨기기는 디렉터리 online 을 지운다.
#[tokio::test(flavor = "multi_thread")]
async fn bundle14_edit_quote_withdraw_acknowledge_and_presence() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    let x = h.message("alice@local", "chat", "bob@local", json!({}), "오타 잇음");
    alice
        .enqueue(&Outgoing::Send { message: x.clone() })
        .unwrap();
    assert_eq!(deliver(&mut brx).await["msg_id"], x["msg_id"]);

    let e = h.message(
        "alice@local",
        "chat",
        "bob@local",
        json!({"edits": id(&x)}),
        "오타 있음",
    );
    alice
        .enqueue(&Outgoing::Send { message: e.clone() })
        .unwrap();
    let got = deliver(&mut brx).await;
    assert_eq!(got["edits"], x["msg_id"]);
    assert_eq!(got["body"]["text"], "오타 있음");

    let q = h.message(
        "bob@local",
        "chat",
        "alice@local",
        json!({"reply_to": id(&x)}),
        "괜찮아",
    );
    bob.enqueue(&Outgoing::Send { message: q }).unwrap();
    assert_eq!(deliver(&mut arx).await["reply_to"], x["msg_id"]);

    bob.enqueue(&Outgoing::ChatAcknowledged { msg_id: id(&e) })
        .unwrap();
    let st = wait(
        &mut arx,
        "acknowledged",
        |i| matches!(i, Inbound::Status { state, .. } if state == "acknowledged"),
    )
    .await;
    assert!(matches!(st, Inbound::Status { msg_id, .. } if msg_id == id(&e)));

    let w = h.message(
        "alice@local",
        "system",
        "bob@local",
        json!({"reply_to": id(&x), "reason": "withdrawn"}),
        "",
    );
    alice.enqueue(&Outgoing::Send { message: w }).unwrap();
    let got = deliver(&mut brx).await;
    assert_eq!(
        (got["reason"].as_str(), got["reply_to"].as_str()),
        (Some("withdrawn"), x["msg_id"].as_str())
    );

    let online = |d: &Value, who: &str| {
        d["people"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["address"] == who)
            .and_then(|p| p.get("online").cloned())
    };
    bob.enqueue(&Outgoing::PresenceSet { share: false })
        .unwrap();
    wait(
        &mut arx,
        "숨긴 디렉터리",
        |i| matches!(i, Inbound::Directory(d) if online(d, "bob@local").is_none()),
    )
    .await;
    bob.enqueue(&Outgoing::PresenceSet { share: true }).unwrap();
    wait(
        &mut arx,
        "다시 보인 디렉터리",
        |i| matches!(i, Inbound::Directory(d) if online(d, "bob@local") == Some(json!(true))),
    )
    .await;
}

/// 심어 둔 내 기기는 등록 전에 디렉터리가 와도(목록에 없어도) 폐기되지 않고, 등록 뒤 처음 나오면 `planted` 표시가 빠진다.
#[tokio::test(flavor = "multi_thread")]
async fn planted_device_survives_directory_before_registration() {
    let h = relay().await;
    let ak = h.user("dana", 1).await;
    let bk = h.user("bob", 5).await;
    let (owner, mut orx) = h.start("dana", &ak, "o.db");
    ready(&mut orx).await;
    let info = DeviceInfo::of("dana", None, &DeviceKeys::generate(&[2; 64]));
    assert!(owner.plant_own_device(&info).unwrap());
    // 등록 전 디렉터리(동료의 접속 변화).
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut brx).await;
    wait(&mut orx, "등록 전 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d.to_string().contains("bob@local") && !d.to_string().contains(&info.device_id))
    })
    .await;
    let trust = |c: &RelayClient| c.store().peer(&info.device_id).unwrap().unwrap().trust;
    assert_eq!(trust(&owner), lodelai_relay_client::Trust::Trusted);
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &info, true)
        .await
        .unwrap();
    wait(
        &mut orx,
        "등록 뒤 디렉터리",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&info.device_id)),
    )
    .await;
    assert_eq!(trust(&owner), lodelai_relay_client::Trust::Trusted);
    let basis = owner.store().basis(&info.device_id).unwrap();
    assert_eq!(basis, vec!["human".to_owned()]);
}

// ------------------------------------------------------------------ 묶음 15

fn write_file(h: &Harness, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = h._dir.path().join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// 첨부 둘을 보내면 받는 쪽에 Deliver(files 목록, 키 없음) 뒤 Attachment 둘이 오고, 풀린 바이트가 같다. 받는 기기가 하나라
/// 다 받으면 relay 에서 지워진다.
#[tokio::test(flavor = "multi_thread")]
async fn attachments_round_trip_and_are_deleted_after_fetch() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let big: Vec<u8> = (0..70_000u32).map(|i| (i % 253) as u8).collect();
    let files = vec![
        lodelai_relay_client::OutFile {
            path: write_file(&h, "big.bin", &big),
            name: "big.bin".into(),
            mime: "application/octet-stream".into(),
            role: None,
            sha256: None,
            size_px: None,
        },
        lodelai_relay_client::OutFile {
            path: write_file(&h, "note.md", b"# hi"),
            name: "note.md".into(),
            mime: "text/markdown".into(),
            role: Some("full_text".into()),
            sha256: None,
            size_px: None,
        },
    ];
    let m = h.message("alice@local", "chat", "bob@local", json!({}), "파일 둘");
    alice
        .enqueue(&Outgoing::SendFiles {
            message: m.clone(),
            attachments: files,
        })
        .unwrap();
    wait(
        &mut arx,
        "ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == id(&m)),
    )
    .await;

    let got = deliver(&mut brx).await;
    assert_eq!(got["body"]["text"], "파일 둘");
    let shown = got["body"]["files"].as_array().unwrap().clone();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[1]["role"], "full_text");
    assert!(shown
        .iter()
        .all(|f| f.get("fk").is_none() && f.get("ct_sha256").is_none()));
    assert_eq!(got["blobs"].as_array().unwrap().len(), 2);

    let mut received = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let Inbound::Attachment {
            msg_id,
            idx,
            outcome,
            ..
        } = wait(&mut brx, "attachment", |i| {
            matches!(i, Inbound::Attachment { .. })
        })
        .await
        else {
            unreachable!()
        };
        assert_eq!(msg_id, id(&m));
        let lodelai_relay_client::AttachmentOutcome::Received { path, size } = outcome else {
            panic!("{outcome:?}")
        };
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, size);
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "풀어 둔 평문은 나만");
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        received.insert(idx, bytes);
    }
    assert_eq!(received[&0], big);
    assert_eq!(received[&1], b"# hi");
    // blob.fetched 뒤 relay 가 지운다 — 고정 시간 대신 빌 때까지(#536).
    let blobs = h._dir.path().join("relay-blobs");
    tokio::time::timeout(WAIT, async {
        while !walk(&blobs).is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("relay 가 받은 첨부를 지우지 않음: {:?}", walk(&blobs)));
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                out.extend(walk(&e.path()));
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

/// relay 가 예약을 거절하면(디스크 하한 storage_full) 행을 빼고 upload_storage(F7). 큐는 비고 다음 것이 나간다.
#[tokio::test(flavor = "multi_thread")]
async fn upload_refused_storage_full_is_upload_storage_and_queue_moves_on() {
    let h = relay_with(|c| c.blob_min_free = u64::MAX).await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let m = h.message("alice@local", "chat", "bob@local", json!({}), "못 감");
    alice
        .enqueue(&Outgoing::SendFiles {
            message: m.clone(),
            attachments: vec![lodelai_relay_client::OutFile {
                path: write_file(&h, "x.bin", b"xyz"),
                name: "x.bin".into(),
                mime: "application/octet-stream".into(),
                role: None,
                sha256: None,
                size_px: None,
            }],
        })
        .unwrap();
    let after = h.message("alice@local", "chat", "bob@local", json!({}), "다음 것");
    alice
        .enqueue(&Outgoing::Send {
            message: after.clone(),
        })
        .unwrap();
    let nack = wait(&mut arx, "nack", |i| matches!(i, Inbound::Nack { .. })).await;
    assert!(
        matches!(&nack, Inbound::Nack { msg_id, reason } if *msg_id == id(&m) && reason == "upload_storage"),
        "{nack:?}"
    );
    assert_eq!(deliver(&mut brx).await["msg_id"], after["msg_id"]);
    // 첨부 없는 메시지·잘못된 첨부는 넣을 때 거절.
    assert!(alice
        .enqueue(&Outgoing::SendFiles {
            message: h.message("alice@local", "chat", "bob@local", json!({}), "없음"),
            attachments: vec![],
        })
        .is_err());
}

// ------------------------------------------------------------------ 묶음 16

// ------------------------------------------------------------------ 프로필 사진(묶음 15 B9)

fn png(side: u32, extra: usize) -> Vec<u8> {
    let mut p = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    p.extend_from_slice(b"IHDR");
    p.extend_from_slice(&side.to_be_bytes());
    p.extend_from_slice(&side.to_be_bytes());
    p.extend(std::iter::repeat_n(0u8, extra));
    p
}

/// 디렉터리에서 그 사람의 `avatar`(없으면 `None`)가 `want` 가 될 때까지 기다린다.
async fn avatar_becomes(rx: &mut Receiver<Inbound>, who: &str, want: bool) -> Option<String> {
    let Inbound::Directory(d) = wait(rx, "directory avatar", |i| {
        matches!(i, Inbound::Directory(d) if d["people"].as_array().is_some_and(|ps| ps.iter().any(|p| {
            p["address"] == who && p.get("avatar").is_some_and(Value::is_string) == want
        })))
    })
    .await
    else {
        unreachable!()
    };
    d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == who)
        .and_then(|p| p["avatar"].as_str())
        .map(str::to_owned)
}

#[tokio::test(flavor = "multi_thread")]
async fn avatar_set_fetch_and_clear() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    // PNG 가 아니거나 상한을 넘으면 넣지 않는다.
    assert!(alice.set_avatar(b"not a png").is_err());
    let max = lodelai_protocol::constants::AVATAR_MAX_BYTES as usize;
    assert!(alice.set_avatar(&png(256, max)).is_err());

    let pic = png(256, 300);
    alice.set_avatar(&pic).unwrap();
    let blob = avatar_becomes(&mut brx, "alice@local", true).await.unwrap();
    assert_eq!(
        bob.fetch_avatar(&blob, Duration::from_secs(5))
            .await
            .unwrap(),
        pic
    );
    assert!(alice.store().is_empty().unwrap());

    alice.clear_avatar().unwrap();
    avatar_becomes(&mut brx, "alice@local", false).await;
    assert!(bob
        .fetch_avatar(&blob, Duration::from_secs(5))
        .await
        .is_err());
}

/// 관문 acct ⑤: 올리기 답이 `avatar_slow_notice` 넘게 없으면 기다리던 채로 '네트워크 기다림'을 한 번 낸다 — 올리기는 버리지
/// 않고 끝까지 가 디렉터리 사진이 바뀐다(느림 알림은 한 번만).
#[tokio::test(flavor = "multi_thread")]
async fn avatar_slow_upload_shows_waiting_once_and_still_lands() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let mut cfg = h.config(&h.ws_url(), "alice", &ak);
    cfg.avatar_slow_notice = Duration::ZERO;
    let (alice, mut arx) = h.start_with(cfg, "a.db");
    ready(&mut arx).await;
    alice.set_avatar(&png(256, 300)).unwrap();
    let mut waits = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let landed = loop {
        let i = tokio::time::timeout_at(deadline, arx.recv())
            .await
            .expect("사진이 디렉터리에 오지 않음")
            .expect("inbound 닫힘");
        match i {
            Inbound::AvatarFailed { reason, org: false } if reason == "waiting_network" => {
                waits += 1;
            }
            Inbound::AvatarFailed { reason, .. } => panic!("거절: {reason}"),
            Inbound::Directory(d)
                if d["people"].as_array().is_some_and(|ps| {
                    ps.iter()
                        .any(|p| p["address"] == "alice@local" && p["avatar"].is_string())
                }) =>
            {
                break true;
            }
            _ => {}
        }
    };
    assert!(landed);
    assert_eq!(waits, 1, "느림 알림은 한 번");
    // relay 의 directory.update 가 PUT 응답 처리(행 빼기)보다 먼저 올 수 있다.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !alice.store().is_empty().unwrap() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(alice.store().is_empty().unwrap());
}

/// 올리기 바로 뒤 지우기 — 같은 큐 키라 마지막 의도(지우기)만 남고, 사진은 되살아나지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn avatar_clear_after_set_keeps_last_intent() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice.set_avatar(&png(256, 10)).unwrap();
    avatar_becomes(&mut brx, "alice@local", true).await;

    alice.set_avatar(&png(256, 20)).unwrap();
    alice.clear_avatar().unwrap();
    avatar_becomes(&mut brx, "alice@local", false).await;
    // 큐가 빈 뒤에도 사진이 다시 생기지 않는다(내 디렉터리도 지운 상태에서 머문다).
    tokio::time::timeout(Duration::from_secs(5), async {
        while !alice.store().is_empty().unwrap() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    avatar_becomes(&mut arx, "alice@local", false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let d = alice.directory();
    let me = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "alice@local")
        .unwrap()
        .clone();
    assert!(me.get("avatar").is_none(), "{me}");
}

/// relay 가 PUT 을 거절하면(PNG 가로세로 512 넘음) 행을 빼고 AvatarFailed, 큐는 다음 것으로.
#[tokio::test(flavor = "multi_thread")]
async fn avatar_refused_is_reported_and_queue_moves_on() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice.set_avatar(&png(1024, 10)).unwrap();
    let after = h.message("alice@local", "chat", "bob@local", json!({}), "다음 것");
    alice
        .enqueue(&Outgoing::Send {
            message: after.clone(),
        })
        .unwrap();
    let failed = wait(&mut arx, "avatar failed", |i| {
        // 부하로 PUT 이 한 번 일시 실패하면 거절 앞에 '네트워크 기다림'이 올 수 있다 — 거절만 기다린다.
        matches!(i, Inbound::AvatarFailed { reason, .. } if reason != "waiting_network")
    })
    .await;
    assert!(
        matches!(&failed, Inbound::AvatarFailed { reason, org: false } if reason == "put_400"),
        "{failed:?}"
    );
    assert_eq!(deliver(&mut brx).await["msg_id"], after["msg_id"]);
}

/// #554: 조직 사진은 `blob.reserve{for: "org"}` 로 — 조직 관리자가 아닌 사용자(로컬 relay 엔 조직이 없다)면 relay 가 예약을
/// 거절하고 `AvatarFailed{org: true}`, 내 사진 큐와 섞이지 않고 큐는 다음 것으로.
#[tokio::test(flavor = "multi_thread")]
async fn org_avatar_refused_for_non_admin_is_reported_as_org() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    assert!(alice.set_org_avatar(b"not a png").is_err());
    alice.set_org_avatar(&png(256, 10)).unwrap();
    let after = h.message("alice@local", "chat", "bob@local", json!({}), "다음 것");
    alice
        .enqueue(&Outgoing::Send {
            message: after.clone(),
        })
        .unwrap();
    let failed = wait(&mut arx, "org avatar failed", |i| {
        // 부하로 PUT 이 한 번 일시 실패하면 거절 앞에 '네트워크 기다림'이 올 수 있다 — 거절만 기다린다.
        matches!(i, Inbound::AvatarFailed { reason, .. } if reason != "waiting_network")
    })
    .await;
    assert!(
        matches!(&failed, Inbound::AvatarFailed { org: true, .. }),
        "{failed:?}"
    );
    assert_eq!(deliver(&mut brx).await["msg_id"], after["msg_id"]);
}

// ------------------------------------------------------------------ held 첨부(묶음 15 §4a, 140b5849)

/// 코어가 넘긴 평문 해시와 지금 읽은 파일이 다르면 보내지 않는다(upload_failed), 같으면 간다(묶음 15 QA 🟢).
#[tokio::test(flavor = "multi_thread")]
async fn upload_checks_core_hash_of_the_bytes_it_seals() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let hex = |b: &[u8]| {
        use sha2::Digest;
        sha2::Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    let file = |name: &str, body: &[u8], sha: String| lodelai_relay_client::OutFile {
        path: write_file(&h, name, body),
        name: name.into(),
        mime: "application/octet-stream".into(),
        role: None,
        sha256: Some(sha),
        size_px: None,
    };
    let bad = h.message("alice@local", "chat", "bob@local", json!({}), "바뀜");
    alice
        .enqueue(&Outgoing::SendFiles {
            message: bad.clone(),
            attachments: vec![file("a.bin", b"now", hex(b"before"))],
        })
        .unwrap();
    let good = h.message("alice@local", "chat", "bob@local", json!({}), "같음");
    alice
        .enqueue(&Outgoing::SendFiles {
            message: good.clone(),
            attachments: vec![file("b.bin", b"same", hex(b"same"))],
        })
        .unwrap();
    let nack = wait(&mut arx, "nack", |i| matches!(i, Inbound::Nack { .. })).await;
    assert!(
        matches!(&nack, Inbound::Nack { msg_id, reason } if *msg_id == id(&bad) && reason == "upload_failed"),
        "{nack:?}"
    );
    assert_eq!(deliver(&mut brx).await["msg_id"], good["msg_id"]);
}
/// 묶음 20: `Outgoing::Publish.audience` 가 `session.publish.audience{people}` 로 나가 범위 밖 사람의 디렉터리에서 그 세션이
/// 빠진다. 범위 안 사람은 본다.
#[tokio::test(flavor = "multi_thread")]
async fn publish_audience_hides_session_from_people_outside() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (_alice, mut arx) = h.start("alice", &ak, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, "c.db");
    for rx in [&mut arx, &mut brx, &mut crx] {
        ready(rx).await;
    }
    bob.enqueue(&Outgoing::Publish {
        slug: "be".into(),
        grade: "task".into(),
        liveness: "live:pty".into(),
        display: None,
        title: None,
        folder: None,
        busy: false,
        audience: Some(vec!["alice".into()]),
        project: None,
        agent: None,
        no: None,
    })
    .unwrap();
    wait(
        &mut arx,
        "범위 안 alice 가 본다",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains("bob@local/be")),
    )
    .await;
    wait(
        &mut brx,
        "주인",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains("bob@local/be")),
    )
    .await;
    // carol 은 같은 갱신을 받지만(같은 방송) 세션이 없다 — 받았을 시간을 둔다.
    tokio::time::sleep(Duration::from_millis(300)).await;
    while crx.try_recv().is_ok() {}
    assert!(
        !carol.directory().to_string().contains("bob@local/be"),
        "{}",
        carol.directory()
    );
    assert!(!carol.directory().to_string().contains("audience"));
    // 빈 people 은 큐에 넣지 않고 오류(QA 20 🟡 — relay 가 프레임을 거절해 publish 가 계속 사라지지 않게).
    assert!(bob
        .enqueue(&Outgoing::Publish {
            slug: "be".into(),
            grade: "task".into(),
            liveness: "live:pty".into(),
            display: None,
            title: None,
            folder: None,
            busy: false,
            audience: Some(vec![]),
            project: None,
            agent: None,
            no: None,
        })
        .is_err());
}

/// #737: code relay 에 대기 명단 주소가 있으면 승인 안 된 새 이메일의 verify 가 그 주소를 싣는다.
#[tokio::test(flavor = "multi_thread")]
async fn code_relay_verify_carries_waitlist_url() {
    use lodelai_relay_client::register::{signup_start, signup_verify};
    let (h, mail, _) =
        remote_relay_with(|c| c.waitlist_url = Some("https://lodelai.com/waitlist".into())).await;
    let url = h.ws_url();
    signup_start(&url, "new@x.io", None, "2026-10-25")
        .await
        .unwrap();
    let code = mail.0.lock().unwrap()["new@x.io"].clone();
    let v = signup_verify(&url, "new@x.io", &code).await.unwrap();
    assert!(!v.org_create_open);
    assert_eq!(
        v.waitlist_url.as_deref(),
        Some("https://lodelai.com/waitlist")
    );
    assert!(!v.approved);
}

/// 묶음 18(#378): `open` relay 는 verify 가 알려 주고 코드 없이 만든다. 기존 계정은 `AccountExists`(토큰 남음), 상한은
/// `OrgRateLimited`·`OrgCreateClosed`.
#[tokio::test(flavor = "multi_thread")]
async fn open_relay_signup_errors_map_to_their_own_variants() {
    use lodelai_relay_client::register::{
        register_device_hosted, signup_start, signup_verify, HostedOrg,
    };
    use lodelai_relay_client::Error;
    let limits = lodelai_relay::OrgCreateLimits {
        per_email_30d: 10,
        per_ip_day: 1,
        per_day: 10,
        max_orgs: 10,
    };
    let (h, mail, _) = remote_relay_with(|c| {
        c.org_create_open = true;
        c.org_create_limits = limits;
    })
    .await;
    let url = h.ws_url();
    let verified = |email: &'static str| {
        let (url, mail) = (url.clone(), mail.clone());
        async move {
            signup_start(&url, email, None, "2026-10-25").await.unwrap();
            let code = mail.0.lock().unwrap()[email].clone();
            signup_verify(&url, email, &code).await.unwrap()
        }
    };
    let create = |name: &str| HostedOrg::Create {
        name: name.into(),
        setup_code: String::new(),
    };
    let v = verified("boss@x.io").await;
    assert!(v.org_create_open && v.existing.is_none());
    let k1 = DeviceKeys::generate(&[1; 64]);
    let info = DeviceInfo::of("boss", None, &k1);
    register_device_hosted(
        &url,
        &v.signup_token,
        &info,
        Some("boss"),
        Some(&create("루이보스")),
        &[],
    )
    .await
    .unwrap();

    let v = verified("boss@x.io").await;
    assert!(!v.org_create_open);
    assert_eq!(
        v.existing.as_ref().unwrap().org_name.as_deref(),
        Some("루이보스")
    );
    let k2 = DeviceKeys::generate(&[2; 64]);
    let info = DeviceInfo::of("boss", None, &k2);
    assert!(matches!(
        register_device_hosted(
            &url,
            &v.signup_token,
            &info,
            None,
            Some(&create("다른")),
            &[]
        )
        .await,
        Err(Error::AccountExists(a)) if a.user == "boss" && a.org_name.as_deref() == Some("루이보스")
    ));
    let reg = register_device_hosted(&url, &v.signup_token, &info, None, None, &[])
        .await
        .unwrap();
    assert!(reg.added);

    // IP 하루 1 — 같은 맥에서 두 번째 조직.
    let v = verified("eve@x.io").await;
    let k3 = DeviceKeys::generate(&[3; 64]);
    let info = DeviceInfo::of("eve", None, &k3);
    assert!(matches!(
        register_device_hosted(
            &url,
            &v.signup_token,
            &info,
            Some("eve"),
            Some(&create("E")),
            &[]
        )
        .await,
        Err(Error::OrgRateLimited)
    ));

    // 조직 수 상한.
    let (h, mail, _) = remote_relay_with(|c| {
        c.org_create_open = true;
        c.org_create_limits = lodelai_relay::OrgCreateLimits {
            max_orgs: 1,
            ..limits
        };
    })
    .await;
    let url = h.ws_url();
    for (n, email) in ["a@x.io", "b@x.io"].into_iter().enumerate() {
        signup_start(&url, email, None, "2026-10-25").await.unwrap();
        let code = mail.0.lock().unwrap()[email].clone();
        let v = signup_verify(&url, email, &code).await.unwrap();
        let user = &email[..1];
        let k = DeviceKeys::generate(&[10 + n as u8; 64]);
        let res = register_device_hosted(
            &url,
            &v.signup_token,
            &DeviceInfo::of(user, None, &k),
            Some(user),
            Some(&create(user)),
            &[],
        )
        .await;
        if n == 0 {
            res.unwrap();
        } else {
            assert!(matches!(res, Err(Error::OrgCreateClosed)), "{res:?}");
        }
    }
}
/// #490 ⑦(28 §4): 맥 이름을 다듬어(숨은 문자·앞뒤 공백 빼기) 보내고, 내 디렉터리의 내 기기에 실린다. 다시 붙어도 같은
/// 이름이면 보내지 않는다 — relay 는 같은 값이면 방송하지 않으니, 두 번째 연결 뒤 이름이 그대로인지만 본다.
#[tokio::test]
async fn device_name_is_cleaned_sent_once_and_shows_on_my_device() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let me = ak.device_id().as_str().to_owned();
    let has_name = move |i: &Inbound| matches!(i, Inbound::Directory(d) if d["people"].as_array().is_some_and(|ps| ps.iter().flat_map(|p| p["devices"].as_array().into_iter().flatten()).any(|x| x["device_id"] == me.as_str() && x["name"] == "앨리스의 맥북")));
    let mut c = h.config(&h.ws_url(), "alice", &ak);
    c.device_name = Some(Arc::new(|| Some(" 앨리스의\u{200b} 맥북\n".to_owned())));
    let (a, mut rx) = h.start_with(c.clone(), "a.db");
    wait(&mut rx, "내 기기 이름이 실린 디렉터리", &has_name).await;
    drop(a);
    drop(rx);
    let (_a, mut rx) = h.start_with(c, "a.db");
    wait(&mut rx, "다시 붙은 뒤 디렉터리(이름 그대로)", &has_name).await;
}
