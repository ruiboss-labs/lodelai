//! L2 in-process 시험 (U4, #56): 라우터를 127.0.0.1 에 올리고 tungstenite 클라이언트 둘·셋으로 두드린다.
//! 시간·ID·난수는 testkit 의 고정 구현. 근거: protocol §7, security §7.2, QA m1-acceptance·security-tests.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::{encoding, sign_challenge, sign_message, DeviceKeys};
use lodelai_effects::{Clock, IdGen, UnixMillis};
use lodelai_relay::{bind_local, db::Db, serve, App, Config, Effects, Relay};
use lodelai_relay_client::mls::pair_group_id;
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod common;
use common::mls_dev::{fake_app, pair_bodies};

const START_MS: i64 = 1_792_728_776_000; // 2026-10-23T04:12:56Z
const TOKEN: &str = "test-registration-token";
const SERVER: &str = "local";
const CHAT_MAX: usize = lodelai_protocol::constants::BODY_MAX_BYTES_CHAT as usize;

struct Harness {
    app: App,
    addr: SocketAddr,
    fx: TestEffects,
    /// 조직 둘 픽스처용 파일 DB(`start_two_orgs`). 임시 폴더는 Harness 와 함께 지워진다.
    db_file: Option<(tempfile::TempDir, std::path::PathBuf)>,
}

async fn start() -> Harness {
    start_with(|_| {}).await
}

async fn start_with(tweak: impl FnOnce(&mut Config)) -> Harness {
    start_db(tweak, Db::memory().unwrap()).await
}

async fn start_db(tweak: impl FnOnce(&mut Config), db: Db) -> Harness {
    start_full(tweak, db, None).await
}

async fn start_full(
    tweak: impl FnOnce(&mut Config),
    db: Db,
    mailer: Option<std::sync::Arc<dyn lodelai_relay::mail::Mailer>>,
) -> Harness {
    let fx = TestEffects::new(START_MS, 7);
    db.set_email_key(b"test-email-hmac-key-0123456789abcdef".to_vec());
    let (listener, addr) = bind_local(0).await.unwrap();
    let mut config = Config::local(SERVER);
    // 접속 변화 directory.update 는 그것을 보는 시험만 켠다(다른 시험의 프레임 순서를 흔들지 않게).
    config.presence_updates = false;
    tweak(&mut config);
    config.port = addr.port();
    config.registration_token = Some(TOKEN.into());
    let effects = Effects {
        clock: fx.clock.clone(),
        ids: fx.ids.clone(),
        rng: fx.rng.clone(),
    };
    let app = Relay::with_mailer(config, effects, db, mailer);
    tokio::spawn(serve(app.clone(), listener));
    Harness {
        app,
        addr,
        fx,
        db_file: None,
    }
}

/// 조직이 둘인 픽스처. `register_device` 가 모두 `LOCAL_ORG` 에 넣으므로(조직 배정 API 는 hosted 몫), 파일 DB 를 두 번째
/// 연결로 열어 `set_org` 로 사용자를 다른 조직으로 옮긴다. 제품 코드는 건드리지 않는다.
async fn start_two_orgs() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let db = Db::open(&path).unwrap();
    let mut h = start_db(|_| {}, db).await;
    h.db_file = Some((dir, path));
    h
}

fn set_org(h: &Harness, user: &str, org: &str) {
    let (_, path) = h.db_file.as_ref().expect("start_two_orgs 로 시작해야 한다");
    let c = rusqlite::Connection::open(path).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    let n = c
        .execute("UPDATE users SET org = ?1 WHERE user = ?2", [org, user])
        .unwrap();
    assert_eq!(n, 1, "{user}");
}

/// 최소 HTTP/1.1 클라이언트. (상태 코드, 본문)
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: 127.0.0.1:{}\r\n", addr.port()));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let code = out.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = out
        .split_once("\r\n\r\n")
        .map(|x| x.1.to_owned())
        .unwrap_or_default();
    (code, body)
}

struct User {
    name: String,
    keys: DeviceKeys,
    device_id: String,
}

impl User {
    fn address(&self) -> String {
        format!("{}@{SERVER}", self.name)
    }
}

fn register_body(name: &str, keys: &DeviceKeys) -> String {
    json!({
        "user": name,
        "device_pubkeys": device_pubkeys(keys),
        "display_name": name,
    })
    .to_string()
}

/// 디렉터리·등록에 싣는 공개키(#313 `x25519_sig` 포함).
fn device_pubkeys(keys: &DeviceKeys) -> Value {
    let x = keys.exchange.public_key();
    json!({
        "ed25519": keys.signing.verifying_key().to_b64(),
        "x25519": encoding::encode(&x),
        "x25519_sig": lodelai_crypto::xkey::sign(&keys.signing, keys.device_id().as_str(), &x),
    })
}

async fn register(h: &Harness, name: &str, seed: u8) -> User {
    let keys = DeviceKeys::generate(&[seed; 64]);
    let auth = format!("Bearer {TOKEN}");
    let (code, resp) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &register_body(name, &keys),
    )
    .await;
    assert_eq!(code, 201, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["device_id"], keys.device_id().as_str());
    User {
        name: name.into(),
        device_id: keys.device_id().as_str().to_owned(),
        keys,
    }
}

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Client {
    ws: Ws,
}

impl Client {
    async fn send(&mut self, v: &Value) {
        self.ws
            .send(Message::Text(v.to_string().into()))
            .await
            .unwrap();
    }

    async fn recv_text(&mut self) -> String {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(3), self.ws.next())
                .await
                .expect("프레임 대기 시간 초과")
                .expect("연결 끊김")
                .unwrap();
            match m {
                Message::Text(t) => return t.to_string(),
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("예상 밖 프레임: {other:?}"),
            }
        }
    }

    /// 다음 프레임. MLS 그룹 관리 `duty`(묶음 22 — 1:1 도 pair 그룹이라 기기 폐기·추가 때 온다)는 이 파일의 규칙 시험 밖이라
    /// 건너뛴다(duty 는 mls.rs 가 본다).
    async fn recv(&mut self) -> Value {
        loop {
            let f: Value = serde_json::from_str(&self.recv_text().await).unwrap();
            if f["t"] != "duty" {
                return f;
            }
        }
    }

    /// 짧게 기다려 아무 텍스트 프레임도 오지 않음을 확인.
    /// 조용해질 때까지(200 ms) 온 프레임을 버린다.
    async fn drain(&mut self) {
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_millis(200), self.ws.next()).await
        {}
    }

    async fn expect_silence(&mut self) {
        if let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_millis(200), self.ws.next()).await
        {
            panic!("조용해야 하는데 받음: {t}");
        }
    }
}

async fn ws_raw(addr: SocketAddr) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/v1/ws", addr.port()))
        .await
        .unwrap();
    ws
}

/// 묶음 22 §12-28 ①: /v1/ws 101 응답에 받는 판 범위 `Lodelai-Protocol: <MIN>-<VERSION>` — 앱이 옛 relay(헤더 없음)의 auth 끊김을
/// 진짜 인증 실패와 가른다.
#[tokio::test(flavor = "multi_thread")]
async fn upgrade_response_carries_protocol_range() {
    let h = start().await;
    let (_ws, resp) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/v1/ws", h.addr.port()))
            .await
            .unwrap();
    assert_eq!(resp.status(), 101);
    // §12-29 ①(#534): 서명을 검사할 서버 이름. §12-30 ②(#535): 기본 켬이라 groups.
    assert_eq!(resp.headers()["lodelai-server"], "local");
    assert_eq!(resp.headers()["lodelai-features"], "groups,device_name");
    assert_eq!(
        resp.headers()["lodelai-protocol"],
        format!(
            "{}-{}",
            lodelai_protocol::PROTOCOL_MIN,
            lodelai_protocol::PROTOCOL_VERSION
        )
        .as_str()
    );
}

/// 묶음 22 §12-28 ①: `/v1/healthz` 200 응답에도 같은 헤더(101 헤더를 프록시가 지웠을 때 앱이 여기서 본다). 본문은 `ok` 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn healthz_carries_protocol_range() {
    let h = start().await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let req = format!(
        "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        h.addr.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let want = format!(
        "lodelai-protocol: {}-{}",
        lodelai_protocol::PROTOCOL_MIN,
        lodelai_protocol::PROTOCOL_VERSION
    );
    assert!(
        head.lines().any(|l| l.eq_ignore_ascii_case(&want)),
        "{head}"
    );
    assert!(
        head.lines()
            .any(|l| l.eq_ignore_ascii_case("lodelai-server: local")),
        "{head}"
    );
    assert!(
        head.lines()
            .any(|l| l.eq_ignore_ascii_case("lodelai-features: groups,device_name")),
        "{head}"
    );
    assert_eq!(body, "ok");
}

/// 묶음 22 §12-30 ②(#535): 그룹을 끈 relay 도 줄은 늘 싣고 groups 가 빠진다(줄 없음 = 모름과 가른다) — 101·healthz 둘 다. 기기 이름
/// (#490 묶음 28 §4 device_name)은 늘 켬이라 값은 `device_name`.
#[tokio::test(flavor = "multi_thread")]
async fn groups_off_relay_says_features_none() {
    let h = start_with(|c| c.groups = false).await;
    let (_ws, resp) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/v1/ws", h.addr.port()))
            .await
            .unwrap();
    assert_eq!(resp.status(), 101);
    assert_eq!(resp.headers()["lodelai-features"], "device_name");
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let req = format!(
        "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        h.addr.port()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    let head = out.split_once("\r\n\r\n").unwrap().0;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.lines()
            .any(|l| l.eq_ignore_ascii_case("lodelai-features: device_name")),
        "{head}"
    );
}

/// 핸드셰이크까지. `ready` 프레임을 돌려준다.
async fn connect(h: &Harness, u: &User) -> (Client, Value) {
    connect_v(h, u, lodelai_protocol::PROTOCOL_VERSION).await
}

/// [`connect`] 를 그 hello.v 로(#598 ② — 판이 섞여 도는 시험).
async fn connect_v(h: &Harness, u: &User, v: u32) -> (Client, Value) {
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.send(&json!({"t": "hello", "v": v, "device_id": u.device_id, "user": u.name}))
        .await;
    let ch = c.recv().await;
    assert_eq!(ch["t"], "challenge");
    let sig = sign_challenge(
        &u.keys.signing,
        SERVER,
        &u.device_id,
        ch["nonce"].as_str().unwrap(),
    )
    .unwrap();
    c.send(&json!({"t": "auth", "sig": sig})).await;
    let ready = c.recv().await;
    assert_eq!(ready["t"], "ready", "{ready}");
    assert_eq!(ready["server"], SERVER);
    (c, ready)
}

fn now_str(h: &Harness, plus_ms: i64) -> String {
    UnixMillis(h.fx.clock.now().0 + plus_ms)
        .to_rfc3339()
        .unwrap()
}

/// 주소의 사용자 이름(`bob@local/backend` → `bob`).
fn user_of(addr: &str) -> &str {
    addr.split('/')
        .next()
        .and_then(|a| a.split('@').next())
        .unwrap_or_default()
}

/// 서명된 메시지. `from_addr` 에 `/` 가 있으면 세션 주소(author=agent). 본문은 `system` 이면 빈 평문, 그 밖은 보낸·받는 사람
/// pair 그룹(epoch 1 — [`pair`] 가 세운다)의 응용 메시지 모양([`fake_app`]).
fn msg(
    h: &Harness,
    from: &User,
    from_addr: &str,
    kind: &str,
    to: &str,
    extra: Value,
    text: &str,
) -> Value {
    let id = h.fx.ids.next_ulid();
    let author = if from_addr.contains('/') {
        "agent"
    } else {
        "human"
    };
    let mut from_obj = json!({"address": from_addr, "author": author, "device_id": from.device_id});
    if author == "agent" {
        from_obj["session_id"] = json!("cee3f37e-0000-0000-0000-000000000000");
    }
    let mut m = json!({
        "v": lodelai_protocol::MESSAGE_V_MAX,
        "msg_id": id,
        "thread_id": id,
        "kind": kind,
        "from": from_obj,
        "to": {"address": to},
        "body": if kind == "system" {
            json!({"enc": "plain", "text": ""})
        } else {
            fake_app(text.as_bytes())
        },
        "created_at": now_str(h, 0),
        "expires_at": now_str(h, 24 * 3600 * 1000),
    });
    if kind != "system" {
        let gid = pair_group_id(user_of(&from.address()), user_of(to));
        m["mls_group"] = json!(encoding::encode(&gid));
        m["epoch"] = json!(1);
    }
    for (k, v) in extra.as_object().unwrap() {
        m[k] = v.clone();
    }
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// pair 그룹 Handshake(epoch 0).
fn pair_msg(h: &Harness, from: &User, to: &User, gid: &[u8], body: Value) -> Value {
    let id = h.fx.ids.next_ulid();
    let mut m = json!({
        "v": lodelai_protocol::MESSAGE_V_MAX,
        "msg_id": id, "thread_id": id, "kind": "mls",
        "from": {"address": from.address(), "author": "human", "device_id": from.device_id},
        "to": {"address": to.address()},
        "mls_group": encoding::encode(gid), "epoch": 0,
        "body": body,
        "created_at": now_str(h, 0),
        "expires_at": now_str(h, 24 * 3600 * 1000),
    });
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// 보내고 답(ack·nack·error)만 — 그 사이 프레임은 버린다.
async fn send_answer(c: &mut Client, m: &Value) -> Value {
    c.send(&json!({"t": "send", "message": m})).await;
    loop {
        let f = c.recv().await;
        if f["t"] == "ack" || f["t"] == "nack" || f["t"] == "error" {
            return f;
        }
    }
}

/// `alice`·`bob` 의 pair 그룹을 세운다(묶음 22 — 1:1 도 MLS, #488): start → bob 기기 KeyPackage 로 Add Commit(+welcome) → epoch 1.
/// bob 은 그 Commit 을 받아 delivered_ack 하고, alice 쪽에 온 received 도 비운다 — 시험의 recv 순서를 흐리지 않게.
async fn pair(h: &Harness, a: &mut Client, alice: &User, b: &mut Client, bob: &User) {
    let (gid, start, commit) = pair_bodies(&alice.keys, &alice.name, &[&bob.keys], &bob.name);
    let start = pair_msg(h, alice, bob, &gid, start);
    assert_eq!(send_answer(a, &start).await["t"], "ack", "pair start");
    let m = pair_msg(h, alice, bob, &gid, commit);
    let r = send_answer(a, &m).await;
    assert_eq!(r["t"], "ack", "pair add {r}");
    let d = b.recv().await;
    assert_eq!(d["message"]["msg_id"], m["msg_id"], "{d}");
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    a.drain().await;
    b.drain().await;
}

/// bob 이 아직 접속 전인 시험용 [`pair`] — bob 의 기기 `devs` 를 모두 잎으로 넣고, 기기마다 잠깐 접속해 그 Commit 을 받아 끊는다.
async fn pair_with(h: &Harness, a: &mut Client, alice: &User, devs: &[&User]) {
    let keys: Vec<&DeviceKeys> = devs.iter().map(|d| &d.keys).collect();
    let bob = devs[0];
    // 둘째 기기부터는 첫 기기의 devcert 가 있어야 잎 자격이 있다.
    if devs.len() > 1 {
        let (mut b, _) = connect(h, bob).await;
        for d in &devs[1..] {
            b.send(&json!({"t": "device.certify", "device_id": d.device_id,
                "sig": devcert(SERVER, bob, d)}))
                .await;
        }
        b.drain().await;
    }
    let (gid, start, commit) = pair_bodies(&alice.keys, &alice.name, &keys, &bob.name);
    let start = pair_msg(h, alice, bob, &gid, start);
    assert_eq!(send_answer(a, &start).await["t"], "ack", "pair start");
    let m = pair_msg(h, alice, bob, &gid, commit);
    let r = send_answer(a, &m).await;
    assert_eq!(r["t"], "ack", "pair add {r}");
    for d in devs {
        let (mut b, _) = connect(h, d).await;
        loop {
            let f = b.recv().await;
            if f["message"]["msg_id"] == m["msg_id"] {
                break;
            }
        }
        b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
            .await;
        b.drain().await;
    }
    a.drain().await;
}

async fn send_expect(c: &mut Client, m: &Value) -> Value {
    c.send(&json!({"t": "send", "message": m})).await;
    c.recv().await
}

fn mid(m: &Value) -> String {
    m["msg_id"].as_str().unwrap().to_owned()
}

async fn publish(c: &mut Client, slug: &str, grade: &str) {
    c.send(
        &json!({"t": "session.publish", "slug": slug, "grade": grade, "liveness": "live:channel"}),
    )
    .await;
}

// ------------------------------------------------------------------ 핸드셰이크·HTTP

/// S-TENANT-1·S-PEER-1: 다른 조직 사용자·세션으로 보낸 메시지는 "없는 사용자"와 바이트 동일한 unroutable 이고, 수신 측에는
/// 아무것도 가지 않는다. 방향 둘 다.
#[tokio::test(flavor = "multi_thread")]
async fn cross_org_send_is_unroutable_and_silent() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let (mut e, _) = connect(&h, &erin).await;
    publish(&mut b, "backend", "question").await;
    publish(&mut e, "ops", "question").await;
    // 같은 조직에게만 디렉터리 갱신이 간다
    for cl in [&mut a, &mut b] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    assert_eq!(e.recv().await["t"], "directory.update");
    a.expect_silence().await;

    let q = json!({"grade": "question"});
    let nack = |m: &Value, raw: &str| raw.replace(&mid(m), "ID");
    // 기준: 없는 사용자
    let base = msg(
        &h,
        &erin,
        &erin.address(),
        "chat",
        "nobody@local",
        json!({}),
        "x",
    );
    e.send(&json!({"t": "send", "message": base})).await;
    let expected = nack(&base, &e.recv_text().await);
    assert_eq!(
        expected,
        r#"{"msg_id":"ID","reason":"unroutable","t":"nack"}"#
    );

    let cases: Vec<(&str, &User, &str, Value)> = vec![
        (
            "erin→alice 사람",
            &erin,
            "erin@local",
            msg(
                &h,
                &erin,
                &erin.address(),
                "chat",
                &alice.address(),
                json!({}),
                "x",
            ),
        ),
        (
            "erin→bob 세션",
            &erin,
            "erin@local",
            msg(
                &h,
                &erin,
                &erin.address(),
                "request",
                "bob@local/backend",
                q.clone(),
                "x",
            ),
        ),
        (
            "alice→erin 사람",
            &alice,
            "alice@local",
            msg(
                &h,
                &alice,
                &alice.address(),
                "chat",
                &erin.address(),
                json!({}),
                "x",
            ),
        ),
        (
            "alice→erin 세션",
            &alice,
            "alice@local",
            msg(
                &h,
                &alice,
                &alice.address(),
                "request",
                "erin@local/ops",
                q.clone(),
                "x",
            ),
        ),
    ];
    for (why, from, _, m) in &cases {
        let c = if from.name == "erin" { &mut e } else { &mut a };
        c.send(&json!({"t": "send", "message": m})).await;
        assert_eq!(nack(m, &c.recv_text().await), expected, "{why}");
    }
    for cl in [&mut a, &mut b, &mut e] {
        cl.expect_silence().await;
    }
    // 같은 조직 안은 정상
    let ok = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "안녕",
    );
    assert_eq!(send_expect(&mut a, &ok).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
}

/// S-TENANT-2: 디렉터리는 자기 조직만 보여 주고, 갱신 푸시도 조직 안에서만 간다.
#[tokio::test(flavor = "multi_thread")]
async fn directory_hides_other_orgs_including_pushes() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    let frank = register(&h, "frank", 4).await;
    set_org(&h, "erin", "acme");
    set_org(&h, "frank", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut e, _) = connect(&h, &erin).await;
    let (mut f, _) = connect(&h, &frank).await;
    publish(&mut b, "backend", "task").await;
    publish(&mut f, "ops", "task").await;
    for cl in [&mut a, &mut b] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    for cl in [&mut e, &mut f] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    for cl in [&mut a, &mut b, &mut e, &mut f] {
        cl.expect_silence().await;
    }
    let addrs = |d: &Value, key: &str| -> Vec<String> {
        d[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["address"].as_str().unwrap().to_owned())
            .collect()
    };
    for (c, people, sessions) in [
        (&mut a, ["alice@local", "bob@local"], ["bob@local/backend"]),
        (&mut e, ["erin@local", "frank@local"], ["frank@local/ops"]),
    ] {
        c.send(&json!({"t": "directory.list"})).await;
        let d = c.recv().await;
        assert_eq!(addrs(&d, "people"), people);
        assert_eq!(addrs(&d, "sessions"), sessions);
    }
}

/// S-TENANT-3: 다른 조직 사용자가 남의 조직 `msg_id` 로 status 를 보내면 "없는 메시지"와 구분되지 않고, 상태가 바뀌지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn cross_org_status_and_reply_cannot_touch_threads() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let (mut e, _) = connect(&h, &erin).await;
    publish(&mut b, "backend", "task").await;
    for cl in [&mut a, &mut b] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    e.expect_silence().await;

    let alice_sess = "alice@local/frontend";
    let req = msg(
        &h,
        &alice,
        alice_sess,
        "request",
        "bob@local/backend",
        json!({"grade": "question"}),
        "Q",
    );
    assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let rid = mid(&req);

    // 다른 조직의 status: 있는 메시지와 없는 메시지의 응답이 같다
    e.send(&json!({"t": "status", "msg_id": rid, "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    let refused = e.recv_text().await;
    e.send(&json!({"t": "status", "msg_id": "01JB0000000000000000000000", "state": "accepted", "at": now_str(&h, 0)})).await;
    assert_eq!(e.recv_text().await, refused);
    // 다른 조직의 reply·rejected(reply_to 지정)도 거부되고 아무 데도 안 간다
    for kind in ["reply", "rejected"] {
        for to in [alice_sess, "bob@local/backend"] {
            let m = msg(
                &h,
                &erin,
                &erin.address(),
                kind,
                to,
                json!({"reply_to": rid, "thread_id": rid}),
                "끼어들기",
            );
            assert_eq!(
                send_expect(&mut e, &m).await["reason"],
                "unroutable",
                "{kind}→{to}"
            );
        }
    }
    for cl in [&mut a, &mut b] {
        cl.expect_silence().await;
    }
    // 다른 조직의 delivered_ack 도 무시된다(발신자에게 received 가 가지 않는다)
    e.send(&json!({"t": "delivered_ack", "msg_id": rid})).await;
    a.expect_silence().await;
    // 상태 불변: 당사자 bob 의 수락은 그대로 통하고 alice 에게 간다
    b.send(&json!({"t": "status", "msg_id": rid, "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["t"], "status", "{st}");
    assert_eq!(st["state"], "accepted");
}

/// 연결이 곧 끊기는지(텍스트 프레임이 오더라도 에러 프레임뿐, 이후 닫힘).
async fn expect_closed(c: &mut Client, within: Duration) -> Vec<String> {
    let mut texts = Vec::new();
    tokio::time::timeout(within, async {
        loop {
            match c.ws.next().await {
                Some(Ok(Message::Text(t))) => texts.push(t.to_string()),
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("연결이 끊기지 않았다");
    texts
}

/// S-PEER-4: hello 없이 먼저 보낸 프레임은 거부되고 연결이 닫힌다. 어떤 메시지도 라우팅되지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn frames_before_hello_are_refused_and_close() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut b, _) = connect(&h, &bob).await;

    for first in [
        json!({"t": "send", "message": msg(&h, &alice, &alice.address(), "chat", &bob.address(), json!({}), "몰래")}),
        json!({"t": "auth", "sig": "AAAA"}),
        json!({"t": "pong"}),
    ] {
        let mut c = Client {
            ws: ws_raw(h.addr).await,
        };
        c.send(&first).await;
        let texts = expect_closed(&mut c, Duration::from_secs(3)).await;
        assert!(
            texts
                .iter()
                .all(|t| t.contains("\"code\":\"protocol\"") && !t.contains("challenge")),
            "{first}: {texts:?}"
        );
    }
    // 바이너리 프레임도 마찬가지
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.ws.send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    expect_closed(&mut c, Duration::from_secs(3)).await;

    // 아무것도 bob 에게 가지 않았다
    b.expect_silence().await;
}

/// S-PEER-4: 인증 전 프레임 상한. 상한을 넘는 hello 는 연결이 닫히고, 다른 연결은 영향이 없다.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_frame_before_auth_closes_connection() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    let big = json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": alice.device_id, "user": "a".repeat(256 * 1024)});
    c.send(&big).await;
    let texts = expect_closed(&mut c, Duration::from_secs(3)).await;
    assert!(!texts.iter().any(|t| t.contains("challenge")), "{texts:?}");
    let (_a, ready) = connect(&h, &alice).await;
    assert_eq!(ready["t"], "ready");
}

/// S-PEER-4: hello 뒤 auth 를 보내지 않으면 `HANDSHAKE_TIMEOUT` 에 끊긴다(인증 안 된 연결을 붙들고 있지 않는다).
/// 실시간 10초가 든다 — 시간이 상수라 가짜 시계로 줄일 수 없다.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_times_out_without_auth() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": alice.device_id, "user": "alice"}))
        .await;
    assert_eq!(c.recv().await["t"], "challenge");
    let t0 = std::time::Instant::now();
    let texts = expect_closed(
        &mut c,
        lodelai_relay::ws::HANDSHAKE_TIMEOUT + Duration::from_secs(5),
    )
    .await;
    assert!(texts.is_empty(), "{texts:?}");
    assert!(t0.elapsed() >= lodelai_relay::ws::HANDSHAKE_TIMEOUT - Duration::from_millis(500));
    assert!(!h.app.conns.is_online("alice"));
}

/// 묶음 22 §12-24 ②⑤: hello 의 v 가 [PROTOCOL_MIN, PROTOCOL_VERSION] 밖이면 challenge 없이 error{version_unsupported, min, max}
/// 를 보내고 닫는다(auth 실패 protocol 과 구별). 맞는 v 는 지금처럼.
#[tokio::test(flavor = "multi_thread")]
async fn hello_outside_version_range_is_version_unsupported() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let (min, max) = (
        lodelai_protocol::PROTOCOL_MIN,
        lodelai_protocol::PROTOCOL_VERSION,
    );
    for v in [min - 1, max + 1] {
        let mut c = Client {
            ws: ws_raw(h.addr).await,
        };
        c.send(&json!({"t": "hello", "v": v, "device_id": alice.device_id, "user": "alice"}))
            .await;
        let e = c.recv().await;
        assert_eq!(
            (&e["t"], &e["code"], &e["min"], &e["max"]),
            (
                &json!("error"),
                &json!("version_unsupported"),
                &json!(min),
                &json!(max)
            ),
            "v {v}"
        );
        let rest = expect_closed(&mut c, Duration::from_secs(5)).await;
        assert!(rest.is_empty(), "{rest:?}");
    }
    assert!(!h.app.conns.is_online("alice"));
    let (_c, ready) = connect(&h, &alice).await;
    assert_eq!(ready["t"], "ready", "맞는 판은 지금처럼");
}

/// #598 ②: 판 9·10 이 함께 붙는다. relay 는 기기마다 마지막 hello.v 를 남겨 디렉터리 `v` 로 내주되, 판 9 연결엔 그 칸을 뺀다
/// (9 앱의 DirectoryDevice 는 additionalProperties false).
#[tokio::test(flavor = "multi_thread")]
async fn 판_9_와_10_이_함께_붙고_디렉터리_v_는_10_연결에만() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let min = lodelai_protocol::PROTOCOL_MIN;
    let max = lodelai_protocol::PROTOCOL_VERSION;
    assert!(min < max, "판이 섞여 도는 동안의 시험");
    let (mut a, ready) = connect_v(&h, &alice, min).await;
    assert_eq!(ready["t"], "ready", "옛 판도 붙는다");
    let (mut b, _) = connect_v(&h, &bob, max).await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = b.recv().await;
    assert_eq!(d["t"], "directory");
    let v_of = |d: &Value, who: &str| {
        d["people"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["address"] == who)
            .unwrap()["devices"][0]
            .get("v")
            .cloned()
    };
    assert_eq!(v_of(&d, "alice@local"), Some(json!(min)));
    assert_eq!(v_of(&d, "bob@local"), Some(json!(max)));
    a.send(&json!({"t": "directory.list"})).await;
    let d = a.recv().await;
    assert_eq!(d["t"], "directory");
    assert_eq!(v_of(&d, "alice@local"), None, "9 연결엔 v 칸 없음");
    assert_eq!(v_of(&d, "bob@local"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_failures_are_indistinguishable() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let mallory = DeviceKeys::generate(&[9; 64]);
    let unknown_device = mallory.device_id().as_str().to_owned();

    // 잘못된 서명 / 사용자 불일치 / 모르는 기기 / 다른 서버 이름으로 서명
    let cases: Vec<(String, &str, &DeviceKeys, &str)> = vec![
        (alice.device_id.clone(), "alice", &mallory, SERVER),
        (alice.device_id.clone(), "bob", &alice.keys, SERVER),
        (unknown_device, "alice", &mallory, SERVER),
        (alice.device_id.clone(), "alice", &alice.keys, "other"),
    ];
    let mut replies = Vec::new();
    for (device_id, user, keys, server) in cases {
        let mut c = Client {
            ws: ws_raw(h.addr).await,
        };
        c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": device_id, "user": user}))
            .await;
        let ch = c.recv().await;
        assert_eq!(ch["t"], "challenge", "모르는 기기에도 challenge 는 간다");
        let sig = sign_challenge(
            &keys.signing,
            server,
            &device_id,
            ch["nonce"].as_str().unwrap(),
        )
        .unwrap();
        c.send(&json!({"t": "auth", "sig": sig})).await;
        replies.push(c.recv_text().await);
    }
    assert!(replies.iter().all(|r| r == &replies[0]), "{replies:?}");
    assert!(replies[0].contains("\"code\":\"protocol\""));

    let (_c, ready) = connect(&h, &alice).await;
    assert_eq!(ready["pending"], 0);
    assert_eq!(ready["now"], "2026-10-23T04:12:56.000Z");
}

#[tokio::test(flavor = "multi_thread")]
async fn host_origin_and_registration_guards() {
    let h = start().await;
    // S-PEER-6: 127.0.0.1 에만 바인딩
    assert!(h.addr.ip().is_loopback());
    let (code, _) = http(h.addr, "GET", "/v1/healthz", &[], "").await;
    assert_eq!(code, 200);
    let (code, _) = http(
        h.addr,
        "GET",
        "/v1/healthz",
        &[("Origin", "http://evil.example")],
        "",
    )
    .await;
    assert_eq!(code, 403, "Origin 있으면 거부");
    let (code, _) = http(
        h.addr,
        "GET",
        "/v1/healthz",
        &[("Host", "evil.example")],
        "",
    )
    .await;
    assert_eq!(code, 403, "DNS rebinding Host 거부");
    let localhost = format!("localhost:{}", h.addr.port());
    let (code, _) = http(h.addr, "GET", "/v1/healthz", &[("Host", &localhost)], "").await;
    assert_eq!(code, 200);

    // 브라우저형 WebSocket(Origin 포함) 업그레이드도 거부
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://127.0.0.1:{}/v1/ws", h.addr.port()),
    )
    .unwrap();
    req.headers_mut()
        .insert("Origin", "http://evil.example".parse().unwrap());
    assert!(tokio_tungstenite::connect_async(req).await.is_err());

    // 등록 토큰 없이·틀린 토큰은 401
    let keys = DeviceKeys::generate(&[3; 64]);
    let body = register_body("eve", &keys);
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[("Content-Type", "application/json")],
        &body,
    )
    .await;
    assert_eq!(code, 401);
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer wrong"),
        ],
        &body,
    )
    .await;
    assert_eq!(code, 401);
    // 토큰 없이는 본문이 깨져 있어도 401(본문 파싱보다 토큰이 먼저)
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[("Content-Type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(code, 401);
    let auth = format!("Bearer {TOKEN}");
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        "{}",
    )
    .await;
    assert_eq!(code, 400);

    // 같은 기기 두 번 등록은 409
    register(&h, "eve", 3).await;
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &body,
    )
    .await;
    assert_eq!(code, 409);
}

// ------------------------------------------------------------------ 전달

/// S-SIGNUP-5: 이미 등록된 공개키를 다른 사용자 이름으로 등록할 수 없고(기기 중복 409), 있는 아이디에 새 키를 `existing_user`
/// 없이 붙일 수도 없다(403) — 아이디 가로채기 불가. 거부된 이름은 만들어지지도 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn registration_cannot_reuse_a_key_or_take_an_existing_handle() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let auth = format!("Bearer {TOKEN}");
    let post = |body: String| {
        let auth = auth.clone();
        let addr = h.addr;
        async move {
            http(
                addr,
                "POST",
                "/v1/devices",
                &[
                    ("Content-Type", "application/json"),
                    ("Authorization", &auth),
                ],
                &body,
            )
            .await
            .0
        }
    };
    // alice 의 공개키로 mallory 등록 → 거부
    assert_eq!(post(register_body("mallory", &alice.keys)).await, 409);
    // 새 키로 alice 아이디 등록(existing_user 없음) → 거부
    let other = DeviceKeys::generate(&[9; 64]);
    assert_eq!(post(register_body("alice", &other)).await, 403);
    // 둘 다 흔적이 없다: mallory·새 키로는 접속할 수 없다.
    assert_eq!(h.app.db.user_org("mallory").unwrap(), None);
    assert!(h
        .app
        .db
        .device(other.device_id().as_str())
        .unwrap()
        .is_none());
    assert_eq!(h.app.db.devices_of("alice").unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_delivers_and_ack_reports_received() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;

    // AC-HH-5: 한글·이모지·줄바꿈·코드 블록이 그대로
    let text = "점심? 🍜\n```rust\nfn main() {}\n```\t탭";
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        text,
    );
    let ack = send_expect(&mut a, &m).await;
    assert_eq!(ack, json!({"t": "ack", "msg_id": mid(&m)}));

    let d = b.recv().await;
    assert_eq!(d["t"], "deliver");
    assert_eq!(d["message"]["body"], m["body"]);
    assert_eq!(d["message"]["sig"], m["sig"]);
    // 수신 코어 재검증이 통과해야 한다(서버는 서명 대상을 바꾸지 않는다)
    lodelai_crypto::verify_message(&d["message"], &alice.keys.signing.verifying_key()).unwrap();

    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["t"], "status");
    assert_eq!(st["state"], "received");
    assert_eq!(st["msg_id"], mid(&m));

    // 두 번째 ack 는 무시. 남(alice)의 ack 도 무시
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    a.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    a.expect_silence().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_recipient_gets_stored_messages_on_connect() {
    // AC-HH-3
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let m1 = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "첫째",
    );
    let m2 = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "둘째",
    );
    assert_eq!(send_expect(&mut a, &m1).await["t"], "ack");
    assert_eq!(send_expect(&mut a, &m2).await["t"], "ack");

    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 2);
    assert_eq!(b.recv().await["message"]["msg_id"], mid(&m1));
    assert_eq!(b.recv().await["message"]["msg_id"], mid(&m2));
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m1)}))
        .await;
    assert_eq!(a.recv().await["state"], "received");
    drop(b);

    // 다시 접속하면 ack 안 한 것만
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b.recv().await["message"]["msg_id"], mid(&m2));
}

/// #537 (a): relay 가 도는 중 다른 연결(bootstrap 등)이 같은 DB 에 계속 커밋해도, 보낸 글은 모두 internal 없이 ack — 쓰기
/// 트랜잭션이 처음부터 쓰기 잠금(IMMEDIATE)이라 busy_timeout 이 듣는다. 기본(deferred)은 읽은 뒤 쓰려는 사이 다른 연결이
/// 커밋했으면 기다리지 않고 BUSY 였다.
#[tokio::test(flavor = "multi_thread")]
async fn busy_db_waits_instead_of_internal() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let path = h.db_file.as_ref().unwrap().1.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let halt = stop.clone();
    let writer = std::thread::spawn(move || {
        let c = rusqlite::Connection::open(path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch("CREATE TABLE IF NOT EXISTS t537(x INTEGER)")
            .unwrap();
        while !halt.load(std::sync::atomic::Ordering::Relaxed) {
            c.execute("INSERT INTO t537(x) VALUES (1)", []).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    for i in 0..20 {
        let m = msg(
            &h,
            &alice,
            &alice.address(),
            "chat",
            &bob.address(),
            json!({}),
            &format!("바쁜 때 {i}"),
        );
        let r = send_expect(&mut a, &m).await;
        assert_eq!(r["t"], "ack", "{i}: {r}");
        assert_eq!(b.recv().await["t"], "deliver");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_msg_id_is_idempotent() {
    // S-FORGE-8
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "한 번",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    assert_eq!(
        send_expect(&mut a, &m).await,
        json!({"t": "ack", "msg_id": mid(&m)})
    );
    b.expect_silence().await;
}

// ------------------------------------------------------------------ 위조·라우팅

#[tokio::test(flavor = "multi_thread")]
async fn forged_sender_fields_get_auth_nack() {
    // S-FORGE-4·5: 서버는 덮어쓰지 않고 거부한다
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;

    // from.address 를 bob 으로(자기 키로 서명)
    let m = msg(
        &h,
        &alice,
        &bob.address(),
        "chat",
        &bob.address(),
        json!({}),
        "나는 bob",
    );
    assert_eq!(send_expect(&mut a, &m).await["reason"], "auth");

    // from.device_id 를 bob 기기로
    let mut m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "x",
    );
    m["from"]["device_id"] = json!(bob.device_id);
    sign_message(&mut m, &alice.keys.signing).unwrap();
    assert_eq!(send_expect(&mut a, &m).await["reason"], "auth");

    // 서명 뒤 본문 변조
    let mut m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "원문",
    );
    m["body"]["payload"]["data"] = json!(encoding::encode(b"tampered-ciphertext-bytes"));
    assert_eq!(send_expect(&mut a, &m).await["reason"], "auth");

    // 다른 서버 이름의 발신 주소
    let m = msg(
        &h,
        &alice,
        "alice@other",
        "chat",
        &bob.address(),
        json!({}),
        "x",
    );
    assert_eq!(send_expect(&mut a, &m).await["reason"], "auth");
}

#[tokio::test(flavor = "multi_thread")]
async fn too_large_body_is_rejected() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let big = "가".repeat(CHAT_MAX / 3 + 1); // chat 상한 초과(UTF-8 3바이트)
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        &big,
    );
    assert_eq!(send_expect(&mut a, &m).await["reason"], "too_large");
}

#[tokio::test(flavor = "multi_thread")]
async fn unroutable_is_byte_identical_across_causes() {
    // QA S-TENANT · protocol §7.2-2: 다른 이유들이 같은 바이트(msg_id 제외). AC-GR-5(등급 초과)·AC-SEC-4(차단) 포함
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    publish(&mut b, "backend", "question").await;
    publish(&mut b, "gone", "question").await;
    b.send(&json!({"t": "session.unpublish", "slug": "gone"}))
        .await;
    h.app.db.block("carol", "alice").unwrap();
    // 디렉터리 갱신 3개씩 비운다
    for _ in 0..3 {
        assert_eq!(a.recv().await["t"], "directory.update");
        assert_eq!(b.recv().await["t"], "directory.update");
    }

    let q = json!({"grade": "question"});
    let me = alice.address();
    let cases: Vec<(&str, Value)> = vec![
        (
            "없는 사용자",
            msg(&h, &alice, &me, "chat", "nobody@local", json!({}), "x"),
        ),
        (
            "다른 서버",
            msg(&h, &alice, &me, "chat", "bob@other", json!({}), "x"),
        ),
        (
            "차단됨",
            msg(&h, &alice, &me, "chat", &carol.address(), json!({}), "x"),
        ),
        (
            "없는 슬러그",
            msg(&h, &alice, &me, "request", "bob@local/nope", q.clone(), "x"),
        ),
        (
            "공개 해제된 세션",
            msg(&h, &alice, &me, "request", "bob@local/gone", q.clone(), "x"),
        ),
        (
            "등급 초과",
            msg(
                &h,
                &alice,
                &me,
                "request",
                "bob@local/backend",
                json!({"grade": "task"}),
                "x",
            ),
        ),
        (
            "chat 을 세션 주소로",
            msg(&h, &alice, &me, "chat", "bob@local/backend", json!({}), "x"),
        ),
        (
            "request 를 사람 주소로",
            msg(&h, &alice, &me, "request", &bob.address(), q.clone(), "x"),
        ),
        (
            "없는 reply_to",
            msg(
                &h,
                &alice,
                &me,
                "rejected",
                &bob.address(),
                json!({"reply_to": "01JB0000000000000000000000"}),
                "x",
            ),
        ),
    ];
    let mut normalized = Vec::new();
    for (why, m) in &cases {
        a.send(&json!({"t": "send", "message": m})).await;
        let raw = a.recv_text().await;
        assert!(raw.contains("\"reason\":\"unroutable\""), "{why}: {raw}");
        normalized.push((*why, raw.replace(&mid(m), "ID")));
    }
    for (why, n) in &normalized {
        assert_eq!(n, &normalized[0].1, "{why}");
    }
    assert_eq!(
        normalized[0].1,
        r#"{"msg_id":"ID","reason":"unroutable","t":"nack"}"#
    );
    b.expect_silence().await;

    // 등급 이하는 통과
    let ok = msg(&h, &alice, &me, "request", "bob@local/backend", q, "질문");
    assert_eq!(send_expect(&mut a, &ok).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
}

#[tokio::test(flavor = "multi_thread")]
async fn reply_rules_status_rank_and_party_checks() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    publish(&mut b, "backend", "task").await;
    for cl in [&mut a, &mut b, &mut c] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }

    // alice 의 세션 → bob 의 세션으로 request
    let alice_sess = "alice@local/frontend";
    let req = msg(
        &h,
        &alice,
        alice_sess,
        "request",
        "bob@local/backend",
        json!({"grade": "question"}),
        "API 스키마?",
    );
    assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let rid = mid(&req);
    let re = json!({"reply_to": rid, "thread_id": rid});

    // 수락 전 회신은 거부(reply_accept_rule: stored·received 는 받지 않음)
    let early = msg(
        &h,
        &bob,
        "bob@local/backend",
        "reply",
        alice_sess,
        re.clone(),
        "성급",
    );
    assert_eq!(send_expect(&mut b, &early).await["reason"], "unroutable");

    // S-FORGE-9: 당사자가 아닌 carol 의 status 는 거부되고 아무 데도 안 간다
    c.send(&json!({"t": "status", "msg_id": rid, "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    let refused = c.recv_text().await;
    c.send(&json!({"t": "status", "msg_id": "01JB0000000000000000000000", "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(
        c.recv_text().await,
        refused,
        "없는 메시지와 남의 메시지가 구분되지 않는다"
    );
    a.expect_silence().await;
    assert_eq!(
        h.app.db.header(&rid).unwrap().unwrap().sender_view,
        "stored"
    );

    // bob 이 accepted 보고: alice 에게 중계, 서버 뷰 갱신
    b.send(&json!({"t": "status", "msg_id": rid, "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["state"], "accepted");
    assert_eq!(st["msg_id"], rid.as_str());
    // 낮은 rank 는 서버 뷰에 반영되지 않는다(중계는 된다 — 발신 코어가 rank 규칙으로 무시)
    b.send(&json!({"t": "status", "msg_id": rid, "state": "pending", "abort_reason": "turn_ended", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["state"], "pending");
    assert!(
        st.get("abort_reason").is_none(),
        "aborted 가 아니면 abort_reason 을 붙이지 않는다"
    );
    assert_eq!(
        h.app.db.header(&rid).unwrap().unwrap().sender_view,
        "accepted"
    );

    // S-FORGE-7: carol 이 남의 스레드에 reply_to 로 끼어들기
    let intrude = msg(
        &h,
        &carol,
        "carol@local/x",
        "reply",
        alice_sess,
        re.clone(),
        "끼어들기",
    );
    assert_eq!(send_expect(&mut c, &intrude).await["reason"], "unroutable");
    // 원 발신자(alice)가 자기 메시지에 reply(방향 반대)
    let wrong_dir = msg(
        &h,
        &alice,
        alice_sess,
        "reply",
        "bob@local/backend",
        re.clone(),
        "역방향",
    );
    assert_eq!(
        send_expect(&mut a, &wrong_dir).await["reason"],
        "unroutable"
    );
    // 원 발신 세션이 아닌 alice 의 다른 주소로
    let wrong_to = msg(
        &h,
        &bob,
        "bob@local/backend",
        "reply",
        "alice@local/other",
        re.clone(),
        "x",
    );
    assert_eq!(send_expect(&mut b, &wrong_to).await["reason"], "unroutable");

    // 정상 회신
    let ok = msg(
        &h,
        &bob,
        "bob@local/backend",
        "reply",
        alice_sess,
        re.clone(),
        "스키마는 #76",
    );
    assert_eq!(send_expect(&mut b, &ok).await["t"], "ack");
    let d = a.recv().await;
    assert_eq!(d["t"], "deliver");
    assert_eq!(d["message"]["reply_to"], rid.as_str());
    // reply 에는 status 가 없다(읽음은 chat 만, #308) — 받은 alice 의 read 도, 보낸 bob 의 상태도 거부.
    a.send(&json!({"t": "status", "msg_id": mid(&ok), "state": "read", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(a.recv().await["t"], "error");
    b.send(&json!({"t": "status", "msg_id": mid(&ok), "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(b.recv().await["t"], "error");
    // request 에는 read 가 없다.
    b.send(&json!({"t": "status", "msg_id": rid, "state": "read", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(b.recv().await["t"], "error");

    // 비공개로 바꿔도 rejected 는 상태 검사 없이 통과
    b.send(&json!({"t": "session.unpublish", "slug": "backend"}))
        .await;
    for cl in [&mut a, &mut b, &mut c] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    b.send(&json!({"t": "status", "msg_id": rid, "state": "rejected", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(a.recv().await["state"], "rejected");
    let rej = msg(
        &h,
        &bob,
        "bob@local/backend",
        "rejected",
        alice_sess,
        re.clone(),
        "바쁨",
    );
    assert_eq!(send_expect(&mut b, &rej).await["t"], "ack");
    let _ = a.recv().await; // rejected deliver
                            // rejected·system 에도 status 가 없다(#308 — kind 별 허용이 다른 kind 로 새지 않는다).
    let sys = msg(
        &h,
        &bob,
        "bob@local/backend",
        "system",
        alice_sess,
        json!({"reply_to": rid, "thread_id": rid, "reason": "aborted", "abort_reason": "turn_ended"}),
        "",
    );
    assert_eq!(send_expect(&mut b, &sys).await["t"], "ack");
    let _ = a.recv().await; // system deliver
    for id in [mid(&rej), mid(&sys)] {
        a.send(&json!({"t": "status", "msg_id": id, "state": "read", "at": now_str(&h, 0)}))
            .await;
        assert_eq!(a.recv().await["t"], "error", "{id}");
    }
    b.expect_silence().await;
    // 종료(rejected) 뒤 reply 는 거부
    let late = msg(
        &h,
        &bob,
        "bob@local/backend",
        "reply",
        alice_sess,
        re,
        "늦음",
    );
    assert_eq!(send_expect(&mut b, &late).await["reason"], "unroutable");
}

#[tokio::test(flavor = "multi_thread")]
async fn aborted_turn_ended_still_accepts_late_reply() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    publish(&mut b, "be", "question").await;
    let _ = a.recv().await;
    let _ = b.recv().await;

    for (reason, accepted) in [("turn_ended", true), ("owner_aborted", false)] {
        let req = msg(
            &h,
            &alice,
            &alice.address(),
            "request",
            "bob@local/be",
            json!({"grade": "question"}),
            "q",
        );
        assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
        assert_eq!(b.recv().await["t"], "deliver");
        let rid = mid(&req);
        b.send(&json!({"t": "status", "msg_id": rid, "state": "aborted", "abort_reason": reason, "at": now_str(&h, 0)}))
            .await;
        let st = a.recv().await;
        assert_eq!(st["state"], "aborted");
        assert_eq!(st["abort_reason"], reason);
        let late = msg(
            &h,
            &bob,
            "bob@local/be",
            "reply",
            &alice.address(),
            json!({"reply_to": rid}),
            "늦은 회신",
        );
        let r = send_expect(&mut b, &late).await;
        if accepted {
            assert_eq!(r["t"], "ack", "{reason}");
            assert_eq!(a.recv().await["t"], "deliver");
        } else {
            assert_eq!(r["reason"], "unroutable", "{reason}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_deletes_header_and_notifies_sender() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    publish(&mut b, "be", "question").await;
    let _ = a.recv().await;
    let _ = b.recv().await;
    let req = msg(
        &h,
        &alice,
        &alice.address(),
        "request",
        "bob@local/be",
        json!({"grade": "question"}),
        "q",
    );
    assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
    let _ = b.recv().await;
    let rid = mid(&req);

    assert_eq!(h.app.expire_tick(), 0, "아직 안 지남");
    h.fx.clock.advance(24 * 3600 * 1000);
    assert_eq!(h.app.expire_tick(), 1);
    let st = a.recv().await;
    assert_eq!(st["state"], "expired");
    assert_eq!(st["msg_id"], rid.as_str());
    assert!(h.app.db.header(&rid).unwrap().is_none(), "헤더 삭제");

    // 헤더가 없으니 reply 는 거부
    let late = msg(
        &h,
        &bob,
        "bob@local/be",
        "reply",
        &alice.address(),
        json!({"reply_to": rid}),
        "x",
    );
    assert_eq!(send_expect(&mut b, &late).await["reason"], "unroutable");
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_is_org_scoped_and_lists_public_sessions() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&json!({"t": "session.publish", "slug": "backend", "grade": "task", "liveness": "live:channel", "display": "서버 작업"}))
        .await;
    let upd = a.recv().await;
    assert_eq!(upd["t"], "directory.update");
    let _ = b.recv().await;
    a.send(&json!({"t": "directory.list"})).await;
    let d = a.recv().await;
    assert_eq!(d["t"], "directory");
    // #132: 사람 항목에 기기 공개키. device_id 는 ed25519 의 지문과 같아야 한다(수신 코어가 재계산해 대조).
    let key_entry = |u: &User| {
        json!({
            "device_id": u.device_id,
            "device_pubkeys": device_pubkeys(&u.keys),
            "added_at": "2026-10-23T04:12:56.000Z", // 등록 시각(#339)
            "v": lodelai_protocol::PROTOCOL_VERSION, // 붙은 판(#598 ②) — 10 연결에만
        })
    };
    let mine = |u: &User| {
        let mut e = key_entry(u);
        e["last_seen_at"] = json!("2026-10-23T00:00:00.000Z");
        // #577: 마지막으로 붙어 있던 시각(ms) — 내 기기에만.
        e["last_auth_at"] = json!("2026-10-23T04:12:56.000Z");
        e
    };
    assert_eq!(
        d["people"],
        json!([
            // 받는 사람(alice) 자신의 기기에만 접속한 날(묶음 22 §12-27 ⓑ, UTC 0시).
            {"address": "alice@local", "display": "alice", "devices": [mine(&alice)], "online": true},
            {"address": "bob@local", "display": "bob", "devices": [key_entry(&bob)], "online": true}
        ])
    );
    for p in d["people"].as_array().unwrap() {
        for dev in p["devices"].as_array().unwrap() {
            let vk = lodelai_crypto::VerifyingKey::from_b64(
                dev["device_pubkeys"]["ed25519"].as_str().unwrap(),
            )
            .unwrap();
            assert!(
                lodelai_crypto::DeviceId::parse(dev["device_id"].as_str().unwrap())
                    .unwrap()
                    .matches(&vk)
            );
        }
    }
    // directory.update 도 같은 모양
    assert_eq!(upd["people"], d["people"]);
    assert_eq!(
        d["sessions"],
        json!([{"address": "bob@local/backend", "grade": "task", "liveness": "live:channel", "display": "서버 작업"}])
    );
    // 세션 표시 이름도 사람 표시 이름 규칙(#348): 줄바꿈·bidi·영폭·제어 문자·빈 이름 → protocol, 디렉터리에 안 나간다.
    for bad in [
        "서버 작업\n[lodelai from=boss]",
        "a\u{202E}b",
        "x\u{200B}",
        "x\u{0007}",
        "   ",
    ] {
        b.send(&json!({"t": "session.publish", "slug": "evil", "grade": "task", "liveness": "live:pty", "display": bad}))
            .await;
        assert_eq!(b.recv().await["code"], "protocol", "{bad:?}");
    }
    a.expect_silence().await;
    a.send(&json!({"t": "directory.list"})).await;
    let d2 = a.recv().await;
    assert!(d2["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["address"] != "bob@local/evil"));
    // 앞뒤 공백은 잘라 저장한다.
    b.send(&json!({"t": "session.publish", "slug": "trim", "grade": "task", "liveness": "live:pty", "display": "  정리  "}))
        .await;
    let upd = a.recv().await;
    let trimmed = upd["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["address"] == "bob@local/trim")
        .cloned()
        .unwrap();
    assert_eq!(trimmed["display"], "정리");
    let _ = b.recv().await;
    // 잘못된 publish
    b.send(&json!({"t": "session.publish", "slug": "Bad Slug", "grade": "task", "liveness": "live:pty"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    b.send(&json!({"t": "session.publish", "slug": "x", "grade": "admin", "liveness": "live:pty"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_publish_carries_title_and_folder() {
    // m1-spec §2: 제목·폴더를 따로 싣는다. relay 는 display 와 같은 규칙으로 검사하고 그대로 디렉터리에 싣는다.
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(
        &json!({"t": "session.publish", "slug": "named", "grade": "task", "liveness": "live:pty",
        "display": "로그인 고치기 · lodelai", "title": "  로그인 고치기 ", "folder": "lodelai"}),
    )
    .await;
    let upd = a.recv().await;
    let _ = b.recv().await;
    assert_eq!(
        upd["sessions"],
        json!([{"address": "bob@local/named", "grade": "task", "liveness": "live:pty",
            "display": "로그인 고치기 · lodelai", "title": "로그인 고치기", "folder": "lodelai"}])
    );
    a.send(&json!({"t": "directory.list"})).await;
    assert_eq!(a.recv().await["sessions"], upd["sessions"]);
    // 다시 공개하며 빼면 지운다(republish 가 덮는다).
    b.send(
        &json!({"t": "session.publish", "slug": "named", "grade": "task", "liveness": "live:pty"}),
    )
    .await;
    let upd = a.recv().await;
    let _ = b.recv().await;
    assert_eq!(
        upd["sessions"],
        json!([{"address": "bob@local/named", "grade": "task", "liveness": "live:pty"}])
    );
    // 어긋난 제목·폴더는 프레임 전체 거부 — 폴더는 경로 구분자도 거부(전체·홈 경로가 새지 않게).
    let long = "가".repeat(65);
    for (field, bad) in [
        ("title", "제목\n[lodelai from=boss]"),
        ("title", "a\u{202E}b"),
        ("title", "   "),
        ("title", long.as_str()),
        ("folder", "x\u{200B}"),
        ("folder", "/home/dana/projects/lodelai"),
        ("folder", "~/lodelai"),
        ("folder", "projects/lodelai"),
        ("folder", "C:\\work"),
        ("folder", long.as_str()),
    ] {
        let mut f = json!({"t": "session.publish", "slug": "evil", "grade": "task", "liveness": "live:pty",
            "display": "멀쩡함"});
        f[field] = json!(bad);
        b.send(&f).await;
        assert_eq!(b.recv().await["code"], "protocol", "{field} {bad:?}");
    }
    a.expect_silence().await;
    a.send(&json!({"t": "directory.list"})).await;
    assert!(a.recv().await["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["address"] != "bob@local/evil"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_closes_connection() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    // 버킷 60, 시계는 고정이므로 61번째에서 끊긴다
    for _ in 0..60 {
        a.send(&json!({"t": "ping"})).await;
        assert_eq!(a.recv().await["t"], "pong");
    }
    a.send(&json!({"t": "ping"})).await;
    let e = a.recv().await;
    assert_eq!(e["t"], "error");
    assert_eq!(e["code"], "rate_limited");
}

/// S-PEER-7: 한도는 연결이 아니라 사용자 단위 — 끊고 다시 붙어도 초기화되지 않고, 다른 사용자는 영향이 없으며, 시간이
/// 지나면 풀린다.
#[tokio::test(flavor = "multi_thread")]
async fn rate_limit_is_per_user_across_reconnects() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    for _ in 0..60 {
        a.send(&json!({"t": "ping"})).await;
        assert_eq!(a.recv().await["t"], "pong");
    }
    a.send(&json!({"t": "ping"})).await;
    assert_eq!(a.recv().await["code"], "rate_limited");
    drop(a);

    // 다시 붙어도(핸드셰이크 프레임은 한도 밖) 첫 프레임부터 한도에 걸린다.
    let (mut a2, _) = connect(&h, &alice).await;
    a2.send(&json!({"t": "ping"})).await;
    assert_eq!(a2.recv().await["code"], "rate_limited");
    // 다른 사용자는 영향이 없다.
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&json!({"t": "ping"})).await;
    assert_eq!(b.recv().await["t"], "pong");
    // 시간이 지나면 풀린다.
    h.fx.clock.advance(5_000);
    let (mut a3, _) = connect(&h, &alice).await;
    a3.send(&json!({"t": "ping"})).await;
    assert_eq!(a3.recv().await["t"], "pong");
}

#[tokio::test(flavor = "multi_thread")]
async fn server_pings_and_closes_silent_connections() {
    let h = start_with(|c| {
        c.ping_interval = Duration::from_millis(100);
        c.idle_timeout = Duration::from_millis(350);
    })
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    // pong 으로 답하는 동안은 유휴 한도를 여러 번 넘겨도 붙어 있다
    for _ in 0..8 {
        assert_eq!(a.recv().await["t"], "ping");
        a.send(&json!({"t": "pong"})).await;
    }
    // 답하지 않으면 끊긴다(서버 ping 은 그 전까지 계속 온다)
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match a.ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    assert_eq!(serde_json::from_str::<Value>(&t).unwrap()["t"], "ping");
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "말 없는 연결이 끊기지 않았다");
    assert!(!h.app.conns.is_online("alice"));
}

#[tokio::test(flavor = "multi_thread")]
async fn schema_invalid_frames_are_rejected_before_rules() {
    // 경계에서 ws::Frame(생성 타입) 스키마 검사: 서명이 맞아도 형식이 틀리면 규칙·저장에 닿지 않는다.
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;

    // 시각 정규형이 아님(밀리초 없음) — 서명은 그 바이트로 정상 서명
    let mut m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "x",
    );
    m["created_at"] = json!("2026-10-23T04:12:56Z");
    sign_message(&mut m, &alice.keys.signing).unwrap();
    let r = send_expect(&mut a, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["code"].as_str()),
        (Some("error"), Some("protocol"))
    );
    assert_eq!(
        r["ref"],
        mid(&m),
        "보낸 쪽이 큐에서 뺄 수 있게 ref = msg_id"
    );

    // 모르는 필드(additionalProperties:false)
    let mut m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "x",
    );
    m["surprise"] = json!(1);
    sign_message(&mut m, &alice.keys.signing).unwrap();
    assert_eq!(send_expect(&mut a, &m).await["code"], "protocol");

    // 서버 전용 프레임을 클라이언트가 보냄
    a.send(&json!({"t": "ack", "msg_id": "01JB0000000000000000000001"}))
        .await;
    assert_eq!(a.recv().await["code"], "protocol");

    b.expect_silence().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn fail_reason_is_relayed_only_with_failed() {
    // #134: 상대에게 가는 실패 사유는 코드. relay 는 state=failed 일 때만 fail_reason 을 중계한다.
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    publish(&mut b, "be", "question").await;
    let _ = a.recv().await;
    let _ = b.recv().await;
    let req = msg(
        &h,
        &alice,
        &alice.address(),
        "request",
        "bob@local/be",
        json!({"grade": "question"}),
        "q",
    );
    assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
    let _ = b.recv().await;
    let rid = mid(&req);

    b.send(&json!({"t": "status", "msg_id": rid, "state": "pending", "fail_reason": "bad_signature", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["state"], "pending");
    assert!(
        st.get("fail_reason").is_none(),
        "failed 가 아니면 붙이지 않는다"
    );

    b.send(&json!({"t": "status", "msg_id": rid, "state": "failed", "fail_reason": "bad_signature", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["state"], "failed");
    assert_eq!(st["fail_reason"], "bad_signature");

    // 모르는 코드는 스키마에서 거부
    b.send(&json!({"t": "status", "msg_id": rid, "state": "failed", "fail_reason": "free text", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
}

/// #308: status 허용은 헤더 kind 로 가른다. chat 은 수신자의 `read` 만 — 서버 뷰는 그대로, 발신자에게 중계만.
/// 발신자의 chat status·사유 붙은 read·request 상태 이름은 거부, reply 에 대한 status 도 거부.
#[tokio::test(flavor = "multi_thread")]
async fn chat_read_is_relayed_from_recipient_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "점심?",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let id = mid(&m);
    let view = |h: &Harness| h.app.db.header(&id).unwrap().unwrap().sender_view;
    let before = view(&h);

    // 수신자의 read → 발신자에게 그대로.
    b.send(&json!({"t": "status", "msg_id": id, "state": "read", "at": now_str(&h, 0)}))
        .await;
    let st = a.recv().await;
    assert_eq!(st["t"], "status");
    assert_eq!(st["state"], "read");
    assert_eq!(st["msg_id"], id.as_str());
    assert_eq!(view(&h), before, "서버 뷰는 바꾸지 않는다");

    // 거부: 발신자의 read, 사유 붙은 read, chat 에 request 상태 이름.
    for (from_sender, f) in [
        (
            true,
            json!({"t": "status", "msg_id": id, "state": "read", "at": now_str(&h, 0)}),
        ),
        (
            false,
            json!({"t": "status", "msg_id": id, "state": "read", "abort_reason": "turn_ended", "at": now_str(&h, 0)}),
        ),
        (
            false,
            json!({"t": "status", "msg_id": id, "state": "accepted", "at": now_str(&h, 0)}),
        ),
    ] {
        let cl = if from_sender { &mut a } else { &mut b };
        cl.send(&f).await;
        assert_eq!(cl.recv().await["t"], "error", "{f}");
    }
    // `at` 형식 오류도 거부, 중계 없음.
    b.send(&json!({"t": "status", "msg_id": id, "state": "read", "at": "어제"}))
        .await;
    assert_eq!(b.recv().await["t"], "error");
    a.expect_silence().await;
    b.expect_silence().await;

    // 같은 read 두 번: relay 는 거르지 않고 두 번 중계한다(한 번만 보내는 것은 relay-client 아웃박스 키).
    for _ in 0..2 {
        b.send(&json!({"t": "status", "msg_id": id, "state": "read", "at": now_str(&h, 0)}))
            .await;
        assert_eq!(a.recv().await["state"], "read");
    }

    // 발신자가 오프라인이면 조용히 버린다 — 수신자에게 오류 없음, 서버 뷰 그대로, 다시 붙어도 오지 않는다(M1).
    drop(a);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    b.send(&json!({"t": "status", "msg_id": id, "state": "read", "at": now_str(&h, 0)}))
        .await;
    b.expect_silence().await;
    assert_eq!(view(&h), before);
    let (mut a2, _) = connect(&h, &alice).await;
    a2.expect_silence().await;
}

/// #315·#313: 프레임 상한(`WS_MAX_FRAME_BYTES`, v1 은 49 152) — 상한 안의 큰 정상 프레임은 통과하고, 상한을 넘는 프레임은
/// **그 연결만** 닫힌다. 다른 연결은 그대로, 닫힌 사용자는 다시 붙어 이어 보낸다.
#[tokio::test(flavor = "multi_thread")]
async fn frame_limit_closes_only_the_offending_connection() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;

    // 상한 안의 가장 큰 chat(32 KiB 봉투, base64 로 약 44 KB)은 통과한다.
    let big = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        &"\u{1}".repeat(CHAT_MAX),
    );
    assert_eq!(send_expect(&mut a, &big).await["t"], "ack");
    assert_eq!(b.recv().await["message"]["body"], big["body"]);

    // 상한을 넘는 프레임 → 그 연결이 닫힌다(텍스트 응답 없음).
    let max = lodelai_protocol::constants::WS_MAX_FRAME_BYTES as usize;
    a.ws.send(Message::Text("x".repeat(max + 1).into()))
        .await
        .unwrap();
    let next = tokio::time::timeout(Duration::from_secs(3), a.ws.next())
        .await
        .expect("닫힘 대기");
    assert!(!matches!(next, Some(Ok(Message::Text(_)))), "{next:?}");

    // 다른 연결은 그대로(오프라인 alice 앞 chat 은 보관 ack).
    let m = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &alice.address(),
        json!({}),
        "괜찮아?",
    );
    assert_eq!(send_expect(&mut b, &m).await["t"], "ack");
    // alice 는 다시 붙어 보관된 것을 받고 이어 보낸다.
    let (mut a2, _) = connect(&h, &alice).await;
    assert_eq!(a2.recv().await["message"]["msg_id"], m["msg_id"]);
    let again = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "응",
    );
    assert_eq!(send_expect(&mut a2, &again).await["t"], "ack");
}

// ------------------------------------------------------------------ 표시 이름·기기 폐기 (#325·#326)

impl Client {
    /// 서버가 연결을 닫을 때까지 텍스트 프레임을 버린다. 받은 텍스트 프레임들.
    /// 받은 것을 모은 뒤(앱처럼) 이쪽에서 닫고, relay 가 닫을 때까지 남은 것도 모은다.
    async fn drain_until_closed_after_close(&mut self) -> Vec<Value> {
        let mut got = Vec::new();
        while let Ok(Some(Ok(m))) =
            tokio::time::timeout(Duration::from_millis(500), self.ws.next()).await
        {
            if let Message::Text(t) = m {
                got.push(serde_json::from_str(&t).unwrap());
            }
        }
        let _ = self.ws.close(None).await;
        got.extend(self.drain_until_closed().await);
        got
    }

    async fn drain_until_closed(&mut self) -> Vec<Value> {
        let mut got = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(3), self.ws.next())
                .await
                .expect("닫힘 대기 시간 초과")
            {
                Some(Ok(Message::Text(t))) => got.push(serde_json::from_str(&t).unwrap()),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_)) | Err(_)) | None => return got,
                Some(Ok(other)) => panic!("예상 밖 프레임: {other:?}"),
            }
        }
    }
}

async fn register_extra_device(h: &Harness, name: &str, seed: u8) -> User {
    let keys = DeviceKeys::generate(&[seed; 64]);
    let mut body: Value = serde_json::from_str(&register_body(name, &keys)).unwrap();
    body["existing_user"] = json!(true);
    let auth = format!("Bearer {TOKEN}");
    let (code, resp) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &body.to_string(),
    )
    .await;
    assert_eq!(code, 201, "{resp}");
    User {
        name: name.into(),
        device_id: keys.device_id().as_str().to_owned(),
        keys,
    }
}

fn people_display(d: &Value, address: &str) -> Value {
    d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == address)
        .map(|p| p["display"].clone())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_update_broadcasts_trimmed_name_and_rejects_bad_names() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;

    b.send(&json!({"t": "profile.update", "display_name": "  밥 Bob  "}))
        .await;
    // 성공 응답은 없다 — 같은 조직의 모든 연결(자기 포함)에 directory.update.
    for c in [&mut a, &mut b] {
        let upd = c.recv().await;
        assert_eq!(upd["t"], "directory.update");
        assert_eq!(people_display(&upd, "bob@local"), "밥 Bob");
    }
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(people_display(&b.recv().await, "bob@local"), "밥 Bob");

    // 규칙 위반은 error{protocol}(ref 없음), 이름은 그대로, 방송 없음.
    for bad in [
        json!(""),
        json!("   "),
        json!("가".repeat(65)),
        json!("bob\u{202E}evil"),
        json!("bob\u{200B}"),
        json!("bob\u{0007}"),
    ] {
        b.send(&json!({"t": "profile.update", "display_name": bad}))
            .await;
        let e = b.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{bad}"
        );
        assert!(e.get("ref").is_none());
    }
    // 남의 이름을 바꾸는 필드는 없다 — 더 붙이면 형식 오류.
    b.send(&json!({"t": "profile.update", "display_name": "x", "user": "alice"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    a.expect_silence().await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = b.recv().await;
    assert_eq!(people_display(&d, "bob@local"), "밥 Bob");
    assert_eq!(people_display(&d, "alice@local"), "alice");
}

/// 그 디렉터리에서 그 기기 항목의 이름.
fn device_name_in(d: &Value, address: &str, device_id: &str) -> Option<String> {
    d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == address)
        .and_then(|p| {
            p["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["device_id"] == device_id)
        })
        .and_then(|x| x["name"].as_str().map(str::to_owned))
}

/// #490 묶음 28 §4: 기기 이름은 본인 디렉터리에만 실리고, 바꾸면 본인 연결들에만 directory.update. NFC·숨은 문자 거절,
/// 같은 값이면 방송 안 함, 지우기는 빈 값(폐기 때 지우기는 db 단위 시험).
#[tokio::test(flavor = "multi_thread")]
async fn device_name_is_only_in_my_own_directory_entry() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a1, _) = connect(&h, &alice).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    let (mut b, _) = connect(&h, &bob).await;

    // 조합형 한글은 NFC 로, 앞뒤 공백은 뺀다.
    a1.send(&json!({"t": "device.name", "name": "  \u{1112}\u{1161}\u{11ab} 맥북 "}))
        .await;
    for c in [&mut a1, &mut a2] {
        let upd = c.recv().await;
        assert_eq!(upd["t"], "directory.update");
        assert_eq!(
            device_name_in(&upd, "alice@local", &alice.device_id).as_deref(),
            Some("한 맥북")
        );
        assert_eq!(device_name_in(&upd, "alice@local", &alice2.device_id), None);
    }
    b.expect_silence().await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = b.recv().await;
    assert_eq!(
        device_name_in(&d, "alice@local", &alice.device_id),
        None,
        "동료 디렉터리엔 없음"
    );

    // 같은 값(NFC 뒤 같음) 두 번 → 방송 없음.
    a1.send(&json!({"t": "device.name", "name": "한 맥북"}))
        .await;
    a1.expect_silence().await;
    a2.expect_silence().await;

    // 숨은 문자·제어 문자·너무 긴 이름은 error{protocol}, 이름은 그대로.
    for bad in [
        json!("맥\u{202E}북"),
        json!("맥\u{200B}"),
        json!("a\nb"),
        json!("가".repeat(65)),
    ] {
        a1.send(&json!({"t": "device.name", "name": bad})).await;
        let e = a1.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{bad}"
        );
    }
    a2.expect_silence().await;

    // 빈 값 = 지우기.
    a1.send(&json!({"t": "device.name", "name": ""})).await;
    let upd = a2.recv().await;
    assert_eq!(device_name_in(&upd, "alice@local", &alice.device_id), None);
    let _ = a1.recv().await;
}

/// 기기당 시간당 DEVICE_NAME_PER_HOUR 번 넘게 바꾸면 error{rate_limited}(조용히 버리지 않음).
#[tokio::test(flavor = "multi_thread")]
async fn device_name_changes_are_rate_limited_per_device() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    let n = lodelai_protocol::constants::DEVICE_NAME_PER_HOUR;
    for i in 0..n {
        a.send(&json!({"t": "device.name", "name": format!("맥 {i}")}))
            .await;
        assert_eq!(a.recv().await["t"], "directory.update", "{i}");
    }
    a.send(&json!({"t": "device.name", "name": "하나 더"}))
        .await;
    let e = a.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("rate_limited"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_display_name_uses_same_rule() {
    let h = start().await;
    let auth = format!("Bearer {TOKEN}");
    for (i, bad) in ["", "  ", "a\u{202E}b"].into_iter().enumerate() {
        let keys = DeviceKeys::generate(&[40 + u8::try_from(i).unwrap(); 64]);
        let mut body: Value = serde_json::from_str(&register_body("carol", &keys)).unwrap();
        body["display_name"] = json!(bad);
        let (code, _) = http(
            h.addr,
            "POST",
            "/v1/devices",
            &[
                ("Content-Type", "application/json"),
                ("Authorization", &auth),
            ],
            &body.to_string(),
        )
        .await;
        assert_eq!(code, 400, "{bad:?}");
    }
    // 앞뒤 공백은 잘라 저장한다.
    let keys = DeviceKeys::generate(&[50; 64]);
    let mut body: Value = serde_json::from_str(&register_body("carol", &keys)).unwrap();
    body["display_name"] = json!("  캐럴 ");
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &body.to_string(),
    )
    .await;
    assert_eq!(code, 201);
    let carol = User {
        name: "carol".into(),
        device_id: keys.device_id().as_str().to_owned(),
        keys,
    };
    let (mut c, _) = connect(&h, &carol).await;
    c.send(&json!({"t": "directory.list"})).await;
    assert_eq!(people_display(&c.recv().await, "carol@local"), "캐럴");
}

#[tokio::test(flavor = "multi_thread")]
async fn device_revoke_answers_broadcasts_closes_and_blocks_auth() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;

    // bob 이 꺼져 있는 동안 쌓인 본문.
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "쌓인 본문",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");

    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b.recv().await["t"], "deliver"); // ack 하지 않는다 — 본문은 아직 서버에
                                                // 같은 기기의 둘째 연결도 폐기와 함께 닫혀야 한다.
    let (mut b_again, _) = connect(&h, &bob).await;
    assert_eq!(b_again.recv().await["t"], "deliver");

    // 공개 세션도 마지막 기기 폐기와 함께 내려간다(QA #334-1).
    publish(&mut b, "backend", "task").await;
    // 공개는 자기 자신(같은 기기의 두 연결 포함)에게도 directory.update 로 온다 — 비우고 폐기한다.
    for c in [&mut b, &mut b_again] {
        while c.recv().await["t"] != "directory.update" {}
    }
    loop {
        let u = a.recv().await;
        if u["t"] == "directory.update" && u["sessions"].as_array().is_some_and(|s| !s.is_empty()) {
            break;
        }
    }

    b.send(&json!({"t": "device.revoke"})).await;
    // 순서 고정: device.revoked → (같은 조직의) directory.update → 닫힘.
    let got = b.drain_until_closed().await;
    assert_eq!(
        got.first().map(|f| f["t"].clone()),
        Some(json!("device.revoked"))
    );
    assert!(
        got.iter().skip(1).all(|f| f["t"] == "directory.update"),
        "{got:?}"
    );
    b_again.drain_until_closed().await;

    // 동료에게: bob 은 남고 기기는 빈 목록.
    let upd = a.recv().await;
    assert_eq!(upd["t"], "directory.update");
    let bob_entry = upd["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "bob@local")
        .cloned()
        .unwrap();
    assert_eq!(bob_entry["devices"], json!([]));
    assert_eq!(upd["sessions"], json!([]), "유령 세션이 남지 않는다");

    // 남은 기기가 없으니 쌓인 본문은 지웠다(헤더는 만료까지 남는다).
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());
    assert!(h.app.db.header(&mid(&m)).unwrap().is_some());

    // 기기가 0대인 사람에게 새로 보낸 것은 없는 사람과 같은 unroutable 이고 쌓이지 않는다(QA #334-2).
    let late = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "폐기 뒤",
    );
    let r = send_expect(&mut a, &late).await;
    assert_eq!(
        (r["t"].as_str(), r["reason"].as_str()),
        (Some("nack"), Some("unroutable"))
    );
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());

    // 폐기된 기기가 자기 키로 맞게 서명하면 그 기기에만 device_revoked(#339 — 비밀키를 가진 쪽만 안다).
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": bob.device_id, "user": bob.name}))
        .await;
    let ch = c.recv().await;
    let sig = sign_challenge(
        &bob.keys.signing,
        SERVER,
        &bob.device_id,
        ch["nonce"].as_str().unwrap(),
    )
    .unwrap();
    c.send(&json!({"t": "auth", "sig": sig})).await;
    let e = c.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("device_revoked"))
    );
    // 끊긴 시각(#577) — 다시 붙은 기기가 '언제 끊겼나'를 보인다.
    assert_eq!(e["at"], now_str(&h, 0), "{e}");
    // 서명이 틀리면(남이 그 device_id 를 대면) 모르는 기기와 같은 응답.
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": bob.device_id, "user": bob.name}))
        .await;
    let ch = c.recv().await;
    let forged = sign_challenge(
        &alice.keys.signing,
        SERVER,
        &bob.device_id,
        ch["nonce"].as_str().unwrap(),
    )
    .unwrap();
    c.send(&json!({"t": "auth", "sig": forged})).await;
    let e = c.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("protocol"))
    );

    // 같은 기기 키로 다시 등록할 수 없다(새 기기 = 새 키).
    let auth = format!("Bearer {TOKEN}");
    let mut body: Value = serde_json::from_str(&register_body("bob", &bob.keys)).unwrap();
    body["existing_user"] = json!(true);
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &body.to_string(),
    )
    .await;
    assert_ne!(code, 201);
}

#[tokio::test(flavor = "multi_thread")]
async fn device_revoke_keeps_other_devices_and_their_mail() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "둘째 기기가 받을 것",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");

    let (mut b, _) = connect(&h, &bob).await;
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(&json!({"t": "device.revoke"})).await;
    assert_eq!(b.drain_until_closed().await[0]["t"], "device.revoked");

    let upd = a.recv().await;
    let devices: Vec<Value> = upd["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "bob@local")
        .unwrap()["devices"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"], bob2.device_id);

    // 남은 기기는 쌓인 본문을 그대로 받는다.
    let (mut b2, ready) = connect(&h, &bob2).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b2.recv().await["message"]["msg_id"], mid(&m));

    // 다른 기기의 연결로 폐기된 기기의 서명을 실어 보내도 auth nack(규칙 1 — from.device_id ≠ 인증 기기). 폐기 기기 자체의
    // 차단 근거는 위 시험의 핸드셰이크 거부와 device() 가 폐기 기기를 모르는 것이다.
    let forged = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &alice.address(),
        json!({}),
        "폐기 뒤",
    );
    let r = send_expect(&mut b2, &forged).await;
    assert_eq!(
        (r["t"].as_str(), r["reason"].as_str()),
        (Some("nack"), Some("auth")),
        "{r}"
    );
}

// ------------------------------------------------------------------ 주인 앱 전용 조회·정리 (#328)

#[tokio::test(flavor = "multi_thread")]
async fn connected_lists_users_with_live_connections_and_needs_token() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let _bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (_a, _) = connect(&h, &alice).await;
    let (_c, _) = connect(&h, &carol).await;
    let auth = format!("Bearer {TOKEN}");
    let (code, body) = http(
        h.addr,
        "GET",
        "/v1/connected",
        &[("Authorization", &auth)],
        "",
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"users": ["alice", "carol"]})
    );
    for bad in [vec![], vec![("Authorization", "Bearer nope")]] {
        let (code, _) = http(h.addr, "GET", "/v1/connected", &bad, "").await;
        assert_eq!(code, 401);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wipe_deletes_everything_closes_connections_and_stops() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "지워질 본문",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");

    // 토큰 없으면 아무것도 안 한다.
    let (code, _) = http(h.addr, "POST", "/v1/wipe", &[], "").await;
    assert_eq!(code, 401);
    assert!(h.app.db.header(&mid(&m)).unwrap().is_some());

    let auth = format!("Bearer {TOKEN}");
    let (code, _) = http(h.addr, "POST", "/v1/wipe", &[("Authorization", &auth)], "").await;
    assert_eq!(code, 200);
    a.drain_until_closed().await;
    assert!(h.app.db.header(&mid(&m)).unwrap().is_none());
    assert!(h.app.db.people_in_org("local").unwrap().is_empty());
    assert!(h.app.db.device(&alice.device_id).unwrap().is_none());

    // 서버가 끝났다 — 곧 접속이 거부된다.
    let mut refused = false;
    for _ in 0..30 {
        if TcpStream::connect(h.addr).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "wipe 뒤에도 서버가 살아 있다");
}

// ------------------------------------------------------------------ E2E 봉투(#313 ②)

/// 서명만 다시(메시지를 손댄 뒤).
fn resign(m: &mut Value, from: &User) {
    m.as_object_mut().unwrap().remove("sig");
    sign_message(m, &from.keys.signing).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_requires_valid_x25519_sig() {
    let h = start().await;
    let auth = format!("Bearer {TOKEN}");
    let post = |body: String| {
        let auth = auth.clone();
        async move {
            http(
                h.addr,
                "POST",
                "/v1/devices",
                &[
                    ("Content-Type", "application/json"),
                    ("Authorization", &auth),
                ],
                &body,
            )
            .await
            .0
        }
    };
    let k = DeviceKeys::generate(&[1; 64]);
    let other = DeviceKeys::generate(&[2; 64]);
    let with = |pk: Value| json!({"user": "alice", "device_pubkeys": pk}).to_string();
    let mut no_sig = device_pubkeys(&k);
    no_sig.as_object_mut().unwrap().remove("x25519_sig");
    assert_eq!(post(with(no_sig)).await, 400, "서명 없음");
    let mut swapped = device_pubkeys(&k);
    swapped["x25519"] = json!(encoding::encode(&other.exchange.public_key()));
    assert_eq!(post(with(swapped)).await, 400, "x25519 바꿔 낌");
    let mut other_key = device_pubkeys(&k);
    other_key["x25519_sig"] = device_pubkeys(&other)["x25519_sig"].clone();
    assert_eq!(post(with(other_key)).await, 400, "다른 기기의 서명");
    assert_eq!(post(with(device_pubkeys(&k))).await, 201);
}

/// #313 ③(e2e-envelope §3.4·§8): v1 평문은 system 빈 본문뿐이다. 그 밖의 평문(chat·request·reply·rejected) 과 본문이 있는
/// system 평문은 형식 오류(`error{protocol, ref}`) — 다운그레이드 방지.
#[tokio::test(flavor = "multi_thread")]
async fn plaintext_is_only_empty_system() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (_b, _) = connect(&h, &bob).await;
    for kind in ["chat", "request", "reply", "rejected"] {
        let to = if kind == "request" {
            format!("{}/api", bob.address())
        } else {
            bob.address()
        };
        let mut m = msg(&h, &alice, &alice.address(), kind, &to, json!({}), "x");
        m["body"] = json!({"enc": "plain", "text": "평문 본문"});
        resign(&mut m, &alice);
        let r = send_expect(&mut a, &m).await;
        assert_eq!(
            (r["t"].as_str(), r["code"].as_str(), r["ref"].as_str()),
            (Some("error"), Some("protocol"), Some(mid(&m).as_str())),
            "{kind}: {r}"
        );
    }
    // system 에 본문이 있으면 형식 오류, 빈 본문이면 형식은 통과(뒤의 규칙으로 간다).
    let mut m = msg(
        &h,
        &alice,
        &alice.address(),
        "system",
        &bob.address(),
        json!({"reason": "expired", "reply_to": "01JB0000000000000000000001"}),
        "",
    );
    m["body"]["text"] = json!("사유 문장");
    resign(&mut m, &alice);
    assert_eq!(send_expect(&mut a, &m).await["code"], "protocol");
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "system",
        &bob.address(),
        json!({"reason": "expired", "reply_to": "01JB0000000000000000000001"}),
        "",
    );
    let r = send_expect(&mut a, &m).await;
    assert_ne!(r["code"], "protocol", "{r}");
}

/// e2e-envelope §1·§10: ack 뒤 relay DB·-wal 원시 바이트에 그 ct 가 없다(secure_delete + WAL 잘라내기).
#[tokio::test(flavor = "multi_thread")]
async fn delivered_ciphertext_is_gone_from_db_and_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    let h = start_db(|_| {}, Db::open(&path).unwrap()).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "카나리아 lodelai-canary-01JB",
    );
    let ct = m["body"]["payload"]["data"].as_str().unwrap().to_owned();
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    let raw = || {
        let mut all = Vec::new();
        for n in ["relay.sqlite3", "relay.sqlite3-wal"] {
            if let Ok(b) = std::fs::read(dir.path().join(n)) {
                all.extend(b);
            }
        }
        all
    };
    let has = |hay: &[u8]| hay.windows(ct.len()).any(|w| w == ct.as_bytes());
    assert!(has(&raw()), "대조군: 전달 전에는 보관 중이다");
    // bob 이 받아 ack
    let (mut b, _) = connect(&h, &bob).await;
    let d = b.recv().await;
    assert_eq!(d["t"], "deliver");
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    // ack 처리를 기다린다(같은 연결의 다음 요청은 앞 것 뒤에 처리된다)
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(b.recv().await["t"], "directory");
    assert!(!has(&raw()), "ack 뒤 DB·-wal 원시 바이트에 ct 가 남았다");
    // 평문 카나리아도 없다(봉투라 처음부터 없지만 함께 본다)
    let canary = "lodelai-canary-01JB".as_bytes();
    assert!(!raw().windows(canary.len()).any(|w| w == canary));
}

/// QA #323 보강: 전달 못 한 봉투가 **만료**로 지워질 때도 DB·-wal 에 ct 가 안 남는다(AC-OP-3 "만료 후 삭제" 경로).
#[tokio::test(flavor = "multi_thread")]
async fn expired_ciphertext_is_gone_from_db_and_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    let h = start_db(|_| {}, Db::open(&path).unwrap()).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "만료 카나리아 lodelai-canary-02",
    );
    let ct = m["body"]["payload"]["data"].as_str().unwrap().to_owned();
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    let raw = || {
        let mut all = Vec::new();
        for n in ["relay.sqlite3", "relay.sqlite3-wal"] {
            if let Ok(b) = std::fs::read(dir.path().join(n)) {
                all.extend(b);
            }
        }
        all
    };
    let has = |hay: &[u8]| hay.windows(ct.len()).any(|w| w == ct.as_bytes());
    assert!(has(&raw()), "대조군: 보관 중");
    // bob 은 한 번도 접속하지 않는다. 시간이 지나 만료.
    h.fx.clock.advance(8 * 24 * 3600 * 1000);
    assert!(h.app.expire_tick() >= 1);
    assert!(!has(&raw()), "만료로 지운 뒤에도 DB·-wal 에 ct 가 남았다");
}

// ------------------------------------------------------------------ hosted 가입·기기 추가·대상 지정 폐기 (#339)

/// 보낸 코드를 이메일별로 붙잡는 가짜 메일. 알림 메일(#577)은 (이메일, 제목)으로 차례로 적는다.
#[derive(Default)]
struct CaptureMailer(
    std::sync::Mutex<std::collections::HashMap<String, String>>,
    std::sync::Mutex<Vec<(String, String)>>,
);

impl lodelai_relay::mail::Mailer for CaptureMailer {
    fn send_code(&self, email: &str, code: &str, _locale: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(email.into(), code.into());
        Ok(())
    }

    fn send_text(&self, email: &str, subject: &str, _text: &str) -> Result<(), String> {
        self.1.lock().unwrap().push((email.into(), subject.into()));
        Ok(())
    }
}

async fn start_hosted() -> (Harness, std::sync::Arc<CaptureMailer>) {
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(|_| {}, Db::memory().unwrap(), Some(mail.clone())).await;
    (h, mail)
}

async fn post_json(h: &Harness, path: &str, body: &Value) -> (u16, String) {
    http(
        h.addr,
        "POST",
        path,
        &[("Content-Type", "application/json")],
        &body.to_string(),
    )
    .await
}

/// 가입 코드 요청 → 메일의 코드로 확인 → 가입 토큰.
async fn signup_token(h: &Harness, mail: &CaptureMailer, email: &str) -> String {
    let (code, _) = post_json(
        h,
        "/v1/signup",
        &json!({"email": email, "privacy": {"version": "test"}}),
    )
    .await;
    assert_eq!(code, 202);
    let sent = mail.0.lock().unwrap()[&email.to_lowercase()].clone();
    assert_eq!(sent.len(), 6);
    assert!(sent.bytes().all(|b| b.is_ascii_digit()));
    let (code, resp) = post_json(
        h,
        "/v1/signup/verify",
        &json!({"email": email, "code": sent}),
    )
    .await;
    assert_eq!(code, 200, "{resp}");
    serde_json::from_str::<Value>(&resp).unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn hosted_body(token: &str, user: Option<&str>, keys: &DeviceKeys) -> Value {
    let mut b = json!({"signup_token": token, "device_pubkeys": device_pubkeys(keys), "display_name": "새 이름"});
    if let Some(u) = user {
        b["user"] = json!(u);
        // 새 계정은 조직이 있어야 한다(#355). 기존 계정이면 서버가 무시한다.
        b["org"] = json!({"create": {"name": "루이보스"}});
    }
    b
}

#[tokio::test(flavor = "multi_thread")]
async fn hosted_email_code_adds_device_to_existing_account() {
    let (h, mail) = start_hosted().await;
    // 첫 가입: 새 계정.
    let token = signup_token(&h, &mail, "Dana@Example.com").await;
    let k1 = DeviceKeys::generate(&[1; 64]);
    let mut first_body = hosted_body(&token, Some("dana"), &k1);
    first_body["display_name"] = json!("다나");
    let (code, resp) = post_json(&h, "/v1/devices", &first_body).await;
    assert_eq!(code, 201, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["user"], "dana");
    assert!(
        v.get("added").is_none(),
        "새 계정은 added 를 싣지 않는다: {v}"
    );
    // 같은 토큰은 다시 못 쓴다(1회용).
    let k_reuse = DeviceKeys::generate(&[9; 64]);
    let (code, _) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &k_reuse)).await;
    assert_eq!(code, 401);

    let first = User {
        name: "dana".into(),
        device_id: k1.device_id().as_str().to_owned(),
        keys: k1,
    };
    let (mut c1, _) = connect(&h, &first).await;

    // 회사 맥: 같은 이메일로 코드만 받아 기기 추가. 다른 아이디를 대면 409 이고 토큰은 남는다(트랜잭션).
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "dana@example.com").await;
    let k2 = DeviceKeys::generate(&[2; 64]);
    let (code, _) = post_json(&h, "/v1/devices", &hosted_body(&token, Some("other"), &k2)).await;
    assert_eq!(code, 409);
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &k2)).await;
    assert_eq!(code, 201, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        (v["user"].as_str(), v["added"].as_bool()),
        (Some("dana"), Some(true))
    );
    // 표시 이름은 무시(계정은 그대로).
    assert_eq!(
        h.app
            .db
            .people_in_org(&h.app.db.user_org("dana").unwrap().unwrap())
            .unwrap(),
        vec![("dana".to_owned(), Some("다나".to_owned()))]
    );

    // 내 첫 기기는 directory.update 의 자기 devices[] 에서 새 기기를 본다(새 프레임 없음).
    let upd = c1.recv().await;
    assert_eq!(upd["t"], "directory.update");
    let mine = upd["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "dana@local")
        .unwrap()["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["device_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(mine.len(), 2);
    assert!(mine.contains(&k2.device_id().as_str().to_owned()));

    // 새 이메일인데 아이디가 남의 것이면 403, 아이디가 없으면 400.
    let token = signup_token(&h, &mail, "eve@example.com").await;
    let k3 = DeviceKeys::generate(&[3; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, Some("dana"), &k3))
            .await
            .0,
        403
    );
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, None, &k3))
            .await
            .0,
        400
    );
}

/// 같은 기기로 다시 가입(protocol §7.1, #389): 확인한 이메일 계정의 폐기 안 된 기기면 200 `added:false`(멱등, 토큰 소비,
/// 디렉터리 그대로). 그 밖은 409 `device_taken` 이고 토큰은 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_same_device_rejoin_is_idempotent_and_others_are_device_taken() {
    let (h, mail) = start_hosted().await;
    let token = signup_token(&h, &mail, "dana@example.com").await;
    let k1 = DeviceKeys::generate(&[1; 64]);
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, Some("dana"), &k1)).await;
    assert_eq!(code, 201, "{resp}");
    let dana = User {
        name: "dana".into(),
        device_id: k1.device_id().as_str().to_owned(),
        keys: k1,
    };
    let (mut c1, _) = connect(&h, &dana).await;

    // 서버를 바꿨다 돌아온 같은 기기: 200 added:false, 기기·디렉터리 그대로, 토큰은 썼다.
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "dana@example.com").await;
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &dana.keys)).await;
    assert_eq!(code, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        (
            v["user"].as_str(),
            v["device_id"].as_str(),
            v["added"].as_bool()
        ),
        (Some("dana"), Some(dana.device_id.as_str()), Some(false))
    );
    assert_eq!(h.app.db.devices_of("dana").unwrap().len(), 1);
    c1.expect_silence().await;
    let k_other = DeviceKeys::generate(&[7; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, None, &k_other))
            .await
            .0,
        401,
        "토큰은 소비됐다"
    );
    // 이메일의 계정과 다른 아이디를 대면 지금처럼 409(본문 없음).
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "dana@example.com").await;
    let (code, resp) = post_json(
        &h,
        "/v1/devices",
        &hosted_body(&token, Some("other"), &dana.keys),
    )
    .await;
    assert_eq!(
        (code, resp.contains("device_taken")),
        (409, false),
        "{resp}"
    );

    // 다른 이메일 계정으로 이 기기를 쓰려 하면 device_taken, 토큰은 남아 다른 기기로 이어 쓸 수 있다.
    let token = signup_token(&h, &mail, "eve@example.com").await;
    let (code, resp) = post_json(
        &h,
        "/v1/devices",
        &hosted_body(&token, Some("eve"), &dana.keys),
    )
    .await;
    assert_eq!(code, 409);
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap(),
        json!({"error": "device_taken"})
    );
    let (code, resp) = post_json(
        &h,
        "/v1/devices",
        &hosted_body(&token, Some("eve"), &k_other),
    )
    .await;
    assert_eq!(code, 201, "토큰이 남아 있다: {resp}");

    // 같은 계정이라도 폐기된 기기면 device_taken(토큰 남음).
    c1.send(&json!({"t": "device.revoke"})).await;
    c1.drain_until_closed().await;
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "dana@example.com").await;
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &dana.keys)).await;
    assert_eq!((code, resp.contains("device_taken")), (409, true), "{resp}");
    let k_new = DeviceKeys::generate(&[8; 64]);
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &k_new)).await;
    assert_eq!(code, 201, "토큰이 남아 있다: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hosted_verify_failures_look_the_same_and_code_dies() {
    let (h, mail) = start_hosted().await;
    // 계정이 있든 없든 signup 은 같은 202.
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "a@x.io", "privacy": {"version": "test"}})
        )
        .await
        .0,
        202
    );
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "nobody", "privacy": {"version": "test"}})
        )
        .await
        .0,
        400
    );
    let right = mail.0.lock().unwrap()["a@x.io"].clone();
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };

    let verify = |email: &'static str, code: String| {
        let h = &h;
        async move {
            post_json(
                h,
                "/v1/signup/verify",
                &json!({"email": email, "code": code}),
            )
            .await
        }
    };
    // 틀림·모르는 이메일·형식 틀린 코드 = 같은 응답.
    let r_wrong = verify("a@x.io", wrong.into()).await;
    let r_unknown = verify("b@x.io", right.clone()).await;
    let r_shape = verify("a@x.io", "abc".into()).await;
    assert_eq!(r_wrong.0, 400);
    assert_eq!(r_wrong, r_unknown);
    assert_eq!(r_wrong, r_shape);
    // 지금까지 a@x.io 로 두 번 틀림 → 세 번 더 틀리면 코드 폐기, 맞는 코드도 거절.
    for _ in 0..3 {
        assert_eq!(verify("a@x.io", wrong.into()).await, r_wrong);
    }
    assert_eq!(verify("a@x.io", right).await, r_wrong);

    // 새로 요청하면 새 코드. 10분이 지나면 만료.
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "a@x.io", "privacy": {"version": "test"}})
        )
        .await
        .0,
        202
    );
    let code = mail.0.lock().unwrap()["a@x.io"].clone();
    h.fx.clock.advance(10 * 60 * 1000);
    assert_eq!(verify("a@x.io", code).await, r_wrong);

    // 이메일당 1시간 5번(위에서 두 번) — 넘으면 429, 한 시간 뒤 다시.
    for _ in 0..3 {
        assert_eq!(
            post_json(
                &h,
                "/v1/signup",
                &json!({"email": "a@x.io", "privacy": {"version": "test"}})
            )
            .await
            .0,
            202
        );
    }
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "a@x.io", "privacy": {"version": "test"}})
        )
        .await
        .0,
        429
    );
    h.fx.clock.advance(60 * 60 * 1000);
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "a@x.io", "privacy": {"version": "test"}})
        )
        .await
        .0,
        202
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hosted_device_add_is_rate_limited_per_user() {
    let (h, mail) = start_hosted().await;
    // 기기 상한(묶음 16, 기본 4)이 아니라 가입 횟수 상한을 보는 시험이다.
    h.app.db.set_max_devices(10);
    let token = signup_token(&h, &mail, "r@x.io").await;
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, Some("r"), &k))
            .await
            .0,
        201
    );
    for seed in 2..=5u8 {
        let token = signup_token(&h, &mail, "r@x.io").await;
        let k = DeviceKeys::generate(&[seed; 64]);
        assert_eq!(
            post_json(&h, "/v1/devices", &hosted_body(&token, None, &k))
                .await
                .0,
            201
        );
        h.fx.clock.advance(60 * 60 * 1000); // 가입 요청 상한(1시간 5번)을 피한다
    }
    let token = signup_token(&h, &mail, "r@x.io").await;
    let k = DeviceKeys::generate(&[6; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, None, &k))
            .await
            .0,
        429
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_is_closed_without_mailer() {
    let h = start().await;
    assert_eq!(
        post_json(
            &h,
            "/v1/signup",
            &json!({"email": "a@x.io", "privacy": {"version": "test"}})
        )
        .await
        .0,
        404
    );
    assert_eq!(
        post_json(
            &h,
            "/v1/signup/verify",
            &json!({"email": "a@x.io", "code": "123456"})
        )
        .await
        .0,
        404
    );
    // 등록 토큰 없이는 가입 토큰을 실어도 401(M1 은 이메일 경로가 없다).
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body("x", Some("a"), &k))
            .await
            .0,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn targeted_revoke_follows_registration_order() {
    let h = start().await;
    let old = register(&h, "dana", 1).await;
    h.fx.clock.advance(1000);
    let new = register_extra_device(&h, "dana", 2).await;
    let bob = register(&h, "bob", 3).await;
    let (mut c_old, _) = connect(&h, &old).await;
    let (mut c_new, _) = connect(&h, &new).await;
    // #577: 잎 자격 있는(먼저 기기가 서명한) 나중 기기만 지금 규칙(24h·too_early) — pending 이면 protocol.
    c_old
        .send(&json!({"t": "device.certify", "device_id": new.device_id, "sig": devcert(SERVER, &old, &new)}))
        .await;
    c_old.drain().await;
    c_new.drain().await;

    // 나중 기기 → 먼저 기기: 24시간 전엔 too_early, 연결은 그대로.
    c_new
        .send(&json!({"t": "device.revoke", "device_id": old.device_id}))
        .await;
    let e = c_new.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("too_early"))
    );
    assert!(e.get("ref").is_none());
    // 남의 기기와 모르는 id 는 같은 바이트.
    c_new
        .send(&json!({"t": "device.revoke", "device_id": bob.device_id}))
        .await;
    let other = c_new.recv_text().await;
    c_new
        .send(&json!({"t": "device.revoke", "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"}))
        .await;
    assert_eq!(c_new.recv_text().await, other);
    assert_eq!(
        serde_json::from_str::<Value>(&other).unwrap()["code"],
        "protocol"
    );
    c_old.expect_silence().await;

    // 24시간 뒤엔 된다: device.revoked{device_id} → directory.update, 대상 연결만 닫힘.
    h.fx.clock.advance(24 * 60 * 60 * 1000);
    c_new
        .send(&json!({"t": "device.revoke", "device_id": old.device_id}))
        .await;
    let r = c_new.recv().await;
    assert_eq!(
        r,
        json!({"t": "device.revoked", "device_id": old.device_id, "by": "device", "at": now_str(&h, 0)})
    );
    assert_eq!(c_new.recv().await["t"], "directory.update");
    c_old.drain_until_closed().await;
    // 이미 폐기된 자기 기기 = 멱등.
    c_new
        .send(&json!({"t": "device.revoke", "device_id": old.device_id}))
        .await;
    assert_eq!(
        c_new.recv().await,
        json!({"t": "device.revoked", "device_id": old.device_id})
    );
    assert!(h.app.db.device(&old.device_id).unwrap().is_none());
    assert!(h.app.db.device(&new.device_id).unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn older_device_revokes_newer_immediately() {
    let h = start().await;
    let old = register(&h, "dana", 1).await;
    h.fx.clock.advance(1000);
    let new = register_extra_device(&h, "dana", 2).await;
    let (mut c_old, _) = connect(&h, &old).await;
    let (mut c_new, _) = connect(&h, &new).await;
    c_old
        .send(&json!({"t": "device.revoke", "device_id": new.device_id}))
        .await;
    assert_eq!(
        c_old.recv().await,
        json!({"t": "device.revoked", "device_id": new.device_id, "by": "device", "at": now_str(&h, 0)})
    );
    assert_eq!(c_old.recv().await["t"], "directory.update");
    c_new.drain_until_closed().await;
    // 자기 id 를 넣은 폐기는 자기 폐기(#325)와 같다 — 응답에 그 값을 그대로 싣는다.
    c_old
        .send(&json!({"t": "device.revoke", "device_id": old.device_id}))
        .await;
    let got = c_old.drain_until_closed().await;
    assert_eq!(
        got[0],
        json!({"t": "device.revoked", "device_id": old.device_id, "by": "device", "at": now_str(&h, 0)})
    );
}

/// #320: 인증 전 연결은 작은 상한 — 큰 hello 는 핸드셰이크 실패(같은 error{protocol})로 끊긴다.
#[tokio::test(flavor = "multi_thread")]
async fn big_frame_before_auth_is_refused() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    let pad = "x".repeat(lodelai_relay::ws::HANDSHAKE_MAX_FRAME_BYTES);
    c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": alice.device_id, "user": alice.name, "pad": pad}))
        .await;
    let e = c.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("protocol"))
    );
    let rest = c.drain_until_closed().await;
    assert!(rest.is_empty(), "{rest:?}");
    // 인증 뒤에는 큰 프레임(상한 안)도 그대로 받는다.
    let (mut a, _) = connect(&h, &alice).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &alice.address(),
        json!({}),
        &"가".repeat(4000),
    );
    let r = send_expect(&mut a, &m).await;
    assert_ne!(r["code"], "protocol", "{r}");
}

// ------------------------------------------------------------------ 조직·팀·초대·이메일 (#355)

/// 이메일 가입 + 기기 등록. 응답 코드와 키.
async fn join(
    h: &Harness,
    mail: &CaptureMailer,
    email: &str,
    user: &str,
    org: Value,
    teams: Value,
    seed: u8,
) -> (u16, User) {
    let token = signup_token(h, mail, email).await;
    let keys = DeviceKeys::generate(&[seed; 64]);
    let body = json!({"signup_token": token, "user": user, "display_name": user, "device_pubkeys": device_pubkeys(&keys), "org": org, "teams": teams});
    let (code, _) = post_json(h, "/v1/devices", &body).await;
    (
        code,
        User {
            name: user.into(),
            device_id: keys.device_id().as_str().to_owned(),
            keys,
        },
    )
}

/// 다음 directory.update(또는 directory) 까지 읽는다.
async fn next_dir(c: &mut Client) -> Value {
    loop {
        let f = c.recv().await;
        if f["t"] == "directory.update" || f["t"] == "directory" {
            return f;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn org_admin_teams_invite_and_directory() {
    let (h, mail) = start_hosted().await;
    // 관리자가 새 조직을 만든다(새 조직엔 팀을 고를 수 없다).
    let (code, _) = join(
        &h,
        &mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "루이보스"}}),
        json!(["t1"]),
        1,
    )
    .await;
    assert_eq!(code, 400);
    let (code, boss) = join(
        &h,
        &mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "  루이보스 "}}),
        json!([]),
        1,
    )
    .await;
    assert_eq!(code, 201);
    // 조직 없는 새 계정은 400.
    let token = signup_token(&h, &mail, "solo@x.io").await;
    let k = DeviceKeys::generate(&[9; 64]);
    let (code, _) = post_json(
        &h,
        "/v1/devices",
        &json!({"signup_token": token, "user": "solo", "device_pubkeys": device_pubkeys(&k)}),
    )
    .await;
    assert_eq!(code, 400);

    let (mut b, _) = connect(&h, &boss).await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut b).await;
    let org_id = d["org"]["id"].as_str().unwrap().to_owned();
    assert_eq!(d["org"]["name"], "루이보스");
    assert_eq!(d["org"]["admins"], json!(["boss"]));
    assert!(d.get("teams").is_none(), "팀 없음 = 생략");
    assert_eq!(d["people"][0]["email"], "boss@x.io");

    // 팀 만들기·이름 바꾸기 → directory.update.
    b.send(&json!({"t": "team.create", "name": "web"})).await;
    let d = next_dir(&mut b).await;
    let web = d["teams"][0]["id"].as_str().unwrap().to_owned();
    b.send(&json!({"t": "team.create", "name": "ops"})).await;
    let d = next_dir(&mut b).await;
    assert_eq!(d["teams"].as_array().unwrap().len(), 2);
    let ops = d["teams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "ops")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // 같은 이름은 name_taken(관리자 판정 뒤에만 — 멤버는 아래에서 protocol).
    b.send(&json!({"t": "team.create", "name": "web"})).await;
    assert_eq!(b.recv().await["code"], "name_taken");
    b.send(&json!({"t": "team.update", "id": ops, "name": "web"}))
        .await;
    assert_eq!(b.recv().await["code"], "name_taken");
    b.send(&json!({"t": "team.update", "id": web, "name": "웹"}))
        .await;
    let d = next_dir(&mut b).await;
    assert!(d["teams"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "웹"));
    b.send(&json!({"t": "org.update", "name": "루이보스 주식회사"}))
        .await;
    assert_eq!(next_dir(&mut b).await["org"]["name"], "루이보스 주식회사");

    // 초대: 이메일 묶음 → 다른 이메일로 쓰면 실패(같은 422), 맞는 이메일로 팀 골라 가입.
    b.send(&json!({"t": "invite.create", "email": "minji@x.io"}))
        .await;
    let inv = b.recv().await;
    assert_eq!(inv["t"], "invite.created");
    let tok = inv["token"].as_str().unwrap().to_owned();
    let (code, _) = join(
        &h,
        &mail,
        "eve@x.io",
        "eve",
        json!({"invite": tok}),
        json!([]),
        3,
    )
    .await;
    assert_eq!(code, 422);
    let (code, _) = join(
        &h,
        &mail,
        "nobody@x.io",
        "nobody",
        json!({"invite": "A".repeat(43)}),
        json!([]),
        4,
    )
    .await;
    assert_eq!(code, 422);
    // 그 조직 팀이 아니면 400(초대는 소모되지 않는다).
    let (code, _) = join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": tok}),
        json!(["nope"]),
        5,
    )
    .await;
    assert_eq!(code, 400);
    let (code, minji) = join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": tok}),
        json!([web]),
        5,
    )
    .await;
    assert_eq!(code, 201);
    // 초대는 1회용.
    let (code, _) = join(
        &h,
        &mail,
        "minji2@x.io",
        "minji2",
        json!({"invite": tok}),
        json!([]),
        6,
    )
    .await;
    assert_eq!(code, 422);

    let d = next_dir(&mut b).await;
    let m = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "minji@local")
        .unwrap()
        .clone();
    assert_eq!(
        (m["email"].as_str(), m["teams"].clone()),
        (Some("minji@x.io"), json!([web]))
    );

    // 멤버: 자기 팀 바꾸기(남의 조직·모르는 팀은 거절), 관리자 동작은 거절.
    let (mut mc, _) = connect(&h, &minji).await;
    mc.send(&json!({"t": "profile.update", "teams": [web, ops]}))
        .await;
    let d = next_dir(&mut mc).await;
    let m = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "minji@local")
        .unwrap()
        .clone();
    assert_eq!(m["teams"].as_array().unwrap().len(), 2);
    assert_eq!(m["display"], "minji", "없는 필드는 안 바꾼다");
    mc.send(&json!({"t": "profile.update", "teams": ["nope"]}))
        .await;
    assert_eq!(mc.recv().await["code"], "protocol");
    for f in [
        json!({"t": "team.create", "name": "x"}),
        json!({"t": "org.update", "name": "x"}),
        json!({"t": "invite.create"}),
        json!({"t": "team.delete", "id": web}),
    ] {
        mc.send(&f).await;
        let e = mc.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{f}"
        );
    }
    // 팀 빼기 → 사람들의 teams 에서도 빠진다.
    let _ = next_dir(&mut b).await; // minji 팀 변경
    b.send(&json!({"t": "team.delete", "id": ops})).await;
    let d = next_dir(&mut b).await;
    let m = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "minji@local")
        .unwrap()
        .clone();
    assert_eq!(m["teams"], json!([web]));

    // 다른 조직은 서로 안 보인다.
    let (code, other) = join(
        &h,
        &mail,
        "z@y.io",
        "zed",
        json!({"create": {"name": "루이보스"}}),
        json!([]),
        7,
    )
    .await;
    assert_eq!(code, 201);
    let (mut z, _) = connect(&h, &other).await;
    z.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut z).await;
    assert_eq!(d["people"].as_array().unwrap().len(), 1);
    assert_ne!(d["org"]["id"], org_id.as_str(), "같은 이름이어도 다른 조직");

    // 관리자는 같은 조직 사람의 기기를 바로 끊는다(24시간 없음), 다른 조직 기기는 모르는 기기와 같은 답.
    b.send(&json!({"t": "device.revoke", "device_id": other.device_id}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    b.send(&json!({"t": "device.revoke", "device_id": minji.device_id}))
        .await;
    loop {
        let f = b.recv().await;
        if f["t"] == "device.revoked" {
            assert_eq!(f["device_id"], minji.device_id);
            break;
        }
    }
    mc.drain_until_closed().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_issuance_is_rate_limited_per_admin() {
    let (h, mail) = start_hosted().await;
    let (_, boss) = join(
        &h,
        &mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "o"}}),
        json!([]),
        1,
    )
    .await;
    let (mut b, _) = connect(&h, &boss).await;
    for _ in 0..lodelai_relay::ws::INVITE_MAX {
        b.send(&json!({"t": "invite.create"})).await;
        assert_eq!(b.recv().await["t"], "invite.created");
        h.fx.clock.advance(1);
    }
    b.send(&json!({"t": "invite.create"})).await;
    let e = b.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("rate_limited"))
    );
    // 연결은 그대로, 한 시간 뒤 다시.
    h.fx.clock.advance(lodelai_relay::ws::INVITE_WINDOW_MS);
    b.send(&json!({"t": "invite.create"})).await;
    assert_eq!(b.recv().await["t"], "invite.created");
}

#[tokio::test(flavor = "multi_thread")]
async fn m1_local_directory_has_no_org_fields() {
    let h = start().await;
    let a = register(&h, "alice", 1).await;
    let (mut c, _) = connect(&h, &a).await;
    c.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut c).await;
    assert!(d.get("org").is_none() && d.get("teams").is_none());
    assert!(d["people"][0].get("email").is_none() && d["people"][0].get("teams").is_none());
    // 팀 기능은 M1 에 없다 — 팀을 고르면 거절, 표시 이름만 바꾸는 건 그대로.
    c.send(&json!({"t": "profile.update", "teams": ["x"]}))
        .await;
    assert_eq!(c.recv().await["code"], "protocol");
    c.send(&json!({"t": "team.create", "name": "x"})).await;
    assert_eq!(c.recv().await["code"], "protocol");
}

// ---------------------------------------------------------------- 원격 relay (#364, m1-spec §17.1)

const PUBLIC: &str = "lodelai.example";

const PRIVACY: &str = "2026-10-25";

/// 원격 relay: 공개 도메인 Host, 처리방침 판, 가입 메일(가짜), 조직 만들기 코드를 미리 낸다(`lodelai-relay bootstrap`).
async fn start_remote_full() -> (Harness, std::sync::Arc<CaptureMailer>, String) {
    start_remote_with(|_| {}).await
}

async fn start_remote_with(
    more: impl FnOnce(&mut Config),
) -> (Harness, std::sync::Arc<CaptureMailer>, String) {
    let db = Db::memory().unwrap();
    let rng = TestEffects::new(START_MS, 99).rng;
    let code = lodelai_relay::http::bootstrap_setup_code(&db, rng.as_ref(), START_MS).unwrap();
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(
        |c| {
            c.remote = true;
            c.public_host = Some(PUBLIC.into());
            c.privacy_version = Some(PRIVACY.into());
            more(c);
        },
        db,
        Some(mail.clone()),
    )
    .await;
    (h, mail, code)
}

async fn start_remote() -> (Harness, String) {
    let (h, _, code) = start_remote_full().await;
    (h, code)
}

/// 원격 relay 가입: 메일 코드 → 가입 토큰(처리방침 판 PRIVACY).
async fn remote_token(h: &Harness, mail: &CaptureMailer, email: &str) -> String {
    let (code, resp) = post_json(
        h,
        "/v1/signup",
        &json!({"email": email, "privacy": {"version": PRIVACY}}),
    )
    .await;
    assert_eq!(code, 202, "{resp}");
    let sent = mail.0.lock().unwrap()[email].clone();
    let (code, resp) = post_json(
        h,
        "/v1/signup/verify",
        &json!({"email": email, "code": sent}),
    )
    .await;
    assert_eq!(code, 200, "{resp}");
    serde_json::from_str::<Value>(&resp).unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// 원격 relay 에서 새 조직 만들기(조직 만들기 코드). 상태 코드.
async fn create_org(
    h: &Harness,
    mail: &CaptureMailer,
    email: &str,
    user: &str,
    keys: &DeviceKeys,
    setup_code: Option<&str>,
) -> u16 {
    let token = remote_token(h, mail, email).await;
    let mut create = json!({"name": "루이보스"});
    if let Some(c) = setup_code {
        create["setup_code"] = json!(c);
    }
    let body = json!({"signup_token": token, "user": user, "display_name": user,
        "device_pubkeys": device_pubkeys(keys), "org": {"create": create}});
    post_json(h, "/v1/devices", &body).await.0
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_accepts_public_host_and_still_rejects_origin() {
    let (h, _) = start_remote().await;
    let get = |host: &'static str, origin: Option<&'static str>| {
        let addr = h.addr;
        async move {
            let mut hs = vec![("Host", host)];
            if let Some(o) = origin {
                hs.push(("Origin", o));
            }
            http(addr, "GET", "/v1/healthz", &hs, "").await.0
        }
    };
    assert_eq!(get("lodelai.example", None).await, 200);
    assert_eq!(get("lodelai.example:443", None).await, 200);
    assert_eq!(get("LODELAI.example", None).await, 200);
    assert_eq!(get("evil.example", None).await, 403);
    assert_eq!(get("lodelai.example:8443", None).await, 403);
    assert_eq!(
        get("lodelai.example", Some("https://lodelai.example")).await,
        403
    );
    // 로컬 relay 는 공개 도메인을 받지 않는다.
    let local = start().await;
    let (code, _) = http(local.addr, "GET", "/v1/healthz", &[("Host", PUBLIC)], "").await;
    assert_eq!(code, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_closes_token_registration() {
    let (h, _) = start_remote().await;
    let keys = DeviceKeys::generate(&[5; 64]);
    let auth = format!("Bearer {TOKEN}");
    let (code, _) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        &register_body("boss", &keys),
    )
    .await;
    assert_eq!(code, 401, "원격 relay 엔 등록 토큰 경로가 없다");
}

#[tokio::test(flavor = "multi_thread")]
async fn org_create_code_is_one_time_and_makes_first_admin() {
    let (h, mail, code) = start_remote_full().await;
    let k1 = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &k1, Some(&code)).await,
        201
    );
    let boss = User {
        name: "boss".into(),
        device_id: k1.device_id().as_str().to_owned(),
        keys: k1,
    };
    let (mut c, ready) = connect(&h, &boss).await;
    assert_eq!(ready["admin"], true);
    c.send(&json!({"t": "directory.list"})).await;
    let d = c.recv().await;
    assert_eq!(d["org"]["admins"], json!(["boss"]));
    // 쓴 코드로는 다른 조직을 못 만든다(초대 실패와 같은 422).
    let k2 = DeviceKeys::generate(&[2; 64]);
    assert_eq!(
        create_org(&h, &mail, "eve@x.io", "eve", &k2, Some(&code)).await,
        422
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_create_without_code_is_refused() {
    let (h, mail, _) = start_remote_full().await;
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &k, None).await,
        422
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn org_create_code_expires_after_an_hour() {
    let (h, mail, code) = start_remote_full().await;
    h.fx.clock.advance(60 * 60 * 1000 + 1);
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &k, Some(&code)).await,
        422
    );
}

// ---- relay 0.1.2: 조직 만들기 코드 여러 개·이메일 묶기·만료 이유·늦춤 ----

/// 그 이메일로 가입해 새 조직 만들기 — (상태, 본문 JSON).
async fn create_org_resp(
    h: &Harness,
    mail: &CaptureMailer,
    email: &str,
    user: &str,
    seed: u8,
    code: &str,
) -> (u16, Value) {
    let token = remote_token(h, mail, email).await;
    let k = DeviceKeys::generate(&[seed; 64]);
    let body = json!({"signup_token": token, "user": user, "display_name": user,
        "device_pubkeys": device_pubkeys(&k), "org": {"create": {"name": "루이보스", "setup_code": code}}});
    let (status, resp) = post_json(h, "/v1/devices", &body).await;
    (status, serde_json::from_str(&resp).unwrap_or(Value::Null))
}

fn email_code(h: &Harness, email: &str, ttl_ms: Option<i64>) -> String {
    lodelai_relay::http::issue_setup_code(
        &h.app.db,
        &lodelai_effects::OsRng,
        h.fx.clock.now().0,
        Some(email),
        ttl_ms,
    )
    .unwrap()
    .code
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_codes_live_together_and_only_the_used_one_goes() {
    let (h, mail, plain) = start_remote_full().await;
    let a = email_code(&h, "a@x.io", None);
    let b = email_code(&h, "b@x.io", None);
    let c = email_code(&h, "c@x.io", None);
    let live = |h: &Harness| h.app.db.list_setup_codes(h.fx.clock.now().0).unwrap().len();
    assert_eq!(live(&h), 4, "이메일 없는 코드 + 이메일 코드 셋");
    for (i, (email, code)) in [("a@x.io", &a), ("b@x.io", &b), ("c@x.io", &c)]
        .into_iter()
        .enumerate()
    {
        let user = format!("u{i}");
        let (status, resp) = create_org_resp(&h, &mail, email, &user, 10 + i as u8, code).await;
        assert_eq!(status, 201, "{email}: {resp}");
        assert_eq!(live(&h), 3 - i, "쓴 것만 사라진다");
    }
    // 쓴 코드는 다시 못 쓴다 — 이유를 가르지 않는 422(a@x.io 는 이미 계정이 있어 409 가 먼저라 새 이메일로).
    let (status, resp) = create_org_resp(&h, &mail, "n@x.io", "u9", 19, &a).await;
    assert_eq!((status, resp.get("reason")), (422, None));
    // 이메일 없는 코드는 아무 이메일로나.
    let (status, _) = create_org_resp(&h, &mail, "zed@y.io", "zed", 30, &plain).await;
    assert_eq!(status, 201);
}

/// #737: 이메일에 묶인 살아 있는 코드(대기 명단 승인)가 있는 이메일은 verify 가 `open` — 코드 없이 한 번 만든다.
/// start 응답은 승인과 상관없이 같다. 승인 안 된 이메일은 `code`, 코드 없이 만들면 422.
#[tokio::test(flavor = "multi_thread")]
async fn approved_email_creates_org_without_code_once() {
    let (h, mail, _) =
        start_remote_with(|c| c.waitlist_url = Some("https://lodelai.com/waitlist".into())).await;
    let _ = email_code(&h, "boss@x.io", None);
    let mut starts = Vec::new();
    let mut org_create = Vec::new();
    let mut tokens = Vec::new();
    for email in ["boss@x.io", "other@x.io"] {
        let (code, resp) = post_json(
            &h,
            "/v1/signup",
            &json!({"email": email, "privacy": {"version": PRIVACY}}),
        )
        .await;
        starts.push((code, resp));
        let sent = mail.0.lock().unwrap()[email].clone();
        let (code, resp) = post_json(
            &h,
            "/v1/signup/verify",
            &json!({"email": email, "code": sent}),
        )
        .await;
        assert_eq!(code, 200, "{resp}");
        let v: Value = serde_json::from_str(&resp).unwrap();
        org_create.push((
            v["org_create"].clone(),
            v["waitlist_url"].clone(),
            v["approved"].clone(),
        ));
        tokens.push(v["signup_token"].as_str().unwrap().to_owned());
    }
    assert_eq!(starts[0], starts[1], "start 는 승인과 상관없이 같다");
    // 승인 안 된 새 이메일에만 대기 명단 주소(앱이 코드 칸 대신 대기 명단 안내).
    assert_eq!(
        org_create,
        [
            (json!("open"), Value::Null, json!(true)),
            (
                json!("code"),
                json!("https://lodelai.com/waitlist"),
                Value::Null
            )
        ]
    );

    let create = |token: &str, user: &str, seed: u8| {
        let k = DeviceKeys::generate(&[seed; 64]);
        json!({"signup_token": token, "user": user, "display_name": user,
            "device_pubkeys": device_pubkeys(&k), "org": {"create": {"name": "루이보스"}}})
    };
    let (status, resp) = post_json(&h, "/v1/devices", &create(&tokens[1], "other", 2)).await;
    assert_eq!(status, 422, "{resp}");
    let (status, resp) = post_json(&h, "/v1/devices", &create(&tokens[0], "boss", 1)).await;
    assert_eq!(status, 201, "{resp}");
    // 승인은 한 번 — 그 이메일의 코드는 다 쓰였다.
    let now = h.fx.clock.now().0;
    assert!(!h.app.db.org_create_allowed("boss@x.io", now).unwrap());
    assert!(h
        .app
        .db
        .list_setup_codes(now)
        .unwrap()
        .iter()
        .all(|c| c.email_mask.is_none()));
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_setup_code_says_so() {
    let (h, mail, _) = start_remote_full().await;
    let code = email_code(&h, "boss@x.io", None);
    h.fx.clock
        .advance(lodelai_relay::http::SETUP_CODE_EMAIL_TTL_MS + 1);
    let (status, resp) = create_org_resp(&h, &mail, "boss@x.io", "boss", 1, &code).await;
    assert_eq!(status, 422, "{resp}");
    assert_eq!(resp["reason"], "setup_code_expired");
    assert_eq!(resp["message"]["ko"], "기한이 지난 조직 만들기 코드예요");
    assert_eq!(resp["message"]["en"], "This organization code has expired");
    // 14일 넘는 기한은 내지 않는다.
    assert!(lodelai_relay::http::issue_setup_code(
        &h.app.db,
        &lodelai_effects::OsRng,
        h.fx.clock.now().0,
        Some("boss@x.io"),
        Some(lodelai_relay::http::SETUP_CODE_MAX_TTL_MS + 1),
    )
    .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn other_email_is_told_and_not_counted_as_a_wrong_try() {
    let (h, mail, _) = start_remote_full().await;
    let code = email_code(&h, "Boss@X.io", None);
    // 같은 토큰으로 여섯 번(거절은 토큰을 쓰지 않는다) — 틀린 시도로 세면 다섯 번째 뒤 429 가 된다.
    let token = remote_token(&h, &mail, "other@x.io").await;
    let k = DeviceKeys::generate(&[40; 64]);
    let body = json!({"signup_token": token, "user": "other", "device_pubkeys": device_pubkeys(&k),
        "org": {"create": {"name": "루이보스", "setup_code": code}}});
    for _ in 0..6 {
        let (status, resp) = post_json(&h, "/v1/devices", &body).await;
        let resp: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
        assert_eq!(status, 422, "{resp}");
        assert_eq!(resp["reason"], "setup_code_other_email");
        assert_eq!(resp["email"], "b***@x…");
        assert_eq!(
            resp["message"]["ko"],
            "b***@x… 로 가입할 때만 쓸 수 있는 코드예요"
        );
        assert_eq!(
            resp["message"]["en"],
            "This code only works if you sign up with b***@x…"
        );
    }
    // 대소문자가 달라도 같은 이메일(정규화).
    let (status, resp) = create_org_resp(&h, &mail, "boss@x.io", "boss", 1, &code).await;
    assert_eq!(status, 201, "{resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn five_wrong_codes_slow_that_email_only_and_keep_every_code() {
    let (h, mail, _) = start_remote_full().await;
    let mine = email_code(&h, "boss@x.io", None);
    let theirs = email_code(&h, "zed@y.io", None);
    let k = DeviceKeys::generate(&[1; 64]);
    // 틀린 코드는 가입 토큰을 쓰지 않는다 — 같은 토큰으로 다시 시도한다.
    let token = remote_token(&h, &mail, "boss@x.io").await;
    let body = |c: &str| {
        json!({"signup_token": token, "user": "boss", "device_pubkeys": device_pubkeys(&k),
            "org": {"create": {"name": "루이보스", "setup_code": c}}})
    };
    for _ in 0..5 {
        assert_eq!(
            post_json(&h, "/v1/devices", &body("0000-0000-0000-0000"))
                .await
                .0,
            422
        );
    }
    // 다섯 번 틀린 이메일은 맞는 코드라도 1시간 늦춘다(429, reason 없음).
    let (status, resp) = post_json(&h, "/v1/devices", &body(&mine)).await;
    assert_eq!(status, 429, "{resp}");
    assert!(!resp.contains("reason"), "{resp}");
    // 다른 사람의 코드는 살아 있다(지우지 않는다). 남은 것: 내 코드 + 처음 낸 이메일 없는 코드.
    let (status, resp) = create_org_resp(&h, &mail, "zed@y.io", "zed", 2, &theirs).await;
    assert_eq!(status, 201, "{resp}");
    assert_eq!(
        h.app.db.list_setup_codes(h.fx.clock.now().0).unwrap().len(),
        2
    );
    // 1시간 뒤엔 내 코드도 그대로 쓴다(가입 토큰은 30분이라 새로).
    h.fx.clock
        .advance(lodelai_relay::http::SETUP_CODE_THROTTLE_MS);
    let (status, resp) = create_org_resp(&h, &mail, "boss@x.io", "boss", 1, &mine).await;
    assert_eq!(status, 201, "{resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_bootstrap_does_not_touch_email_codes() {
    let (h, mail, first_plain) = start_remote_full().await;
    let email = email_code(&h, "boss@x.io", None);
    let again = email_code(&h, "zed@y.io", None);
    let second_plain = lodelai_relay::http::bootstrap_setup_code(
        &h.app.db,
        &lodelai_effects::OsRng,
        h.fx.clock.now().0,
    )
    .unwrap();
    let rows = h.app.db.list_setup_codes(h.fx.clock.now().0).unwrap();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows.iter().filter(|r| r.email_mask.is_none()).count(), 1);
    // 이메일 없는 코드는 앞의 것만 무효, 이메일 코드는 그대로.
    assert_eq!(
        create_org_resp(&h, &mail, "p@x.io", "p", 3, &first_plain)
            .await
            .0,
        422
    );
    assert_eq!(
        create_org_resp(&h, &mail, "boss@x.io", "boss", 1, &email)
            .await
            .0,
        201
    );
    // 같은 이메일로 다시 내면 그 이메일의 앞 코드만 무효.
    let newer = email_code(&h, "zed@y.io", None);
    assert_eq!(
        create_org_resp(&h, &mail, "zed@y.io", "zed", 2, &again)
            .await
            .0,
        422
    );
    assert_eq!(
        create_org_resp(&h, &mail, "zed@y.io", "zed", 2, &newer)
            .await
            .0,
        201
    );
    assert_eq!(
        create_org_resp(&h, &mail, "q@x.io", "q", 4, &second_plain)
            .await
            .0,
        201
    );
}

#[test]
fn old_single_setup_code_row_moves_to_setup_codes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE setup_code (
               one        INTEGER PRIMARY KEY CHECK (one = 1),
               admin      TEXT NOT NULL,
               code_hash  BLOB NOT NULL,
               expires_ms INTEGER NOT NULL,
               failures   INTEGER NOT NULL DEFAULT 0
             );",
        )
        .unwrap();
        c.execute(
            "INSERT INTO setup_code(one, admin, code_hash, expires_ms, failures) VALUES (1, '', ?1, ?2, 2)",
            rusqlite::params![
                lodelai_relay::http::setup_code_hash("ABCD-EFGH-JKLM-NPQR"),
                START_MS + 1_000
            ],
        )
        .unwrap();
    }
    let db = Db::open(&path).unwrap();
    let rows = db.list_setup_codes(START_MS).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].email_mask.as_deref(), rows[0].expires_ms),
        (None, START_MS + 1_000)
    );
    assert_eq!(
        db.check_setup_code(
            &lodelai_relay::http::setup_code_hash("abcd efgh jklm npqr".replace(' ', "-").as_str()),
            None,
            START_MS
        )
        .unwrap(),
        lodelai_relay::db::SetupCheck::Ok
    );
    drop(db);
    let c = rusqlite::Connection::open(&path).unwrap();
    let old: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'setup_code')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!old, "옛 표는 지운다");
    // 다시 열어도 그대로(이주는 한 번).
    assert_eq!(
        Db::open(&path)
            .unwrap()
            .list_setup_codes(START_MS)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_needs_current_privacy_version_before_any_mail() {
    let (h, mail, _) = start_remote_full().await;
    let (code, resp) = http(h.addr, "GET", "/v1/privacy", &[("Host", PUBLIC)], "").await;
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap()["version"],
        PRIVACY
    );
    for body in [
        json!({"email": "a@x.io"}),
        json!({"email": "a@x.io", "privacy": {"version": "2020-01-01"}}),
        json!({"email": "a@x.io", "privacy": {"version": ""}}),
    ] {
        assert_eq!(post_json(&h, "/v1/signup", &body).await.0, 422, "{body}");
    }
    assert!(mail.0.lock().unwrap().is_empty(), "메일 전에 막힌다");
    // 동의한 판은 등록 때 그 사람 행에 남는다.
    let k = DeviceKeys::generate(&[1; 64]);
    let code = lodelai_relay::http::bootstrap_setup_code(
        &h.app.db,
        TestEffects::new(START_MS, 5).rng.as_ref(),
        START_MS,
    )
    .unwrap();
    assert_eq!(
        create_org(&h, &mail, "a@x.io", "alice", &k, Some(&code)).await,
        201
    );
    assert_eq!(
        h.app.db.privacy_of("alice").unwrap(),
        Some((PRIVACY.to_owned(), START_MS))
    );
}

/// 가짜 SMTP 서버 하나(로컬, 평문): 받은 세션마다 (MAIL FROM 줄, DATA 본문)을 보낸다.
async fn fake_smtp() -> (u16, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut r = BufReader::new(r);
                w.write_all(b"220 fake ESMTP\r\n").await.unwrap();
                let (mut from, mut data) = (String::new(), String::new());
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let up = line.to_ascii_uppercase();
                    let reply: &[u8] = if up.starts_with("EHLO") {
                        b"250-fake\r\n250 8BITMIME\r\n"
                    } else if up.starts_with("MAIL FROM") {
                        from = line.trim_end().to_owned();
                        b"250 ok\r\n"
                    } else if up.starts_with("RCPT TO") {
                        b"250 ok\r\n"
                    } else if up.starts_with("DATA") {
                        w.write_all(b"354 go\r\n").await.unwrap();
                        loop {
                            line.clear();
                            r.read_line(&mut line).await.unwrap();
                            if line == ".\r\n" {
                                break;
                            }
                            data.push_str(&line);
                        }
                        let _ = tx.send((from.clone(), data.clone()));
                        b"250 queued\r\n"
                    } else if up.starts_with("QUIT") {
                        let _ = w.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        b"502 no\r\n"
                    };
                    w.write_all(reply).await.unwrap();
                }
            });
        }
    });
    (port, rx)
}

/// 묶음 29 §1-3: 운영자 SMTP 로 가입 코드 한 통 — 봉투·머리글의 보내는 사람이 LODELAI_MAIL_FROM, 받은 코드로 확인이 된다.
#[tokio::test(flavor = "multi_thread")]
async fn signup_code_goes_out_by_smtp_from_operator_address() {
    let (port, mut rx) = fake_smtp().await;
    let from = lodelai_relay::mail::MailFrom::parse("lodelai <noreply@example.org>").unwrap();
    let mailer = std::sync::Arc::new(lodelai_relay::mail::SmtpMailer::plaintext_for_test(
        port, from,
    ));
    let h = start_full(
        |c| {
            c.remote = true;
            c.public_host = Some(PUBLIC.into());
            c.privacy_version = Some(PRIVACY.into());
        },
        Db::memory().unwrap(),
        Some(mailer),
    )
    .await;
    let (code, resp) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "a@x.io", "privacy": {"version": PRIVACY}}),
    )
    .await;
    assert_eq!(code, 202, "{resp}");
    let (envelope, data) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(envelope, "MAIL FROM:<noreply@example.org>");
    assert!(
        data.contains("From: lodelai <noreply@example.org>"),
        "{data}"
    );
    assert!(data.contains("To: a@x.io"), "{data}");
    let sent: String = data
        .lines()
        .find(|l| l.starts_with("Subject:"))
        .unwrap()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    assert_eq!(sent.len(), 6, "{data}");
    let (c, r) = post_json(
        &h,
        "/v1/signup/verify",
        &json!({"email": "a@x.io", "code": sent}),
    )
    .await;
    assert_eq!(c, 200, "{r}");
}

/// 묶음 29 §1-3·§1-4: 하루 상한은 설정값(LODELAI_MAIL_PER_DAY), 처리방침 응답에 운영자 url(없으면 싣지 않음).
#[tokio::test(flavor = "multi_thread")]
async fn mail_per_day_and_privacy_url_come_from_config() {
    let (h, _, _) = start_remote_full().await;
    let (_, resp) = http(h.addr, "GET", "/v1/privacy", &[("Host", PUBLIC)], "").await;
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap(),
        json!({"version": PRIVACY})
    );
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(
        |c| {
            c.remote = true;
            c.public_host = Some(PUBLIC.into());
            c.privacy_version = Some(PRIVACY.into());
            c.privacy_url = Some("https://corp.example/privacy".into());
            c.mail_per_day = 1;
        },
        Db::memory().unwrap(),
        Some(mail.clone()),
    )
    .await;
    let (_, resp) = http(h.addr, "GET", "/v1/privacy", &[("Host", PUBLIC)], "").await;
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap(),
        json!({"version": PRIVACY, "url": "https://corp.example/privacy"})
    );
    let signup = |email: &'static str| {
        let h = &h;
        async move {
            post_json(
                h,
                "/v1/signup",
                &json!({"email": email, "privacy": {"version": PRIVACY}}),
            )
            .await
            .0
        }
    };
    assert_eq!(signup("a@x.io").await, 202);
    assert_eq!(signup("b@x.io").await, 429, "하루 1통 넘음");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_says_existing_with_account_or_new() {
    let (h, mail, code) = start_remote_full().await;
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &k, Some(&code)).await,
        201
    );
    let verify = |email: &'static str| {
        let (h, mail) = (&h, mail.clone());
        async move {
            post_json(
                h,
                "/v1/signup",
                &json!({"email": email, "privacy": {"version": PRIVACY}}),
            )
            .await;
            let sent = mail.0.lock().unwrap()[email].clone();
            let (c, r) = post_json(
                h,
                "/v1/signup/verify",
                &json!({"email": email, "code": sent}),
            )
            .await;
            assert_eq!(c, 200);
            serde_json::from_str::<Value>(&r).unwrap()
        }
    };
    let v = verify("boss@x.io").await;
    assert_eq!(v["kind"], "existing");
    assert_eq!(
        v["account"],
        json!({"user": "boss", "display_name": "boss", "org_name": "루이보스"})
    );
    assert!(v.get("org_create").is_none(), "org_create 는 new 에만: {v}");
    let v = verify("new@x.io").await;
    assert_eq!(v["kind"], "new");
    assert!(v.get("account").is_none());
    assert_eq!(v["org_create"], "code");
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_check_does_not_consume_token_and_hides_why() {
    let (h, mail, code) = start_remote_full().await;
    let kb = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &kb, Some(&code)).await,
        201
    );
    let boss = User {
        name: "boss".into(),
        device_id: kb.device_id().as_str().to_owned(),
        keys: kb,
    };
    let (mut c, _) = connect(&h, &boss).await;
    c.send(&json!({"t": "team.create", "name": "웹"})).await;
    assert_eq!(c.recv().await["t"], "directory.update");
    c.send(&json!({"t": "invite.create"})).await;
    let inv = c.recv().await;
    let invite = inv["token"].as_str().unwrap().to_owned();

    // #554: 조직 사진이 있으면 확인 응답에 그 PNG 를 base64url 로 싣는다(가입 전이라 blob.get 을 못 쓴다).
    let org = h.app.db.user_org("boss").unwrap().unwrap();
    let pic = [
        &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A][..],
        b"org-picture",
    ]
    .concat();
    let blob = "QUJDREVGR0hJSktMTU5PUA";
    assert!(h
        .app
        .db
        .blob_reserve(
            &lodelai_relay::db::NewBlob {
                blob_id: blob,
                user: "boss",
                device: boss.device_id.as_str(),
                avatar: true,
                for_org: Some(org.as_str()),
                ct_len: pic.len() as u64,
                put_token_hash: b"h",
                put_token_exp: i64::MAX,
                now_ms: START_MS,
            },
            u64::MAX,
        )
        .unwrap());
    let file = h.app.blob_dir.join(&blob[..2]).join(blob);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &pic).unwrap();
    assert!(h.app.db.blob_put_done(blob).unwrap());
    assert_eq!(
        h.app.db.set_org_avatar(&org, "boss", blob).unwrap(),
        Some(None)
    );
    // 관리자가 아니면 바꾸지 않고 그 blob 행을 지운다(PUT 끝 403, #554 — 검사와 교체를 한 트랜잭션에).
    assert_eq!(
        h.app
            .db
            .set_org_avatar(&org, "nobody", "QUJDREVGR0hJSktMTU5PUQ")
            .unwrap(),
        None
    );
    assert_eq!(h.app.db.org_avatar(&org).unwrap().as_deref(), Some(blob));

    let token = remote_token(&h, &mail, "minji@x.io").await;
    let check = |tok: &str, inv: &str| {
        let body = json!({"signup_token": tok, "invite": inv});
        let h = &h;
        async move { post_json(h, "/v1/invites/check", &body).await }
    };
    let (status, resp) = check(&token, &invite).await;
    assert_eq!(status, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["org_name"], "루이보스");
    assert_eq!(
        v["inviter"],
        json!({"user": "boss", "display_name": "boss"})
    );
    assert_eq!(v["teams"][0]["name"], "웹");
    assert_eq!(v["org_avatar"], lodelai_crypto::encoding::encode(&pic));
    // 초대 화면 타일 색 키 — 가입 뒤 디렉터리 org.id 와 같은 값(#554).
    assert_eq!(v["org_id"], org.as_str());
    // 쓸 수 없는 초대·가입 토큰 없음은 같은 404(본문까지 같음).
    let bad = check(&token, &"x".repeat(43)).await;
    let no_token = check(&"y".repeat(43), &invite).await;
    assert_eq!(bad, no_token);
    assert_eq!(bad.0, 404);
    assert!(
        !bad.1.contains("org_id") && !bad.1.contains("org_avatar"),
        "{}",
        bad.1
    );
    // 확인은 토큰을 쓰지 않는다 — 그 토큰으로 초대 가입이 된다.
    let km = DeviceKeys::generate(&[2; 64]);
    let body = json!({"signup_token": token, "user": "minji", "device_pubkeys": device_pubkeys(&km),
        "org": {"invite": invite}});
    assert_eq!(post_json(&h, "/v1/devices", &body).await.0, 201);
    // 쓰인 초대는 이제 404.
    let token2 = remote_token(&h, &mail, "jun@x.io").await;
    assert_eq!(check(&token2, &invite).await.0, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn invites_check_stops_after_ten_wrong_tries_per_token() {
    let (h, mail, _) = start_remote_full().await;
    let token = remote_token(&h, &mail, "minji@x.io").await;
    for _ in 0..10 {
        let body = json!({"signup_token": token, "invite": "x".repeat(43)});
        assert_eq!(post_json(&h, "/v1/invites/check", &body).await.0, 404);
    }
    assert_eq!(
        h.app
            .db
            .invite_check_failures(&lodelai_relay::http::signup_token_hash(&token))
            .unwrap(),
        10
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_limits_email_hour_day_and_global() {
    let (h, _mail) = start_hosted().await;
    let send = |email: String| {
        let h = &h;
        async move {
            post_json(
                h,
                "/v1/signup",
                &json!({"email": email, "privacy": {"version": "test"}}),
            )
            .await
            .0
        }
    };
    // 이메일당 1시간 5번.
    for _ in 0..5 {
        assert_eq!(send("a@x.io".into()).await, 202);
    }
    assert_eq!(send("a@x.io".into()).await, 429);
    // 한 시간 뒤엔 다시 — 하루 10번까지.
    h.fx.clock.advance(60 * 60 * 1000 + 1);
    for _ in 0..5 {
        assert_eq!(send("a@x.io".into()).await, 202);
    }
    h.fx.clock.advance(60 * 60 * 1000 + 1);
    assert_eq!(send("a@x.io".into()).await, 429, "하루 10번");
    // 전역 하루 80통(이미 10통) — 다른 주소 70통 뒤 막힌다.
    for n in 0..70 {
        assert_eq!(send(format!("u{n}@x.io")).await, 202);
    }
    assert_eq!(send("late@x.io".into()).await, 429);
    assert_eq!(h.app.db.signup_sent_today(h.fx.clock.now().0).unwrap(), 80);
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_ip_limit_only_on_remote() {
    let (h, _mail, _) = start_remote_full().await;
    // 원격 relay 는 연결 주소(127.0.0.1)를 IP 로 본다(--behind-cloudflare 아님) — 20번 뒤 막힌다.
    let mut last = 0;
    for n in 0..21 {
        last = post_json(
            &h,
            "/v1/signup",
            &json!({"email": format!("u{n}@x.io"), "privacy": {"version": PRIVACY}}),
        )
        .await
        .0;
    }
    assert_eq!(last, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn local_ready_has_no_admin() {
    let h = start().await;
    let a = register(&h, "alice", 1).await;
    let (_c, ready) = connect(&h, &a).await;
    assert!(ready.get("admin").is_none(), "{ready}");
}

// ---- QA(#355 묶음 5 보안): 코드·초대·조직 경계 ----

/// 가입 시도 한 번의 (상태, 본문) 전체. 실패 이유가 응답에서 갈리지 않는지 비교하는 데 쓴다.
async fn try_join(
    h: &Harness,
    mail: &CaptureMailer,
    email: &str,
    user: &str,
    org: Value,
    seed: u8,
) -> (u16, String) {
    let token = signup_token(h, mail, email).await;
    let keys = DeviceKeys::generate(&[seed; 64]);
    let body = json!({"signup_token": token, "user": user, "display_name": user, "device_pubkeys": device_pubkeys(&keys), "org": org});
    post_json(h, "/v1/devices", &body).await
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_failures_are_byte_identical_and_invite_expires() {
    let (h, mail) = start_hosted().await;
    let (_, boss) = join(
        &h,
        &mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "o"}}),
        json!([]),
        1,
    )
    .await;
    let (mut b, _) = connect(&h, &boss).await;
    let mut issue = async |email: Option<&str>| {
        let f = match email {
            Some(e) => json!({"t": "invite.create", "email": e}),
            None => json!({"t": "invite.create"}),
        };
        b.send(&f).await;
        let inv = b.recv().await;
        assert_eq!(inv["t"], "invite.created");
        inv["token"].as_str().unwrap().to_owned()
    };
    let bound = issue(Some("minji@x.io")).await;
    let open = issue(None).await;
    let soon_gone = issue(None).await;

    // 이유 넷 — 다른 이메일에 묶인 초대, 없는 토큰, 이미 쓴 초대, (아래) 만료 — 가 같은 응답이어야 한다.
    let wrong_email = try_join(&h, &mail, "eve@x.io", "eve", json!({"invite": bound}), 3).await;
    let unknown = try_join(
        &h,
        &mail,
        "f@x.io",
        "ff",
        json!({"invite": "A".repeat(43)}),
        4,
    )
    .await;
    let garbage = try_join(&h, &mail, "g@x.io", "gg", json!({"invite": "x"}), 5).await;
    assert_eq!(wrong_email.0, 422, "{wrong_email:?}");
    assert_eq!(wrong_email, unknown);
    assert_eq!(wrong_email, garbage);

    // 열린 초대는 한 번만 쓰인다. 쓰고 나면 위 실패와 같은 응답.
    assert_eq!(
        try_join(&h, &mail, "h@x.io", "hh", json!({"invite": open}), 6)
            .await
            .0,
        201
    );
    let consumed = try_join(&h, &mail, "i@x.io", "ii", json!({"invite": open}), 7).await;
    assert_eq!(consumed, wrong_email);

    // 만료: 7일에서 1ms 모자라면 아직, 지나면 같은 응답. 묶인 초대도 같다.
    h.fx.clock.advance(lodelai_relay::ws::INVITE_TTL_MS - 1);
    assert_eq!(
        try_join(&h, &mail, "j@x.io", "jj", json!({"invite": soon_gone}), 8)
            .await
            .0,
        201,
        "만료 직전엔 쓸 수 있다"
    );
    h.fx.clock.advance(1);
    let expired = try_join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": bound}),
        9,
    )
    .await;
    assert_eq!(expired, wrong_email, "만료된 초대 = 다른 실패와 같은 응답");
    // 응답 본문에 토큰·이메일·조직 이름이 실리지 않는다.
    for needle in [bound.as_str(), "minji@x.io", "boss"] {
        assert!(
            !expired.1.contains(needle),
            "{needle} 가 새었다: {}",
            expired.1
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_and_register_do_not_reveal_existing_accounts() {
    let (h, mail) = start_hosted().await;
    let (_, _boss) = join(
        &h,
        &mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "o"}}),
        json!([]),
        1,
    )
    .await;
    // 코드 요청: 계정이 있는 이메일과 없는 이메일이 상태·본문 모두 같다.
    let existing = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "boss@x.io", "privacy": {"version": "test"}}),
    )
    .await;
    let fresh = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "new@x.io", "privacy": {"version": "test"}}),
    )
    .await;
    assert_eq!(existing, fresh);
    // 대문자·공백이 섞인 같은 이메일도 같은 응답(정규화는 서버 안에서만).
    let shouty = post_json(
        &h,
        "/v1/signup",
        &json!({"email": " BOSS@X.io ", "privacy": {"version": "test"}}),
    )
    .await;
    assert_eq!(shouty.0, existing.0);
    // 코드 확인: 계정 있음/없음 × 틀린 코드가 같은 응답.
    let a = post_json(
        &h,
        "/v1/signup/verify",
        &json!({"email": "boss@x.io", "code": "999999"}),
    )
    .await;
    let b = post_json(
        &h,
        "/v1/signup/verify",
        &json!({"email": "ghost@x.io", "code": "999999"}),
    )
    .await;
    assert_eq!(a, b);
    // 가입 토큰은 그 이메일 것 — 그 이메일 계정(boss)에 다른 사용자 이름으로 붙을 수 없다(409). 묶음 18(ed5b8f9a): 409
    // account_exists 는 그 계정을 싣는다 — 이메일 주인 확인 뒤라 verify 가 이미 이 토큰 주인에게 준 것과 같고, 그 밖의 것은 없다.
    let (code, verified) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "boss@x.io", "privacy": {"version": "test"}}),
    )
    .await;
    assert_eq!(code, 202, "{verified}");
    let sent = mail.0.lock().unwrap()["boss@x.io"].clone();
    let (_, verified) = post_json(
        &h,
        "/v1/signup/verify",
        &json!({"email": "boss@x.io", "code": sent}),
    )
    .await;
    let verified: Value = serde_json::from_str(&verified).unwrap();
    let token = verified["signup_token"].as_str().unwrap().to_owned();
    let k = DeviceKeys::generate(&[20; 64]);
    let (code, body) = post_json(
        &h,
        "/v1/devices",
        &hosted_body(&token, Some("someone-else"), &k),
    )
    .await;
    assert_eq!(code, 409, "{body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body,
        json!({"reason": "account_exists", "account": verified["account"]}),
        "verify 가 준 것 말고는 싣지 않는다"
    );
    // 가입 토큰은 1회용: 같은 토큰으로 두 번째 등록은 거절.
    let token = signup_token(&h, &mail, "boss@x.io").await;
    let k2 = DeviceKeys::generate(&[21; 64]);
    assert_eq!(
        post_json(&h, "/v1/devices", &hosted_body(&token, None, &k2))
            .await
            .0,
        201
    );
    let k3 = DeviceKeys::generate(&[22; 64]);
    assert_ne!(
        post_json(&h, "/v1/devices", &hosted_body(&token, None, &k3))
            .await
            .0,
        201,
        "쓴 가입 토큰"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn other_org_people_are_invisible_and_unreachable() {
    let (h, mail) = start_hosted().await;
    let (_, ann) = join(
        &h,
        &mail,
        "ann@a.io",
        "ann",
        json!({"create": {"name": "A"}}),
        json!([]),
        1,
    )
    .await;
    let (_, bob) = join(
        &h,
        &mail,
        "bob@b.io",
        "bob",
        json!({"create": {"name": "B"}}),
        json!([]),
        2,
    )
    .await;
    let (mut a, _) = connect(&h, &ann).await;
    let (mut b, _) = connect(&h, &bob).await;
    // 디렉터리: 서로 이름·이메일·팀·세션이 보이지 않는다.
    for (c, other) in [(&mut a, "bob"), (&mut b, "ann")] {
        c.send(&json!({"t": "directory.list"})).await;
        let d = next_dir(c).await;
        let s = d.to_string();
        assert_eq!(d["people"].as_array().unwrap().len(), 1, "{s}");
        assert!(!s.contains(other), "다른 조직 이름이 디렉터리에: {s}");
    }
    // 관리자 동작은 자기 조직에만: 다른 조직 사람의 기기 폐기는 모르는 기기와 같은 응답.
    a.send(&json!({"t": "device.revoke", "device_id": bob.device_id}))
        .await;
    let known_other = a.recv().await;
    let ghost = DeviceKeys::generate(&[99; 64]);
    a.send(&json!({"t": "device.revoke", "device_id": ghost.device_id().as_str()}))
        .await;
    let unknown = a.recv().await;
    assert_eq!(known_other, unknown);
    // 다른 조직 사람에게 보내기: 없는 사람에게 보낸 것과 같은 nack(존재 여부가 갈리지 않는다), 받는 쪽은 조용.
    let me = ann.address();
    let to_other = msg(&h, &ann, &me, "chat", &bob.address(), json!({}), "hi");
    let to_nobody = msg(&h, &ann, &me, "chat", "nobody@local", json!({}), "hi");
    a.send(&json!({"t": "send", "message": to_other})).await;
    let r1 = a.recv_text().await.replace(&mid(&to_other), "ID");
    a.send(&json!({"t": "send", "message": to_nobody})).await;
    let r2 = a.recv_text().await.replace(&mid(&to_nobody), "ID");
    assert_eq!(r1, r2);
    assert!(r1.contains("\"reason\":\"unroutable\""), "{r1}");
    b.expect_silence().await;
}

// ---- 묶음 5: 관리자 여러 명·내보내기·조직 나가기·last_admin (m1-spec §17.3) ----

/// hosted 조직 하나: boss(만든 사람, 관리자) + 초대로 들어온 `members`. 사람 순서대로 seed 1, 2, ….
async fn hosted_org(h: &Harness, mail: &CaptureMailer, members: &[&str]) -> Vec<User> {
    let (code, boss) = join(
        h,
        mail,
        "boss@x.io",
        "boss",
        json!({"create": {"name": "루이보스"}}),
        json!([]),
        1,
    )
    .await;
    assert_eq!(code, 201);
    let (mut b, _) = connect(h, &boss).await;
    let mut people = vec![boss];
    for (i, m) in members.iter().enumerate() {
        b.send(&json!({"t": "invite.create"})).await;
        let inv = b.recv().await;
        let tok = inv["token"].as_str().unwrap().to_owned();
        let seed = u8::try_from(i + 2).unwrap();
        let (code, u) = join(
            h,
            mail,
            &format!("{m}@x.io"),
            m,
            json!({"invite": tok}),
            json!([]),
            seed,
        )
        .await;
        assert_eq!(code, 201);
        next_dir(&mut b).await;
        people.push(u);
    }
    people
}

/// 같은 이메일로 기기 하나 더(내 다른 맥).
async fn second_device(h: &Harness, mail: &CaptureMailer, u: &User, seed: u8) -> User {
    h.fx.clock.advance(60_000);
    let token = signup_token(h, mail, &format!("{}@x.io", u.name)).await;
    let keys = DeviceKeys::generate(&[seed; 64]);
    let (code, resp) = post_json(h, "/v1/devices", &hosted_body(&token, None, &keys)).await;
    assert_eq!(code, 201, "{resp}");
    User {
        name: u.name.clone(),
        device_id: keys.device_id().as_str().to_owned(),
        keys,
    }
}

/// 닫힐 때까지 읽은 프레임 중 `device.revoked` 의 `by`. 그 뒤엔 아무것도 오지 않는다(폐기 → 닫기).
fn revoked_by_then_closed(texts: &[String]) -> Option<String> {
    let i = texts
        .iter()
        .position(|t| t.contains("\"device.revoked\""))?;
    assert_eq!(i, texts.len() - 1, "폐기 통지 뒤에 더 옴: {texts:?}");
    let v: Value = serde_json::from_str(&texts[i]).unwrap();
    v["by"].as_str().map(str::to_owned)
}

/// 핸드셰이크를 끝까지 하고 첫 응답(ready 또는 error).
async fn handshake_answer(h: &Harness, u: &User) -> Value {
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    c.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": u.device_id, "user": u.name}))
        .await;
    let ch = c.recv().await;
    let sig = sign_challenge(
        &u.keys.signing,
        SERVER,
        &u.device_id,
        ch["nonce"].as_str().unwrap(),
    )
    .unwrap();
    c.send(&json!({"t": "auth", "sig": sig})).await;
    c.recv().await
}

#[tokio::test(flavor = "multi_thread")]
async fn org_admin_gives_takes_and_keeps_one_admin() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;

    // 관리자 아님 → protocol.
    m.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    assert_eq!(m.recv().await["code"], "protocol");
    // 조직 밖·없는 사람 → protocol.
    b.send(&json!({"t": "org.admin", "user": "nobody", "admin": true}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    // 주기 → 같은 조직에 directory.update(admins 이름순).
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    assert_eq!(
        next_dir(&mut b).await["org"]["admins"],
        json!(["boss", "minji"])
    );
    assert_eq!(
        next_dir(&mut m).await["org"]["admins"],
        json!(["boss", "minji"])
    );
    // 이미 그 상태면 멱등, 방송 없음.
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    b.expect_silence().await;
    // 새 관리자는 자기 자신을 뺄 수 있다.
    m.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    assert_eq!(next_dir(&mut m).await["org"]["admins"], json!(["boss"]));
    // 마지막 관리자는 빠지지 않는다.
    b.send(&json!({"t": "org.admin", "user": "boss", "admin": false}))
        .await;
    next_dir(&mut b).await;
    b.send(&json!({"t": "org.admin", "user": "boss", "admin": false}))
        .await;
    assert_eq!(b.recv().await["code"], "last_admin");
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(next_dir(&mut b).await["org"]["admins"], json!(["boss"]));
}

/// 처리방침 0.2.0 3항: 조직을 나가면 기기 바꾸기 요청·막은 기록을 지운다. 쓰지 않은 조직 만들기 코드·승인은 기한 뒤 30일이 지나면 청소가 지운다.
#[tokio::test(flavor = "multi_thread")]
async fn privacy_retention_leave_and_setup_codes() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let db = &h.app.db;
    let now = h.fx.clock.now().0;
    db.recovery_schedule("jun", "k1_x", now, now + 1_000, &[p[2].device_id.clone()])
        .unwrap();
    db.recovery_end(
        "jun",
        Some(lodelai_relay::db::RecoveryState::Blocked),
        now,
        Some(&p[2].device_id),
    )
    .unwrap();
    assert!(db.recovery("jun").unwrap().is_some());
    assert_eq!(db.recovery_blocks_since("jun", 0).unwrap().len(), 1);
    db.member_leave("jun", now).unwrap();
    assert!(db.recovery("jun").unwrap().is_none());
    assert!(db.recovery_blocks_since("jun", 0).unwrap().is_empty());

    // 쓰지 않은 코드: 기한 뒤 30일 안은 남고(‘기한 지남’ 안내), 지나면 청소가 지운다.
    let day_ms = 24 * 60 * 60 * 1000;
    db.add_setup_code("old", b"h-old", None, None, now + day_ms, now)
        .unwrap();
    h.fx.clock.advance(day_ms * 30);
    h.app.expire_tick();
    assert_eq!(db.list_setup_codes(0).unwrap().len(), 1, "기한 뒤 30일 안");
    h.fx.clock.advance(day_ms * 2);
    h.app.expire_tick();
    assert!(db.list_setup_codes(0).unwrap().is_empty(), "30일 지남");
}

/// #737 관리자 폐기(ADR 0006): 메일 확인 끊기를 건 사람의 대상 기기만, 같은 조직 관리자가 지금 끊는다 — 요청 기기가 바로
/// 쓰이고 그 사람에게 메일. 자기 user·관리자 아님·걸기 없음·대상 아님은 protocol. 확인 안 된 관리자 기기는 관리자 동작 전부
/// device_unconfirmed.
#[tokio::test(flavor = "multi_thread")]
async fn admin_revokes_old_device_of_switching_member() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let minji2 = second_device(&h, &mail, &p[1], 12).await;
    let mut b = recovery_connect(&h, &p[0]).await;
    let mut m1 = recovery_connect(&h, &p[1]).await;
    let mut m2 = recovery_connect(&h, &minji2).await;
    let mut j = recovery_connect(&h, &p[2]).await;
    let cut =
        |user: &str, d: &str| json!({"t": "member.revoke_device", "user": user, "device_id": d});

    // 걸기 없음 → protocol.
    b.send(&cut("minji", &p[1].device_id)).await;
    assert_eq!(recv_t(&mut b, "error").await["code"], "protocol");

    m2.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut m2, "device.recover_scheduled").await;
    recv_t(&mut m1, "device.recover_against").await;
    // 관리자는 디렉터리에서 대상(옛 기기)을 본다.
    b.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut b, "directory").await;
    let minji = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["address"].as_str().unwrap().starts_with("minji@"))
        .unwrap()
        .clone();
    assert_eq!(minji["recovery"]["targets"], json!([p[1].device_id]));
    // 관리자는 대상(옛 기기)의 마지막 접속(일 단위)을 본다 — 새 기기 것은 아니다.
    let dev = |id: &str| {
        minji["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["device_id"] == id)
            .unwrap()
            .clone()
    };
    assert!(dev(&p[1].device_id)["last_seen_at"].is_string(), "{minji}");
    assert!(
        dev(&minji2.device_id).get("last_seen_at").is_none(),
        "{minji}"
    );
    // 관리자 아닌 동료는 못 본다.
    j.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut j, "directory").await;
    let mj = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["address"].as_str().unwrap().starts_with("minji@"))
        .unwrap()
        .clone();
    assert!(
        mj["devices"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d.get("last_seen_at").is_none()),
        "{mj}"
    );
    // 본인(새 기기)의 디렉터리: 지금 붙어 있는 옛 기기의 last_auth_at 은 지금(코어 seen_since_me).
    m2.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut m2, "directory").await;
    let me = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["address"].as_str().unwrap().starts_with("minji@"))
        .unwrap()
        .clone();
    let old = me["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["device_id"] == p[1].device_id)
        .unwrap()
        .clone();
    assert_eq!(old["last_auth_at"], now_str(&h, 0), "{old}");

    // 관리자 아님·자기 user·대상 아닌 기기 → protocol.
    j.send(&cut("minji", &p[1].device_id)).await;
    assert_eq!(recv_t(&mut j, "error").await["code"], "protocol");
    b.send(&cut("boss", &p[0].device_id)).await;
    assert_eq!(recv_t(&mut b, "error").await["code"], "protocol");
    b.send(&cut("minji", &minji2.device_id)).await;
    assert_eq!(recv_t(&mut b, "error").await["code"], "protocol");

    // 끊기 → 옛 기기 device.revoked{by: admin_device}(내보내기와 다른 사유)·닫힘, 요청 기기는 끝, 메일.
    b.send(&cut("minji", &p[1].device_id)).await;
    let got = m1.drain_until_closed().await;
    assert!(
        got.iter()
            .any(|f| f["t"] == "device.revoked" && f["by"] == "admin_device"),
        "{got:?}"
    );
    // 대상이 다 끊겼다 — 걸기는 실행 완료(done)와 같다(계약 순서). 요청 기기가 홀로 남아 잎 자격을 얻었어도 certified 가
    // 아니다: 동료 코어는 디렉터리에서 걸기가 그냥 사라지면 '옛 기기에서 확인' 줄을 낸다(관문 8번).
    let rec = recv_t(&mut m2, "device.recovered").await;
    assert_eq!(rec["targets"], json!([]), "{rec}");
    j.drain().await;
    j.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut j, "directory").await;
    let mj = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["address"].as_str().unwrap().starts_with("minji@"))
        .unwrap()
        .clone();
    assert_eq!(mj["recovery"]["state"], "done", "{mj}");
    assert!(h.app.db.device(&p[1].device_id).unwrap().is_none());
    assert!(mail_subjects(&mail)
        .await
        .iter()
        .any(|s| s.contains("관리자가 예전 기기를 끊었어요")));
    // 이제 요청 기기는 잎 자격 — 다시 걸면 trusted.
    m2.send(&json!({"t": "device.recover"})).await;
    assert_eq!(refused(&recv_t(&mut m2, "error").await).0, Some("trusted"));

    // 확인 안 된 관리자 기기 → 관리자 동작 전부 device_unconfirmed.
    let boss2 = second_device(&h, &mail, &p[0], 20).await;
    let mut b2 = recovery_connect(&h, &boss2).await;
    for f in [
        json!({"t": "org.admin", "user": "jun", "admin": true}),
        json!({"t": "member.remove", "user": "jun"}),
        json!({"t": "org.update", "name": "다른 이름"}),
        json!({"t": "team.create", "name": "새 팀"}),
        json!({"t": "team.update", "id": "t1", "name": "새 팀"}),
        json!({"t": "team.delete", "id": "t1"}),
        json!({"t": "invite.create"}),
        cut("jun", &p[2].device_id),
    ] {
        b2.send(&f).await;
        assert_eq!(
            recv_t(&mut b2, "error").await["code"],
            "device_unconfirmed",
            "{f}"
        );
    }
    // 확인된 관리자 기기는 그대로 된다.
    b.drain().await;
    b.send(&json!({"t": "org.admin", "user": "jun", "admin": true}))
        .await;
    let f = b.recv().await;
    assert_eq!(f["org"]["admins"], json!(["boss", "jun"]), "{f}");
}

#[tokio::test(flavor = "multi_thread")]
async fn member_remove_revokes_all_devices_and_revives_by_new_invite() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let minji2 = second_device(&h, &mail, &p[1], 12).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m1, _) = connect(&h, &p[1]).await;
    let (mut m2, _) = connect(&h, &minji2).await;
    let (mut j, _) = connect(&h, &p[2]).await;

    // 관리자 아님·자기·조직 밖 → protocol.
    j.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    assert_eq!(j.recv().await["code"], "protocol");
    b.send(&json!({"t": "member.remove", "user": "boss"})).await;
    assert_eq!(b.recv().await["code"], "protocol");
    b.send(&json!({"t": "member.remove", "user": "nobody"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    // 관리자 대상은 protocol(먼저 org.admin false).
    b.send(&json!({"t": "org.admin", "user": "jun", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut j).await;
    b.send(&json!({"t": "member.remove", "user": "jun"})).await;
    assert_eq!(b.recv().await["code"], "protocol");
    // 관리자 대상 남의 device.revoke 도 protocol.
    b.send(&json!({"t": "device.revoke", "device_id": p[2].device_id}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");

    // 내보내기: minji 의 두 기기 모두 device.revoked{by:admin} 뒤 닫힘, 디렉터리에서 빠짐.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    for c in [&mut m1, &mut m2] {
        let texts = expect_closed(c, Duration::from_secs(3)).await;
        assert_eq!(revoked_by_then_closed(&texts).as_deref(), Some("admin"));
    }
    let d = next_dir(&mut b).await;
    assert!(d["people"]
        .as_array()
        .unwrap()
        .iter()
        .all(|x| x["address"] != "minji@local"));
    // 다시 접속하면(자기 키) error{device_revoked, by:admin, at}.
    let e = handshake_answer(&h, &p[1]).await;
    assert_eq!(
        (e["code"].as_str(), e["by"].as_str()),
        (Some("device_revoked"), Some("admin"))
    );
    assert_eq!(e["at"], now_str(&h, 0), "{e}");
    // 같은 사람을 다시 내보내면 protocol.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");

    // 이메일 코드만으로는 다시 붙지 않는다(verify = new, 조직 없는 등록은 400).
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "minji@x.io").await;
    let k = DeviceKeys::generate(&[30; 64]);
    let (code, _) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &k)).await;
    assert_eq!(code, 400);
    // 새 초대로 같은 아이디가 되살아난다(다른 아이디를 대면 409 — 기기 추가와 같은 규칙).
    b.send(&json!({"t": "invite.create"})).await;
    let tok = b.recv().await["token"].as_str().unwrap().to_owned();
    let (code, _) = join(
        &h,
        &mail,
        "minji@x.io",
        "other-id",
        json!({"invite": tok}),
        json!([]),
        31,
    )
    .await;
    assert_eq!(code, 409);
    let (code, back) = join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": tok}),
        json!([]),
        31,
    )
    .await;
    assert_eq!(code, 201);
    let (_m, ready) = connect(&h, &back).await;
    assert_eq!(ready["t"], "ready");
    let d = next_dir(&mut b).await;
    assert!(d["people"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["address"] == "minji@local"));
    assert_eq!(d["org"]["admins"], json!(["boss", "jun"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_revoking_one_device_tells_only_that_device() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let minji2 = second_device(&h, &mail, &p[1], 12).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m1, _) = connect(&h, &p[1]).await;
    let (mut m2, _) = connect(&h, &minji2).await;
    b.send(&json!({"t": "device.revoke", "device_id": minji2.device_id}))
        .await;
    let texts = expect_closed(&mut m2, Duration::from_secs(3)).await;
    assert_eq!(revoked_by_then_closed(&texts).as_deref(), Some("admin"));
    // 같은 사람의 다른 기기는 폐기 통지를 받지 않는다 — 디렉터리만.
    let f = next_dir(&mut m1).await;
    assert_eq!(
        f["people"][1]["devices"].as_array().unwrap().len(),
        1,
        "{f}"
    );
    m1.expect_silence().await;
    let e = handshake_answer(&h, &minji2).await;
    assert_eq!(
        (e["code"].as_str(), e["by"].as_str()),
        (Some("device_revoked"), Some("admin"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn member_leave_revokes_all_my_devices_and_needs_another_admin() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let minji2 = second_device(&h, &mail, &p[1], 12).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m1, _) = connect(&h, &p[1]).await;
    let (mut m2, _) = connect(&h, &minji2).await;

    // 유일한 관리자는 다른 사람이 있으면 나갈 수 없고, 마지막 기기도 끊을 수 없다(연결은 그대로).
    b.send(&json!({"t": "member.leave"})).await;
    assert_eq!(b.recv().await["code"], "last_admin");
    b.send(&json!({"t": "device.revoke"})).await;
    assert_eq!(b.recv().await["code"], "last_admin");
    b.send(&json!({"t": "ping"})).await;
    assert_eq!(b.recv().await["t"], "pong");

    // 멤버가 나가면 내 모든 연결에 device.revoked{by:left} 뒤 닫힘.
    m1.send(&json!({"t": "member.leave"})).await;
    for c in [&mut m1, &mut m2] {
        let texts = expect_closed(c, Duration::from_secs(3)).await;
        assert_eq!(revoked_by_then_closed(&texts).as_deref(), Some("left"));
    }
    let d = next_dir(&mut b).await;
    assert_eq!(d["people"].as_array().unwrap().len(), 1);
    let e = handshake_answer(&h, &minji2).await;
    assert_eq!(
        (e["code"].as_str(), e["by"].as_str()),
        (Some("device_revoked"), Some("left"))
    );

    // 혼자 남은 관리자는 나갈 수 있다(갇히지 않게).
    b.send(&json!({"t": "member.leave"})).await;
    let texts = expect_closed(&mut b, Duration::from_secs(3)).await;
    assert!(texts[0].contains("\"left\""), "{texts:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn lone_admin_can_log_out_and_multi_device_admin_can_drop_one() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let boss2 = second_device(&h, &mail, &p[0], 11).await;
    let (_b1, _) = connect(&h, &p[0]).await;
    let (mut b2, _) = connect(&h, &boss2).await;
    // 기기가 둘이면 하나는 끊을 수 있다.
    b2.send(&json!({"t": "device.revoke"})).await;
    let texts = expect_closed(&mut b2, Duration::from_secs(3)).await;
    assert!(texts[0].contains("device.revoked"), "{texts:?}");
    // 혼자인 조직의 관리자는 마지막 기기도 끊을 수 있다.
    let (h2, mail2) = start_hosted().await;
    let solo = hosted_org(&h2, &mail2, &[]).await;
    let (mut s, _) = connect(&h2, &solo[0]).await;
    s.send(&json!({"t": "device.revoke"})).await;
    let texts = expect_closed(&mut s, Duration::from_secs(3)).await;
    assert!(texts[0].contains("device.revoked"), "{texts:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn local_relay_refuses_org_admin_frames() {
    let h = start().await;
    let a = register(&h, "alice", 1).await;
    let _b = register(&h, "bob", 2).await;
    let (mut c, _) = connect(&h, &a).await;
    for f in [
        json!({"t": "org.admin", "user": "bob", "admin": true}),
        json!({"t": "member.remove", "user": "bob"}),
        json!({"t": "member.leave"}),
        json!({"t": "server.status"}),
    ] {
        c.send(&f).await;
        assert_eq!(c.recv().await["code"], "protocol", "{f}");
    }
    // 로컬엔 관리자가 없어 last_admin 이 걸리지 않는다 — 자기 폐기 그대로.
    c.send(&json!({"t": "device.revoke"})).await;
    let texts = expect_closed(&mut c, Duration::from_secs(3)).await;
    assert!(texts[0].contains("device.revoked"), "{texts:?}");
}

// ---- QA(#355 묶음 5 보안): 관리자 권한의 경계 ----

#[tokio::test(flavor = "multi_thread")]
async fn admin_actions_do_not_cross_orgs_and_do_not_reveal_existence() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await; // 조직 A: boss(관리자), minji
    let (code, zed) = join(
        &h,
        &mail,
        "zed@y.io",
        "zed",
        json!({"create": {"name": "다른 조직"}}),
        json!([]),
        40,
    )
    .await;
    assert_eq!(code, 201);
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut z, _) = connect(&h, &zed).await;
    // A 의 관리자가 B 사람(zed)을 대상으로: 없는 사람과 응답이 한 글자도 다르지 않다.
    for (other, ghost, mk) in [
        (
            json!({"t": "org.admin", "user": "zed", "admin": true}),
            json!({"t": "org.admin", "user": "ghost", "admin": true}),
            "org.admin",
        ),
        (
            json!({"t": "member.remove", "user": "zed"}),
            json!({"t": "member.remove", "user": "ghost"}),
            "member.remove",
        ),
    ] {
        b.send(&other).await;
        let r_other = b.recv_text().await;
        b.send(&ghost).await;
        let r_ghost = b.recv_text().await;
        assert_eq!(r_other, r_ghost, "{mk}");
        assert!(r_other.contains("\"code\":\"protocol\""), "{r_other}");
    }
    // 아무 일도 없었다: B 는 그대로 자기 조직의 유일한 관리자, 연결도 살아 있다.
    z.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut z).await;
    assert_eq!(d["org"]["admins"], json!(["zed"]));
    assert_eq!(d["people"].as_array().unwrap().len(), 1);
    z.send(&json!({"t": "ping"})).await;
    assert_eq!(z.recv().await["t"], "pong");
    // 반대로 B 관리자가 A 사람(minji)을 내보낼 수도 없다.
    z.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    assert_eq!(z.recv().await["code"], "protocol");
    z.send(&json!({"t": "org.admin", "user": "boss", "admin": false}))
        .await;
    assert_eq!(z.recv().await["code"], "protocol");
}

#[tokio::test(flavor = "multi_thread")]
async fn demoted_admin_loses_power_on_the_open_connection() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    // 새 관리자는 실제로 권한이 있다 — 초대·팀.
    m.send(&json!({"t": "invite.create"})).await;
    assert_eq!(m.recv().await["t"], "invite.created");
    // 내려가면 같은 연결에서 곧바로 모든 관리자 동작이 거절된다(연결 때 한 번만 판정하지 않는다).
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    for f in [
        json!({"t": "invite.create"}),
        json!({"t": "team.create", "name": "t"}),
        json!({"t": "org.update", "name": "탈취"}),
        json!({"t": "org.admin", "user": "boss", "admin": false}),
        json!({"t": "org.admin", "user": "jun", "admin": true}),
        json!({"t": "member.remove", "user": "jun"}),
        json!({"t": "device.revoke", "device_id": p[2].device_id}),
    ] {
        m.send(&f).await;
        let e = m.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{f}"
        );
    }
    // 조직은 그대로: boss 가 유일한 관리자, 이름 그대로.
    b.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut b).await;
    assert_eq!(d["org"]["admins"], json!(["boss"]));
    assert_eq!(d["org"]["name"], "루이보스");
    assert_eq!(d["people"].as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_admins_demoting_each_other_at_once_leave_one() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    // 같은 순간 서로를 내린다. 반복해도 관리자가 0명이 되는 순서는 없어야 한다.
    for round in 0..20 {
        h.fx.clock.advance(10_000); // 프레임 한도(버킷 60) 리필
        let (fb, fm) = (
            json!({"t": "org.admin", "user": "minji", "admin": false}),
            json!({"t": "org.admin", "user": "boss", "admin": false}),
        );
        tokio::join!(b.send(&fb), m.send(&fm));
        // 서로에게 온 프레임을 모두 비운다(방송·오류 어느 쪽이든).
        b.send(&json!({"t": "directory.list"})).await;
        m.send(&json!({"t": "directory.list"})).await;
        let mut last = Value::Null;
        for c in [&mut b, &mut m] {
            loop {
                let f = c.recv().await;
                if f["t"] == "directory" {
                    last = f;
                    break;
                }
            }
        }
        let admins = last["org"]["admins"].as_array().unwrap().clone();
        assert!(!admins.is_empty(), "{round}회차: 관리자가 0명: {last}");
        // 다음 판을 위해 둘 다 관리자로 되돌린다(이미 그 상태면 멱등).
        let (keeper, other) = if admins[0] == "boss" {
            (&mut b, "minji")
        } else {
            (&mut m, "boss")
        };
        keeper
            .send(&json!({"t": "org.admin", "user": other, "admin": true}))
            .await;
        b.send(&json!({"t": "ping"})).await;
        m.send(&json!({"t": "ping"})).await;
        for c in [&mut b, &mut m] {
            loop {
                if c.recv().await["t"] == "pong" {
                    break;
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_member_is_unreachable_and_leaves_no_session_behind() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    let (mut j, _) = connect(&h, &p[2]).await;
    publish(&mut m, "backend", "question").await;
    next_dir(&mut b).await;
    next_dir(&mut j).await;
    next_dir(&mut m).await;
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    let _ = expect_closed(&mut m, Duration::from_secs(3)).await;
    let d = next_dir(&mut j).await;
    let s = d.to_string();
    assert!(!s.contains("minji"), "내보낸 사람이 디렉터리에 남음: {s}");
    assert!(
        d["sessions"].as_array().is_none_or(|v| v.is_empty()),
        "내보낸 사람의 공개 세션이 남음: {s}"
    );
    // 그에게 보내기: 한 번도 없던 사람과 같은 nack, 세션 주소도 같다.
    let me = p[2].address();
    let to_removed = msg(&h, &p[2], &me, "chat", &p[1].address(), json!({}), "x");
    let to_nobody = msg(&h, &p[2], &me, "chat", "nobody@local", json!({}), "x");
    j.send(&json!({"t": "send", "message": to_removed})).await;
    let r1 = j.recv_text().await.replace(&mid(&to_removed), "ID");
    j.send(&json!({"t": "send", "message": to_nobody})).await;
    let r2 = j.recv_text().await.replace(&mid(&to_nobody), "ID");
    assert_eq!(r1, r2);
    assert!(r1.contains("unroutable"), "{r1}");
    let q = json!({"grade": "question"});
    let to_sess = msg(
        &h,
        &p[2],
        &me,
        "request",
        &format!("{}/backend", p[1].address()),
        q,
        "x",
    );
    j.send(&json!({"t": "send", "message": to_sess})).await;
    let r3 = j.recv_text().await.replace(&mid(&to_sess), "ID");
    assert_eq!(r1, r3, "공개 세션이었던 주소도 같은 응답");
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_from_a_demoted_and_removed_admin_is_reported() {
    // 관리자에서 내려가면(나가기·내보내기 포함) 그 사람이 만든 안 쓴 초대도 끝난다 — 미리 뿌려 둔 초대로 사람을 들이지 못하게.
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    m.send(&json!({"t": "invite.create"})).await;
    let tok = m.recv().await["token"].as_str().unwrap().to_owned();
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    let _ = expect_closed(&mut m, Duration::from_secs(3)).await;
    let (code, body) = try_join(&h, &mail, "late@x.io", "late", json!({"invite": tok}), 50).await;
    assert_eq!(
        code, 422,
        "내보낸 관리자가 만든 초대가 아직 통한다(201): {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_status_only_for_remote_admins_and_has_no_ids() {
    let (h, mail, code) = start_remote_full().await;
    let kb = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &kb, Some(&code)).await,
        201
    );
    let boss = User {
        name: "boss".into(),
        device_id: kb.device_id().as_str().to_owned(),
        keys: kb,
    };
    let (mut b, _) = connect(&h, &boss).await;
    b.send(&json!({"t": "invite.create"})).await;
    let invite = b.recv().await["token"].as_str().unwrap().to_owned();
    let token = remote_token(&h, &mail, "minji@x.io").await;
    let km = DeviceKeys::generate(&[2; 64]);
    let body = json!({"signup_token": token, "user": "minji", "display_name": "minji",
        "device_pubkeys": device_pubkeys(&km), "org": {"invite": invite}});
    assert_eq!(post_json(&h, "/v1/devices", &body).await.0, 201);
    next_dir(&mut b).await;
    let minji = User {
        name: "minji".into(),
        device_id: km.device_id().as_str().to_owned(),
        keys: km,
    };
    let (mut m, _) = connect(&h, &minji).await;

    // 관리자 아님 → protocol.
    m.send(&json!({"t": "server.status"})).await;
    assert_eq!(m.recv().await["code"], "protocol");

    b.send(&json!({"t": "server.status"})).await;
    let raw = b.recv_text().await;
    let s: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(s["t"], "server.status", "{raw}");
    assert_eq!(s["members"], 2);
    assert_eq!(s["devices"], json!({"connected": 2, "total": 2}));
    assert_eq!(s["mail"]["daily_limit"], 80);
    assert_eq!(s["mail"]["sent_today"], 2);
    assert_eq!(s["queue"]["pending"], 0);
    assert_eq!(s["backup"]["last"], "none");
    // 묶음 15 §2.7: 파일 저장 공간(첨부 없음)과 그 판정.
    assert_eq!(
        s["files"],
        json!({"bytes": 0, "count": 0, "attachments": {"bytes": 0, "count": 0},
            "avatars": {"bytes": 0, "count": 0}}),
        "{raw}"
    );
    assert_eq!(s["levels"]["files"], "ok", "{raw}");
    assert_eq!(s["level"], "ok", "{raw}");
    assert_eq!(s["reasons"], json!([]));
    assert_eq!(s["now_ms"], START_MS);
    // 주소·아이디·기기 id·이메일이 응답 어디에도 없다.
    for leak in [
        "boss",
        "minji",
        "x.io",
        &boss.device_id,
        &minji.device_id,
        PUBLIC,
    ] {
        assert!(!raw.contains(leak), "{leak} 가 샘: {raw}");
    }
    // 10초 캐시: 숫자는 그대로, now_ms 는 새로.
    let (_m2, _) = connect(&h, &minji).await;
    h.fx.clock.advance(5_000);
    b.send(&json!({"t": "server.status"})).await;
    let s: Value = b.recv().await;
    assert_eq!(s["devices"]["connected"], 2);
    assert_eq!(s["now_ms"], START_MS + 5_000);
    h.fx.clock.advance(5_000);
    b.send(&json!({"t": "server.status"})).await;
    assert_eq!(b.recv().await["devices"]["connected"], 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_refuses_device_register_even_for_admin() {
    let (h, mail, code) = start_remote_full().await;
    let kb = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &kb, Some(&code)).await,
        201
    );
    let boss = User {
        name: "boss".into(),
        device_id: kb.device_id().as_str().to_owned(),
        keys: kb,
    };
    let (mut b, ready) = connect(&h, &boss).await;
    assert_eq!(ready["admin"], true);
    b.send(&json!({"t": "device.register", "code": "lodelai-dev1.AAAA"}))
        .await;
    assert_eq!(b.recv().await["code"], "protocol");
    b.send(&json!({"t": "ping"})).await;
    assert_eq!(b.recv().await["t"], "pong", "연결은 그대로");
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_dev_mail_works_only_on_test_domains() {
    let dir = tempfile::tempdir().unwrap();
    let start = |host: &'static str| {
        let dir = dir.path().join(host);
        async move {
            let mailer = std::sync::Arc::new(lodelai_relay::mail::FileMailer::new(dir));
            start_full(
                |c| {
                    c.remote = true;
                    c.public_host = Some(host.into());
                    c.privacy_version = Some(PRIVACY.into());
                },
                Db::memory().unwrap(),
                Some(mailer),
            )
            .await
        }
    };
    let body = json!({"email": "a@x.io", "privacy": {"version": PRIVACY}});
    // 시험용 도메인(시험 원격 relay)은 파일 메일로 코드를 낸다.
    let h = start("lodelai.test").await;
    assert_eq!(post_json(&h, "/v1/signup", &body).await.0, 202);
    assert!(dir.path().join("lodelai.test").join("a@x.io.txt").exists());
    // 실제 도메인에 가짜 메일이 붙어 있으면 코드를 내지 않는다(503 → 앱 email_unavailable).
    let h = start("relay.example.com").await;
    assert_eq!(post_json(&h, "/v1/signup", &body).await.0, 503);
    assert!(!dir.path().join("relay.example.com").exists());
}

// ---- QA(#355 묶음 5 보안): server.status ----

/// 원격 relay 에 관리자 boss 한 명(설정 코드로 만든 조직).
async fn remote_boss(
    h: &Harness,
    mail: &CaptureMailer,
    code: &str,
    email: &str,
    user: &str,
    seed: u8,
) -> User {
    let k = DeviceKeys::generate(&[seed; 64]);
    assert_eq!(create_org(h, mail, email, user, &k, Some(code)).await, 201);
    User {
        name: user.into(),
        device_id: k.device_id().as_str().to_owned(),
        keys: k,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_status_follows_the_admin_role_on_an_open_connection() {
    let (h, mail, code) = start_remote_full().await;
    let boss = remote_boss(&h, &mail, &code, "boss@x.io", "boss", 1).await;
    let (mut b, _) = connect(&h, &boss).await;
    b.send(&json!({"t": "invite.create"})).await;
    let invite = b.recv().await["token"].as_str().unwrap().to_owned();
    let token = remote_token(&h, &mail, "minji@x.io").await;
    let km = DeviceKeys::generate(&[2; 64]);
    let body = json!({"signup_token": token, "user": "minji", "display_name": "minji",
        "device_pubkeys": device_pubkeys(&km), "org": {"invite": invite}});
    assert_eq!(post_json(&h, "/v1/devices", &body).await.0, 201);
    next_dir(&mut b).await;
    let minji = User {
        name: "minji".into(),
        device_id: km.device_id().as_str().to_owned(),
        keys: km,
    };
    let (mut m, _) = connect(&h, &minji).await;

    // 올라가면 같은 연결에서 바로 응답, 내려가면 바로 거절(연결 때 한 번만 판정하지 않는다).
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    m.send(&json!({"t": "server.status"})).await;
    assert_eq!(m.recv().await["t"], "server.status");
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut m).await;
    m.send(&json!({"t": "server.status"})).await;
    let e = m.recv().await;
    assert_eq!(
        (e["t"].as_str(), e["code"].as_str()),
        (Some("error"), Some("protocol"))
    );
    // 거절 응답에는 서버 값이 하나도 실리지 않는다(어느 쪽이 거절됐는지 말고는).
    assert!(e.as_object().unwrap().len() <= 3, "{e}");

    // 내보낸 사람은 연결이 닫혀 조회할 수 없다.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    let _ = expect_closed(&mut m, Duration::from_secs(3)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn server_status_levels_come_from_the_db_through_the_frame() {
    let (h, mail, code) = start_remote_full().await;
    let boss = remote_boss(&h, &mail, &code, "boss@x.io", "boss", 1).await;
    let (mut b, _) = connect(&h, &boss).await;
    b.send(&json!({"t": "server.status"})).await;
    let calm = b.recv().await;
    assert_eq!(calm["level"], "ok", "{calm}");

    // 백업 실패 + 바깥 사본 실패 + 메일 실패 → 문제, 이유는 표 순서. 캐시(10초) 안에서는 아직 안 바뀐다.
    h.app.db.backup_started(START_MS).unwrap();
    h.app.db.backup_failed().unwrap();
    h.app
        .db
        .backup_offsite(lodelai_relay::db::BackupOffsite::Failed)
        .unwrap();
    h.app.db.mail_failed(START_MS).unwrap();
    h.fx.clock.advance(5_000);
    b.send(&json!({"t": "server.status"})).await;
    let cached = b.recv().await;
    assert_eq!(cached["level"], "ok", "캐시 안에서는 이전 값: {cached}");
    h.fx.clock.advance(5_000);
    b.send(&json!({"t": "server.status"})).await;
    let s = b.recv().await;
    assert_eq!(s["level"], "bad", "{s}");
    assert_eq!(s["levels"]["backup"], "bad");
    assert_eq!(s["levels"]["mail"], "warn");
    assert_eq!(
        s["reasons"],
        json!(["backup_failed", "offsite_failed", "mail_failed"])
    );
    // 백업이 다시 성공하고 메일 실패가 1시간 지나면 정상으로 돌아온다.
    h.app.db.backup_succeeded(START_MS + 10_000).unwrap();
    h.app
        .db
        .backup_offsite(lodelai_relay::db::BackupOffsite::Ok)
        .unwrap();
    h.fx.clock.advance(60 * 60 * 1000);
    b.send(&json!({"t": "server.status"})).await;
    let s = b.recv().await;
    assert_eq!(
        (s["level"].as_str(), s["reasons"].clone()),
        (Some("ok"), json!([])),
        "{s}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn server_status_counts_members_per_org_but_not_other_orgs_people() {
    // 한 서버에 조직이 둘일 때: 인원·기기 수는 자기 조직만, 메일 수는 서버 전체(공유 상한 — 10-25 결정).
    let (h, mail, code) = start_remote_full().await;
    let boss = remote_boss(&h, &mail, &code, "boss@x.io", "boss", 1).await;
    let code2 = "ABCD-EFGH-JKLM-NPQR";
    h.app
        .db
        .set_setup_code(
            "qa",
            &lodelai_relay::http::setup_code_hash(code2),
            START_MS + 3_600_000,
        )
        .unwrap();
    let zed = remote_boss(&h, &mail, code2, "zed@y.io", "zed", 2).await;
    let (mut b, _) = connect(&h, &boss).await;
    let (mut z, _) = connect(&h, &zed).await;
    b.send(&json!({"t": "server.status"})).await;
    let sb = b.recv().await;
    z.send(&json!({"t": "server.status"})).await;
    let sz = z.recv().await;
    assert_eq!(
        (sb["members"].clone(), sz["members"].clone()),
        (json!(1), json!(1))
    );
    for (raw, other) in [(sb.to_string(), "zed"), (sz.to_string(), "boss")] {
        assert!(!raw.contains(other), "다른 조직 사람이 상태에 보임: {raw}");
    }
    assert_eq!(sb["devices"], json!({"connected": 1, "total": 1}));
    assert_eq!(sz["devices"], json!({"connected": 1, "total": 1}));
    // 한 조직에 연결이 늘어도 다른 조직 값은 그대로(조직별 캐시).
    let (_b2, _) = connect(&h, &boss).await;
    h.fx.clock.advance(10_000);
    z.send(&json!({"t": "server.status"})).await;
    assert_eq!(z.recv().await["devices"]["connected"], 1);
    b.send(&json!({"t": "server.status"})).await;
    let sb = b.recv().await;
    assert_eq!(sb["devices"]["connected"], 2);
    assert_eq!(sb["mail"]["sent_today"], sz["mail"]["sent_today"]);
    assert_eq!(sb["mail"]["sent_today"], 2, "메일은 서버 전체");
}

// ---- QA(#355 묶음 5 보안): 메일·원격 등록 ----

/// 보낸 (이메일, 로케일, 코드)를 모두 적고, `fail` 이면 실패한다.
#[derive(Default)]
struct RecordMailer {
    sent: std::sync::Mutex<Vec<(String, String, String)>>,
    fail: std::sync::atomic::AtomicBool,
}

impl lodelai_relay::mail::Mailer for RecordMailer {
    fn send_code(&self, email: &str, code: &str, locale: &str) -> Result<(), String> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Resend HTTP 500".into());
        }
        self.sent
            .lock()
            .unwrap()
            .push((email.into(), locale.into(), code.into()));
        Ok(())
    }

    fn send_text(&self, _email: &str, _subject: &str, _text: &str) -> Result<(), String> {
        Ok(())
    }
}

async fn start_recording(fail: bool) -> (Harness, std::sync::Arc<RecordMailer>) {
    let mail = std::sync::Arc::new(RecordMailer::default());
    mail.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    let h = start_full(
        |c| {
            c.remote = true;
            c.public_host = Some(PUBLIC.into());
            c.privacy_version = Some(PRIVACY.into());
        },
        Db::memory().unwrap(),
        Some(mail.clone()),
    )
    .await;
    (h, mail)
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_mail_goes_only_to_the_one_typed_address_and_locale_is_closed() {
    let (h, mail) = start_recording(false).await;
    // 한 요청이 다른 사람에게도 메일을 보내게 만드는 모양(여러 수신자·헤더 주입·이름 붙은 주소)은 보내기 전에 거절한다.
    let hostile = [
        "a@x.io,evil@y.io",
        "evil@y.io,a@x.io",
        "a@x.io;evil@y.io",
        "a@x.io\r\nBcc: evil@y.io",
        "a@x.io\nTo: evil@y.io",
        "a@x.io evil@y.io",
        "Bob <evil@y.io>",
        "a(evil@y.io)@x.io",
        "a@@x.io",
        "a@x.io\0",
    ];
    let mut passed = Vec::new();
    for e in hostile {
        h.fx.clock.advance(60_000);
        let (code, _) = post_json(
            &h,
            "/v1/signup",
            &json!({"email": e, "privacy": {"version": PRIVACY}}),
        )
        .await;
        if code != 400 {
            passed.push(e);
        }
    }
    assert!(passed.is_empty(), "거절돼야 할 주소가 통과: {passed:?}");
    assert!(
        mail.sent.lock().unwrap().is_empty(),
        "거절한 주소로 메일이 나감"
    );
    // 로케일은 ko 아니면 en — 아무 문자열도 메일에 닿지 않는다.
    for (loc, want) in [
        (json!("ko"), "ko"),
        (json!("en"), "en"),
        (json!("fr"), "en"),
        (json!("ko\r\nBcc: x"), "en"),
        (json!(null), "en"),
    ] {
        h.fx.clock.advance(60_000);
        let n = format!("l{}@x.io", mail.sent.lock().unwrap().len());
        let (code, _) = post_json(
            &h,
            "/v1/signup",
            &json!({"email": n, "locale": loc, "privacy": {"version": PRIVACY}}),
        )
        .await;
        assert_eq!(code, 202);
        let last = mail.sent.lock().unwrap().last().cloned().unwrap();
        assert_eq!((last.0.as_str(), last.1.as_str()), (n.as_str(), want));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mail_failure_is_a_bare_503_recorded_and_hides_account_existence() {
    let (h, mail) = start_recording(true).await;
    let (a, ba) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "boss@x.io", "privacy": {"version": PRIVACY}}),
    )
    .await;
    let (b, bb) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "new@x.io", "privacy": {"version": PRIVACY}}),
    )
    .await;
    assert_eq!((a, b), (503, 503));
    assert_eq!(ba, bb);
    // 응답에 실패 진단(Resend 상태)·이메일이 실리지 않는다.
    assert!(
        ba.is_empty() || !ba.contains("Resend") && !ba.contains("x.io"),
        "{ba}"
    );
    assert_eq!(h.app.db.mail_last_failed().unwrap(), Some(START_MS));
    assert!(mail.sent.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_device_register_is_refused_for_plain_members_too() {
    let (h, mail, code) = start_remote_full().await;
    let kb = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        create_org(&h, &mail, "boss@x.io", "boss", &kb, Some(&code)).await,
        201
    );
    let boss = User {
        name: "boss".into(),
        device_id: kb.device_id().as_str().to_owned(),
        keys: kb,
    };
    let (mut b, _) = connect(&h, &boss).await;
    b.send(&json!({"t": "invite.create"})).await;
    let invite = b.recv().await["token"].as_str().unwrap().to_owned();
    let token = remote_token(&h, &mail, "minji@x.io").await;
    let km = DeviceKeys::generate(&[2; 64]);
    let body = json!({"signup_token": token, "user": "minji", "display_name": "minji",
        "device_pubkeys": device_pubkeys(&km), "org": {"invite": invite}});
    assert_eq!(post_json(&h, "/v1/devices", &body).await.0, 201);
    let minji = User {
        name: "minji".into(),
        device_id: km.device_id().as_str().to_owned(),
        keys: km,
    };
    let (mut m, _) = connect(&h, &minji).await;
    // 연결 코드 모양이든 아니든, 멤버든 관리자든 같은 거절. 거절 뒤 기기 수는 그대로.
    for f in [
        json!({"t": "device.register", "code": "lodelai-dev1.AAAA"}),
        json!({"t": "device.register"}),
        json!({"t": "device.register", "code": ""}),
    ] {
        for c in [&mut m, &mut b] {
            c.send(&f).await;
            let e = loop {
                let e = c.recv().await;
                if e["t"] != "directory.update" {
                    break e;
                }
            };
            assert_eq!(
                (e["t"].as_str(), e["code"].as_str()),
                (Some("error"), Some("protocol")),
                "{f}"
            );
        }
    }
    b.send(&json!({"t": "server.status"})).await;
    let st = loop {
        let f = b.recv().await;
        if f["t"] == "server.status" {
            break f;
        }
    };
    assert_eq!(st["devices"]["total"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_rejects_angle_and_quote_addresses() {
    let (h, mail) = start_recording(false).await;
    let mut passed = Vec::new();
    for e in [
        "bob<evil@y.io>",
        "<evil@y.io>",
        "\"bob\"@y.io",
        "a@x.io>",
        "a<b@x.io",
    ] {
        h.fx.clock.advance(60_000);
        let (code, _) = post_json(
            &h,
            "/v1/signup",
            &json!({"email": e, "privacy": {"version": PRIVACY}}),
        )
        .await;
        if code != 400 {
            passed.push(e);
        }
    }
    assert!(passed.is_empty(), "통과: {passed:?}");
    assert!(mail.sent.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn signup_verify_shares_the_ip_limit_on_remote() {
    let (h, _mail, _) = start_remote_full().await;
    // 남의 이메일로 틀린 확인을 되풀이하면 IP 상한(1시간 20번, 가입 메일과 같은 통)에 걸린다 — 코드를 계속 지우지 못한다.
    let mut codes = Vec::new();
    for _ in 0..21 {
        codes.push(
            post_json(
                &h,
                "/v1/signup/verify",
                &json!({"email": "victim@x.io", "code": "000000"}),
            )
            .await
            .0,
        );
    }
    assert_eq!(codes[..20], [400; 20]);
    assert_eq!(codes[20], 429);
    // 같은 IP 의 가입 메일도 같은 통이라 막힌다.
    let (code, _) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "victim@x.io", "privacy": {"version": PRIVACY}}),
    )
    .await;
    assert_eq!(code, 429);
}

// ---- 묶음 5 정보 파기 A(10-25 결정, m1-spec §17.3): 내보내기·나가기 때 지우고 email_mac 만 ----

#[tokio::test(flavor = "multi_thread")]
async fn removed_and_left_people_keep_only_id_email_mac_and_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(|_| {}, Db::open(&path).unwrap(), Some(mail.clone())).await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    // 지워져야 할 표시 이름·팀을 알아보기 쉬운 값으로 넣는다.
    b.send(&json!({"t": "team.create", "name": "카나리아팀"}))
        .await;
    let team = next_dir(&mut b).await["teams"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (u, name) in [(&p[1], "카나리아민지"), (&p[2], "카나리아준")] {
        let (mut c, _) = connect(&h, u).await;
        c.send(&json!({"t": "profile.update", "display_name": name, "teams": [team]}))
            .await;
        next_dir(&mut c).await;
    }
    next_dir(&mut b).await;
    next_dir(&mut b).await;
    let raw = || {
        let mut all = Vec::new();
        for n in ["relay.sqlite3", "relay.sqlite3-wal"] {
            if let Ok(b) = std::fs::read(dir.path().join(n)) {
                all.extend(b);
            }
        }
        all
    };
    let has = |needle: &str| raw().windows(needle.len()).any(|w| w == needle.as_bytes());
    assert!(has("카나리아민지") && has("카나리아준"), "대조군");

    // minji 는 내보내고, jun 은 스스로 나간다.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    next_dir(&mut b).await;
    let (mut j, _) = connect(&h, &p[2]).await;
    j.send(&json!({"t": "member.leave"})).await;
    let _ = expect_closed(&mut j, Duration::from_secs(3)).await;
    next_dir(&mut b).await;

    let conn = rusqlite::Connection::open(&path).unwrap();
    for (user, by) in [("minji", "admin"), ("jun", "left")] {
        let (wiped, mac_len): (bool, Option<i64>) = conn
            .query_row(
                "SELECT email IS NULL AND display IS NULL AND privacy_version IS NULL AND privacy_ms IS NULL,
                 length(email_mac) FROM users WHERE user = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(wiped, "{user}: email·display·privacy 가 남았다");
        assert_eq!(mac_len, Some(32), "{user}: email_mac");
        let teams: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM user_teams WHERE user = ?1",
                [user],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(teams, 0, "{user}");
        let (x, sig, ed, revoked_by): (String, Option<String>, String, String) = conn
            .query_row(
                "SELECT x25519, x25519_sig, ed25519, revoked_by FROM devices WHERE user = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!((x.as_str(), sig), ("", None), "{user}: 암호화 키는 지움");
        assert!(!ed.is_empty(), "{user}: 서명 공개키는 남긴다(재접속 통지)");
        assert_eq!(revoked_by, by);
    }
    // 표시 이름은 DB·WAL 바이트 어디에도 남지 않는다(secure_delete·WAL 잘라냄).
    assert!(
        !has("카나리아민지") && !has("카나리아준"),
        "표시 이름이 남았다"
    );
    // 꺼져 있던 기기는 서명 확인 뒤 '빠졌다'를 받는다.
    let e = handshake_answer(&h, &p[1]).await;
    assert_eq!(
        (e["code"].as_str(), e["by"].as_str()),
        (Some("device_revoked"), Some("admin"))
    );

    // 다른 이메일은 그 아이디를 가질 수 없다(아이디가 남아 있다 — 이미 쓰는 아이디와 같은 403).
    b.send(&json!({"t": "invite.create"})).await;
    let tok = b.recv().await["token"].as_str().unwrap().to_owned();
    let (code, _) = join(
        &h,
        &mail,
        "other@y.io",
        "minji",
        json!({"invite": tok}),
        json!([]),
        40,
    )
    .await;
    assert_eq!(code, 403);
    // 같은 이메일로 새 초대 → 같은 아이디가 되살아나고 이메일이 다시 평문으로, email_mac 은 지운다.
    let (code, back) = join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": tok}),
        json!([]),
        41,
    )
    .await;
    assert_eq!(code, 201);
    let (_m, ready) = connect(&h, &back).await;
    assert_eq!(ready["t"], "ready");
    let (email, mac): (Option<String>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT email, email_mac FROM users WHERE user = 'minji'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((email.as_deref(), mac), (Some("minji@x.io"), None));
}

#[test]
fn email_mac_depends_on_the_server_key() {
    use lodelai_relay::db::email_mac;
    let a = email_mac(b"key-one-0123456789abcdef0123456789", "minji@x.io");
    assert_eq!(
        a,
        email_mac(b"key-one-0123456789abcdef0123456789", "minji@x.io")
    );
    assert_ne!(
        a,
        email_mac(b"key-two-0123456789abcdef0123456789", "minji@x.io")
    );
    assert_ne!(
        a,
        email_mac(b"key-one-0123456789abcdef0123456789", "minjj@x.io")
    );
}

// ---- M1 결함 ①(§17.3): 초대한 쪽 자동 추가 — invited_by_me 는 받는 사람마다 ----

fn person<'a>(d: &'a Value, user: &str) -> &'a Value {
    d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| {
            p["address"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{user}@"))
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn invited_by_me_is_only_for_the_inviter_and_all_their_devices() {
    let (h, mail) = start_hosted().await;
    // boss 가 minji 를 초대(hosted_org), 그 뒤 minji 를 관리자로 세워 minji 가 jun 을 초대한다.
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let boss2 = second_device(&h, &mail, &p[0], 11).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut b2, _) = connect(&h, &boss2).await;
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    next_dir(&mut b2).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    m.send(&json!({"t": "invite.create"})).await;
    let tok = loop {
        let f = m.recv().await;
        if f["t"] == "invite.created" {
            break f["token"].as_str().unwrap().to_owned();
        }
    };
    let (code, jun) = join(
        &h,
        &mail,
        "jun@x.io",
        "jun",
        json!({"invite": tok}),
        json!([]),
        3,
    )
    .await;
    assert_eq!(code, 201);

    // 관리자의 두 기기 모두: minji 에게만 표시, jun 은 boss 가 초대한 사람이 아니다.
    for c in [&mut b, &mut b2] {
        let d = next_dir(c).await;
        assert_eq!(person(&d, "minji")["invited_by_me"], true, "{d}");
        assert!(person(&d, "jun").get("invited_by_me").is_none(), "{d}");
        assert!(person(&d, "boss").get("invited_by_me").is_none(), "{d}");
        // 조직을 만든 boss 를 초대한 사람은 없다.
        assert!(
            d["people"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p.get("invited_me").is_none()),
            "{d}"
        );
    }
    // minji 에게는 jun 만, 받는 사람이 아닌 사람의 초대 관계는 보이지 않는다.
    let d = next_dir(&mut m).await;
    assert_eq!(person(&d, "jun")["invited_by_me"], true, "{d}");
    assert!(person(&d, "minji").get("invited_by_me").is_none(), "{d}");
    // §17.3 짝: 받는 사람을 초대한 사람에게만 invited_me — minji 에겐 boss, jun 에겐 minji.
    assert_eq!(person(&d, "boss")["invited_me"], true, "{d}");
    assert!(person(&d, "jun").get("invited_me").is_none(), "{d}");
    let (mut j, _) = connect(&h, &jun).await;
    j.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut j).await;
    assert!(
        d["people"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p.get("invited_by_me").is_none()),
        "{d}"
    );
    assert_eq!(person(&d, "minji")["invited_me"], true, "{d}");
    assert!(person(&d, "boss").get("invited_me").is_none(), "{d}");

    // 내보내면 초대 관계도 지운다(정보 파기 A) — 같은 이메일로 다른 사람의 초대로 돌아오면 그 사람 것.
    m.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    next_dir(&mut b).await;
    b.send(&json!({"t": "member.remove", "user": "jun"})).await;
    next_dir(&mut b).await;
    b.send(&json!({"t": "invite.create"})).await;
    let tok = loop {
        let f = b.recv().await;
        if f["t"] == "invite.created" {
            break f["token"].as_str().unwrap().to_owned();
        }
    };
    let (code, jun2) = join(
        &h,
        &mail,
        "jun@x.io",
        "jun",
        json!({"invite": tok}),
        json!([]),
        13,
    )
    .await;
    assert_eq!(code, 201);
    let d = next_dir(&mut b).await;
    assert_eq!(person(&d, "jun")["invited_by_me"], true, "{d}");
    // 돌아온 jun 의 새 기기도 처음 디렉터리로 새 초대자 boss 를 안다(옛 초대자 minji 는 아니다).
    let (mut j2, _) = connect(&h, &jun2).await;
    j2.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut j2).await;
    assert_eq!(person(&d, "boss")["invited_me"], true, "{d}");
    assert!(person(&d, "minji").get("invited_me").is_none(), "{d}");
    m.send(&json!({"t": "directory.list"})).await;
    let d = loop {
        let f = next_dir(&mut m).await;
        if f["t"] == "directory" {
            break f;
        }
    };
    assert!(person(&d, "jun").get("invited_by_me").is_none(), "{d}");
}

/// #382: 초대한 사람이 내보내졌다가 같은 아이디로 돌아와도, 예전에 초대한 사람과의 관계(invited_by_me·invited_me)가
/// 되살아나지 않는다 — 내보낼 때 그 사람을 가리키는 invited_by 도 지운다.
#[tokio::test(flavor = "multi_thread")]
async fn removed_inviter_back_with_same_id_has_no_old_invitees() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": true}))
        .await;
    next_dir(&mut b).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    m.send(&json!({"t": "invite.create"})).await;
    let tok = loop {
        let f = m.recv().await;
        if f["t"] == "invite.created" {
            break f["token"].as_str().unwrap().to_owned();
        }
    };
    let (code, jun) = join(
        &h,
        &mail,
        "jun@x.io",
        "jun",
        json!({"invite": tok}),
        json!([]),
        3,
    )
    .await;
    assert_eq!(code, 201);
    next_dir(&mut b).await;
    // minji 를 관리자에서 내리고 내보낸 뒤, boss 의 초대로 같은 아이디·이메일로 돌아온다.
    b.send(&json!({"t": "org.admin", "user": "minji", "admin": false}))
        .await;
    next_dir(&mut b).await;
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    next_dir(&mut b).await;
    b.send(&json!({"t": "invite.create"})).await;
    let tok = loop {
        let f = b.recv().await;
        if f["t"] == "invite.created" {
            break f["token"].as_str().unwrap().to_owned();
        }
    };
    let (code, minji2) = join(
        &h,
        &mail,
        "minji@x.io",
        "minji",
        json!({"invite": tok}),
        json!([]),
        13,
    )
    .await;
    assert_eq!(code, 201);
    // 돌아온 minji: jun 은 내가 초대한 사람이 아니다. 나를 초대한 사람은 새 초대자 boss.
    let (mut m2, _) = connect(&h, &minji2).await;
    m2.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut m2).await;
    assert!(person(&d, "jun").get("invited_by_me").is_none(), "{d}");
    assert_eq!(person(&d, "boss")["invited_me"], true, "{d}");
    // jun: minji 가 나를 초대한 사람으로 되살아나지 않는다.
    let (mut j, _) = connect(&h, &jun).await;
    j.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut j).await;
    assert!(person(&d, "minji").get("invited_me").is_none(), "{d}");
}

// ---- 기기별 보관(protocol §7.2-6, 10-25 결정 (B)): 꺼진 둘째 기기도 나중에 받는다 ----

/// 서버가 ack·폐기를 처리할 때까지 기다려 남은 본문 수가 `n` 이 되는지 본다.
async fn wait_pending_count(h: &Harness, n: i64) {
    for _ in 0..50 {
        if h.app.db.pending_count().unwrap() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(h.app.db.pending_count().unwrap(), n);
}

/// 기기 등록·폐기로 오는 `directory.update`·앞 메시지의 `status` 를 건너뛰고 send 응답을 받는다.
async fn send_skip_dir(c: &mut Client, m: &Value) -> Value {
    c.send(&json!({"t": "send", "message": m})).await;
    loop {
        let f = c.recv().await;
        if f["t"] != "directory.update" && f["t"] != "status" {
            return f;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_second_device_gets_message_after_first_device_acks() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let (mut b, _) = connect(&h, &bob).await;

    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "꺼진 둘째 기기도",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    assert_eq!(a.recv().await["state"], "received");
    // 첫 기기가 받아도 둘째 기기 몫의 본문은 남는다.
    assert_eq!(h.app.db.pending_count().unwrap(), 1);
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());

    // 꺼져 있던 둘째 기기가 붙으면 받는다. 그 ack 로 대상이 모두 받았으니 본문을 지운다.
    let (mut b2, ready) = connect(&h, &bob2).await;
    assert_eq!(ready["pending"], 1);
    let d = b2.recv().await;
    assert_eq!(
        (d["t"].as_str(), d["message"]["msg_id"].as_str()),
        (Some("deliver"), Some(mid(&m).as_str()))
    );
    b2.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    wait_pending_count(&h, 0).await;
    // 발신자 received 는 첫 ack 에서 한 번만.
    a.expect_silence().await;

    // (묶음 22: 저장 뒤 등록한 기기가 대상인지는 그룹 잎의 일 — mls.rs only_leaves_get_mls_frames·group_messages_follow_leaves.)
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_leaves_targets_and_expiry_drops_all() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let (mut b, _) = connect(&h, &bob).await;

    // 둘째 기기가 받고 ack 하지 않은 채 폐기되면, 첫 기기 ack 만으로 본문을 지운다.
    let m1 = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "폐기 전",
    );
    assert_eq!(send_expect(&mut a, &m1).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let (mut b2, _) = connect(&h, &bob2).await;
    assert_eq!(b2.recv().await["t"], "deliver");
    b2.send(&json!({"t": "device.revoke"})).await;
    b2.drain_until_closed().await;
    assert_eq!(
        h.app.db.pending_count().unwrap(),
        1,
        "첫 기기가 아직 ack 안 함"
    );
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m1)}))
        .await;
    wait_pending_count(&h, 0).await;

    // (묶음 22: 나중에 등록한 기기 몫은 그룹 잎의 일 — mls.rs duties_add_and_remove_device.)
}

// ---- 기기별 보관(QA): 권한·중복 ack·대상 행의 수명 ----

/// 파일 DB 의 `envelope_devices` 행 수(받는 사람의 기기 id 가 만료·폐기·정리 뒤에도 남지 않는지).
/// 기기별 대상 행 수 — pair 그룹을 세운 Handshake(kind mls) 몫은 빼고(규칙 시험의 글만).
fn device_rows(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM envelope_devices d JOIN envelopes e USING (msg_id) WHERE e.kind != 'mls'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn device_keep_acks_are_per_user_and_per_device() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let carol = register(&h, "carol", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "남의 ack 는 아무 일도 하지 않는다",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");

    // 받는 사람이 아닌 사용자의 기기가 ack 해도 전이·발신자 received·본문 삭제·대상 변경이 없다.
    c.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        h.app.db.header(&mid(&m)).unwrap().unwrap().env_state,
        "stored"
    );
    assert_eq!(h.app.db.pending_count().unwrap(), 1);
    a.expect_silence().await;
    assert_eq!(
        h.app.db.pending_for("bob", &bob.device_id).unwrap().len(),
        1,
        "bob 의 첫 기기 몫이 그대로"
    );

    // 같은 기기의 ack 를 되풀이해도 다른 기기 몫을 대신 채우지 못한다 — 본문은 둘째 기기 몫으로 남는다.
    for _ in 0..3 {
        b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
            .await;
    }
    assert_eq!(
        a.recv().await["state"],
        "received",
        "발신자 received 는 한 번"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    a.expect_silence().await;
    assert_eq!(h.app.db.pending_count().unwrap(), 1, "둘째 기기 몫이 남음");
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());
    assert_eq!(
        h.app.db.pending_for("bob", &bob2.device_id).unwrap().len(),
        1
    );

    // 둘째 기기가 받아 ack 해야 지워진다.
    let (mut b2, ready) = connect(&h, &bob2).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b2.recv().await["t"], "deliver");
    b2.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    wait_pending_count(&h, 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn device_keep_target_rows_follow_wipe_and_do_not_outlive_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    let h = start_full(|_| {}, Db::open(&path).unwrap(), None).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let _bob2 = register_extra_device(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &_bob2]).await;
    let send = |text: &'static str| {
        msg(
            &h,
            &alice,
            &alice.address(),
            "chat",
            &bob.address(),
            json!({}),
            text,
        )
    };

    // 만료: 아무 기기도 받지 않으면 본문과 함께 대상 행(받는 사람의 기기 id)도 사라진다.
    assert_eq!(send_expect(&mut a, &send("만료")).await["t"], "ack");
    assert_eq!(device_rows(&path), 2);
    h.fx.clock.advance(8 * 24 * 3600 * 1000);
    assert!(h.app.expire_tick() >= 1);
    assert_eq!(h.app.db.pending_count().unwrap(), 0);
    assert_eq!(device_rows(&path), 0, "만료 뒤 대상 행이 남음");

    // 정리(wipe): 대상 행도 함께 지운다.
    h.fx.clock.advance(60_000);
    let (mut a2, _) = connect(&h, &alice).await;
    assert_eq!(send_expect(&mut a2, &send("정리")).await["t"], "ack");
    assert_eq!(device_rows(&path), 2);
    let auth = format!("Bearer {TOKEN}");
    let (code, _) = http(h.addr, "POST", "/v1/wipe", &[("Authorization", &auth)], "").await;
    assert_eq!(code, 200);
    assert_eq!(device_rows(&path), 0, "wipe 뒤 대상 행이 남음");
}

#[tokio::test(flavor = "multi_thread")]
async fn removed_member_leaves_no_undelivered_body_or_device_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite3");
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(|_| {}, Db::open(&path).unwrap(), Some(mail.clone())).await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let minji2 = second_device(&h, &mail, &p[1], 40).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut j, _) = connect(&h, &p[2]).await;
    while let Ok(f) = tokio::time::timeout(Duration::from_millis(200), j.recv()).await {
        let _ = f;
    }
    pair_with(&h, &mut j, &p[2], &[&p[1], &minji2]).await;
    // jun → minji(기기 둘, 둘 다 꺼짐): 본문과 대상 행 둘이 쌓인다.
    let m = msg(
        &h,
        &p[2],
        &p[2].address(),
        "chat",
        &p[1].address(),
        json!({}),
        "꺼진 사이에",
    );
    assert_eq!(send_skip_dir(&mut j, &m).await["t"], "ack");
    assert_eq!(h.app.db.pending_count().unwrap(), 1);
    assert_eq!(device_rows(&path), 2);
    assert_eq!(
        h.app
            .db
            .pending_for("minji", &minji2.device_id)
            .unwrap()
            .len(),
        1
    );

    // 관리자가 내보내면 쌓인 본문도 지운다(정보 파기) — 새로 붙는 일도 없다. 헤더·발신자 뷰는 만료까지.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    for _ in 0..50 {
        if h.app.db.pending_count().unwrap() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        h.app.db.pending_count().unwrap(),
        0,
        "내보낸 사람 앞 본문이 남음"
    );
    assert!(h
        .app
        .db
        .pending_for("minji", &minji2.device_id)
        .unwrap()
        .is_empty());
    assert!(h
        .app
        .db
        .pending_for("minji", &p[1].device_id)
        .unwrap()
        .is_empty());
    assert!(h.app.db.header(&mid(&m)).unwrap().is_some());
    // 대상 행은 폐기된 기기 몫이라 이미 없다.
    assert_eq!(
        device_rows(&path),
        0,
        "내보낸 사람의 기기 id 가 대상 행에 남음"
    );
}

/// 내 기기 서명(#393, e2e-envelope §7a)의 `lodelai-devcert-v1` 서명.
fn devcert(server: &str, signer: &User, target: &User) -> String {
    lodelai_crypto::devcert::sign(
        &signer.keys.signing,
        &lodelai_crypto::devcert::Cert {
            server,
            user: &signer.name,
            device_id: &target.device_id,
            x25519: &target.keys.exchange.public_key(),
            signer: &signer.device_id,
        },
    )
}

/// `directory.list` 로 그 사람의 기기 항목들.
async fn listed_devices(c: &mut Client, user: &str) -> Vec<Value> {
    c.send(&json!({"t": "directory.list"})).await;
    loop {
        let d = c.recv().await;
        if d["t"] != "directory" {
            continue;
        }
        return d["people"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| {
                p["address"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{user}@"))
            })
            .unwrap()["devices"]
            .as_array()
            .unwrap()
            .clone();
    }
}

/// #393: 같은 사용자의 기존 기기가 새 기기에 서명하면 저장하고 디렉터리 `certs` 로 보인다. 서명이 틀리거나(다른 서버·
/// 쓰레기) 대상이 자기·남의 기기면 error{protocol}. 서명자나 대상이 폐기되면 서명이 빠진다.
#[tokio::test(flavor = "multi_thread")]
async fn device_certify_is_verified_listed_and_dropped_on_revoke() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;

    // 어긋난 것은 모두 같은 error{protocol}(ref 없음), 저장하지 않는다.
    for (target, sig, why) in [
        (
            &alice2,
            devcert("other-server", &alice, &alice2),
            "다른 서버",
        ),
        (&alice2, "A".repeat(86), "쓰레기 서명"),
        (&alice, devcert(SERVER, &alice, &alice), "자기 기기"),
        (&bob, devcert(SERVER, &alice, &bob), "남의 기기"),
    ] {
        a.send(&json!({"t": "device.certify", "device_id": target.device_id, "sig": sig}))
            .await;
        let r = a.recv().await;
        assert_eq!(
            (r["t"].as_str(), r["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{why}: {r}"
        );
        assert!(r.get("ref").is_none(), "{why}");
    }
    assert!(h.app.db.device_certs_of("alice").unwrap().is_empty());

    // 맞는 서명 → 응답 없이 같은 조직에 directory.update, 디렉터리 대상 기기에 certs.
    let sig = devcert(SERVER, &alice, &alice2);
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": sig}))
        .await;
    assert_eq!(b.recv().await["t"], "directory.update");
    assert_eq!(
        a.recv().await["t"],
        "directory.update",
        "서명한 쪽도 같은 조직"
    );
    let devices = listed_devices(&mut b, "alice").await;
    let entry = |id: &str| {
        devices
            .iter()
            .find(|d| d["device_id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        entry(&alice2.device_id)["certs"],
        json!([{"signer": alice.device_id, "sig": sig}])
    );
    assert!(
        entry(&alice.device_id).get("certs").is_none(),
        "없으면 생략"
    );
    // 같은 쌍·같은 sig 는 아무것도 쓰지 않고 방송도 없다(certify ↔ directory.update 고리 방지).
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": sig}))
        .await;
    a.expect_silence().await;
    b.expect_silence().await;
    assert_eq!(h.app.db.device_certs_of("alice").unwrap().len(), 1);

    // 반대 방향도 서명해 두고, 나중 기기(alice2)를 폐기하면 그 기기가 서명자·대상인 서명이 모두 빠진다.
    let (mut a2, _) = connect(&h, &alice2).await;
    a2.send(&json!({"t": "device.certify", "device_id": alice.device_id, "sig": devcert(SERVER, &alice2, &alice)}))
        .await;
    assert_eq!(b.recv().await["t"], "directory.update");
    assert_eq!(h.app.db.device_certs_of("alice").unwrap().len(), 2);
    a.send(&json!({"t": "device.revoke", "device_id": alice2.device_id}))
        .await;
    assert_eq!(b.recv().await["t"], "directory.update");
    assert!(h.app.db.device_certs_of("alice").unwrap().is_empty());
    let devices = listed_devices(&mut b, "alice").await;
    assert_eq!(devices.len(), 1);
    assert!(devices[0].get("certs").is_none());
}

// ---- A15(묶음 7): 동료 세션 busy — session.publish 의 busy 를 저장해 디렉터리에 참일 때만 ----

#[tokio::test(flavor = "multi_thread")]
async fn session_busy_is_stored_and_listed_only_when_true() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    // 같은 세션을 busy 참 → 필드 없음 → false 로 다시 공개한다. 디렉터리엔 참일 때만 busy: true.
    let session = |d: &Value| {
        d["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["address"] == "bob@local/be")
            .cloned()
            .unwrap()
    };

    for (busy, want) in [
        (Some(true), Some(json!(true))),
        (None, None),
        (Some(false), None),
    ] {
        let mut f = json!({"t": "session.publish", "slug": "be", "grade": "task", "liveness": "live:channel"});
        if let Some(v) = busy {
            f["busy"] = json!(v);
        }
        b.send(&f).await;
        let d = loop {
            let f = a.recv().await;
            if f["t"] == "directory.update" {
                break f;
            }
        };
        assert_eq!(session(&d).get("busy").cloned(), want, "{busy:?}: {d}");
        a.send(&json!({"t": "directory.list"})).await;
        let d = loop {
            let f = a.recv().await;
            if f["t"] == "directory" {
                break f;
            }
        };
        assert_eq!(session(&d).get("busy").cloned(), want, "{busy:?}: {d}");
    }
}

// ---- A15 QA: busy 는 공개한 세션에만, 내리면 사라지고, 값 형식이 틀리면 거부 ----

#[tokio::test(flavor = "multi_thread")]
async fn session_busy_disappears_on_unpublish_and_bad_values_are_rejected() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let find = |d: &Value| {
        d["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["address"] == "bob@local/be")
            .cloned()
    };
    let publish = json!({"t": "session.publish", "slug": "be", "grade": "task", "liveness": "live:channel", "busy": true});
    b.send(&publish).await;
    assert_eq!(find(&dir_list(&mut a).await).unwrap()["busy"], json!(true));
    // 형식이 틀린 busy 는 프레임 거부(error protocol)이고 저장된 값은 그대로.
    for bad in [json!("yes"), json!(1), json!({"x": 1})] {
        let mut f = publish.clone();
        f["busy"] = bad.clone();
        f["liveness"] = json!("live:pty");
        b.send(&f).await;
        let e = loop {
            let f = b.recv().await;
            if f["t"] != "directory.update" {
                break f;
            }
        };
        assert_eq!(e["t"], "error", "{bad}: {e}");
    }
    // 공개를 내리면 목록에서 사라지고, busy 없이 다시 공개하면 이전 busy 가 되살아나지 않는다.
    b.send(&json!({"t": "session.unpublish", "slug": "be"}))
        .await;
    assert!(find(&dir_list(&mut a).await).is_none());
    b.send(
        &json!({"t": "session.publish", "slug": "be", "grade": "task", "liveness": "live:channel"}),
    )
    .await;
    let s = find(&dir_list(&mut a).await).unwrap();
    assert!(s.get("busy").is_none(), "{s}");
}

async fn dir_list(a: &mut Client) -> Value {
    // 다른 연결이 보낸 프레임이 처리될 틈을 준다.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    a.send(&json!({"t": "directory.list"})).await;
    loop {
        let f = a.recv().await;
        if f["t"] == "directory" {
            return f;
        }
    }
}

/// #389 QA: `device_taken` 은 이유를 가르지 않는다 — 남의 살아 있는 기기·폐기된 기기·내보낸 사람의 기기가 모두 같은 응답
/// 본문이고(소유자·상태 미노출), 내보낸 사람의 옛 기기는 자기 이메일 코드로도 다시 가입되지 않으며 토큰은 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_device_taken_is_uniform_and_removed_members_cannot_rejoin() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji", "jun"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut j, _) = connect(&h, &p[2]).await;
    let taken = json!({"error": "device_taken"});

    // ① 남의 살아 있는 기기(jun 의 기기를 minji 이메일 토큰으로).
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "minji@x.io").await;
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &p[2].keys)).await;
    assert_eq!(code, 409);
    assert_eq!(
        serde_json::from_str::<Value>(&resp).unwrap(),
        taken,
        "{resp}"
    );
    // 토큰은 남아 minji 의 새 기기로 이어 쓸 수 있다(응답이 소유자를 가르지 않았으니 시도 자체는 공짜가 아니다 — 토큰 1개당 1성공).
    let k_new = DeviceKeys::generate(&[41; 64]);
    let (code, resp) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &k_new)).await;
    assert_eq!(code, 201, "{resp}");

    // ② 폐기된 기기(jun 이 자기 기기를 폐기).
    j.send(&json!({"t": "device.revoke"})).await;
    j.drain_until_closed().await;
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "jun@x.io").await;
    let (code, resp2) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &p[2].keys)).await;
    assert_eq!(code, 409);
    assert_eq!(serde_json::from_str::<Value>(&resp2).unwrap(), taken);

    // ③ 내보낸 사람의 옛 기기: 자기 이메일 코드로도 device_taken, 토큰은 남는다.
    b.send(&json!({"t": "member.remove", "user": "minji"}))
        .await;
    next_dir(&mut b).await;
    h.fx.clock.advance(60_000);
    let token = signup_token(&h, &mail, "minji@x.io").await;
    let (code, resp3) = post_json(&h, "/v1/devices", &hosted_body(&token, None, &p[1].keys)).await;
    assert_eq!(code, 409);
    assert_eq!(
        serde_json::from_str::<Value>(&resp3).unwrap(),
        taken,
        "{resp3}"
    );
    assert_eq!(resp2, resp3, "응답 바이트가 같다");
    // 폐기된(devices_of 는 살아 있는 기기만) 옛 기기가 되살아나지 않았다.
    assert!(h
        .app
        .db
        .devices_of("minji")
        .unwrap()
        .iter()
        .all(|d| d.device_id != p[1].device_id));
}

/// 받는 기기는 그룹 잎으로 좁힌다(묶음 22, 옛 봉투 `recipients` — protocol §7.2-6). 보낸 쪽이 아직 신뢰하지 않은 새 기기는
/// 대상에서 빠져 풀 수 없는 봉투를 받지 않고(18787 시험의 빈 글), 기존 기기 몫의 보관은 그대로다.
#[tokio::test(flavor = "multi_thread")]
async fn untrusted_new_device_is_not_a_target_and_old_device_keeps_retention() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    // pair 그룹의 잎은 bob 하나 — bob2 는 아직 잎이 아니다(묶음 22: 대상 = 잎).
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let (mut b2, _) = connect(&h, &bob2).await;

    // 기존 기기(bob)는 꺼져 있고 새 기기(bob2)만 붙어 있다.
    let sealed_to_bob = |text: &str, _seed: u8| {
        msg(
            &h,
            &alice,
            &alice.address(),
            "chat",
            &bob.address(),
            json!({}),
            text,
        )
    };
    let m = sealed_to_bob("새 기기는 못 푼다", 11);
    assert_eq!(send_skip_dir(&mut a, &m).await["t"], "ack");
    b2.expect_silence().await;
    assert!(h
        .app
        .db
        .pending_for("bob", &bob2.device_id)
        .unwrap()
        .is_empty());
    // 대상이 아닌 새 기기의 ack 는 아무 일도 하지 않는다 — 기존 기기 몫의 본문은 남는다.
    b2.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.app.db.pending_count().unwrap(), 1);
    assert_eq!(
        h.app.db.header(&mid(&m)).unwrap().unwrap().env_state,
        "stored"
    );

    // 기존 기기가 붙으면 받고, 그 ack 로 대상이 모두 받았으니 본문을 지운다.
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b.recv().await["message"]["msg_id"], mid(&m).as_str());
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&m)}))
        .await;
    wait_pending_count(&h, 0).await;
    assert_eq!(a.recv().await["state"], "received");

    // (묶음 22: 잎이 된 뒤 둘 다 받는 것은 mls.rs duties_add_and_remove_device·group_messages_follow_leaves.)
}

// ------------------------------------------------------------------ 묶음 14 메시지 동작

/// 거두기(system withdrawn, `reply_to` = X, `to` = X 의 to).
fn withdraw_of(h: &Harness, from: &User, x: &Value) -> Value {
    msg(
        h,
        from,
        &from.address(),
        "system",
        x["to"]["address"].as_str().unwrap(),
        json!({"reply_to": mid(x), "reason": "withdrawn"}),
        "",
    )
}

/// #403: 보낸 사람만 거둘 수 있고(남·받는 사람의 시도는 없는 메시지와 바이트 동일 unroutable), 거두면 X 의 아직 받지 않은
/// 기기 몫과 본문이 지워지며, withdraw 는 X 의 원래 수신 기기 전부(이미 받은 기기 포함)에 간다.
#[tokio::test(flavor = "multi_thread")]
async fn withdraw_is_sender_only_drops_unreceived_copies_and_reaches_original_devices() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let bob2 = register_extra_device(&h, "bob", 3).await;
    let carol = register(&h, "carol", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let x = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "잘못 보냄",
    );
    assert_eq!(send_expect(&mut a, &x).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(&json!({"t": "delivered_ack", "msg_id": mid(&x)}))
        .await;
    assert_eq!(a.recv().await["state"], "received");

    // 거둔 뒤 새로 들어온 bob 의 기기는 원래 수신 기기가 아니다 — withdraw 를 받지 않는다.
    let bob3 = register_extra_device(&h, "bob", 5).await;
    for cl in [&mut a, &mut b, &mut c] {
        let _ = next_dir(cl).await;
    }

    // 남(carol)·받는 사람(bob)·없는 메시지: 모두 같은 unroutable.
    let ghost = {
        let mut g = x.clone();
        g["msg_id"] = json!("01JB0000000000000000000000");
        g
    };
    let base = send_expect(&mut a, &withdraw_of(&h, &alice, &ghost)).await;
    assert_eq!(base["reason"], "unroutable", "{base}");
    let strip = |v: &Value| {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove("msg_id");
        v
    };
    let mut by_carol = withdraw_of(&h, &carol, &x);
    by_carol["from"]["address"] = json!(carol.address());
    resign(&mut by_carol, &carol);
    let mut by_bob = msg(
        &h,
        &bob,
        &bob.address(),
        "system",
        &alice.address(),
        json!({"reply_to": mid(&x), "reason": "withdrawn"}),
        "",
    );
    resign(&mut by_bob, &bob);
    // 다른 사람 주소로 보낸 거두기(X 의 to 가 아님)도 같다.
    let mut elsewhere = withdraw_of(&h, &alice, &x);
    elsewhere["to"]["address"] = json!(carol.address());
    resign(&mut elsewhere, &alice);
    for (cl, m) in [(&mut c, &by_carol), (&mut b, &by_bob), (&mut a, &elsewhere)] {
        let r = send_expect(cl, m).await;
        assert_eq!(strip(&r), strip(&base), "{r}");
    }
    assert_eq!(
        h.app.db.pending_for("bob", &bob2.device_id).unwrap().len(),
        1,
        "실패한 거두기는 X 를 건드리지 않는다"
    );

    let w = withdraw_of(&h, &alice, &x);
    assert_eq!(send_expect(&mut a, &w).await["t"], "ack");
    let got = b.recv().await;
    assert_eq!(got["t"], "deliver", "이미 받은 기기도 지우도록 받는다");
    assert_eq!(got["message"]["reason"], "withdrawn");
    c.expect_silence().await;

    // 받지 않았던 둘째 기기: X 없이 withdraw 만. 새 셋째 기기: 둘 다 없음.
    let pending: Vec<Value> = h
        .app
        .db
        .pending_for("bob", &bob2.device_id)
        .unwrap()
        .iter()
        .map(|(t, _)| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["msg_id"], mid(&w).as_str());
    assert!(h
        .app
        .db
        .pending_for("bob", &bob3.device_id)
        .unwrap()
        .is_empty());
    let (mut b2, ready) = connect(&h, &bob2).await;
    assert_eq!(ready["pending"], 1);
    assert_eq!(b2.recv().await["message"]["msg_id"], mid(&w).as_str());
    b2.expect_silence().await;
    // 헤더는 남는다(같은 msg_id 재생 거부·늦은 거두기 재전송의 멱등 ack).
    assert!(h.app.db.header(&mid(&x)).unwrap().is_some());
    assert_eq!(send_expect(&mut a, &w).await["t"], "ack");
    b.expect_silence().await;
}

/// #403: request 거두기 — 받는 쪽의 status withdrawn 은 수락 전이면 발신자 뷰를 withdrawn(종료)으로, 이미 수락했으면
/// 뷰를 바꾸지 않는다(경합에서 수락이 이김). withdrawn 뒤의 accepted 도 무시. 거둔 request 에는 회신할 수 없다.
#[tokio::test(flavor = "multi_thread")]
async fn request_withdraw_status_respects_accept_race() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    publish(&mut b, "backend", "task").await;
    for cl in [&mut a, &mut b] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    let view = |h: &Harness, id: &str| h.app.db.header(id).unwrap().unwrap().sender_view;
    let request = |h: &Harness| {
        msg(
            h,
            &alice,
            &alice.address(),
            "request",
            "bob@local/backend",
            json!({"grade": "question"}),
            "이거 봐 줄래?",
        )
    };
    let status = |h: &Harness, id: &str, state: &str| json!({"t": "status", "msg_id": id, "state": state, "at": now_str(h, 0)});

    // 수락 전 거두기: withdraw 전달 → 받는 쪽 status withdrawn → 발신자 뷰 withdrawn, 뒤늦은 accepted 무시.
    let r1 = request(&h);
    assert_eq!(send_expect(&mut a, &r1).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let w1 = withdraw_of(&h, &alice, &r1);
    assert_eq!(send_expect(&mut a, &w1).await["t"], "ack");
    assert_eq!(b.recv().await["message"]["reason"], "withdrawn");
    b.send(&status(&h, &mid(&r1), "withdrawn")).await;
    assert_eq!(a.recv().await["state"], "withdrawn");
    assert_eq!(view(&h, &mid(&r1)), "withdrawn");
    b.send(&status(&h, &mid(&r1), "accepted")).await;
    let _ = a.recv().await;
    assert_eq!(
        view(&h, &mid(&r1)),
        "withdrawn",
        "종료 상태에서 나오지 않는다"
    );
    let late = msg(
        &h,
        &bob,
        "bob@local/backend",
        "reply",
        &alice.address(),
        json!({"reply_to": mid(&r1), "thread_id": mid(&r1)}),
        "늦은 답",
    );
    assert_eq!(send_expect(&mut b, &late).await["reason"], "unroutable");

    // 수락이 먼저: withdrawn status 는 뷰를 바꾸지 않는다.
    let r2 = request(&h);
    assert_eq!(send_expect(&mut a, &r2).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(&status(&h, &mid(&r2), "accepted")).await;
    assert_eq!(a.recv().await["state"], "accepted");
    b.send(&status(&h, &mid(&r2), "withdrawn")).await;
    let _ = a.recv().await;
    assert_eq!(view(&h, &mid(&r2)), "accepted");

    // reply·system 은 거둘 수 없다(대상은 request·chat 만).
    let mut on_withdraw = withdraw_of(&h, &alice, &w1);
    on_withdraw["to"]["address"] = json!("bob@local/backend");
    resign(&mut on_withdraw, &alice);
    assert_eq!(
        send_expect(&mut a, &on_withdraw).await["reason"],
        "unroutable"
    );
}

/// #404·B2: 고친 chat(`edits: X`)은 X 를 보낸 사람이 같은 받는 사람에게만 — X 의 아직 받지 않은 기기 몫은 지워져
/// 그 기기에는 새 글만 간다. `reply_to`(인용)는 relay 가 검사하지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn edit_replaces_unreceived_copies_and_is_sender_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let (mut c, _) = connect(&h, &carol).await;
    let x = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "오타 있음",
    );
    assert_eq!(send_expect(&mut a, &x).await["t"], "ack");

    let edit = |h: &Harness, from: &User, to: &str, edits: &str| {
        msg(
            h,
            from,
            &from.address(),
            "chat",
            to,
            json!({"edits": edits}),
            "오타 고침",
        )
    };
    // 남의 chat 을 고치기·다른 사람에게 보내는 고치기·없는 X: unroutable.
    let theirs = edit(&h, &carol, &bob.address(), &mid(&x));
    assert_eq!(send_expect(&mut c, &theirs).await["reason"], "unroutable");
    for m in [
        edit(&h, &alice, &carol.address(), &mid(&x)),
        edit(&h, &alice, &bob.address(), "01JB0000000000000000000000"),
    ] {
        assert_eq!(send_expect(&mut a, &m).await["reason"], "unroutable", "{m}");
    }
    // edits 형식 오류는 형식 오류.
    let bad = edit(&h, &alice, &bob.address(), "x");
    let r = send_expect(&mut a, &bad).await;
    assert_eq!(
        (r["t"].as_str(), r["code"].as_str()),
        (Some("error"), Some("protocol"))
    );

    let e = edit(&h, &alice, &bob.address(), &mid(&x));
    assert_eq!(send_expect(&mut a, &e).await["t"], "ack");
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 1, "옛 글은 늦게 가지 않는다");
    let got = b.recv().await;
    assert_eq!(got["message"]["msg_id"], mid(&e).as_str());
    assert_eq!(got["message"]["edits"], mid(&x).as_str());
    b.expect_silence().await;

    // 인용 답하기: 어떤 ULID 든 relay 는 보지 않는다.
    let quote = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &alice.address(),
        json!({"reply_to": "01JB0000000000000000000000"}),
        "그래",
    );
    assert_eq!(send_expect(&mut b, &quote).await["t"], "ack");
    assert_eq!(
        a.recv().await["message"]["reply_to"],
        "01JB0000000000000000000000"
    );
}

/// B3: chat 의 acknowledged 는 받는 사람만, 발신자에게 그대로 중계(서버 뷰는 그대로). request 에는 없다.
#[tokio::test(flavor = "multi_thread")]
async fn chat_acknowledged_is_relayed_from_recipient_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    let m = msg(
        &h,
        &alice,
        &alice.address(),
        "chat",
        &bob.address(),
        json!({}),
        "배포했어",
    );
    assert_eq!(send_expect(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    let ack =
        json!({"t": "status", "msg_id": mid(&m), "state": "acknowledged", "at": now_str(&h, 0)});
    b.send(&ack).await;
    assert_eq!(a.recv().await["state"], "acknowledged");
    a.send(&ack).await;
    assert_eq!(a.recv().await["t"], "error");
    b.expect_silence().await;

    // request 에는 확인함이 없다(수락·거절이 그 뜻).
    publish(&mut b, "backend", "task").await;
    for cl in [&mut a, &mut b] {
        assert_eq!(cl.recv().await["t"], "directory.update");
    }
    let r = msg(
        &h,
        &alice,
        &alice.address(),
        "request",
        "bob@local/backend",
        json!({"grade": "question"}),
        "봐 줄래?",
    );
    assert_eq!(send_expect(&mut a, &r).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(
        &json!({"t": "status", "msg_id": mid(&r), "state": "acknowledged", "at": now_str(&h, 0)}),
    )
    .await;
    assert_eq!(b.recv().await["t"], "error");
    a.expect_silence().await;
}

fn online_of(d: &Value, address: &str) -> Option<bool> {
    d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == address)
        .unwrap()
        .get("online")
        .and_then(Value::as_bool)
}

/// B1: 연결은 바로(본인 말고) 알리고, 끊김은 유예 뒤에. 같은 사용자의 변화는 합치기 창에 한 번. 숨기면 서로 안 보인다(맞교환).
/// 마지막 접속 시각 같은 필드는 없다.
#[tokio::test(flavor = "multi_thread")]
async fn presence_grace_coalesce_and_mutual_hiding() {
    let grace = Duration::from_millis(500);
    let coalesce = Duration::from_millis(400);
    let h = start_with(|c| {
        c.presence_updates = true;
        c.presence_grace = grace;
        c.presence_coalesce = coalesce;
    })
    .await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    // 자기 접속은 본인에게 보내지 않는다(directory.list 로 안다).
    a.expect_silence().await;

    let (mut b, _) = connect(&h, &bob).await;
    let d = next_dir(&mut a).await;
    assert_eq!(online_of(&d, "bob@local"), Some(true));
    for p in d["people"].as_array().unwrap() {
        let keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
        assert!(
            keys.iter()
                .all(|k| ["address", "display", "devices", "online"].contains(k)),
            "{keys:?}"
        );
    }
    b.expect_silence().await;

    // 끊김: 유예 안에는 조용하고 디렉터리에도 접속 중, 유예 뒤 꺼짐을 알린다.
    let t0 = std::time::Instant::now();
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.expect_silence().await;
    a.send(&json!({"t": "directory.list"})).await;
    assert_eq!(online_of(&a.recv().await, "bob@local"), Some(true));
    let d = next_dir(&mut a).await;
    assert!(t0.elapsed() >= grace, "{:?}", t0.elapsed());
    assert_eq!(online_of(&d, "bob@local"), Some(false));

    // 바로 다시 연결: 합치기 창 끝까지 미뤘다가 한 번.
    let t1 = std::time::Instant::now();
    let (mut b, _) = connect(&h, &bob).await;
    let d = next_dir(&mut a).await;
    assert!(t1.elapsed() >= coalesce / 2, "{:?}", t1.elapsed());
    assert_eq!(online_of(&d, "bob@local"), Some(true));
    b.expect_silence().await;

    // bob 이 숨긴다: alice 에게 bob 의 online 이 없고, bob 에게는 누구의 online 도 없다. 같은 값은 조용하다.
    b.send(&json!({"t": "presence.set", "share": false})).await;
    let d = next_dir(&mut a).await;
    assert_eq!(online_of(&d, "bob@local"), None);
    assert_eq!(online_of(&d, "alice@local"), Some(true));
    let d = next_dir(&mut b).await;
    assert_eq!(online_of(&d, "alice@local"), None);
    assert_eq!(online_of(&d, "bob@local"), None);
    b.send(&json!({"t": "presence.set", "share": false})).await;
    a.expect_silence().await;
    b.expect_silence().await;
    // 다시 켠다.
    b.send(&json!({"t": "presence.set", "share": true})).await;
    assert_eq!(
        online_of(&next_dir(&mut b).await, "alice@local"),
        Some(true)
    );
    assert_eq!(online_of(&next_dir(&mut a).await, "bob@local"), Some(true));
}

// ---------------------------------------------------------------- 묶음 20 세션 공개 범위 (#463, bundle-20-publish-audience.md)

async fn publish_to(c: &mut Client, slug: &str, audience: Value) {
    c.send(
        &json!({"t": "session.publish", "slug": slug, "grade": "task",
        "liveness": "live:channel", "audience": audience}),
    )
    .await;
}

/// 그 사람이 받는 디렉터리에 세션 주소가 있나.
async fn sees(c: &mut Client, address: &str) -> bool {
    c.send(&json!({"t": "directory.list"})).await;
    let d = c.recv().await;
    assert_eq!(d["t"], "directory", "{d}");
    session_listed(&d, address)
}

fn session_listed(d: &Value, address: &str) -> bool {
    d["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["address"] == address)
}

/// 범위 밖 사람: 디렉터리에 없고 request 는 없는 세션과 바이트 같은 unroutable. 범위 안·주인은 통과. 범위 목록은 아무 디렉터리에도
/// 실리지 않는다. 범위를 바꾸면 directory.update 로 빠진 사람에게서 사라지고 든 사람에게 생긴다. 이미 오간 요청의 reply 는 범위 무관.
#[tokio::test(flavor = "multi_thread")]
async fn audience_filters_directory_and_requests() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    // 묶음 22: 1:1 은 pair 그룹(epoch 1) 위에서만 — 범위 검사 앞에 세운다.
    pair(&h, &mut a, &alice, &mut b, &bob).await;
    pair(&h, &mut c, &carol, &mut b, &bob).await;
    let sess = "bob@local/backend";
    publish_to(
        &mut b,
        "backend",
        json!({"kind": "people", "users": ["alice"]}),
    )
    .await;
    for cl in [&mut a, &mut b, &mut c] {
        let d = cl.recv().await;
        assert_eq!(d["t"], "directory.update");
        assert!(
            !d.to_string().contains("audience"),
            "범위는 싣지 않는다: {d}"
        );
    }
    assert!(sees(&mut a, sess).await);
    assert!(sees(&mut b, sess).await, "주인은 늘 본다");
    assert!(!sees(&mut c, sess).await);

    // carol: 범위 밖 = 없는 세션과 같은 바이트.
    let q = json!({"grade": "question"});
    let norm = |m: &Value, raw: String| raw.replace(&mid(m), "ID");
    let none = msg(
        &h,
        &carol,
        &carol.address(),
        "request",
        "bob@local/nope",
        q.clone(),
        "x",
    );
    c.send(&json!({"t": "send", "message": none})).await;
    let base = norm(&none, c.recv_text().await);
    let out = msg(
        &h,
        &carol,
        &carol.address(),
        "request",
        sess,
        q.clone(),
        "x",
    );
    c.send(&json!({"t": "send", "message": out})).await;
    assert_eq!(norm(&out, c.recv_text().await), base);
    b.expect_silence().await;

    // alice: 범위 안.
    let req = msg(
        &h,
        &alice,
        "alice@local/front",
        "request",
        sess,
        q.clone(),
        "질문",
    );
    assert_eq!(send_expect(&mut a, &req).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    // 주인 자신의 request 는 묶음 22 에서 기기가 하나뿐이면 pair 그룹이 없어 unroutable — 주인이 늘 보는 것은 위 sees 로.

    // 범위를 carol 로 바꿈 → alice 에게서 사라지고 carol 에게 생긴다.
    publish_to(
        &mut b,
        "backend",
        json!({"kind": "people", "users": ["carol"]}),
    )
    .await;
    assert!(!session_listed(&a.recv().await, sess));
    assert!(session_listed(&c.recv().await, sess));
    assert_eq!(b.recv().await["t"], "directory.update");
    let again = msg(
        &h,
        &alice,
        "alice@local/front",
        "request",
        sess,
        q.clone(),
        "또",
    );
    assert_eq!(send_expect(&mut a, &again).await["reason"], "unroutable");

    // 이미 받은 alice 의 요청: 수락·회신은 범위와 무관하게 끝까지.
    let rid = mid(&req);
    b.send(&json!({"t": "status", "msg_id": rid, "state": "accepted", "at": now_str(&h, 0)}))
        .await;
    assert_eq!(a.recv().await["t"], "status");
    let re = json!({"reply_to": rid, "thread_id": rid});
    let reply = msg(&h, &bob, sess, "reply", "alice@local/front", re, "답");
    assert_eq!(send_expect(&mut b, &reply).await["t"], "ack");
    assert_eq!(a.recv().await["t"], "deliver");

    // 조직 전체로 되돌림(audience 없음 = 옛 앱 = org).
    publish(&mut b, "backend", "task").await;
    assert!(session_listed(&a.recv().await, sess));
    let back = msg(&h, &alice, "alice@local/front", "request", sess, q, "다시");
    // 앞 directory.update 들을 비운 뒤.
    c.recv().await;
    b.recv().await;
    assert_eq!(send_expect(&mut a, &back).await["t"], "ack");
}

/// 형식·나 자신·중복·257명·org 에 users·빈 people 은 error{protocol} — 그 프레임 전체를 거절(저장 안 됨). 조직 밖 아이디는
/// 아래 시험(빼고 저장).
#[tokio::test(flavor = "multi_thread")]
async fn audience_shape_errors_reject_the_whole_publish() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let _bob = register(&h, "bob", 2).await;
    let _erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let many: Vec<String> = (0..257).map(|n| format!("u{n}")).collect();
    for bad in [
        json!({"kind": "people", "users": []}),
        json!({"kind": "people", "users": ["alice"]}),
        json!({"kind": "people", "users": ["bob", "bob"]}),
        json!({"kind": "people", "users": many}),
        json!({"kind": "org", "users": ["bob"]}),
        json!({"kind": "team"}),
        json!({"kind": "people", "users": ["bob"], "teams": ["x"]}),
    ] {
        publish_to(&mut a, "s", bad.clone()).await;
        let e = a.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{bad}"
        );
    }
    assert!(h.app.db.sessions_in_org("local").unwrap().is_empty());
    // 맞는 것: org, 같은 조직 사람.
    publish_to(&mut a, "s", json!({"kind": "org"})).await;
    assert_eq!(a.recv().await["t"], "directory.update");
    publish_to(&mut a, "s", json!({"kind": "people", "users": ["bob"]})).await;
    assert_eq!(a.recv().await["t"], "directory.update");
}

/// d3284b3c: 지금 내 조직에 없는 아이디(모름·다른 조직으로 옮김)는 거절하지 않고 빼고 저장한다 — 범위에 든 사람이 다른 조직으로
/// 옮긴 뒤에도 주인 코어가 쥔 같은 범위로 다시 publish 하면 통과하고, 그 아이디만 빠진다. 다 빠지면 빈 목록(주인만).
#[tokio::test(flavor = "multi_thread")]
async fn audience_drops_ids_no_longer_in_my_org() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let _bob = register(&h, "bob", 2).await;
    let _carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let stored = |h: &Harness| {
        h.app.db.sessions_in_org("local").unwrap()[0]
            .audience
            .clone()
    };
    let same = json!({"kind": "people", "users": ["bob", "carol", "nobody"]});
    publish_to(&mut a, "s", same.clone()).await;
    assert_eq!(a.recv().await["t"], "directory.update");
    assert_eq!(
        stored(&h),
        Some(vec!["bob".to_owned(), "carol".to_owned()]),
        "모르는 아이디는 빠짐"
    );
    // carol 이 다른 조직으로 옮김 → 같은 범위로 다시 publish(재접속 등) 해도 통과, carol 만 빠진다.
    set_org(&h, "carol", "acme");
    publish_to(&mut a, "s", same.clone()).await;
    assert_eq!(a.recv().await["t"], "directory.update");
    assert_eq!(stored(&h), Some(vec!["bob".to_owned()]));
    // bob 도 옮기면 빈 목록 — 주인만.
    set_org(&h, "bob", "acme");
    publish_to(&mut a, "s", same).await;
    assert_eq!(a.recv().await["t"], "directory.update");
    assert_eq!(stored(&h), Some(Vec::new()));
    assert!(sees(&mut a, "alice@local/s").await, "주인은 본다");
}

/// 묶음 23 §5·§10: session.publish.project{id, name} — 없으면 통과(옛 앱), `회사/api` 통과·저장·디렉터리에 그대로, 형식 위반
/// (id 길이·빈 성분·`..`·`\`·65자·전체 경로)은 publish 전체 error{protocol}, 범위 밖 사람에겐 세션째 없음(묶음 20).
#[tokio::test(flavor = "multi_thread")]
async fn session_publish_carries_project() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let id = "AbCdEfGhIjKlMnOpQrStUv";
    b.send(&json!({"t": "session.publish", "slug": "api", "grade": "task", "liveness": "live:pty",
        "project": {"id": id, "name": "회사/api"}, "audience": {"kind": "people", "users": ["alice"]}}))
    .await;
    let upd = a.recv().await;
    assert_eq!(
        upd["sessions"],
        json!([{"address": "bob@local/api", "grade": "task", "liveness": "live:pty",
            "project": {"id": id, "name": "회사/api"}}]),
        "{upd}"
    );
    let _ = b.recv().await;
    // 범위 밖 carol 에겐 세션째 없다.
    let d = c.recv().await;
    assert!(!session_listed(&d, "bob@local/api"), "{d}");
    // project 없는 publish(옛 앱)는 통과하고 싣지 않는다.
    b.send(
        &json!({"t": "session.publish", "slug": "api", "grade": "task", "liveness": "live:pty",
        "audience": {"kind": "people", "users": ["alice"]}}),
    )
    .await;
    let upd = a.recv().await;
    assert!(upd["sessions"][0].get("project").is_none(), "{upd}");
    let _ = b.recv().await;
    let long = format!("{}/{}", "가".repeat(32), "나".repeat(32));
    for (pid, name) in [
        ("short", "api"),
        (id, ""),
        (id, "/home/dana/api"),
        (id, "회사//api"),
        (id, "../api"),
        (id, "회사\\api"),
        (id, "a\u{200B}/api"),
        (id, long.as_str()),
    ] {
        b.send(
            &json!({"t": "session.publish", "slug": "evil", "grade": "task", "liveness": "live:pty",
            "project": {"id": pid, "name": name}}),
        )
        .await;
        assert_eq!(b.recv().await["code"], "protocol", "{pid} {name:?}");
    }
    a.expect_silence().await;
}

/// Codex C2(PROTOCOL 13): session.publish.agent — 저장해 디렉터리 세션 항목에 그대로, 없으면 싣지 않음(claude_code·옛 앱),
/// 꼴(소문자 식별자 24자)이 어긋나면 publish 전체 error{protocol}. 옛 판(hello v12) 연결에도 그대로 싣는다 — 옛 앱은 모르는
/// 칸을 건너뛴다.
#[tokio::test(flavor = "multi_thread")]
async fn session_publish_carries_agent() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect_v(&h, &alice, 12).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(
        &json!({"t": "session.publish", "slug": "cx", "grade": "task", "liveness": "live:pty",
        "agent": "codex"}),
    )
    .await;
    let upd = a.recv().await;
    assert_eq!(
        upd["sessions"],
        json!([{"address": "bob@local/cx", "grade": "task", "liveness": "live:pty", "agent": "codex"}]),
        "{upd}"
    );
    let _ = b.recv().await;
    // agent 없는 publish(claude_code·옛 앱)는 지난 값을 남기지 않는다.
    b.send(&json!({"t": "session.publish", "slug": "cx", "grade": "task", "liveness": "live:pty"}))
        .await;
    let upd = a.recv().await;
    assert!(upd["sessions"][0].get("agent").is_none(), "{upd}");
    let _ = b.recv().await;
    // 모르는 종류도 꼴이 맞으면 통과(relay 는 값을 가리지 않는다).
    b.send(
        &json!({"t": "session.publish", "slug": "cx", "grade": "task", "liveness": "live:pty",
        "agent": "agy"}),
    )
    .await;
    assert_eq!(a.recv().await["sessions"][0]["agent"], "agy");
    let _ = b.recv().await;
    let long = "a".repeat(25);
    for bad in [
        json!(""),
        json!("Codex"),
        json!("1x"),
        json!("co-dex"),
        json!(long),
        json!(1),
    ] {
        b.send(
            &json!({"t": "session.publish", "slug": "evil", "grade": "task", "liveness": "live:pty",
            "agent": bad}),
        )
        .await;
        assert_eq!(b.recv().await["code"], "protocol", "{bad}");
    }
    a.expect_silence().await;
}

/// 관문 Y2(PROTOCOL 13): session.publish.no — 저장해 디렉터리 세션 항목에 그대로, 없으면 싣지 않음. 1..=999 밖(0·1000·음수)은
/// 프레임은 받고 칸만 버린다(publish 가 사라지지 않게). 정수가 아니면 형식 오류.
#[tokio::test(flavor = "multi_thread")]
async fn session_publish_carries_no() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&json!({"t": "session.publish", "slug": "a-4", "grade": "task", "liveness": "live:pty", "no": 6}))
        .await;
    let upd = a.recv().await;
    assert_eq!(
        upd["sessions"],
        json!([{"address": "bob@local/a-4", "grade": "task", "liveness": "live:pty", "no": 6}]),
        "{upd}"
    );
    let _ = b.recv().await;
    b.send(
        &json!({"t": "session.publish", "slug": "a-4", "grade": "task", "liveness": "live:pty"}),
    )
    .await;
    let upd = a.recv().await;
    assert!(
        upd["sessions"][0].get("no").is_none(),
        "없으면 지난 값을 남기지 않는다: {upd}"
    );
    let _ = b.recv().await;
    for out in [json!(0), json!(1000), json!(-3), json!(99_999_999_999_i64)] {
        b.send(
            &json!({"t": "session.publish", "slug": "a-4", "grade": "task", "liveness": "live:pty",
            "no": out}),
        )
        .await;
        let upd = a.recv().await;
        assert_eq!(
            upd["sessions"][0]["liveness"], "live:pty",
            "{out}: 프레임은 받는다"
        );
        assert!(
            upd["sessions"][0].get("no").is_none(),
            "{out}: 칸만 버린다 {upd}"
        );
        let _ = b.recv().await;
    }
    b.send(
        &json!({"t": "session.publish", "slug": "a-4", "grade": "task", "liveness": "live:pty",
        "no": "6"}),
    )
    .await;
    assert_eq!(b.recv().await["code"], "protocol");
    a.expect_silence().await;
    // 판 12 연결(0.1.x 앱)의 전체 directory(directory.list 답)엔 13 칸 agent·no 가 없다 — 12 앱은 세션 항목의 모르는 칸을
    // 거절한다(백엔드 리뷰). directory.update 는 그대로 싣는다.
    b.send(
        &json!({"t": "session.publish", "slug": "a-4", "grade": "task", "liveness": "live:pty",
        "no": 6, "agent": "codex"}),
    )
    .await;
    let _ = a.recv().await;
    let _ = b.recv().await;
    let (mut old, _) = connect_v(&h, &alice, 12).await;
    old.send(&json!({"t": "directory.list"})).await;
    let full = loop {
        let f = old.recv().await;
        if f["t"] == "directory" {
            break f;
        }
    };
    let s = &full["sessions"][0];
    assert_eq!(s["address"], "bob@local/a-4", "{full}");
    assert!(s.get("no").is_none() && s.get("agent").is_none(), "{full}");
    a.send(&json!({"t": "directory.list"})).await;
    let full = loop {
        let f = a.recv().await;
        if f["t"] == "directory" {
            break f;
        }
    };
    assert_eq!(full["sessions"][0]["no"], 6, "13 연결은 그대로: {full}");
}

// ---------------------------------------------------------------- 묶음 18 공개 가입 (#378, bundle-18-public-signup.md)

/// 원격 relay, `--org-create open`(상한은 `limits` 로). 조직 만들기 코드도 하나 낸다(상한 밖 경로 시험용).
async fn start_open(
    limits: lodelai_relay::OrgCreateLimits,
) -> (Harness, std::sync::Arc<CaptureMailer>, String) {
    let db = Db::memory().unwrap();
    let rng = TestEffects::new(START_MS, 99).rng;
    let code = lodelai_relay::http::bootstrap_setup_code(&db, rng.as_ref(), START_MS).unwrap();
    let mail = std::sync::Arc::new(CaptureMailer::default());
    let h = start_full(
        |c| {
            c.remote = true;
            c.public_host = Some(PUBLIC.into());
            c.privacy_version = Some(PRIVACY.into());
            c.org_create_open = true;
            c.org_create_limits = limits;
        },
        db,
        Some(mail.clone()),
    )
    .await;
    (h, mail, code)
}

/// 넉넉한 상한 — 시험이 보는 것 하나만 줄인다.
fn wide() -> lodelai_relay::OrgCreateLimits {
    lodelai_relay::OrgCreateLimits {
        per_email_30d: 100,
        per_ip_day: 100,
        per_day: 100,
        max_orgs: 100,
    }
}

/// 가입 메일·확인의 IP 상한(1시간 20번)을 다시 채운다 — 이 시험들은 조직 만들기 상한만 본다.
fn refill_signup_ip(h: &Harness) {
    h.fx.clock.advance(60 * 60 * 1000 + 1);
}

/// 원격 verify 응답 전체.
async fn remote_verify(h: &Harness, mail: &CaptureMailer, email: &str) -> Value {
    let (code, resp) = post_json(
        h,
        "/v1/signup",
        &json!({"email": email, "privacy": {"version": PRIVACY}}),
    )
    .await;
    assert_eq!(code, 202, "{resp}");
    let sent = mail.0.lock().unwrap()[email].clone();
    let (code, resp) = post_json(
        h,
        "/v1/signup/verify",
        &json!({"email": email, "code": sent}),
    )
    .await;
    assert_eq!(code, 200, "{resp}");
    serde_json::from_str(&resp).unwrap()
}

/// 가입 토큰으로 코드 없이 새 조직. (상태 코드, 본문)
async fn open_create(
    h: &Harness,
    token: &str,
    user: &str,
    keys: &DeviceKeys,
    org: Value,
) -> (u16, Value) {
    let body = json!({"signup_token": token, "user": user, "display_name": user,
        "device_pubkeys": device_pubkeys(keys), "org": org});
    let (code, resp) = post_json(h, "/v1/devices", &body).await;
    (code, serde_json::from_str(&resp).unwrap_or(Value::Null))
}

fn create(name: &str) -> Value {
    json!({"create": {"name": name}})
}

fn user_with(name: &str, keys: DeviceKeys) -> User {
    User {
        name: name.into(),
        device_id: keys.device_id().as_str().to_owned(),
        keys,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn open_mode_creates_org_without_code_and_verify_says_so() {
    let (h, mail, _) = start_open(wide()).await;
    let v = remote_verify(&h, &mail, "boss@x.io").await;
    assert_eq!(
        (v["kind"].as_str(), v["org_create"].as_str()),
        (Some("new"), Some("open"))
    );
    let k = DeviceKeys::generate(&[1; 64]);
    let (code, resp) = open_create(
        &h,
        v["signup_token"].as_str().unwrap(),
        "boss",
        &k,
        create("루이보스"),
    )
    .await;
    assert_eq!(code, 201, "{resp}");
    let (mut c, ready) = connect(&h, &user_with("boss", k)).await;
    assert_eq!(ready["admin"], true);
    c.send(&json!({"t": "directory.list"})).await;
    assert_eq!(c.recv().await["org"]["name"], "루이보스");

    // 같은 이메일을 다시 확인하면 existing + 조직 이름, org_create 는 new 에만.
    let v = remote_verify(&h, &mail, "boss@x.io").await;
    assert_eq!(v["kind"], "existing");
    assert_eq!(v["account"]["org_name"], "루이보스");
    assert!(v.get("org_create").is_none(), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn code_mode_verify_says_code_and_local_relay_says_open() {
    let (h, mail, _) = start_remote_full().await;
    let v = remote_verify(&h, &mail, "boss@x.io").await;
    assert_eq!(v["org_create"], "code");
    // 로컬 relay 는 설정과 상관없이 코드 없이 만든다.
    let (h, mail) = start_hosted().await;
    let (code, _) = post_json(
        &h,
        "/v1/signup",
        &json!({"email": "a@x.io", "privacy": {"version": "t"}}),
    )
    .await;
    assert_eq!(code, 202);
    let sent = mail.0.lock().unwrap()["a@x.io"].clone();
    let (_, resp) = post_json(
        &h,
        "/v1/signup/verify",
        &json!({"email": "a@x.io", "code": sent}),
    )
    .await;
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["org_create"], "open");
    let k = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        open_create(
            &h,
            v["signup_token"].as_str().unwrap(),
            "a",
            &k,
            create("o")
        )
        .await
        .0,
        201
    );
}

/// ADR 0011: 기존 계정의 이메일로는 조직을 만들거나 다른 초대로 들어갈 수 없다 — 409 `account_exists`, 토큰은 남아 같은
/// 토큰으로 기기 추가가 된다. 코드 검사보다 먼저 본다(틀린 코드여도 409).
#[tokio::test(flavor = "multi_thread")]
async fn existing_account_cannot_create_or_join_and_keeps_token() {
    let (h, mail, code) = start_open(wide()).await;
    let token = remote_token(&h, &mail, "boss@x.io").await;
    let k1 = DeviceKeys::generate(&[1; 64]);
    assert_eq!(
        open_create(&h, &token, "boss", &k1, create("A")).await.0,
        201
    );
    let (mut c, _) = connect(&h, &user_with("boss", k1.clone())).await;
    c.send(&json!({"t": "invite.create"})).await;
    let invite = c.recv().await["token"].as_str().unwrap().to_owned();

    let token = remote_token(&h, &mail, "boss@x.io").await;
    let k2 = DeviceKeys::generate(&[2; 64]);
    for org in [
        create("B"),
        json!({"create": {"name": "B", "setup_code": "0000-0000-0000-0000"}}),
        json!({"create": {"name": "B", "setup_code": code}}),
        json!({"invite": invite}),
    ] {
        // 친 아이디가 달라도(경합 — 다른 기기가 먼저 가입) 본문의 account 는 실제 계정이다.
        let (status, resp) = open_create(&h, &token, "typed", &k2, org.clone()).await;
        assert_eq!(
            (status, resp["reason"].as_str()),
            (409, Some("account_exists")),
            "{org}"
        );
        assert_eq!(
            resp["account"],
            json!({"user": "boss", "display_name": "boss", "org_name": "A"}),
            "{org}"
        );
    }
    // 이미 그 계정의 기기로 다시 가입해도 조직을 실으면 409.
    let (status, resp) = open_create(&h, &token, "boss", &k1, create("B")).await;
    assert_eq!(
        (status, resp["reason"].as_str()),
        (409, Some("account_exists"))
    );
    assert_eq!(resp["account"]["user"], "boss");
    // 같은 토큰으로 기기 추가.
    let body = json!({"signup_token": token, "device_pubkeys": device_pubkeys(&k2)});
    let (status, resp) = post_json(&h, "/v1/devices", &body).await;
    assert_eq!(status, 201, "{resp}");
    // 틀린 코드를 세지 않았다 — 운영자 코드는 아직 쓸 수 있다(다른 이메일).
    let token = remote_token(&h, &mail, "eve@x.io").await;
    let k3 = DeviceKeys::generate(&[3; 64]);
    let org = json!({"create": {"name": "C", "setup_code": code}});
    assert_eq!(open_create(&h, &token, "eve", &k3, org).await.0, 201);
}

/// `--max-orgs` 는 내보내지 않은 멤버가 있는 조직만 센다. 넘으면 403 `org_create_closed`, 토큰은 남는다. 운영자 코드는 상한 밖.
#[tokio::test(flavor = "multi_thread")]
async fn max_orgs_closes_creation_and_empty_orgs_do_not_count() {
    let (h, mail, code) = start_open(lodelai_relay::OrgCreateLimits {
        max_orgs: 1,
        ..wide()
    })
    .await;
    let ka = DeviceKeys::generate(&[1; 64]);
    let token = remote_token(&h, &mail, "a@x.io").await;
    assert_eq!(open_create(&h, &token, "a", &ka, create("A")).await.0, 201);

    let kb = DeviceKeys::generate(&[2; 64]);
    let token = remote_token(&h, &mail, "b@x.io").await;
    let (status, resp) = open_create(&h, &token, "b", &kb, create("B")).await;
    assert_eq!(
        (status, resp["reason"].as_str()),
        (403, Some("org_create_closed"))
    );
    // 코드를 주면 상한을 보지 않는다(같은 토큰 — 거절이 쓰지 않았다).
    let org = json!({"create": {"name": "B", "setup_code": code}});
    assert_eq!(open_create(&h, &token, "b", &kb, org).await.0, 201);

    // A 가 혼자 나가 빈 조직이 되어도 B 가 있어 아직 1개 — 닫힘. B 도 나가면 0 → 열림.
    let (mut a, _) = connect(&h, &user_with("a", ka)).await;
    a.send(&json!({"t": "member.leave"})).await;
    expect_closed(&mut a, Duration::from_secs(3)).await;
    refill_signup_ip(&h);
    let kc = DeviceKeys::generate(&[3; 64]);
    let token = remote_token(&h, &mail, "c@x.io").await;
    assert_eq!(open_create(&h, &token, "c", &kc, create("C")).await.0, 403);
    let (mut b, _) = connect(&h, &user_with("b", kb)).await;
    b.send(&json!({"t": "member.leave"})).await;
    expect_closed(&mut b, Duration::from_secs(3)).await;
    assert_eq!(open_create(&h, &token, "c", &kc, create("C")).await.0, 201);
}

/// 같은 이메일 30일 상한 — 만들고 나가고 다시 만들기를 센다(내보내도 email_mac 으로 남음). 넘으면 429 `org_rate_limited`,
/// 토큰은 남는다. 30일 뒤엔 다시.
#[tokio::test(flavor = "multi_thread")]
async fn per_email_30d_counts_create_leave_create() {
    let (h, mail, _) = start_open(lodelai_relay::OrgCreateLimits {
        per_email_30d: 2,
        ..wide()
    })
    .await;
    for n in 0..2u8 {
        let k = DeviceKeys::generate(&[10 + n; 64]);
        let token = remote_token(&h, &mail, "a@x.io").await;
        assert_eq!(open_create(&h, &token, "a", &k, create("A")).await.0, 201);
        let (mut c, _) = connect(&h, &user_with("a", k)).await;
        c.send(&json!({"t": "member.leave"})).await;
        expect_closed(&mut c, Duration::from_secs(3)).await;
    }
    let k = DeviceKeys::generate(&[20; 64]);
    let token = remote_token(&h, &mail, "a@x.io").await;
    let (status, resp) = open_create(&h, &token, "a", &k, create("A")).await;
    assert_eq!(
        (status, resp["reason"].as_str()),
        (429, Some("org_rate_limited"))
    );
    // 다른 이메일은 된다.
    let kb = DeviceKeys::generate(&[21; 64]);
    let tb = remote_token(&h, &mail, "b@x.io").await;
    assert_eq!(open_create(&h, &tb, "b", &kb, create("B")).await.0, 201);
    // 30일 뒤 — 청소가 옛 기록을 지우고, 같은 토큰은 끝났으니 새로 받는다.
    h.fx.clock.advance(30 * 24 * 60 * 60 * 1000);
    h.app.expire_tick();
    let token = remote_token(&h, &mail, "a@x.io").await;
    assert_eq!(open_create(&h, &token, "a", &k, create("A")).await.0, 201);
}

/// IP 하루·전역 하루 상한. 실패한 만들기는 세지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn per_ip_and_per_day_limits_count_only_successes() {
    let (h, mail, _) = start_open(lodelai_relay::OrgCreateLimits {
        per_ip_day: 2,
        ..wide()
    })
    .await;
    // 실패(남이 쓰는 아이디 403·팀 고름 400)는 세지 않는다.
    let k0 = DeviceKeys::generate(&[1; 64]);
    let t0 = remote_token(&h, &mail, "a@x.io").await;
    assert_eq!(open_create(&h, &t0, "a", &k0, create("A")).await.0, 201);
    let k1 = DeviceKeys::generate(&[2; 64]);
    let t1 = remote_token(&h, &mail, "b@x.io").await;
    assert_eq!(open_create(&h, &t1, "a", &k1, create("B")).await.0, 403);
    assert_eq!(open_create(&h, &t1, "b", &k1, create("B")).await.0, 201);
    let k2 = DeviceKeys::generate(&[3; 64]);
    let t2 = remote_token(&h, &mail, "c@x.io").await;
    let (status, resp) = open_create(&h, &t2, "c", &k2, create("C")).await;
    assert_eq!(
        (status, resp["reason"].as_str()),
        (429, Some("org_rate_limited")),
        "IP 하루 2"
    );
    // 초대로 들어오는 길은 상한과 무관.
    let (mut a, _) = connect(&h, &user_with("a", k0)).await;
    a.send(&json!({"t": "invite.create"})).await;
    let invite = a.recv().await["token"].as_str().unwrap().to_owned();
    assert_eq!(
        open_create(&h, &t2, "c", &k2, json!({"invite": invite}))
            .await
            .0,
        201
    );

    // 전역 UTC 하루.
    let (h, mail, _) = start_open(lodelai_relay::OrgCreateLimits {
        per_day: 1,
        ..wide()
    })
    .await;
    let k = DeviceKeys::generate(&[4; 64]);
    let t = remote_token(&h, &mail, "a@x.io").await;
    assert_eq!(open_create(&h, &t, "a", &k, create("A")).await.0, 201);
    let k = DeviceKeys::generate(&[5; 64]);
    let t = remote_token(&h, &mail, "b@x.io").await;
    let (status, resp) = open_create(&h, &t, "b", &k, create("B")).await;
    assert_eq!(
        (status, resp["reason"].as_str()),
        (429, Some("org_rate_limited")),
        "전역 하루 1"
    );
}

/// `code` 모드: 코드 없이 오면 422(상한·reason 없음), 맞는 코드는 지금처럼.
#[tokio::test(flavor = "multi_thread")]
async fn code_mode_still_needs_code() {
    let (h, mail, code) = start_remote_full().await;
    let k = DeviceKeys::generate(&[1; 64]);
    let token = remote_token(&h, &mail, "a@x.io").await;
    assert_eq!(open_create(&h, &token, "a", &k, create("A")).await.0, 422);
    let org = json!({"create": {"name": "A", "setup_code": code}});
    assert_eq!(open_create(&h, &token, "a", &k, org).await.0, 201);
}

// ---- 묶음 22 §12-27 ⓑ: 내 기기 last_seen_at — 날 단위, 내 항목에만 ----

/// `directory.list` 에 대한 `directory` 답(사이에 끼는 directory.update·presence 는 건너뜀).
async fn list_dir(c: &mut Client) -> Value {
    c.send(&json!({"t": "directory.list"})).await;
    loop {
        let f = c.recv().await;
        if f["t"] == "directory" {
            return f;
        }
    }
}

fn day_of(ms: i64) -> String {
    lodelai_effects::UnixMillis(ms - ms.rem_euclid(24 * 3600 * 1000))
        .to_rfc3339()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn last_seen_at_is_day_granular_and_only_in_my_own_entry() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let (mut b, _) = connect(&h, &p[0]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    let today = day_of(h.fx.clock.now().0);
    let devices = |d: &Value, u: &str| person(d, u)["devices"].as_array().unwrap().clone();
    // 내 기기에는 오늘 0시(UTC), 동료 기기에는 없음 — 동료가 접속해 있어도.
    for (c, me, other) in [(&mut b, "boss", "minji"), (&mut m, "minji", "boss")] {
        let d = list_dir(c).await;
        assert!(
            devices(&d, me)
                .iter()
                .all(|x| x["last_seen_at"] == today.as_str()),
            "{d}"
        );
        assert!(
            devices(&d, other)
                .iter()
                .all(|x| x.get("last_seen_at").is_none()),
            "동료의 접속 시각이 새면 안 된다: {d}"
        );
    }
    // 내 둘째 기기가 다음 날 다시 접속하면 그 기기만 갱신되고, 내 다른 기기(b)에 directory.update — 값은 날 단위.
    // 첫 접속(처음 적는 값)은 방송하지 않는다 — 새 기기는 등록이 이미 알렸다.
    let boss2 = second_device(&h, &mail, &p[0], 11).await;
    drop(connect(&h, &boss2).await);
    h.fx.clock.advance(24 * 3600 * 1000);
    let tomorrow = day_of(h.fx.clock.now().0);
    let (_b2, _) = connect(&h, &boss2).await;
    let seen = |d: &Value, id: &str| {
        devices(d, "boss")
            .iter()
            .find(|x| x["device_id"] == id)
            .map(|x| x["last_seen_at"].clone())
    };
    let d = loop {
        let d = next_dir(&mut b).await;
        if seen(&d, &boss2.device_id) == Some(json!(tomorrow)) {
            break d;
        }
    };
    assert_eq!(seen(&d, &p[0].device_id), Some(json!(today)), "{d}");
    assert!(
        devices(&d, "minji")
            .iter()
            .all(|x| x.get("last_seen_at").is_none()),
        "{d}"
    );
    // minji 쪽에는 boss 의 날짜가 끝내 실리지 않는다.
    let d = list_dir(&mut m).await;
    assert!(
        devices(&d, "boss")
            .iter()
            .all(|x| x.get("last_seen_at").is_none()),
        "{d}"
    );
    assert!(
        devices(&d, "minji")
            .iter()
            .all(|x| x["last_seen_at"] == today.as_str()),
        "{d}"
    );
}

// ---------------------------------------------------------------- #569 ③ 꺼진 기기의 공개 세션은 dead

/// 디렉터리에서 그 세션 주소의 항목.
fn session_of<'a>(d: &'a Value, address: &str) -> Option<&'a Value> {
    d["sessions"]
        .as_array()?
        .iter()
        .find(|s| s["address"] == address)
}

async fn publish_live(c: &mut Client, slug: &str, title: &str) {
    c.send(
        &json!({"t": "session.publish", "slug": slug, "grade": "task",
        "liveness": "live:pty", "title": title, "busy": true}),
    )
    .await;
}

/// #569 ③: 기기의 마지막 연결이 끊기고 유예(시험은 1초 — '조용함' 확인 창 [유예/3 + 200ms] 이 유예 안에 들게) 뒤에도 안 붙으면 그 기기가 공개한 세션은 dead·busy 없음 —
/// update 한 번. 같은 기기 연결 둘 중 하나만 끊기면 live, 유예 안에 다시 붙으면 update 없음. 다시 publish 하면 live 와 새
/// 제목(옛 이름이 남지 않음).
#[tokio::test(flavor = "multi_thread")]
async fn 꺼진_기기의_공개_세션은_유예_뒤_dead() {
    let grace = Duration::from_millis(1000);
    let h = start_with(|c| c.session_dead_grace = grace).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut a1, _) = connect(&h, &alice).await;
    let (a2, _) = connect(&h, &alice).await;
    publish_live(&mut a1, "s1", "옛 이름").await;
    let d = next_dir(&mut b).await;
    let s = session_of(&d, "alice@local/s1").unwrap();
    assert_eq!(
        (s["liveness"].as_str(), s["busy"].as_bool()),
        (Some("live:pty"), Some(true)),
        "{s}"
    );

    // 같은 기기 연결 둘 중 하나만 끊김 → 그대로.
    drop(a1);
    tokio::time::sleep(grace * 2).await;
    b.expect_silence().await;

    // 마지막 연결 끊김 → 유예 안엔 조용, 뒤에 dead·busy 없음 update 한 번.
    let t0 = std::time::Instant::now();
    drop(a2);
    tokio::time::sleep(grace / 3).await;
    b.expect_silence().await;
    let d = next_dir(&mut b).await;
    assert!(t0.elapsed() >= grace, "{:?}", t0.elapsed());
    let s = session_of(&d, "alice@local/s1").unwrap();
    assert_eq!(s["liveness"], "dead", "{s}");
    assert_ne!(s["busy"], json!(true), "{s}");
    // #739: 끊김으로 dead — 주인이 끝낸 것과 가르는 offline.
    assert_eq!(s["offline"], true, "{s}");
    b.expect_silence().await;

    // 다시 붙어 publish → live·새 제목.
    let (mut a3, _) = connect(&h, &alice).await;
    publish_live(&mut a3, "s1", "새 이름").await;
    let d = next_dir(&mut b).await;
    let s = session_of(&d, "alice@local/s1").unwrap();
    assert_eq!(
        (s["liveness"].as_str(), s["title"].as_str()),
        (Some("live:pty"), Some("새 이름")),
        "{s}"
    );
    assert!(s.get("offline").is_none(), "다시 publish 하면 빠진다: {s}");

    // 유예 안에 다시 붙음 → update 없음, live 그대로.
    drop(a3);
    tokio::time::sleep(grace / 3).await;
    let (mut _a4, _) = connect(&h, &alice).await;
    tokio::time::sleep(grace * 2).await;
    b.expect_silence().await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut b).await;
    assert_eq!(
        session_of(&d, "alice@local/s1").unwrap()["liveness"],
        "live:pty"
    );

    // #739: 주인이 끝낸 dead(publish) 는 offline 이 없고, 그 뒤 기기가 끊겨도 생기지 않는다.
    _a4.send(
        &json!({"t": "session.publish", "slug": "s1", "grade": "task", "liveness": "dead", "title": "새 이름"}),
    )
    .await;
    let d = next_dir(&mut b).await;
    let s = session_of(&d, "alice@local/s1").unwrap();
    assert_eq!(
        (s["liveness"].as_str(), s.get("offline")),
        (Some("dead"), None),
        "{s}"
    );
    drop(_a4);
    tokio::time::sleep(grace * 2).await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut b).await;
    assert!(session_of(&d, "alice@local/s1")
        .unwrap()
        .get("offline")
        .is_none());
}

/// #569 ③: relay 가 다시 뜨면(연결 0) 기기를 아는 공개 세션은 모두 dead. 기기 없는 옛 행은 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn relay_기동_때_기기를_아는_공개_세션은_dead() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let h = start_db(
        |c| c.session_dead_grace = Duration::from_secs(3600),
        Db::open(&path).unwrap(),
    )
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    publish_live(&mut a, "s1", "제목").await;
    a.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut a).await;
    assert_eq!(
        session_of(&d, "alice@local/s1").unwrap()["liveness"],
        "live:pty"
    );
    // 옛 앱이 남긴 행(device_id 없음).
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute(
            "INSERT INTO sessions_public(user, slug, grade, liveness) VALUES ('alice', 'old', 'task', 'live:channel')",
            [],
        )
        .unwrap();
    }
    // 같은 DB 로 relay 를 다시 띄운다.
    let h2 = start_db(|_| {}, Db::open(&path).unwrap()).await;
    let (mut a2, _) = connect(&h2, &alice).await;
    a2.send(&json!({"t": "directory.list"})).await;
    let d = next_dir(&mut a2).await;
    assert_eq!(
        session_of(&d, "alice@local/s1").unwrap()["liveness"],
        "dead",
        "{d}"
    );
    assert_eq!(
        session_of(&d, "alice@local/old").unwrap()["liveness"],
        "live:channel",
        "{d}"
    );
    drop(h);
}

// ------------------------------------------------------------------ 메일 확인 끊기(#577, 계약 6490433889 §7)

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// hosted 계정 하나에 먼저 기기·나중 기기(메일 코드로 추가 — 서명 없음 = pending).
async fn recovery_account(h: &Harness, mail: &CaptureMailer, extra: u8) -> (User, User) {
    let token = signup_token(h, mail, "dana@example.com").await;
    let k1 = DeviceKeys::generate(&[1; 64]);
    let (code, resp) = post_json(h, "/v1/devices", &hosted_body(&token, Some("dana"), &k1)).await;
    assert_eq!(code, 201, "{resp}");
    let old = User {
        name: "dana".into(),
        device_id: k1.device_id().as_str().to_owned(),
        keys: k1,
    };
    h.fx.clock.advance(60_000);
    let new = recovery_extra(h, mail, extra).await;
    (old, new)
}

async fn recovery_extra(h: &Harness, mail: &CaptureMailer, seed: u8) -> User {
    let token = signup_token(h, mail, "dana@example.com").await;
    let k = DeviceKeys::generate(&[seed; 64]);
    let (code, resp) = post_json(h, "/v1/devices", &hosted_body(&token, None, &k)).await;
    assert_eq!(code, 201, "{resp}");
    User {
        name: "dana".into(),
        device_id: k.device_id().as_str().to_owned(),
        keys: k,
    }
}

/// 접속하고 접속 직후 프레임(디렉터리·알림)을 비운다.
async fn recovery_connect(h: &Harness, u: &User) -> Client {
    let (mut c, _) = connect(h, u).await;
    c.drain().await;
    c
}

/// 디렉터리 갱신을 건너뛰고 그 종류의 다음 프레임.
async fn recv_t(c: &mut Client, t: &str) -> Value {
    loop {
        let f = c.recv().await;
        if f["t"] == t {
            return f;
        }
        assert!(
            matches!(
                f["t"].as_str(),
                Some("directory" | "directory.update" | "groups")
            ),
            "{t} 를 기다리는데 받음: {f}"
        );
    }
}

/// 알림 메일 제목들(보내기는 따로 스레드 — 잠깐 기다린다).
async fn mail_subjects(mail: &CaptureMailer) -> Vec<String> {
    tokio::time::sleep(Duration::from_millis(100)).await;
    mail.1
        .lock()
        .unwrap()
        .iter()
        .map(|(_, s)| s.clone())
        .collect()
}

fn refused(f: &Value) -> (Option<&str>, Option<&str>) {
    assert_eq!(f["t"], "error", "{f}");
    assert_eq!(f["code"], "recover_refused", "{f}");
    (f["reason"].as_str(), f["until"].as_str())
}

/// 시험 1·2·7a·8: pending 직후 걸기 → 대상 즉시·재접속 때 recover_against → 접속만으론 그대로 → at 에 실행.
#[tokio::test(flavor = "multi_thread")]
async fn recover_schedules_notifies_targets_and_executes_at_time() {
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;

    c_new.send(&json!({"t": "device.recover"})).await;
    let at = now_str(&h, DAY_MS);
    assert_eq!(
        recv_t(&mut c_new, "device.recover_scheduled").await,
        json!({"t": "device.recover_scheduled", "at": at, "targets": [old.device_id]})
    );
    assert_eq!(
        recv_t(&mut c_old, "device.recover_against").await,
        json!({"t": "device.recover_against", "at": at, "requester": new.device_id})
    );
    // 재요청은 멱등.
    c_new.send(&json!({"t": "device.recover"})).await;
    assert_eq!(
        recv_t(&mut c_new, "device.recover_scheduled").await["at"],
        at
    );

    // 디렉터리: 내 항목에 recovery·last_auth_at.
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    let me = &d["people"][0];
    assert_eq!(me["recovery"]["state"], "scheduled");
    assert_eq!(me["recovery"]["targets"], json!([old.device_id]));
    assert_eq!(me["recovery"]["requester"], new.device_id);
    assert!(me["devices"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d["last_auth_at"].is_string()));

    // 7a: 대상이 끊고 다시 붙기만 함 → 걸기 그대로, 다시 recover_against.
    drop(c_old);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut c_old, _) = connect(&h, &old).await;
    assert_eq!(recv_t(&mut c_old, "device.recover_against").await["at"], at);
    assert_eq!(h.app.expire_tick(), 0);

    // #737: 걸기 뒤 대상이 붙었다 — at 에 실행하지 않고 한 번 미룬다(양쪽에 새 시각).
    h.fx.clock.advance(DAY_MS);
    assert_eq!(h.app.expire_tick(), 0);
    let later = now_str(&h, DAY_MS);
    assert_eq!(
        recv_t(&mut c_new, "device.recover_scheduled").await,
        json!({"t": "device.recover_scheduled", "at": later, "targets": [old.device_id]})
    );
    assert_eq!(
        recv_t(&mut c_old, "device.recover_against").await,
        json!({"t": "device.recover_against", "at": later, "requester": new.device_id})
    );
    assert!(h.app.db.device(&old.device_id).unwrap().is_some());
    // 미룬 동안 다시 붙어도 더 미루지 않는다.
    drop(c_old);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut c_old, _) = connect(&h, &old).await;
    assert_eq!(
        recv_t(&mut c_old, "device.recover_against").await["at"],
        later
    );

    // 8: 미룬 at 도달 → 대상 끊김(by recovery, 증명 없음) → device.recovered → 메일.
    h.fx.clock.advance(DAY_MS);
    h.app.expire_tick();
    assert_eq!(
        recv_t(&mut c_new, "device.recovered").await,
        json!({"t": "device.recovered", "at": now_str(&h, 0), "targets": [old.device_id]})
    );
    let got = c_old.drain_until_closed().await;
    assert!(
        got.iter().any(|f| f["t"] == "device.revoked"
            && f["by"] == "recovery"
            && f["at"] == now_str(&h, 0)),
        "{got:?}"
    );
    assert!(h.app.db.device(&old.device_id).unwrap().is_none());
    let subjects = mail_subjects(&mail).await;
    assert_eq!(subjects.len(), 2, "{subjects:?}");
    // 실행 뒤 디렉터리: done, 요청 기기는 이제 뿌리.
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    assert_eq!(d["people"][0]["recovery"]["state"], "done");
    // 이제 자격이 있으니 다시 걸면 trusted.
    c_new.send(&json!({"t": "device.recover"})).await;
    assert_eq!(
        refused(&recv_t(&mut c_new, "error").await).0,
        Some("trusted")
    );
}

/// #737: 옛 기기가 걸기 뒤 한 번도 안 붙음 → 처음 at 에 실행. 걸 때 붙어 있기만 해도 '붙음' → 한 번 미룸.
#[tokio::test(flavor = "multi_thread")]
async fn recover_defers_once_only_when_target_was_seen() {
    // 안 붙음: 옛 기기는 꺼져 있다.
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_new = recovery_connect(&h, &new).await;
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    h.fx.clock.advance(DAY_MS);
    h.app.expire_tick();
    assert_eq!(
        recv_t(&mut c_new, "device.recovered").await["targets"],
        json!([old.device_id])
    );
    assert!(h.app.db.device(&old.device_id).unwrap().is_none());
    drop(h);

    // 걸 때 붙어 있음(다시 붙지 않음): 한 번 미룸 → 미룬 at 에 실행.
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    recv_t(&mut c_old, "device.recover_against").await;
    h.fx.clock.advance(DAY_MS);
    h.app.expire_tick();
    assert_eq!(
        recv_t(&mut c_new, "device.recover_scheduled").await["at"],
        now_str(&h, DAY_MS)
    );
    assert!(h.app.db.device(&old.device_id).unwrap().is_some());
    // 디렉터리에 미룸 표시(postponed).
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    assert_eq!(d["people"][0]["recovery"]["postponed"], true, "{d}");
    h.fx.clock.advance(DAY_MS);
    h.app.expire_tick();
    recv_t(&mut c_new, "device.recovered").await;
    assert!(h.app.db.device(&old.device_id).unwrap().is_none());
}

/// 시험 3·4·5·6·6a·7c: 막기·대상 아닌 막기·취소·쿨다운·30일 상한.
#[tokio::test(flavor = "multi_thread")]
async fn recover_block_cooldown_and_exhaustion() {
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;

    // 걸기 없음: 막기 = ended, 취소 = not_scheduled.
    c_old.send(&json!({"t": "device.recover_block"})).await;
    assert_eq!(refused(&recv_t(&mut c_old, "error").await).0, Some("ended"));
    c_new.send(&json!({"t": "device.recover_cancel"})).await;
    assert_eq!(
        refused(&recv_t(&mut c_new, "error").await).0,
        Some("not_scheduled")
    );

    for round in 0..3 {
        c_new.send(&json!({"t": "device.recover"})).await;
        recv_t(&mut c_new, "device.recover_scheduled").await;
        recv_t(&mut c_old, "device.recover_against").await;
        // 4: 대상 아닌 기기(요청 기기)의 막기, 대상의 취소.
        c_new.send(&json!({"t": "device.recover_block"})).await;
        assert_eq!(
            refused(&recv_t(&mut c_new, "error").await).0,
            Some("not_target")
        );
        c_old.send(&json!({"t": "device.recover_cancel"})).await;
        assert_eq!(
            refused(&recv_t(&mut c_old, "error").await).0,
            Some("not_scheduled")
        );
        // 3: 막기.
        c_old.send(&json!({"t": "device.recover_block"})).await;
        let now = now_str(&h, 0);
        let c = recv_t(&mut c_new, "device.recover_canceled").await;
        assert_eq!(c["reason"], "blocked");
        assert_eq!(c["by"], old.device_id);
        assert_eq!(c["at"], now);
        assert_eq!(
            recv_t(&mut c_old, "device.recover_against_ended").await,
            json!({"t": "device.recover_against_ended", "reason": "blocked"})
        );
        if round < 2 {
            // 7c·5: 쿨다운 24h — retry_at·until·디렉터리 at 이 같다.
            let retry = now_str(&h, DAY_MS);
            assert_eq!(c["retry_at"], retry);
            c_new.send(&json!({"t": "device.recover"})).await;
            assert_eq!(
                refused(&recv_t(&mut c_new, "error").await),
                (Some("cooldown"), Some(retry.as_str()))
            );
            c_new.send(&json!({"t": "directory.list"})).await;
            let d = recv_t(&mut c_new, "directory").await;
            assert_eq!(d["people"][0]["recovery"]["state"], "blocked");
            assert_eq!(d["people"][0]["recovery"]["at"], retry);
            assert_eq!(
                d["people"][0]["recovery"]["blocked_by"],
                json!({"device_id": old.device_id, "at": now})
            );
            h.fx.clock.advance(DAY_MS);
        }
    }
    // 6: 30일에 막기 3번 → exhausted, until = 첫 막기 + 30일.
    h.fx.clock.advance(DAY_MS);
    c_new.send(&json!({"t": "device.recover"})).await;
    let e = recv_t(&mut c_new, "error").await;
    let (reason, until) = refused(&e);
    assert_eq!(reason, Some("exhausted"));
    let until = until.unwrap().to_owned();
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    assert_eq!(d["people"][0]["recovery"]["state"], "exhausted");
    assert_eq!(d["people"][0]["recovery"]["at"], until);
    // 창이 풀리면 다시 된다.
    h.fx.clock.advance(28 * DAY_MS);
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    recv_t(&mut c_old, "device.recover_against").await;

    // 취소 → 쿨다운.
    c_new.send(&json!({"t": "device.recover_cancel"})).await;
    let c = recv_t(&mut c_new, "device.recover_canceled").await;
    assert_eq!(c["reason"], "requester");
    assert_eq!(c["retry_at"], now_str(&h, DAY_MS));
    assert_eq!(
        recv_t(&mut c_old, "device.recover_against_ended").await["reason"],
        "canceled"
    );
    c_new.send(&json!({"t": "device.recover"})).await;
    assert_eq!(
        refused(&recv_t(&mut c_new, "error").await).0,
        Some("cooldown")
    );
    // 막기 셋·취소 하나·걸기 다섯의 메일(scheduled 4 + blocked 3 + canceled 1).
    assert_eq!(mail_subjects(&mail).await.len(), 8);
}

/// 시험 7·7b: 대상의 certify → certified(메일·쿨다운 없음). 지금 끊기(자기 폐기) — 대상 O1·O2 중 O1 만이면 계속.
#[tokio::test(flavor = "multi_thread")]
async fn recover_ends_when_requester_becomes_eligible() {
    let (h, mail) = start_hosted().await;
    let (o2, o1) = recovery_account(&h, &mail, 2).await;
    h.fx.clock.advance(60_000);
    let new = recovery_extra(&h, &mail, 3).await;
    let mut c_o2 = recovery_connect(&h, &o2).await;
    let mut c_o1 = recovery_connect(&h, &o1).await;
    let mut c_new = recovery_connect(&h, &new).await;
    let before = mail_subjects(&mail).await.len();

    c_new.send(&json!({"t": "device.recover"})).await;
    let s = recv_t(&mut c_new, "device.recover_scheduled").await;
    assert_eq!(s["targets"], json!([o2.device_id, o1.device_id]));
    recv_t(&mut c_o2, "device.recover_against").await;
    recv_t(&mut c_o1, "device.recover_against").await;

    // O1(뿌리 사슬 밖 — O2 가 서명 안 함)이 서명하고 자기 폐기 → 요청 기기는 여전히 pending, 대상은 O2 만.
    c_o1.send(&json!({"t": "device.certify", "device_id": new.device_id, "sig": devcert(SERVER, &o1, &new)}))
        .await;
    c_o1.send(&json!({"t": "device.revoke"})).await;
    c_o1.drain_until_closed().await;
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    assert_eq!(d["people"][0]["recovery"]["state"], "scheduled");
    assert_eq!(d["people"][0]["recovery"]["targets"], json!([o2.device_id]));

    // 7: 뿌리 O2 가 서명 → 요청 기기 자격 → certified.
    c_o2.send(&json!({"t": "device.certify", "device_id": new.device_id, "sig": devcert(SERVER, &o2, &new)}))
        .await;
    assert_eq!(
        recv_t(&mut c_new, "device.recover_canceled").await,
        json!({"t": "device.recover_canceled", "reason": "certified"})
    );
    assert_eq!(
        recv_t(&mut c_o2, "device.recover_against_ended").await["reason"],
        "certified"
    );
    c_new.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_new, "directory").await;
    assert!(d["people"][0].get("recovery").is_none(), "{d}");
    // 걸기 메일 하나뿐(certified 는 메일 없음), 실행도 없음.
    assert_eq!(mail_subjects(&mail).await.len(), before + 1);
    h.fx.clock.advance(DAY_MS);
    h.app.expire_tick();
    assert!(h.app.db.device(&o2.device_id).unwrap().is_some());
}

/// 시험 7b 의 대상 하나: 지금 끊기(서명 + 자기 폐기) → 요청 기기가 뿌리 → certified, 그대로 끝.
#[tokio::test(flavor = "multi_thread")]
async fn recover_cut_self_with_single_target_ends_it() {
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    recv_t(&mut c_old, "device.recover_against").await;
    c_old
        .send(&json!({"t": "device.certify", "device_id": new.device_id, "sig": devcert(SERVER, &old, &new)}))
        .await;
    assert_eq!(
        recv_t(&mut c_new, "device.recover_canceled").await["reason"],
        "certified"
    );
    c_old.send(&json!({"t": "device.revoke"})).await;
    c_old.drain_until_closed().await;
    assert!(h.app.db.recovery("dana").unwrap().is_none());
}

/// 시험 10·11·12: 자격 있는 요청 기기·pending 나중 기기의 직접 끊기·요청 기기 폐기.
#[tokio::test(flavor = "multi_thread")]
async fn recover_edges_trusted_pending_revoke_and_requester_gone() {
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;
    // 10: 뿌리 기기는 trusted.
    c_old.send(&json!({"t": "device.recover"})).await;
    assert_eq!(
        refused(&recv_t(&mut c_old, "error").await).0,
        Some("trusted")
    );
    // 11: pending 나중 기기 → 먼저 기기 직접 끊기 = protocol(too_early 아님, 24h 뒤에도).
    h.fx.clock.advance(2 * DAY_MS);
    c_new
        .send(&json!({"t": "device.revoke", "device_id": old.device_id}))
        .await;
    let e = recv_t(&mut c_new, "error").await;
    assert_eq!(e["code"], "protocol", "{e}");
    assert!(h.app.db.device(&old.device_id).unwrap().is_some());
    // 12: 걸고 요청 기기가 스스로 폐기 → 걸기 지워지고 대상에 ended{canceled}.
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    recv_t(&mut c_old, "device.recover_against").await;
    c_new.send(&json!({"t": "device.revoke"})).await;
    c_new.drain_until_closed().await;
    assert_eq!(
        recv_t(&mut c_old, "device.recover_against_ended").await["reason"],
        "canceled"
    );
    assert!(h.app.db.recovery("dana").unwrap().is_none());
}

/// 시험 9·14: 실행과 막기가 겹치면 하나만(막기가 먼저면 실행 없음), 다시 띄운 relay 가 지난 걸기를 실행.
#[tokio::test(flavor = "multi_thread")]
async fn recover_block_vs_execute_and_restart() {
    let (h, mail) = start_hosted().await;
    let (old, new) = recovery_account(&h, &mail, 2).await;
    let mut c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    recv_t(&mut c_old, "device.recover_against").await;
    // at 이 지났지만 tick 전에 막기 → 막기가 이기고 tick 은 아무것도 안 한다.
    h.fx.clock.advance(DAY_MS + 1);
    c_old.send(&json!({"t": "device.recover_block"})).await;
    recv_t(&mut c_new, "device.recover_canceled").await;
    h.app.expire_tick();
    assert!(h.app.db.device(&old.device_id).unwrap().is_some());
    // 막힌 뒤에 실행은 없다(db 층에서도).
    assert!(h
        .app
        .db
        .recovery_execute("dana", h.fx.clock.now().0)
        .unwrap()
        .is_none());
}

/// 시험 13: `last_auth_at`·`recovery.targets` 는 내 항목에만, 동료는 state·at·requester 만.
#[tokio::test(flavor = "multi_thread")]
async fn recover_directory_fields_are_mine_only() {
    let h = start().await;
    let old = register(&h, "dana", 1).await;
    h.fx.clock.advance(1000);
    let new = register_extra_device(&h, "dana", 2).await;
    let bob = register(&h, "bob", 3).await;
    let _c_old = recovery_connect(&h, &old).await;
    let mut c_new = recovery_connect(&h, &new).await;
    let mut c_bob = recovery_connect(&h, &bob).await;
    c_new.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut c_new, "device.recover_scheduled").await;
    c_bob.send(&json!({"t": "directory.list"})).await;
    let d = recv_t(&mut c_bob, "directory").await;
    let people = d["people"].as_array().unwrap();
    let dana = people
        .iter()
        .find(|p| p["address"] == format!("dana@{SERVER}"))
        .unwrap();
    assert_eq!(dana["recovery"]["state"], "scheduled");
    assert_eq!(dana["recovery"]["requester"], new.device_id);
    assert!(
        dana["recovery"]
            .get("targets")
            .is_none_or(|t| t == &json!([])),
        "{dana}"
    );
    assert!(dana["devices"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d.get("last_auth_at").is_none()));
    let me = people
        .iter()
        .find(|p| p["address"] == format!("bob@{SERVER}"))
        .unwrap();
    assert!(me["devices"][0]["last_auth_at"].is_string(), "{me}");
}

/// §9 ②(v4.2): 끊긴 옛 기기 큐에만 있던 1:1 글 → 보낸 사람에게 status{failed, recipient_device_changed} → 같은 msg_id 로 다시
/// 보내면 멱등 ack 가 아니라 다시 받는다. 다른 기기가 받은 글·Handshake 는 알리지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn recover_done_reports_undelivered_messages_and_takes_resend() {
    // 글 보관(24h)보다 먼저 실행되게 시험 relay 만 대기를 줄인다.
    let h = start_with(|c| c.recovery_wait = Duration::from_secs(3600)).await;
    let old = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &old).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut b, &bob, &mut a, &old).await;
    // 옛 기기가 받은 글(알리지 않음)과 꺼진 뒤 쌓인 글(알림 대상).
    let got = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &old.address(),
        json!({}),
        "받음",
    );
    assert_eq!(send_answer(&mut b, &got).await["t"], "ack");
    assert_eq!(a.recv().await["message"]["msg_id"], got["msg_id"]);
    a.send(&json!({"t": "delivered_ack", "msg_id": mid(&got)}))
        .await;
    drop(a);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let lost = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &old.address(),
        json!({}),
        "못 받음",
    );
    assert_eq!(send_answer(&mut b, &lost).await["t"], "ack");
    b.drain().await;

    h.fx.clock.advance(1000);
    let new = register_extra_device(&h, "alice", 2).await;
    let mut n = recovery_connect(&h, &new).await;
    n.send(&json!({"t": "device.recover"})).await;
    recv_t(&mut n, "device.recover_scheduled").await;
    h.fx.clock.advance(3600 * 1000);
    h.app.expire_tick();
    recv_t(&mut n, "device.recovered").await;

    let s = recv_t(&mut b, "status").await;
    assert_eq!(s["msg_id"], lost["msg_id"], "{s}");
    assert_eq!(s["state"], "failed");
    assert_eq!(s["fail_reason"], "recipient_device_changed");
    b.drain().await;
    // 한 번만 알린다.
    h.app.expire_tick();
    b.expect_silence().await;

    // 새 잎이 생기기 전의 다시 보내기: 재생 ack 가 아니라 다시 받고, 받는 사람 기기가 아직 바뀌는 중이라 ack 뒤 다시 기기 바뀜
    // 실패(표시는 남는다 — 새 잎이 들면 또 다시 보낸다). 새 잎이 생긴 뒤 다시 받기는 relay-client 시험 16a 가 본다.
    let r = send_answer(&mut b, &lost).await;
    assert_eq!(r["t"], "ack", "{r}");
    let s = b.recv().await;
    assert_eq!(
        (
            s["t"].as_str(),
            s["msg_id"].as_str(),
            s["fail_reason"].as_str()
        ),
        (
            Some("status"),
            lost["msg_id"].as_str(),
            Some("recipient_device_changed")
        ),
        "{s}"
    );
    assert!(h.app.db.device_changed_has(&mid(&lost), "bob").unwrap());
    // 남이 같은 msg_id 를 써도 다시 받지 않는다.
    assert!(!h.app.db.device_changed_has(&mid(&lost), "alice").unwrap());

    // 설계 리뷰 🟡2: 끊긴 뒤·새 기기가 들기 전에 보낸 새 1:1 글 — unroutable 대신 ack, 그 뒤 기기 바뀜 실패(조용히 안 빠짐).
    let after = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &old.address(),
        json!({}),
        "끊긴 뒤",
    );
    let r = send_answer(&mut b, &after).await;
    assert_eq!(r["t"], "ack", "{r}");
    let s = b.recv().await;
    assert_eq!(
        (
            s["t"].as_str(),
            s["msg_id"].as_str(),
            s["state"].as_str(),
            s["fail_reason"].as_str()
        ),
        (
            Some("status"),
            after["msg_id"].as_str(),
            Some("failed"),
            Some("recipient_device_changed")
        ),
        "{s}"
    );
    b.expect_silence().await;
    // 기한이 지나면 표시도 지운다.
    h.fx.clock.advance(2 * DAY_MS);
    h.app.expire_tick();
    assert!(!h.app.db.device_changed_has(&mid(&after), "bob").unwrap());
}

/// 설계 리뷰 🟡2: 잎이 모두 끊긴 사람이 기기가 아예 없으면(마지막 기기 로그아웃) 기기 바뀜이 아니라 지금처럼 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn pair_message_to_fully_logged_out_user_stays_unroutable() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    pair(&h, &mut b, &bob, &mut a, &alice).await;
    a.send(&json!({"t": "device.revoke"})).await;
    a.drain_until_closed().await;
    b.drain().await;
    let m = msg(
        &h,
        &bob,
        &bob.address(),
        "chat",
        &alice.address(),
        json!({}),
        "없음",
    );
    let r = send_answer(&mut b, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["reason"].as_str()),
        (Some("nack"), Some("unroutable")),
        "{r}"
    );
    b.expect_silence().await;
    assert!(!h.app.db.device_changed_has(&mid(&m), "bob").unwrap());
}

/// #622: 자기 폐기 응답(device.revoked) 앞에 온 프레임에 앱이 답해 쓰는 동안에도 연결이 끊기지 않아 응답을 읽는다. relay 가
/// 응답을 큐에 넣자마자 닫으면 앱의 쓰기가 끊긴 연결에 막혀(RST) 버퍼에 와 있던 응답을 읽기 전에 연결을 버렸다 — 폐기는 됐는데
/// 앱은 Unreachable. relay 는 앱이 읽고 스스로 닫을 때까지(상한 REVOKED_LINGER) 연결을 둔다.
#[tokio::test(flavor = "multi_thread")]
async fn self_revoke_answer_survives_writes_after_request() {
    let h = start().await;
    let bob = register(&h, "bob", 2).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&json!({"t": "device.revoke"})).await;
    // 앱이 응답을 읽기 전에 앞 프레임에 답해 쓰는 꼴 — relay 가 폐기를 처리하고 난 뒤.
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..3 {
        b.ws.send(Message::Text(json!({"t": "ping"}).to_string().into()))
            .await
            .expect("응답을 읽기 전 쓰기가 끊긴 연결에 막힘");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = b.drain_until_closed_after_close().await;
    assert_eq!(
        got.first().map(|f| f["t"].clone()),
        Some(json!("device.revoked")),
        "{got:?}"
    );
}

/// #622 후속(설계 리뷰 6515564969): 조직 나가기도 요청한 연결에 device.revoked{by:left} 를 넣자마자 닫으면 같은 꼴로 앱이 응답을
/// 읽기 전에 연결을 버린다 — 요청한 연결은 앱이 읽고 닫을 때까지(상한 REVOKED_LINGER) 둔다.
#[tokio::test(flavor = "multi_thread")]
async fn member_leave_answer_survives_writes_after_request() {
    let (h, mail) = start_hosted().await;
    let p = hosted_org(&h, &mail, &["minji"]).await;
    let (mut m, _) = connect(&h, &p[1]).await;
    m.send(&json!({"t": "member.leave"})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..3 {
        m.ws.send(Message::Text(json!({"t": "ping"}).to_string().into()))
            .await
            .expect("응답을 읽기 전 쓰기가 끊긴 연결에 막힘");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = m.drain_until_closed_after_close().await;
    let first = got.first().cloned().unwrap_or_default();
    assert_eq!(
        (first["t"].clone(), first["by"].clone()),
        (json!("device.revoked"), json!("left")),
        "{got:?}"
    );
}
