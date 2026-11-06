//! 첨부(묶음 15 `docs/design/bundle-15-files.md` §2.8): 예약 상한·PUT 토큰·길이·임시 파일·send 묶기·blob.get 인가·GET 헤더·
//! 지우기(모두 받음·만료·거두기)·envelope_devices 수명·카나리아. 시간·ID·난수는 testkit 고정 구현, DB 는 파일(카나리아·조직 옮기기).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::blob::{blob_ct_len, seal_blob};
use lodelai_crypto::{encoding, sign_challenge, sign_message, DeviceKeys};
use lodelai_effects::{Clock, IdGen, UnixMillis};
use lodelai_protocol::constants as c;
use lodelai_relay::{bind_local, db::Db, serve, App, Config, Effects, Relay};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod common;
use common::mls_dev::{fake_app, pair_bodies};
use lodelai_relay_client::mls::pair_group_id;

const START_MS: i64 = 1_792_728_776_000;
const TOKEN: &str = "test-registration-token";
const SERVER: &str = "local";

struct Harness {
    app: App,
    addr: SocketAddr,
    fx: TestEffects,
    dir: tempfile::TempDir,
}

impl Harness {
    fn blob_dir(&self) -> PathBuf {
        self.dir.path().join("blobs")
    }
    fn db_path(&self) -> PathBuf {
        self.dir.path().join("relay.db")
    }
}

async fn start_with(tweak: impl FnOnce(&mut Config)) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("relay.db")).unwrap();
    let fx = TestEffects::new(START_MS, 7);
    let (listener, addr) = bind_local(0).await.unwrap();
    let mut config = Config::local(SERVER);
    config.presence_updates = false;
    // 예약을 수백 번 보내는 시험이 연결 단위 상한에 걸리지 않게.
    config.rate_per_sec = 10_000;
    config.rate_burst = 10_000;
    config.blob_dir = Some(dir.path().join("blobs"));
    config.blob_min_free = 0;
    tweak(&mut config);
    config.port = addr.port();
    config.registration_token = Some(TOKEN.into());
    let effects = Effects {
        clock: fx.clock.clone(),
        ids: fx.ids.clone(),
        rng: fx.rng.clone(),
    };
    let app = Relay::new(config, effects, db);
    tokio::spawn(serve(app.clone(), listener));
    Harness { app, addr, fx, dir }
}

async fn start() -> Harness {
    start_with(|_| {}).await
}

/// 최소 HTTP/1.1 클라이언트(바이트 본문). (상태 코드, 헤더 줄들, 본문)
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\n",
        addr.port(),
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    // 서버가 넘침으로 먼저 끊으면 쓰기가 실패할 수 있다 — 응답만 본다.
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("응답 머리");
    let head = String::from_utf8_lossy(&out[..split]).into_owned();
    let code = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (code, head, out[split + 4..].to_vec())
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

async fn register(h: &Harness, name: &str, seed: u8, existing: bool) -> User {
    let keys = DeviceKeys::generate(&[seed; 64]);
    let x = keys.exchange.public_key();
    let mut body = json!({
        "user": name,
        "device_pubkeys": {
            "ed25519": keys.signing.verifying_key().to_b64(),
            "x25519": encoding::encode(&x),
            "x25519_sig": lodelai_crypto::xkey::sign(&keys.signing, keys.device_id().as_str(), &x),
        },
        "display_name": name,
    });
    if existing {
        body["existing_user"] = json!(true);
    }
    let auth = format!("Bearer {TOKEN}");
    let (code, _, resp) = http(
        h.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&resp));
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

    async fn recv(&mut self) -> Value {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(3), self.ws.next())
                .await
                .expect("프레임 대기 시간 초과")
                .expect("연결 끊김")
                .unwrap();
            if let Message::Text(t) = m {
                let v: Value = serde_json::from_str(&t).unwrap();
                // 여기서 보지 않는 프레임(디렉터리 갱신·발신자 status)은 건너뛴다.
                if v["t"] != "directory.update" && v["t"] != "status" && v["t"] != "duty" {
                    return v;
                }
            }
        }
    }

    /// 디렉터리 갱신도 그대로 받는다(접속 표시 `presence` 만 건너뛴다).
    async fn recv_any(&mut self) -> Value {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(3), self.ws.next())
                .await
                .expect("프레임 대기 시간 초과")
                .expect("연결 끊김")
                .unwrap();
            if let Message::Text(t) = m {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["t"] != "presence" {
                    return v;
                }
            }
        }
    }

    async fn ask(&mut self, v: &Value) -> Value {
        self.send(v).await;
        self.recv().await
    }

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
            assert!(t.contains("directory.update"), "조용해야 하는데 받음: {t}");
        }
    }
}

async fn connect(h: &Harness, u: &User) -> Client {
    let (ws, _) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/v1/ws", h.addr.port()))
            .await
            .unwrap();
    let mut c = Client { ws };
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
    assert_eq!(c.recv().await["t"], "ready");
    c
}

fn now_str(h: &Harness, plus_ms: i64) -> String {
    UnixMillis(h.fx.clock.now().0 + plus_ms)
        .to_rfc3339()
        .unwrap()
}

/// 서명된 chat. `blobs` 가 비면 헤더를 싣지 않는다.
fn chat(h: &Harness, from: &User, to: &User, blobs: &[String], n: usize) -> Value {
    let id = h.fx.ids.next_ulid();
    let mut m = json!({
        "v": lodelai_protocol::MESSAGE_V_MAX,
        "msg_id": id,
        "thread_id": id,
        "kind": "chat",
        "from": {"address": from.address(), "author": "human", "device_id": from.device_id},
        "to": {"address": to.address()},
        "body": fake_app(&vec![0u8; n]),
        "mls_group": encoding::encode(&pair_group_id(&from.name, &to.name)), "epoch": 1,
        "created_at": now_str(h, 0),
        "expires_at": now_str(h, 24 * 3600 * 1000),
    });
    if !blobs.is_empty() {
        m["blobs"] = json!(blobs);
    }
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// `alice`·`bob` 의 pair 그룹을 세운다(묶음 22 — 1:1 도 MLS, #488). bob 의 기기 `devs`(첫째 = bob)를 모두 잎으로 넣고 — 둘째부터는
/// 첫 기기의 devcert 로 잎 자격 — 기기마다 잠깐 접속해 그 Commit 을 받아 끊는다(시험의 recv 순서를 흐리지 않게).
async fn pair_with(h: &Harness, a: &mut Client, alice: &User, devs: &[&User]) {
    let bob = devs[0];
    if devs.len() > 1 {
        let mut b = connect(h, bob).await;
        for d in &devs[1..] {
            let sig = lodelai_crypto::devcert::sign(
                &bob.keys.signing,
                &lodelai_crypto::devcert::Cert {
                    server: SERVER,
                    user: &bob.name,
                    device_id: &d.device_id,
                    x25519: &d.keys.exchange.public_key(),
                    signer: &bob.device_id,
                },
            );
            b.send(&json!({"t": "device.certify", "device_id": d.device_id, "sig": sig}))
                .await;
        }
        b.drain().await;
    }
    let keys: Vec<&DeviceKeys> = devs.iter().map(|d| &d.keys).collect();
    let (gid, start, commit) = pair_bodies(&alice.keys, &alice.name, &keys, &bob.name);
    let hs = |body: Value| {
        let id = h.fx.ids.next_ulid();
        let mut m = json!({
            "v": lodelai_protocol::MESSAGE_V_MAX,
            "msg_id": id, "thread_id": id, "kind": "mls",
            "from": {"address": alice.address(), "author": "human", "device_id": alice.device_id},
            "to": {"address": bob.address()},
            "mls_group": encoding::encode(&gid), "epoch": 0,
            "body": body,
            "created_at": now_str(h, 0),
            "expires_at": now_str(h, 24 * 3600 * 1000),
        });
        sign_message(&mut m, &alice.keys.signing).unwrap();
        m
    };
    assert_eq!(
        a.ask(&json!({"t": "send", "message": hs(start)})).await["t"],
        "ack",
        "pair start"
    );
    let m = hs(commit);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": m})).await["t"],
        "ack",
        "pair add"
    );
    for d in devs {
        let mut b = connect(h, d).await;
        loop {
            let f = b.recv().await;
            if f["message"]["msg_id"] == m["msg_id"] {
                break;
            }
        }
        b.send(&json!({"t": "delivered_ack", "msg_id": m["msg_id"]}))
            .await;
        b.drain().await;
    }
    a.drain().await;
}

async fn reserve(c: &mut Client, ct_len: u64, purpose: &str) -> Value {
    c.ask(&json!({"t": "blob.reserve", "req": "r1", "ct_len": ct_len, "purpose": purpose}))
        .await
}

async fn put(h: &Harness, blob_id: &str, token: &str, body: &[u8]) -> u16 {
    let auth = format!("Bearer {token}");
    http(
        h.addr,
        "PUT",
        &format!("/v1/blobs/{blob_id}"),
        &[("Authorization", &auth)],
        body,
    )
    .await
    .0
}

/// 예약 → 올림. (blob_id, 올린 바이트)
async fn upload(h: &Harness, c: &mut Client, data: &[u8]) -> String {
    let r = reserve(c, data.len() as u64, "message").await;
    assert_eq!(r["t"], "blob.reserved", "{r}");
    let id = r["blob_id"].as_str().unwrap().to_owned();
    assert_eq!(
        put(h, &id, r["put_token"].as_str().unwrap(), data).await,
        204
    );
    id
}

async fn fetch(h: &Harness, c: &mut Client, blob_id: &str) -> (u16, String, Vec<u8>) {
    let t = c
        .ask(&json!({"t": "blob.get", "req": "g1", "blob_id": blob_id}))
        .await;
    assert_eq!(t["t"], "blob.ticket", "{t}");
    let auth = format!("Bearer {}", t["get_token"].as_str().unwrap());
    http(
        h.addr,
        "GET",
        &format!("/v1/blobs/{blob_id}"),
        &[("Authorization", &auth)],
        b"",
    )
    .await
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                out.extend(files_under(&e.path()));
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

fn blob_file(h: &Harness, id: &str) -> PathBuf {
    h.blob_dir().join(&id[..2]).join(id)
}

// ------------------------------------------------------------------ 예약 상한

#[tokio::test(flavor = "multi_thread")]
async fn reserve_limits_size_quota_rate_and_disk() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let mut a = connect(&h, &alice).await;
    let max = blob_ct_len(c::FILE_MAX_BYTES);

    for (len, purpose) in [(max + 1, "message"), (c::AVATAR_MAX_BYTES + 1, "avatar")] {
        let r = reserve(&mut a, len, purpose).await;
        assert_eq!(
            (r["t"].as_str(), r["code"].as_str(), r["ref"].as_str()),
            (Some("error"), Some("protocol"), Some("r1"))
        );
    }
    // 합계: 상한까지 예약은 되고(올리지 않아도 센다), 넘는 한 건은 quota. 연결은 그대로.
    let per = max;
    let fits = c::BLOB_USER_PENDING_MAX_BYTES / per;
    for _ in 0..fits {
        assert_eq!(reserve(&mut a, per, "message").await["t"], "blob.reserved");
    }
    let r = reserve(&mut a, per, "message").await;
    assert_eq!(
        (r["code"].as_str(), r["ref"].as_str()),
        (Some("quota"), Some("r1"))
    );
    // 프로필 사진은 합계에 들지 않는다.
    assert_eq!(reserve(&mut a, 100, "avatar").await["t"], "blob.reserved");

    // 사진 시간당(묶음 27 #427): 사진만 AVATAR_RESERVE_PER_HOUR 번, 넘으면 rate_limited(연결은 유지).
    for _ in 1..c::AVATAR_RESERVE_PER_HOUR {
        assert_eq!(reserve(&mut a, 1, "avatar").await["t"], "blob.reserved");
    }
    let r = reserve(&mut a, 1, "avatar").await;
    assert_eq!(r["code"], "rate_limited", "{r}");
    a.send(&json!({"t": "directory.list"})).await;
    assert_eq!(a.recv().await["t"], "directory", "연결은 살아 있다");

    // 첨부 시간당: 사진 상한과 따로 센다 — 사진을 다 써도 첨부는 남은 만큼 된다.
    let carol = register(&h, "carol", 3, false).await;
    let mut cc = connect(&h, &carol).await;
    for _ in 0..c::AVATAR_RESERVE_PER_HOUR {
        assert_eq!(reserve(&mut cc, 1, "avatar").await["t"], "blob.reserved");
    }
    for _ in 0..c::BLOB_RESERVE_PER_HOUR {
        assert_eq!(reserve(&mut cc, 1, "message").await["t"], "blob.reserved");
    }
    let r = reserve(&mut cc, 1, "message").await;
    assert_eq!(r["code"], "rate_limited", "{r}");

    // 디스크 하한.
    let h2 = start_with(|c| c.blob_min_free = u64::MAX).await;
    let bob = register(&h2, "bob", 2, false).await;
    let mut b = connect(&h2, &bob).await;
    let r = reserve(&mut b, 10, "message").await;
    assert_eq!(
        (r["code"].as_str(), r["ref"].as_str()),
        (Some("storage_full"), Some("r1"))
    );
}

// ------------------------------------------------------------------ PUT

#[tokio::test(flavor = "multi_thread")]
async fn put_token_is_single_use_scoped_and_expires_and_length_is_exact() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let mut a = connect(&h, &alice).await;
    let data = vec![5u8; 1000];

    let r1 = reserve(&mut a, 1000, "message").await;
    let r2 = reserve(&mut a, 1000, "message").await;
    let (id1, t1) = (
        r1["blob_id"].as_str().unwrap(),
        r1["put_token"].as_str().unwrap(),
    );
    let (id2, t2) = (
        r2["blob_id"].as_str().unwrap(),
        r2["put_token"].as_str().unwrap(),
    );
    // 다른 blob 의 토큰·토큰 없음·모르는 id: 404.
    assert_eq!(put(&h, id2, t1, &data).await, 404);
    assert_eq!(
        http(h.addr, "PUT", &format!("/v1/blobs/{id1}"), &[], &data)
            .await
            .0,
        404
    );
    assert_eq!(put(&h, "AAAAAAAAAAAAAAAAAAAAAA", t1, &data).await, 404);
    // 넘침 413, 다시 쓰면 토큰은 이미 소진(404).
    assert_eq!(put(&h, id1, t1, &vec![5u8; 1001]).await, 413);
    assert_eq!(put(&h, id1, t1, &data).await, 404);
    // 모자람 400.
    assert_eq!(put(&h, id2, t2, &data[..999]).await, 400);
    // 임시 파일·자리 파일이 남지 않는다.
    assert!(
        files_under(&h.blob_dir()).is_empty(),
        "{:?}",
        files_under(&h.blob_dir())
    );

    // 만료: 10분 지난 토큰은 404.
    let r3 = reserve(&mut a, 1000, "message").await;
    h.fx.clock.advance(c::BLOB_PUT_TOKEN_TTL_S as i64 * 1000);
    assert_eq!(
        put(
            &h,
            r3["blob_id"].as_str().unwrap(),
            r3["put_token"].as_str().unwrap(),
            &data
        )
        .await,
        404
    );

    // 정상: 204, 파일은 0600, 폴더는 0700.
    let id = upload(&h, &mut a, &data).await;
    use std::os::unix::fs::PermissionsExt;
    let f = blob_file(&h, &id);
    assert_eq!(std::fs::read(&f).unwrap(), data);
    assert_eq!(
        std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(f.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

// ------------------------------------------------------------------ send 묶기

#[tokio::test(flavor = "multi_thread")]
async fn send_binds_only_own_uploaded_unbound_blobs() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let carol = register(&h, "carol", 3, false).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let mut cl = connect(&h, &carol).await;

    let mine = upload(&h, &mut a, b"ciphertext-a").await;
    let theirs = upload(&h, &mut cl, b"ciphertext-c").await;
    let pending = reserve(&mut a, 10, "message").await["blob_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let nack = |r: &Value| {
        (
            r["t"].as_str().map(str::to_owned),
            r["reason"].as_str().map(str::to_owned),
        )
    };
    let want = (Some("nack".to_owned()), Some("blob_unavailable".to_owned()));
    // 남의 것·안 올린 것·모르는 id.
    for b in [theirs.clone(), pending, "AAAAAAAAAAAAAAAAAAAAAA".into()] {
        let m = chat(&h, &alice, &bob, &[mine.clone(), b], 10);
        assert_eq!(
            nack(&a.ask(&json!({"t": "send", "message": m})).await),
            want
        );
    }
    // 실패한 send 는 아무것도 묶지 않았다 — 같은 것을 혼자 묶으면 된다. 두 번째 묶기는 거부.
    let m = chat(&h, &alice, &bob, std::slice::from_ref(&mine), 10);
    assert_eq!(a.ask(&json!({"t": "send", "message": m})).await["t"], "ack");
    let again = chat(&h, &alice, &bob, std::slice::from_ref(&mine), 10);
    assert_eq!(
        nack(&a.ask(&json!({"t": "send", "message": again})).await),
        want
    );

    // 형식: 중복·11개·system 에 blobs → error protocol(ref = msg_id).
    let one = upload(&h, &mut a, b"x").await;
    let dup = chat(&h, &alice, &bob, &[one.clone(), one.clone()], 10);
    let eleven: Vec<String> = (0..11).map(|i| format!("{i:A>22}")).collect();
    let too_many = chat(&h, &alice, &bob, &eleven, 10);
    for m in [dup, too_many] {
        let r = a.ask(&json!({"t": "send", "message": m})).await;
        assert_eq!(
            (r["t"].as_str(), r["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{r}"
        );
    }

    // 평문 상한: pt=json1 이면 kind 상한 + 1 KiB × 첨부 수까지.
    let two = [
        upload(&h, &mut a, b"1").await,
        upload(&h, &mut a, b"2").await,
    ];
    let at_cap = c::BODY_MAX_BYTES_CHAT as usize + 2 * c::FILE_ENTRY_MAX_BYTES as usize;
    let over = chat(&h, &alice, &bob, &two, at_cap + 1);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": over})).await["reason"],
        "too_large"
    );
    let ok = chat(&h, &alice, &bob, &two, at_cap);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": ok})).await["t"],
        "ack"
    );
}

// ------------------------------------------------------------------ blob.get·GET·지우기

#[tokio::test(flavor = "multi_thread")]
async fn get_is_for_recipient_devices_only_and_all_fetched_deletes() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let bob2 = register(&h, "bob", 3, true).await;
    let carol = register(&h, "carol", 4, false).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let mut b = connect(&h, &bob).await;
    let mut cl = connect(&h, &carol).await;

    let data = vec![42u8; 70_000];
    let id = upload(&h, &mut a, &data).await;
    let m = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": m.clone()})).await["t"],
        "ack"
    );
    assert_eq!(b.recv().await["t"], "deliver");
    // 본문은 모든 기기가 받아 지워져도 첨부 인가(envelope_devices)는 남는다.
    b.send(&json!({"t": "delivered_ack", "msg_id": m["msg_id"]}))
        .await;
    let mut b2 = connect(&h, &bob2).await;
    assert_eq!(b2.recv().await["t"], "deliver");
    b2.send(&json!({"t": "delivered_ack", "msg_id": m["msg_id"]}))
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 남(carol)·보낸 사람(alice)·모르는 id: 모두 같은 오류.
    let ask = |id: &str| json!({"t": "blob.get", "req": "g1", "blob_id": id});
    let unknown = cl.ask(&ask("AAAAAAAAAAAAAAAAAAAAAA")).await;
    assert_eq!(
        (unknown["code"].as_str(), unknown["ref"].as_str()),
        (Some("protocol"), Some("g1"))
    );
    assert_eq!(cl.ask(&ask(&id)).await, unknown);
    assert_eq!(a.ask(&ask(&id)).await, unknown);

    // 받는 기기: 표 → GET 200, 바이트 그대로, 헤더.
    let (code, head, body) = fetch(&h, &mut b, &id).await;
    assert_eq!(code, 200);
    assert_eq!(body, data);
    let head = head.to_ascii_lowercase();
    for want in [
        "content-type: application/octet-stream",
        "x-content-type-options: nosniff",
        "cache-control: no-store",
    ] {
        assert!(head.contains(want), "{head}");
    }
    // 표는 1회.
    let t = b.ask(&ask(&id)).await;
    let auth = format!("Bearer {}", t["get_token"].as_str().unwrap());
    let path = format!("/v1/blobs/{id}");
    assert_eq!(
        http(h.addr, "GET", &path, &[("Authorization", &auth)], b"")
            .await
            .0,
        200
    );
    assert_eq!(
        http(h.addr, "GET", &path, &[("Authorization", &auth)], b"")
            .await
            .0,
        404
    );
    // 다른 blob 경로에 쓴 표도 404.
    let t = b.ask(&ask(&id)).await;
    let auth = format!("Bearer {}", t["get_token"].as_str().unwrap());
    assert_eq!(
        http(
            h.addr,
            "GET",
            "/v1/blobs/AAAAAAAAAAAAAAAAAAAAAA",
            &[("Authorization", &auth)],
            b""
        )
        .await
        .0,
        404
    );

    // 받음 표시: 수신 기기 아닌 carol 은 무시, 한 기기만 받으면 남고, 둘 다 받으면 파일·행이 지워진다.
    cl.send(&json!({"t": "blob.fetched", "blob_id": id})).await;
    b.send(&json!({"t": "blob.fetched", "blob_id": id})).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(blob_file(&h, &id).exists());
    b2.send(&json!({"t": "blob.fetched", "blob_id": id})).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!blob_file(&h, &id).exists());
    assert!(!h.app.db.blob_known(&id).unwrap());
    let gone = b2.ask(&ask(&id)).await;
    assert_eq!(gone["code"], "protocol");
    cl.expect_silence().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_does_not_hold_blob_and_expiry_deletes() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let bob2 = register(&h, "bob", 3, true).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob, &bob2]).await;
    let mut b = connect(&h, &bob).await;

    let id = upload(&h, &mut a, b"held-by-revoked").await;
    let m = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    assert_eq!(a.ask(&json!({"t": "send", "message": m})).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    b.send(&json!({"t": "blob.fetched", "blob_id": id})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(blob_file(&h, &id).exists(), "둘째 기기가 아직");
    // 둘째 기기 폐기 → 청소에서 '모두 받음'.
    b.send(&json!({"t": "device.revoke", "device_id": bob2.device_id}))
        .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    h.app.expire_tick();
    assert!(!blob_file(&h, &id).exists());

    // 만료: 아무도 안 받아도 메시지 만료와 같이.
    let id2 = upload(&h, &mut a, b"expires").await;
    let m2 = chat(&h, &alice, &bob, std::slice::from_ref(&id2), 10);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": m2})).await["t"],
        "ack"
    );
    h.fx.clock.advance(24 * 3600 * 1000 + 1);
    h.app.expire_tick();
    assert!(!blob_file(&h, &id2).exists());
    assert!(!h.app.db.blob_known(&id2).unwrap());

    // 묶이지 않은 채 1시간 → 지움. 시작 안 한 예약은 토큰 만료로.
    let id3 = upload(&h, &mut a, b"never-sent").await;
    let r = reserve(&mut a, 5, "message").await;
    let id4 = r["blob_id"].as_str().unwrap().to_owned();
    h.fx.clock.advance(c::BLOB_PUT_TOKEN_TTL_S as i64 * 1000);
    h.app.expire_tick();
    assert!(!h.app.db.blob_known(&id4).unwrap());
    assert!(h.app.db.blob_known(&id3).unwrap());
    h.fx.clock.advance(c::BLOB_UNATTACHED_TTL_S as i64 * 1000);
    h.app.expire_tick();
    assert!(!blob_file(&h, &id3).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn withdraw_deletes_blobs_at_once() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let id = upload(&h, &mut a, b"oops").await;
    let x = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": x.clone()})).await["t"],
        "ack"
    );
    let wid = h.fx.ids.next_ulid();
    let mut w = json!({
        "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": wid, "thread_id": wid, "kind": "system",
        "from": {"address": alice.address(), "author": "human", "device_id": alice.device_id},
        "to": {"address": bob.address()}, "body": {"enc": "plain", "text": ""},
        "created_at": now_str(&h, 0), "expires_at": now_str(&h, 3600 * 1000),
        "reply_to": x["msg_id"], "reason": "withdrawn",
    });
    sign_message(&mut w, &alice.keys.signing).unwrap();
    assert_eq!(a.ask(&json!({"t": "send", "message": w})).await["t"], "ack");
    assert!(!blob_file(&h, &id).exists());
    assert!(!h.app.db.blob_known(&id).unwrap());
}

/// 리뷰 ①: blob PUT·GET 은 토큰이 인증이라 맞는 요청은 IP 상한(버스트 30)에 세지 않는다 — 로컬 relay 는 모두 127.0.0.1.
/// 토큰이 틀린 요청만 세어 넘으면 429.
#[tokio::test(flavor = "multi_thread")]
async fn blob_http_counts_only_bad_tokens_against_ip_limit() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let mut a = connect(&h, &alice).await;
    for i in 0..40u8 {
        let r = reserve(&mut a, 16, "message").await;
        let id = r["blob_id"].as_str().unwrap();
        assert_eq!(
            put(&h, id, r["put_token"].as_str().unwrap(), &[i; 16]).await,
            204,
            "{i}번째 맞는 PUT"
        );
    }
    let mut last = 0;
    for _ in 0..40 {
        last = put(&h, "AAAAAAAAAAAAAAAAAAAAAA", "nope", &[0; 16]).await;
    }
    assert_eq!(last, 429);
}

/// 리뷰 ⑥: 고친 글의 첨부를 묶을 수 없으면 원 메시지를 거두기 전에 blob_unavailable — 원문과 그 첨부는 그대로 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn edit_with_unbindable_blob_keeps_original() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let id = upload(&h, &mut a, b"first").await;
    let x = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    assert_eq!(
        a.ask(&json!({"t": "send", "message": x.clone()})).await["t"],
        "ack"
    );
    // 이미 x 에 묶인 blob 을 다시 쓰는 고침 — 묶을 수 없다.
    let mut e = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    e["edits"] = x["msg_id"].clone();
    sign_message(&mut e, &alice.keys.signing).unwrap();
    let r = a.ask(&json!({"t": "send", "message": e})).await;
    assert_eq!(
        (r["t"].as_str(), r["reason"].as_str()),
        (Some("nack"), Some("blob_unavailable")),
        "{r}"
    );
    assert!(blob_file(&h, &id).exists(), "원 메시지 첨부는 남는다");
    assert!(h.app.db.blob_known(&id).unwrap());
    let orig = h
        .app
        .db
        .header(x["msg_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_ne!(orig.env_state, "withdrawn", "원 메시지는 거두지 않았다");
}

// ------------------------------------------------------------------ 프로필 사진

async fn put_avatar(h: &Harness, u: &User, data: Vec<u8>) -> (u16, String) {
    let mut c = connect(h, u).await;
    let r = reserve(&mut c, data.len() as u64, "avatar").await;
    let id = r["blob_id"].as_str().unwrap().to_owned();
    (
        put(h, &id, r["put_token"].as_str().unwrap(), &data).await,
        id,
    )
}

fn png(side: u32, extra: usize) -> Vec<u8> {
    let mut p = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    p.extend_from_slice(b"IHDR");
    p.extend_from_slice(&side.to_be_bytes());
    p.extend_from_slice(&side.to_be_bytes());
    p.extend(std::iter::repeat_n(0u8, extra));
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn avatar_is_png_only_listed_and_same_org_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let mut a = connect(&h, &alice).await;
    let mut b = connect(&h, &bob).await;

    assert_eq!(put_avatar(&h, &alice, png(513, 10)).await.0, 400);
    // EXIF 조각이 든 PNG 는 받지 않는다(묶음 27 #427 — 앱은 다시 인코딩해 보낸다).
    let mut exif = png(256, 0);
    // IHDR 내용 나머지 5바이트 + CRC, 그다음 eXIf 조각.
    exif.extend_from_slice(&[0; 5]);
    exif.extend_from_slice(&[0, 0, 0, 0]);
    exif.extend_from_slice(&[0, 0, 0, 3]);
    exif.extend_from_slice(b"eXIf");
    exif.extend_from_slice(b"GPS");
    exif.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(put_avatar(&h, &alice, exif).await.0, 400);
    assert_eq!(
        put_avatar(&h, &alice, b"not a png at all, really not".to_vec())
            .await
            .0,
        400
    );
    let (code, first) = put_avatar(&h, &alice, png(256, 100)).await;
    assert_eq!(code, 204);
    let (_, second) = put_avatar(&h, &alice, png(256, 120)).await;
    assert!(!blob_file(&h, &first).exists(), "옛 사진은 지운다");

    a.send(&json!({"t": "directory.list"})).await;
    let d = a.recv().await;
    let me = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "alice@local")
        .unwrap();
    assert_eq!(me["avatar"], second.as_str());
    let (code, _, body) = fetch(&h, &mut b, &second).await;
    assert_eq!((code, body), (200, png(256, 120)));

    // 다른 조직으로 옮긴 사람은 못 받는다(모르는 id 와 같은 오류).
    let conn = rusqlite::Connection::open(h.db_path()).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.execute("UPDATE users SET org = 'other' WHERE user = 'bob'", [])
        .unwrap();
    let r = b
        .ask(&json!({"t": "blob.get", "req": "g1", "blob_id": second}))
        .await;
    assert_eq!(r["code"], "protocol");
}

/// `profile.update{avatar: null}`(묶음 15 §2): 지우면 디렉터리에서 빠지고 파일·행이 지워진다. 없을 때 지우기는 방송하지 않고,
/// null 이 아닌 값은 거절한다.
#[tokio::test(flavor = "multi_thread")]
async fn avatar_clear_removes_it_and_quiet_when_none() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let mut a = connect(&h, &alice).await;
    let mut b = connect(&h, &bob).await;
    let (code, id) = put_avatar(&h, &alice, png(256, 100)).await;
    assert_eq!(code, 204);
    assert_eq!(b.recv_any().await["t"], "directory.update");

    a.send(&json!({"t": "profile.update", "avatar": null}))
        .await;
    let d = b.recv_any().await;
    assert_eq!(d["t"], "directory.update");
    let her = d["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["address"] == "alice@local")
        .unwrap();
    assert!(her.get("avatar").is_none(), "{her}");
    assert!(!blob_file(&h, &id).exists());
    assert!(!h.app.db.blob_known(&id).unwrap());

    // 이미 없으면 방송하지 않는다 — 다음에 오는 것은 내가 부른 directory 다.
    a.send(&json!({"t": "profile.update", "avatar": null}))
        .await;
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(b.recv_any().await["t"], "directory");

    let r = a.ask(&json!({"t": "profile.update", "avatar": "x"})).await;
    assert_eq!(r["code"], "protocol");
}

// ------------------------------------------------------------------ 조직 사진(#554)

/// `register` 는 모두 같은 조직에 넣는다 — 그 조직의 행과 관리자를 만든다(조직 만들기 API 는 hosted 몫). 조직 id.
fn make_org(h: &Harness, admin: &str) -> String {
    let conn = rusqlite::Connection::open(h.db_path()).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    let org: String = conn
        .query_row("SELECT org FROM users WHERE user = ?1", [admin], |r| {
            r.get(0)
        })
        .unwrap();
    conn.execute(
        "INSERT INTO orgs(org_id, name, admin, created_ms) VALUES (?1, '루이보스', ?2, 0)",
        [&org, admin],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO org_admins(org_id, user) VALUES (?1, ?2)",
        [&org, admin],
    )
    .unwrap();
    org
}

async fn reserve_org(c: &mut Client, ct_len: u64, purpose: &str) -> Value {
    c.ask(&json!({"t": "blob.reserve", "req": "r1", "ct_len": ct_len, "purpose": purpose, "for": "org"}))
        .await
}

/// 조직 사진 예약 → 올림. (상태 코드, blob_id)
async fn put_org_avatar(h: &Harness, c: &mut Client, data: &[u8]) -> (u16, String) {
    let r = reserve_org(c, data.len() as u64, "avatar").await;
    assert_eq!(r["t"], "blob.reserved", "{r}");
    let id = r["blob_id"].as_str().unwrap().to_owned();
    (
        put(h, &id, r["put_token"].as_str().unwrap(), data).await,
        id,
    )
}

/// 다음 directory.update 의 조직 항목.
async fn next_org(c: &mut Client) -> Value {
    loop {
        let f = c.recv_any().await;
        if f["t"] == "directory.update" {
            return f["org"].clone();
        }
    }
}

/// #554 §1: 조직 사진은 관리자만 올리고(사람 사진과 같은 꼴 검사), 같은 조직에 directory.update 로 `org.avatar` 가 가며,
/// 같은 조직만 받는다. 바꾸면 옛 사진을 지우고, `org.update{avatar: null}` 은 관리자만·이미 없으면 조용하다.
#[tokio::test(flavor = "multi_thread")]
async fn org_avatar_admin_only_listed_same_org_and_clearable() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    make_org(&h, "alice");
    let mut a = connect(&h, &alice).await;
    let mut b = connect(&h, &bob).await;

    // 관리자 아님·사진 아님은 예약 단계에서 거절.
    let r = reserve_org(&mut b, 100, "avatar").await;
    assert_eq!(
        (r["code"].as_str(), r["ref"].as_str()),
        (Some("protocol"), Some("r1")),
        "{r}"
    );
    let r = reserve_org(&mut a, 100, "message").await;
    assert_eq!(r["code"], "protocol", "{r}");
    // 꼴 검사는 사람 사진과 같다.
    assert_eq!(put_org_avatar(&h, &mut a, &png(513, 10)).await.0, 400);
    let r = reserve_org(&mut a, c::AVATAR_MAX_BYTES + 1, "avatar").await;
    assert_eq!(r["code"], "protocol", "{r}");

    let (code, first) = put_org_avatar(&h, &mut a, &png(256, 100)).await;
    assert_eq!(code, 204);
    assert_eq!(next_org(&mut b).await["avatar"], first.as_str());
    let (code, second) = put_org_avatar(&h, &mut a, &png(256, 120)).await;
    assert_eq!(code, 204);
    assert_eq!(next_org(&mut b).await["avatar"], second.as_str());
    assert!(!blob_file(&h, &first).exists(), "옛 조직 사진은 지운다");
    assert!(!h.app.db.blob_known(&first).unwrap());
    // 사람 사진은 그대로 사람 것 — 조직 사진은 사람 항목에 실리지 않는다.
    b.send(&json!({"t": "directory.list"})).await;
    let d = b.recv().await;
    assert!(
        d["people"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p.get("avatar").is_none()),
        "{d}"
    );
    assert_eq!(d["org"]["avatar"], second.as_str());
    let (code, _, body) = fetch(&h, &mut b, &second).await;
    assert_eq!((code, body), (200, png(256, 120)));

    // 청소는 조직이 쓰는 사진을 지우지 않는다.
    let far = START_MS + 400 * 24 * 3_600_000;
    h.app.db.blob_sweep(far, 1).unwrap();
    assert!(h.app.db.blob_known(&second).unwrap());

    // 지우기: 관리자만, 형식은 avatar null 이나 name.
    assert_eq!(
        b.ask(&json!({"t": "org.update", "avatar": null})).await["code"],
        "protocol"
    );
    assert_eq!(
        a.ask(&json!({"t": "org.update", "avatar": "x"})).await["code"],
        "protocol"
    );
    assert_eq!(a.ask(&json!({"t": "org.update"})).await["code"], "protocol");
    b.drain().await;
    a.send(&json!({"t": "org.update", "avatar": null})).await;
    let org = next_org(&mut b).await;
    assert!(org.get("avatar").is_none(), "{org}");
    assert!(!blob_file(&h, &second).exists());
    assert!(!h.app.db.blob_known(&second).unwrap());
    // 이미 없으면 방송하지 않는다 — 다음에 오는 것은 내가 부른 directory 다.
    a.send(&json!({"t": "org.update", "avatar": null})).await;
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(b.recv_any().await["t"], "directory");

    // 다른 조직으로 옮긴 사람은 조직 사진을 못 받는다.
    let (code, third) = put_org_avatar(&h, &mut a, &png(256, 90)).await;
    assert_eq!(code, 204);
    let conn = rusqlite::Connection::open(h.db_path()).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.execute("UPDATE users SET org = 'other' WHERE user = 'bob'", [])
        .unwrap();
    let r = b
        .ask(&json!({"t": "blob.get", "req": "g1", "blob_id": third}))
        .await;
    assert_eq!(r["code"], "protocol");
}

/// #554 §1: 예약 뒤 관리자에서 내려가면 PUT 끝에서 403 — blob 은 지우고 조직 사진은 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn org_avatar_put_after_demotion_is_forbidden_and_dropped() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    make_org(&h, "alice");
    let mut a = connect(&h, &alice).await;
    let data = png(256, 100);
    let r = reserve_org(&mut a, data.len() as u64, "avatar").await;
    let id = r["blob_id"].as_str().unwrap().to_owned();
    let conn = rusqlite::Connection::open(h.db_path()).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    conn.execute("DELETE FROM org_admins WHERE user = 'alice'", [])
        .unwrap();
    assert_eq!(
        put(&h, &id, r["put_token"].as_str().unwrap(), &data).await,
        403
    );
    assert!(!h.app.db.blob_known(&id).unwrap());
    assert!(!blob_file(&h, &id).exists());
    let org = h.app.db.user_org("alice").unwrap().unwrap();
    assert_eq!(h.app.db.org_avatar(&org).unwrap(), None);
}

/// #554 §1: 조직 사진 예약은 사람 사진과 같은 시간당 상한을 함께 쓴다(사용자당 AVATAR_RESERVE_PER_HOUR).
#[tokio::test(flavor = "multi_thread")]
async fn org_avatar_shares_hourly_limit_with_person_avatar() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    make_org(&h, "alice");
    let mut a = connect(&h, &alice).await;
    let n = c::AVATAR_RESERVE_PER_HOUR;
    for i in 0..n {
        let r = if i % 2 == 0 {
            reserve(&mut a, 100, "avatar").await
        } else {
            reserve_org(&mut a, 100, "avatar").await
        };
        assert_eq!(r["t"], "blob.reserved", "{i}: {r}");
    }
    let r = reserve_org(&mut a, 100, "avatar").await;
    assert_eq!(r["code"], "rate_limited", "{r}");
}

// ------------------------------------------------------------------ 카나리아

#[tokio::test(flavor = "multi_thread")]
async fn canary_plaintext_never_reaches_relay_storage() {
    let h = start().await;
    let alice = register(&h, "alice", 1, false).await;
    let bob = register(&h, "bob", 2, false).await;
    let mut a = connect(&h, &alice).await;
    pair_with(&h, &mut a, &alice, &[&bob]).await;
    let marker = b"LODELAI-CANARY-7f3c9e-plaintext-file-body";
    let mut plain = marker.repeat(50);
    plain.extend_from_slice(marker);
    let r = reserve(&mut a, blob_ct_len(plain.len() as u64), "message").await;
    let id = r["blob_id"].as_str().unwrap().to_owned();
    let mut ct = Vec::new();
    seal_blob(&[3u8; 32], &[4u8; 19], &id, plain.as_slice(), &mut ct).unwrap();
    assert_eq!(
        put(&h, &id, r["put_token"].as_str().unwrap(), &ct).await,
        204
    );
    let m = chat(&h, &alice, &bob, std::slice::from_ref(&id), 10);
    assert_eq!(a.ask(&json!({"t": "send", "message": m})).await["t"], "ack");

    let mut stored = files_under(&h.blob_dir());
    stored.extend(
        files_under(h.dir.path())
            .into_iter()
            .filter(|p| !p.starts_with(h.blob_dir())),
    );
    assert!(!stored.is_empty());
    for f in stored {
        let bytes = std::fs::read(&f).unwrap();
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "평문이 {} 에 있다",
            f.display()
        );
    }
}
