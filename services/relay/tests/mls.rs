//! 묶음 22 MLS 전달 서비스(docs/design/bundle-22-mls.md) 시험 — 실제 openmls KeyPackage·그룹 바이트로 relay 를 두드린다.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::{encoding, sign_challenge, DeviceKeys};
use lodelai_relay::{bind_local, db::Db, serve, App, Config, Effects, Relay};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod common;
use common::mls_dev::{capabilities, data, Dev, DAYS};
use openmls_traits::OpenMlsProvider as _;

impl Dev {
    fn of(u: &User) -> Self {
        Self::new(&u.keys)
    }
}

const START_MS: i64 = 1_792_728_776_000; // 2026-10-23T04:12:56Z
const TOKEN: &str = "test-registration-token";
const SERVER: &str = "local";

struct Harness {
    app: App,
    addr: SocketAddr,
    fx: TestEffects,
    /// 조직 둘 픽스처용 파일 DB(`start_two_orgs`). 임시 폴더는 Harness 와 함께 지워진다.
    db_file: Option<(tempfile::TempDir, std::path::PathBuf)>,
    /// 시험마다 따로 둔 blob 폴더 — 기본값(pid·시계로 지은 임시 폴더)은 같은 프로세스의 시험끼리 겹쳐, 다른 시험이 시작하며
    /// `tmp` 를 비우면 올리기가 500 이 된다.
    _blobs: tempfile::TempDir,
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
    let blobs = tempfile::tempdir().unwrap();
    config.blob_dir = Some(blobs.path().to_path_buf());
    config.blob_min_free = 0;
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
        _blobs: blobs,
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

/// 조직 둘 + 그룹(#845 ④ 섞인 그룹).
async fn start_two_orgs_groups() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let db = Db::open(&path).unwrap();
    let mut h = start_db(|c| c.groups = true, db).await;
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
                // 판 16 접속 때 받침 low(#846, last_resort:false) — KeyPackage 를 안 올리는 시험 기기는 늘 받는다. 그 시험만 따로 본다.
                Message::Text(t) if is_backstop_low(&t) => {}
                Message::Text(t) => return t.to_string(),
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("예상 밖 프레임: {other:?}"),
            }
        }
    }

    async fn recv(&mut self) -> Value {
        serde_json::from_str(&self.recv_text().await).unwrap()
    }

    /// 짧게 기다려 아무 텍스트 프레임도 오지 않음을 확인.
    async fn expect_silence(&mut self) {
        while let Ok(Some(Ok(Message::Text(t)))) =
            tokio::time::timeout(Duration::from_millis(200), self.ws.next()).await
        {
            if is_backstop_low(&t) {
                continue;
            }
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

/// 핸드셰이크까지. `ready` 프레임을 돌려준다.
async fn connect(h: &Harness, u: &User) -> (Client, Value) {
    connect_with(h, u, json!({})).await
}

/// #870·#872: 내 기기끼리 글·own_stream 을 아는 기기(hello.own).
async fn connect_own(h: &Harness, u: &User) -> (Client, Value) {
    connect_with(h, u, json!({"own": true})).await
}

/// hello 에 칸을 더해 붙는다.
async fn connect_with(h: &Harness, u: &User, extra: Value) -> (Client, Value) {
    let mut c = Client {
        ws: ws_raw(h.addr).await,
    };
    let mut hello = json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": u.device_id, "user": u.name});
    for (k, v) in extra.as_object().unwrap() {
        hello[k] = v.clone();
    }
    c.send(&hello).await;
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

// ------------------------------------------------------------------ MLS 도우미

use lodelai_relay_client::mls::{DeviceSigner, CIPHERSUITE, EXT_LODELAI};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{CredentialType, ExtensionType, KeyPackage, Lifetime, MlsMessageOut};
use openmls_rust_crypto::OpenMlsRustCrypto;

/// 그 기기 키로 만든 KeyPackage(MLSMessage) base64url. `lifetime_s` 로 기간을 바꿀 수 있다.
fn kp(keys: &DeviceKeys, lifetime_s: u64, last_resort: bool) -> String {
    let provider = OpenMlsRustCrypto::default();
    let signer = DeviceSigner::new(keys.signing.clone());
    let mut b = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(lifetime_s))
        .leaf_node_capabilities(capabilities());
    if last_resort {
        b = b.mark_as_last_resort();
    }
    let bundle = b
        .build(CIPHERSUITE, &provider, &signer, signer.credential())
        .unwrap();
    let out = MlsMessageOut::from(bundle.key_package().clone());
    encoding::encode(&out.tls_serialize_detached().unwrap())
}

async fn publish_kps(c: &mut Client, items: Vec<String>, last_resort: Option<String>) {
    let mut f = json!({"t": "key_packages.publish", "items": items});
    if let Some(l) = last_resort {
        f["last_resort"] = json!(l);
    }
    c.send(&f).await;
}

/// 가져가기 답(자기 기기를 가져가면 같은 연결에 먼저 오는 key_packages.low 는 건너뜀).
async fn claim(c: &mut Client, ids: &[&str]) -> Value {
    c.send(&json!({"t": "key_packages.claim", "device_ids": ids}))
        .await;
    loop {
        let f = c.recv().await;
        if f["t"] != "key_packages.low" {
            return f;
        }
    }
}

// ------------------------------------------------------------------ §3 KeyPackage

/// 올리기·가져가기: 보통 것 먼저(가져가면 지움), 없으면 마지막 수단(남김). 남이 서명한·다른 기기 Credential·90일 넘는 lifetime
/// 은 프레임 전체 error{protocol}(아무것도 저장 안 함). 조직 밖·모르는 기기는 항목 없음(열거 없음).
#[tokio::test(flavor = "multi_thread")]
async fn key_packages_publish_claim_and_checks() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut e, _) = connect(&h, &erin).await;

    // 잘못된 것들 — 아무것도 저장되지 않는다.
    for (why, items) in [
        ("남의 기기 키", vec![kp(&alice.keys, 60 * DAYS, false)]),
        ("90일 넘음", vec![kp(&bob.keys, 91 * DAYS, false)]),
        ("꼴 아님", vec!["AAAA".to_owned()]),
        (
            "하나라도 틀리면 전체",
            vec![
                kp(&bob.keys, 60 * DAYS, false),
                kp(&alice.keys, 60 * DAYS, false),
            ],
        ),
    ] {
        publish_kps(&mut b, items, None).await;
        let r = b.recv().await;
        assert_eq!(
            (r["t"].as_str(), r["code"].as_str()),
            (Some("error"), Some("protocol")),
            "{why}"
        );
    }
    assert_eq!(h.app.db.kp_count(&bob.device_id).unwrap(), 0);

    // 보통 둘 + 마지막 수단.
    publish_kps(
        &mut b,
        vec![
            kp(&bob.keys, 60 * DAYS, false),
            kp(&bob.keys, 60 * DAYS, false),
        ],
        Some(kp(&bob.keys, 60 * DAYS, true)),
    )
    .await;
    b.expect_silence().await;
    assert_eq!(h.app.db.kp_count(&bob.device_id).unwrap(), 2);

    // 가져가기 셋: 보통 둘 다음 마지막 수단(남음). bob 에게는 남은 수가 20 아래라 low.
    for left in [1u64, 0, 0] {
        let r = claim(
            &mut a,
            &[&bob.device_id, "k1_AAAAAAAAAAAAAAAAAAAAAA", &erin.device_id],
        )
        .await;
        assert_eq!(r["t"], "key_packages", "{r}");
        let items = r["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "모르는·조직 밖 기기는 항목 없음: {r}");
        assert_eq!(items[0]["device_id"], bob.device_id.as_str());
        let low = b.recv().await;
        assert_eq!(
            (low["t"].as_str(), low["remaining"].as_u64()),
            (Some("key_packages.low"), Some(left))
        );
    }
    assert_eq!(h.app.db.kp_count(&bob.device_id).unwrap(), 0);
    // 조직 밖 사람은 가져갈 수 없다(빈 답).
    let r = claim(&mut e, &[&bob.device_id]).await;
    assert_eq!(r["items"], json!([]));
}

/// g025f B(0.2.5): 로컬 MLS 데이터를 잃고 같은 기기로 다시 붙은 기기의 첫 올리기는 `reset` — relay 에 남은 옛 것(그 기기가
/// 열 수 없음)을 지우고 바꾼다. `reset` 없이는 옛 것과 합쳐 상한을 넘어 거절되고 옛 것만 남는다(고치기 전 모습).
#[tokio::test(flavor = "multi_thread")]
async fn key_packages_publish_reset_replaces_old_ones() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let old: Vec<String> = (0..100).map(|_| kp(&bob.keys, 60 * DAYS, false)).collect();
    publish_kps(&mut b, old.clone(), Some(kp(&bob.keys, 60 * DAYS, true))).await;
    b.expect_silence().await;
    assert_eq!(h.app.db.kp_count(&bob.device_id).unwrap(), 100);

    let fresh: Vec<String> = (0..100).map(|_| kp(&bob.keys, 60 * DAYS, false)).collect();
    // reset 없이: 상한 — 아무것도 바뀌지 않는다.
    publish_kps(&mut b, fresh.clone(), Some(kp(&bob.keys, 60 * DAYS, true))).await;
    let r = b.recv().await;
    assert_eq!(r["message"], "key_packages.publish 상한", "{r}");
    // reset: 옛 것을 지우고 새 것만.
    let mut f = json!({"t": "key_packages.publish", "items": fresh.clone(), "reset": true});
    f["last_resort"] = json!(kp(&bob.keys, 60 * DAYS, true));
    b.send(&f).await;
    b.expect_silence().await;
    assert_eq!(h.app.db.kp_count(&bob.device_id).unwrap(), 100);
    let r = claim(&mut a, &[&bob.device_id]).await;
    let got = r["items"][0]["key_package"].as_str().unwrap().to_owned();
    assert!(fresh.contains(&got), "새 것을 내줘야 한다: {r}");
    assert!(!old.contains(&got));
}

/// g025f 리뷰 🟡: 나간 사람의 잎은 remove_user 전까지 남는다 — 그 사이 그 사람 새 기기의 add_device 가 60초 남아도 다시 들기 표시를
/// 주지 않는다. 지금 멤버면 준다(같은 장면의 대조).
#[tokio::test(flavor = "multi_thread")]
async fn 나간_사람_새_기기에는_다시_들기_표시를_주지_않는다() {
    let (h, path) = start_groups_file().await;
    let bob = register(&h, "bob", 2).await;
    // 표시는 접속한 후보에게만(a27ddf71c) — 새 기기가 붙어 있다.
    let (_b, _) = connect(&h, &bob).await;
    let c = rusqlite::Connection::open(&path).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    let marked = |gid: &str| -> i64 {
        c.query_row(
            "SELECT COUNT(*) FROM mls_rejoin WHERE group_id = ?1 AND device_id = ?2",
            rusqlite::params![gid, bob.device_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    let now = h.fx.clock.now().0;
    for (gid, left) in [("g-left", "5"), ("g-member", "NULL")] {
        c.execute_batch(&format!(
            "INSERT INTO groups(gid, org, seq, created_ms) VALUES ('{gid}', 'o', 5, 0);
             INSERT INTO group_members(gid, user, role, joined_seq, left_seq) VALUES ('{gid}', 'bob', 'member', 1, {left});
             INSERT INTO mls_leaves(group_id, device_id) VALUES ('{gid}', 'k1_old_bob_leaf');
             INSERT INTO mls_duties(group_id, task, subject, created_ms) VALUES ('{gid}', 'add_device', '{}', {now});",
            bob.device_id
        ))
        .unwrap();
    }
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert_eq!(marked("g-left"), 0, "나간 그룹엔 표시 없음");
    assert_eq!(marked("g-member"), 1, "멤버인 그룹엔 표시");
}

/// 소비 상한(§3): (가져가는 사람, 대상 기기) 하루 25(0.2.5, 예전 10) — 넘으면 error{rate_limited, until} 이고 아무것도 가져가지
/// 않는다. `until` = 가장 오래된 가져가기가 하루 창을 벗어나는 때. 주인은 예외.
#[tokio::test(flavor = "multi_thread")]
async fn key_package_claim_limits() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let items: Vec<String> = (0..40).map(|_| kp(&bob.keys, 60 * DAYS, false)).collect();
    publish_kps(&mut b, items, Some(kp(&bob.keys, 60 * DAYS, true))).await;
    b.expect_silence().await;
    let first = h.fx.clock.now().0;
    for _ in 0..25 {
        assert_eq!(
            claim(&mut a, &[&bob.device_id]).await["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    let r = claim(&mut a, &[&bob.device_id]).await;
    assert_eq!(
        (r["t"].as_str(), r["code"].as_str()),
        (Some("error"), Some("rate_limited")),
        "{r}"
    );
    assert_eq!(
        r["until"].as_str(),
        lodelai_effects::UnixMillis(first + 24 * 60 * 60 * 1000 + 1)
            .to_rfc3339()
            .ok()
            .as_deref(),
        "{r}"
    );
    assert_eq!(
        h.app.db.kp_count(&bob.device_id).unwrap(),
        15,
        "넘은 것은 가져가지 않음"
    );
    // 주인(bob 의 다른 기기 자리 — 같은 사용자)은 이 상한을 받지 않는다.
    for _ in 0..12 {
        assert_eq!(
            claim(&mut b, &[&bob.device_id]).await["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    // 하루 뒤 다시.
    h.fx.clock.advance(24 * 60 * 60 * 1000 + 1);
    assert_eq!(
        claim(&mut a, &[&bob.device_id]).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// 한 번이라도 올린 기기는 접속 때 남은 수가 20 아래면 low 를 받는다. #846 받침: 마지막 수단이 없는(첫 묶음이 처리되기 전에
/// 끊긴) 기기는 **다시 붙는** 판 16 이상 연결에만 low{0, last_resort:false} — (가) 처음 붙는 판 16 연결 없음(스스로 첫 묶음을
/// 올림) (나) 판 15 로 다시 붙기 없음 (다) 판 16 으로 다시 붙기 low{0,false}. (가)(나)는 받침을 건너뛰는 도우미가 아닌 날 프레임으로.
#[tokio::test(flavor = "multi_thread")]
async fn key_packages_low_on_connect_and_backstop_for_v16() {
    async fn raw_frames(c: &mut Client) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(Some(Ok(m))) =
            tokio::time::timeout(Duration::from_millis(300), c.ws.next()).await
        {
            if let Message::Text(t) = m {
                out.push(t.to_string());
            }
        }
        out
    }
    let h = start().await;
    let bob = register(&h, "bob", 2).await;
    // (가) 처음 붙는 판 16 연결.
    let (mut b, _) = connect(&h, &bob).await;
    let first = raw_frames(&mut b).await;
    assert!(
        !first.iter().any(|t| t.contains("key_packages.low")),
        "{first:?}"
    );
    drop(b);
    // (나) 판 15 로 다시 붙기.
    let mut old = connect_v(&h, &bob, 15).await;
    let v15 = raw_frames(&mut old).await;
    assert!(
        !v15.iter().any(|t| t.contains("key_packages.low")),
        "{v15:?}"
    );
    drop(old);
    // (다) 판 16 으로 다시 붙기.
    let (mut b, _) = connect(&h, &bob).await;
    let t = loop {
        match tokio::time::timeout(Duration::from_secs(3), b.ws.next())
            .await
            .expect("받침 low 가 와야 한다")
        {
            Some(Ok(Message::Text(t))) if t.contains("key_packages.low") => break t,
            Some(Ok(_)) => {}
            other => panic!("{other:?}"),
        }
    };
    let low: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(
        low,
        json!({"t": "key_packages.low", "remaining": 0, "last_resort": false}),
        "{low}"
    );
    b.expect_silence().await;
    publish_kps(
        &mut b,
        vec![kp(&bob.keys, 60 * DAYS, false)],
        Some(kp(&bob.keys, 60 * DAYS, true)),
    )
    .await;
    b.expect_silence().await;
    drop(b);
    let (mut b, _) = connect(&h, &bob).await;
    let low = b.recv().await;
    assert_eq!(
        (
            low["t"].as_str(),
            low["remaining"].as_u64(),
            low.get("last_resort")
        ),
        (Some("key_packages.low"), Some(1), None)
    );
}

// ------------------------------------------------------------------ §4·§6 그룹(pair·self)

use lodelai_crypto::sign_message;
use lodelai_relay_client::mls::{join_config, pair_group_id, self_group_id, Kind};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{
    MlsGroup, MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, StagedWelcome,
};

/// 서명한 MLS 메시지. `kind` 가 mls 면 Handshake, 그 밖은 응용.
/// 시험 글의 메시지 v — 반응(#626)은 `REACTION_V`, 그 밖은 판 10.
fn msg_v(kind: &str) -> u64 {
    if kind == "reaction" || kind.starts_with("own_") {
        lodelai_protocol::constants::REACTION_V
    } else {
        10
    }
}

fn mls_msg(
    h: &Harness,
    from: &User,
    to: &str,
    kind: &str,
    group: &[u8],
    epoch: u64,
    body: Value,
) -> Value {
    let id = h.fx.ids.next_ulid();
    let mut m = json!({
        "v": msg_v(kind), // 메시지 v 는 9·10(판 11 은 ws typing 만, #613) — 판 10 글(#598 ② 가르기 대상), 반응만 판 12(#626)
        "msg_id": id, "thread_id": id, "kind": kind,
        "from": {"address": from.address(), "author": "human", "device_id": from.device_id},
        "to": {"address": to},
        "mls_group": encoding::encode(group), "epoch": epoch,
        "body": body,
        "created_at": UnixMillis(h.fx.clock.now().0).to_rfc3339().unwrap(),
        "expires_at": UnixMillis(h.fx.clock.now().0 + 30 * 24 * 3600 * 1000).to_rfc3339().unwrap(),
    });
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

use lodelai_effects::{Clock, IdGen, UnixMillis};

async fn send(c: &mut Client, m: &Value) -> Value {
    c.send(&json!({"t": "send", "message": m})).await;
    loop {
        let f = c.recv().await;
        if f["t"] == "ack" || f["t"] == "nack" || f["t"] == "error" {
            return f;
        }
    }
}

/// alice 가 bob 과 pair 를 만든다: start → bob KeyPackage 로 Add commit(+welcome). (alice 그룹, bob Dev 의 Welcome 메시지)
async fn make_pair(
    h: &Harness,
    a: &mut Client,
    alice: &User,
    ad: &Dev,
    bob: &User,
    bd: &Dev,
) -> (MlsGroup, Value) {
    let gid = pair_group_id(&alice.name, &bob.name);
    let mut g = ad.create(Kind::Pair, &gid);
    let start = mls_msg(
        h,
        alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
    );
    let r = send(a, &start).await;
    assert_eq!(r["t"], "ack", "{r}");
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[bd.key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = mls_msg(
        h,
        alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
    );
    assert_eq!(send(a, &m).await["t"], "ack", "add commit");
    (g, m)
}

/// pair 만들기 → Add commit 의 welcome 으로 bob 이 들어오고 → 응용 메시지가 bob 의 잎에 가서 풀린다.
#[tokio::test(flavor = "multi_thread")]
async fn pair_start_add_and_app_round_trip() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    // 보낸 기기에는 자기 Commit 이 되돌아가지 않는다 — 돌아가면 처리 실패(openmls)가 다시 들어가기로 번진다(h4 리뷰 🟡).
    a.expect_silence().await;
    // bob 은 Add commit 을 받는다(보낸 그대로 — welcome 칸으로 들어옴).
    let d = b.recv().await;
    assert_eq!(d["t"], "deliver", "{d}");
    let w = encoding::decode(
        d["message"]["body"]["welcome"]["data"].as_str().unwrap(),
        "w",
    )
    .unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(w.as_slice())
        .unwrap()
        .extract()
    else {
        panic!("welcome 아님")
    };
    let mut bg = StagedWelcome::new_from_welcome(&bd.provider, &join_config(), welcome, None)
        .unwrap()
        .into_group(&bd.provider)
        .unwrap();
    // 응용 메시지 alice → bob(epoch 1).
    let gid = pair_group_id(&alice.name, &bob.name);
    let ct = g
        .create_message(&ad.provider, &ad.signer, b"hello")
        .unwrap();
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "chat",
        &gid,
        1,
        json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    a.expect_silence().await;
    let d = b.recv().await;
    let p = encoding::decode(
        d["message"]["body"]["payload"]["data"].as_str().unwrap(),
        "p",
    )
    .unwrap();
    let pm = MlsMessageIn::tls_deserialize_exact(p.as_slice())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(app) =
        bg.process_message(&bd.provider, pm).unwrap().into_content()
    else {
        panic!("응용 메시지 아님")
    };
    assert_eq!(app.into_bytes(), b"hello");
    // 미래 epoch·지난 창 밖은 stale_epoch.
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "chat",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "stale_epoch");
}

/// start 는 한 번만(epoch_taken), id 가 보낸·받는 사람으로 계산한 것과 다르면 unroutable, 잎이 보낸 기기가 아니면 invalid_commit.
#[tokio::test(flavor = "multi_thread")]
async fn start_rules() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let ad = Dev::of(&alice);
    let gid = pair_group_id(&alice.name, &bob.name);
    let g = ad.create(Kind::Pair, &gid);
    let body = json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))});
    // 다른 pair id(alice·carol)로 alice→bob 은 unroutable.
    let wrong = pair_group_id(&alice.name, &carol.name);
    let wg = ad.create(Kind::Pair, &wrong);
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &wrong,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&wg))}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "unroutable");
    // alice 의 GroupInfo 를 bob 이 자기 start 로(잎 ≠ 보낸 기기) → invalid_commit.
    let m = mls_msg(&h, &bob, &alice.address(), "mls", &gid, 0, body.clone());
    assert_eq!(send(&mut b, &m).await["reason"], "invalid_commit");
    assert_eq!(
        send(
            &mut a,
            &mls_msg(&h, &alice, &bob.address(), "mls", &gid, 0, body.clone())
        )
        .await["t"],
        "ack"
    );
    assert_eq!(
        send(
            &mut a,
            &mls_msg(&h, &alice, &bob.address(), "mls", &gid, 0, body)
        )
        .await["reason"],
        "epoch_taken"
    );
    // self 그룹(나 → 나).
    let sid = self_group_id(&alice.name);
    let sg = ad.create(Kind::SelfDevices, &sid);
    let m = mls_msg(
        &h,
        &alice,
        &alice.address(),
        "mls",
        &sid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&sg))}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
}

/// Commit 검사: 지난 epoch 는 stale_epoch, 남의 잎 Commit 을 자기 연결로 밀어 넣으면 invalid_commit, pair 밖 사람의 기기 Add 는
/// invalid_commit, Add 가 있는데 welcome 이 없으면 invalid_commit.
#[tokio::test(flavor = "multi_thread")]
async fn commit_rules() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let gid = pair_group_id(&alice.name, &bob.name);
    let mut g = ad.create(Kind::Pair, &gid);
    let start = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
    );
    assert_eq!(send(&mut a, &start).await["t"], "ack");

    // carol(pair 밖) Add.
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[cd.key_package()])
        .unwrap();
    let body = |c: &openmls::prelude::MlsMessageOut,
                w: Option<&openmls::prelude::MlsMessageOut>,
                gi: Vec<u8>| {
        let mut b = json!({"enc": "mls", "wire": "commit",
            "payload": data(&c.tls_serialize_detached().unwrap()), "group_info": data(&gi)});
        if let Some(w) = w {
            b["welcome"] = data(&w.tls_serialize_detached().unwrap());
        }
        b
    };
    let gi0 = ad.group_info(&g);
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        body(&commit, Some(&welcome), gi0.clone()),
    );
    assert_eq!(
        send(&mut a, &m).await["reason"],
        "invalid_commit",
        "pair 밖 Add"
    );
    g.clear_pending_commit(ad.provider.storage()).unwrap();

    // bob Add 인데 welcome 칸 없음.
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[bd.key_package()])
        .unwrap();
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        body(&commit, None, gi0.clone()),
    );
    assert_eq!(
        send(&mut a, &m).await["reason"],
        "invalid_commit",
        "welcome 없음"
    );
    // 같은 Commit 을 bob 이 자기 연결로(보낸 잎 ≠ 인증 기기).
    let m = mls_msg(
        &h,
        &bob,
        &alice.address(),
        "mls",
        &gid,
        0,
        body(&commit, Some(&welcome), gi0.clone()),
    );
    assert_eq!(
        send(&mut b, &m).await["reason"],
        "invalid_commit",
        "남의 잎"
    );
    // 지난 epoch 헤더.
    g.merge_pending_commit(&ad.provider).unwrap();
    let gi1 = ad.group_info(&g);
    let ok = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        body(&commit, Some(&welcome), gi1.clone()),
    );
    assert_eq!(send(&mut a, &ok).await["t"], "ack");
    let again = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        body(&commit, Some(&welcome), gi1),
    );
    assert_eq!(send(&mut a, &again).await["reason"], "stale_epoch");
}

// ------------------------------------------------------------------ §5a Handshake 보관 상한·30일·rejoin_needed

use openmls::prelude::LeafNodeParameters;

/// alice 의 self update Commit 하나(epoch 하나 올림).
async fn self_update(
    h: &Harness,
    a: &mut Client,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    to: &str,
    gid: &[u8],
) {
    let epoch = g.epoch().as_u64();
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = mls_msg(
        h,
        alice,
        to,
        "mls",
        gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(g)),
        }),
    );
    assert_eq!(send(a, &m).await["t"], "ack", "self update");
}

/// 접속 직후 프레임 하나 — rejoin_needed 면 그 그룹들.
async fn rejoin_groups(c: &mut Client) -> Vec<String> {
    let f = c.recv().await;
    assert_eq!(f["t"], "rejoin_needed", "{f}");
    f["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap().to_owned())
        .collect()
}

/// 상한(시험은 2개)을 넘으면 그 그룹을 비우고 접속 때 rejoin_needed. 표시가 있는 동안 새 Handshake 는 쌓지 않고,
/// external commit 으로 다시 잎이 되면 표시가 지워진다.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_cap_evicts_group_until_rejoin() {
    let h = start_with(|c| c.handshake_cap.count = 2).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    // bob 은 꺼져 있다: Add commit + self update 둘 = 셋 → 상한 2 를 넘어 그 그룹이 비워진다.
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    self_update(&h, &mut a, &alice, &ad, &mut g, &bob.address(), &gid).await;
    assert_eq!(
        h.app.db.pending_for("bob", &bob.device_id).unwrap().len(),
        2
    );
    self_update(&h, &mut a, &alice, &ad, &mut g, &bob.address(), &gid).await;
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());
    // 접속하면 rejoin_needed{그 그룹}, 비운 Handshake 는 오지 않는다.
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 0);
    assert_eq!(rejoin_groups(&mut b).await, vec![encoding::encode(&gid)]);
    b.expect_silence().await;
    // 표시가 있는 동안 새 Handshake 는 bob 에 쌓지도 보내지도 않는다.
    self_update(&h, &mut a, &alice, &ad, &mut g, &bob.address(), &gid).await;
    b.expect_silence().await;
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());
    // bob 이 최신 GroupInfo 로 external commit(옛 잎은 openmls 가 같은 서명 키로 찾아 뺀다).
    let gi = MlsMessageIn::tls_deserialize_exact(ad.group_info(&g).as_slice()).unwrap();
    let MlsMessageBodyIn::GroupInfo(vgi) = gi.extract() else {
        panic!("group info 아님")
    };
    let bd2 = Dev::of(&bob);
    let epoch = g.epoch().as_u64();
    let (bg, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .build_group(&bd2.provider, vgi, bd2.signer.credential())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(bd2.provider.storage())
        .unwrap()
        .build(
            bd2.provider.rand(),
            bd2.provider.crypto(),
            &bd2.signer,
            |_| true,
        )
        .unwrap()
        .finalize(&bd2.provider)
        .unwrap();
    let m = mls_msg(
        &h,
        &bob,
        &alice.address(),
        "mls",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&bd2.group_info(&bg)),
        }),
    );
    assert_eq!(send(&mut b, &m).await["t"], "ack", "external commit");
    assert_eq!(a.recv().await["t"], "deliver");
    // 다시 잎이 됐으니 다음 접속엔 rejoin_needed 가 없다.
    drop(b);
    let (mut b, _) = connect(&h, &bob).await;
    b.expect_silence().await;
    assert!(h.app.db.rejoin_for(&bob.device_id).unwrap().is_empty());
}

/// 바이트 상한: 넘는 Handshake 하나로도 그 그룹이 비워지고, 접속해 있으면 바로 rejoin_needed.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_byte_cap_marks_online_device_at_once() {
    let h = start_with(|c| c.handshake_cap.bytes = 1).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    assert_eq!(rejoin_groups(&mut b).await, vec![encoding::encode(&gid)]);
    b.expect_silence().await;
}

/// Handshake 는 7일 만료 작업 밖이고, 30일(relay 가 받은 시각 기준)이 지나면 받지 않은 기기에 rejoin_needed.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_kept_past_7_days_then_rejoin_at_30() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    h.fx.clock.advance((7 * DAYS * 1000 + 1) as i64);
    h.app.expire_tick();
    let (b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 1, "7일 뒤에도 Add commit 이 남는다");
    drop(b);
    h.fx.clock.advance((23 * DAYS * 1000) as i64);
    h.app.expire_tick();
    assert!(h
        .app
        .db
        .pending_for("bob", &bob.device_id)
        .unwrap()
        .is_empty());
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 0);
    assert_eq!(rejoin_groups(&mut b).await, vec![encoding::encode(&gid)]);
    // alice 에게 status expired 는 없다(상태기계를 거치지 않음).
    a.expect_silence().await;
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

/// 배달은 잎 목록뿐(§5d·§12-12): 잎 아닌 내 다른 기기·상대의 잎 아닌 기기엔 아무 프레임도 안 가고, 받을 잎이 하나도
/// 없으면(여기선 바이트 상한으로 유일한 잎이 비워짐) 봉투를 저장하지 않고 보낸 쪽엔 ack 만.
#[tokio::test(flavor = "multi_thread")]
async fn only_leaves_get_mls_frames() {
    let h = start_with(|c| c.handshake_cap.bytes = 1).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let bob2 = register_extra_device(&h, "bob", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    let (mut b2, _) = connect(&h, &bob2).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (mut g, add) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    // Add commit 의 유일한 대상(bob)은 상한으로 비워졌다 → 저장 없음, bob 은 rejoin_needed 만.
    assert_eq!(rejoin_groups(&mut b).await, vec![encoding::encode(&gid)]);
    assert!(h
        .app
        .db
        .header(add["msg_id"].as_str().unwrap())
        .unwrap()
        .is_none());
    for d in [&alice2, &bob2] {
        assert!(h
            .app
            .db
            .pending_for(&d.name, &d.device_id)
            .unwrap()
            .is_empty());
    }
    // 응용 메시지는 bob 의 잎에만(relay 트리에선 bob 이 잎).
    let ct = g.create_message(&ad.provider, &ad.signer, b"hi").unwrap();
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "chat",
        &gid,
        1,
        json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert_eq!(b.recv().await["t"], "deliver");
    a2.expect_silence().await;
    b2.expect_silence().await;
}

async fn group_info_get(c: &mut Client, group: &str) -> Value {
    c.send(&json!({"t": "group_info.get", "group": group}))
        .await;
    next_of(c, "group_info").await
}

/// §5b group_info.get: 멤버 사용자(pair 의 두 사람)의 기기는 최신 GroupInfo, 멤버 아닌 사람·없는 그룹은 group 만(같은 모양).
#[tokio::test(flavor = "multi_thread")]
async fn group_info_get_members_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = encoding::encode(&pair_group_id(&alice.name, &bob.name));
    let (g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await; // Add commit
    let want = encoding::encode(&ad.group_info(&g));
    for cl in [&mut a, &mut b] {
        let f = group_info_get(cl, &gid).await;
        assert_eq!(f["epoch"], 1, "{f}");
        assert_eq!(f["group_info"]["data"], want.as_str());
    }
    // 멤버 아님·없는 그룹: 같은 모양(group 만).
    assert_eq!(
        group_info_get(&mut c, &gid).await,
        json!({"t": "group_info", "group": gid})
    );
    let none = encoding::encode(&pair_group_id("carol", "dave"));
    assert_eq!(
        group_info_get(&mut c, &none).await,
        json!({"t": "group_info", "group": none})
    );
    assert_eq!(
        group_info_get(&mut a, &none).await,
        json!({"t": "group_info", "group": none})
    );
}

// ------------------------------------------------------------------ §7 duty

fn devcert(signer: &User, target: &User) -> String {
    lodelai_crypto::devcert::sign(
        &signer.keys.signing,
        &lodelai_crypto::devcert::Cert {
            server: SERVER,
            user: &signer.name,
            device_id: &target.device_id,
            x25519: &target.keys.exchange.public_key(),
            signer: &signer.device_id,
        },
    )
}

/// `signer` 기기가 `target` 기기에 devcert(승인, #846) — 서명한 기기에 directory.update 가 올 때까지.
async fn certify(c: &mut Client, signer: &User, target: &User) {
    c.send(&json!({"t": "device.certify", "device_id": target.device_id, "sig": devcert(signer, target)}))
        .await;
    next_of(c, "directory.update").await;
}

/// 그 종류 프레임이 올 때까지(다른 프레임은 넘김).
async fn next_of(c: &mut Client, t: &str) -> Value {
    loop {
        let f = c.recv().await;
        if f["t"] == t {
            return f;
        }
    }
}

/// alice 의 Commit 하나(Add 면 welcome 도).
#[allow(clippy::too_many_arguments)]
async fn alice_commit(
    h: &Harness,
    a: &mut Client,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    to: &str,
    commit: &MlsMessageOut,
    welcome: Option<&MlsMessageOut>,
    merge: bool,
) -> Value {
    let gid = g.group_id().as_slice().to_vec();
    let epoch = g.epoch().as_u64();
    let mut body = json!({
        "enc": "mls", "wire": "commit",
        "payload": data(&commit.tls_serialize_detached().unwrap()),
    });
    if let Some(w) = welcome {
        body["welcome"] = data(&w.tls_serialize_detached().unwrap());
    }
    // GroupInfo 는 새 epoch 것 — 보내기 전에 합쳐 본 그룹에서(거절될 Commit 은 합치지 않고 지금 것을 싣는다).
    if merge {
        g.merge_pending_commit(&ad.provider).unwrap();
    }
    body["group_info"] = data(&ad.group_info(g));
    let m = mls_msg(h, alice, to, "mls", &gid, epoch, body);
    send(a, &m).await
}

/// devcert 로 새로 잎 자격을 얻은 기기 → 내 다른 잎(접속)에 add_device. duty 는 권한이 아니다(그 기기의 Commit 도 §4 그대로).
/// 폐기 → 남은 잎에 remove_device, 나중에 접속한 후보는 rank = 접속한 다른 후보 수. 다 되면(잎 됨·빠짐) 일이 지워진다.
#[tokio::test(flavor = "multi_thread")]
async fn duties_add_and_remove_device() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let alice3 = register_extra_device(&h, "alice", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = encoding::encode(&pair_group_id(&alice.name, &bob.name));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;

    // a1 이 a2 에 devcert → a1 에 add_device(후보는 alice 의 다른 잎 a1 하나 → rank 0). bob 은 후보가 아니다.
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    let d = next_of(&mut a, "duty").await;
    assert_eq!(
        d,
        json!({"t": "duty", "group": gid, "task": "add_device", "subject": alice2.device_id, "rank": 0})
    );
    // duty 는 권한이 아니다: devcert 없는 a3 를 들이는 Commit 은 invalid_commit.
    let (c3, w3, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice3).key_package()])
        .unwrap();
    let r = alice_commit(
        &h,
        &mut a,
        &alice,
        &ad,
        &mut g,
        &bob.address(),
        &c3,
        Some(&w3),
        false,
    )
    .await;
    assert_eq!(r["reason"], "invalid_commit", "{r}");
    g.clear_pending_commit(ad.provider.storage()).unwrap();
    // a2 를 들이면 일이 끝난다 — 다시 접속해도 duty 없음.
    let (c2, w2, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice2).key_package()])
        .unwrap();
    let r = alice_commit(
        &h,
        &mut a,
        &alice,
        &ad,
        &mut g,
        &bob.address(),
        &c2,
        Some(&w2),
        true,
    )
    .await;
    assert_eq!(r["t"], "ack", "{r}");
    assert!(h.app.db.duties().unwrap().is_empty());

    // bob 은 꺼 두고 a2 가 스스로 폐기 → 접속한 남은 잎 a1 이 rank 0.
    drop(b);
    let (mut a2c, _) = connect(&h, &alice2).await;
    a2c.send(&json!({"t": "device.revoke"})).await;
    let d = next_of(&mut a, "duty").await;
    assert_eq!(
        d,
        json!({"t": "duty", "group": gid, "task": "remove_device", "subject": alice2.device_id, "rank": 0})
    );
    // bob 이 나중에 접속 → rank 1(접속한 다른 후보 a1 하나).
    let (mut b, _) = connect(&h, &bob).await;
    assert_eq!(next_of(&mut b, "duty").await["rank"], 1);
    // a1 이 다시 접속하면 같은 자리(0)로 다시 받는다.
    drop(a);
    let (mut a, _) = connect(&h, &alice).await;
    assert_eq!(next_of(&mut a, "duty").await["rank"], 0);
    // a1 이 a2 의 잎을 빼면 일이 끝난다.
    let idx = g
        .members()
        .find(|m| {
            openmls::prelude::BasicCredential::try_from(m.credential.clone())
                .unwrap()
                .identity()
                == alice2.device_id.as_bytes()
        })
        .unwrap()
        .index;
    let (rc, _, _) = g.remove_members(&ad.provider, &ad.signer, &[idx]).unwrap();
    let r = alice_commit(
        &h,
        &mut a,
        &alice,
        &ad,
        &mut g,
        &bob.address(),
        &rc,
        None,
        true,
    )
    .await;
    assert_eq!(r["t"], "ack", "{r}");
    assert!(h.app.db.duties().unwrap().is_empty());
}

// ------------------------------------------------------------------ §12-11 ⓐ devrevoke·§2b 3 뿌리 그래프

/// #863: 승인(devcert) 때 새 기기에 KeyPackage 가 없어 후보가 add_device 를 못 했다 — 그 기기가 처음 KeyPackage 를 올리면 이미
/// 받은 접속 후보에게 같은 rank 로 다시 간다(후보가 다시 붙기를 기다리지 않음). 이미 있는 기기가 더 올릴 때는 다시 가지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn late_first_key_packages_resend_add_duty_to_ranked_candidate() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = encoding::encode(&pair_group_id(&alice.name, &bob.name));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;

    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    let want = json!({"t": "duty", "group": gid, "task": "add_device", "subject": alice2.device_id, "rank": 0});
    assert_eq!(next_of(&mut a, "duty").await, want);
    assert_eq!(h.app.db.kp_state(&alice2.device_id).unwrap(), (0, false));

    // 새 기기가 늦게 붙어 처음 올린다 → a1 에 같은 일이 다시(a1 은 다시 붙지 않았다).
    let (mut a2c, _) = connect(&h, &alice2).await;
    publish_kps(
        &mut a2c,
        vec![kp(&alice2.keys, 3600, false)],
        Some(kp(&alice2.keys, 3600, true)),
    )
    .await;
    let again = tokio::time::timeout(Duration::from_secs(5), next_of(&mut a, "duty"))
        .await
        .expect("처음 올린 KeyPackage 뒤 a1 에 일이 다시 와야 한다");
    assert_eq!(again, want);

    // 이미 있는 기기가 더 올리면 다시 가지 않는다.
    publish_kps(&mut a2c, vec![kp(&alice2.keys, 3600, false)], None).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), next_of(&mut a, "duty"))
            .await
            .is_err(),
        "KeyPackage 가 이미 있으면 다시 보내지 않는다"
    );

    // 다시 받은 일로 a2 를 들이면 잎이 되고 일이 끝난다.
    let (c2, w2, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice2).key_package()])
        .unwrap();
    let r = alice_commit(
        &h,
        &mut a,
        &alice,
        &ad,
        &mut g,
        &bob.address(),
        &c2,
        Some(&w2),
        true,
    )
    .await;
    assert_eq!(r["t"], "ack", "{r}");
    assert!(h.app.db.duties().unwrap().is_empty());
    assert!(h
        .app
        .db
        .group_leaves(&gid)
        .unwrap()
        .contains(&alice2.device_id));
}

fn revoke_proof(h: &Harness, signer: &User, target: &User, at_ms: i64) -> Value {
    let at = UnixMillis(at_ms).to_rfc3339().unwrap();
    let sig = lodelai_crypto::devrevoke::sign(
        &signer.keys.signing,
        &lodelai_crypto::devrevoke::Revoke {
            server: SERVER,
            device_id: &target.device_id,
            at: &at,
        },
    );
    let _ = h;
    json!({"at": at, "sig": sig})
}

/// 증명이 틀리면(남의 키·시각 ±5분 밖·남의 기기) error{protocol} 이고 폐기하지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_proof_is_checked() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let now = h.fx.clock.now().0;
    for (why, proof, target) in [
        ("남의 키", revoke_proof(&h, &bob, &alice2, now), &alice2),
        (
            "6분 앞",
            revoke_proof(&h, &alice, &alice2, now + 6 * 60 * 1000),
            &alice2,
        ),
        ("남의 기기", revoke_proof(&h, &alice, &bob, now), &bob),
    ] {
        a.send(&json!({"t": "device.revoke", "device_id": target.device_id, "proof": proof}))
            .await;
        let r = next_of(&mut a, "error").await;
        assert_eq!(r["code"], "protocol", "{why}: {r}");
        assert!(
            h.app.db.device(&target.device_id).unwrap().is_some(),
            "{why}"
        );
    }
    assert!(h.app.db.revocations_of("alice").unwrap().is_empty());
    // 맞는 증명이면 폐기되고 증명이 남지만, 아래에 산 기기가 없는 마디는 디렉터리에 싣지 않는다(쌓이지 않게).
    let proof = revoke_proof(&h, &alice, &alice2, now);
    a.send(&json!({"t": "device.revoke", "device_id": alice2.device_id, "proof": proof}))
        .await;
    assert_eq!(
        next_of(&mut a, "device.revoked").await["t"],
        "device.revoked"
    );
    assert_eq!(h.app.db.revocations_of("alice").unwrap().len(), 1);
    let dir = lodelai_relay::ws::directory(&h.app, "bob");
    let p = dir
        .people
        .iter()
        .find(|p| p.address.starts_with("alice@"))
        .unwrap();
    assert!(p.revocations.is_empty());
}

/// bob 쪽 GroupInfo 로 external commit(그 사용자의 다른 잎이 없는 새 기기 — §7).
async fn external_join(h: &Harness, c: &mut Client, u: &User, to: &User, gid: &[u8]) -> Value {
    let f = group_info_get(c, &encoding::encode(gid)).await;
    let gi = encoding::decode(f["group_info"]["data"].as_str().unwrap(), "gi").unwrap();
    let MlsMessageBodyIn::GroupInfo(vgi) = MlsMessageIn::tls_deserialize_exact(gi.as_slice())
        .unwrap()
        .extract()
    else {
        panic!("group info 아님")
    };
    let d = Dev::of(u);
    let (g, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .build_group(&d.provider, vgi, d.signer.credential())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(d.provider.storage())
        .unwrap()
        .build(d.provider.rand(), d.provider.crypto(), &d.signer, |_| true)
        .unwrap()
        .finalize(&d.provider)
        .unwrap();
    let m = mls_msg(
        h,
        u,
        &to.address(),
        "mls",
        gid,
        f["epoch"].as_u64().unwrap(),
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&d.group_info(&g)),
        }),
    );
    send(c, &m).await
}

/// 계약 시험(c53989c0·e73b25bd): A→B 에서 A 를 증명으로 끊어도 A 가 뿌리로 남는다 — B 가 서명한 C 는 잎 자격, devcert 없는
/// 나중 기기 D2 는 invalid_commit. 디렉터리에 revocations 와 A 로 들어오고 나가는 devcert 가 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn proof_revoked_root_keeps_chain() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await; // A
    let bob = register(&h, "bob", 2).await;
    let alice_b = register_extra_device(&h, "alice", 3).await; // B
    let alice_c = register_extra_device(&h, "alice", 4).await; // C
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;
    // A → B, 그리고 A 가 자기 자신을 증명으로 끊는다.
    a.send(&json!({"t": "device.certify", "device_id": alice_b.device_id, "sig": devcert(&alice, &alice_b)}))
        .await;
    let proof = revoke_proof(&h, &alice, &alice, h.fx.clock.now().0);
    a.send(&json!({"t": "device.revoke", "proof": proof})).await;
    assert_eq!(
        next_of(&mut a, "device.revoked").await["t"],
        "device.revoked"
    );
    assert!(h.app.db.device(&alice.device_id).unwrap().is_none());
    let revs = h.app.db.revocations_of("alice").unwrap();
    assert_eq!(revs.len(), 1);
    assert_eq!(revs[0].device_id, alice.device_id);
    assert_eq!(revs[0].proof.signer, alice.device_id);
    assert!(h
        .app
        .db
        .device_certs_of("alice")
        .unwrap()
        .iter()
        .any(|(t, s, _)| *t == alice_b.device_id && *s == alice.device_id));
    // 디렉터리: revocations 에 A(서명자·at·ed25519·added_at).
    let dir = lodelai_relay::ws::directory(&h.app, "bob");
    let p = dir
        .people
        .iter()
        .find(|p| p.address.starts_with("alice@"))
        .unwrap();
    assert_eq!(p.revocations.len(), 1);
    assert_eq!(p.revocations[0].signer, alice.device_id);
    // B → C. 그 뒤 devcert 없는 D2 가 등록된다.
    let (mut bc, _) = connect(&h, &alice_b).await;
    certify(&mut bc, &alice_b, &alice_c).await;
    let d2 = register_extra_device(&h, "alice", 5).await;
    let (mut d2c, _) = connect(&h, &d2).await;
    // D2 는 뿌리 A 아래가 아니다 — 확인 전 기기라 GroupInfo 부터 못 받는다(#888, 전엔 Commit 이 invalid_commit). req 가
    // 없는 요청이라 답 없이 버린다.
    d2c.send(&json!({"t": "group_info.get", "group": encoding::encode(&gid)}))
        .await;
    none_of(&mut d2c, &["group_info", "error"]).await;
    let (mut cc, _) = connect(&h, &alice_c).await;
    let r = external_join(&h, &mut cc, &alice_c, &bob, &gid).await;
    assert_eq!(r["t"], "ack", "C 는 A→B→C: {r}");
}

/// #599 ①: 끊기 완료 때 그 사람의 산 잎이 하나도 안 남은 그룹이면, 잎 자격 있는 그 사람의 비잎 기기에 rejoin_needed 를 바로
/// (Remove 확정을 기다리지 않음). external commit 으로 들면 표시가 지워진다. 산 잎이 남은 그룹이면 보내지 않는다(add_device 길).
#[tokio::test(flavor = "multi_thread")]
async fn revoke_last_leaf_sends_rejoin_to_new_device() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await; // A — 그룹의 유일한 alice 잎
    let bob = register(&h, "bob", 2).await;
    let alice_b = register_extra_device(&h, "alice", 3).await; // B — 새 기기(아직 잎 아님)
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let gid_s = encoding::encode(&gid);
    make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;
    certify(&mut a, &alice, &alice_b).await;
    let (mut bc, _) = connect(&h, &alice_b).await;
    assert!(h.app.db.rejoin_for(&alice_b.device_id).unwrap().is_empty());

    // A 가 자기를 끊는다(지금 끊기) — A 의 잎은 아직 트리에 있지만 산 잎이 아니다.
    a.send(&json!({"t": "device.revoke"})).await;
    let f = next_of(&mut bc, "rejoin_needed").await;
    assert_eq!(f["groups"], json!([gid_s]), "{f}");
    assert_eq!(
        h.app.db.rejoin_for(&alice_b.device_id).unwrap(),
        vec![gid_s.clone()]
    );

    // B 가 external commit 으로 든다 → 표시가 지워지고 다음 접속엔 rejoin_needed 가 없다.
    let r = external_join(&h, &mut bc, &alice_b, &bob, &gid).await;
    assert_eq!(r["t"], "ack", "{r}");
    assert!(h.app.db.rejoin_for(&alice_b.device_id).unwrap().is_empty());
    drop(bc);
    let (mut bc, _) = connect(&h, &alice_b).await;
    // 접속하면 A 의 옛 잎을 빼는 일(remove_device)은 오지만 rejoin_needed 는 없다.
    let f = bc.recv().await;
    assert_eq!(
        (f["t"].as_str(), f["task"].as_str()),
        (Some("duty"), Some("remove_device")),
        "{f}"
    );

    // 산 잎(B)이 남은 그룹: B 가 서명한 C·D 중 D 를 끊어도 C 에는 보내지 않는다(B 가 add_device 로 들인다).
    // 등록 시각이 B 보다 늦게 — 같은 ms 면 뿌리를 아이디 순으로 가려 B 가 자격을 잃을 수 있다(#888 은 그때 B 를 막는다).
    h.fx.clock.advance(1000);
    let alice_c = register_extra_device(&h, "alice", 4).await;
    let alice_d = register_extra_device(&h, "alice", 5).await;
    certify(&mut bc, &alice_b, &alice_c).await;
    certify(&mut bc, &alice_b, &alice_d).await;
    let (mut cc, _) = connect(&h, &alice_c).await;
    bc.send(&json!({"t": "device.revoke", "device_id": alice_d.device_id}))
        .await;
    assert_eq!(
        next_of(&mut bc, "device.revoked").await["device_id"],
        alice_d.device_id
    );
    assert!(h.app.db.rejoin_for(&alice_c.device_id).unwrap().is_empty());
    // 디렉터리 갱신은 와도 rejoin_needed 는 오지 않는다.
    while let Ok(Some(Ok(Message::Text(t)))) =
        tokio::time::timeout(Duration::from_millis(300), cc.ws.next()).await
    {
        assert!(!t.contains("\"rejoin_needed\""), "{t}");
    }
}

/// #599 ①(설계 리뷰 6512635445): 잎 자격 있는 비잎 기기가 둘이면 하나에만 — 지금 연결된 것이 먼저(등록이 늦어도). 연결된 기기가
/// 없으면 가장 이른 기기에 표시만.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_last_leaf_rejoins_one_device_online_first() {
    for online_c in [true, false] {
        let h = start().await;
        let alice = register(&h, "alice", 1).await;
        let bob = register(&h, "bob", 2).await;
        let alice_b = register_extra_device(&h, "alice", 3).await; // 먼저 등록
        let alice_c = register_extra_device(&h, "alice", 4).await; // 나중 등록
        let (mut a, _) = connect(&h, &alice).await;
        let (mut b, _) = connect(&h, &bob).await;
        let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
        let gid_s = encoding::encode(&pair_group_id(&alice.name, &bob.name));
        make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
        let _ = b.recv().await;
        for t in [&alice_b, &alice_c] {
            certify(&mut a, &alice, t).await;
        }
        let cc = if online_c {
            Some(connect(&h, &alice_c).await.0)
        } else {
            None
        };
        // 증명 있는 자기 끊기 — A 가 뿌리로 남아 B·C 둘 다 잎 자격(증명 없으면 A 의 서명이 지워져 C 는 자격을 잃는다).
        let proof = revoke_proof(&h, &alice, &alice, h.fx.clock.now().0);
        a.send(&json!({"t": "device.revoke", "proof": proof})).await;
        if let Some(mut cc) = cc {
            assert_eq!(
                next_of(&mut cc, "rejoin_needed").await["groups"],
                json!([gid_s])
            );
            assert_eq!(
                h.app.db.rejoin_for(&alice_c.device_id).unwrap(),
                vec![gid_s.clone()]
            );
            assert!(h.app.db.rejoin_for(&alice_b.device_id).unwrap().is_empty());
        } else {
            for _ in 0..50 {
                if !h.app.db.rejoin_for(&alice_b.device_id).unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(
                h.app.db.rejoin_for(&alice_b.device_id).unwrap(),
                vec![gid_s.clone()]
            );
            assert!(h.app.db.rejoin_for(&alice_c.device_id).unwrap().is_empty());
        }
    }
}

// ------------------------------------------------------------------ §5c 큰 Handshake 는 blob 길

/// 바이트 본문 HTTP(PUT·GET). (상태, 본문)
async fn bhttp(h: &Harness, method: &str, path: &str, token: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nHost: 127.0.0.1:{}\r\nContent-Length: {}\r\nAuthorization: Bearer {token}\r\n\r\n",
        h.addr.port(),
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let _ = s.write_all(body).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..split]).into_owned();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        out[split + 4..].to_vec(),
    )
}

/// 예약 → 올림 → MLS blob 칸 `{blob:{blob_id, size, sha256}}`.
async fn upload_mls(h: &Harness, c: &mut Client, bytes: &[u8]) -> Value {
    c.send(&json!({"t": "blob.reserve", "req": "r1", "ct_len": bytes.len(), "purpose": "message"}))
        .await;
    let r = next_of(c, "blob.reserved").await;
    let id = r["blob_id"].as_str().unwrap().to_owned();
    let (code, _) = bhttp(
        h,
        "PUT",
        &format!("/v1/blobs/{id}"),
        r["put_token"].as_str().unwrap(),
        bytes,
    )
    .await;
    assert_eq!(code, 204);
    let sha = encoding::encode(&sha2::Sha256::digest(bytes));
    json!({"blob": {"blob_id": id, "size": bytes.len(), "sha256": sha}})
}

/// blob.get → GET. (상태, 바이트) — 표를 못 받으면 (0, 빈).
async fn fetch_blob(h: &Harness, c: &mut Client, blob_id: &str) -> (u16, Vec<u8>) {
    c.send(&json!({"t": "blob.get", "req": "g1", "blob_id": blob_id}))
        .await;
    let t = loop {
        let f = c.recv().await;
        if f["t"] == "blob.ticket" || f["t"] == "error" {
            break f;
        }
    };
    if t["t"] != "blob.ticket" {
        return (0, Vec::new());
    }
    bhttp(
        h,
        "GET",
        &format!("/v1/blobs/{blob_id}"),
        t["get_token"].as_str().unwrap(),
        b"",
    )
    .await
}

use sha2::Digest as _;

/// Welcome 이 blob 이어도 Handshake 수명(§5c): 7일 첨부 규칙이 아니라 — 8일 꺼졌던 bob 이 Commit 과 그 Welcome blob 을 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_welcome_blob_lives_with_handshake() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let mut g = ad.create(Kind::Pair, &gid);
    let start_m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
    );
    assert_eq!(send(&mut a, &start_m).await["t"], "ack");
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[bd.key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let wbytes = welcome.tls_serialize_detached().unwrap();
    let wref = upload_mls(&h, &mut a, &wbytes).await;
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": wref,
        }),
    );
    let r = send(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    h.fx.clock.advance(8 * DAYS as i64 * 1000);
    h.app.expire_tick();
    let (mut b, _) = connect(&h, &bob).await;
    let d = next_of(&mut b, "deliver").await;
    let id = d["message"]["body"]["welcome"]["blob"]["blob_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (code, got) = fetch_blob(&h, &mut b, &id).await;
    assert_eq!(code, 200);
    assert_eq!(got, wbytes);
}

/// GroupInfo 가 blob 이면 relay 가 읽어 검사하고 그룹의 지금 GroupInfo 로 붙잡는다: group_info.get 은 blob 참조, 멤버 사용자만
/// 받는다. 다음 Commit 이 프레임 안 GroupInfo 면 다시 data. 해시가 틀리면 invalid_commit, 남이 올린 blob 은 blob_unavailable.
#[tokio::test(flavor = "multi_thread")]
async fn group_info_blob_pinned_for_members() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let gid_s = encoding::encode(&gid);
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;
    // 해시 틀린 payload blob → invalid_commit.
    let epoch = g.epoch().as_u64();
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let cbytes = bundle.commit().tls_serialize_detached().unwrap();
    let mut bad = upload_mls(&h, &mut a, &cbytes).await;
    bad["blob"]["sha256"] = json!(encoding::encode(&[7u8; 32]));
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        epoch,
        json!({"enc": "mls", "wire": "commit", "payload": bad, "group_info": data(&ad.group_info(&g))}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "invalid_commit");
    // 남(bob)이 올린 blob 을 alice 가 쓰면 blob_unavailable.
    let gi_bytes = ad.group_info(&g);
    let bobs = upload_mls(&h, &mut b, &gi_bytes).await;
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        epoch,
        json!({"enc": "mls", "wire": "commit", "payload": data(&cbytes), "group_info": bobs}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "blob_unavailable");
    // 맞는 GroupInfo blob → ack, group_info.get 은 blob 참조.
    let gi_ref = upload_mls(&h, &mut a, &gi_bytes).await;
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        epoch,
        json!({"enc": "mls", "wire": "commit", "payload": data(&cbytes), "group_info": gi_ref.clone()}),
    );
    let r = send(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    let f = group_info_get(&mut b, &gid_s).await;
    assert_eq!(f["group_info"], gi_ref, "{f}");
    let id = gi_ref["blob"]["blob_id"].as_str().unwrap().to_owned();
    // bob 이 받고 다 받았다고 해도(fetched) GroupInfo blob 은 붙잡혀 남는다.
    let (code, got) = fetch_blob(&h, &mut b, &id).await;
    assert_eq!((code, got.as_slice()), (200, gi_bytes.as_slice()));
    b.send(&json!({"t": "blob.fetched", "blob_id": id})).await;
    h.app.expire_tick();
    let (code, _) = fetch_blob(&h, &mut a, &id).await;
    assert_eq!(code, 200, "멤버(주인)는 여전히 받는다");
    // 같은 조직이라도 멤버 아닌 carol 은 표를 못 받는다.
    assert_eq!(fetch_blob(&h, &mut c, &id).await.0, 0);
    // 다음 Commit 이 프레임 안 GroupInfo 면 다시 data.
    self_update(&h, &mut a, &alice, &ad, &mut g, &bob.address(), &gid).await;
    let f = group_info_get(&mut b, &gid_s).await;
    assert!(f["group_info"]["data"].is_string(), "{f}");
}

/// blob 파일이 디스크에 있는가.
fn blob_file(h: &Harness, id: &str) -> bool {
    h.app.blob_dir.join(&id[..2]).join(id).exists()
}

/// 풀린 GroupInfo blob 은 고아로 남지 않는다(⑨ 리뷰 ②): start 의 GroupInfo blob(봉투가 없음)은 다음 Commit 이 GroupInfo 를
/// 바꾸는 순간 행·파일이 지워진다. 1 MiB 넘는 blob 칸은 읽기 전에 blob_unavailable.
#[tokio::test(flavor = "multi_thread")]
async fn released_group_info_blob_is_removed() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let ad = Dev::of(&alice);
    let gid = pair_group_id(&alice.name, &bob.name);
    let mut g = ad.create(Kind::Pair, &gid);
    let mut big = upload_mls(&h, &mut a, &[1u8; 16]).await;
    big["blob"]["size"] = json!(lodelai_relay::mls::MLS_BLOB_MAX_BYTES + 1);
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": big}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "blob_unavailable");
    let gi_ref = upload_mls(&h, &mut a, &ad.group_info(&g)).await;
    let id = gi_ref["blob"]["blob_id"].as_str().unwrap().to_owned();
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "mls",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": gi_ref}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert!(h.app.db.blob_known(&id).unwrap() && blob_file(&h, &id));
    self_update(&h, &mut a, &alice, &ad, &mut g, &bob.address(), &gid).await;
    assert!(!h.app.db.blob_known(&id).unwrap(), "행이 남음");
    assert!(!blob_file(&h, &id), "파일이 남음");
}

/// 묶기는 Commit 과 한 트랜잭션(⑨ 리뷰 ①): 묶기 검사 뒤 다른 쪽이 먼저 묶었으면(여기선 남의 blob 으로 흉내) BlobUnavailable,
/// epoch·지금 GroupInfo 는 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn commit_rolls_back_when_blob_cannot_bind() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid_s = encoding::encode(&pair_group_id(&alice.name, &bob.name));
    let (g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let bobs = upload_mls(&h, &mut b, &ad.group_info(&g)).await;
    let bid = bobs["blob"]["blob_id"].as_str().unwrap().to_owned();
    let (_, epoch, storage, gi) = h.app.db.mls_group(&gid_s).unwrap().unwrap();
    let pin = lodelai_relay::db::GiPin {
        blob_id: bid.clone(),
        size: bobs["blob"]["size"].as_u64().unwrap(),
        sha256: bobs["blob"]["sha256"].as_str().unwrap().to_owned(),
    };
    let r = h.app.db.mls_group_commit(
        &gid_s,
        epoch,
        &storage,
        &gi,
        &alice.device_id,
        false,
        (Some(&pin), "m-race", &alice.name),
        std::slice::from_ref(&bid),
        std::slice::from_ref(&alice.device_id),
        0,
    );
    assert!(
        matches!(r, Err(lodelai_relay::db::DbError::BlobUnavailable)),
        "{r:?}"
    );
    assert_eq!(h.app.db.mls_group(&gid_s).unwrap().unwrap().1, epoch);
    assert!(h.app.db.gi_pin(&gid_s).unwrap().is_none());
}

// ------------------------------------------------------------------ §4-7 group 종류 2단계(§12-13·14)

fn gaddr(gid: &str) -> String {
    format!("+{gid}@{SERVER}")
}

/// group 종류 메시지(헤더 `mls_group` = gid 문자열). `extra` 는 group_op·subject·base_seq 등.
#[allow(clippy::too_many_arguments)]
fn gmsg(
    h: &Harness,
    from: &User,
    to: &str,
    kind: &str,
    gid: &str,
    epoch: u64,
    body: Value,
    extra: Value,
) -> Value {
    let id = h.fx.ids.next_ulid();
    let mut m = json!({
        "v": msg_v(kind), // 메시지 v 는 9·10(판 11 은 ws typing 만, #613) — 판 10 글(#598 ② 가르기 대상), 반응만 판 12(#626)
        "msg_id": id, "thread_id": id, "kind": kind,
        "from": {"address": from.address(), "author": "human", "device_id": from.device_id},
        "to": {"address": to},
        "mls_group": gid, "epoch": epoch,
        "body": body,
        "created_at": UnixMillis(h.fx.clock.now().0).to_rfc3339().unwrap(),
        "expires_at": UnixMillis(h.fx.clock.now().0 + 24 * 3600 * 1000).to_rfc3339().unwrap(),
    });
    for (k, v) in extra.as_object().unwrap() {
        m[k] = v.clone();
    }
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// 보내고 답(ack·nack·error)과 그 앞에 온 프레임들.
async fn send_seen(c: &mut Client, m: &Value) -> (Value, Vec<Value>) {
    c.send(&json!({"t": "send", "message": m})).await;
    let mut seen = Vec::new();
    loop {
        let f = c.recv().await;
        if f["t"] == "ack" || f["t"] == "nack" || f["t"] == "error" {
            return (f, seen);
        }
        seen.push(f);
    }
}

fn commit_hash(commit: &MlsMessageOut) -> String {
    encoding::encode(&sha2::Sha256::digest(
        commit.tls_serialize_detached().unwrap(),
    ))
}

/// alice 혼자 group 을 만든다(create = start, seq 1).
async fn make_group(h: &Harness, a: &mut Client, alice: &User, ad: &Dev) -> (String, MlsGroup) {
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let g = ad.create(Kind::Group, gid.as_bytes());
    let m = gmsg(
        h,
        alice,
        &gaddr(&gid),
        "group",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
        json!({"group_op": "create", "base_seq": 0}),
    );
    let r = send(a, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["group_seq"].as_u64()),
        (Some("ack"), Some(1)),
        "{r}"
    );
    (gid, g)
}

/// 0.2.5: start 뒤 만들기가 실패한 빈 그룹은 같은 사람·같은 기기가 같은 gid 로 다시 start 하면 다시 받는다(seq 1 부터).
/// 다른 계정이 그 gid 로 오면 지금처럼 unroutable(가로채기 막기).
#[tokio::test(flavor = "multi_thread")]
async fn failed_group_start_is_taken_again_by_same_device_only() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (gid, _) = make_group(&h, &mut a, &alice, &Dev::of(&alice)).await;
    let start_of = |u: &User, d: &Dev| {
        let g = d.create(Kind::Group, gid.as_bytes());
        gmsg(
            &h,
            u,
            &gaddr(&gid),
            "group",
            &gid,
            0,
            json!({"enc": "mls", "wire": "start", "group_info": data(&d.group_info(&g))}),
            json!({"group_op": "create", "base_seq": 0}),
        )
    };
    let r = send(&mut b, &start_of(&bob, &Dev::of(&bob))).await;
    assert_eq!(r["reason"], "unroutable", "{r}");
    let r = send(&mut a, &start_of(&alice, &Dev::of(&alice))).await;
    assert_eq!(
        (r["t"].as_str(), r["group_seq"].as_u64()),
        (Some("ack"), Some(1)),
        "{r}"
    );
}

/// #805: 만들기가 실패하고 다시 만들지 않은 빈 그룹은 30일 동안 남고(그 사이 같은 기기가 다시 만들 수 있음, 목록엔 없음 —
/// #817), 30일이 지나면 만료 스캔이 지운다 — 그 gid 는 다시 비어 새 start 를 받는다. 그 사이 update 가
/// 확정돼 epoch 가 움직였어도(만든 사람 다른 기기의 스스로 들기와 같은 op) 지운다.
#[tokio::test(flavor = "multi_thread")]
async fn failed_group_start_expires_after_30_days() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let ad = Dev::of(&alice);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    // 실패 그룹에 그 사람의 기기가 update(스스로 들기 external commit 과 같은 op)를 확정해도 seq 는 1 그대로 — epoch 만 1.
    let (up, _, _) = update_msg(&h, &alice, &ad, &mut g, &gid, 1);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    for _ in 0..100 {
        if h.app.db.mls_pending(&gid).unwrap().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none(), "update 확정");
    assert_eq!(h.app.db.mls_group(&gid).unwrap().map(|g| g.1), Some(1));
    h.fx.clock.advance((29 * DAYS * 1000) as i64);
    h.app.expire_tick();
    assert!(h.app.db.mls_group(&gid).unwrap().is_some(), "29일엔 남음");
    assert_eq!(
        groups_list(&mut a).await,
        json!([]),
        "만들기 전 그룹은 목록에 없음"
    );
    h.fx.clock.advance((DAYS * 1000) as i64);
    h.app.expire_tick();
    assert!(h.app.db.mls_group(&gid).unwrap().is_none(), "30일에 지움");
    let bd = Dev::of(&bob);
    let g = bd.create(Kind::Group, gid.as_bytes());
    let m = gmsg(
        &h,
        &bob,
        &gaddr(&gid),
        "group",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&bd.group_info(&g))}),
        json!({"group_op": "create", "base_seq": 0}),
    );
    let r = send(&mut b, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["group_seq"].as_u64()),
        (Some("ack"), Some(1)),
        "{r}"
    );
}

/// #817: 만들기 Commit 이 확정되지 않은 그룹(seq 1)은 만든 사람의 다른 기기 `groups` 에 없다 — 스스로 들기 후보가 되지
/// 않게. 첫 멤버가 들어 seq 가 오르면 실린다.
#[tokio::test(flavor = "multi_thread")]
async fn groups_list_hides_group_until_create_commit() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    certify(&mut a, &alice, &alice2).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    assert_eq!(groups_list(&mut a2).await, json!([]));
    assert_eq!(groups_list(&mut a).await, json!([]));
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert_eq!(
        groups_list(&mut a2).await,
        json!([{"group": gaddr(&gid), "seq": 2}])
    );
}

/// alice 의 add Commit(사람 하나). (메시지, Commit 해시)
#[allow(clippy::too_many_arguments)]
fn add_msg(
    h: &Harness,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    gid: &str,
    who: &User,
    wd: &Dev,
    base_seq: u64,
) -> (Value, String) {
    let epoch = g.epoch().as_u64();
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[wd.key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = gmsg(
        h,
        alice,
        &gaddr(gid),
        "group",
        gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
        json!({"group_op": "add", "subject": who.address(), "base_seq": base_seq}),
    );
    (m, commit_hash(&commit))
}

/// 혼자 만든 그룹의 첫 add 는 응답할 사람이 없어 바로 확정(seq 2). 둘째 add 는 확정 전으로 배달(seq 없음, 새 잎엔 아직 안 감) →
/// 60초 창 안의 ack 로는 확정하지 않고, 창이 끝나면 확정(commit_final seq 3, 새 잎은 그때 Commit). 그룹 맥락의 box 는 형식 오류.
#[tokio::test(flavor = "multi_thread")]
async fn group_commit_two_phase_final() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;

    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    let (r, seen) = send_seen(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    // 응답할 사람이 없어 바로 확정 — commit_final 이 ack 보다 먼저(§12-16).
    let fin = seen
        .iter()
        .find(|f| f["t"] == "commit_final")
        .expect("commit_final");
    assert_eq!(
        (fin["epoch"].as_u64(), fin["group_seq"].as_u64()),
        (Some(0), Some(2)),
        "{fin}"
    );
    let d = next_of(&mut b, "deliver").await;
    assert_eq!(
        (d["group_seq"].as_u64(), d["message"]["msg_id"].clone()),
        (Some(2), m["msg_id"].clone())
    );
    let _ = hash;

    // 둘째 add: bob 이 응답할 수 있다.
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    let r = send(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    assert!(r.get("group_seq").is_none(), "{r}");
    let d = next_of(&mut b, "deliver").await;
    assert_eq!(d["message"]["msg_id"], m["msg_id"]);
    assert!(d.get("group_seq").is_none(), "확정 전 배달엔 seq 없음: {d}");
    c.expect_silence().await;
    // 응답할 산 사람(bob — 드는 carol 은 Welcome 을 확정 뒤에 받아 셀 수 없음)이 모두 ack — 창을 기다리지 않고 확정(#599).
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    let f = next_of(&mut b, "commit_final").await;
    assert_eq!(
        (
            f["epoch"].as_u64(),
            f["group_seq"].as_u64(),
            f["commit_hash"].as_str()
        ),
        (Some(1), Some(3), Some(hash.as_str())),
        "{f}"
    );
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(f["group_seq"].as_u64(), Some(3));
    let d = next_of(&mut c, "deliver").await;
    assert_eq!(
        (d["message"]["msg_id"].clone(), d["group_seq"].as_u64()),
        (m["msg_id"].clone(), Some(3))
    );

    // #599: 응답할 산 사람이 둘(bob·carol)이면 하나만 ack 해서는 창을 기다리고, 둘 다 ack 하면 바로 확정한다.
    let epoch = g.epoch().as_u64();
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let hash = commit_hash(bundle.commit());
    let up = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
        }),
        json!({"group_op": "update", "base_seq": 3}),
    );
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let _ = next_of(&mut c, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "하나만 ack — 창을 기다린다"
    );
    c.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    let f = next_of(&mut b, "commit_final").await;
    assert_eq!(f["epoch"].as_u64(), Some(epoch), "{f}");
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());

    // 그룹 맥락의 box 는 형식 오류(판 7).
    let boxed = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "chat",
        &gid,
        2,
        json!({"enc": "box", "alg": "x", "epk": "x", "nonce": "x", "ct": "x", "cek_commit": "x", "recipients": []}),
        json!({}),
    );
    assert_eq!(send(&mut a, &boxed).await["t"], "error");
}

/// 그룹 update Commit 하나(시험용) — (메시지, commit_hash, epoch).
fn update_msg(
    h: &Harness,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    gid: &str,
    base_seq: u64,
) -> (Value, String, u64) {
    let epoch = g.epoch().as_u64();
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let hash = commit_hash(bundle.commit());
    let up = gmsg(
        h,
        alice,
        &gaddr(gid),
        "group",
        gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(g)),
        }),
        json!({"group_op": "update", "base_seq": base_seq}),
    );
    (up, hash, epoch)
}

/// 그 사용자의 연결이 relay 에서 빠질 때까지(상한 5초).
async fn until_offline(h: &Harness, user: &str) {
    for _ in 0..100 {
        if !h.app.conns.is_online(user) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{user} 가 relay 에서 빠지지 않음");
}

/// hosted 11-04 A: 확정 전 Commit 은 **지금 연결된 잎**을 가진 투표자만 다 ack 하면 창을 기다리지 않고 확정한다(오프라인 carol 을
/// 기다리지 않음). 연결된 투표자가 fail 이면 지금 규칙대로 창을 기다린다.
#[tokio::test(flavor = "multi_thread")]
async fn online_voters_ack_finalizes_without_window() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    let _ = next_of(&mut b, "commit_final").await;

    // carol 이 끊긴 채 alice 의 update — 연결된 투표자 bob 하나의 ack 로 바로 확정.
    drop(c);
    until_offline(&h, "carol").await;
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 3);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    let f = next_of(&mut b, "commit_final").await;
    assert_eq!(f["epoch"].as_u64(), Some(epoch), "{f}");
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());

    // 연결된 투표자가 fail — 창 안에서는 확정하지 않고, 창이 끝나면 연결된 투표자 전원(bob 하나) fail 이라 무효(§7-28).
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 4);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "fail 은 확정 아님"
    );
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_none(),
        "연결된 투표자 전원 fail — 창 끝에 무효(§7-28)"
    );
    assert_eq!(next_of(&mut b, "commit_void").await["commit_hash"], hash);
}

/// hosted 11-04 A·B·#846: 연결된 투표자가 없고 fail 도 없으면 창 끝(B)을 기다리지 않는다 — ⓐ 배달 직후 바로 확정(동료가 다
/// 꺼진 그룹의 Add 가 창+tick 만큼 늦던 것) ⓑ 배달 땐 붙어 있던 투표자가 표 없이 끊기면 창 안의 다음 tick 에 확정. 돌아온 bob 은
/// 그 Commit 과 확정 결과를 받는다(처리 못 하면 다시 든다).
#[tokio::test(flavor = "multi_thread")]
async fn no_online_voter_finalizes_without_window() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());

    // ⓑ bob 이 받고 표 없이 끊김 — 창 안(시계 그대로)의 tick 에 확정.
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 2);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "붙어 있는 bob 을 기다림"
    );
    drop(b);
    until_offline(&h, "bob").await;
    h.app.expire_tick();
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(
        (f["epoch"].as_u64(), f["commit_hash"].as_str()),
        (Some(epoch), Some(hash.as_str())),
        "{f}"
    );
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());

    // ⓐ bob 이 꺼진 채 update — tick 없이 배달 직후 확정(ack 보다 commit_final 이 먼저 오니 send 가 그것을 건너뛴다 — 표로 잰다).
    let (up, _hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 3);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_none(),
        "연결된 투표자 없음 — 배달 직후 확정"
    );
    // 다시 붙으면 ack 하지 않은 앞 배달(add)부터 다시 온다 — 그 뒤에 확정된 update.
    let (mut b, _) = connect(&h, &bob).await;
    // 접속 때 마지막 결과(commit_final)가 쌓인 배달보다 먼저 올 수 있다 — 순서 없이 둘 다.
    let (mut got_update, mut got_final) = (false, false);
    while !(got_update && got_final) {
        let f = b.recv().await;
        match f["t"].as_str() {
            Some("deliver") if f["message"]["msg_id"] == up["msg_id"] => got_update = true,
            Some("commit_final") if f["epoch"].as_u64() == Some(epoch) => got_final = true,
            _ => {}
        }
    }

    // ⓒ fail 이 하나라도 있으면 일찍 확정하지 않는다 — bob 이 fail 을 내고 끊겨 연결된 투표자가 없어도 창 안·창 끝 모두 그대로,
    // 1시간(PENDING_MAX)에 무효.
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 4);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    loop {
        let f = next_of(&mut b, "deliver").await;
        if f["message"]["msg_id"] == up["msg_id"] {
            break;
        }
    }
    b.send(&json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(b);
    until_offline(&h, "bob").await;
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "fail 있음 — 창 안 확정 없음"
    );
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "fail 있음 — 창 끝 B 없음"
    );
    h.fx.clock.advance(lodelai_relay::mls_group::PENDING_MAX_MS);
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_none(),
        "1시간 — 무효"
    );
    assert_eq!(next_of(&mut a, "commit_void").await["commit_hash"], hash);
}

/// #807(0.2.6 계약 §2-2): 접속해 있고 살아 있지만(ping 은 옴) 표를 내지 않는 투표자는 Commit 배달 뒤 5분(`VOTE_SILENT_MS`)이
/// 지나면 '연결 안 됨'으로 센다 — 창 끝 B(연결된 투표자 없음 → 확정)가 걸린다. 5분 안에는 지금처럼 기다린다. 무효가 아니라 확정이라
/// duty 가 다시 나가지 않는다. 진짜 SIGSTOP 은 앱 ping 이 끊겨 relay 가 90초 뒤 끊으므로 이 규칙 없이도 창 끝에 풀린다
/// (`no_online_voter_finalizes_without_window`).
#[tokio::test(flavor = "multi_thread")]
async fn connected_silent_voter_counts_as_offline_after_vote_silent() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // bob 은 이 Add 로 드는 잎이라 표가 없다 — 창 끝에 확정.
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());

    // alice 의 update — bob 은 받고(배달 ack 는 함) 표는 내지 않는다. 앱 ping 은 계속 보낸다(살아 있음).
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 2);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let d = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "ack", "msg_id": d["message"]["msg_id"]}))
        .await;
    for (advance, what) in [(61_000, "창 끝"), (3 * 60_000, "4분"), (58_000, "4분 59초")] {
        b.send(&json!({"t": "ping"})).await;
        let _ = next_of(&mut b, "pong").await;
        h.fx.clock.advance(advance);
        h.app.expire_tick();
        assert!(h.app.conns.is_online("bob"), "{what}: bob 은 붙어 있음");
        assert!(
            h.app.db.mls_pending(&gid).unwrap().is_some(),
            "{what}: 5분 안 — 표 없는 연결된 투표자를 기다림"
        );
    }
    h.fx.clock.advance(2_000);
    h.app.expire_tick();
    assert!(h.app.conns.is_online("bob"));
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(
        (f["epoch"].as_u64(), f["commit_hash"].as_str()),
        (Some(epoch), Some(hash.as_str())),
        "5분 침묵 — 확정(무효 아님): {f}"
    );
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());
}

/// #807·§7-28: 연결된 투표자가 fail 을 냈으면 침묵이 아니다 — 그리고 그 투표자가 연결된 투표자 전원(여기선 하나뿐)이면 창 끝에
/// 바로 무효(1시간 기다리지 않음).
#[tokio::test(flavor = "multi_thread")]
async fn connected_failing_only_voter_voids_at_window_end() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 2);
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_none(),
        "연결된 투표자 전원 fail — 창 끝에 무효"
    );
    assert_eq!(next_of(&mut b, "commit_void").await["commit_hash"], hash);
}

/// §7-28: 드는 잎은 표를 낼 수 없다 — 창 끝에 남은 투표자가 그 잎뿐이면(다른 투표자는 폐기) 확정.
#[tokio::test(flavor = "multi_thread")]
async fn only_joining_leaf_left_finalizes_at_window_end() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (_c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "bob 이 투표자"
    );
    // bob 이 끊기고(투표자 없음) 창이 끝나면 드는 잎(carol)만 남는다 — 확정.
    drop(b);
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_none(),
        "드는 잎만 남으면 확정"
    );
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(f["group_seq"].as_u64(), Some(3), "{f}");
}

/// #599(설계 리뷰 6519899388 ②): 확정 결과는 그 그룹에 다시 들라는 표시(`mls_rejoin`)가 있는 기기에도 간다 — 잎이 아니라
/// `stale_epoch` 로 물러선 external commit 이 물러섬을 다 기다리지 않게. 지금 그룹 멤버가 아닌 사람의 기기에는 보내지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn commit_outcome_goes_to_rejoin_marked_member_devices() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let dave = register(&h, "dave", 4).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // #888: 승인을 relay 가 처리한 뒤 붙는다 — 붙은 뒤 처리되면 승인 닫기로 그 연결이 닫힌다(간헐 Close).
    certify(&mut a, &alice, &alice_b).await;
    let (mut bc, _) = connect(&h, &alice_b).await;
    let (mut dc, _) = connect(&h, &dave).await;
    let now = h.fx.clock.now().0;
    assert!(h.app.db.rejoin_mark(&alice_b.device_id, &gid, now).unwrap());
    assert!(h.app.db.rejoin_mark(&dave.device_id, &gid, now).unwrap());
    let epoch = g.epoch().as_u64();
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let hash = commit_hash(bundle.commit());
    let up = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
        }),
        json!({"group_op": "update", "base_seq": 2}),
    );
    assert_eq!(send(&mut a, &up).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    let f = next_of(&mut bc, "commit_final").await;
    assert_eq!(
        (f["epoch"].as_u64(), f["commit_hash"].as_str()),
        (Some(epoch), Some(hash.as_str())),
        "{f}"
    );
    while let Ok(Some(Ok(Message::Text(t)))) =
        tokio::time::timeout(Duration::from_millis(300), dc.ws.next()).await
    {
        assert!(!t.contains("\"commit_final\""), "멤버 아닌 사람: {t}");
    }
}

/// 확정 전 Commit 의 N+1 응용 메시지는 쥐었다가, 창이 끝나고 ack 0 + fail 사용자 둘이면 무효 — 옛 잎에 commit_void, 쥔 메시지는
/// 보낸 기기에 nack commit_void(꺼져 있으면 접속 때 마지막 결과보다 먼저).
#[tokio::test(flavor = "multi_thread")]
async fn group_commit_void_returns_held_messages() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd, dd) = (
        Dev::of(&alice),
        Dev::of(&bob),
        Dev::of(&carol),
        Dev::of(&dave),
    );
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let _ = next_of(&mut c, "deliver").await;
    let _ = next_of(&mut b, "commit_final").await;

    // epoch 2 → dave add(확정 전), alice 는 자기 Commit 을 merge 해 epoch 3 응용 메시지를 보낸다 → 쥠.
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &dave, &dd, 3);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let app_msg = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "chat",
        &gid,
        3,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({}),
    );
    assert_eq!(send(&mut a, &app_msg).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await; // 확정 전 Commit
    b.expect_silence().await; // 쥔 응용 메시지는 아직
                              // epoch 밖(지금 + 2)은 stale_epoch.
    let far = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "chat",
        &gid,
        4,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({}),
    );
    assert_eq!(send(&mut a, &far).await["reason"], "stale_epoch");
    drop(a);
    for cl in [&mut b, &mut c] {
        cl.send(&json!({"t": "commit_fail", "group": gid, "epoch": 2, "commit_hash": hash}))
            .await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await; // 응답이 relay 에 닿게
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let v = next_of(&mut b, "commit_void").await;
    assert_eq!(
        (v["epoch"].as_u64(), v["commit_hash"].as_str()),
        (Some(2), Some(hash.as_str())),
        "{v}"
    );
    b.expect_silence().await; // 쥔 메시지는 배달되지 않음
                              // 꺼져 있던 alice: 접속 때 nack commit_void → 마지막 결과(void).
    let (mut a, _) = connect(&h, &alice).await;
    let n = next_of(&mut a, "nack").await;
    assert_eq!(
        (n["msg_id"].clone(), n["reason"].as_str()),
        (app_msg["msg_id"].clone(), Some("commit_void"))
    );
    let v = next_of(&mut a, "commit_void").await;
    assert_eq!(v["epoch"].as_u64(), Some(2));
}

/// #599 후속(백엔드 검토 6518326981): 지금 끊기 — A 가 새 기기 B 를 add(확정 전)한 뒤 자기를 끊으면, 그 Commit 은 확정될 길이 없으니
/// 시계를 움직이지 않아도 바로 무효가 되고 B 에 rejoin_needed 가 간다(창 판정의 1시간을 기다리며 B 의 external commit 이
/// stale_epoch 로 막히지 않게). 이미 ack 를 받은 Commit 은 무효로 하지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_voids_pending_commit_from_that_device_at_once() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // #888: 승인을 relay 가 처리한 뒤 붙는다 — 붙은 뒤 처리되면 승인 닫기로 그 연결이 닫힌다(간헐 Close).
    certify(&mut a, &alice, &alice_b).await;
    let (mut bc, _) = connect(&h, &alice_b).await;
    let epoch = g.epoch().as_u64();
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice_b).key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
        json!({"group_op": "update", "base_seq": 2}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let proof = revoke_proof(&h, &alice, &alice, h.fx.clock.now().0);
    a.send(&json!({"t": "device.revoke", "proof": proof})).await;
    // 시계·창 판정 없이 바로.
    assert_eq!(
        next_of(&mut b, "commit_void").await["epoch"].as_u64(),
        Some(epoch)
    );
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());
    assert_eq!(
        next_of(&mut bc, "rejoin_needed").await["groups"],
        json!([gid])
    );
}

/// #599 후속(설계 리뷰 🟡 6518544153 ②): 폐기 자리를 거치지 않은 길(폐기 뒤 남은 연결로 온 Commit·조직 나가기·내보내기)도 창 판정이
/// 받친다 — 보낸 기기가 폐기됐고 ack 가 없으면 창(60초)을 기다리지 않고 다음 판정에서 무효.
#[tokio::test(flavor = "multi_thread")]
async fn tick_voids_pending_commit_of_revoked_sender_without_window() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // #888: 승인을 relay 가 처리한 뒤 붙는다 — 붙은 뒤 처리되면 승인 닫기로 그 연결이 닫힌다(간헐 Close).
    certify(&mut a, &alice, &alice_b).await;
    let _bc = connect(&h, &alice_b).await;
    let epoch = g.epoch().as_u64();
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice_b).key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
        json!({"group_op": "update", "base_seq": 2}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // 폐기 자리(ws)를 거치지 않고 저장소에서만 폐기 — 무효 처리가 지나간 뒤 남은 꼴.
    h.app
        .db
        .revoke_device(&alice.device_id, h.fx.clock.now().0, None)
        .unwrap();
    assert!(h.app.db.mls_pending(&gid).unwrap().is_some());
    // 시계를 움직이지 않은 다음 판정에서 무효.
    h.app.expire_tick();
    assert_eq!(
        next_of(&mut b, "commit_void").await["epoch"].as_u64(),
        Some(epoch)
    );
    assert!(h.app.db.mls_pending(&gid).unwrap().is_none());
}

/// #599 후속: 폐기된 기기의 확정 전 Commit 이라도 이미 ack 를 받았으면 무효로 하지 않는다(창 끝에 확정).
#[tokio::test(flavor = "multi_thread")]
async fn revoke_keeps_acked_pending_commit() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 4).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    // carol 은 붙은 채 ack 하지 않는다 — 연결된 투표자만 세므로(hosted 11-04 A) 오프라인이면 bob 하나로 바로 확정된다.
    let (_c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // 응답할 사람을 둘(bob·carol)로 — 하나만 ack 한 채 남게(연결된 전원 ack 면 바로 확정, #599·A).
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    let _ = next_of(&mut b, "commit_final").await;
    // #888: 승인을 relay 가 처리한 뒤 붙는다 — 붙은 뒤 처리되면 승인 닫기로 그 연결이 닫힌다(간헐 Close).
    certify(&mut a, &alice, &alice_b).await;
    let (_bc, _) = connect(&h, &alice_b).await;
    let epoch = g.epoch().as_u64();
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(&alice_b).key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let hash = commit_hash(&commit);
    let m = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
        json!({"group_op": "update", "base_seq": 3}),
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let proof = revoke_proof(&h, &alice, &alice, h.fx.clock.now().0);
    a.send(&json!({"t": "device.revoke", "proof": proof})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        h.app.db.mls_pending(&gid).unwrap().is_some(),
        "ack 받은 것은 남긴다"
    );
}

/// pair 응용 메시지의 헤더 첨부(묶음 15 blobs)는 그 메시지에 묶이고, 받는 잎이 blob.get 으로 받는다(§5d — 배달된 잎 기준).
/// 남이 올린 blob 은 blob_unavailable.
#[tokio::test(flavor = "multi_thread")]
async fn pair_app_header_blobs_are_bound_for_leaves() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = b.recv().await;
    let file = upload_mls(&h, &mut a, b"attached bytes").await;
    let id = file["blob"]["blob_id"].as_str().unwrap().to_owned();
    let bobs = upload_mls(&h, &mut b, b"not alice's").await;
    let bid = bobs["blob"]["blob_id"].as_str().unwrap().to_owned();
    let app = |blob: &str| {
        let mut m = mls_msg(
            &h,
            &alice,
            &bob.address(),
            "chat",
            &gid,
            g.epoch().as_u64(),
            json!({"enc": "mls", "wire": "app", "payload": data(&[3u8; 80])}),
        );
        m["blobs"] = json!([blob]);
        m.as_object_mut().unwrap().remove("sig");
        sign_message(&mut m, &alice.keys.signing).unwrap();
        m
    };
    assert_eq!(send(&mut a, &app(&bid)).await["reason"], "blob_unavailable");
    let m = app(&id);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let d = next_of(&mut b, "deliver").await;
    assert_eq!(d["message"]["msg_id"], m["msg_id"]);
    let (code, got) = fetch_blob(&h, &mut b, &id).await;
    assert_eq!((code, got.as_slice()), (200, b"attached bytes".as_slice()));
}

/// GroupInfo = Commit 결과(§12-18): 그룹 id·epoch 는 맞지만 트리가 다른(같은 기기 키로 서명한 다른 그룹의) GroupInfo 를 실은
/// Commit 은 invalid_commit, 맞는 GroupInfo 로 다시 보내면 ack.
#[tokio::test(flavor = "multi_thread")]
async fn commit_group_info_must_match_merged_state() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let epoch = g.epoch().as_u64();
    // 같은 키·같은 id 로 따로 만든 그룹을 같은 epoch 까지.
    let other_dev = Dev::of(&alice);
    let mut other = other_dev.create(Kind::Pair, &gid);
    while other.epoch().as_u64() < epoch + 1 {
        other
            .self_update(
                &other_dev.provider,
                &other_dev.signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        other.merge_pending_commit(&other_dev.provider).unwrap();
    }
    let bundle = g
        .self_update(&ad.provider, &ad.signer, LeafNodeParameters::default())
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let payload = data(&bundle.commit().tls_serialize_detached().unwrap());
    let msg = |gi: Vec<u8>| {
        mls_msg(
            &h,
            &alice,
            &bob.address(),
            "mls",
            &gid,
            epoch,
            json!({"enc": "mls", "wire": "commit", "payload": payload.clone(), "group_info": data(&gi)}),
        )
    };
    let r = send(&mut a, &msg(other_dev.group_info(&other))).await;
    assert_eq!(r["reason"], "invalid_commit", "{r}");
    let r = send(&mut a, &msg(ad.group_info(&g))).await;
    assert_eq!(r["t"], "ack", "{r}");
}

/// 고치기(§12-18): MLS 응용 메시지도 edits 가 원 메시지의 아직 안 받은 몫을 지운다 — 꺼져 있던 bob 은 고친 글만 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn mls_edit_drops_undelivered_original() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let app = |extra: Option<&str>| {
        let mut m = mls_msg(
            &h,
            &alice,
            &bob.address(),
            "chat",
            &gid,
            g.epoch().as_u64(),
            json!({"enc": "mls", "wire": "app", "payload": data(&[5u8; 80])}),
        );
        // chat 은 판 10 칸이 없어 v9 — 꺼져 있던 bob(판 모름 = 9)에게도 간다(#598 ②, v10 이면 recipient_outdated).
        m["v"] = json!(9);
        if let Some(x) = extra {
            m["edits"] = json!(x);
        }
        m.as_object_mut().unwrap().remove("sig");
        sign_message(&mut m, &alice.keys.signing).unwrap();
        m
    };
    let first = app(None);
    assert_eq!(send(&mut a, &first).await["t"], "ack");
    let edit = app(first["msg_id"].as_str());
    assert_eq!(send(&mut a, &edit).await["t"], "ack");
    let (mut b, _) = connect(&h, &bob).await;
    let mut got = Vec::new();
    loop {
        let f = b.recv().await;
        if f["t"] == "deliver" && f["message"]["kind"] == "chat" {
            got.push(f["message"]["msg_id"].clone());
            if f["message"]["msg_id"] == edit["msg_id"] {
                break;
            }
        }
    }
    assert_eq!(got, vec![edit["msg_id"].clone()]);
}

/// 확정 뒤 서로 다른 둘이 commit_fail(§4-7·§12-20): 그룹 관리자 기기에 group_alert{sender, n, acked} 한 번 — 꺼져 있었으면 접속 때.
#[tokio::test(flavor = "multi_thread")]
async fn group_alert_after_final_fails() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (mut d, _) = connect(&h, &dave).await;
    let (ad, bd, cd, dd) = (
        Dev::of(&alice),
        Dev::of(&bob),
        Dev::of(&carol),
        Dev::of(&dave),
    );
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    for (who, wd, seq) in [(&carol, &cd, 2u64), (&dave, &dd, 3)] {
        let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, who, wd, seq);
        assert_eq!(send(&mut a, &m).await["t"], "ack");
        let epoch = g.epoch().as_u64() - 1;
        b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.fx.clock.advance(61_000);
        h.app.expire_tick();
        let _ = next_of(&mut b, "commit_final").await;
        if seq == 3 {
            drop(a);
            // carol·dave 가 확정 뒤 처리 못 함.
            for cl in [&mut c, &mut d] {
                cl.send(
                    &json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}),
                )
                .await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            let (mut a, _) = connect(&h, &alice).await;
            let f = next_of(&mut a, "group_alert").await;
            assert_eq!(
                (
                    f["reason"].as_str(),
                    f["sender"].as_str(),
                    f["n"].as_u64(),
                    f["acked"].clone(),
                    f["commit_hash"].as_str()
                ),
                (
                    Some("commit_unprocessed"),
                    Some("alice@local"),
                    Some(2),
                    json!(["bob@local"]),
                    Some(hash.as_str())
                ),
                "{f}"
            );
            // #819: duty_stuck 칸을 더했어도 commit_unprocessed 꼴은 옛 앱이 푸는 그대로(옛 GroupAlert 는 deny_unknown_fields —
            // 새 칸이 null 로라도 실리면 옛 앱이 이 줄까지 버린다).
            let mut keys: Vec<&str> = f.as_object().unwrap().keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "acked",
                    "commit_hash",
                    "epoch",
                    "group",
                    "n",
                    "reason",
                    "sender",
                    "t"
                ],
                "{f}"
            );
            // 한 번만: 같은 Commit 의 fail 이 더 와도 다시 보내지 않는다.
            b.send(&json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}))
                .await;
            a.expect_silence().await;
            return;
        }
    }
}

/// MLS 응용 메시지 크기(§12-17): 평문 상한 = kind 상한 + 64(머리) + 1 024 × 헤더 blobs, payload 는 거기에 MLS 덧붙음.
#[tokio::test(flavor = "multi_thread")]
async fn mls_app_size_cap() {
    use lodelai_relay::frames::{MLS_APP_OVERHEAD, MLS_PLAINTEXT_HEAD_BYTES};
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let max = lodelai_protocol::constants::BODY_MAX_BYTES_CHAT as usize
        + MLS_PLAINTEXT_HEAD_BYTES
        + MLS_APP_OVERHEAD;
    let app = |n: usize| {
        mls_msg(
            &h,
            &alice,
            &bob.address(),
            "chat",
            &gid,
            g.epoch().as_u64(),
            json!({"enc": "mls", "wire": "app", "payload": data(&vec![1u8; n])}),
        )
    };
    assert_eq!(send(&mut a, &app(max)).await["t"], "ack");
    assert_eq!(send(&mut a, &app(max + 1)).await["reason"], "too_large");
}

/// 조직 빠짐(§12-13 ②): 나간 사람의 잎이 남은 그룹마다 남은 접속 기기에 duty remove_user(subject = 사람 주소) — 받은 기기가
/// group_op=org_left·subject=그 사람 Commit 을 낸다(관리자 아니어도, 보낸 사람 ≠ subject).
#[tokio::test(flavor = "multi_thread")]
async fn org_left_gives_remove_user_duty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let mut h = start_db(|c| c.groups = true, Db::open(&path).unwrap()).await;
    h.db_file = Some((dir, path.clone()));
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    // 나가기(member.leave)는 hosted 조직만 — 지금 조직을 orgs 표에 올린다(관리자 alice).
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch(
            "INSERT INTO orgs(org_id, name, admin, created_ms)
               SELECT org, 'org', 'alice', 0 FROM users WHERE user = 'alice';
             INSERT INTO org_admins(org_id, user) SELECT org, 'alice' FROM users WHERE user = 'alice';",
        )
        .unwrap();
    }
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let _ = next_of(&mut b, "commit_final").await;
    // #816 ①: 나가기 전에 남은 다시 들기 표시는 조직 빠짐 때 지운다.
    let now = h.fx.clock.now().0;
    assert!(h.app.db.rejoin_mark(&carol.device_id, &gid, now).unwrap());
    c.send(&json!({"t": "member.leave"})).await;
    let duty = next_of(&mut b, "duty").await;
    assert!(h.app.db.rejoin_for(&carol.device_id).unwrap().is_empty());
    assert_eq!(
        (
            duty["task"].as_str(),
            duty["subject"].as_str(),
            duty["group"].as_str()
        ),
        (Some("remove_user"), Some("carol@local"), Some(gid.as_str())),
        "{duty}"
    );
    let _ = next_of(&mut a, "duty").await;
    // 16 §3a ④ 조직 빠짐 힌트: 남은 멤버에게 groups{items[].org_left}.
    let gf = next_of(&mut b, "groups").await;
    assert_eq!(gf["items"][0]["org_left"][0]["user"], "carol@local", "{gf}");
}

/// 모바일 검증 S3: hello.no_duty 연결(휴대폰)은 접속해 있어도 duty 후보가 아니다 — 다른 접속 후보(맥)에만 간다.
#[tokio::test(flavor = "multi_thread")]
async fn no_duty_connection_gets_no_duty() {
    no_duty_case(true).await;
}

/// 서버 고르기 §3: 푸시를 못 켜는 자체 서버에서도 같다(no_duty 는 푸시와 무관).
#[tokio::test(flavor = "multi_thread")]
async fn no_duty_holds_without_push() {
    no_duty_case(false).await;
}

async fn no_duty_case(mobile_push: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let mut h = start_db(
        |c| {
            c.groups = true;
            c.mobile_push = mobile_push;
            c.duty_log = true;
        },
        Db::open(&path).unwrap(),
    )
    .await;
    h.db_file = Some((dir, path.clone()));
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch(
            "INSERT INTO orgs(org_id, name, admin, created_ms)
               SELECT org, 'org', 'alice', 0 FROM users WHERE user = 'alice';
             INSERT INTO org_admins(org_id, user) SELECT org, 'alice' FROM users WHERE user = 'alice';",
        )
        .unwrap();
    }
    let (mut a, _) = connect(&h, &alice).await;
    // bob 은 휴대폰처럼 no_duty 로 붙는다.
    let mut b = Client {
        ws: ws_raw(h.addr).await,
    };
    b.send(&json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": bob.device_id, "user": bob.name, "no_duty": true}))
        .await;
    let ch = b.recv().await;
    assert_eq!(ch["t"], "challenge", "{ch}");
    let sig = sign_challenge(
        &bob.keys.signing,
        SERVER,
        &bob.device_id,
        ch["nonce"].as_str().unwrap(),
    )
    .unwrap();
    b.send(&json!({"t": "auth", "sig": sig})).await;
    assert_eq!(b.recv().await["t"], "ready");
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let _ = next_of(&mut b, "commit_final").await;
    c.send(&json!({"t": "member.leave"})).await;
    let duty = next_of(&mut a, "duty").await;
    assert_eq!(duty["task"], "remove_user", "{duty}");
    let ranked: Vec<String> = h
        .app
        .db
        .duty_ranks(&gid, "remove_user", "carol")
        .unwrap()
        .into_iter()
        .map(|(d, _)| d)
        .collect();
    // 시험 relay 는 보낸 duty 를 적는다 — 휴대폰(bob) 앞은 없다(실기 판정 duty-log 와 같은 표).
    let sent = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT group_concat(DISTINCT device_id) FROM mls_duty_sent",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap();
    assert_eq!(sent.as_deref(), Some(alice.device_id.as_str()));
    assert_eq!(
        ranked,
        std::slice::from_ref(&alice.device_id),
        "no_duty 연결(bob)은 후보가 아니다"
    );

    // 휴대폰이 첫 기기(설계 ③): 붙은 후보가 no_duty 연결뿐이면 그 연결이 받는다 — 일이 orphan 까지 서지 않게.
    drop(a);
    until_offline(&h, "alice").await;
    lodelai_relay::mls::dispatch_duties(&h.app, None);
    let duty = next_of(&mut b, "duty").await;
    assert_eq!(duty["task"], "remove_user", "{duty}");
}

/// 모바일 검증: push.register 는 `--mobile-push` relay 만, 토큰 꼴을 보고 기기당 한 행. salt·key 는 등록마다 새로,
/// unregister·기기 폐기 때 지운다.
#[tokio::test(flavor = "multi_thread")]
async fn push_register_keeps_one_checked_token_per_device() {
    let h = start_with(|c| {
        c.mobile_push = true;
        c.push_app_ids = vec!["com.example.app".into()];
    })
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    let apns = "ab".repeat(32);
    let reg = |req: &str, platform: &str, token: &str, env: &str| json!({"t": "push.register", "req": req, "platform": platform, "token": token, "env": env, "app_id": "com.example.app"});
    a.send(&reg("r1", "apns", &apns, "sandbox")).await;
    let ok = a.recv().await;
    assert_eq!(
        (ok["t"].as_str(), ok["req"].as_str()),
        (Some("push.ok"), Some("r1")),
        "{ok}"
    );
    let (salt, key) = (
        ok["salt"].as_str().unwrap().to_owned(),
        ok["key"].as_str().unwrap().to_owned(),
    );
    assert_eq!((salt.len(), key.len()), (22, 43));
    let row = h.app.db.push_token(&alice.device_id).unwrap().unwrap();
    assert_eq!(
        (row.platform.as_str(), row.token.as_str(), row.env.as_str()),
        ("apns", apns.as_str(), "sandbox")
    );
    assert_eq!((row.salt.len(), row.key.len()), (16, 32));
    // 다시 등록하면 같은 행을 바꾸고 salt·key 도 새로.
    a.send(&reg("r2", "fcm", "fcm_tok:AB-c", "prod")).await;
    let ok2 = a.recv().await;
    assert_eq!(ok2["t"], "push.ok", "{ok2}");
    assert_ne!(ok2["salt"], ok["salt"]);
    assert_ne!(ok2["key"], ok["key"]);
    assert_eq!(
        h.app
            .db
            .push_token(&alice.device_id)
            .unwrap()
            .unwrap()
            .platform,
        "fcm"
    );
    // 꼴이 틀리면 ref 붙은 protocol 오류, 행은 그대로.
    for (req, frame) in [
        ("b1", reg("b1", "apns", "zz", "sandbox")),
        ("b2", reg("b2", "apns", &format!("{apns}/x"), "sandbox")),
        ("b3", reg("b3", "fcm", "a b", "prod")),
        ("b4", reg("b4", "fcm", "tok", "sandbox")),
        ("b5", {
            let mut f = reg("b5", "fcm", "tok", "prod");
            f["app_id"] = json!("com.other.app");
            f
        }),
    ] {
        a.send(&frame).await;
        let e = a.recv().await;
        assert_eq!(
            (e["t"].as_str(), e["code"].as_str(), e["ref"].as_str()),
            (Some("error"), Some("protocol"), Some(req)),
            "{e}"
        );
    }
    assert_eq!(
        h.app
            .db
            .push_token(&alice.device_id)
            .unwrap()
            .unwrap()
            .token,
        "fcm_tok:AB-c"
    );
    a.send(&json!({"t": "push.unregister", "req": "u1"})).await;
    let ok = a.recv().await;
    assert_eq!(
        (ok["t"].as_str(), ok["req"].as_str()),
        (Some("push.ok"), Some("u1")),
        "{ok}"
    );
    assert!(ok.get("salt").is_none() && ok.get("key").is_none());
    assert!(h.app.db.push_token(&alice.device_id).unwrap().is_none());
    // 같은 OS 토큰에 기기 여럿(휴대폰 한 대의 여러 계정) — bob 이 alice 가 쥔 토큰을 등록해도 alice 행은 남는다.
    a.send(&reg("r3", "apns", &apns, "prod")).await;
    assert_eq!(a.recv().await["t"], "push.ok");
    let bob = register(&h, "bob", 2).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&reg("r4", "apns", &apns, "prod")).await;
    assert_eq!(b.recv().await["t"], "push.ok");
    assert_eq!(
        h.app
            .db
            .push_token(&alice.device_id)
            .unwrap()
            .unwrap()
            .token,
        apns
    );
    assert_eq!(
        h.app.db.push_token(&bob.device_id).unwrap().unwrap().token,
        apns
    );
    assert_eq!(h.app.db.push_token_devices("apns", &apns).unwrap(), 2);
    // 기기 폐기 때 같이 지운다.
    a.send(&reg("r5", "apns", &"cd".repeat(32), "prod")).await;
    let _ = next_of(&mut a, "push.ok").await;
    h.app
        .db
        .revoke_device(&alice.device_id, h.fx.clock.now().0, None)
        .unwrap();
    assert!(h.app.db.push_token(&alice.device_id).unwrap().is_none());
}

/// 휴대폰 여러 계정: 한 OS 토큰은 상한(5)까지 — 넘으면 가장 오래 전에 등록한 기기부터 빠진다. 애플·구글이 '없는 토큰'이라 하면
/// 그 토큰의 행이 모두 빠진다.
#[tokio::test(flavor = "multi_thread")]
async fn push_token_holds_up_to_five_accounts() {
    let h = start_with(|c| {
        c.mobile_push = true;
        c.push_app_ids = vec!["com.example.app".into()];
    })
    .await;
    let apns = "ef".repeat(32);
    let mut devices = Vec::new();
    for (i, name) in ["u1", "u2", "u3", "u4", "u5", "u6"].into_iter().enumerate() {
        let u = register(&h, name, u8::try_from(i).unwrap() + 1).await;
        let (mut s, _) = connect(&h, &u).await;
        s.send(&json!({"t": "push.register", "req": "r", "platform": "apns", "token": apns, "env": "prod", "app_id": "com.example.app"}))
            .await;
        assert_eq!(next_of(&mut s, "push.ok").await["req"], "r");
        devices.push(u.device_id.clone());
        h.fx.clock.advance(10);
    }
    assert_eq!(h.app.db.push_token_devices("apns", &apns).unwrap(), 5);
    assert!(
        h.app.db.push_token(&devices[0]).unwrap().is_none(),
        "가장 오래된 등록이 빠짐"
    );
    for d in &devices[1..] {
        assert!(h.app.db.push_token(d).unwrap().is_some());
    }
    assert!(h.app.db.push_token_drop_if(&devices[5], &apns).unwrap());
    assert_eq!(h.app.db.push_token_devices("apns", &apns).unwrap(), 0);
}

/// 받은 요청을 남기고 정해 둔 응답을 차례로 주는 가짜 푸시 전송(네트워크 없음).
#[derive(Default)]
struct FakePush {
    seen: std::sync::Mutex<Vec<lodelai_relay::push::Request>>,
    replies: std::sync::Mutex<Vec<lodelai_relay::push::Response>>,
}

impl lodelai_relay::push::Transport for FakePush {
    fn post(
        &self,
        req: lodelai_relay::push::Request,
    ) -> lodelai_relay::push::BoxFuture<'_, std::io::Result<lodelai_relay::push::Response>> {
        self.seen.lock().unwrap().push(req);
        let mut r = self.replies.lock().unwrap();
        let next = if r.is_empty() {
            lodelai_relay::push::Response {
                status: 200,
                headers: vec![],
                body: br#"{"name":"m"}"#.to_vec(),
            }
        } else {
            r.remove(0)
        };
        Box::pin(async move { Ok(next) })
    }
}

struct NoSign;
impl lodelai_relay::push::Rs256Signer for NoSign {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, lodelai_relay::push::PushError> {
        Ok(vec![0; 8])
    }
}

fn fcm_sends(fake: &FakePush) -> Vec<Value> {
    fake.seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.host == "fcm.googleapis.com")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

async fn wait_fcm_sends(fake: &FakePush, n: usize) -> Vec<Value> {
    for _ in 0..250 {
        let v = fcm_sends(fake);
        if v.len() >= n {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("푸시 {n}개가 나가지 않음: {:?}", fcm_sends(fake));
}

/// 모바일 검증 ④: 접속 안 한 받는 기기 앞 그룹 응용 메시지가 보관되면 그 기기 토큰으로 푸시 하나 — 대화 값은 그 기기 salt 의
/// conv_tag, 본문 p 는 그 기기 push 키로 풀려 (msg_id, MLS 바이트). 접속한 기기에는 보내지 않고, 같은 대화 2초 안에 더 온
/// 글은 창 끝에 가장 늦은 하나만 보낸다.
#[tokio::test(flavor = "multi_thread")]
async fn stored_app_message_pushes_offline_device_with_two_second_trailing_window() {
    let h = start_with(|c| {
        c.groups = true;
        c.mobile_push = true;
        c.push_app_ids = vec!["com.example.app".into()];
    })
    .await;
    let fake = std::sync::Arc::new(FakePush::default());
    fake.replies
        .lock()
        .unwrap()
        .push(lodelai_relay::push::Response {
            status: 200,
            headers: vec![],
            body: br#"{"access_token":"at","expires_in":3600}"#.to_vec(),
        });
    let fcm = lodelai_relay::push::Fcm::with_signer(
        "proj",
        "svc@proj.iam.gserviceaccount.com",
        "https://oauth2.googleapis.com/token",
        Box::new(NoSign),
    )
    .unwrap();
    std::sync::Arc::new(lodelai_relay::push::Outbox::new(
        lodelai_relay::push::Sender {
            apns: None,
            fcm: Some(fcm),
            transport: fake.clone(),
        },
    ))
    .install(&h.app);
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    // bob 이 Welcome 을 받고(받은 Handshake 가 남지 않게) 푸시 토큰을 등록한 뒤 끊는다.
    let welcome = next_of(&mut b, "deliver").await;
    assert!(
        h.app.db.handshake_waiting(&bob.device_id, &gid).unwrap(),
        "받지 않은 Welcome 이 있으면 빈 깨우기 쪽"
    );
    b.send(&json!({"t": "delivered_ack", "msg_id": welcome["message"]["msg_id"]}))
        .await;
    b.send(
        &json!({"t": "push.register", "req": "r1", "platform": "fcm", "token": "bob-fcm-token",
        "env": "prod", "app_id": "com.example.app"}),
    )
    .await;
    let ok = next_of(&mut b, "push.ok").await;
    let salt = encoding::decode(ok["salt"].as_str().unwrap(), "salt").unwrap();
    let key: [u8; 32] = encoding::decode_array(ok["key"].as_str().unwrap(), "key").unwrap();
    drop(b);
    until_offline(&h, "bob").await;
    assert!(
        !h.app.db.handshake_waiting(&bob.device_id, &gid).unwrap(),
        "받은 Welcome 은 남지 않는다"
    );
    let m1 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m1).await["t"], "ack");
    let sent = wait_fcm_sends(&fake, 1).await;
    let msg = &sent[0]["message"];
    assert_eq!(msg["token"], "bob-fcm-token");
    let conv = lodelai_relay::push::conv_tag(&salt, &gid);
    // FCM 은 접지 않는다(Android 실기 11-06 — 몰아 보내기 20개 제한·앞 글 p 버림). 대화는 data.conv 로만.
    assert!(msg["android"].get("collapse_key").is_none(), "{msg}");
    assert_eq!(msg["data"]["conv"], conv.as_str());
    let (id, bytes) = lodelai_relay::push::open(&key, msg["data"]["p"].as_str().unwrap())
        .expect("p 가 bob 키로 풀린다");
    assert_eq!(id, m1["msg_id"].as_str().unwrap());
    assert_eq!(bytes, [9u8; 64], "gapp 의 MLS 바이트");
    // 같은 대화 2초 안에 더 온 글(m2·m3)은 창 끝에 가장 늦은 하나(m3)만 — m2 는 밀린다.
    let m2 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m2).await["t"], "ack");
    let m3 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m3).await["t"], "ack");
    assert_eq!(fcm_sends(&fake).len(), 1, "창 안에서는 바로 보내지 않는다");
    let sent = wait_fcm_sends(&fake, 2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fcm_sends(&fake).len(), 2, "창 끝에 한 번");
    let (id, _) =
        lodelai_relay::push::open(&key, sent[1]["message"]["data"]["p"].as_str().unwrap()).unwrap();
    assert_eq!(id, m3["msg_id"].as_str().unwrap(), "가장 늦은 글");
    let out = h.app.push.get().unwrap();
    assert_eq!(
        out.counts
            .limited
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    // 창 안에 밀린 글이 있어도 창 끝 전에 앱을 열어 접속했으면 보내지 않는다(배너 하나 더 없음).
    h.fx.clock.advance(4_000);
    let m5 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m5).await["t"], "ack");
    let _ = wait_fcm_sends(&fake, 3).await;
    let m6 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m6).await["t"], "ack");
    let (b2, _) = connect(&h, &bob).await;
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    assert_eq!(
        fcm_sends(&fake).len(),
        3,
        "접속한 기기에는 창 끝에 보내지 않는다"
    );
    drop(b2);
    until_offline(&h, "bob").await;
    // 토큰이 더는 맞지 않으면(UNREGISTERED) 만료 tick 이 그 행을 지운다.
    fake.replies
        .lock()
        .unwrap()
        .push(lodelai_relay::push::Response {
            status: 404,
            headers: vec![],
            body: br#"{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}"#.to_vec(),
        });
    h.fx.clock.advance(4_000);
    let m4 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m4).await["t"], "ack");
    let _ = wait_fcm_sends(&fake, 4).await;
    for _ in 0..100 {
        if out
            .counts
            .token_gone
            .load(std::sync::atomic::Ordering::Relaxed)
            == 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    h.app.expire_tick();
    assert!(h.app.db.push_token(&bob.device_id).unwrap().is_none());
}

/// 모바일 검증 ④: 확정을 기다리며 붙잡아 둔 N+1 글은 확정 배달 때 꺼진 휴대폰에 알린다(확정 전 0, 뒤 1).
#[tokio::test(flavor = "multi_thread")]
async fn held_app_message_pushes_when_commit_finalizes() {
    let h = start_with(|c| {
        c.groups = true;
        c.mobile_push = true;
        c.push_app_ids = vec!["com.example.app".into()];
    })
    .await;
    let fake = std::sync::Arc::new(FakePush::default());
    fake.replies
        .lock()
        .unwrap()
        .push(lodelai_relay::push::Response {
            status: 200,
            headers: vec![],
            body: br#"{"access_token":"at","expires_in":3600}"#.to_vec(),
        });
    let fcm = lodelai_relay::push::Fcm::with_signer(
        "proj",
        "svc@proj.iam.gserviceaccount.com",
        "https://oauth2.googleapis.com/token",
        Box::new(NoSign),
    )
    .unwrap();
    std::sync::Arc::new(lodelai_relay::push::Outbox::new(
        lodelai_relay::push::Sender {
            apns: None,
            fcm: Some(fcm),
            transport: fake.clone(),
        },
    ))
    .install(&h.app);
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut d, _) = connect(&h, &dave).await;
    let (ad, bd, cd, dd) = (
        Dev::of(&alice),
        Dev::of(&bob),
        Dev::of(&carol),
        Dev::of(&dave),
    );
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &dave, &dd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut d, "deliver").await;
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut d, "deliver").await;
    d.send(&json!({"t": "commit_ack", "group": gid, "epoch": 1, "commit_hash": hash}))
        .await;
    let _ = next_of(&mut d, "commit_final").await;
    let welcome = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "delivered_ack", "msg_id": welcome["message"]["msg_id"]}))
        .await;
    b.send(
        &json!({"t": "push.register", "req": "r1", "platform": "fcm", "token": "bob-fcm-token",
        "env": "prod", "app_id": "com.example.app"}),
    )
    .await;
    let _ = next_of(&mut b, "push.ok").await;
    drop(b);
    until_offline(&h, "bob").await;
    // carol 넣기 Commit 이 확정을 기다리는 동안(bob 은 꺼짐, 연결된 투표자 dave 는 아직 표 없음 — #846 뒤로는 연결된 투표자가
    // 없으면 바로 확정이라 dave 로 붙잡는다) alice 가 N+1 글을 쓴다 — 붙잡힌다.
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 3);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let held = gapp(&h, &alice, &gid, 3, json!({}));
    assert_eq!(send(&mut a, &held).await["t"], "ack");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fcm_sends(&fake).is_empty(), "확정 전에는 알리지 않는다");
    let _ = next_of(&mut d, "deliver").await;
    d.send(&json!({"t": "commit_ack", "group": gid, "epoch": 2, "commit_hash": hash}))
        .await;
    let sent = wait_fcm_sends(&fake, 1).await;
    assert_eq!(sent[0]["message"]["token"], "bob-fcm-token");
}

/// `--mobile-push` 가 없는 relay 는 push.register 를 받지 않는다(기능 표시도 없음).
#[tokio::test(flavor = "multi_thread")]
async fn push_register_needs_mobile_push_relay() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    a.send(&json!({"t": "push.register", "req": "r1", "platform": "apns", "token": "ab".repeat(32), "env": "sandbox", "app_id": "com.example.app"}))
        .await;
    let e = a.recv().await;
    assert_eq!(
        (e["code"].as_str(), e["ref"].as_str()),
        (Some("protocol"), Some("r1")),
        "{e}"
    );
    assert!(h.app.db.push_token(&alice.device_id).unwrap().is_none());
    let off = lodelai_relay::ws::features_header_value(&h.app.config, true);
    assert!(!off.to_str().unwrap().contains("push"));
    let mut on = h.app.config.clone();
    on.mobile_push = true;
    let v = lodelai_relay::ws::features_header_value(&on, true);
    assert_eq!(
        v.to_str().unwrap(),
        "groups,device_name,device_os,kp_reset,unreadable_ack,push,push_prefs,push_multi,no_duty,own_live,own_control,own_alert_kinds,history_transfer,org_leave,link_unblock,link_block,org_color,lists,org_external,org_external_preview,look,contacts,org_move,mutes,pins,away,next_turn"
    );
}

// ------------------------------------------------------------------ 16 그룹 표 의미를 MLS 로(groups.rs 에서 옮김, ⑧)

/// 그룹 응용 메시지(지금 epoch). `extra` 는 헤더 덧붙임.
fn gapp(h: &Harness, from: &User, gid: &str, epoch: u64, extra: Value) -> Value {
    gmsg(
        h,
        from,
        &gaddr(gid),
        "chat",
        gid,
        epoch,
        json!({"enc": "mls", "wire": "app", "payload": data(&[9u8; 64])}),
        extra,
    )
}

/// alice 의 remove Commit(그 사람 잎 전부).
fn remove_msg(
    h: &Harness,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    gid: &str,
    who: &User,
    base_seq: u64,
) -> (Value, String) {
    remove_msg_op(h, alice, ad, g, gid, who, base_seq, "remove")
}

/// 그 사람 잎을 모두 빼는 alice 의 Commit — 헤더 op 는 `op`(remove·leave·org_left).
#[allow(clippy::too_many_arguments)]
fn remove_msg_op(
    h: &Harness,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    gid: &str,
    who: &User,
    base_seq: u64,
    op: &str,
) -> (Value, String) {
    let epoch = g.epoch().as_u64();
    let idx: Vec<_> = g
        .members()
        .filter(|m| {
            openmls::prelude::BasicCredential::try_from(m.credential.clone())
                .is_ok_and(|c| c.identity() == who.device_id.as_bytes())
        })
        .map(|m| m.index)
        .collect();
    let (commit, _, _) = g.remove_members(&ad.provider, &ad.signer, &idx).unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = gmsg(
        h,
        alice,
        &gaddr(gid),
        "group",
        gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(g)),
        }),
        json!({"group_op": op, "subject": who.address(), "base_seq": base_seq}),
    );
    (m, commit_hash(&commit))
}

/// 확정 전 Commit 을 bob 의 ack 와 창 지나기로 확정한다.
async fn confirm_by(h: &Harness, b: &mut Client, gid: &str, epoch: u64, hash: &str) {
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let f = next_of(b, "commit_final").await;
    assert_eq!(f["commit_hash"], hash, "{f}");
}

/// 0.2.5(g025f 물음): 나간 사람의 잎은 remove_user 확정 전까지 남는다 — 그 사이 응용 글은 지금 멤버의 잎에만 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 나간_사람의_남은_잎에는_그룹_글을_주지_않는다() {
    let (h, path) = start_groups_file().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let _ = next_of(&mut c, "deliver").await; // Welcome
                                              // carol 이 나갔다 — 잎은 아직(remove_user 전).
    let db = rusqlite::Connection::open(&path).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    db.execute(
        "UPDATE group_members SET left_seq = 99 WHERE gid = ?1 AND user = 'carol'",
        [&gid],
    )
    .unwrap();
    let m = gapp(&h, &bob, &gid, 2, json!({}));
    assert_eq!(send(&mut b, &m).await["t"], "ack");
    let f = next_of(&mut a, "deliver").await;
    assert_eq!(f["message"]["msg_id"], m["msg_id"]);
    while let Ok(f) = tokio::time::timeout(Duration::from_millis(300), c.recv()).await {
        assert!(
            !(f["t"] == "deliver" && f["message"]["msg_id"] == m["msg_id"]),
            "나간 사람에게 감: {f}"
        );
    }
}

/// 16 lifecycle·qa_removed_*: 응용 메시지는 잎(멤버 기기)에만, seq 없음. 멤버 아닌 사람의 글·관리자 아닌 remove 는 unroutable.
/// 빠진 사람은 commit_final 을 받고, 그 뒤 글을 받지도 보내지도 못한다. 빠지기 전에 쌓인 몫도 지워진다.
#[tokio::test(flavor = "multi_thread")]
async fn group_messages_follow_leaves() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (mut d, _) = connect(&h, &dave).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let _ = next_of(&mut c, "deliver").await; // Welcome

    let m = gapp(&h, &bob, &gid, 2, json!({}));
    assert_eq!(send(&mut b, &m).await["t"], "ack");
    for cl in [&mut a, &mut c] {
        let f = next_of(cl, "deliver").await;
        assert_eq!(f["message"]["msg_id"], m["msg_id"]);
        assert!(f.get("group_seq").is_none(), "{f}");
    }
    // 멤버 아닌 dave 의 글, 관리자 아닌 bob 의 remove 는 unroutable.
    assert_eq!(
        send(&mut d, &gapp(&h, &dave, &gid, 2, json!({}))).await["reason"],
        "unroutable"
    );
    let bob_remove = gmsg(
        &h,
        &bob,
        &gaddr(&gid),
        "group",
        &gid,
        2,
        json!({"enc": "mls", "wire": "commit", "payload": data(&[1u8; 32]), "group_info": data(&[1u8; 32])}),
        json!({"group_op": "remove", "subject": carol.address(), "base_seq": 3}),
    );
    assert_eq!(send(&mut b, &bob_remove).await["reason"], "unroutable");

    // carol 이 꺼진 동안 쌓인 글은 빠질 때 지워진다.
    drop(c);
    let queued = gapp(&h, &bob, &gid, 2, json!({}));
    assert_eq!(send(&mut b, &queued).await["t"], "ack");
    let (m, hash) = remove_msg(&h, &alice, &ad, &mut g, &gid, &carol, 3);
    assert_eq!(send(&mut a, &m).await["t"], "ack", "remove");
    confirm_by(&h, &mut b, &gid, 2, &hash).await;
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(f["group_seq"].as_u64(), Some(4), "{f}");
    let (mut c, _) = connect(&h, &carol).await;
    // 꺼져 있던 carol 은 자기를 빼는 Commit 을 group_seq 가 붙은 채(= 이미 확정, §12-14 ①) 받는다.
    let mut seen = Vec::new();
    loop {
        let f = c.recv().await;
        if f["t"] == "deliver" && f["message"]["msg_id"] == m["msg_id"] {
            assert_eq!(f["group_seq"].as_u64(), Some(4), "{f}");
            break;
        }
        seen.push(f);
    }
    assert!(
        !seen
            .iter()
            .any(|f| f["message"]["msg_id"] == queued["msg_id"]),
        "빠지기 전에 쌓인 글이 갔다: {seen:?}"
    );
    assert_eq!(
        send(&mut c, &gapp(&h, &carol, &gid, 3, json!({}))).await["reason"],
        "unroutable"
    );
    let after = gapp(&h, &bob, &gid, 3, json!({}));
    assert_eq!(send(&mut b, &after).await["t"], "ack");
    let _ = next_of(&mut a, "deliver").await;
    c.expect_silence().await;
}

/// 16 group_status_carries_by: 그룹 글의 read 를 다른 멤버가 보내면 보낸 사람이 by 를 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn group_status_carries_by() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let m = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let at = UnixMillis(h.fx.clock.now().0).to_rfc3339().unwrap();
    b.send(&json!({"t": "status", "msg_id": m["msg_id"], "state": "read", "at": at}))
        .await;
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (st["state"].as_str(), st["by"].as_str()),
        (Some("read"), Some("bob@local")),
        "{st}"
    );
}

/// 16 refusals_are_byte_identical·qa_replay_nonmember: 없는 그룹·멤버 아님·권한 없음은 msg_id 말고 같은 바이트, 멤버 아닌
/// 사람의 replay 는 없는 그룹과 같다. 그룹 끔(기본)이면 만들기도 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn group_refusals_look_the_same() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let ad = Dev::of(&alice);
    let (gid, _) = make_group(&h, &mut a, &alice, &ad).await;
    let shape = |mut v: Value| {
        v.as_object_mut().unwrap().remove("msg_id");
        v
    };
    let commit = |from: &User, gid: &str, op: &str| {
        gmsg(
            &h,
            from,
            &gaddr(gid),
            "group",
            gid,
            0,
            json!({"enc": "mls", "wire": "commit", "payload": data(&[1u8; 32]), "group_info": data(&[1u8; 32])}),
            json!({"group_op": op, "subject": alice.address(), "base_seq": 1}),
        )
    };
    let unknown = h.fx.ids.next_ulid().to_lowercase();
    let r1 = shape(send(&mut b, &commit(&bob, &gid, "remove")).await);
    let r2 = shape(send(&mut b, &commit(&bob, &unknown, "remove")).await);
    let r3 = shape(send(&mut b, &gapp(&h, &bob, &gid, 0, json!({}))).await);
    assert_eq!(r1["reason"], "unroutable");
    assert_eq!(r1, r2);
    assert_eq!(r1, r3);
    let replay = |gid: &str| json!({"t": "groups.replay", "group": gaddr(gid), "from_seq": 0});
    b.send(&replay(&gid)).await;
    let real = b.recv().await;
    b.send(&replay(&unknown)).await;
    let none = b.recv().await;
    assert_eq!(real, none, "멤버 아님과 없는 그룹이 다르게 보인다");

    let off = start_with(|c| c.groups = false).await;
    let alice2 = register(&off, "alice", 1).await;
    let (mut a2, _) = connect(&off, &alice2).await;
    let ad2 = Dev::of(&alice2);
    let gid2 = off.fx.ids.next_ulid().to_lowercase();
    let g2 = ad2.create(Kind::Group, gid2.as_bytes());
    let m = gmsg(
        &off,
        &alice2,
        &gaddr(&gid2),
        "group",
        &gid2,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad2.group_info(&g2))}),
        json!({"group_op": "create", "base_seq": 0}),
    );
    assert_eq!(send(&mut a2, &m).await["reason"], "unroutable");
}

/// 그룹 첨부 합계(§5d, 16 에서 옮김): MLS 그룹 글의 헤더 blobs ct_len 합 > blob_ct_len(25 MiB) + 16 × n 이면 too_large.
#[tokio::test(flavor = "multi_thread")]
async fn group_app_attachment_total_is_capped() {
    use lodelai_crypto::blob::blob_ct_len;
    let max = lodelai_protocol::constants::GROUP_FILES_MAX_BYTES;
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    let ad = Dev::of(&alice);
    let (gid, _) = make_group(&h, &mut a, &alice, &ad).await;
    let mut ids = Vec::new();
    for plain in [max, 100] {
        a.send(&json!({"t": "blob.reserve", "req": "r", "ct_len": blob_ct_len(plain), "purpose": "message"}))
            .await;
        let r = next_of(&mut a, "blob.reserved").await;
        ids.push(r["blob_id"].as_str().unwrap().to_owned());
    }
    let m = gapp(&h, &alice, &gid, 0, json!({"blobs": ids}));
    assert_eq!(send(&mut a, &m).await["reason"], "too_large");
}

/// 16 qa_create_is_bounded_per_user: 한 사람이 만들 수 있는 그룹 수는 GROUPS_PER_USER 까지 — 넘으면 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn group_create_is_bounded_per_user() {
    let h = start_with(|c| {
        c.groups = true;
        // 연결 단위 초당 상한에 걸리지 않게(만들기 100번).
        c.rate_per_sec = 10_000;
        c.rate_burst = 10_000;
    })
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect(&h, &alice).await;
    let ad = Dev::of(&alice);
    for _ in 0..lodelai_protocol::constants::GROUPS_PER_USER {
        let _ = make_group(&h, &mut a, &alice, &ad).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let g = ad.create(Kind::Group, gid.as_bytes());
    let m = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
        json!({"group_op": "create", "base_seq": 0}),
    );
    assert_eq!(send(&mut a, &m).await["reason"], "unroutable");
}

/// 묶음 22(§12-13 ⑤·설계 10-27): relay 는 1:1 box 봉투를 늘 error{protocol} 로 거절한다 — 예외 칸 없음(#488 에서 시험 전용
/// `rule_tests_accept_box` 를 지움, 규칙 시험은 MLS 봉투로).
#[tokio::test(flavor = "multi_thread")]
async fn one_to_one_box_is_always_refused() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let id = h.fx.ids.next_ulid();
    let mut m = json!({
        "v": 10, // 메시지 v 는 9·10(판 11 은 ws typing 만, #613) — 판 10 글(#598 ② 가르기 대상)
        "msg_id": id, "thread_id": id, "kind": "chat",
        "from": {"address": alice.address(), "author": "human", "device_id": alice.device_id},
        "to": {"address": bob.address()},
        "body": {
            "enc": "box",
            // 옛 판(7) 앱이 보내던 봉투 꼴 — 값은 아무거나(#560 에서 seal 을 걷어냄, 꼴만으로 거절되는지 본다).
            "alg": "x25519-xchacha20poly1305",
            "epk": encoding::encode(&[7u8; 32]),
            "nonce": encoding::encode(&[8u8; 24]),
            "ct": encoding::encode(&[0u8; 40]),
            "cek_commit": encoding::encode(&[9u8; 32]),
            "recipients": [{"device_id": bob.device_id, "wk": encoding::encode(&[6u8; 48])}],
        },
        "created_at": UnixMillis(h.fx.clock.now().0).to_rfc3339().unwrap(),
        "expires_at": UnixMillis(h.fx.clock.now().0 + 3600 * 1000).to_rfc3339().unwrap(),
    });
    sign_message(&mut m, &alice.keys.signing).unwrap();
    let r = send(&mut a, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["code"].as_str()),
        (Some("error"), Some("protocol")),
        "{r}"
    );
}

/// alice 의 GCE Commit(0xF0A1 을 `lodelai` JSON 으로 바꿈) — op 와 subject 를 헤더에.
#[allow(clippy::too_many_arguments)]
fn gce_msg(
    h: &Harness,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    gid: &str,
    lodelai: Value,
    op: &str,
    subject: Option<&User>,
    base_seq: u64,
) -> Value {
    use openmls::prelude::{
        Extension, Extensions, RequiredCapabilitiesExtension, UnknownExtension,
    };
    let epoch = g.epoch().as_u64();
    let ext = Extensions::from_vec(vec![
        Extension::Unknown(
            EXT_LODELAI,
            UnknownExtension(lodelai.to_string().into_bytes()),
        ),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(EXT_LODELAI)],
            &[],
            &[CredentialType::Basic],
        )),
    ])
    .unwrap();
    let (commit, _, _) = g
        .update_group_context_extensions(&ad.provider, ext, &ad.signer)
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let mut extra = json!({"group_op": op, "base_seq": base_seq});
    if let Some(s) = subject {
        extra["subject"] = json!(s.address());
    }
    gmsg(
        h,
        alice,
        &gaddr(gid),
        "group",
        gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(g)),
        }),
        extra,
    )
}

/// admin(§12-13 ①): Commit + GCE 는 지금 관리자가 op admin 으로만, 0xF0A1 의 kind 는 그대로 — kind 가 바뀌거나 op 가
/// update 면 invalid_commit. (거절된 Commit 은 alice 쪽 상태를 갈라 놓으므로 경우마다 새 그룹.)
#[tokio::test(flavor = "multi_thread")]
async fn group_admin_change_is_gce_by_admin() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let bd = Dev::of(&bob);
    let admins = json!(["alice@local", "bob@local"]);
    let cases = [
        (
            json!({"kind": "group", "admins": admins}),
            "admin",
            true,
            "ack",
        ),
        (
            json!({"kind": "pair", "admins": admins}),
            "admin",
            true,
            "invalid_commit",
        ),
        (
            json!({"kind": "group", "admins": admins}),
            "update",
            false,
            "invalid_commit",
        ),
    ];
    for (lodelai, op, with_subject, want) in cases {
        let ad = Dev::of(&alice);
        let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
        let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
        assert_eq!(send(&mut a, &m).await["t"], "ack");
        let m = gce_msg(
            &h,
            &alice,
            &ad,
            &mut g,
            &gid,
            lodelai,
            op,
            with_subject.then_some(&bob),
            2,
        );
        let r = send(&mut a, &m).await;
        let got = if r["t"] == "ack" {
            "ack"
        } else {
            r["reason"].as_str().unwrap_or("?")
        };
        assert_eq!(got, want, "{op}: {r}");
    }
}

/// 나가기(§12-13 ②): 나가는 사람의 leave(wire app)는 받은 때 표에서 빼고 seq — 남은 잎에 seq 와 함께 배달, 남은 접속 기기에
/// remove_user duty. 남은 멤버(관리자 아니어도 됨)의 group_op=leave·subject=그 사람 Commit 은 그 사람 잎을 모두 빼야 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn group_leave_flow() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    // 남이 대신 나가게 할 수 없다(subject ≠ 보낸 사람인 leave app).
    let forged = gmsg(
        &h,
        &bob,
        &gaddr(&gid),
        "group",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({"group_op": "leave", "subject": carol.address(), "base_seq": 3}),
    );
    assert_eq!(send(&mut b, &forged).await["reason"], "unroutable");
    let leave = gmsg(
        &h,
        &carol,
        &gaddr(&gid),
        "group",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({"group_op": "leave", "subject": carol.address(), "base_seq": 3}),
    );
    let r = send(&mut c, &leave).await;
    assert_eq!(
        (r["t"].as_str(), r["group_seq"].as_u64()),
        (Some("ack"), Some(4)),
        "{r}"
    );
    let d = next_of(&mut a, "deliver").await;
    assert_eq!(
        (d["message"]["msg_id"].clone(), d["group_seq"].as_u64()),
        (leave["msg_id"].clone(), Some(4))
    );
    let duty = next_of(&mut b, "duty").await;
    assert_eq!(
        (duty["task"].as_str(), duty["subject"].as_str()),
        (Some("remove_user"), Some("carol@local")),
        "{duty}"
    );
    // 남은 alice(관리자든 아니든)가 leave Commit — 보낸 사람 ≠ subject 이지만 나간 기록이 있다. bob 이 확정.
    let (m, hash) = remove_msg_op(&h, &alice, &ad, &mut g, &gid, &carol, 4, "leave");
    let r = send(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    confirm_by(&h, &mut b, &gid, 2, &hash).await;
    let f = next_of(&mut a, "commit_final").await;
    assert_eq!(f["group_seq"].as_u64(), Some(5), "{f}");
}

/// #816 나간 사람 경계: ① 나가기 전에 남은 다시 들기 표시·add_device 일은 나갈 때 지워지고, 지운 뒤 남은 표시(옛 판)도 접속 때
/// rejoin_needed 로 가지 않는다. ② 잎이 남아 있어도(remove_user 확정 전) 나간 사람의 그룹 글은 unroutable. ③ 나간 사람의
/// external commit(직전 epoch 에 잎이 있었음)도 받지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn left_member_gets_no_rejoin_and_cannot_send_or_rejoin() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let now = h.fx.clock.now().0;
    assert!(h.app.db.rejoin_mark(&carol.device_id, &gid, now).unwrap());
    h.app
        .db
        .duty_add(&gid, "add_device", &carol.device_id, now)
        .unwrap();
    let leave = gmsg(
        &h,
        &carol,
        &gaddr(&gid),
        "group",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({"group_op": "leave", "subject": carol.address(), "base_seq": 3}),
    );
    assert_eq!(send(&mut c, &leave).await["t"], "ack");
    // ①
    assert!(h.app.db.rejoin_for(&carol.device_id).unwrap().is_empty());
    assert!(
        !h.app
            .db
            .duties_of("add_device")
            .unwrap()
            .iter()
            .any(|(_, s, _)| *s == carol.device_id),
        "나간 사람 기기의 add_device 일은 지운다"
    );
    assert!(
        h.app
            .db
            .group_leaves(&gid)
            .unwrap()
            .contains(&carol.device_id),
        "잎은 remove_user 확정 전까지 남는다"
    );
    // ② 남은 잎으로 그룹 글.
    let chat = gmsg(
        &h,
        &carol,
        &gaddr(&gid),
        "chat",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])}),
        json!({}),
    );
    assert_eq!(send(&mut c, &chat).await["reason"], "unroutable");
    // ③ 직전 GroupInfo 로 external commit(group_op update).
    let MlsMessageBodyIn::GroupInfo(vgi) =
        MlsMessageIn::tls_deserialize_exact(ad.group_info(&g).as_slice())
            .unwrap()
            .extract()
    else {
        panic!("group info 아님")
    };
    let cv = Dev::of(&carol);
    let (ng, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .build_group(&cv.provider, vgi, cv.signer.credential())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(cv.provider.storage())
        .unwrap()
        .build(cv.provider.rand(), cv.provider.crypto(), &cv.signer, |_| {
            true
        })
        .unwrap()
        .finalize(&cv.provider)
        .unwrap();
    let ext = gmsg(
        &h,
        &carol,
        &gaddr(&gid),
        "group",
        &gid,
        2,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
            "group_info": data(&cv.group_info(&ng)),
        }),
        json!({"group_op": "update", "base_seq": 4}),
    );
    let r = send(&mut c, &ext).await;
    assert_ne!(r["t"], "ack", "{r}");
    // ① 옛 판이 남긴 표시: 접속 때 rejoin_needed 로 가지 않는다.
    h.app.db.rejoin_mark(&carol.device_id, &gid, now).unwrap();
    drop(c);
    let (mut c, _) = connect(&h, &carol).await;
    while let Ok(Some(Ok(Message::Text(t)))) =
        tokio::time::timeout(Duration::from_millis(300), c.ws.next()).await
    {
        assert!(!t.contains("\"rejoin_needed\""), "{t}");
    }
}

/// 16 group_request_needs_member_session_owner(보안, MLS 판): 헤더 group 이 붙은 request 는 멤버의 세션에만 — 멤버 아닌
/// 사람의 세션이면 unroutable. 그룹 잎 모두가 본다. 수락은 세션 주인만, 회신 대조(규칙 4)는 세션 주인 — 다른 멤버의 회신은
/// unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn group_request_needs_member_session_owner() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut cl, _) = connect(&h, &carol).await;
    let (mut d, _) = connect(&h, &dave).await;
    for (cn, slug) in [(&mut a, "front"), (&mut d, "ops")] {
        cn.send(&json!({"t": "session.publish", "slug": slug, "grade": "task", "liveness": "live:channel"}))
            .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let _ = next_of(&mut cl, "deliver").await; // Welcome
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[2u8; 64])});
    let req = gmsg(
        &h,
        &bob,
        "alice@local/front",
        "request",
        &gid,
        2,
        body.clone(),
        json!({"grade": "question", "group": gaddr(&gid)}),
    );
    assert_eq!(send(&mut b, &req).await["t"], "ack");
    assert_eq!(
        next_of(&mut a, "deliver").await["message"]["msg_id"],
        req["msg_id"]
    );
    assert_eq!(
        next_of(&mut cl, "deliver").await["message"]["msg_id"],
        req["msg_id"],
        "다른 멤버도 본다"
    );
    // 멤버 아닌 dave 의 세션 → unroutable.
    let bad = gmsg(
        &h,
        &bob,
        "dave@local/ops",
        "request",
        &gid,
        2,
        body.clone(),
        json!({"grade": "question", "group": gaddr(&gid)}),
    );
    assert_eq!(send(&mut b, &bad).await["reason"], "unroutable");
    // 수락은 세션 주인만.
    let at = UnixMillis(h.fx.clock.now().0).to_rfc3339().unwrap();
    cl.send(&json!({"t": "status", "msg_id": req["msg_id"], "state": "accepted", "at": at}))
        .await;
    assert_eq!(
        next_of(&mut cl, "error").await["t"],
        "error",
        "주인 아닌 수락"
    );
    a.send(&json!({"t": "status", "msg_id": req["msg_id"], "state": "accepted", "at": at}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rid = req["msg_id"].as_str().unwrap();
    let reply_from = |who: &User, slug_addr: &str, sid: &str| {
        let mut r = gmsg(
            &h,
            who,
            "bob@local",
            "reply",
            &gid,
            2,
            body.clone(),
            json!({"reply_to": rid, "group": gaddr(&gid)}),
        );
        r["from"]["address"] = json!(slug_addr);
        r["from"]["author"] = json!("agent");
        r["from"]["session_id"] = json!(sid);
        r.as_object_mut().unwrap().remove("sig");
        sign_message(&mut r, &who.keys.signing).unwrap();
        r
    };
    let rep = reply_from(
        &alice,
        "alice@local/front",
        "cee3f37e-0000-0000-0000-000000000000",
    );
    assert_eq!(send(&mut a, &rep).await["t"], "ack");
    assert_eq!(
        next_of(&mut cl, "deliver").await["message"]["kind"],
        "reply"
    );
    // 규칙 4: 원 메시지 대조는 세션 주인 — 그룹의 다른 멤버 carol 의 회신은 unroutable.
    let forged = reply_from(
        &carol,
        "carol@local/front",
        "cee3f37e-0000-0000-0000-000000000001",
    );
    assert_eq!(send(&mut cl, &forged).await["reason"], "unroutable");
}

/// 그룹 켠 파일 DB relay(조직 빠짐 시험용 — 표를 직접 본다).
async fn start_groups_file() -> (Harness, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let mut h = start_db(|c| c.groups = true, Db::open(&path).unwrap()).await;
    h.db_file = Some((dir, path.clone()));
    (h, path)
}

/// alice 를 지금 조직의 hosted 관리자로(내보내기·나가기는 hosted 조직만).
fn make_alice_org_admin(path: &std::path::Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(path).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.execute_batch(
        "INSERT OR IGNORE INTO orgs(org_id, name, admin, created_ms)
           SELECT org, 'org', 'alice', 0 FROM users WHERE user = 'alice';
         INSERT OR IGNORE INTO org_admins(org_id, user) SELECT org, 'alice' FROM users WHERE user = 'alice';",
    )
    .unwrap();
    c
}

async fn groups_list(c: &mut Client) -> Value {
    c.send(&json!({"t": "groups.list"})).await;
    next_of(c, "groups").await["items"].clone()
}

/// 16 org_removal_cleans_tables_and_replay_is_members_only(보안, MLS 판): 접속 때 directory → groups → 쌓인 것. 내보낸
/// 사람은 모든 그룹 표에서 빠지고(혼자이던 그룹은 지워짐) 남은 멤버의 groups 에 조직 빠짐 힌트. 멤버 아닌 사람의 replay 는
/// protocol 오류.
#[tokio::test(flavor = "multi_thread")]
async fn org_removal_cleans_tables_and_replay_is_members_only() {
    let (h, path) = start_groups_file().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    // bob 은 꺼져 있었다 — directory → groups → (결과·)쌓인 Commit(seq 2).
    let (mut b, _) = connect(&h, &bob).await;
    let first = b.recv().await;
    assert_eq!(first["t"], "directory", "{first}");
    let second = b.recv().await;
    assert_eq!(
        (second["t"].as_str(), &second["items"]),
        (Some("groups"), &json!([{"group": gaddr(&gid), "seq": 2}])),
        "{second}"
    );
    let d = next_of(&mut b, "deliver").await;
    assert_eq!(d["group_seq"], 2);
    // bob 혼자인 그룹.
    let bd2 = Dev::of(&bob);
    let _solo = make_group(&h, &mut b, &bob, &bd2).await;
    b.send(&json!({"t": "groups.replay", "group": gaddr(&gid), "from_seq": 1}))
        .await;
    let r = next_of(&mut b, "deliver").await;
    assert_eq!(r["group_seq"], 2, "{r}");
    // 조직 관리자 alice 가 bob 을 내보낸다.
    let conn = make_alice_org_admin(&path);
    let now = h.fx.clock.now().0;
    h.app.db.member_remove("alice", "bob", now).unwrap();
    assert_eq!(
        groups_list(&mut a).await,
        json!([{"group": gaddr(&gid), "seq": 2, "org_left": [{"user": "bob@local", "seq": 2}]}])
    );
    let groups: i64 = conn
        .query_row("SELECT COUNT(*) FROM groups", [], |r| r.get(0))
        .unwrap();
    assert_eq!(groups, 1, "bob 혼자이던 그룹은 지워짐");
    let mls: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM mls_groups WHERE kind = 'group'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(mls, 1, "지워진 그룹의 MLS 상태도 지워짐");
    let bob_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_members WHERE user = 'bob' AND left_seq IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bob_rows, 0);
    let carol = register(&h, "carol", 3).await;
    let (mut cl, _) = connect(&h, &carol).await;
    cl.send(&json!({"t": "groups.replay", "group": gaddr(&gid), "from_seq": 1}))
        .await;
    assert_eq!(next_of(&mut cl, "error").await["code"], "protocol");
}

/// 16 org_removal_hint_reaches_members_before_later_changes(보안, MLS 판): 조직 빠짐은 실시간으로 directory.update → groups
/// (힌트) 순, 다시 접속하면 directory(빠진 사람 없음) → groups(힌트)가 쌓인 것보다 먼저. op 로 내보낸 사람은 힌트에 없다.
#[tokio::test(flavor = "multi_thread")]
async fn org_removal_hint_reaches_members_before_later_changes() {
    let (h, path) = start_groups_file().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd, cd, dd) = (
        Dev::of(&alice),
        Dev::of(&bob),
        Dev::of(&carol),
        Dev::of(&dave),
    );
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    for (who, wd, seq, epoch) in [(&carol, &cd, 2u64, 1u64), (&dave, &dd, 3, 2)] {
        let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, who, wd, seq);
        assert_eq!(send(&mut a, &m).await["t"], "ack");
        confirm_by(&h, &mut b, &gid, epoch, &hash).await;
    }
    // dave 는 op 로 내보냄(seq 5) — 힌트에 없다.
    let (m, hash) = remove_msg(&h, &alice, &ad, &mut g, &gid, &dave, 4);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 3, &hash).await;
    let _conn = make_alice_org_admin(&path);
    {
        let _order = h.app.group_order.lock().unwrap();
        h.app
            .db
            .member_remove("alice", "carol", h.fx.clock.now().0)
            .unwrap();
        lodelai_relay::ws::announce_org_removal(&h.app, "alice");
    }
    let hint =
        json!([{"group": gaddr(&gid), "seq": 5, "org_left": [{"user": "carol@local", "seq": 5}]}]);
    let mut seen = Vec::new();
    loop {
        let f = b.recv().await;
        if f["t"] == "directory.update" || f["t"] == "groups" {
            seen.push(f["t"].as_str().unwrap().to_owned());
            if f["t"] == "groups" {
                assert_eq!(f["items"], hint);
                break;
            }
        }
    }
    assert_eq!(
        seen.first().map(String::as_str),
        Some("directory.update"),
        "디렉터리가 먼저"
    );
    drop(b);
    let (mut b, _) = connect(&h, &bob).await;
    let first = b.recv().await;
    assert_eq!(first["t"], "directory");
    assert!(
        !first.to_string().contains("carol@local"),
        "빠진 사람은 디렉터리에 없다: {first}"
    );
    let second = b.recv().await;
    assert_eq!(
        (second["t"].as_str(), &second["items"]),
        (Some("groups"), &hint)
    );
}

/// group 종류 복구(§4-5·§12-15): 멤버는 group_info.get 으로 지금 GroupInfo 를 받고(멤버 아니면 빈 답), 자기 옛 잎을 빼는
/// external commit 을 group_op=update 로 낸다 → 확정 전 배달. 잎이 한 번도 없던 사람(멤버 아님)의 external 은 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn group_external_recovery_is_update_by_member() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut d, _) = connect(&h, &dave).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert!(
        group_info_get(&mut d, &gid).await["group_info"].is_null(),
        "멤버 아님"
    );
    for (cl, who, want) in [(&mut b, &bob, "ack"), (&mut d, &dave, "unroutable")] {
        let f = group_info_get(cl, &gid).await;
        let gi_src = if f["group_info"].is_null() {
            // 멤버 아닌 dave 는 GroupInfo 를 못 받는다 — 시험에선 alice 것을 넘겨받았다고 친다.
            ad.group_info(&g)
        } else {
            encoding::decode(f["group_info"]["data"].as_str().unwrap(), "gi").unwrap()
        };
        let MlsMessageBodyIn::GroupInfo(vgi) =
            MlsMessageIn::tls_deserialize_exact(gi_src.as_slice())
                .unwrap()
                .extract()
        else {
            panic!("group info 아님")
        };
        let dv = Dev::of(who);
        let (ng, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .build_group(&dv.provider, vgi, dv.signer.credential())
            .unwrap()
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(capabilities())
                    .build(),
            )
            .load_psks(dv.provider.storage())
            .unwrap()
            .build(dv.provider.rand(), dv.provider.crypto(), &dv.signer, |_| {
                true
            })
            .unwrap()
            .finalize(&dv.provider)
            .unwrap();
        let m = gmsg(
            &h,
            who,
            &gaddr(&gid),
            "group",
            &gid,
            1,
            json!({
                "enc": "mls", "wire": "commit",
                "payload": data(&bundle.commit().tls_serialize_detached().unwrap()),
                "group_info": data(&dv.group_info(&ng)),
            }),
            json!({"group_op": "update", "base_seq": 2}),
        );
        let r = send(cl, &m).await;
        let got = if r["t"] == "ack" {
            "ack"
        } else {
            r["reason"].as_str().unwrap_or("?")
        };
        assert_eq!(got, want, "{r}");
    }
}

/// 만들기 Commit(§12-22): start 뒤 첫 Commit 은 group_op create·헤더 subjects — 처음 멤버를 한 Commit 으로, 응답할 사람이
/// 없어 바로 확정(commit_final group_seq 2), 새 멤버는 Welcome 을 seq 2 로 받는다. Add 사용자 집합이 subjects 와 다르면
/// invalid_commit, subjects 를 add 에 실으면 형식 오류.
#[tokio::test(flavor = "multi_thread")]
async fn group_create_commit_adds_first_members() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (bd, cd) = (Dev::of(&bob), Dev::of(&carol));
    let create_commit = |g: &mut MlsGroup, ad: &Dev, gid: &str, adds: &[&Dev], subjects: Value| {
        let kps: Vec<_> = adds.iter().map(|d| d.key_package()).collect();
        let (commit, welcome, _) = g.add_members(&ad.provider, &ad.signer, &kps).unwrap();
        g.merge_pending_commit(&ad.provider).unwrap();
        gmsg(
            &h,
            &alice,
            &gaddr(gid),
            "group",
            gid,
            0,
            json!({
                "enc": "mls", "wire": "commit",
                "payload": data(&commit.tls_serialize_detached().unwrap()),
                "group_info": data(&ad.group_info(g)),
                "welcome": data(&welcome.tls_serialize_detached().unwrap()),
            }),
            json!({"group_op": "create", "subjects": subjects, "base_seq": 1}),
        )
    };
    // subjects 와 Add 사용자가 다르면 invalid_commit(그 그룹은 alice 쪽이 갈라져 버린다).
    let ad = Dev::of(&alice);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let m = create_commit(&mut g, &ad, &gid, &[&bd, &cd], json!([bob.address()]));
    assert_eq!(send(&mut a, &m).await["reason"], "invalid_commit");
    // 맞는 만들기 Commit.
    let ad = Dev::of(&alice);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let m = create_commit(
        &mut g,
        &ad,
        &gid,
        &[&bd, &cd],
        json!([bob.address(), carol.address()]),
    );
    let (r, seen) = send_seen(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    let fin = seen
        .iter()
        .find(|f| f["t"] == "commit_final")
        .expect("commit_final");
    assert_eq!(
        (fin["epoch"].as_u64(), fin["group_seq"].as_u64()),
        (Some(0), Some(2)),
        "{fin}"
    );
    for cl in [&mut b, &mut c] {
        let d = next_of(cl, "deliver").await;
        assert_eq!(
            (d["message"]["msg_id"].clone(), d["group_seq"].as_u64()),
            (m["msg_id"].clone(), Some(2))
        );
    }
    assert_eq!(
        groups_list(&mut b).await,
        json!([{"group": gaddr(&gid), "seq": 2}])
    );
    // subjects 는 create Commit 에만 — add 에 실으면 형식 오류.
    let bad = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        1,
        json!({"enc": "mls", "wire": "commit", "payload": data(&[1u8; 32]), "group_info": data(&[1u8; 32])}),
        json!({"group_op": "add", "subject": bob.address(), "subjects": [bob.address()], "base_seq": 2}),
    );
    assert_eq!(send(&mut a, &bad).await["t"], "error");
    let _ = g;
}

/// 이름 바꾸기(§12-23): kind group·group_op rename·wire app, subject 없음. 지금 epoch 만(지난 epoch 는 stale_epoch), 멤버 누구나,
/// seq 를 매겨 잎 − 보낸 기기에 배달. 이름은 MLS 평문 안이라 relay 는 보지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn group_rename_app() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let rename = |epoch: u64| {
        gmsg(
            &h,
            &bob,
            &gaddr(&gid),
            "group",
            &gid,
            epoch,
            json!({"enc": "mls", "wire": "app", "payload": data(&[2u8; 64])}),
            json!({"group_op": "rename", "base_seq": 3}),
        )
    };
    assert_eq!(send(&mut b, &rename(1)).await["reason"], "stale_epoch");
    let ok = rename(2);
    let r = send(&mut b, &ok).await;
    assert_eq!(
        (r["t"].as_str(), r["group_seq"].as_u64()),
        (Some("ack"), Some(4)),
        "{r}"
    );
    // 앞 Commit 배달(seq ≤ 3)이 먼저 올 수 있다.
    for ws in [&mut a, &mut c] {
        let d = loop {
            let d = next_of(ws, "deliver").await;
            if d["message"]["msg_id"] == ok["msg_id"] {
                break d;
            }
            assert!(d["group_seq"].as_u64() < Some(4), "{d}");
        };
        assert_eq!(d["group_seq"].as_u64(), Some(4));
    }
}

/// 빠진 기기 채우기(§12-24): 그룹을 만든 뒤에 KeyPackage 를 올린 내 다른 기기(잎 자격 있음)는 KeyPackage 를 받을 때 다시 세어
/// 그 그룹 잎인 내 기기에 add_device duty 가 간다(만들 때는 relay 가 duty 를 만들지 않는다).
#[tokio::test(flavor = "multi_thread")]
async fn kp_publish_refreshes_add_device() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    let ad = Dev::of(&alice);
    let (gid, _g) = make_group(&h, &mut a, &alice, &ad).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    publish_kps(&mut a2, vec![kp(&alice2.keys, 60 * DAYS, false)], None).await;
    let d = loop {
        let d = next_of(&mut a, "duty").await;
        if d["subject"] == json!(alice2.device_id) {
            break d;
        }
    };
    assert_eq!(d["task"], "add_device", "{d}");
    assert!(
        d["group"].as_str().is_some_and(|g| !g.is_empty()),
        "{d} {gid}"
    );
}

// ------------------------------------------------------------------ #598 ② recipient_outdated

/// hello 의 판을 골라 붙는다(판 9 기기 흉내).
async fn connect_v(h: &Harness, u: &User, v: u64) -> Client {
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
    assert_eq!(c.recv().await["t"], "ready");
    c
}

/// 같은 msg_id 를 v9 로 다시 서명한 판(보내는 코어가 recipient_outdated 뒤 칸을 빼고 다시 보내는 꼴).
fn as_v9(m: &Value, from: &User) -> Value {
    let mut m = m.clone();
    m.as_object_mut().unwrap().remove("no_reply");
    with_v(&m, from, 9)
}

/// 같은 메시지를 판 `v` 로 다시 서명한다(도우미는 PROTOCOL_VERSION 으로 쓴다).
fn with_v(m: &Value, from: &User, v: u64) -> Value {
    let mut m = m.clone();
    let o = m.as_object_mut().unwrap();
    o.remove("sig");
    o.insert("v".into(), json!(v));
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// 섞인 그룹(bob 판 10·carol 판 9): v10 글은 bob 에게만, 보낸 기기엔 ack 뒤 status{failed, recipient_outdated}. 같은 msg_id 의
/// v9 다시 보내기는 중복으로 버려지지 않고 carol 에게만(bob 엔 다시 안 감), 한 번 더 보내면 멱등 ack(두 번 안 감).
#[tokio::test(flavor = "multi_thread")]
async fn outdated_group_member_gets_v9_resend_only() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let mut cl = connect_v(&h, &carol, 9).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let _ = next_of(&mut cl, "deliver").await; // Welcome
    let _ = next_of(&mut a, "commit_final").await;
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[3u8; 64])});
    let m10 = gmsg(&h, &alice, &gaddr(&gid), "chat", &gid, 2, body, json!({}));
    let m10 = with_v(&m10, &alice, 10);
    let id = m10["msg_id"].clone();
    assert_eq!(send(&mut a, &m10).await["t"], "ack");
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (
            &st["msg_id"],
            st["state"].as_str(),
            st["fail_reason"].as_str()
        ),
        (&id, Some("failed"), Some("recipient_outdated")),
        "{st}"
    );
    assert_eq!(next_of(&mut b, "deliver").await["message"]["msg_id"], id);
    cl.expect_silence().await;
    // 다시 보낸 v9 — 표시된 carol 에게만.
    let m9 = as_v9(&m10, &alice);
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    let d = next_of(&mut cl, "deliver").await;
    assert_eq!(
        (&d["message"]["msg_id"], &d["message"]["v"]),
        (&id, &json!(9))
    );
    b.expect_silence().await;
    a.expect_silence().await;
    // 한 번 더(재접속 뒤 같은 행) — 멱등 ack, carol 에게 두 번 가지 않는다.
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    cl.expect_silence().await;
    // carol 의 ack 로 곁 몫이 끝난다.
    cl.send(&json!({"t": "delivered_ack", "msg_id": id})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let left = h.app.db.pending_for(&carol.name, &carol.device_id).unwrap();
    assert!(
        !left.iter().any(|(m, _)| m.contains(id.as_str().unwrap())),
        "{left:?}"
    );
}

/// #626: 반응은 글 판(12)보다 낮은 기기(carol 판 9)에 전하지 않고, 보낸 기기에 recipient_outdated 도 내지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn reaction_skips_old_devices_without_outdated_status() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let mut cl = connect_v(&h, &carol, 9).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    let _ = next_of(&mut cl, "deliver").await; // Welcome
    let _ = next_of(&mut a, "commit_final").await;
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[3u8; 64])});
    let r = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "reaction",
        &gid,
        2,
        body,
        json!({}),
    );
    let id = r["msg_id"].clone();
    assert_eq!(send(&mut a, &r).await["t"], "ack");
    assert_eq!(next_of(&mut b, "deliver").await["message"]["msg_id"], id);
    cl.expect_silence().await;
    a.expect_silence().await;
}

/// #626: 반응은 세션 주소로 보낼 수 없다 — chat 을 세션 주소로 보낼 때와 같은 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn reaction_to_session_address_is_unroutable() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await; // Add commit(welcome)
    let mut msg = |kind: &str, to: String| {
        let ct = g.create_message(&ad.provider, &ad.signer, b"x").unwrap();
        let body = json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())});
        mls_msg(&h, &alice, &to, kind, &gid, 1, body)
    };
    let session = format!("{}/front", bob.address());
    let (r, c) = (msg("reaction", session.clone()), msg("chat", session));
    let (fr, fc) = (send(&mut a, &r).await, send(&mut a, &c).await);
    assert_eq!(fr["reason"], "unroutable", "{fr}");
    assert_eq!((&fr["t"], &fr["reason"]), (&fc["t"], &fc["reason"]));
    // 사람 주소면 간다.
    let ok = msg("reaction", bob.address());
    assert_eq!(send(&mut a, &ok).await["t"], "ack");
    assert_eq!(
        next_of(&mut b, "deliver").await["message"]["kind"],
        "reaction"
    );
}

/// 1:1 에서 받는 사람 기기가 모두 판 9: 봉투를 남기지 않고 보낸 기기엔 status 만 — 같은 msg_id 의 v9 는 중복 검사에 걸리지
/// 않고 보통 길로 bob 에게 간다. 그 뒤 같은 v9 를 또 보내면 멱등 ack(두 번 안 감). 판 10 이 아닌 글은 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn outdated_pair_all_v9_resend_goes_normal_path() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let mut b = connect_v(&h, &bob, 9).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = pair_group_id(&alice.name, &bob.name);
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await; // Add commit(welcome)
    let ct = g.create_message(&ad.provider, &ad.signer, b"hi").unwrap();
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())});
    let m10 = mls_msg(&h, &alice, &bob.address(), "chat", &gid, 1, body);
    let id = m10["msg_id"].clone();
    assert_eq!(send(&mut a, &m10).await["t"], "ack");
    let st = next_of(&mut a, "status").await;
    assert_eq!(st["fail_reason"], "recipient_outdated", "{st}");
    b.expect_silence().await;
    assert!(h.app.db.header(id.as_str().unwrap()).unwrap().is_none());
    let m9 = as_v9(&m10, &alice);
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    let d = next_of(&mut b, "deliver").await;
    assert_eq!(
        (&d["message"]["msg_id"], &d["message"]["v"]),
        (&id, &json!(9))
    );
    a.expect_silence().await;
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    b.expect_silence().await;
    // 처음부터 v9 인 글은 판 9 기기에도 그대로 간다.
    let ct = g
        .create_message(&ad.provider, &ad.signer, b"again")
        .unwrap();
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())});
    let plain9 = as_v9(
        &mls_msg(&h, &alice, &bob.address(), "chat", &gid, 1, body),
        &alice,
    );
    assert_eq!(send(&mut a, &plain9).await["t"], "ack");
    assert_eq!(
        next_of(&mut b, "deliver").await["message"]["msg_id"],
        plain9["msg_id"]
    );
    a.expect_silence().await;
}

/// no_reply 는 판 10 request 칸 — v9 에 실리면 형식 오류(스키마 if/then 을 relay 파싱이 대신 본다).
#[tokio::test(flavor = "multi_thread")]
async fn no_reply_needs_v10() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let gid = pair_group_id(&alice.name, &bob.name);
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[1u8; 64])});
    let mut m = mls_msg(&h, &alice, &bob.address(), "request", &gid, 1, body);
    let o = m.as_object_mut().unwrap();
    o.remove("sig");
    o.insert("grade".into(), json!("question"));
    o.insert("no_reply".into(), json!(true));
    o.insert("v".into(), json!(9));
    sign_message(&mut m, &alice.keys.signing).unwrap();
    let r = send(&mut a, &m).await;
    assert_eq!(
        (r["t"].as_str(), r["code"].as_str()),
        (Some("error"), Some("protocol")),
        "{r}"
    );
}

/// #577 설계 리뷰 🔴(4d5a06598 리뷰): 잎이 없고 add_device 일도 없는 멤버(예: KeyPackage 가 없어 못 든 사람)가 있어도 그룹 글은
/// 실패 알림 없이 다른 멤버에게 간다 — '기기 바뀜'은 끊기 완료가 남긴 일이 있는 그 사이만.
#[tokio::test(flavor = "multi_thread")]
async fn group_member_without_leaf_or_duty_does_not_fail_messages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let mut h = start_db(|c| c.groups = true, Db::open(&path).unwrap()).await;
    h.db_file = Some((dir, path.clone()));
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let _carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    next_of(&mut b, "deliver").await;
    // carol: 그룹 표 멤버인데 잎이 없고(산 기기는 있음) add_device 일도 없다.
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute(
            "INSERT INTO group_members(gid, user, role, joined_seq) VALUES (?1, 'carol', 'member', 2)",
            [&gid],
        )
        .unwrap();
    }
    assert!(h
        .app
        .db
        .group_view(&gid)
        .unwrap()
        .unwrap()
        .members
        .contains(&"carol".to_owned()));
    assert!(!h.app.db.add_duty_pending_for_user(&gid, "carol").unwrap());

    let m = gapp(&h, &alice, &gid, g.epoch().as_u64(), json!({}));
    let (r, _) = send_seen(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    assert_eq!(
        next_of(&mut b, "deliver").await["message"]["msg_id"],
        m["msg_id"]
    );
    a.expect_silence().await;
    assert!(!h
        .app
        .db
        .device_changed_has(m["msg_id"].as_str().unwrap(), "alice")
        .unwrap());
}

/// #577 설계 리뷰 6493882795 🟡2: 그룹에서 어떤 멤버의 잎이 모두 끊겼고(새 기기는 있으나 아직 안 듦) 그 사이 글을 보내면, 그
/// 몫이 조용히 빠지지 않고 보낸 사람에게 ack 뒤 status{failed, recipient_device_changed}. 같은 msg_id 로 다시 보내면(새 잎이
/// 든 뒤) Conflict 가 아니라 다시 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn group_message_while_member_changes_device_reports_failure() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    next_of(&mut b, "deliver").await;
    let epoch = g.epoch().as_u64();

    // bob 의 새 기기(아직 잎 아님) → 옛 기기 로그아웃: 잎은 모두 끊겼고 산 기기는 있다.
    let bob2 = register_extra_device(&h, "bob", 5).await;
    b.send(&json!({"t": "device.revoke"})).await;
    while b.recv().await["t"] != "device.revoked" {}

    let m = gapp(&h, &alice, &gid, epoch, json!({}));
    let (r, _) = send_seen(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    let s = next_of(&mut a, "status").await;
    assert_eq!(
        (
            s["msg_id"].clone(),
            s["state"].as_str(),
            s["fail_reason"].as_str()
        ),
        (
            m["msg_id"].clone(),
            Some("failed"),
            Some("recipient_device_changed")
        ),
        "{s}"
    );
    assert!(h
        .app
        .db
        .device_changed_has(m["msg_id"].as_str().unwrap(), "alice")
        .unwrap());

    // 같은 msg_id 로 다시 보내기 — 재생 ack 나 Conflict(unroutable)가 아니라 다시 받는다(아직 bob2 가 안 들어 또 실패 알림).
    let (r, _) = send_seen(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "{r}");
    let s = next_of(&mut a, "status").await;
    assert_eq!(s["fail_reason"], "recipient_device_changed", "{s}");

    // 옛 잎이 빠진 뒤(bob 잎 0 — 이 epoch 잎 목록에 bob 이 아예 없음, bob2 는 아직 안 듦)에 보낸 글도 조용히 빠지지 않는다
    // (10-29 실기 확인: 옛 잎 빼기 확정 직후 다시 보낸 글이 새 기기에 끝내 안 감).
    // 끊기 뒤 새 기기(bob2)에 이 그룹 add_device 일이 남아 있다 — '기기 바뀜'을 가르는 조건.
    assert!(h.app.db.add_duty_pending_for_user(&gid, "bob").unwrap());
    // 폐기된 잎 빼기는 사람 단위 op 가 아니라 update(subject 없음 — bob 은 멤버로 남는다).
    let idx: Vec<_> = g
        .members()
        .filter(|m| {
            openmls::prelude::BasicCredential::try_from(m.credential.clone())
                .is_ok_and(|c| c.identity() == bob.device_id.as_bytes())
        })
        .map(|m| m.index)
        .collect();
    let (commit, _, _) = g.remove_members(&ad.provider, &ad.signer, &idx).unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let rm = gmsg(
        &h,
        &alice,
        &gaddr(&gid),
        "group",
        &gid,
        epoch,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
        }),
        json!({"group_op": "update", "base_seq": 2}),
    );
    let r = send(&mut a, &rm).await;
    assert_eq!(r["t"], "ack", "{r}");
    // 응답할 산 잎이 없어 바로 확정된다(commit_final 은 ack 앞에 올 수 있다) — relay 상태로 본다.
    assert!(h.app.db.mls_pendings().unwrap().is_empty());
    assert!(!h
        .app
        .db
        .group_leaves(&gid)
        .unwrap()
        .contains(&bob.device_id));
    let m2 = gapp(&h, &alice, &gid, epoch + 1, json!({}));
    let (r, _) = send_seen(&mut a, &m2).await;
    assert_eq!(r["t"], "ack", "{r}");
    let s = next_of(&mut a, "status").await;
    assert_eq!(
        (s["msg_id"].clone(), s["fail_reason"].as_str()),
        (m2["msg_id"].clone(), Some("recipient_device_changed")),
        "{s}"
    );
    let _ = bob2;
}

// ------------------------------------------------------------------ #598 ② × #577 §9 ② 겹친 경우

/// 1:1 응용 메시지(판 10) — g 의 지금 epoch 로 암호화.
fn pair_app(h: &Harness, alice: &User, ad: &Dev, g: &mut MlsGroup, bob: &User) -> Value {
    let ct = g.create_message(&ad.provider, &ad.signer, b"hi").unwrap();
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())});
    mls_msg(
        h,
        alice,
        &bob.address(),
        "chat",
        g.group_id().as_slice(),
        g.epoch().as_u64(),
        body,
    )
}

/// 같은 msg_id 로 다시 서명한 판(보내는 코어가 새 epoch 로 다시 암호화해 같은 글을 다시 보내는 꼴).
fn same_id(m: &Value, id: &Value, from: &User) -> Value {
    let mut m = m.clone();
    let o = m.as_object_mut().unwrap();
    o.remove("sig");
    o.insert("msg_id".into(), id.clone());
    o.insert("thread_id".into(), id.clone());
    sign_message(&mut m, &from.keys.signing).unwrap();
    m
}

/// bob 이 새 기기를 증명한 뒤 옛 기기를 끊는다 — 잎은 모두 끊겼고 새 기기는 아직 안 듦(#577 기기 바뀜 중).
async fn bob_changes_device(h: &Harness, b: &mut Client, bob: &User, seed: u8) -> User {
    let bob2 = register_extra_device(h, "bob", seed).await;
    b.send(
        &json!({"t": "device.certify", "device_id": bob2.device_id, "sig": devcert(bob, &bob2)}),
    )
    .await;
    b.send(&json!({"t": "device.revoke"})).await;
    while b.recv().await["t"] != "device.revoked" {}
    bob2
}

/// alice 가 pair 에 기기 잎 하나를 들인다(Commit + Welcome).
#[allow(clippy::too_many_arguments)]
async fn add_leaf(
    h: &Harness,
    a: &mut Client,
    alice: &User,
    ad: &Dev,
    g: &mut MlsGroup,
    bob: &User,
    who: &User,
) {
    let (c, w, _) = g
        .add_members(&ad.provider, &ad.signer, &[Dev::of(who).key_package()])
        .unwrap();
    let r = alice_commit(h, a, alice, ad, g, &bob.address(), &c, Some(&w), true).await;
    assert_eq!(r["t"], "ack", "{r}");
}

/// 이 msg_id 의 deliver 가 200ms 안에 오지 않는다(duty 같은 다른 프레임은 지나친다).
async fn no_deliver(c: &mut Client, id: &Value) {
    let end = tokio::time::Instant::now() + Duration::from_millis(200);
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout_at(end, c.ws.next()).await {
        let f: Value = serde_json::from_str(&t).unwrap();
        assert!(
            !(f["t"] == "deliver" && f["message"]["msg_id"] == *id),
            "또 받음: {f}"
        );
    }
}

/// 설계 리뷰 6512403281 🟡: 기기 바뀜으로 실패를 알린 판 10 글을 같은 msg_id 로 다시 보냈는데 새 잎이 판 9 → recipient_outdated →
/// 칸 뺀 v9 가 새 기기에 한 번 간다. 다시 받기 표시는 그 다시 보내기로 끝나 같은 글이 또 오지 않는다(보낸 사람의 다른 기기 몫으로
/// 봉투가 남아 있어도 — 1:1 이른 return 앞에서 옛 봉투·표시를 지움, 그룹과 같은 순서).
#[tokio::test(flavor = "multi_thread")]
async fn device_changed_resend_to_v9_new_leaf_goes_once() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await;
    // 보낸 사람의 다른 기기(판 10, 꺼져 있음) — 처음 글이 그 몫으로 봉투를 남겨 다시 보내기 때 header 가 있다.
    let alice2 = register_extra_device(&h, "alice", 3).await;
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    add_leaf(&h, &mut a, &alice, &ad, &mut g, &bob, &alice2).await;
    drop(connect(&h, &alice2).await); // 판 10 으로 한 번 붙었다가 꺼짐(판을 모르면 9 로 본다)
    let bob2 = bob_changes_device(&h, &mut b, &bob, 5).await;

    let m10 = pair_app(&h, &alice, &ad, &mut g, &bob);
    let id = m10["msg_id"].clone();
    assert_eq!(send(&mut a, &m10).await["t"], "ack");
    let st = next_of(&mut a, "status").await;
    assert_eq!(st["fail_reason"], "recipient_device_changed", "{st}");
    assert!(h.app.db.header(id.as_str().unwrap()).unwrap().is_some());

    // 새 기기가 판 9 앱으로 든다 → 코어가 같은 글을 다시 보낸다(판 10 그대로).
    add_leaf(&h, &mut a, &alice, &ad, &mut g, &bob, &bob2).await;
    let mut b2 = connect_v(&h, &bob2, 9).await;
    let _ = next_of(&mut b2, "deliver").await; // Welcome
    let again = same_id(&pair_app(&h, &alice, &ad, &mut g, &bob), &id, &alice);
    assert_eq!(send(&mut a, &again).await["t"], "ack");
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (&st["msg_id"], st["fail_reason"].as_str()),
        (&id, Some("recipient_outdated")),
        "{st}"
    );
    no_deliver(&mut b2, &id).await;

    // 칸 뺀 v9 — 새 기기에 한 번.
    let m9 = as_v9(&again, &alice);
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    let d = next_of(&mut b2, "deliver").await;
    assert_eq!(
        (&d["message"]["msg_id"], &d["message"]["v"]),
        (&id, &json!(9))
    );
    assert!(!h
        .app
        .db
        .device_changed_has(id.as_str().unwrap(), "alice")
        .unwrap());
    // 같은 v9 를 또 보내도(코어의 다음 다시 보내기) 두 번 가지 않는다.
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    no_deliver(&mut b2, &id).await;
}

/// 받는 사람이 기기를 바꾸는 중(잎 0)이고 보낸 사람의 다른 기기가 판 9: 판 10 글은 이른 return(봉투 없음, recipient_outdated
/// 만)이지만 v9 다시 보내기가 보통 길에서 기기 바뀜을 다시 보고 표시한다 → 새 기기가 든 뒤 같은 글이 그 기기에 간다(조용히 안 빠짐).
#[tokio::test(flavor = "multi_thread")]
async fn changing_recipient_with_sender_v9_device_still_gets_message() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await;
    // 보낸 사람의 다른 기기(판 9 앱)도 잎.
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    add_leaf(&h, &mut a, &alice, &ad, &mut g, &bob, &alice2).await;
    let mut a2 = connect_v(&h, &alice2, 9).await;
    let _ = next_of(&mut a2, "deliver").await; // Welcome
    let bob2 = bob_changes_device(&h, &mut b, &bob, 5).await;

    let m10 = pair_app(&h, &alice, &ad, &mut g, &bob);
    let id = m10["msg_id"].clone();
    assert_eq!(send(&mut a, &m10).await["t"], "ack");
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (&st["msg_id"], st["fail_reason"].as_str()),
        (&id, Some("recipient_outdated")),
        "{st}"
    );
    assert!(h.app.db.header(id.as_str().unwrap()).unwrap().is_none());

    // v9 다시 보내기: 판 9 기기엔 가고, 받는 사람 몫은 기기 바뀜으로 표시·알림.
    let m9 = as_v9(&m10, &alice);
    assert_eq!(send(&mut a, &m9).await["t"], "ack");
    let d = next_of(&mut a2, "deliver").await;
    assert_eq!(
        (&d["message"]["msg_id"], &d["message"]["v"]),
        (&id, &json!(9))
    );
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (&st["msg_id"], st["fail_reason"].as_str()),
        (&id, Some("recipient_device_changed")),
        "{st}"
    );
    assert!(h
        .app
        .db
        .device_changed_has(id.as_str().unwrap(), "alice")
        .unwrap());

    // 새 기기가 든 뒤 같은 글(코어의 기기 바뀜 다시 보내기, 본문은 이미 v9) → 새 기기가 받는다.
    add_leaf(&h, &mut a, &alice, &ad, &mut g, &bob, &bob2).await;
    let (mut b2, _) = connect(&h, &bob2).await;
    let _ = next_of(&mut b2, "deliver").await; // Welcome
    let again = same_id(
        &as_v9(&pair_app(&h, &alice, &ad, &mut g, &bob), &alice),
        &id,
        &alice,
    );
    assert_eq!(send(&mut a, &again).await["t"], "ack");
    let d = next_of(&mut b2, "deliver").await;
    assert_eq!(d["message"]["msg_id"], id);
    assert!(!h
        .app
        .db
        .device_changed_has(id.as_str().unwrap(), "alice")
        .unwrap());
}

// ------------------------------------------------------------------ 묶음 36 #613 입력 중 표시

async fn typing(c: &mut Client, to: &str, on: bool) {
    c.send(&json!({"t": "typing", "to": to, "on": on})).await;
}

/// 200ms 안에 typing 이 오지 않는다(다른 프레임은 지나친다 — 오류도 typing 의 답으로는 안 와야 하니 error 는 잡는다).
async fn no_typing(c: &mut Client) {
    let end = tokio::time::Instant::now() + Duration::from_millis(200);
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout_at(end, c.ws.next()).await {
        let f: Value = serde_json::from_str(&t).unwrap();
        assert!(f["t"] != "typing" && f["t"] != "error", "받으면 안 됨: {f}");
    }
}

/// 1:1: from 은 인증된 사용자, 받는 사람의 지금 연결된 판 11 기기에만(판 10 연결·보낸 사람 다른 기기엔 안 감), to·값마다 초당 1,
/// 클라이언트가 from 을 실으면 조용히 버림, 오프라인 기기엔 쌓지 않음.
#[tokio::test(flavor = "multi_thread")]
async fn typing_one_to_one_reaches_connected_v11_devices_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let bob2 = register_extra_device(&h, "bob", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    let (mut b, _) = connect(&h, &bob).await;
    let mut b10 = connect_v(&h, &bob2, 10).await;

    // 남을 흉내 내려고 from 을 실으면 형식 밖 — 오류 없이 버린다.
    a.send(&json!({"t": "typing", "to": bob.address(), "on": true, "from": "carol@local"}))
        .await;
    no_typing(&mut b).await;
    no_typing(&mut a).await;

    typing(&mut a, &bob.address(), true).await;
    let f = next_of(&mut b, "typing").await;
    assert_eq!(
        f,
        json!({"t": "typing", "from": alice.address(), "on": true})
    );
    no_typing(&mut b10).await;
    no_typing(&mut a2).await;
    no_typing(&mut a).await;

    // 같은 to·같은 값은 1초 안 둘째를 버린다. 값이 바뀌면(멈춤) 따로 초당 1 — 바로 간다.
    typing(&mut a, &bob.address(), true).await;
    no_typing(&mut b).await;
    typing(&mut a, &bob.address(), false).await;
    assert_eq!(next_of(&mut b, "typing").await["on"], false);
    typing(&mut a, &bob.address(), false).await;
    no_typing(&mut b).await;
    tokio::time::sleep(Duration::from_millis(900)).await;

    // 오프라인 기기엔 쌓지 않는다 — 끊긴 사이의 typing 은 다시 붙어도 안 온다.
    drop(b);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    typing(&mut a, &bob.address(), true).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut b, ready) = connect(&h, &bob).await;
    assert_eq!(ready["pending"], 0, "{ready}");
    no_typing(&mut b).await;
}

/// 범위 밖·세션 주소·자기 자신은 조용히 버리고, 접속 표시를 끈 사람은 보내지도 받지도 않는다(맞교환).
#[tokio::test(flavor = "multi_thread")]
async fn typing_scope_and_presence_share() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    set_org(&h, "carol", "other");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;

    // 다른 조직.
    typing(&mut a, &carol.address(), true).await;
    no_typing(&mut c).await;
    typing(&mut c, &alice.address(), true).await;
    no_typing(&mut a).await;
    // 세션 주소·자기 자신·없는 사람·없는 그룹.
    typing(&mut a, &format!("{}/api", bob.address()), true).await;
    typing(&mut a, &alice.address(), true).await;
    typing(&mut a, "nobody@local", true).await;
    typing(&mut a, "+01jb0000000000000000000000@local", true).await;
    no_typing(&mut b).await;
    no_typing(&mut a).await;

    // bob 이 접속 표시를 끄면: 받지 않고, 보낸 것도 가지 않는다.
    b.send(&json!({"t": "presence.set", "share": false})).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    typing(&mut a, &bob.address(), true).await;
    no_typing(&mut b).await;
    typing(&mut b, &alice.address(), true).await;
    no_typing(&mut a).await;
    // 다시 켜면 다시 간다.
    b.send(&json!({"t": "presence.set", "share": true})).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    typing(&mut a, &bob.address(), true).await;
    assert_eq!(next_of(&mut b, "typing").await["from"], alice.address());
}

/// 그룹: 보낸 사람이 지금 멤버면 나를 뺀 멤버 전원에게 group 을 붙여, 멤버 아닌 사람의 것은 버린다.
#[tokio::test(flavor = "multi_thread")]
async fn typing_group_goes_to_other_members() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;

    typing(&mut b, &gaddr(&gid), true).await;
    let f = next_of(&mut a, "typing").await;
    assert_eq!(
        f,
        json!({"t": "typing", "from": bob.address(), "group": gaddr(&gid), "on": true})
    );
    no_typing(&mut b).await;
    no_typing(&mut c).await;
    // 멤버 아닌 carol 의 것은 버린다.
    typing(&mut c, &gaddr(&gid), true).await;
    no_typing(&mut a).await;
    no_typing(&mut b).await;
}

// ------------------------------------------------------------------ 0.2.6 #809 못 엶 보고

/// 그 클라이언트에 200ms 안에 `status` 가 오지 않는다(다른 프레임은 건너뜀).
async fn no_status(c: &mut Client) {
    while let Ok(Some(Ok(Message::Text(t)))) =
        tokio::time::timeout(Duration::from_millis(200), c.ws.next()).await
    {
        let f: Value = serde_json::from_str(&t).unwrap();
        assert_ne!(f["t"], "status", "status 가 오면 안 됨: {f}");
    }
}

/// alice·bob·carol 그룹(epoch 2)과 alice 가 보낸 글 하나 — bob·carol 이 받았다. (그룹 id, 글, 글 id)
async fn group_of_three_with_message(
    h: &Harness,
    a: &mut Client,
    b: &mut Client,
    c: &mut Client,
    alice: &User,
    bob: &User,
    carol: &User,
) -> (String, Value, Value) {
    let (ad, bd, cd) = (Dev::of(alice), Dev::of(bob), Dev::of(carol));
    let (gid, mut g) = make_group(h, a, alice, &ad).await;
    let (m, _) = add_msg(h, alice, &ad, &mut g, &gid, bob, &bd, 1);
    assert_eq!(send(a, &m).await["t"], "ack");
    let (m, hash) = add_msg(h, alice, &ad, &mut g, &gid, carol, &cd, 2);
    assert_eq!(send(a, &m).await["t"], "ack");
    confirm_by(h, b, &gid, 1, &hash).await;
    let _ = next_of(c, "deliver").await; // Welcome
    let _ = next_of(a, "commit_final").await;
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[5u8; 64])});
    let m = gmsg(h, alice, &gaddr(&gid), "chat", &gid, 2, body, json!({}));
    let id = m["msg_id"].clone();
    assert_eq!(send(a, &m).await["t"], "ack");
    assert_eq!(next_of(b, "deliver").await["message"]["msg_id"], id);
    assert_eq!(next_of(c, "deliver").await["message"]["msg_id"], id);
    (gid, m, id)
}

/// #809 §1-1~1-3: bob 의 못 엶 ack 은 received 가 아니고, 30초 뒤 tick 에 alice 에게 recipient_unreadable(by bob). 같은
/// msg_id 다시 보내기는 bob 에게만 가고(carol 은 이미 열었다), 또 못 열면 final, 셋째 보고부터는 알리지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_ack_notifies_sender_once_settled_and_resend_reaches_reporter_only() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (_, m, id) =
        group_of_three_with_message(&h, &mut a, &mut b, &mut c, &alice, &bob, &carol).await;
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    no_status(&mut a).await;
    // carol 은 열었다 — 그 ack 이 received.
    c.send(&json!({"t": "delivered_ack", "msg_id": id})).await;
    let st = next_of(&mut a, "status").await;
    assert_eq!(st["state"], "received", "{st}");
    // 보고 직후 tick 은 알리지 않는다(§1-9 (나)).
    h.app.expire_tick();
    no_status(&mut a).await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (
            &st["msg_id"],
            st["state"].as_str(),
            st["fail_reason"].as_str(),
            st["by"].as_str()
        ),
        (
            &id,
            Some("failed"),
            Some("recipient_unreadable"),
            Some("bob@local")
        ),
        "{st}"
    );
    // 다시 보내기 — bob 에게만.
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert_eq!(next_of(&mut b, "deliver").await["message"]["msg_id"], id);
    c.expect_silence().await;
    // 또 못 엶 → final.
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (st["fail_reason"].as_str(), st["by"].as_str()),
        (Some("recipient_unreadable_final"), Some("bob@local")),
        "{st}"
    );
    // 다시 보내도 받지 않는다(멱등 ack) — bob 에게 가지 않는다. 셋째 보고는 알리지 않는다.
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    no_status(&mut a).await;
    assert!(!h
        .app
        .db
        .pending_for(&bob.name, &bob.device_id)
        .unwrap()
        .iter()
        .any(|(m, _)| m.contains(id.as_str().unwrap())));
}

/// unreadable-backlog 판정 §3: 못 엶 보고가 기기당 시간당 상한(100)을 넘으면 그 ack 는 버린다 — 보통 ack 로 넘기면 못 연
/// 글이 보낸 화면에 '받음'으로 뜨고 영영 못 연다. 글은 ack 안 된 채 남고, 상한이 풀린 뒤 다시 보고하면 지금 길 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_ack_over_hourly_cap_is_dropped_not_received() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (_, _, id) =
        group_of_three_with_message(&h, &mut a, &mut b, &mut c, &alice, &bob, &carol).await;
    let now = h.fx.clock.now().0;
    h.app
        .db
        .unreadable_fill_for_test(
            &bob.device_id,
            lodelai_relay::rules::UNREADABLE_PER_HOUR,
            now,
        )
        .unwrap();
    let pending = |h: &Harness| {
        h.app
            .db
            .pending_for(&bob.name, &bob.device_id)
            .unwrap()
            .iter()
            .any(|(m, _)| m.contains(id.as_str().unwrap()))
    };
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // 버림 — bob 몫은 ack 안 된 채(다음 연결에 다시 감), alice 에게 아무 상태도 없다.
    assert!(pending(&h), "상한 넘은 못 엶 ack 가 받음으로 넘어감");
    no_status(&mut a).await;
    // 한 시간 지나 상한이 풀리면 보고가 지금 길로 간다(받음 아님, 30초 뒤 recipient_unreadable).
    h.fx.clock.advance(60 * 60 * 1000 + 1);
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (st["fail_reason"].as_str(), st["by"].as_str()),
        (Some("recipient_unreadable"), Some("bob@local")),
        "{st}"
    );
}

/// #809 §1-7: recipient_unreadable 은 hello.v ≥ 14 연결에만 — 판 13 으로만 붙은 보낸 사람이면 남겨 두었다가, 판 14 로 붙을 때
/// 접속에서 보낸다. 받는 대상이 아니던 기기(dave)의 보고는 무시한다.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_notice_waits_for_v14_sender_and_ignores_non_targets() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (mut d, _) = connect(&h, &dave).await;
    let (_, _, id) =
        group_of_three_with_message(&h, &mut a, &mut b, &mut c, &alice, &bob, &carol).await;
    d.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(a);
    until_offline(&h, &alice.name).await;
    let mut a13 = connect_v(&h, &alice, 13).await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    no_status(&mut a13).await;
    drop(a13);
    until_offline(&h, &alice.name).await;
    let (mut a, _) = connect(&h, &alice).await;
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (st["fail_reason"].as_str(), st["by"].as_str()),
        (Some("recipient_unreadable"), Some("bob@local")),
        "{st}"
    );
    // dave 몫은 없다 — 한 번만.
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    no_status(&mut a).await;
}

/// #809 1:1: 그룹 id 는 글의 mls_group(pair id) — bob 의 못 엶 ack 뒤 alice 에 recipient_unreadable, 다시 보낸 것은 bob 에게.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_ack_in_pair_notifies_and_resends() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (mut g, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await; // Add commit(Welcome)
    let gid = pair_group_id(&alice.name, &bob.name);
    let ct = g
        .create_message(&ad.provider, &ad.signer, b"hello")
        .unwrap();
    let m = mls_msg(
        &h,
        &alice,
        &bob.address(),
        "chat",
        &gid,
        1,
        json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())}),
    );
    let id = m["msg_id"].clone();
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert_eq!(next_of(&mut b, "deliver").await["message"]["msg_id"], id);
    b.send(&json!({"t": "delivered_ack", "msg_id": id, "unreadable": true}))
        .await;
    no_status(&mut a).await;
    h.fx.clock.advance(30_001);
    h.app.expire_tick();
    let st = next_of(&mut a, "status").await;
    assert_eq!(
        (st["fail_reason"].as_str(), st["by"].as_str()),
        (Some("recipient_unreadable"), Some("bob@local")),
        "{st}"
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    assert_eq!(next_of(&mut b, "deliver").await["message"]["msg_id"], id);
    // 이번엔 열었다 — received.
    b.send(&json!({"t": "delivered_ack", "msg_id": id})).await;
    let st = next_of(&mut a, "status").await;
    assert_eq!(st["state"], "received", "{st}");
}

/// #819: 그룹 일(remove_user)의 Commit 이 무효로 상한(3)에 닿으면 — 관리자에게 group_alert{duty_stuck} 한 번(필수 칸은 마지막
/// 무효 Commit 값, n = 무효 수, acked 없음), 하루 동안 나눠 주지 않음, 다시 줄 때는 무효를 낸 기기 말고 다른 기기에, 관리자 접속 때 걸린 일 다시 보냄, 일이 끝나면 done 한 번.
#[tokio::test(flavor = "multi_thread")]
async fn duty_void_cap_alerts_admin_delays_and_moves_to_other_device() {
    use lodelai_relay::mls_group::{DUTY_STUCK_DELAY_MS, DUTY_VOID_MAX};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let mut h = start_db(|c| c.groups = true, Db::open(&path).unwrap()).await;
    h.db_file = Some((dir, path.clone()));
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let sql = |q: &str| {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute_batch(q).unwrap();
    };
    sql(
        "INSERT INTO orgs(org_id, name, admin, created_ms)
           SELECT org, 'org', 'alice', 0 FROM users WHERE user = 'alice';
         INSERT INTO org_admins(org_id, user) SELECT org, 'alice' FROM users WHERE user = 'alice';",
    );
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut c, _) = connect(&h, &carol).await;
    let (ad, bd, cd) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    c.send(&json!({"t": "member.leave"})).await;
    let _ = next_of(&mut b, "duty").await;
    let _ = next_of(&mut a, "duty").await;
    drop(c);
    until_offline(&h, "carol").await;

    // 앞 무효 둘(다른 기기)은 저장소로 세 둔다 — 셋째를 실제 Commit 으로.
    let now = h.fx.clock.now().0;
    for _ in 1..DUTY_VOID_MAX {
        h.app
            .db
            .duty_note_void(
                &gid,
                "remove_user",
                "carol",
                "other-device",
                now,
                DUTY_VOID_MAX,
                DUTY_STUCK_DELAY_MS,
            )
            .unwrap();
    }
    // alice 가 org_left Commit 을 내고 bob 이 fail.
    let epoch = g.epoch().as_u64();
    let seq: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT seq FROM groups WHERE gid = ?1", [&gid], |r| {
            r.get(0)
        })
        .unwrap();
    let (m, hash) = remove_msg_op(
        &h,
        &alice,
        &ad,
        &mut g,
        &gid,
        &carol,
        u64::try_from(seq).unwrap(),
        "org_left",
    );
    let r = send(&mut a, &m).await;
    assert_eq!(r["t"], "ack", "org_left Commit {r}");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // bob 의 기기는 옛 판으로 붙었던 것으로 — 알림의 stale_clients 에 bob.
    h.app.db.set_device_hello_v(&bob.device_id, 13).unwrap();
    h.fx.clock
        .advance(lodelai_relay::mls_group::PENDING_MAX_MS + 1);
    h.app.expire_tick();
    let _ = next_of(&mut b, "commit_void").await;

    // 관리자 alice 에 한 번.
    let f = next_of(&mut a, "group_alert").await;
    assert_eq!(
        (
            f["reason"].as_str(),
            f["task"].as_str(),
            f["subject"].as_str(),
            f["n"].as_u64(),
            f["failed"].clone(),
            f["acked"].clone(),
            f["sender"].as_str(),
            f["commit_hash"].as_str(),
            f["stale_clients"].clone(),
            f.get("done").is_none(),
            f.get("subject_device").is_none(),
        ),
        (
            Some("duty_stuck"),
            Some("remove_user"),
            Some("carol@local"),
            Some(DUTY_VOID_MAX),
            json!(["bob@local"]),
            json!([]),
            Some("alice@local"),
            Some(hash.as_str()),
            json!(["bob@local"]),
            true,
            true,
        ),
        "{f}"
    );
    // 하루 동안은 나눠 주지 않는다.
    let now = h.fx.clock.now().0;
    assert!(h.app.db.duties_due(now).unwrap().is_empty());
    h.app.expire_tick();
    assert!(h
        .app
        .db
        .duty_ranks(&gid, "remove_user", "carol")
        .unwrap()
        .is_empty());
    b.expect_silence().await;

    // 관리자 기기가 다시 붙으면 지금 걸린 일을 다시 받는다.
    drop(a);
    until_offline(&h, "alice").await;
    let (mut a, _) = connect(&h, &alice).await;
    let f = next_of(&mut a, "group_alert").await;
    assert_eq!(
        (f["reason"].as_str(), f["task"].as_str()),
        (Some("duty_stuck"), Some("remove_user")),
        "{f}"
    );

    // 하루 뒤: 무효를 낸 alice 의 기기 말고 bob 에.
    h.fx.clock.advance(DUTY_STUCK_DELAY_MS + 1);
    h.app.expire_tick();
    let d = next_of(&mut b, "duty").await;
    assert_eq!(d["task"].as_str(), Some("remove_user"), "{d}");
    let ranks = h.app.db.duty_ranks(&gid, "remove_user", "carol").unwrap();
    assert_eq!(
        ranks.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
        [bob.device_id.as_str()]
    );

    // 일이 끝나면(행이 지워짐) 다음 판정에서 done 한 번, 그 뒤 접속엔 걸린 일이 없다.
    sql(&format!("DELETE FROM mls_duties WHERE group_id = '{gid}'"));
    h.app.expire_tick();
    let f = next_of(&mut a, "group_alert").await;
    assert_eq!(
        (
            f["reason"].as_str(),
            f["done"].as_bool(),
            f["subject"].as_str()
        ),
        (Some("duty_stuck"), Some(true), Some("carol@local")),
        "{f}"
    );
    h.app.expire_tick();
    a.expect_silence().await;
}

/// #819: 일이 상한으로 늦춰진 동안에도 그 그룹의 사람 Commit 은 막히지 않는다 — 늦춤은 일 나눠 주기에만 걸린다.
#[tokio::test(flavor = "multi_thread")]
async fn delayed_duty_does_not_block_human_commit() {
    use lodelai_relay::mls_group::{DUTY_STUCK_DELAY_MS, DUTY_VOID_MAX};
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    // alice 의 새 기기 → add_device 일, 상한까지 무효로 세 하루 늦춘다.
    a.send(&json!({"t": "device.certify", "device_id": alice_b.device_id, "sig": devcert(&alice, &alice_b)}))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let now = h.fx.clock.now().0;
    for _ in 0..DUTY_VOID_MAX {
        h.app
            .db
            .duty_note_void(
                &gid,
                "add_device",
                &alice_b.device_id,
                "x",
                now,
                DUTY_VOID_MAX,
                DUTY_STUCK_DELAY_MS,
            )
            .unwrap();
    }
    assert!(h.app.db.duties_due(now).unwrap().is_empty());
    assert_eq!(h.app.db.duties().unwrap().len(), 1);
    let (up, hash, epoch) = update_msg(&h, &alice, &ad, &mut g, &gid, 2);
    assert_eq!(send(&mut a, &up).await["t"], "ack", "늦춘 동안 update");
    let _ = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "commit_ack", "group": gid, "epoch": epoch, "commit_hash": hash}))
        .await;
    let f = next_of(&mut b, "commit_final").await;
    assert_eq!(f["commit_hash"], hash.as_str(), "{f}");
}

/// #819 조건 2: 늦춘 동안에도 폐기된 기기는 붙을 수 없다(그룹 글이 그 기기에 가지 않는다) — remove_device 를 하루 늦춰도 폐기
/// 기기가 글을 받는 틈은 없다.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_cannot_connect_while_remove_is_delayed() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let alice_b = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    a.send(&json!({"t": "device.certify", "device_id": alice_b.device_id, "sig": devcert(&alice, &alice_b)}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.app
        .db
        .revoke_device(&alice_b.device_id, h.fx.clock.now().0, None)
        .unwrap();
    let err = handshake_answer(&h, &alice_b).await;
    assert_eq!(err["code"].as_str(), Some("device_revoked"), "{err}");
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

// ------------------------------------------------------------------ #870·#872 내 기기끼리

/// 200ms 안에 이 종류의 프레임이 오지 않는다(디렉터리 갱신 같은 다른 프레임은 지나친다).
async fn none_of(c: &mut Client, ts: &[&str]) {
    let end = tokio::time::Instant::now() + Duration::from_millis(200);
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout_at(end, c.ws.next()).await {
        let f: Value = serde_json::from_str(&t).unwrap();
        // 받은 쪽 delivered_ack 의 status received 는 보통 길 — 실패 status 만 잡는다.
        if f["t"] == "status" && f["state"] != "failed" {
            continue;
        }
        assert!(!ts.iter().any(|x| f["t"] == *x), "받으면 안 됨: {f}");
    }
}

const QUIET: &[&str] = &["deliver", "own_stream", "status", "error", "nack"];

/// alice 가 self 그룹을 만들고 둘째 기기(alice2)를 넣는다. (alice 그룹, self id)
async fn make_self(
    h: &Harness,
    a: &mut Client,
    alice: &User,
    ad: &Dev,
    alice2: &User,
    a2d: &Dev,
) -> (MlsGroup, [u8; 32]) {
    // 둘째 기기는 첫 기기의 devcert 가 있어야 잎 자격이 있다(§2b).
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(alice, alice2)}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sid = self_group_id(&alice.name);
    let mut g = ad.create(Kind::SelfDevices, &sid);
    let start = mls_msg(
        h,
        alice,
        &alice.address(),
        "mls",
        &sid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))}),
    );
    assert_eq!(send(a, &start).await["t"], "ack");
    let (commit, welcome, _) = g
        .add_members(&ad.provider, &ad.signer, &[a2d.key_package()])
        .unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let m = mls_msg(
        h,
        alice,
        &alice.address(),
        "mls",
        &sid,
        0,
        json!({
            "enc": "mls", "wire": "commit",
            "payload": data(&commit.tls_serialize_detached().unwrap()),
            "group_info": data(&ad.group_info(&g)),
            "welcome": data(&welcome.tls_serialize_detached().unwrap()),
        }),
    );
    let r = send(a, &m).await;
    assert_eq!(r["t"], "ack", "self add {r}");
    (g, sid)
}

/// self 그룹 응용 글 하나(`to` 와 `kind` 를 고른다).
fn self_app(
    h: &Harness,
    alice: &User,
    g: &mut MlsGroup,
    ad: &Dev,
    sid: &[u8],
    to: &str,
    kind: &str,
) -> Value {
    let ct = g.create_message(&ad.provider, &ad.signer, b"x").unwrap();
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&ct.tls_serialize_detached().unwrap())});
    mls_msg(h, alice, to, kind, sid, g.epoch().as_u64(), body)
}

/// own_control·own_control_result·own_delete 는 내 다른 기기에 저장 봉투로 간다(보낸 기기엔 되돌아가지 않음). hello.own
/// 없이 붙은 기기엔 전하지도 쌓지도 않고, 보낸 기기에 recipient_outdated 도 내지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn own_kinds_reach_my_new_devices_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let (mut a, _) = connect_own(&h, &alice).await;
    // #888: 붙기 전에 서명(붙은 채 승인되면 닫히고 다시 붙는다).
    certify(&mut a, &alice, &alice2).await;
    let (mut a2, _) = connect_own(&h, &alice2).await;
    let (ad, a2d) = (Dev::of(&alice), Dev::of(&alice2));
    let (mut g, sid) = make_self(&h, &mut a, &alice, &ad, &alice2, &a2d).await;
    let w = next_of(&mut a2, "deliver").await; // Welcome
    a2.send(&json!({"t": "delivered_ack", "msg_id": w["message"]["msg_id"]}))
        .await;
    for kind in ["own_control", "own_control_result", "own_delete"] {
        let m = self_app(&h, &alice, &mut g, &ad, &sid, &alice.address(), kind);
        let id = m["msg_id"].clone();
        assert_eq!(send(&mut a, &m).await["t"], "ack", "{kind}");
        let d = next_of(&mut a2, "deliver").await;
        assert_eq!(
            (&d["message"]["msg_id"], &d["message"]["kind"]),
            (&id, &json!(kind))
        );
        a2.send(&json!({"t": "delivered_ack", "msg_id": id})).await;
    }
    none_of(&mut a, QUIET).await;

    // hello.own 없이 다시 붙은 기기(옛 앱) — 전하지 않고 쌓지도 않는다. 보낸 쪽엔 status 없음.
    drop(a2);
    let (mut a2, _) = connect(&h, &alice2).await;
    let m = self_app(
        &h,
        &alice,
        &mut g,
        &ad,
        &sid,
        &alice.address(),
        "own_control",
    );
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    none_of(&mut a2, QUIET).await;
    none_of(&mut a, QUIET).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let left = h.app.db.pending_for("alice", &alice2.device_id).unwrap();
    assert!(
        !left.iter().any(|(m, _)| m.contains("own_control")),
        "{left:?}"
    );
}

/// own_* 는 내 사람 주소로만 — 세션 주소는 스키마(PersonAddress)가 형식 오류로, 남(pair 그룹·남의 사람 주소)은 chat 을 세션
/// 주소로 보낼 때와 같은 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn own_kinds_only_to_my_person_address() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect_own(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, a2d, bd) = (Dev::of(&alice), Dev::of(&alice2), Dev::of(&bob));
    let (mut sg, sid) = make_self(&h, &mut a, &alice, &ad, &alice2, &a2d).await;
    let pid = pair_group_id(&alice.name, &bob.name);
    let (mut pg, _) = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    let _ = next_of(&mut b, "deliver").await; // Welcome

    let session = format!("{}/front", alice.address());
    let baseline = send(
        &mut a,
        &self_app(&h, &alice, &mut sg, &ad, &sid, &session, "chat"),
    )
    .await;
    assert_eq!(baseline["reason"], "unroutable", "{baseline}");
    let to_session = send(
        &mut a,
        &self_app(&h, &alice, &mut sg, &ad, &sid, &session, "own_control"),
    )
    .await;
    let to_bob = send(
        &mut a,
        &self_app(&h, &alice, &mut pg, &ad, &pid, &bob.address(), "own_delete"),
    )
    .await;
    assert_eq!(
        (&to_session["t"], &to_session["code"]),
        (&json!("error"), &json!("protocol")),
        "{to_session}"
    );
    assert_eq!(
        (&to_bob["t"], &to_bob["reason"]),
        (&json!("nack"), &json!("unroutable")),
        "{to_bob}"
    );
    assert_eq!(
        to_bob.as_object().unwrap().len(),
        baseline.as_object().unwrap().len()
    );
    none_of(&mut b, QUIET).await;
    // 남의 self 그룹 id 를 실어도(내 사람 주소가 아니면) 안 된다.
    let to_bob_self = send(
        &mut a,
        &self_app(
            &h,
            &alice,
            &mut sg,
            &ad,
            &sid,
            &bob.address(),
            "own_control",
        ),
    )
    .await;
    assert_eq!(to_bob_self["reason"], "unroutable", "{to_bob_self}");
    none_of(&mut b, QUIET).await;
}

/// #870 규칙 3: 내 공개 안 한 세션 앞 request 는 내 다른 기기에 간다(등급은 받는 맥 코어가 본다). 남이 같은 주소로 보내면 없는
/// 세션과 같은 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn request_to_my_unpublished_session_passes_for_me_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect_own(&h, &alice).await;
    certify(&mut a, &alice, &alice2).await;
    let (mut a2, _) = connect_own(&h, &alice2).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, a2d, bd) = (Dev::of(&alice), Dev::of(&alice2), Dev::of(&bob));
    let (mut sg, sid) = make_self(&h, &mut a, &alice, &ad, &alice2, &a2d).await;
    let _ = next_of(&mut a2, "deliver").await; // Welcome
                                               // bob → alice pair(bob 이 만든다).
    let pid = pair_group_id(&bob.name, &alice.name);
    let (mut pg, _) = make_pair(&h, &mut b, &bob, &bd, &alice, &ad).await;
    let _ = next_of(&mut a, "deliver").await; // Welcome

    let secret = format!("{}/secret", alice.address());
    let req = |g: &mut MlsGroup, dev: &Dev, from: &User, gid: &[u8]| {
        let mut m = self_app(&h, from, g, dev, gid, &secret, "request");
        m["grade"] = json!("task");
        sign_message(&mut m, &from.keys.signing).unwrap();
        m
    };
    let mine = req(&mut sg, &ad, &alice, &sid);
    let id = mine["msg_id"].clone();
    assert_eq!(send(&mut a, &mine).await["t"], "ack");
    assert_eq!(next_of(&mut a2, "deliver").await["message"]["msg_id"], id);

    let theirs = send(&mut b, &req(&mut pg, &bd, &bob, &pid)).await;
    let gone = {
        let mut m = req(&mut pg, &bd, &bob, &pid);
        m["to"]["address"] = json!(format!("{}/nosuch", alice.address()));
        sign_message(&mut m, &bob.keys.signing).unwrap();
        send(&mut b, &m).await
    };
    assert_eq!(theirs["reason"], "unroutable", "{theirs}");
    assert_eq!(
        theirs.as_object().unwrap().keys().collect::<Vec<_>>(),
        gone.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert_eq!(gone["reason"], "unroutable");
}

/// own_stream: 같은 사용자의 지금 hello.own 으로 붙은 기기에만 from_device 를 relay 가 채워 넘긴다. 남의 기기·자기 자신·hello.own 없는
/// 연결·너무 큰 data 는 조용히 버린다(오류 없음). 저장하지 않는다 — 다시 붙어도 오지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn own_stream_reaches_my_connected_device_only() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let alice2 = register_extra_device(&h, "alice", 2).await;
    let bob = register(&h, "bob", 3).await;
    let (mut a, _) = connect_own(&h, &alice).await;
    // 승인 전 기기엔 own_stream 이 가지 않는다(#846) — 승인된 내 기기로.
    certify(&mut a, &alice, &alice2).await;
    let (mut a2, _) = connect_own(&h, &alice2).await;
    let (mut b, _) = connect(&h, &bob).await;
    let stream = |to: &str, data: &str| json!({"t": "own_stream", "to_device": to, "epoch": 3, "seq": 7, "data": data});
    a.send(&stream(&alice2.device_id, "AAAA")).await;
    assert_eq!(
        next_of(&mut a2, "own_stream").await,
        json!({"t": "own_stream", "from_device": alice.device_id, "epoch": 3, "seq": 7, "data": "AAAA"})
    );
    // 남의 기기·자기 자신·클라이언트가 from_device 를 실은 것·너무 큰 것.
    a.send(&stream(&bob.device_id, "AAAA")).await;
    a.send(&stream(&alice.device_id, "AAAA")).await;
    let mut forged = stream(&alice2.device_id, "AAAA");
    forged["from_device"] = json!(bob.device_id);
    a.send(&forged).await;
    let big = "A".repeat((lodelai_protocol::constants::OWN_STREAM_MAX_BYTES as usize / 3 + 1) * 4);
    a.send(&stream(&alice2.device_id, &big)).await;
    none_of(&mut b, QUIET).await;
    none_of(&mut a2, QUIET).await;
    none_of(&mut a, QUIET).await;

    // hello.own 없는 연결엔 가지 않는다.
    drop(a2);
    let (mut a2, _) = connect(&h, &alice2).await;
    a.send(&stream(&alice2.device_id, "AAAA")).await;
    none_of(&mut a2, QUIET).await;
    // 붙지 않은 기기 몫은 쌓지 않는다.
    drop(a2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.send(&stream(&alice2.device_id, "AAAA")).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut a2, ready) = connect_own(&h, &alice2).await;
    assert_eq!(ready["pending"], 0, "{ready}");
    none_of(&mut a2, QUIET).await;
    none_of(&mut a, QUIET).await;
}

/// #870 규칙 3 의 '나 → 내 세션' 갈래는 그룹 안 request 엔 없다 — 그룹 잎 모두가 보니 공개 안 한 내 세션이 그룹에 드러난다.
/// 그룹 안에선 지금 규칙 그대로 공개 세션만.
#[tokio::test(flavor = "multi_thread")]
async fn group_request_to_my_unpublished_session_is_unroutable() {
    let h = start_with(|c| c.groups = true).await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    a.send(&json!({"t": "session.publish", "slug": "front", "grade": "task", "liveness": "live:channel"}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack"); // 응답할 사람이 없어 바로 확정
    let _ = next_of(&mut b, "deliver").await; // Welcome
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[2u8; 64])});
    let req = |to: &str| {
        gmsg(
            &h,
            &alice,
            to,
            "request",
            &gid,
            1,
            body.clone(),
            json!({"grade": "question", "group": gaddr(&gid)}),
        )
    };
    let hidden = send(&mut a, &req("alice@local/secret")).await;
    assert_eq!(hidden["reason"], "unroutable", "{hidden}");
    none_of(&mut b, QUIET).await;
    let shown = req("alice@local/front");
    assert_eq!(send(&mut a, &shown).await["t"], "ack");
    assert_eq!(
        next_of(&mut b, "deliver").await["message"]["msg_id"],
        shown["msg_id"]
    );
}

/// #845: 다른 조직 사람의 KeyPackage 는 연락처가 되기 전엔 항목 없음(열거 없음), 수락된 연락처면 가져간다.
#[tokio::test(flavor = "multi_thread")]
async fn key_packages_claim_needs_org_or_link() {
    let h = start_two_orgs().await;
    let alice = register(&h, "alice", 1).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut e, _) = connect(&h, &erin).await;
    publish_kps(&mut e, vec![kp(&erin.keys, 60 * DAYS, false)], None).await;
    e.expect_silence().await;
    let r = claim(&mut a, &[erin.device_id.as_str()]).await;
    assert_eq!(r["items"], json!([]), "{r}");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let r = claim(&mut a, &[erin.device_id.as_str()]).await;
    assert_eq!(r["items"].as_array().map(Vec::len), Some(1), "{r}");
}

/// #845 ④ 그룹 규칙 '내가 지금 멤버': 다른 조직 사람은 연락처가 되기 전엔 그룹에 더할 수 없고, 더한 뒤엔 그룹 글이 조직을
/// 가리지 않고 오간다. 그룹이 1:1·세션을 열지는 않는다(연락처 아닌 그룹 동료 세션 앞 request 는 unroutable).
#[tokio::test(flavor = "multi_thread")]
async fn mixed_org_group_needs_link_to_add_then_carries_messages() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    b.send(&json!({"t": "session.publish", "slug": "front", "grade": "task", "liveness": "live:channel"}))
        .await;
    let (mut e, _) = connect(&h, &erin).await;
    let (bd, ed) = (Dev::of(&bob), Dev::of(&erin));

    // 연락처 전: 다른 조직 사람 add 는 unroutable.
    let ad = Dev::of(&alice);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["reason"], "unroutable");
    e.expect_silence().await;

    // 수락된 연락처(alice↔erin)면 더한다. bob 은 alice 와 같은 조직.
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let ad = Dev::of(&alice);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack"); // 응답할 사람이 없어 바로 확정
    let _ = next_of(&mut e, "deliver").await; // Welcome
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 1, &hash).await;
    let _ = next_of(&mut b, "deliver").await; // Welcome

    // erin(acme) 의 그룹 글이 alice·bob(local)에게.
    let m = gapp(&h, &erin, &gid, 2, json!({}));
    assert_eq!(send(&mut e, &m).await["t"], "ack");
    for cl in [&mut a, &mut b] {
        assert_eq!(
            next_of(cl, "deliver").await["message"]["msg_id"],
            m["msg_id"]
        );
    }
    // bob 의 그룹 글도 erin 에게.
    let m = gapp(&h, &bob, &gid, 2, json!({}));
    assert_eq!(send(&mut b, &m).await["t"], "ack");
    assert_eq!(
        next_of(&mut e, "deliver").await["message"]["msg_id"],
        m["msg_id"]
    );
    let _ = next_of(&mut a, "deliver").await;

    // erin ↔ bob 은 연락처가 아니다: 그룹 안이라도 bob 세션 앞 request 는 unroutable.
    let req = gmsg(
        &h,
        &erin,
        "bob@local/front",
        "request",
        &gid,
        2,
        json!({"enc": "mls", "wire": "app", "payload": data(&[2u8; 64])}),
        json!({"grade": "question", "group": gaddr(&gid)}),
    );
    assert_eq!(send(&mut e, &req).await["reason"], "unroutable");
    none_of(&mut b, &["deliver"]).await;
    let _ = g;
}

/// #845 ④(§7-6): 섞인 그룹에서 조직 빠짐 힌트(org_left)는 그 사람과 같은 조직이던 멤버에게만 — 다른 조직 멤버에겐 즉시·
/// 다시 붙을 때 둘 다 힌트가 없다(남의 조직 사정을 알리지 않음, 잎 빼기 Commit 은 그대로 간다).
#[tokio::test(flavor = "multi_thread")]
async fn org_left_hint_only_to_same_org_members_of_mixed_group() {
    let h = start_two_orgs_groups().await;
    let path = h.db_file.as_ref().unwrap().1.clone();
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut e, _) = connect(&h, &erin).await;
    let (ad, bd, ed) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&erin));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut e, "deliver").await; // Welcome
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 1, &hash).await;
    let _ = next_of(&mut b, "deliver").await; // Welcome
    drop(b);
    let _conn = make_alice_org_admin(&path);
    {
        let _order = h.app.group_order.lock().unwrap();
        h.app
            .db
            .member_remove("alice", "bob", h.fx.clock.now().0)
            .unwrap();
        lodelai_relay::ws::announce_org_removal(&h.app, "alice");
    }
    // 같은 조직 alice: 즉시 힌트.
    let f = next_of(&mut a, "groups").await;
    assert_eq!(f["items"][0]["org_left"][0]["user"], "bob@local", "{f}");
    // 다른 조직 erin: 즉시 groups 프레임 없음, 다시 붙어도 힌트 없음.
    none_of(&mut e, &["groups"]).await;
    drop(e);
    let (mut e, _) = connect(&h, &erin).await;
    let f = next_of(&mut e, "groups").await;
    assert_eq!(f["items"][0]["group"], gaddr(&gid), "{f}");
    assert!(f["items"][0].get("org_left").is_none(), "{f}");
    // alice 는 다시 붙어도 힌트가 있다.
    drop(a);
    let (mut a, _) = connect(&h, &alice).await;
    let f = next_of(&mut a, "groups").await;
    assert_eq!(f["items"][0]["org_left"][0]["user"], "bob@local", "{f}");
    let _ = g;
}

async fn gi_ask(c: &mut Client, f: &Value) -> Value {
    c.send(f).await;
    loop {
        let r = c.recv().await;
        if matches!(r["t"].as_str(), Some("group.invite.sent" | "error")) {
            return r;
        }
    }
}

async fn next_dir_update(c: &mut Client) -> Value {
    next_of(c, "directory.update").await
}

/// 조건에 맞는 directory.update 까지(§7-44 ②: 멤버 수가 바뀌면 대기 초대받은 사람에게 디렉터리가 더 온다).
async fn dir_update_until(c: &mut Client, ok: impl Fn(&Value) -> bool) -> Value {
    loop {
        let d = next_dir_update(c).await;
        if ok(&d) {
            return d;
        }
    }
}

/// 그 사람을 그 그룹에 add 할 수 있나(relay 그룹 규칙만).
fn may_add(h: &Harness, gid: &str, sender: &str, subject: &str) -> bool {
    h.app
        .db
        .group_op_allowed(&lodelai_relay::db::GroupOp {
            gid,
            op: "add",
            sender,
            subject: Some(subject),
            admin: None,
            now_ms: h.app.effects.clock.now().0,
        })
        .unwrap()
}

/// #845 §7-44 ②: 카드 멤버 수 = 지금 멤버 ∪ 살아 있는 다른 초대(받는 사람 빼고). 혼자 만든 뒤 초대 둘 → 각 카드 2,
/// 하나가 거절하면 남은 카드는 1 — 바뀔 때마다 대기 중인 초대받은 사람에게 디렉터리를 다시 보낸다.
#[tokio::test(flavor = "multi_thread")]
async fn group_invite_card_counts_members_and_other_invites() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let erin = register(&h, "erin", 3).await;
    let carol = register(&h, "carol", 4).await;
    set_org(&h, "erin", "acme");
    set_org(&h, "carol", "acme");
    let ct = json!({"contacts": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct.clone()).await;
    let (mut c, _) = connect_with(&h, &carol, ct.clone()).await;
    let ad = Dev::of(&alice);
    let (gid, _g) = make_group(&h, &mut a, &alice, &ad).await;
    let group = gaddr(&gid);
    let card_of = |d: &Value| -> Value { d["group_invites"][0].clone() };

    let r = gi_ask(
        &mut a,
        &json!({"t": "group.invite", "group": group, "user": "erin"}),
    )
    .await;
    assert_eq!(r["t"], "group.invite.sent", "{r}");
    assert_eq!(card_of(&next_dir_update(&mut e).await)["members"], 1);
    let r = gi_ask(
        &mut a,
        &json!({"t": "group.invite", "group": group, "user": "carol"}),
    )
    .await;
    assert_eq!(r["t"], "group.invite.sent", "{r}");
    let carol_card = card_of(&next_dir_update(&mut c).await);
    assert_eq!(carol_card["members"], 2, "alice·erin");
    assert_eq!(
        card_of(&next_dir_update(&mut e).await)["members"],
        2,
        "alice·carol"
    );

    // carol 이 거절 → erin 카드는 1.
    c.send(&json!({"t": "group.invite.answer", "id": carol_card["id"], "answer": "decline"}))
        .await;
    assert_eq!(card_of(&next_dir_update(&mut e).await)["members"], 1);
}

/// #845 ④ §7-2·§7-12: group.invite 는 지금 멤버만, 답은 늘 같은 바이트. 닿지 않는 가입한 사람에겐 카드(그룹 이름 없이
/// 초대한 사람·멤버 수), 수락하면 초대한 사람과 연락처가 되고 '들어가는 중'(joining) — 지금 멤버 기기에 groups 를 다시
/// 보내고, 연락처가 아닌 다른 멤버도 그 사람 KP 를 가져가 add 할 수 있다. add 되면 joining 은 끝. 이미 닿는 사람은 카드 없이
/// 바로 joining. 연락처 아닌 그룹 동료는 디렉터리 group_members 로만 보인다.
#[tokio::test(flavor = "multi_thread")]
async fn group_invite_card_accept_joining_and_add() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    let carol = register(&h, "carol", 4).await;
    let dave = register(&h, "dave", 5).await;
    set_org(&h, "erin", "acme");
    let ct = json!({"contacts": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut b, _) = connect_with(&h, &bob, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct.clone()).await;
    let (mut d, _) = connect_with(&h, &dave, ct.clone()).await;
    publish_kps(&mut e, vec![kp(&erin.keys, 60 * DAYS, false)], None).await;
    let (ad, bd, ed) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&erin));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await; // Welcome
    let group = gaddr(&gid);

    // 멤버 아님 → protocol.
    let r = gi_ask(
        &mut d,
        &json!({"t": "group.invite", "req": "g", "group": group, "user": "erin"}),
    )
    .await;
    assert_eq!(
        (&r["t"], &r["code"]),
        (&json!("error"), &json!("protocol")),
        "{r}"
    );
    // 카드·가입 안 한 이메일·이미 멤버 — 같은 바이트.
    let mut answers = Vec::new();
    for to in [
        json!({"user": "erin"}),
        json!({"email": "nobody@z.io"}),
        json!({"user": "bob"}),
    ] {
        let mut f = json!({"t": "group.invite", "req": "g1", "group": group});
        for (k, v) in to.as_object().unwrap() {
            f[k] = v.clone();
        }
        answers.push(gi_ask(&mut a, &f).await.to_string());
    }
    assert!(answers.iter().all(|x| *x == answers[0]), "{answers:?}");
    // 답끼리는 받은 바이트 그대로 비교, 꼴은 값으로(칸 순서는 serde_json 기능에 따라 다르다).
    assert_eq!(
        serde_json::from_str::<Value>(&answers[0]).unwrap(),
        json!({"t": "group.invite.sent", "req": "g1"})
    );

    let dir = next_dir_update(&mut e).await;
    let card = dir["group_invites"][0].clone();
    assert_eq!(
        (
            &card["group"],
            &card["by"],
            &card["members"],
            card.get("joining")
        ),
        (&json!(group), &json!("alice@local"), &json!(2), None),
        "{dir}"
    );
    // 수락 전: bob 은 erin 을 add 할 수 없고 KP 도 못 가져간다.
    assert!(!may_add(&h, &gid, "bob", "erin"));
    assert_eq!(
        claim(&mut b, &[erin.device_id.as_str()]).await["items"],
        json!([])
    );

    e.send(&json!({"t": "group.invite.answer", "id": card["id"], "answer": "accept"}))
        .await;
    let gf = next_of(&mut b, "groups").await;
    assert_eq!(gf["items"][0]["joining"], json!(["erin@local"]), "{gf}");
    // §7-57: 연락처 아닌 멤버(bob)도 들어가는 중인 사람의 가입 이름을 받는다.
    assert_eq!(
        gf["items"][0]["members_display"],
        json!([{"user": "erin@local", "display_name": "erin"}]),
        "{gf}"
    );
    let dir = dir_update_until(&mut e, |d| d["group_invites"][0]["joining"] == true).await;
    assert_eq!(dir["group_invites"][0]["joining"], true, "{dir}");
    assert!(
        h.app
            .db
            .can_reach("alice", "erin", h.app.effects.clock.now().0),
        "초대한 사람과 연락처"
    );
    assert!(!h
        .app
        .db
        .can_reach("bob", "erin", h.app.effects.clock.now().0));
    // 연락처 아닌 멤버(bob)도 '들어가는 중' 사람은 add 하고 KP 를 가져간다.
    assert!(may_add(&h, &gid, "bob", "erin"));
    let r = claim(&mut b, &[erin.device_id.as_str()]).await;
    assert_eq!(r["items"].as_array().map(Vec::len), Some(1), "{r}");

    // alice 가 add → joining 끝.
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut b, &gid, 1, &hash).await;
    b.send(&json!({"t": "groups.list"})).await;
    let gf = next_of(&mut b, "groups").await;
    assert!(gf["items"][0].get("joining").is_none(), "{gf}");
    e.send(&json!({"t": "directory.list"})).await;
    let dir = next_of(&mut e, "directory").await;
    assert_eq!(dir["group_invites"], json!([]), "{dir}");
    // 연락처 아닌 그룹 동료: 디렉터리 group_members 로만.
    // §7-14: 그룹 잎을 검증하도록 기기 키는 싣고, 이메일·접속·기기 이름·os 는 없다.
    let gm = &dir["group_members"];
    assert_eq!(gm.as_array().map(Vec::len), Some(1), "{dir}");
    assert_eq!(
        (&gm[0]["address"], &gm[0]["display"]),
        (&json!("bob@local"), &json!("bob")),
        "{dir}"
    );
    assert_eq!(
        gm[0]["devices"][0]["device_id"],
        bob.device_id.as_str(),
        "{dir}"
    );
    assert!(
        gm[0]["devices"][0]["device_pubkeys"]["ed25519"].is_string(),
        "{dir}"
    );
    for k in ["email", "online", "teams", "avatar"] {
        assert!(gm[0].get(k).is_none(), "{k}: {dir}");
    }
    for k in ["name", "os", "online", "last_seen_at", "last_auth_at"] {
        assert!(gm[0]["devices"][0].get(k).is_none(), "{k}: {dir}");
    }
    b.send(&json!({"t": "directory.list"})).await;
    let dir = next_of(&mut b, "directory").await;
    assert_eq!(dir["group_members"][0]["address"], "erin@local", "{dir}");
    assert!(!dir["people"].to_string().contains("erin@local"), "{dir}");

    // 이미 닿는 사람(같은 조직 carol): 카드 없이 바로 joining.
    let r = gi_ask(
        &mut a,
        &json!({"t": "group.invite", "req": "g2", "group": group, "user": "carol"}),
    )
    .await;
    assert_eq!(r["t"], "group.invite.sent");
    let gf = next_of(&mut b, "groups").await;
    assert_eq!(gf["items"][0]["joining"], json!(["carol@local"]), "{gf}");
    let (mut c, _) = connect_with(&h, &carol, ct).await;
    c.send(&json!({"t": "directory.list"})).await;
    let dir = next_of(&mut c, "directory").await;
    assert_eq!(dir["group_invites"][0]["joining"], true, "{dir}");
}

/// #845 ④: 옛 앱 연결(hello.contacts 없음)엔 groups.items[].joining 을 싣지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn groups_joining_hidden_from_old_app() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let (mut a, _) = connect_with(&h, &alice, json!({"contacts": true})).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let r = gi_ask(
        &mut a,
        &json!({"t": "group.invite", "group": gaddr(&gid), "user": "carol"}),
    )
    .await;
    assert_eq!(r["t"], "group.invite.sent");
    let gf = next_of(&mut b, "groups").await;
    assert!(gf["items"][0].get("joining").is_none(), "{gf}");
    a.send(&json!({"t": "groups.list"})).await;
    let gf = next_of(&mut a, "groups").await;
    assert_eq!(gf["items"][0]["joining"], json!(["carol@local"]), "{gf}");
    let _ = (g, carol);
}

/// blob.get 표를 받았나(받으면 true).
async fn blob_ticket_ok(c: &mut Client, blob_id: &str) -> bool {
    c.send(&json!({"t": "blob.get", "req": "av", "blob_id": blob_id}))
        .await;
    loop {
        let f = c.recv().await;
        if f["t"] == "blob.ticket" {
            return true;
        }
        if f["t"] == "error" && f["ref"] == "av" {
            return false;
        }
    }
}

/// #845 ⑦(§8-1): 섞인 그룹에서 연락처 아닌 동료의 얼굴 — group_members 에 look·avatar 가 실리고, 그 아바타 blob.get 은 지금 같은
/// 그룹 멤버일 때만 열린다(그룹을 나가면 다음 요청부터 막힘).
#[tokio::test(flavor = "multi_thread")]
async fn group_member_face_visible_while_in_same_group() {
    let h = start_two_orgs_groups().await;
    let path = h.db_file.as_ref().unwrap().1.clone();
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let avatar = "bobAvatarBlob00000000a";
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute(
            "INSERT INTO blobs(blob_id, user, device, purpose, ct_len, state, created_ms)
             VALUES (?1, 'bob', 'd', 'avatar', 10, 'uploaded', 0)",
            [avatar],
        )
        .unwrap();
        c.execute(
            "UPDATE users SET avatar_blob = ?1, look_json = ?2 WHERE user = 'bob'",
            [avatar, r#"{"kind":"initial","tone":2}"#],
        )
        .unwrap();
    }
    let ct = json!({"contacts": true, "look": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut b, _) = connect_with(&h, &bob, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct).await;
    let (ad, bd, ed) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&erin));
    // 그룹 전: erin 은 bob 의 아바타를 못 받는다.
    assert!(!blob_ticket_ok(&mut e, avatar).await);
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut e, "deliver").await;
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 1, &hash).await;
    let _ = next_of(&mut b, "deliver").await;
    e.send(&json!({"t": "directory.list"})).await;
    let dir = next_of(&mut e, "directory").await;
    let gm = &dir["group_members"][0];
    assert_eq!(
        (&gm["address"], &gm["avatar"], &gm["look"]["tone"]),
        (&json!("bob@local"), &json!(avatar), &json!(2)),
        "{dir}"
    );
    assert!(
        blob_ticket_ok(&mut e, avatar).await,
        "같은 그룹이면 얼굴을 받는다"
    );
    // bob 이 그룹에서 빠지면 막힌다.
    let (m, hash) = remove_msg(&h, &alice, &ad, &mut g, &gid, &bob, 3);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 2, &hash).await;
    assert!(!blob_ticket_ok(&mut e, avatar).await, "그룹을 나가면 막힘");
}

/// #877: 연락처 아닌 다른 조직의 그룹 동료가 이름·얼굴을 바꾸면 그 그룹 사람에게 바로 directory.update(다시 붙기 전에) — 그룹을
/// 나간 뒤의 바뀜은 가지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn group_member_profile_change_reaches_other_org_members_live() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let ct = json!({"contacts": true, "look": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut b, _) = connect_with(&h, &bob, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct).await;
    let (ad, bd, ed) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&erin));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut e, "deliver").await;
    let (m, hash) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 1, &hash).await;
    let _ = next_of(&mut b, "deliver").await;
    let bob_in = |f: &Value| {
        f["group_members"]
            .as_array()
            .and_then(|a| a.iter().find(|p| p["address"] == "bob@local").cloned())
    };
    // bob(연락처 아님·다른 조직)이 이름과 얼굴을 바꾼다 — erin 은 다시 붙지 않고 받는다.
    b.send(&json!({"t": "profile.update", "display_name": "밥 새이름", "look": {"kind": "initial", "tone": 5}}))
        .await;
    loop {
        let f = e.recv().await;
        if f["t"] != "directory.update" {
            continue;
        }
        if let Some(p) = bob_in(&f) {
            if p["display"] == "밥 새이름" {
                assert_eq!(p["look"]["tone"], 5, "{f}");
                break;
            }
        }
    }
    // bob 이 그룹에서 빠진 뒤의 바뀜은 erin 에 가지 않는다.
    let (m, hash) = remove_msg(&h, &alice, &ad, &mut g, &gid, &bob, 3);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    confirm_by(&h, &mut e, &gid, 2, &hash).await;
    b.send(&json!({"t": "profile.update", "display_name": "밥 셋째"}))
        .await;
    loop {
        let f = b.recv().await;
        if f["t"] == "directory.update" && f.to_string().contains("밥 셋째") {
            break;
        }
    }
    e.send(&json!({"t": "directory.list"})).await;
    loop {
        let f = e.recv().await;
        assert!(!f.to_string().contains("밥 셋째"), "그룹 밖이면 안 감: {f}");
        if f["t"] == "directory" {
            break;
        }
    }
}

/// #845 §7-25: 수락한 joining 사람은 그 그룹 멤버의 group_members 에(기기 키), joining 인 사람은 그 그룹 지금 멤버를 안다 — 수락 전
/// 카드인 사람은 안 보인다. 수락 때 디렉터리가 groups(joining) 보다 먼저 가고, 꺼져 있던 멤버는 다시 붙을 때 디렉터리를 밀린 그룹
/// Commit 보다 먼저 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn joining_people_keys_reach_group_before_commit() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let erin = register(&h, "erin", 2).await;
    let carol = register(&h, "carol", 3).await;
    set_org(&h, "erin", "acme");
    set_org(&h, "carol", "beta");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let ct = json!({"contacts": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct.clone()).await;
    let (mut c, _) = connect_with(&h, &carol, ct.clone()).await;
    let (ad, ed, cd) = (Dev::of(&alice), Dev::of(&erin), Dev::of(&carol));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &erin, &ed, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut e, "deliver").await;
    // 수락 전 카드: erin 은 carol 을 모른다.
    a.send(&json!({"t": "group.invite", "group": gaddr(&gid), "user": "carol"}))
        .await;
    let card = next_of(&mut c, "directory.update").await["group_invites"][0].clone();
    e.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut e, "directory").await;
    assert!(!d.to_string().contains("carol@"), "수락 전엔 안 보임: {d}");
    // 수락: erin 은 directory.update(carol 기기 키)를 groups(joining) 보다 먼저 받는다.
    c.send(&json!({"t": "group.invite.answer", "id": card["id"], "answer": "accept"}))
        .await;
    let mut got_dir = false;
    loop {
        let f = e.recv().await;
        if f["t"] == "directory.update" && f["group_members"].to_string().contains("carol@local") {
            assert_eq!(
                f["group_members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["address"] == "carol@local")
                    .unwrap()["devices"][0]["device_id"],
                carol.device_id.as_str()
            );
            got_dir = true;
        }
        if f["t"] == "groups" {
            assert!(got_dir, "디렉터리가 groups 보다 먼저");
            assert_eq!(f["items"][0]["joining"], json!(["carol@local"]), "{f}");
            break;
        }
    }
    // carol 은 그 그룹 지금 멤버(erin — 연락처 아님)를 안다.
    c.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut c, "directory").await;
    assert!(d["group_members"].to_string().contains("erin@local"), "{d}");
    // erin 이 꺼진 동안 alice 가 carol 을 add — 다시 붙은 erin 은 디렉터리를 그 Commit 보다 먼저 받는다.
    drop(e);
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &carol, &cd, 2);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let (mut e, _) = connect_with(&h, &erin, ct).await;
    let mut seen_dir = false;
    loop {
        let f = e.recv().await;
        if f["t"] == "directory" {
            assert!(
                f["group_members"].to_string().contains("carol@local"),
                "{f}"
            );
            seen_dir = true;
        }
        if f["t"] == "deliver" && f["message"]["msg_id"] == m["msg_id"] {
            assert!(seen_dir, "디렉터리가 밀린 Commit 보다 먼저");
            break;
        }
    }
}

/// #845 §7-26: 보낸 그룹 초대 기록은 보낸 사람에게만 — 거절해도 30일 그대로, 닿는 사람은 바로 joining 이라 행이 없다. 거두면
/// 받는 쪽 카드도 사라지고, 이미 수락했으면 거두기는 아무 일 없다.
#[tokio::test(flavor = "multi_thread")]
async fn group_invites_sent_to_sender_only_and_withdraw() {
    let h = start_two_orgs_groups().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let carol = register(&h, "carol", 3).await;
    let dave = register(&h, "dave", 4).await;
    let zed = register(&h, "zed", 5).await;
    for u in ["carol", "dave"] {
        set_org(&h, u, "acme");
    }
    let ct = json!({"contacts": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut b, _) = connect_with(&h, &bob, ct.clone()).await;
    let (mut c, _) = connect_with(&h, &carol, ct.clone()).await;
    let (mut d, _) = connect_with(&h, &dave, ct.clone()).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let _ = next_of(&mut b, "deliver").await;
    let group = gaddr(&gid);
    for u in ["carol", "dave", "zed"] {
        assert_eq!(
            gi_ask(
                &mut a,
                &json!({"t": "group.invite", "group": group, "user": u})
            )
            .await["t"],
            "group.invite.sent"
        );
    }
    a.send(&json!({"t": "directory.list"})).await;
    let dir = next_of(&mut a, "directory").await;
    let rows = dir["group_invites_sent"].as_array().cloned().unwrap();
    let names: Vec<&str> = rows.iter().map(|r| r["shown"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 2, "닿는 zed 는 바로 joining — 행 없음: {dir}");
    assert!(names.contains(&"carol") && names.contains(&"dave"), "{dir}");
    assert_eq!(rows[0]["group"], json!(group));
    // 다른 멤버(bob)에겐 없다.
    b.send(&json!({"t": "directory.list"})).await;
    assert_eq!(
        next_of(&mut b, "directory").await["group_invites_sent"],
        json!([])
    );
    // carol 거절 — 행 그대로.
    let card = next_of(&mut c, "directory.update").await["group_invites"][0]["id"].clone();
    c.send(&json!({"t": "group.invite.answer", "id": card, "answer": "decline"}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.send(&json!({"t": "directory.list"})).await;
    assert_eq!(
        next_of(&mut a, "directory").await["group_invites_sent"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // dave 앞 초대 거두기 → dave 카드도 사라짐.
    let dave_row = rows.iter().find(|r| r["shown"] == "dave").unwrap()["id"].clone();
    let dcard = next_of(&mut d, "directory.update").await["group_invites"][0]["id"].clone();
    a.send(&json!({"t": "group.invite.withdraw", "id": dave_row}))
        .await;
    let dd = dir_update_until(&mut d, |x| x["group_invites"] == json!([])).await;
    assert_eq!(dd["group_invites"], json!([]), "{dd}");
    // 거둔 뒤 수락은 아무 일 없음.
    d.send(&json!({"t": "group.invite.answer", "id": dcard, "answer": "accept"}))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!h
        .app
        .db
        .can_reach("alice", "dave", h.app.effects.clock.now().0));
    let _ = (g, zed);
}

/// §7-30: 막힌 사람 앞 그룹 초대도 카드 갈래와 같게 연락 요청 셈에 넣는다 — 상한 끝에서 답이 갈리면 막힘이 샌다.
#[tokio::test(flavor = "multi_thread")]
async fn group_invite_to_blocked_counts_like_card() {
    let h = start_two_orgs_groups().await;
    let path = h.db_file.as_ref().unwrap().1.clone();
    let alice = register(&h, "alice", 1).await;
    let _carol = register(&h, "carol", 2).await;
    let _dave = register(&h, "dave", 3).await;
    for u in ["carol", "dave"] {
        set_org(&h, u, "acme");
    }
    h.app.db.block("dave", "alice").unwrap();
    let (mut a, _) = connect_with(&h, &alice, json!({"contacts": true})).await;
    let ad = Dev::of(&alice);
    let (gid, _g) = make_group(&h, &mut a, &alice, &ad).await;
    let count = || -> i64 {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.query_row(
            "SELECT COALESCE(SUM(requested), 0) FROM link_counts WHERE user = 'alice'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    let before = count();
    // 같은 대상에게 두 번씩 — 두 번째는 두 갈래 모두 셈 없음(막힌 쪽만 또 세면 상한 끝에서 막힘이 샌다).
    for u in ["carol", "dave", "carol", "dave"] {
        assert_eq!(
            gi_ask(
                &mut a,
                &json!({"t": "group.invite", "group": gaddr(&gid), "user": u})
            )
            .await["t"],
            "group.invite.sent"
        );
    }
    assert_eq!(
        count() - before,
        2,
        "카드(carol)와 막힘(dave) 모두 한 번씩만 센다"
    );
}

/// #845 §7-56: 받는 사람이 음소거한 대화(그룹 주소)의 chat 은 푸시하지 않고, 같은 대화의 request 는 보낸다. until 이 지나면
/// chat 도 다시 간다. mute.set 은 내 계정 목록(디렉터리 mutes)에 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn muted_conversation_skips_chat_push_but_not_request() {
    let h = start_with(|c| {
        c.groups = true;
        c.mobile_push = true;
        c.push_app_ids = vec!["com.example.app".into()];
    })
    .await;
    let fake = std::sync::Arc::new(FakePush::default());
    fake.replies
        .lock()
        .unwrap()
        .push(lodelai_relay::push::Response {
            status: 200,
            headers: vec![],
            body: br#"{"access_token":"at","expires_in":3600}"#.to_vec(),
        });
    let fcm = lodelai_relay::push::Fcm::with_signer(
        "proj",
        "svc@proj.iam.gserviceaccount.com",
        "https://oauth2.googleapis.com/token",
        Box::new(NoSign),
    )
    .unwrap();
    std::sync::Arc::new(lodelai_relay::push::Outbox::new(
        lodelai_relay::push::Sender {
            apns: None,
            fcm: Some(fcm),
            transport: fake.clone(),
        },
    ))
    .install(&h.app);
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let (gid, mut g) = make_group(&h, &mut a, &alice, &ad).await;
    let (m, _) = add_msg(&h, &alice, &ad, &mut g, &gid, &bob, &bd, 1);
    assert_eq!(send(&mut a, &m).await["t"], "ack");
    let welcome = next_of(&mut b, "deliver").await;
    b.send(&json!({"t": "delivered_ack", "msg_id": welcome["message"]["msg_id"]}))
        .await;
    b.send(
        &json!({"t": "push.register", "req": "r1", "platform": "fcm", "token": "bob-fcm-token",
        "env": "prod", "app_id": "com.example.app"}),
    )
    .await;
    next_of(&mut b, "push.ok").await;
    // 그룹 request 는 멤버의 세션 앞으로만 — bob 이 세션을 공개해 둔다.
    b.send(&json!({"t": "session.publish", "slug": "front", "grade": "task", "liveness": "live:channel"}))
        .await;
    // 1분 음소거. 주소 꼴이 아니면 protocol(ref = req).
    b.send(&json!({"t": "mute.set", "req": "m0", "conv": "nope"}))
        .await;
    let e = next_of(&mut b, "error").await;
    assert_eq!(
        (&e["code"], &e["ref"]),
        (&json!("protocol"), &json!("m0")),
        "{e}"
    );
    let until = UnixMillis(h.fx.clock.now().0 + 60_000)
        .to_rfc3339()
        .unwrap();
    b.send(&json!({"t": "mute.set", "req": "m1", "conv": gaddr(&gid), "until": until}))
        .await;
    next_of(&mut b, "directory.update").await;
    assert_eq!(
        h.app.db.mutes_of("bob", h.fx.clock.now().0).unwrap(),
        vec![(gaddr(&gid), Some(h.fx.clock.now().0 + 60_000))]
    );
    drop(b);
    until_offline(&h, "bob").await;

    // 음소거한 그룹의 chat → 푸시 없음.
    let m1 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m1).await["t"], "ack");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(fcm_sends(&fake).is_empty(), "{:?}", fcm_sends(&fake));
    // 같은 그룹의 request 는 음소거와 상관없이 간다.
    let body = json!({"enc": "mls", "wire": "app", "payload": data(&[2u8; 64])});
    let req = gmsg(
        &h,
        &alice,
        "bob@local/front",
        "request",
        &gid,
        1,
        body,
        json!({"grade": "question", "group": gaddr(&gid)}),
    );
    assert_eq!(send(&mut a, &req).await["t"], "ack");
    let sent = wait_fcm_sends(&fake, 1).await;
    assert_eq!(sent[0]["message"]["token"], "bob-fcm-token");
    // until 이 지나면 chat 도 다시 간다(지난 줄은 목록에서 빠진다).
    h.fx.clock.advance(61_000);
    assert!(h
        .app
        .db
        .mutes_of("bob", h.fx.clock.now().0)
        .unwrap()
        .is_empty());
    let m2 = gapp(&h, &alice, &gid, 1, json!({}));
    assert_eq!(send(&mut a, &m2).await["t"], "ack");
    let _ = wait_fcm_sends(&fake, 2).await;
}

/// QA `--test-invite-fail`: 앞부분이 fail 인 대상의 group.invite 만 rate_limited(앱 '초대 안 됨'), 다른 대상은 그대로 보낸다.
#[tokio::test(flavor = "multi_thread")]
async fn test_invite_fail_flag_refuses_only_fail_targets() {
    let h = start_db(
        |c| {
            c.groups = true;
            c.test_invite_fail = true;
        },
        Db::memory().unwrap(),
    )
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect_with(&h, &alice, json!({"contacts": true})).await;
    let ad = Dev::of(&alice);
    let (gid, _g) = make_group(&h, &mut a, &alice, &ad).await;
    let group = gaddr(&gid);
    for to in [json!({"email": "Fail1@x.test"}), json!({"user": "failbob"})] {
        let mut f = json!({"t": "group.invite", "req": "q", "group": group});
        for (k, v) in to.as_object().unwrap() {
            f[k] = v.clone();
        }
        let r = gi_ask(&mut a, &f).await;
        assert_eq!(
            (&r["t"], &r["code"]),
            (&json!("error"), &json!("rate_limited")),
            "{to}: {r}"
        );
    }
    let r = gi_ask(
        &mut a,
        &json!({"t": "group.invite", "req": "q", "group": group, "email": "ok@x.test"}),
    )
    .await;
    assert_eq!(r["t"], "group.invite.sent", "{r}");
}

/// QA `--test-invite-fail-retry-secs`: 처음 거절은 그 초 뒤를 다시 시도 시각으로 주고, 그 전 다시 시도는 같은 시각으로 거절,
/// 지난 뒤 같은 대상의 두 번째 시도는 통과한다(앱 '다시 초대'). 다른 fail 대상은 따로 센다.
#[tokio::test(flavor = "multi_thread")]
async fn test_invite_fail_retry_passes_after_retry_secs() {
    let h = start_db(
        |c| {
            c.groups = true;
            c.test_invite_fail = true;
            c.test_invite_fail_retry_secs = 5;
        },
        Db::memory().unwrap(),
    )
    .await;
    let alice = register(&h, "alice", 1).await;
    let (mut a, _) = connect_with(&h, &alice, json!({"contacts": true})).await;
    let ad = Dev::of(&alice);
    let (gid, _g) = make_group(&h, &mut a, &alice, &ad).await;
    let group = gaddr(&gid);
    let invite =
        |email: &str| json!({"t": "group.invite", "req": "q", "group": group, "email": email});
    let r1 = gi_ask(&mut a, &invite("fail1@x.test")).await;
    assert_eq!(r1["code"], "rate_limited", "{r1}");
    h.fx.clock.advance(4_000);
    let r2 = gi_ask(&mut a, &invite("Fail1@x.test")).await;
    assert_eq!(r2["code"], "rate_limited", "아직: {r2}");
    assert_eq!(r2["until"], r1["until"], "같은 시각: {r2}");
    assert!(r1["until"].is_string(), "{r1}");
    // 다른 fail 대상은 처음 — 거절.
    let r = gi_ask(&mut a, &invite("fail2@x.test")).await;
    assert_eq!(r["code"], "rate_limited", "{r}");
    h.fx.clock.advance(1_000);
    let r = gi_ask(&mut a, &invite("fail1@x.test")).await;
    assert_eq!(r["t"], "group.invite.sent", "지난 뒤 통과: {r}");
}

/// #846: 승인 전(잎 자격 없음) 기기는 디렉터리를 내 항목만 받고 동료 typing 을 받지 않는다. 내 다른 기기가 서명하면 그 순간
/// 전체 directory.update 가 간다. 승인된 기기는 그대로 다 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn unapproved_device_sees_only_my_entry_until_certified() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    for c in [&mut a, &mut b, &mut a2] {
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_millis(200), c.ws.next()).await
        {}
    }
    let addrs = |d: &Value| -> Vec<String> {
        d["people"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["address"].as_str().unwrap().to_owned())
            .collect()
    };

    a2.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut a2, "directory").await;
    assert_eq!(addrs(&d), [alice.address()], "{d}");
    let me = &d["people"][0];
    assert!(
        me["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["device_id"] == alice2.device_id),
        "{d}"
    );
    assert_eq!(d["sessions"], json!([]), "{d}");

    // 승인된 기기는 지금과 같다.
    a.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut a, "directory").await;
    assert!(addrs(&d).contains(&bob.address()), "{d}");

    // 동료 typing 은 승인 전 기기에 가지 않는다(승인된 기기엔 간다).
    typing(&mut b, &alice.address(), true).await;
    assert_eq!(
        next_of(&mut a, "typing").await["from"],
        json!(bob.address())
    );
    no_typing(&mut a2).await;

    // 승인(내 다른 기기의 서명) 순간 error{approved} 뒤 닫힘(#888) — 다시 붙으면 전체 디렉터리.
    a.send(&json!({"t": "device.certify", "device_id": alice2.device_id, "sig": devcert(&alice, &alice2)}))
        .await;
    let e = next_of(&mut a2, "error").await;
    assert_eq!(e["code"], "approved", "{e}");
    closed(&mut a2).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    a2.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut a2, "directory").await;
    assert!(addrs(&d).contains(&bob.address()), "{d}");
    assert!(addrs(&d).contains(&alice.address()), "{d}");
}

/// 연결이 닫힐 때까지(다른 프레임은 넘김).
async fn closed(c: &mut Client) {
    loop {
        match tokio::time::timeout(Duration::from_secs(3), c.ws.next())
            .await
            .expect("닫혀야 한다")
        {
            None | Some(Err(_) | Ok(Message::Close(_))) => return,
            Some(Ok(_)) => {}
        }
    }
}

/// #888: 승인 전 기기는 허용 목록 밖 프레임을 못 한다 — 답을 기다리는 요청은 error{device_unconfirmed}(req 있으면 ref),
/// 성공 답이 없는 접속 때 일(session.publish 등)은 조용히 버림, 남의 기기 끊기는 거절, 되찾기·내 기기 로그아웃은 됨.
#[tokio::test(flavor = "multi_thread")]
async fn unapproved_device_is_limited_to_the_allow_list() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (mut a2, _) = connect(&h, &alice2).await;
    for c in [&mut a, &mut b, &mut a2] {
        while let Ok(Some(Ok(_))) =
            tokio::time::timeout(Duration::from_millis(200), c.ws.next()).await
        {}
    }
    for (f, r#ref) in [
        (
            json!({"t": "pin.set", "req": "p1", "conv": "bob@local", "index": 0}),
            json!("p1"),
        ),
        // #737 관리자 동작은 ref 없이도 답한다(앱이 안다).
        (json!({"t": "invite.create"}), Value::Null),
        (json!({"t": "member.remove", "user": "bob"}), Value::Null),
    ] {
        a2.send(&f).await;
        let e = next_of(&mut a2, "error").await;
        assert_eq!(
            (&e["code"], &e["ref"]),
            (&json!("device_unconfirmed"), &r#ref),
            "{f} {e}"
        );
    }
    // 남의 기기 끊기도 req 없는 제어 요청이라 ref 없이 답한다.
    a2.send(&json!({"t": "device.revoke", "device_id": alice.device_id}))
        .await;
    let e = next_of(&mut a2, "error").await;
    assert_eq!(
        (&e["code"], &e["ref"]),
        (&json!("device_unconfirmed"), &Value::Null),
        "{e}"
    );
    // req·msg_id 없는 그 밖 거절은 답 없이 버린다 — 앱이 걸어 둔 다른 요청(push.register 등)의 답으로 붙지 않게.
    a2.send(&json!({"t": "groups.list"})).await;
    a2.send(&json!({"t": "push.register", "req": "r1", "platform": "fcm", "token": "t", "env": "prod", "app_id": "x"}))
        .await;
    let f = loop {
        let f = a2.recv().await;
        if !matches!(f["t"].as_str(), Some("directory" | "directory.update")) {
            break f;
        }
    };
    assert_ne!(
        f["code"], "device_unconfirmed",
        "버린 것의 답이 push.register 앞에 끼면 안 됨: {f}"
    );
    assert_eq!(
        f["req"].as_str().or(f["ref"].as_str()),
        Some("r1"),
        "push.register 의 답: {f}"
    );
    // 남의 기기 끊기를 막았으니 alice 첫 기기는 그대로.
    a.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut a, "directory").await;
    assert!(d.to_string().contains(&alice.device_id), "{d}");
    // 성공 답 없는 접속 때 일은 답 없이 버림 — 동료 디렉터리에 세션이 나오지 않는다.
    a2.send(&json!({"t": "session.publish", "slug": "front", "grade": "task", "liveness": "live:channel"}))
        .await;
    none_of(&mut a2, QUIET).await;
    b.send(&json!({"t": "directory.list"})).await;
    let d = next_of(&mut b, "directory").await;
    assert_eq!(d["sessions"], json!([]), "{d}");
    // #909: 승인 전 기기는 서버 상태도 못 읽는다(관리자 계정이어도) — 관문에서 바로 거절한다. 승인된 기기의 것은 처리기까지 간다.
    a2.send(&json!({"t": "server.status"})).await;
    let e = next_of(&mut a2, "error").await;
    assert_eq!(
        (&e["code"], &e["ref"]),
        (&json!("device_unconfirmed"), &Value::Null),
        "바로 거절 답(시간 초과까지 기다리게 두지 않는다): {e}"
    );
    a.send(&json!({"t": "server.status"})).await;
    let st = loop {
        let f = a.recv().await;
        if !matches!(f["t"].as_str(), Some("directory" | "directory.update")) {
            break f;
        }
    };
    // 이 시험의 alice 는 관리자가 아니라 처리기의 거절(error{protocol, message: server.status})이 온다 — 관문은 지났다.
    assert!(
        st["t"] == "server.status" || st["message"] == "server.status",
        "승인된 기기의 요청은 처리기까지 간다: {st}"
    );
    // 이 기기 로그아웃은 된다.
    a2.send(&json!({"t": "device.revoke"})).await;
    closed(&mut a2).await;
    assert!(!h
        .app
        .db
        .devices_of("alice")
        .unwrap()
        .iter()
        .any(|x| x.device_id == alice2.device_id));
}

/// 판 16 접속 때 받침 `key_packages.low{…, last_resort:false}`(#846).
fn is_backstop_low(t: &str) -> bool {
    t.contains("\"key_packages.low\"") && t.contains("\"last_resort\":false")
}

/// #877 묶음 B: org.leave 는 옛 조직이 주인인 그룹만 org_left(+그 사람 잎 빼기 일), 다른 공간이 주인인 섞인 그룹은 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn org_leave_drops_only_old_org_groups() {
    let h = start_two_orgs_groups().await;
    let path = h.db_file.as_ref().unwrap().1.clone();
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let erin = register(&h, "erin", 3).await;
    set_org(&h, "erin", "acme");
    h.app.db.link_accept("alice", "erin", 0).unwrap();
    let old = h.app.db.user_org("alice").unwrap().unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.execute(
            "INSERT OR IGNORE INTO orgs(org_id, name, admin, created_ms, kind) VALUES (?1, 'x', 'bob', 0, 'org')",
            [&old],
        )
        .unwrap();
    }
    let ct = json!({"contacts": true});
    let (mut a, _) = connect_with(&h, &alice, ct.clone()).await;
    let (mut b, _) = connect_with(&h, &bob, ct.clone()).await;
    let (mut e, _) = connect_with(&h, &erin, ct).await;
    let (ad, bd, ed) = (Dev::of(&alice), Dev::of(&bob), Dev::of(&erin));
    // 옛 조직 그룹(bob 이 만들고 alice 를 더함).
    let (g1, mut gb) = make_group(&h, &mut b, &bob, &bd).await;
    let (m, _) = add_msg(&h, &bob, &bd, &mut gb, &g1, &alice, &ad, 1);
    assert_eq!(send(&mut b, &m).await["t"], "ack");
    let _ = next_of(&mut a, "deliver").await;
    // 다른 조직(erin, acme)이 주인인 섞인 그룹 — 연락처 alice.
    let (g2, mut ge) = make_group(&h, &mut e, &erin, &ed).await;
    let (m, _) = add_msg(&h, &erin, &ed, &mut ge, &g2, &alice, &ad, 1);
    assert_eq!(send(&mut e, &m).await["t"], "ack");
    let _ = next_of(&mut a, "deliver").await;

    let now = h.app.effects.clock.now().0;
    assert!(matches!(
        h.app.db.org_leave("alice", "pa", now).unwrap(),
        lodelai_relay::db::OrgLeaveOut::Moved { .. }
    ));
    let c = rusqlite::Connection::open(&path).unwrap();
    let in_group = |g: &str| -> bool {
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = 'alice' AND left_seq IS NULL)",
            [g],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(!in_group(&g1), "옛 조직 그룹에선 빠짐");
    assert!(in_group(&g2), "다른 공간의 섞인 그룹은 그대로");
    let duties: Vec<String> = c
        .prepare("SELECT group_id FROM mls_duties WHERE task = 'remove_user' AND subject = 'alice'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(duties, vec![g1.clone()], "잎 빼기 일은 옛 조직 그룹에만");
    assert!(h.app.db.can_reach("alice", "erin", now), "연락처는 그대로");
    assert!(!h.app.db.can_reach("alice", "bob", now), "옛 동료는 끊김");
}

/// #897: 메일 확인 끊기(recovery, 증명 없음)로 옛 기기 a1 이 끊길 때, 남은 잎(bob)은 a1 이 빠진 디렉터리를 duty(remove_device
/// a1)보다 **먼저** 받아야 한다. 거꾸로면 받는 쪽 relay-client 가 아직 디렉터리에 산 a1 을 빼는 Remove 를 remove_live 로 멈추고
/// (증명 없는 끊기라 폐기 목록에도 없다), 새 기기의 external commit 이 물러섬을 되풀이한다.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_sends_directory_before_remove_duty() {
    let h = start().await;
    let alice = register(&h, "alice", 1).await;
    let bob = register(&h, "bob", 2).await;
    let alice2 = register_extra_device(&h, "alice", 3).await;
    let (mut a, _) = connect(&h, &alice).await;
    let (mut b, _) = connect(&h, &bob).await;
    let (ad, bd) = (Dev::of(&alice), Dev::of(&bob));
    let gid = encoding::encode(&pair_group_id(&alice.name, &bob.name));
    let _ = make_pair(&h, &mut a, &alice, &ad, &bob, &bd).await;
    // a1 은 꺼져 있다(붙어 있으면 #737 로 한 번 미룬다). bob 에 쌓인 것을 비운다.
    drop(a);
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(300), b.ws.next()).await {}
    let now = h.fx.clock.now().0;
    h.app
        .db
        .recovery_schedule(
            "alice",
            &alice2.device_id,
            now,
            now,
            std::slice::from_ref(&alice.device_id),
        )
        .unwrap();
    h.app.expire_tick();
    let mut dir_without_a1 = false;
    loop {
        let t = b.recv_text().await;
        let f: Value = serde_json::from_str(&t).unwrap();
        if f["t"] == "directory.update" && !t.contains(alice.device_id.as_str()) {
            dir_without_a1 = true;
        }
        if f["t"] == "duty" {
            assert_eq!(
                f,
                json!({"t": "duty", "group": gid, "task": "remove_device", "subject": alice.device_id, "rank": 0})
            );
            assert!(dir_without_a1, "a1 이 빠진 디렉터리보다 duty 가 먼저 왔다");
            break;
        }
    }
}
