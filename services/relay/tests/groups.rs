//! 사용자당 기기 상한(묶음 16 §3a ①). 그룹 표·seq·거절 바이트·조직 빠짐 등 그룹 시험은 판 7(묶음 22 ⑧)부터 MLS 로
//! `tests/mls.rs` 에 있다(group_* 시험). 시간·ID·난수는 testkit 고정 구현.

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

const START_MS: i64 = 1_792_728_776_000;
const TOKEN: &str = "test-registration-token";
const SERVER: &str = "local";

struct Harness {
    app: App,
    addr: SocketAddr,
    _fx: TestEffects,
    _dir: tempfile::TempDir,
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
    // 그룹 시험은 플래그를 켠 설정으로(묶음 16 §3b — 기본은 꺼짐).
    config.groups = true;
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
    Harness {
        app,
        addr,
        _fx: fx,
        _dir: dir,
    }
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
                // 여기서 보지 않는 프레임(디렉터리 갱신·발신자 status·relay 가 먼저 보내는 groups)은 건너뛴다.
                if v["t"] != "directory.update" && v["t"] != "status" && v["t"] != "groups" {
                    return v;
                }
            }
        }
    }

    async fn ask(&mut self, v: &Value) -> Value {
        self.send(v).await;
        self.recv().await
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

fn devs(h: &Harness, users: &[&User]) -> Vec<String> {
    let mut ids: Vec<String> = users
        .iter()
        .flat_map(|u| h.app.db.devices_of(&u.name).unwrap())
        .map(|d| d.device_id)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// §3a ①: 사용자당 폐기 안 된 기기는 설정 상한(기본 4)까지 — 5번째 등록은 409 too_many_devices, 하나를 끊으면 다시 된다.
#[tokio::test(flavor = "multi_thread")]
async fn device_cap_counts_live_devices_only() {
    let h = start().await;
    let first = register(&h, "alice", 1, false).await;
    for seed in 2..=4u8 {
        register(&h, "alice", seed, true).await;
    }
    let keys = DeviceKeys::generate(&[9u8; 64]);
    let x = keys.exchange.public_key();
    let body = json!({
        "user": "alice",
        "existing_user": true,
        "device_pubkeys": {
            "ed25519": keys.signing.verifying_key().to_b64(),
            "x25519": encoding::encode(&x),
            "x25519_sig": lodelai_crypto::xkey::sign(&keys.signing, keys.device_id().as_str(), &x),
        },
    })
    .to_string();
    let auth = format!("Bearer {TOKEN}");
    let hdrs = [
        ("Content-Type", "application/json"),
        ("Authorization", auth.as_str()),
    ];
    let post = || http(h.addr, "POST", "/v1/devices", &hdrs, body.as_bytes());
    let (code, _, resp) = post().await;
    assert_eq!(code, 409);
    assert_eq!(
        serde_json::from_slice::<Value>(&resp).unwrap()["error"],
        "too_many_devices"
    );
    // 가장 늦게 들어온 기기를 첫 기기가 끊으면 자리가 난다.
    let last = devs(&h, &[&first])
        .into_iter()
        .find(|d| *d != first.device_id)
        .unwrap();
    let mut c1 = connect(&h, &first).await;
    let r = c1
        .ask(&json!({"t": "device.revoke", "device_id": last}))
        .await;
    assert_eq!(r["t"], "device.revoked", "{r}");
    assert_eq!(post().await.0, 201);

    // 설정으로 바꾼 상한.
    let h2 = start_with(|c| c.max_devices_per_user = 1).await;
    register(&h2, "bob", 1, false).await;
    let k2 = DeviceKeys::generate(&[2u8; 64]);
    let x2 = k2.exchange.public_key();
    let b2 = json!({"user": "bob", "existing_user": true, "device_pubkeys": {
        "ed25519": k2.signing.verifying_key().to_b64(), "x25519": encoding::encode(&x2),
        "x25519_sig": lodelai_crypto::xkey::sign(&k2.signing, k2.device_id().as_str(), &x2)}})
    .to_string();
    let (code, _, _) = http(
        h2.addr,
        "POST",
        "/v1/devices",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &auth),
        ],
        b2.as_bytes(),
    )
    .await;
    assert_eq!(code, 409);
}
