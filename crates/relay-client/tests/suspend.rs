//! #845: 운영자가 계정을 멈추면 relay 가 인증 뒤 `error{account_suspended, until?}` 를 보내고 닫는다 — 클라이언트는 보통
//! 다시 붙기(빠른 물러섬)를 멈추고 until 에, 없으면 `suspend_retry` 마다 다시 붙어 본다. 조직이 바뀌면(`org_changed`) 물러섬
//! 없이 곧바로 한 번 다시 붙는다. 아직 relay 가 보내지 않는 코드라 가짜 relay 로 본다.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::DeviceKeys;
use lodelai_effects::{Clock, UnixMillis};
use lodelai_relay_client::{Config, Inbound, RelayClient};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const NOW: i64 = 1_700_000_000_000;

/// hello 에 challenge, auth 에 `after_auth` 를 보내고(있으면 그 뒤 `then`) 닫는 가짜 relay. ws 접속 시각을 남긴다.
async fn fake_relay(after_auth: Value, then: Option<Value>) -> (String, Arc<Mutex<Vec<Instant>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (after_auth, then, log) = (after_auth.clone(), then.clone(), log.clone());
            tokio::spawn(async move {
                // ws 업그레이드만 센다(판 범위 healthz 같은 HTTP 요청은 빼고).
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                log.lock().unwrap().push(Instant::now());
                let text = |v: &Value| Message::Text(v.to_string().into());
                if let Some(Ok(Message::Text(_hello))) = ws.next().await {
                    let nonce = lodelai_crypto::encoding::encode(&[1u8; 32]);
                    let ch = json!({"t": "challenge", "nonce": nonce});
                    let _ = ws.send(text(&ch)).await;
                }
                if let Some(Ok(Message::Text(_auth))) = ws.next().await {
                    let _ = ws.send(text(&after_auth)).await;
                    if let Some(t) = then {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let _ = ws.send(text(&t)).await;
                    }
                }
                let _ = ws.close(None).await;
            });
        }
    });
    (url, seen)
}

fn start(
    url: &str,
) -> (
    RelayClient,
    tokio::sync::mpsc::Receiver<Inbound>,
    tempfile::TempDir,
) {
    let fx = TestEffects::new(NOW, 3);
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::new(
        url,
        "local",
        "dana",
        DeviceKeys::generate(&[9; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.backoff_max = Duration::from_millis(50);
    c.suspend_retry = Duration::from_millis(1500);
    c.suspend_floor = Duration::from_millis(1000);
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (client, rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    (client, rx, dir)
}

async fn suspended(rx: &mut tokio::sync::mpsc::Receiver<Inbound>) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Inbound::AccountSuspended { until })) => return until,
            Ok(Some(_)) => {}
            other => panic!("account_suspended 가 오지 않음: {other:?}"),
        }
    }
}

fn gaps(seen: &Mutex<Vec<Instant>>) -> Vec<Duration> {
    let s = seen.lock().unwrap();
    s.windows(2).map(|w| w[1] - w[0]).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn 멈춘_계정은_빠르게_다시_붙지_않고_기한이나_suspend_retry_에_붙어_본다() {
    // 기한 없음 → suspend_retry(1.5초)마다. 빠른 물러섬(50ms)이면 그 사이 여러 번 붙었을 것.
    let (url, seen) = fake_relay(json!({"t": "error", "code": "account_suspended"}), None).await;
    let (_c, mut rx, _d) = start(&url);
    assert_eq!(suspended(&mut rx).await, None);
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "기한 없으면 suspend_retry 전엔 다시 안 붙음"
    );
    assert_eq!(suspended(&mut rx).await, None);
    let g = gaps(&seen);
    assert!(g[0] >= Duration::from_millis(1400), "{g:?}");

    // 기한(지금 + 300ms) → 그때 붙어 본다(suspend_retry 보다 이르게). 못 읽는 기한은 없음으로.
    let until = UnixMillis(NOW + 300).to_rfc3339().unwrap();
    let (url, seen) = fake_relay(
        json!({"t": "error", "code": "account_suspended", "until": until}),
        None,
    )
    .await;
    let (_c, mut rx, _d) = start(&url);
    assert_eq!(suspended(&mut rx).await.as_deref(), Some(until.as_str()));
    assert_eq!(suspended(&mut rx).await.as_deref(), Some(until.as_str()));
    let g = gaps(&seen);
    // 시계는 멈춰 있어 기한까지 300ms 그대로 — 바닥(suspend_floor, 시험 1초) 아래로 줄이지 않는다.
    assert!(
        g[0] >= Duration::from_millis(900) && g[0] < Duration::from_millis(1400),
        "{g:?}"
    );
    // 며칠 뒤 기한이어도 suspend_retry(천장)마다 붙어 본다 — 일찍 풀렸으면 그때 이어지게(§7-13).
    let far = UnixMillis(NOW + 3 * 86_400_000).to_rfc3339().unwrap();
    let (url, seen) = fake_relay(
        json!({"t": "error", "code": "account_suspended", "until": far}),
        None,
    )
    .await;
    let (_c, mut rx, _d) = start(&url);
    suspended(&mut rx).await;
    suspended(&mut rx).await;
    let g = gaps(&seen);
    assert!(
        g[0] >= Duration::from_millis(1400) && g[0] < Duration::from_millis(2500),
        "천장: {g:?}"
    );
    let (url, _) = fake_relay(
        json!({"t": "error", "code": "account_suspended", "until": "내일"}),
        None,
    )
    .await;
    let (_c, mut rx, _d) = start(&url);
    assert_eq!(suspended(&mut rx).await, None, "못 읽는 기한은 버림");
}

#[tokio::test(flavor = "multi_thread")]
async fn 조직이_바뀌면_물러섬_없이_곧바로_한_번_다시_붙는다() {
    let ready = json!({"t": "ready", "server": "local", "pending": 0});
    let (url, seen) = fake_relay(ready, Some(json!({"t": "error", "code": "org_changed"}))).await;
    let (_c, _rx, _d) = start(&url);
    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().len() < 3 {
        assert!(
            Instant::now() < deadline,
            "다시 붙지 않음: {:?}",
            gaps(&seen)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let g = gaps(&seen);
    // 첫 다시 붙기는 바로(받은 뒤 닫힘까지 50ms + 붙기), 연달아 온 둘째는 보통 물러섬(250ms 부터).
    assert!(g[0] < Duration::from_millis(200), "{g:?}");
    assert!(g[1] >= Duration::from_millis(250), "{g:?}");
}

/// #888 이 기기가 승인되면 relay 가 `error{approved}` 뒤 닫는다 — 조직 바뀜과 같은 길로 물러섬 없이 곧바로 다시 붙는다.
#[tokio::test(flavor = "multi_thread")]
async fn 승인되면_물러섬_없이_곧바로_다시_붙는다() {
    let ready = json!({"t": "ready", "server": "local", "pending": 0});
    let (url, seen) = fake_relay(ready, Some(json!({"t": "error", "code": "approved"}))).await;
    let (_c, _rx, _d) = start(&url);
    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline, "다시 붙지 않음");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let g = gaps(&seen);
    assert!(g[0] < Duration::from_millis(200), "{g:?}");
}

/// 판 16 앞(11-10): 판을 올린 앱(16)이 옛 relay(101 헤더 `lodelai-protocol: 9-15`)에 붙으면 hello.v 를 15 로 —
/// 옛 relay 가 범위 밖 판을 version_unsupported 로 막지 않게.
#[tokio::test(flavor = "multi_thread")]
async fn 판을_올린_앱이_옛_relay_에_붙으면_hello_v_는_relay_가장_높은_판() {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let hellos = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = hellos.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let add = |_: &Request, mut r: Response| {
                    r.headers_mut()
                        .insert("lodelai-protocol", "9-15".parse().unwrap());
                    Ok(r)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, add).await else {
                    return;
                };
                if let Some(Ok(Message::Text(t))) = ws.next().await {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        log.lock().unwrap().push(v);
                    }
                }
                let _ = ws.close(None).await;
            });
        }
    });
    let fx = TestEffects::new(NOW, 3);
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::new(
        &url,
        "local",
        "dana",
        DeviceKeys::generate(&[9; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.protocol = 16;
    c.backoff_max = Duration::from_millis(50);
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (_client, _rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while hellos.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "hello 가 오지 않음");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let h = hellos.lock().unwrap()[0].clone();
    assert_eq!(h["t"], "hello");
    assert_eq!(h["v"], 15, "{h}");
}

/// #888 설계 리뷰: 101 헤더를 지우는 터널 뒤 옛 relay(9-15) — 앱 16 이 헤더 없이 16 으로 보내 version_unsupported{max:15} 를
/// 받으면 물러섬 없이 곧바로 15 로 다시 붙는다(예전엔 'relay 옛 판' 표시 뒤 version_retry 15분을 기다렸다).
#[tokio::test]
async fn 헤더_없는_옛_relay_가_판을_거절하면_그_판으로_곧바로_다시_붙는다() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let hellos = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = hellos.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                if let Some(Ok(Message::Text(t))) = ws.next().await {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        let too_new = v["v"].as_u64().is_some_and(|n| n > 15);
                        log.lock().unwrap().push(v);
                        if too_new {
                            let e = json!({"t": "error", "code": "version_unsupported", "min": 9, "max": 15});
                            let _ = ws.send(Message::Text(e.to_string().into())).await;
                        }
                    }
                }
                let _ = ws.close(None).await;
            });
        }
    });
    let fx = TestEffects::new(NOW, 3);
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::new(
        &url,
        "local",
        "dana",
        DeviceKeys::generate(&[9; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.protocol = 16;
    // 물러섬이면 이 시험 안에 두 번째 hello 가 오지 않는다 — 곧바로 다시 붙을 때만 온다.
    c.backoff_max = Duration::from_secs(60);
    c.version_retry = Duration::from_secs(60);
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (_client, _rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while hellos.lock().unwrap().len() < 2 {
        assert!(
            Instant::now() < deadline,
            "두 번째 hello 가 오지 않음: {:?}",
            hellos.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let h = hellos.lock().unwrap().clone();
    assert_eq!(h[0]["v"], 16, "{h:?}");
    assert_eq!(h[1]["v"], 15, "{h:?}");
}
