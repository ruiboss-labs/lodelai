//! 묶음 26 §6: 판이 맞지 않아 relay 가 hello 를 거절할 때(`error{version_unsupported, min, max}`). 이 앱이 옛 판이면 다시 붙지
//! 않고, relay 가 옛 판이면 `version_retry` 마다 한 번만 다시 붙는다. 모양이 틀린 오류는 앱 쪽 업데이트로 푼다.
//! 22 전 relay 는 이 코드를 보내지 않으니 가짜 relay 로 본다.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::DeviceKeys;
use lodelai_effects::Clock;
use lodelai_relay_client::{Config, Inbound, RelayClient, VersionMismatch};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// hello 에 `answer` 로 답하고 끊는 가짜 relay. 접속 수를 센다.
async fn fake_relay(answer: Value) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let n = count.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            n.fetch_add(1, Ordering::SeqCst);
            let answer = answer.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                if let Some(Ok(Message::Text(_hello))) = ws.next().await {
                    let _ = ws.send(Message::Text(answer.to_string().into())).await;
                }
                let _ = ws.close(None).await;
            });
        }
    });
    (url, count)
}

fn start(
    url: &str,
    retry: Duration,
) -> (
    RelayClient,
    tokio::sync::mpsc::Receiver<Inbound>,
    tempfile::TempDir,
) {
    let fx = TestEffects::new(1_700_000_000_000, 3);
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::new(
        url,
        "local",
        "dana",
        DeviceKeys::generate(&[7; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.backoff_max = Duration::from_millis(50);
    c.version_retry = retry;
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (client, rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    (client, rx, dir)
}

async fn mismatch(rx: &mut tokio::sync::mpsc::Receiver<Inbound>) -> VersionMismatch {
    // 다른 이벤트가 계속 와도 끝나게 전체 상한으로 센다(#552 — 고치기 전엔 끊김이 50ms 마다 와서 멈췄다).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Inbound::VersionUnsupported(m, _))) => return m,
            Ok(Some(_)) => {}
            other => panic!("version_unsupported 가 오지 않음: {other:?}"),
        }
    }
}

fn v() -> u64 {
    u64::from(lodelai_protocol::PROTOCOL_VERSION)
}

#[tokio::test]
async fn 앱이_옛_판이면_다시_붙지_않는다() {
    let (url, count) = fake_relay(
        json!({"t": "error", "code": "version_unsupported", "min": v() + 1, "max": v() + 1}),
    )
    .await;
    let (_c, mut rx, _d) = start(&url, Duration::from_millis(100));
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::AppOutdated);
    // 백오프(50ms)·version_retry(100ms) 를 여러 번 지나도 다시 붙지 않는다.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_가_옛_판이면_version_retry_마다_한_번() {
    let (url, count) = fake_relay(json!({"t": "error", "code": "version_unsupported", "min": v().saturating_sub(2), "max": v().saturating_sub(1)})).await;
    if v() == 0 {
        // 판 0 에서는 relay 가 더 옛 판일 수 없다.
        return;
    }
    let (_c, mut rx, _d) = start(&url, Duration::from_millis(300));
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::ServerOutdated);
    // 백오프(50ms)가 아니라 300ms 간격 — 700ms 안에 많아야 세 번.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let n = count.load(Ordering::SeqCst);
    assert!((2..=3).contains(&n), "{n}번 붙음");
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::ServerOutdated);
}

#[tokio::test]
async fn 모양이_틀린_오류는_앱_업데이트로() {
    let (url, count) =
        fake_relay(json!({"t": "error", "code": "version_unsupported", "min": "x"})).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_millis(100));
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::AppOutdated);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

/// 묶음 22 §12-28 ②: challenge 를 주고 auth 를 서명 실패(`error{protocol, handshake}` — 옛·지금 relay 모양)로 끊는 가짜 relay.
/// `upgrade` 면 101 에, `healthz` 면 `/v1/healthz` 에 판 범위 헤더를 싣는다. `at_hello` 면 challenge 없이 hello 에 바로 그
/// 오류로 끊는다 — 8 전 relay 가 판이 다른 hello 를 스키마에서 거절하는 모양(#552). (접속 수, healthz GET 수).
async fn auth_failing_relay(
    upgrade: bool,
    healthz: bool,
    at_hello: bool,
) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let (count, gets) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (n, g) = (count.clone(), gets.clone());
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let (n, g) = (n.clone(), g.clone());
            tokio::spawn(async move {
                let mut peek = [0u8; 32];
                let Ok(k) = tcp.peek(&mut peek).await else {
                    return;
                };
                if peek[..k].starts_with(b"GET /v1/healthz") {
                    g.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 1024];
                    let _ = tcp.read(&mut buf).await;
                    let h = if healthz {
                        "lodelai-protocol: 8-8\r\n"
                    } else {
                        ""
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n{h}Content-Length: 2\r\nConnection: close\r\n\r\nok"
                    );
                    let _ = tcp.write_all(resp.as_bytes()).await;
                    return;
                }
                n.fetch_add(1, Ordering::SeqCst);
                let cb = move |_: &Request, mut resp: Response| {
                    if upgrade {
                        resp.headers_mut()
                            .insert("lodelai-protocol", "8-8".parse().unwrap());
                    }
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, cb).await else {
                    return;
                };
                let err = json!({"t": "error", "code": "protocol", "message": "handshake"});
                if let Some(Ok(Message::Text(_hello))) = ws.next().await {
                    if at_hello {
                        let _ = ws.send(Message::Text(err.to_string().into())).await;
                    } else {
                        let ch = json!({"t": "challenge", "nonce": lodelai_crypto::encoding::encode(&[0u8; 32])});
                        let _ = ws.send(Message::Text(ch.to_string().into())).await;
                        if let Some(Ok(Message::Text(_auth))) = ws.next().await {
                            let _ = ws.send(Message::Text(err.to_string().into())).await;
                        }
                    }
                }
                let _ = ws.close(None).await;
            });
        }
    });
    (url, count, gets)
}

/// §12-28 ②: 101·healthz 둘 다 헤더 없는 relay 의 서명 실패 → 8 전 relay(server_outdated), version_retry 마다 한 번.
#[tokio::test]
async fn 헤더_없는_relay_의_서명_실패는_server_outdated() {
    let (url, count, gets) = auth_failing_relay(false, false, false).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_millis(300));
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::ServerOutdated);
    tokio::time::sleep(Duration::from_millis(700)).await;
    let n = count.load(Ordering::SeqCst);
    assert!(
        (2..=3).contains(&n),
        "백오프(50ms)가 아니라 300ms 간격: {n}번 붙음"
    );
    assert_eq!(gets.load(Ordering::SeqCst), 1, "healthz 는 한 번만(기억)");
}

/// #552: 8 전 relay 는 판이 다른 hello 를 challenge 전에 끊는다 — 그래도 healthz 로 가려 server_outdated.
#[tokio::test]
async fn 헤더_없는_relay_가_hello_를_거절해도_server_outdated() {
    let (url, _count, gets) = auth_failing_relay(false, false, true).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_secs(60));
    assert_eq!(mismatch(&mut rx).await, VersionMismatch::ServerOutdated);
    assert_eq!(gets.load(Ordering::SeqCst), 1);
}

/// §12-28 ②: 101 에 헤더가 있는데 hello 를 거절하면(지금 relay 의 모양 틀린 hello) 지금의 백오프 — healthz 를 보지 않는다.
#[tokio::test]
async fn 헤더_있는_relay_의_hello_거절은_백오프() {
    let (url, count, gets) = auth_failing_relay(true, true, true).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        count.load(Ordering::SeqCst) >= 3,
        "백오프로 계속 다시 붙는다"
    );
    assert_eq!(gets.load(Ordering::SeqCst), 0);
    while let Ok(m) = rx.try_recv() {
        assert!(!matches!(m, Inbound::VersionUnsupported(..)), "{m:?}");
    }
}

/// §12-28 ②: 101 에 헤더가 있으면 지금의 auth 처리(백오프) — healthz 를 보지 않는다.
#[tokio::test]
async fn 헤더_있는_relay_의_서명_실패는_백오프() {
    let (url, count, gets) = auth_failing_relay(true, true, false).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        count.load(Ordering::SeqCst) >= 3,
        "백오프로 계속 다시 붙는다"
    );
    assert_eq!(gets.load(Ordering::SeqCst), 0);
    while let Ok(m) = rx.try_recv() {
        assert!(!matches!(m, Inbound::VersionUnsupported(..)), "{m:?}");
    }
}

/// §12-28 ②: 101 헤더는 터널이 지웠고 healthz 에는 있다 → 지금의 auth 처리(백오프), healthz GET 은 한 번만.
#[tokio::test]
async fn 터널이_101_헤더를_지워도_healthz_로_가린다() {
    let (url, count, gets) = auth_failing_relay(false, true, false).await;
    let (_c, mut rx, _d) = start(&url, Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        count.load(Ordering::SeqCst) >= 3,
        "백오프로 계속 다시 붙는다"
    );
    assert_eq!(gets.load(Ordering::SeqCst), 1, "healthz 는 한 번만");
    while let Ok(m) = rx.try_recv() {
        assert!(!matches!(m, Inbound::VersionUnsupported(..)), "{m:?}");
    }
}
