//! #1171: relay 가 이 기기의 서명(auth)을 연달아 거절하면(모르는 기기·서명 안 맞음 — relay 는 같은 `error{protocol}` 로 답해
//! 가를 수 없다) 3번 + `reject_grace` 뒤 `Inbound::AuthRejected` 를 한 번 내고 `version_retry` 마다 다시 붙어 본다. 멈추지
//! 않는다 — relay 가 돌아오면 다음 `Ready` 로 풀린다. 그리고 「당겨서 새로고침」(`reconnect_now`)은 남은 기다림을 건너뛴다.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::DeviceKeys;
use lodelai_effects::Clock;
use lodelai_relay_client::{Config, Inbound, RelayClient};
use lodelai_testkit::effects::TestEffects;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Receiver;
use tokio_tungstenite::tungstenite::Message;

/// 접속 하나에 가짜 relay 가 하는 일.
#[derive(Clone, Copy)]
enum Step {
    /// challenge 를 주고 auth 를 거절한다(지금 relay 의 모르는 기기·서명 실패).
    Reject,
    /// hello 를 challenge 없이 거절한다.
    HelloReject,
    /// 아무 답 없이 닫는다(접속 실패).
    Drop,
    /// hello 에 판 불일치(서버가 옛 판)로 답한다.
    Outdated,
    /// ready 를 주고 이만큼 뒤 닫는다.
    Ready(Duration),
}

/// 접속 차례대로 `script` 를 따르는 가짜 relay(다 쓰면 마지막 것을 되풀이). ws 접속 시각을 남긴다.
async fn fake_relay(script: Vec<Step>) -> (String, Arc<Mutex<Vec<Instant>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (script, log) = (script.clone(), log.clone());
            tokio::spawn(async move {
                // ws 업그레이드만 센다(판 범위 healthz 같은 HTTP 요청은 빼고).
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let n = {
                    let mut l = log.lock().unwrap();
                    l.push(Instant::now());
                    l.len() - 1
                };
                let step = script[n.min(script.len() - 1)];
                let text = |v: Value| Message::Text(v.to_string().into());
                let no = json!({"t": "error", "code": "protocol", "message": "handshake"});
                if matches!(step, Step::Drop) {
                    let _ = ws.close(None).await;
                    return;
                }
                let Some(Ok(Message::Text(_hello))) = ws.next().await else {
                    return;
                };
                match step {
                    Step::HelloReject => {
                        let _ = ws.send(text(no)).await;
                    }
                    Step::Outdated => {
                        let old = json!({"t": "error", "code": "version_unsupported", "min": 1, "max": 1});
                        let _ = ws.send(text(old)).await;
                    }
                    _ => {
                        let nonce = lodelai_crypto::encoding::encode(&[1u8; 32]);
                        let _ = ws
                            .send(text(json!({"t": "challenge", "nonce": nonce})))
                            .await;
                        if let Some(Ok(Message::Text(_auth))) = ws.next().await {
                            if let Step::Ready(hold) = step {
                                let ready = json!({"t": "ready", "server": "local", "pending": 0});
                                let _ = ws.send(text(ready)).await;
                                tokio::time::sleep(hold).await;
                            } else {
                                let _ = ws.send(text(no)).await;
                            }
                        }
                    }
                }
                let _ = ws.close(None).await;
            });
        }
    });
    (url, seen)
}

struct Times {
    grace: Duration,
    version_retry: Duration,
    backoff_max: Duration,
}

const FAST: Times = Times {
    grace: Duration::ZERO,
    version_retry: Duration::from_millis(1500),
    backoff_max: Duration::from_millis(50),
};

fn start(url: &str, t: &Times) -> (RelayClient, Receiver<Inbound>, tempfile::TempDir) {
    let fx = TestEffects::new(1_700_000_000_000, 3);
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::new(
        url,
        "local",
        "dana",
        DeviceKeys::generate(&[9; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.backoff_max = t.backoff_max;
    c.version_retry = t.version_retry;
    c.reject_grace = t.grace;
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (client, rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    (client, rx, dir)
}

/// `want` 가 올 때까지 받는다(5초). 그 사이 온 것 가운데 AuthRejected 수를 돌려준다(`want` 자신은 뺀다).
async fn until(rx: &mut Receiver<Inbound>, want: impl Fn(&Inbound) -> bool) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut rejected = 0;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(i)) if want(&i) => return rejected,
            Ok(Some(Inbound::AuthRejected)) => rejected += 1,
            Ok(Some(_)) => {}
            other => panic!("기다린 것이 오지 않음: {other:?}"),
        }
    }
}

/// `wait` 동안 온 AuthRejected·Ready 수.
async fn during(rx: &mut Receiver<Inbound>, wait: Duration) -> (usize, usize) {
    let deadline = tokio::time::Instant::now() + wait;
    let (mut rejected, mut ready) = (0, 0);
    while let Ok(Some(i)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        match i {
            Inbound::AuthRejected => rejected += 1,
            Inbound::Ready { .. } => ready += 1,
            _ => {}
        }
    }
    (rejected, ready)
}

fn count(seen: &Mutex<Vec<Instant>>) -> usize {
    seen.lock().unwrap().len()
}

fn gaps(seen: &Mutex<Vec<Instant>>) -> Vec<Duration> {
    let s = seen.lock().unwrap();
    s.windows(2).map(|w| w[1] - w[0]).collect()
}

/// `n` 번째 접속이 올 때까지(5초).
async fn connects(seen: &Mutex<Vec<Instant>>, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while count(seen) < n {
        assert!(
            Instant::now() < deadline,
            "접속 {n}번이 오지 않음: {:?}",
            gaps(seen)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn 거절이_3번_넘고_grace_가_지나면_한_번_알리고_version_retry_마다_붙어_본다() {
    let (url, seen) = fake_relay(vec![Step::Reject]).await;
    let t = Times {
        grace: Duration::from_millis(400),
        ..FAST
    };
    let (_c, mut rx, _d) = start(&url, &t);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    let at = count(&seen);
    {
        let s = seen.lock().unwrap();
        assert!(at >= 3, "3번 전에는 알리지 않는다: {at}");
        // 3번이 넘어도 첫 거절부터 grace 가 지나야 한다(빠른 물러섬 50ms 라 3번째는 100ms 남짓).
        assert!(
            s[at - 1] - s[0] >= Duration::from_millis(350),
            "grace 전에 알림: {:?}",
            s[at - 1] - s[0]
        );
    }
    // 알린 뒤는 빠른 물러섬이 아니라 version_retry(1.5초) — 그 사이 다시 붙지 않고, 또 알리지도 않는다.
    assert_eq!(during(&mut rx, Duration::from_millis(1000)).await, (0, 0));
    assert_eq!(count(&seen), at, "version_retry 전엔 다시 안 붙음");
    connects(&seen, at + 2).await;
    let g = gaps(&seen);
    assert!(g[at - 1] >= Duration::from_millis(1400), "{g:?}");
    assert!(g[at] >= Duration::from_millis(1400), "{g:?}");
    assert_eq!(
        during(&mut rx, Duration::from_millis(100)).await.0,
        0,
        "한 연속에 한 번만"
    );
}

/// 로컬 relay 의 「연결 대기」 멤버 기기: 주인 승인 전엔 접속마다 auth 거절 — 알리지도, version_retry 로 늦추지도 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 등록_전_계정은_붙기_전_거절을_세지_않고_한_번_붙은_뒤부터_센다() {
    use Step::{Ready, Reject};
    let (url, seen) = fake_relay(vec![
        Reject,
        Reject,
        Reject,
        Reject,
        Reject,
        Ready(Duration::from_millis(50)),
        Reject,
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let fx = TestEffects::new(1_700_000_000_000, 3);
    let mut c = Config::new(
        url.as_str(),
        "local",
        "dana",
        DeviceKeys::generate(&[9; 64]),
        zeroize::Zeroizing::new([7; 32]),
    );
    c.backoff_max = FAST.backoff_max;
    c.version_retry = Duration::from_secs(60);
    c.reject_grace = Duration::ZERO;
    c.registered = false;
    let clock: Arc<dyn Clock> = fx.clock.clone();
    let (_c, mut rx) =
        RelayClient::start(c, &dir.path().join("q.db"), clock, fx.rng.clone()).unwrap();
    // 다섯 번 거절(문턱 3 을 넘음)에도 알림 없이 보통 물러섬으로 붙는다 — version_retry(60초)에 걸리면 until 이 5초에 넘어진다.
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::Ready { .. })).await,
        0,
        "붙기 전 거절은 세지 않는다"
    );
    // 한 번 붙은 뒤의 거절은 등록된 기기처럼 센다.
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    assert!(count(&seen) >= 9, "붙은 뒤 거절 셋: {}", count(&seen));
}

#[tokio::test(flavor = "multi_thread")]
async fn 두_번_거절_뒤_붙으면_알리지_않는다() {
    use Step::{Ready, Reject};
    let hold = Duration::from_secs(10);
    let (url, _seen) = fake_relay(vec![Reject, Reject, Ready(hold)]).await;
    let (_c, mut rx, _d) = start(&url, &FAST);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::Ready { .. })).await,
        0
    );
    assert_eq!(during(&mut rx, Duration::from_millis(300)).await.0, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn 거절_사이의_접속_실패는_세지도_지우지도_않는다() {
    use Step::{Drop, Reject};
    let (url, seen) = fake_relay(vec![Reject, Drop, Reject, Drop, Reject]).await;
    let (_c, mut rx, _d) = start(&url, &FAST);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    assert_eq!(count(&seen), 5, "세 번째 거절(다섯째 접속)에서 알린다");
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_전_거절은_세지_않고_연속을_끊는다() {
    use Step::{HelloReject, Ready, Reject};
    // hello 거절만 오면 몇 번이 와도 알리지 않는다.
    let (url, seen) = fake_relay(vec![HelloReject]).await;
    let (_c, mut rx, _d) = start(&url, &FAST);
    connects(&seen, 5).await;
    assert_eq!(during(&mut rx, Duration::from_millis(100)).await.0, 0);
    // relay 가 다른 답을 하면 연속이 끊긴다 — 둘·(hello 거절)·둘은 셋이 아니다.
    let hold = Duration::from_secs(10);
    let script = vec![Reject, Reject, HelloReject, Reject, Reject, Ready(hold)];
    let (url, _seen) = fake_relay(script).await;
    let (_c, mut rx, _d) = start(&url, &FAST);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::Ready { .. })).await,
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn 알린_뒤_붙으면_풀리고_다음_거절은_처음부터_다시_센다() {
    use Step::{Ready, Reject};
    let short = Duration::from_millis(100);
    let script = vec![
        Reject,
        Reject,
        Reject,
        Ready(short),
        Reject,
        Reject,
        Ready(short),
        Reject,
        Reject,
        Reject,
    ];
    let (url, seen) = fake_relay(script).await;
    let t = Times {
        version_retry: Duration::from_millis(300),
        ..FAST
    };
    let (_c, mut rx, _d) = start(&url, &t);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    assert_eq!(count(&seen), 3);
    // version_retry 뒤 붙는다 → 보통 연결. 그 뒤 거절 둘은 셋이 아니라 알리지 않고, 다시 붙은 뒤 셋째 거절에서 다시 알린다.
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::Ready { .. })).await,
        0
    );
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::Ready { .. })).await,
        0
    );
    assert_eq!(count(&seen), 7, "{:?}", gaps(&seen));
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    assert_eq!(count(&seen), 10);
}

/// 당겨서 새로고침: 15분 기다림(인증 거절) 중이면 지금 한 번 붙어 본다 — 또 거절이면 다시 알리지 않고 도로 version_retry.
/// 연달아 당긴 것은 `RECONNECT_NOW_MIN` 안에서 버린다.
#[tokio::test(flavor = "multi_thread")]
async fn reconnect_now_는_거절_기다림을_건너뛰고_또_거절이면_다시_알리지_않는다() {
    let (url, seen) = fake_relay(vec![Step::Reject]).await;
    let t = Times {
        version_retry: Duration::from_secs(60),
        ..FAST
    };
    let (c, mut rx, _d) = start(&url, &t);
    assert_eq!(
        until(&mut rx, |i| matches!(i, Inbound::AuthRejected)).await,
        0
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(count(&seen), 3, "기다리는 중");
    c.reconnect_now();
    connects(&seen, 4).await;
    // 바로 또 당겨도(3초 안) 받지 않는다.
    tokio::time::sleep(Duration::from_millis(200)).await;
    c.reconnect_now();
    assert_eq!(
        during(&mut rx, Duration::from_millis(500)).await.0,
        0,
        "다시 알리지 않음"
    );
    assert_eq!(count(&seen), 4, "도로 version_retry — 연달아 당김은 버림");
    // 바닥이 지나면 다시 받는다.
    tokio::time::sleep(lodelai_relay_client::RECONNECT_NOW_MIN).await;
    c.reconnect_now();
    connects(&seen, 5).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnect_now_는_서버_옛_판_기다림도_건너뛰고_도로_version_retry() {
    let (url, seen) = fake_relay(vec![Step::Outdated]).await;
    let t = Times {
        version_retry: Duration::from_secs(60),
        ..FAST
    };
    let (c, mut rx, _d) = start(&url, &t);
    let outdated = |i: &Inbound| matches!(i, Inbound::VersionUnsupported(..));
    until(&mut rx, outdated).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(count(&seen), 1, "기다리는 중");
    c.reconnect_now();
    until(&mut rx, outdated).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count(&seen), 2, "도로 version_retry");
}

/// 물러섬 중에 당기면 지금 한 번 붙어 볼 뿐, 물러섬 단계는 처음으로 돌리지 않는다(죽은 relay 를 당길 때마다 빠르게 두드리지 않게).
#[tokio::test(flavor = "multi_thread")]
async fn reconnect_now_는_물러섬_단계를_처음으로_돌리지_않는다() {
    let (url, seen) = fake_relay(vec![Step::Drop]).await;
    let t = Times {
        backoff_max: Duration::from_secs(30),
        ..FAST
    };
    let (c, _rx, _d) = start(&url, &t);
    // 250ms·500ms·1초 뒤 넷째 접속, 다음 기다림은 2초.
    connects(&seen, 4).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    c.reconnect_now();
    connects(&seen, 5).await;
    let g = gaps(&seen);
    assert!(g[3] < Duration::from_millis(1000), "바로 붙음: {g:?}");
    // 당긴 뒤의 다음 기다림은 250ms 가 아니라 이어서 4초.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        count(&seen),
        5,
        "물러섬이 처음으로 돌아감: {:?}",
        gaps(&seen)
    );
}
