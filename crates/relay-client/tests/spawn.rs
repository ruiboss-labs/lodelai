//! 로컬 relay 자식 프로세스: 준비 줄·stdin 토큰·10초 한도·3회 재시도. 진짜 relay 대신 셸 스크립트로 흉내 낸다.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lodelai_relay_client::spawn::{spawn_local, Spawn};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[tokio::test]
async fn ready_line_and_token_on_stdin() {
    let d = tempfile::tempdir().unwrap();
    let got = d.path().join("token.txt");
    let args = d.path().join("args.txt");
    let bin = script(
        d.path(),
        "fake-relay",
        &format!(
            "echo \"$@\" > {args}\nread tok\necho \"$tok\" > {got}\necho '{{\"relay\":\"ready\",\"port\":5123,\"server\":\"local\"}}'\nexec sleep 30",
            args = args.display(),
            got = got.display()
        ),
    );
    let r = spawn_local(
        &Spawn::new(&bin, d.path().join("data"), "local"),
        "secret-token",
    )
    .await
    .unwrap();
    assert_eq!(r.port, 5123);
    assert_eq!(r.ws_url(), "ws://127.0.0.1:5123/v1/ws");
    assert_eq!(
        std::fs::read_to_string(&got).unwrap().trim(),
        "secret-token",
        "토큰은 stdin 으로"
    );
    let a = std::fs::read_to_string(&args).unwrap();
    assert!(
        a.contains("--local")
            && a.contains("--port 0")
            && a.contains("--token-stdin")
            && a.contains("--exit-on-stdin-eof"),
        "{a}"
    );
    assert!(
        !a.contains("secret-token"),
        "토큰을 인자로 넘기지 않는다(ps 로 보임)"
    );
    let pid = r.pid().unwrap();
    r.shutdown().await;
    // 끝났다(kill 0 실패)
    let alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(!alive, "핸들로 자식을 끝낸다");
}

#[tokio::test]
async fn no_ready_line_times_out_and_retries() {
    let d = tempfile::tempdir().unwrap();
    let count = d.path().join("count");
    let bin = script(
        d.path(),
        "silent-relay",
        &format!("echo x >> {}\nexec sleep 30", count.display()),
    );
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
    // 셸이 첫 줄(횟수 기록)을 실행할 시간을 넉넉히 준다 — 300ms 는 전체 시험(병렬 부하) 중에 셸이 뜨기 전에 끝내 버려
    // 횟수가 3보다 적게 찍혔다(#333).
    spec.timeout = Duration::from_secs(1);
    let t = std::time::Instant::now();
    let err = spawn_local(&spec, "t").await.err().expect("실패해야 한다");
    assert!(err.to_string().contains("준비 줄"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&count).unwrap().lines().count(),
        3,
        "최대 3번"
    );
    assert!(t.elapsed() < Duration::from_secs(8));
}

#[tokio::test]
async fn garbage_or_early_exit_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let bin = script(d.path(), "garbage", "echo 'listening on 5123'");
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
    spec.attempts = 1;
    assert!(spawn_local(&spec, "t").await.is_err());
    let bin = script(d.path(), "exits", "exit 1");
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
    spec.attempts = 1;
    assert!(spawn_local(&spec, "t").await.is_err());
}

/// 진짜 relay 바이너리(`cargo build -p lodelai-relay` 뒤). CI 에서는 돌리지 않는다.
#[tokio::test]
#[ignore = "lodelai-relay 바이너리 필요"]
async fn real_relay_binary() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lodelai-relay");
    let d = tempfile::tempdir().unwrap();
    let r = spawn_local(&Spawn::new(&bin, d.path().join("data"), "local"), "tok")
        .await
        .unwrap();
    assert!(r.port > 0);
    r.shutdown().await;
}

/// 동기 종료(앱 종료 경로): 신호 뒤 상한 안에 끝난다.
#[tokio::test]
async fn kill_blocking_ends_child_within_limit() {
    let d = tempfile::tempdir().unwrap();
    let bin = script(
        d.path(),
        "relay",
        "read t; echo '{\"relay\":\"ready\",\"port\":5123}'; exec sleep 30",
    );
    let mut r = spawn_local(&Spawn::new(&bin, d.path().join("data"), "local"), "t")
        .await
        .unwrap();
    let pid = r.pid().unwrap();
    assert!(r.kill_blocking(Duration::from_secs(2)));
    let alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .unwrap()
        .success();
    assert!(!alive, "자식이 남았다");
}
