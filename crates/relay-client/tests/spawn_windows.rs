//! Windows 몫 `spawn.rs`: 같은 시험을 `/bin/sh` 대신 `.cmd` 로 흉내 낸 relay 로. 기다림은 cmd 내장 `set /p`(stdin 한 줄 대기)
//! — 앱이 stdin 을 닫지 않고 쥐므로 계속 기다리고, `sleep` 같은 손자 프로세스가 없어 자식을 끝내면 남는 것이 없다.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use lodelai_relay_client::spawn::{spawn_local, Spawn};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(format!("{name}.cmd"));
    std::fs::write(
        &p,
        format!("@echo off\r\n{}\r\n", body.replace('\n', "\r\n")),
    )
    .unwrap();
    p
}

/// 가짜 relay(`cmd.exe`) pid 가 아직 살아 있나(`tasklist` — Unix 시험의 `kill -0`). 이미지 이름도 거른다 — Windows 는
/// pid 를 빨리 다시 쓰므로 끝난 자식의 pid 를 다른 프로세스가 받아도 살아 있다고 보지 않게.
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args([
            "/NH",
            "/FO",
            "CSV",
            "/FI",
            &format!("PID eq {pid}"),
            "/FI",
            "IMAGENAME eq cmd.exe",
        ])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
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
            "echo %*> \"{args}\"\nset /p tok=\necho %tok%> \"{got}\"\necho {{\"relay\":\"ready\",\"port\":5123,\"server\":\"local\"}}\nset /p wait=",
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
        "토큰을 인자로 넘기지 않는다(작업 관리자로 보임)"
    );
    let pid = r.pid().unwrap();
    assert!(alive(pid), "확인 수단이 산 자식을 본다(양성 대조)");
    r.shutdown().await;
    assert!(!alive(pid), "핸들로 자식을 끝낸다");
}

#[tokio::test]
async fn no_ready_line_times_out_and_retries() {
    let d = tempfile::tempdir().unwrap();
    let count = d.path().join("count");
    let bin = script(
        d.path(),
        "silent-relay",
        &format!("echo x>> \"{}\"\nset /p wait=", count.display()),
    );
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
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
    let bin = script(d.path(), "garbage", "echo listening on 5123");
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
    spec.attempts = 1;
    assert!(spawn_local(&spec, "t").await.is_err());
    let bin = script(d.path(), "exits", "exit /b 1");
    let mut spec = Spawn::new(&bin, d.path().join("data"), "local");
    spec.attempts = 1;
    assert!(spawn_local(&spec, "t").await.is_err());
}

/// 진짜 relay 바이너리(`cargo build -p lodelai-relay` 뒤).
#[tokio::test]
#[ignore = "lodelai-relay 바이너리 필요"]
async fn real_relay_binary() {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let bin = target.join("debug/lodelai-relay.exe");
    let d = tempfile::tempdir().unwrap();
    let r = spawn_local(&Spawn::new(&bin, d.path().join("data"), "local"), "tok")
        .await
        .unwrap();
    assert!(r.port > 0);
    r.shutdown().await;
}

/// 동기 종료(앱 종료 경로): 상한 안에 끝난다.
#[tokio::test]
async fn kill_blocking_ends_child_within_limit() {
    let d = tempfile::tempdir().unwrap();
    let bin = script(
        d.path(),
        "relay",
        "set /p t=\necho {\"relay\":\"ready\",\"port\":5123}\nset /p wait=",
    );
    let mut r = spawn_local(&Spawn::new(&bin, d.path().join("data"), "local"), "t")
        .await
        .unwrap();
    let pid = r.pid().unwrap();
    assert!(alive(pid), "확인 수단이 산 자식을 본다(양성 대조)");
    assert!(r.kill_blocking(Duration::from_secs(2)));
    assert!(!alive(pid), "자식이 남았다");
}
