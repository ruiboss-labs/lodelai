//! 로컬 relay 자식 프로세스(M1-D2). 앱이 `lodelai-relay --local …` 을 띄우고 stdin 으로 등록 토큰을 넘긴 뒤
//! stdout 의 준비 줄(`{"relay":"ready","port":N,"server":…}`)을 10초 안에 받는다. 실패하면 최대 3번(`RELAY_HANDSHAKE_*`).
//!
//! 자식은 [`LocalRelay`] 가 쥔 `Child` 핸들로만 끝낸다(`kill_on_drop`). 파일에 적힌 PID 를 재기동 뒤 그대로 죽이지 않는다 —
//! PID 는 재사용되므로 남의 프로세스일 수 있다. stdin 은 토큰 뒤에도 닫지 않고 쥔다 — 앱이 크래시·SIGKILL 로 죽으면 커널이
//! 닫고, relay 는 `--exit-on-stdin-eof` 로 스스로 끝난다(#338, 고아 relay 가 같은 데이터를 쥐지 않게).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

use crate::{Error, Result};

/// constants.json `RELAY_HANDSHAKE_TIMEOUT_S`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// constants.json `RELAY_HANDSHAKE_MAX_ATTEMPTS`.
pub const MAX_ATTEMPTS: u32 = 3;

/// 띄울 방법.
#[derive(Debug, Clone)]
pub struct Spawn {
    pub binary: PathBuf,
    pub data_dir: PathBuf,
    pub server: String,
    pub timeout: Duration,
    pub attempts: u32,
}

impl Spawn {
    pub fn new(
        binary: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
        server: impl Into<String>,
    ) -> Self {
        Self {
            binary: binary.into(),
            data_dir: data_dir.into(),
            server: server.into(),
            timeout: HANDSHAKE_TIMEOUT,
            attempts: MAX_ATTEMPTS,
        }
    }
}

/// 떠 있는 로컬 relay.
pub struct LocalRelay {
    child: Child,
    /// 닫히면 relay 가 끝난다(#338). 쓰지 않고 쥐기만 한다.
    _stdin: ChildStdin,
    pub port: u16,
    pub server: String,
}

impl LocalRelay {
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/v1/ws", self.port)
    }

    pub fn http_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// 끝내고 기다린다.
    pub async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }

    /// 동기로 끝낸다(앱 종료 경로 — 비동기 런타임이 이미 멈추고 있을 수 있다). kill 신호를 보내고 `limit` 까지
    /// 끝나기를 기다린다. 끝났으면 참.
    pub fn kill_blocking(&mut self, limit: Duration) -> bool {
        let _ = self.child.start_kill();
        let deadline = std::time::Instant::now() + limit;
        loop {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// 띄우고 준비 줄을 기다린다. `token` 은 기기 등록 토큰(stdin 첫 줄 — env·인자는 `ps` 로 보인다).
///
/// # Errors
/// 모든 시도가 실패하면 마지막 이유.
pub async fn spawn_local(spec: &Spawn, token: &str) -> Result<LocalRelay> {
    let mut last = Error::Relay("시도 없음".into());
    for attempt in 1..=spec.attempts.max(1) {
        match try_once(spec, token).await {
            Ok(r) => return Ok(r),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "로컬 relay 기동 실패");
                last = e;
            }
        }
    }
    Err(last)
}

async fn try_once(spec: &Spawn, token: &str) -> Result<LocalRelay> {
    std::fs::create_dir_all(&spec.data_dir)?;
    let mut child = Command::new(&spec.binary)
        .args(["--local", "--data"])
        .arg(&spec.data_dir)
        .args([
            "--port",
            "0",
            "--server",
            &spec.server,
            "--token-stdin",
            "--exit-on-stdin-eof",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Relay("stdin 없음".into()))?;
    stdin.write_all(format!("{token}\n").as_bytes()).await?;
    stdin.flush().await?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Relay("stdout 없음".into()))?;
    let mut lines = BufReader::new(stdout).lines();
    let line = match tokio::time::timeout(spec.timeout, lines.next_line()).await {
        Ok(Ok(Some(l))) => l,
        Ok(Ok(None)) => {
            let _ = child.kill().await;
            return Err(Error::Relay("준비 줄 전에 stdout 이 닫혔다".into()));
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            return Err(e.into());
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(Error::Relay(format!(
                "{}초 안에 준비 줄이 오지 않았다",
                spec.timeout.as_secs()
            )));
        }
    };
    match parse_ready(&line) {
        Some((port, server)) => {
            // 남은 stdout 은 버린다(파이프가 차서 자식이 멈추지 않게).
            tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
            Ok(LocalRelay {
                child,
                _stdin: stdin,
                port,
                server,
            })
        }
        None => {
            let _ = child.kill().await;
            Err(Error::Relay(format!("준비 줄 형식이 아니다: {line}")))
        }
    }
}

/// `{"relay":"ready","port":N,"server":"…"}`
pub fn parse_ready(line: &str) -> Option<(u16, String)> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("relay").and_then(Value::as_str) != Some("ready") {
        return None;
    }
    let port = u16::try_from(v.get("port")?.as_u64()?)
        .ok()
        .filter(|p| *p != 0)?;
    let server = v
        .get("server")
        .and_then(Value::as_str)
        .unwrap_or("local")
        .to_owned();
    Some((port, server))
}

/// 레포 빌드 산출물 경로(시험·개발용).
pub fn dev_binary(target_dir: &Path) -> PathBuf {
    target_dir.join("lodelai-relay")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_line() {
        assert_eq!(
            parse_ready(r#"{"relay":"ready","port":5123,"server":"local"}"#),
            Some((5123, "local".into()))
        );
        assert_eq!(parse_ready(r#"{"relay":"ready","port":0}"#), None);
        assert_eq!(parse_ready(r#"{"relay":"starting","port":5}"#), None);
        assert_eq!(parse_ready("listening on 5123"), None);
    }
}
