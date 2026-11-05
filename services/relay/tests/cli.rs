//! 원격 relay 운영 하위 명령(#364): `bootstrap`·`backup`·`backup-mark`, 원격 모드 인자 검사. 실제 바이너리를 띄운다.

use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use lodelai_relay::db::{BackupLast, BackupOffsite, Db};

fn relay() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lodelai-relay"))
}

/// `output()` 에 10초 상한 — 넘으면 자식을 죽이고 실패한다. 새어 나간 relay 가 출력 파이프를 물면 `output()` 이 끝나지
/// 않아 검사가 cargo 잠금을 몇 시간씩 쥐었다(10-29).
trait Run {
    fn run(&mut self) -> Output;
}

impl Run for Command {
    fn run(&mut self) -> Output {
        let child = self
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(out) => out.unwrap(),
            Err(_) => {
                let _ = Command::new("kill").args(["-9", &pid]).status();
                panic!(
                    "10초 안에 끝나지 않았다: {:?}",
                    self.get_args().collect::<Vec<_>>()
                );
            }
        }
    }
}

/// 띄운 relay 는 시험이 panic 해도 끈다 — 남으면 옆 시험의 출력 파이프를 물어 그 시험이 끝나지 않는다.
struct Alive(Child);

impl Drop for Alive {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 빈 포트(OS 가 고른 것)를 정해 원격 relay 를 띄우고 `GET path` 응답 전체(#808). 포트를 놓은 뒤 자식이 다시 열기 전에 다른
/// 시험이 그 포트를 가져가면 relay 는 바인드 실패로 바로 끝난다 — 그러면 새 포트로 다시 띄운다(3번까지). 답이 없으면 자식의
/// stderr 를 실패 메시지에 싣는다(멈춤·느림·바인드 실패를 가르게).
fn remote_get(build: impl Fn(u16) -> Command, path: &str) -> String {
    use std::io::{Read, Write};
    let mut last = String::new();
    for _ in 0..3 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let err = tempfile::NamedTempFile::new().unwrap();
        let mut c = build(port);
        c.stderr(err.reopen().unwrap());
        let mut child = Alive(c.spawn().unwrap());
        let stderr = || std::fs::read_to_string(err.path()).unwrap_or_default();
        let mut exited = None;
        for _ in 0..50 {
            if let Ok(Some(st)) = child.0.try_wait() {
                exited = Some(st);
                break;
            }
            let mut out = String::new();
            let ok = std::net::TcpStream::connect(("127.0.0.1", port)).is_ok_and(|mut s| {
                write!(
                    s,
                    "GET {path} HTTP/1.1\r\nHost: lodelai.test\r\nConnection: close\r\n\r\n"
                )
                .is_ok()
                    && s.read_to_string(&mut out).is_ok()
            });
            if ok && !out.is_empty() {
                return out;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        match exited {
            // 바인드 실패 등으로 먼저 끝났다 — 새 포트로 다시.
            Some(st) => last = format!("relay 가 {st} 로 끝남 — stderr: {}", stderr()),
            None => panic!(
                "127.0.0.1:{port}{path} 에 5초 안에 답이 없다(relay 는 살아 있음) — stderr: {}",
                stderr()
            ),
        }
    }
    panic!("relay 가 세 번 다 먼저 끝났다 — {last}");
}

#[test]
fn bootstrap_prints_code_once_and_backup_copies_db() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let out = relay().args(["bootstrap", "--data"]).arg(&data).run();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let code = stdout
        .split_whitespace()
        .find(|w| w.len() == 19 && w.matches('-').count() == 3)
        .expect("설정 코드 줄");
    // 코드는 stdout 에만 — 진단 출력(stderr)과 DB 에는 없다.
    assert!(!String::from_utf8_lossy(&out.stderr).contains(code));
    let db = std::fs::read(data.join("relay.sqlite3")).unwrap();
    assert!(!db.windows(code.len()).any(|w| w == code.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    let copy = dir.path().join("copy.sqlite3");
    let out = relay()
        .args(["backup", "--data"])
        .arg(&data)
        .arg("--out")
        .arg(&copy)
        .run();
    assert!(out.status.success(), "{out:?}");
    let conn = rusqlite::Connection::open(&copy).unwrap();
    let n: i64 = conn
        .query_row("SELECT count(*) FROM setup_codes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let record = || {
        Db::open(&data.join("relay.sqlite3"))
            .unwrap()
            .backup_record()
            .unwrap()
    };
    let mark = |flag: &[&str]| {
        relay()
            .args(["backup-mark", "--data"])
            .arg(&data)
            .args(flag)
            .run()
    };
    // backup 은 시도 시각만 — 성공은 스크립트가 gzip 뒤 --local-ok 로.
    let r = record();
    assert_eq!(
        (r.last, r.offsite, r.last_ok_ms),
        (BackupLast::None, BackupOffsite::None, None)
    );
    assert!(r.last_attempt_ms.is_some());
    assert!(mark(&["--local-ok"]).status.success());
    let r = record();
    assert_eq!(r.last, BackupLast::Ok);
    let ok_ms = r.last_ok_ms.expect("성공 시각");
    assert!(r.last_attempt_ms.unwrap() <= ok_ms);
    assert!(mark(&["--offsite", "ok"]).status.success());
    assert_eq!(record().offsite, BackupOffsite::Ok);
    // 이미 있는 파일은 덮어쓰지 않는다.
    let again = relay()
        .args(["backup", "--data"])
        .arg(&data)
        .arg("--out")
        .arg(&copy)
        .run();
    assert!(!again.status.success());
    // 실패도 기록된다 — 마지막 성공 시각은 그대로, 바깥 사본은 이번 판 것 없음.
    let r = record();
    assert_eq!(
        (r.last, r.offsite, r.last_ok_ms),
        (BackupLast::Failed, BackupOffsite::None, Some(ok_ms))
    );
    assert!(mark(&["--offsite", "skipped"]).status.success());
    assert!(mark(&["--failed"]).status.success());
    assert_eq!(
        (record().last, record().offsite),
        (BackupLast::Failed, BackupOffsite::Skipped)
    );
}

#[test]
fn bad_mode_flags_exit_2() {
    for args in [
        vec!["--data", "/nonexistent"],
        vec!["--data", "/nonexistent", "--public-host", "lodelai.example"],
        vec![
            "--local",
            "--data",
            "/x",
            "--public-host",
            "lodelai.example",
        ],
        vec!["--local", "--data", "/x", "--behind-cloudflare"],
        // #338: stdin EOF 로 끝내기는 토큰을 stdin 으로 받을 때만.
        vec!["--local", "--data", "/x", "--exit-on-stdin-eof"],
        vec![
            "--data",
            "/x",
            "--public-host",
            "h",
            "--port",
            "8787",
            "--privacy-version",
            "2026-10-25",
            "--token-stdin",
        ],
        vec!["bootstrap"],
        // 묶음 5: 조직 만들기 코드는 아이디에 묶지 않는다.
        vec!["bootstrap", "--data", "/x", "--admin", "boss"],
        // relay 0.1.2: sudoers 가 앞을 고정한 뒤 `--data` 를 다시 붙여 폴더를 바꾸지 못한다. --ttl 은 --email 과만, 목록·지우기는 따로.
        vec![
            "bootstrap",
            "--data",
            "/x",
            "--email",
            "a@b.io",
            "--data",
            "/y",
        ],
        vec!["bootstrap", "--data", "/x", "--ttl", "7d"],
        vec![
            "bootstrap",
            "--data",
            "/x",
            "--email",
            "a@b.io",
            "--ttl",
            "15x",
        ],
        vec!["bootstrap", "--data", "/x", "--list", "--revoke", "ab"],
        vec!["bootstrap", "--data", "/x", "--list", "--email", "a@b.io"],
        // 원격은 처리방침 판이 있어야 하고 개발용 가짜 메일을 받지 않는다.
        vec!["--data", "/x", "--public-host", "h", "--port", "8787"],
        // 서비스 파일의 LODELAI_PRIVACY_VERSION 이 비면 빈 인자로 온다 — 판이 없는 것과 같다.
        vec![
            "--data",
            "/x",
            "--public-host",
            "h",
            "--port",
            "8787",
            "--privacy-version",
            " ",
        ],
        vec![
            "--data",
            "/x",
            "--public-host",
            "h",
            "--port",
            "8787",
            "--privacy-version",
            "2026-10-25",
            "--dev-mail",
            "/x/mail",
        ],
        vec!["backup", "--out", "/x"],
        vec!["backup-mark", "--data", "/x"],
        vec!["backup-mark", "--data", "/x", "--offsite", "none"],
        vec!["backup-mark", "--data", "/x", "--failed", "--offsite", "ok"],
        vec!["backup-mark", "--data", "/x", "--local-ok", "--failed"],
    ] {
        let out = relay().args(&args).run();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn remote_needs_resend_key_and_dev_mail_only_on_test_domains() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    // 이메일 HMAC 키(묶음 5 정보 파기 A)가 없거나 짧은 원격 relay 는 DB 를 열기 전에 2 로 끝난다.
    for key in [None, Some("short")] {
        let mut cmd = relay();
        cmd.env_remove("LODELAI_EMAIL_HMAC_KEY")
            .env("RESEND_API_KEY", "re_test");
        if let Some(k) = key {
            cmd.env("LODELAI_EMAIL_HMAC_KEY", k);
        }
        let out = cmd
            .args(["--public-host", "relay.example.com", "--port", "18999"])
            .args(["--privacy-version", "2026-10-25", "--data"])
            .arg(&data)
            .run();
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("LODELAI_EMAIL_HMAC_KEY"));
        assert!(!data.exists(), "DB 를 열기 전에 멈춘다");
    }
    // RESEND_API_KEY 없는 원격 relay 는 DB 를 열기 전에 2 로 끝난다.
    let out = relay()
        .env("LODELAI_EMAIL_HMAC_KEY", "k".repeat(64))
        .env("LODELAI_MAIL_FROM", "lodelai <noreply@example.org>")
        .env_remove("LODELAI_MAIL")
        .env_remove("RESEND_API_KEY")
        .args(["--public-host", "relay.example.com", "--port", "18999"])
        .args(["--privacy-version", "2026-10-25", "--data"])
        .arg(&data)
        .run();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("RESEND_API_KEY"));
    assert!(!data.exists(), "DB 를 열기 전에 멈춘다");
    // 실제 도메인에 --dev-mail 은 거부(2).
    let out = relay()
        .args(["--public-host", "relay.example.com", "--port", "18999"])
        .args([
            "--privacy-version",
            "2026-10-25",
            "--dev-mail",
            "/x/mail",
            "--data",
        ])
        .arg(&data)
        .run();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

/// 묶음 29 §1: 서비스 파일은 `EnvironmentFile` 만 쓰고 `--port` 말고는 인자가 없다 — 데이터·공개 도메인·처리방침은 env
/// 로 받는다(인자가 이긴다). 메일 설정이 빠지면 무엇을 채울지 한 줄 내고 멈춘다(§1-3).
#[test]
fn remote_relay_reads_operator_env_and_stops_without_mail_from() {
    let dir = tempfile::tempdir().unwrap();
    let base = |c: &mut Command| {
        c.env_clear()
            .env("LODELAI_RELAY_DATA", dir.path().join("data"))
            .env("LODELAI_PUBLIC_HOST", "lodelai.example.org")
            .env("LODELAI_BEHIND_CLOUDFLARE", "false")
            .env("LODELAI_PRIVACY_VERSION", "2026-10-25")
            .env("LODELAI_PRIVACY_URL", "https://lodelai.example.org/privacy")
            .env("LODELAI_EMAIL_HMAC_KEY", "k".repeat(40))
            .env("LODELAI_MAIL", "smtp")
            .env("SMTP_URL", "smtps://u:secret-pw@mail.example.org")
            .args(["--port", "1"]);
    };
    let mut c = relay();
    base(&mut c);
    let out = c.run();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("LODELAI_MAIL_FROM"), "{err}");
    assert!(!err.contains("secret-pw"), "{err}");
    // 처리방침 주소는 https 만.
    let mut c = relay();
    base(&mut c);
    let out = c.env("LODELAI_PRIVACY_URL", "http://x.example").run();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("https://"),
        "{out:?}"
    );
    let mut c = relay();
    base(&mut c);
    let out = c.env("LODELAI_BEHIND_CLOUDFLARE", "yes").run();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("true|false"),
        "{out:?}"
    );
    // 그룹 끄기 env 도 true|false 만(묶음 29 §1).
    let mut c = relay();
    base(&mut c);
    let out = c.env("LODELAI_GROUPS", "off").run();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("LODELAI_GROUPS 는 true|false"),
        "{out:?}"
    );
}

/// env 만으로 뜬 원격 relay 의 `GET /v1/privacy` 가 운영자 url 을 싣는다(가짜 메일은 시험 도메인만 — 인자로).
#[test]
fn env_only_remote_relay_serves_privacy_url() {
    let dir = tempfile::tempdir().unwrap();
    let body = remote_get(
        |port| {
            let mut c = relay();
            c.env_clear()
                .env("LODELAI_RELAY_DATA", dir.path().join("data"))
                .env("LODELAI_PUBLIC_HOST", "lodelai.test")
                .env("LODELAI_PRIVACY_VERSION", "2026-10-25")
                .env("LODELAI_PRIVACY_URL", "https://lodelai.test/privacy")
                .env("LODELAI_EMAIL_HMAC_KEY", "k".repeat(40))
                .args(["--port", &port.to_string(), "--dev-mail"])
                .arg(dir.path().join("mail"));
            c
        },
        "/v1/privacy",
    );
    assert!(
        body.contains(r#""url":"https://lodelai.test/privacy""#),
        "{body}"
    );
    assert!(body.contains(r#""version":"2026-10-25""#), "{body}");
}

/// #338: 앱이 크래시·SIGKILL 로 죽으면 쥐고 있던 stdin 파이프가 닫힌다 — `--exit-on-stdin-eof` relay 는 스스로 끝나 고아로
/// 남지 않는다. 토큰을 쓴 뒤 닫지 않는 동안은 산다.
#[test]
fn local_relay_exits_when_parent_stdin_closes() {
    use std::io::{BufRead, BufReader, Write};
    use std::time::Instant;
    let dir = tempfile::tempdir().unwrap();
    let mut child = relay()
        .args([
            "--local",
            "--port",
            "0",
            "--token-stdin",
            "--exit-on-stdin-eof",
            "--data",
        ])
        .arg(dir.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "t-338").unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.contains("\"ready\""), "{ready}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().unwrap().is_none(),
        "stdin 을 쥔 동안은 산다"
    );
    drop(stdin);
    let t = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if t.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("stdin 이 닫혔는데 5초 안에 끝나지 않았다");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{status:?}");
}

/// `RUST_LOG` 없이 띄워도 stderr 에 info 줄이 남는다(0.2.5 관문 relay.log 가 비었던 것) — 준비 줄 하나.
#[test]
fn relay_logs_info_to_stderr_without_rust_log() {
    use std::io::{BufRead, BufReader, Write};
    let dir = tempfile::tempdir().unwrap();
    let err = tempfile::NamedTempFile::new().unwrap();
    let child = relay()
        .args([
            "--local",
            "--port",
            "0",
            "--token-stdin",
            "--exit-on-stdin-eof",
            "--data",
        ])
        .arg(dir.path().join("data"))
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(err.reopen().unwrap())
        .spawn()
        .unwrap();
    let mut child = Alive(child);
    let mut stdin = child.0.stdin.take().unwrap();
    writeln!(stdin, "t-log").unwrap();
    let mut ready = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.contains("\"ready\""), "{ready}");
    drop(stdin);
    let _ = child.0.wait();
    let log = std::fs::read_to_string(err.path()).unwrap();
    assert!(
        log.contains("INFO") && log.contains("로컬 relay 준비"),
        "{log}"
    );
    assert!(!log.contains("t-log"), "토큰은 찍지 않는다");
}

/// 묶음 22 §12-30(#535): 실행 파일은 기본으로 그룹을 켠다(healthz 에 `Lodelai-Features: groups,device_name,kp_reset`), `--no-groups` 면 `device_name,kp_reset` 만.
#[test]
fn groups_on_by_default_and_no_groups_turns_off() {
    use std::io::{BufRead, BufReader, Read, Write};
    let healthz_head = |extra: &[&str]| -> String {
        let dir = tempfile::tempdir().unwrap();
        let child = relay()
            .args(["--local", "--port", "0", "--token-stdin", "--data"])
            .arg(dir.path().join("data"))
            .args(extra)
            // --local 은 운영자 env 를 보지 않는다(묶음 29 §1) — 켜짐이 그대로여야 한다.
            .env("LODELAI_GROUPS", "false")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = Alive(child);
        writeln!(child.0.stdin.as_mut().unwrap(), "t-535").unwrap();
        let mut ready = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let port = serde_json::from_str::<serde_json::Value>(&ready).unwrap()["port"]
            .as_u64()
            .unwrap();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port as u16)).unwrap();
        write!(
            s,
            "GET /v1/healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        drop(child);
        out.split_once("\r\n\r\n").unwrap().0.to_ascii_lowercase()
    };
    let on = healthz_head(&[]);
    assert!(
        on.lines()
            .any(|l| l == "lodelai-features: groups,device_name,kp_reset,unreadable_ack"),
        "{on}"
    );
    let old_flag = healthz_head(&["--groups"]);
    assert!(
        old_flag
            .lines()
            .any(|l| l == "lodelai-features: groups,device_name,kp_reset,unreadable_ack"),
        "{old_flag}"
    );
    let off = healthz_head(&["--no-groups"]);
    assert!(
        off.lines()
            .any(|l| l == "lodelai-features: device_name,kp_reset,unreadable_ack"),
        "{off}"
    );
}

/// 묶음 29 §1: 원격 relay 는 `LODELAI_GROUPS` 로 그룹을 끈다(없거나 빈 값·true = 켬, false = `--no-groups`). 인자가 이기고,
/// `--local`(앱이 띄우는 relay)은 env 를 보지 않는다.
#[test]
fn lodelai_groups_env_turns_off_remote_groups_and_args_win() {
    let features = |groups_env: Option<&str>, extra: &[&str]| -> String {
        let dir = tempfile::tempdir().unwrap();
        let out = remote_get(
            |port| {
                let mut c = relay();
                c.env_clear()
                    .env("LODELAI_RELAY_DATA", dir.path().join("data"))
                    .env("LODELAI_PUBLIC_HOST", "lodelai.test")
                    .env("LODELAI_PRIVACY_VERSION", "2026-10-25")
                    .env("LODELAI_EMAIL_HMAC_KEY", "k".repeat(40))
                    .args(["--port", &port.to_string(), "--dev-mail"])
                    .arg(dir.path().join("mail"))
                    .args(extra);
                if let Some(v) = groups_env {
                    c.env("LODELAI_GROUPS", v);
                }
                c
            },
            "/v1/healthz",
        );
        let head = out.split_once("\r\n\r\n").map_or(out.as_str(), |h| h.0);
        head.to_ascii_lowercase()
            .lines()
            .find_map(|l| l.strip_prefix("lodelai-features: ").map(str::to_owned))
            .unwrap_or_else(|| panic!("{out}"))
    };
    assert_eq!(
        features(None, &[]),
        "groups,device_name,kp_reset,unreadable_ack"
    );
    assert_eq!(
        features(Some(""), &[]),
        "groups,device_name,kp_reset,unreadable_ack"
    );
    assert_eq!(
        features(Some("true"), &[]),
        "groups,device_name,kp_reset,unreadable_ack"
    );
    assert_eq!(
        features(Some("false"), &[]),
        "device_name,kp_reset,unreadable_ack"
    );
    assert_eq!(
        features(Some("false"), &["--groups"]),
        "groups,device_name,kp_reset,unreadable_ack"
    );
    assert_eq!(
        features(Some("true"), &["--no-groups"]),
        "device_name,kp_reset,unreadable_ack"
    );
}

#[test]
fn bootstrap_email_code_list_and_revoke() {
    // relay 0.1.2: 이메일 코드는 `code:`·`id:`·`expires:`·`email:` 줄, 목록엔 코드가 없고, id 로 지운다.
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let out = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .args(["--email", "Boss@X.io", "--ttl", "10d"])
        .run();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let field = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap_or_else(|| panic!("{k} 줄: {stdout}"))
            .to_owned()
    };
    let (code, id) = (field("code: "), field("id: "));
    assert_eq!(code.len(), 19);
    assert_eq!(field("email: "), "b***@x…");
    assert!(field("expires: ").ends_with('Z'));
    assert_eq!(stdout.lines().count(), 4, "{stdout}");

    let list = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .arg("--list")
        .run();
    assert!(list.status.success(), "{list:?}");
    let listed = String::from_utf8(list.stdout).unwrap();
    assert!(
        listed.contains(&id) && listed.contains("b***@x…"),
        "{listed}"
    );
    assert!(!listed.contains(&code), "목록엔 코드가 없다");

    // 15일은 내지 않는다(상한 14일).
    let long = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .args(["--email", "z@y.io", "--ttl", "15d"])
        .run();
    assert!(!long.status.success());

    let gone = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .args(["--revoke", &id])
        .run();
    assert!(gone.status.success(), "{gone:?}");
    let again = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .args(["--revoke", &id])
        .run();
    assert!(!again.status.success(), "없는 id");
    let list = relay()
        .args(["bootstrap", "--data"])
        .arg(&data)
        .arg("--list")
        .run();
    assert!(String::from_utf8(list.stdout).unwrap().trim().is_empty());
}
