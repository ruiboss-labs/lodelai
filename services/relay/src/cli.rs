//! lodelai-relay 실행 파일의 인자·하위 명령과 진입점 [`run`]. `main.rs` 와 앱이 번들하는 사이드카 bin 이 같은 [`run`] 을 부른다
//! (서버 로직은 라이브러리의 나머지 — 시험은 그것을 in-process 로 올린다).
//!
//! ```text
//! lodelai-relay --local --data <dir> [--port 0] [--server local] [--token-stdin [--exit-on-stdin-eof]] [--dev-mail <dir>]  같은 맥 로컬 relay(앱의 자식)
//! lodelai-relay --data <dir> --port 8787 --public-host <도메인> [--behind-cloudflare] [--blob-min-free <바이트>] [--max-devices-per-user <수>] [--no-groups]
//!     [--org-create code|open] [--org-create-per-email-30d 3] [--org-create-per-ip-day 5] [--org-create-per-day 50] [--max-orgs 50]
//!                                                                                        원격 relay(#364)
//! lodelai-relay bootstrap --data <dir>                                                    1회용 조직 만들기 코드(1시간)
//! lodelai-relay bootstrap --data <dir> --email <주소> [--ttl 7d]                           그 이메일 가입만 쓰는 코드(기본 7일·최대 14일)
//! lodelai-relay bootstrap --data <dir> --list | --revoke <id>                             살아 있는 코드 보기(코드 없이)·지우기
//! lodelai-relay backup --data <dir> --out <파일>                                           DB 사본(VACUUM INTO)
//! lodelai-relay backup-mark --data <dir> (--local-ok | --offsite ok|failed|skipped | --failed) 백업 결과 기록(lodelai-backup.sh)
//! ```
//!
//! - `127.0.0.1` 에만 바인딩한다. 원격 relay 도 같다 — 바깥은 Cloudflare Tunnel(cloudflared)이 같은 기기에서 잇는다.
//! - 로컬: `--port 0` 이면 OS 가 고른 포트. 준비되면 stdout 에 한 줄 JSON `{"relay":"ready","port":<n>,"server":"<name>"}`.
//!   앱(부모)은 이 줄을 10초 안에 못 받으면 다시 띄운다(최대 3회, constants `RELAY_HANDSHAKE_*`).
//! - 원격: 서버 이름 = 공개 도메인(`--server` 를 따로 주지 않으면 `--public-host`). 등록 토큰 경로는 없고 모두 이메일 코드로
//!   가입한다(묶음 5) — 첫 관리자는 `bootstrap` 의 조직 만들기 코드로 새 조직을, 동료는 관리자의 초대 코드로. `--privacy-version`
//!   이 필요하고 개발용 `--dev-mail` 은 받지 않는다.
//! - `--token-stdin`: stdin 첫 줄을 기기 등록 토큰으로 쓴다(env·인자는 `ps` 로 보이므로 쓰지 않는다). 로컬만.
//! - `--exit-on-stdin-eof`: 토큰 뒤 stdin 이 닫히면 끝난다(#338) — 앱이 파이프를 쥐고 있다가 크래시·SIGKILL 로 죽으면 닫혀
//!   고아 relay 가 같은 데이터를 쥔 채 남지 않는다. `--token-stdin` 과 같이만.
//! - `bootstrap` 은 조직 만들기 코드를 stdout 에 **한 번만** 쓰고 어디에도 남기지 않는다(DB 엔 해시만). 서비스와 같은 사용자로 실행한다.
//!   코드는 여럿이 함께 산다(relay 0.1.2): 이메일 없는 코드는 앞의 이메일 없는 코드만, `--email` 코드는 같은 이메일의 앞 코드만
//!   덮어쓴다. `--email` 이면 `code:`·`id:`·`expires:`·`email:` 줄만 찍는다(스크립트가 `code:` 줄만 집는다).
//! - `--dev-mail <dir>`: hosted 가입(`/v1/signup`, #339)을 켜고 확인 코드를 `<dir>/<이메일>.txt` 에 쓴다(개발용 가짜 메일 —
//!   실제 발송은 M2 hosted 배포 때). 계정 알림 메일(#577 메일 확인 끊기 넷)은 `<dir>/<이메일>.notices.txt` 에 덧붙인다.
//! - `--test-recovery-wait <초>`·`--test-recovery-cooldown <초>`·`--test-recovery-window <초>`(#577 시험 시계): 메일 확인
//!   끊기의 대기(24h)·쿨다운(24h)·막기 3번 창(30일)을 줄인다. `--dev-mail` 과 같은 조건 — 로컬이나 시험용 도메인 원격만.
//! - 시간·난수 주입 플래그는 없다.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::db::{BackupOffsite, Db};
use crate::{bind_local, serve, Config, Effects, Relay};

enum Command {
    Serve(Box<Args>),
    Bootstrap { data: PathBuf, op: BootstrapOp },
    Backup { data: PathBuf, out: PathBuf },
    BackupMark { data: PathBuf, mark: Mark },
}

/// `bootstrap` 이 할 일(relay 0.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapOp {
    Issue {
        email: Option<String>,
        ttl_ms: Option<i64>,
    },
    List,
    Revoke(String),
}

/// `--ttl` 값: `<n>d` 또는 `<n>h`.
fn parse_ttl(v: &str) -> Result<i64, String> {
    let bad = || format!("--ttl 은 7d·36h 꼴: {v}");
    let (n, unit) = v.split_at(v.len().saturating_sub(1));
    let n: i64 = n.parse().map_err(|_| bad())?;
    match unit {
        "d" => Ok(n * 24 * 60 * 60 * 1000),
        "h" => Ok(n * 60 * 60 * 1000),
        _ => Err(bad()),
    }
}

/// #577 시험 시계 — 주어진 칸만 [`Config`] 의 기본(24h·24h·30일)을 덮는다.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct TestRecovery {
    wait: Option<u64>,
    cooldown: Option<u64>,
    window: Option<u64>,
}

impl TestRecovery {
    fn any(self) -> bool {
        self.wait.is_some() || self.cooldown.is_some() || self.window.is_some()
    }

    fn apply(self, config: &mut Config) {
        let secs = std::time::Duration::from_secs;
        if let Some(s) = self.wait {
            config.recovery_wait = secs(s);
        }
        if let Some(s) = self.cooldown {
            config.recovery_cooldown = secs(s);
        }
        if let Some(s) = self.window {
            config.recovery_block_window = secs(s);
        }
    }
}

/// `backup-mark`: 백업 스크립트가 남기는 결과(m1-spec §17.3).
enum Mark {
    /// 로컬 사본(gzip 까지)이 생겼다 — 성공 시각은 이때 쓴다.
    LocalOk,
    Offsite(BackupOffsite),
    Failed,
}

struct Args {
    data: PathBuf,
    port: u16,
    server: String,
    token_stdin: bool,
    /// 토큰 뒤 stdin EOF 면 끝냄(#338).
    exit_on_stdin_eof: bool,
    /// 원격 relay(#364): 이 공개 도메인을 Host 로 받는다.
    public_host: Option<String>,
    behind_cloudflare: bool,
    dev_mail: Option<PathBuf>,
    /// 처리방침 판(묶음 5, 원격 필수).
    privacy_version: Option<String>,
    /// 운영자 처리방침 주소(묶음 29 §1-4, `--privacy-url`, https 만).
    privacy_url: Option<String>,
    /// 대기 명단 주소(#737, `--waitlist-url`·`LODELAI_WAITLIST_URL`, https 만 — hosted).
    waitlist_url: Option<String>,
    /// 첨부 디스크 하한(묶음 15, `--blob-min-free <바이트>`). 없으면 기본 5 GiB.
    blob_min_free: Option<u64>,
    /// 사용자당 기기 상한(묶음 16, `--max-devices-per-user <수>`). 없으면 4.
    max_devices: Option<usize>,
    /// 코드 없는 조직 만들기(묶음 18, `--org-create open`). 원격만.
    org_create_open: bool,
    /// #577 시험 시계(초): 메일 확인 끊기 대기·쿨다운·막기 창. 로컬·시험용 도메인만.
    test_recovery: TestRecovery,
    /// 조직 만들기 상한(묶음 18 §3). 없는 값은 기본.
    org_limits: crate::OrgCreateLimits,
    /// 그룹(묶음 16 §3b). 22 §12-30(#535)부터 기본 켬 — 끄기는 `--no-groups`, `--groups` 는 받기만(옛 서비스 파일).
    groups: bool,
}

/// 부모(앱)가 쥔 stdin 파이프가 닫히면 끝낸다(#338). 부모가 정상으로 끝낼 때는 그 전에 kill 하고, 크래시·SIGKILL 이면
/// 커널이 파이프를 닫는다. 저장은 SQLite 트랜잭션이라 kill 과 같은 끝남이다.
fn exit_on_eof() {
    std::thread::spawn(|| {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
        eprintln!("lodelai-relay: 부모의 stdin 이 닫혔다 — 끝낸다");
        std::process::exit(0);
    });
}

/// 1 이상의 수.
fn count<T: std::str::FromStr + PartialOrd + From<u8>>(
    it: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    value(it, flag)?
        .parse::<T>()
        .ok()
        .filter(|n| *n >= T::from(1))
        .ok_or_else(|| format!("{flag} 1 이상의 수"))
}

fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} 값"))
}

/// env 한 값.
fn env_var(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// 운영자 env 값(묶음 29 — 서비스는 `EnvironmentFile` 만 쓰고 인자를 넘기지 않는다). 앞뒤 공백을 떼고 비면 없음.
/// 인자가 있으면 인자가 이긴다.
fn env_opt(k: &str) -> Option<String> {
    env_var(k)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// `--data` 가 없으면 `LODELAI_RELAY_DATA`.
fn data_or_env(data: Option<PathBuf>) -> Result<PathBuf, String> {
    data.or_else(|| env_opt("LODELAI_RELAY_DATA").map(PathBuf::from))
        .ok_or_else(|| "--data 또는 LODELAI_RELAY_DATA 필요".to_owned())
}

/// `--privacy-url` 값 검사(https 만, 빈 값은 없음).
fn privacy_url_arg(v: &str) -> Result<Option<String>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if !v.starts_with("https://") || v.contains(char::is_whitespace) {
        return Err("--privacy-url(LODELAI_PRIVACY_URL) 은 https:// 주소".into());
    }
    Ok(Some(v.to_owned()))
}

fn parse_args(args: Vec<String>) -> Result<Command, String> {
    let mut it = args.into_iter().peekable();
    match it.peek().map(String::as_str) {
        Some("bootstrap") => {
            it.next();
            let (mut data, mut email, mut ttl, mut list, mut revoke) =
                (None, None, None, false, None);
            let mut seen = std::collections::HashSet::new();
            while let Some(a) = it.next() {
                // 같은 인자 두 번은 받지 않는다 — sudoers 가 `--data <폴더> --email *` 처럼 앞을 고정하므로 뒤에 `--data` 를 다시
                // 붙여 다른 폴더를 건드리지 못하게(relay 0.1.2).
                if a.starts_with("--") && !seen.insert(a.clone()) {
                    return Err(format!("같은 인자 두 번: {a}"));
                }
                match a.as_str() {
                    "--data" => data = Some(PathBuf::from(value(&mut it, "--data")?)),
                    "--email" => email = Some(value(&mut it, "--email")?),
                    "--ttl" => ttl = Some(parse_ttl(&value(&mut it, "--ttl")?)?),
                    "--list" => list = true,
                    "--revoke" => revoke = Some(value(&mut it, "--revoke")?),
                    other => return Err(format!("모르는 인자: {other}")),
                }
            }
            let plain = email.is_none() && ttl.is_none();
            let op = match (list, revoke) {
                (true, None) if plain => BootstrapOp::List,
                (false, Some(id)) if plain => BootstrapOp::Revoke(id),
                (false, None) if email.is_some() || ttl.is_none() => {
                    BootstrapOp::Issue { email, ttl_ms: ttl }
                }
                (false, None) => return Err("--ttl 은 --email 과 같이만".into()),
                _ => return Err("--list·--revoke 는 따로, --email·--ttl 없이".into()),
            };
            return Ok(Command::Bootstrap {
                data: data_or_env(data)?,
                op,
            });
        }
        Some("backup") => {
            it.next();
            let (mut data, mut out) = (None, None);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--data" => data = Some(PathBuf::from(value(&mut it, "--data")?)),
                    "--out" => out = Some(PathBuf::from(value(&mut it, "--out")?)),
                    other => return Err(format!("모르는 인자: {other}")),
                }
            }
            return Ok(Command::Backup {
                data: data_or_env(data)?,
                out: out.ok_or("--out 필요")?,
            });
        }
        Some("backup-mark") => {
            it.next();
            let (mut data, mut mark) = (None, None);
            while let Some(a) = it.next() {
                let m = match a.as_str() {
                    "--data" => {
                        data = Some(PathBuf::from(value(&mut it, "--data")?));
                        continue;
                    }
                    "--offsite" => match value(&mut it, "--offsite")?.as_str() {
                        "ok" => Mark::Offsite(BackupOffsite::Ok),
                        "failed" => Mark::Offsite(BackupOffsite::Failed),
                        "skipped" => Mark::Offsite(BackupOffsite::Skipped),
                        _ => return Err("--offsite 는 ok|failed|skipped".into()),
                    },
                    "--failed" => Mark::Failed,
                    "--local-ok" => Mark::LocalOk,
                    other => return Err(format!("모르는 인자: {other}")),
                };
                if mark.replace(m).is_some() {
                    return Err("--local-ok·--offsite·--failed 는 하나만".into());
                }
            }
            return Ok(Command::BackupMark {
                data: data_or_env(data)?,
                mark: mark.ok_or("--local-ok·--offsite·--failed 중 하나 필요")?,
            });
        }
        _ => {}
    }
    let (mut local, mut data, mut port, mut server, mut token_stdin) =
        (false, None, 0u16, None, false);
    let (mut public_host, mut behind_cloudflare) = (None, false);
    let (mut dev_mail, mut privacy_version, mut blob_min_free) = (None, None, None);
    let mut privacy_url = None;
    let mut waitlist_url = None;
    let mut max_devices = None;
    let (mut org_create_open, mut org_limits) = (false, crate::OrgCreateLimits::default());
    let mut groups = None;
    let mut exit_on_stdin_eof = false;
    let mut test_recovery = TestRecovery::default();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--local" => local = true,
            "--data" => data = Some(PathBuf::from(value(&mut it, "--data")?)),
            "--port" => {
                port = value(&mut it, "--port")?
                    .parse()
                    .map_err(|_| "--port 숫자")?;
            }
            "--server" => server = Some(value(&mut it, "--server")?),
            "--token-stdin" => token_stdin = true,
            "--exit-on-stdin-eof" => exit_on_stdin_eof = true,
            "--public-host" => public_host = Some(value(&mut it, "--public-host")?),
            "--behind-cloudflare" => behind_cloudflare = true,
            "--dev-mail" => dev_mail = Some(PathBuf::from(value(&mut it, "--dev-mail")?)),
            "--privacy-version" => {
                // 빈 값(서비스의 LODELAI_PRIVACY_VERSION 을 안 채움)은 판이 없는 것과 같다 — 원격이면 아래에서 거부.
                privacy_version = Some(value(&mut it, "--privacy-version")?.trim().to_owned())
                    .filter(|v| !v.is_empty());
            }
            "--privacy-url" => {
                // 빈 값은 없는 것과 같다 — 앱이 hosted 기본을 쓴다.
                privacy_url = privacy_url_arg(&value(&mut it, "--privacy-url")?)?;
            }
            "--waitlist-url" => {
                waitlist_url = privacy_url_arg(&value(&mut it, "--waitlist-url")?)?;
            }
            "--blob-min-free" => {
                blob_min_free = Some(
                    value(&mut it, "--blob-min-free")?
                        .parse()
                        .map_err(|_| "--blob-min-free 바이트 숫자")?,
                );
            }
            "--groups" => groups = Some(true),
            "--no-groups" => groups = Some(false),
            "--max-devices-per-user" => {
                max_devices = Some(count(&mut it, "--max-devices-per-user")?);
            }
            "--org-create" => {
                org_create_open = match value(&mut it, "--org-create")?.as_str() {
                    "code" => false,
                    "open" => true,
                    _ => return Err("--org-create 는 code|open".into()),
                };
            }
            "--org-create-per-email-30d" => {
                org_limits.per_email_30d = count(&mut it, "--org-create-per-email-30d")?;
            }
            "--org-create-per-ip-day" => {
                org_limits.per_ip_day = count(&mut it, "--org-create-per-ip-day")?;
            }
            "--org-create-per-day" => {
                org_limits.per_day = count(&mut it, "--org-create-per-day")?;
            }
            "--max-orgs" => org_limits.max_orgs = count(&mut it, "--max-orgs")?,
            "--test-recovery-wait" => {
                test_recovery.wait = Some(count(&mut it, "--test-recovery-wait")?);
            }
            "--test-recovery-cooldown" => {
                test_recovery.cooldown = Some(count(&mut it, "--test-recovery-cooldown")?);
            }
            "--test-recovery-window" => {
                test_recovery.window = Some(count(&mut it, "--test-recovery-window")?);
            }
            "--version" => {
                println!("lodelai-relay {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("모르는 인자: {other}")),
        }
    }
    // 운영자 env(묶음 29 §1 — 서비스 파일은 EnvironmentFile 만, 인자가 이긴다). --local(앱이 띄우는 relay)은 env 를 보지
    // 않는다 — 공개 도메인·처리방침은 원격 relay 의 것.
    if !local {
        public_host = public_host.or_else(|| env_opt("LODELAI_PUBLIC_HOST"));
        if !behind_cloudflare {
            behind_cloudflare = match env_opt("LODELAI_BEHIND_CLOUDFLARE").as_deref() {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => return Err("LODELAI_BEHIND_CLOUDFLARE 는 true|false".into()),
            };
        }
        if privacy_version.is_none() {
            privacy_version = env_opt("LODELAI_PRIVACY_VERSION");
        }
        if privacy_url.is_none() {
            privacy_url = privacy_url_arg(&env_opt("LODELAI_PRIVACY_URL").unwrap_or_default())?;
        }
        if waitlist_url.is_none() {
            waitlist_url = privacy_url_arg(&env_opt("LODELAI_WAITLIST_URL").unwrap_or_default())?;
        }
        if groups.is_none() {
            groups = match env_opt("LODELAI_GROUPS").as_deref() {
                None | Some("true") => None,
                Some("false") => Some(false),
                Some(_) => return Err("LODELAI_GROUPS 는 true|false".into()),
            };
        }
    }
    if exit_on_stdin_eof && !token_stdin {
        return Err("--exit-on-stdin-eof 는 --token-stdin 과 같이만".into());
    }
    match (local, &public_host) {
        (true, Some(_)) => return Err("--local 과 --public-host 는 같이 쓸 수 없다".into()),
        (false, None) => return Err("--local 또는 --public-host 가 필요하다".into()),
        (false, Some(_)) if port == 0 => return Err("원격 relay 는 --port 를 정해야 한다".into()),
        (false, Some(_)) if token_stdin => {
            return Err("원격 relay 엔 등록 토큰이 없다(bootstrap 을 쓴다)".into())
        }
        (true, None) if behind_cloudflare => {
            return Err("--behind-cloudflare 는 원격 relay 만".into())
        }
        (true, None) if org_create_open => {
            return Err("--org-create open 은 원격 relay 만(로컬은 늘 코드 없이 만든다)".into())
        }
        (false, Some(h)) if dev_mail.is_some() && !crate::is_test_domain(h) => {
            return Err(
                "원격 relay 는 개발용 가짜 메일(--dev-mail)을 쓰지 않는다(시험용 도메인 .test 등만 예외)".into(),
            )
        }
        (false, Some(h)) if test_recovery.any() && !crate::is_test_domain(h) => {
            return Err(
                "원격 relay 는 시험 시계(--test-recovery-*)를 쓰지 않는다(시험용 도메인 .test 등만 예외)".into(),
            )
        }
        (false, Some(_)) if privacy_version.is_none() => {
            return Err("원격 relay 는 --privacy-version 이 필요하다(처리방침 판)".into())
        }
        _ => {}
    }
    let server = server
        .or_else(|| public_host.clone())
        .unwrap_or_else(|| "local".to_owned());
    Ok(Command::Serve(Box::new(Args {
        data: data_or_env(data)?,
        port,
        server,
        token_stdin,
        exit_on_stdin_eof,
        dev_mail,
        privacy_version,
        privacy_url,
        waitlist_url,
        public_host,
        behind_cloudflare,
        blob_min_free,
        max_devices,
        org_create_open,
        org_limits,
        test_recovery,
        groups: groups.unwrap_or(true),
    })))
}

/// 데이터 폴더를 만들고(0700) DB 를 연다.
fn open_db(data: &Path) -> Result<Db, String> {
    std::fs::create_dir_all(data).map_err(|e| format!("데이터 폴더: {e}"))?;
    // 본문이 든 DB 가 있는 폴더 — 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("데이터 폴더 권한: {e}"))?;
    }
    Db::open(&data.join("relay.sqlite3")).map_err(|e| format!("DB: {e}"))
}

fn bootstrap(data: &Path, op: BootstrapOp) -> ExitCode {
    let db = match open_db(data) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let fx = Effects::system();
    let now = fx.clock.now();
    let at = |ms: i64| {
        lodelai_effects::UnixMillis(ms)
            .to_rfc3339()
            .unwrap_or_default()
    };
    let fail = |e: &dyn std::fmt::Display| {
        eprintln!("lodelai-relay: {e}");
        ExitCode::FAILURE
    };
    match op {
        BootstrapOp::List => match db.list_setup_codes(now.0) {
            Ok(rows) => {
                for r in rows {
                    println!(
                        "{}  {}  {}",
                        r.id,
                        r.email_mask.as_deref().unwrap_or("-"),
                        at(r.expires_ms)
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        BootstrapOp::Revoke(id) => match db.revoke_setup_code(&id) {
            Ok(true) => {
                println!("지움: {id}");
                ExitCode::SUCCESS
            }
            Ok(false) => fail(&format!("없는 id: {id}")),
            Err(e) => fail(&e),
        },
        BootstrapOp::Issue { email, ttl_ms } => {
            match crate::http::issue_setup_code(
                &db,
                fx.rng.as_ref(),
                now.0,
                email.as_deref(),
                ttl_ms,
            ) {
                Ok(c) if c.email_mask.is_some() => {
                    println!("code: {}", c.code);
                    println!("id: {}", c.id);
                    println!("expires: {}", at(c.expires_ms));
                    println!("email: {}", c.email_mask.unwrap_or_default());
                    ExitCode::SUCCESS
                }
                Ok(c) => {
                    println!("조직 만들기 코드(1시간, 한 번만): {}", c.code);
                    println!(
                        "앱 가입 ① 에서 '새 조직' 을 고르고 이 코드를 넣으면 그 사람이 첫 관리자가 된다."
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e),
            }
        }
    }
}

/// 있는 DB 만 연다(백업 명령이 빈 DB 를 만들지 않게).
fn existing_db(data: &Path) -> Result<Db, String> {
    let path = data.join("relay.sqlite3");
    if !path.exists() {
        return Err(format!("DB 가 없다: {}", path.display()));
    }
    Db::open(&path).map_err(|e| format!("DB: {e}"))
}

/// 사본을 만든다. 시도 시각과 실패는 같은 DB 에 기록한다(m1-spec §17.3). 성공 시각은 쓰지 않는다 — 스크립트가
/// gzip 까지 끝낸 뒤 `backup-mark --local-ok` 로 쓴다(만들어지지 않은 사본의 시각이 남지 않게).
fn backup(data: &Path, out: &Path) -> ExitCode {
    let db = match existing_db(data) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = db
        .backup_started(Effects::system().clock.now().0)
        .and_then(|()| db.backup_to(out));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lodelai-relay: 백업: {e}");
            if let Err(e) = db.backup_failed() {
                eprintln!("lodelai-relay: 백업 실패 기록: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

fn backup_mark(data: &Path, mark: &Mark) -> ExitCode {
    let result = existing_db(data).and_then(|db| {
        match mark {
            Mark::LocalOk => db.backup_succeeded(Effects::system().clock.now().0),
            Mark::Offsite(o) => db.backup_offsite(*o),
            Mark::Failed => db.backup_failed(),
        }
        .map_err(|e| format!("기록: {e}"))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 실행 파일 진입점: `args` 는 프로그램 이름을 뺀 인자. 하위 명령(`bootstrap`·`backup`·`backup-mark`)이면 그것을 하고, 아니면
/// relay 를 띄워 끝날 때까지 돈다. 인자 오류는 2.
pub async fn run(args: Vec<String>) -> ExitCode {
    // 부르는 쪽이 이미 구독자를 걸었으면 그대로 둔다.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let args = match parse_args(args) {
        Ok(Command::Serve(a)) => a,
        Ok(Command::Bootstrap { data, op }) => return bootstrap(&data, op),
        Ok(Command::Backup { data, out }) => return backup(&data, &out),
        Ok(Command::BackupMark { data, mark }) => return backup_mark(&data, &mark),
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::from(2);
        }
    };
    let token = if args.token_stdin {
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() || line.trim().is_empty() {
            eprintln!("lodelai-relay: stdin 에서 등록 토큰을 못 읽었다");
            return ExitCode::from(2);
        }
        if args.exit_on_stdin_eof {
            exit_on_eof();
        }
        Some(line.trim().to_owned())
    } else {
        None
    };
    // 이메일 HMAC 키(묶음 5 정보 파기 A): 원격은 relay.env 의 LODELAI_EMAIL_HMAC_KEY 필수(DB 밖 — 백업만으로 이메일을 대입해
    // 맞혀 보지 못하게). 로컬 개발은 없으면 프로세스마다 새 키(내보낸 사람은 재시작 뒤 되살아나지 않는다).
    let email_key = match env_var("LODELAI_EMAIL_HMAC_KEY").map(|k| k.trim().to_owned()) {
        Some(k) if k.len() >= 32 => k.into_bytes(),
        Some(_) | None if args.public_host.is_some() => {
            eprintln!("lodelai-relay: 원격 relay 는 LODELAI_EMAIL_HMAC_KEY(32자 이상)가 필요하다 — install.sh 가 relay.env 에 만든다");
            return ExitCode::from(2);
        }
        _ => {
            let mut k = vec![0u8; 32];
            if Effects::system().rng.try_fill(&mut k).is_err() {
                eprintln!("lodelai-relay: 이메일 HMAC 키를 만들지 못했다");
                return ExitCode::FAILURE;
            }
            k
        }
    };
    // 가입 메일: --dev-mail 이면 파일(로컬·시험용 도메인), 아니면 원격 relay 는 운영자 env 로 고른 메일(묶음 29 §1-3 —
    // LODELAI_MAIL=resend|smtp, LODELAI_MAIL_FROM 늘 필요). 빠지면 무엇을 채울지 한 줄 내고 멈춘다.
    let mailer: Option<std::sync::Arc<dyn crate::mail::Mailer>> =
        match (args.dev_mail, &args.public_host) {
            (Some(dir), _) => Some(std::sync::Arc::new(crate::mail::FileMailer::new(dir))),
            (None, Some(_)) => match crate::mail::mailer_from_env(env_var) {
                Ok(m) => Some(m),
                Err(e) => {
                    eprintln!("lodelai-relay: {e}");
                    return ExitCode::from(2);
                }
            },
            (None, None) => None,
        };
    let db = match open_db(&args.data) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    db.set_email_key(email_key);
    let (listener, addr) = match bind_local(args.port).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("lodelai-relay: 바인딩: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut config = Config::local(args.server.clone());
    config.port = addr.port();
    config.registration_token = token;
    config.remote = args.public_host.is_some();
    config.public_host = args.public_host.clone();
    config.behind_cloudflare = args.behind_cloudflare;
    config.privacy_version = args.privacy_version.clone();
    config.privacy_url = args.privacy_url.clone();
    config.waitlist_url = args.waitlist_url.clone();
    // 가입 메일 하루 상한(묶음 29 §1-3). 비면 기본(80).
    if let Some(v) = env_var("LODELAI_MAIL_PER_DAY")
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
    {
        match v.parse::<i64>() {
            Ok(n) if n >= 1 => config.mail_per_day = n,
            _ => {
                eprintln!("lodelai-relay: LODELAI_MAIL_PER_DAY 는 1 이상의 수");
                return ExitCode::from(2);
            }
        }
    }
    config.data_dir = Some(args.data.clone());
    if let Some(b) = args.blob_min_free {
        config.blob_min_free = b;
    }
    if let Some(n) = args.max_devices {
        config.max_devices_per_user = n;
    }
    config.org_create_open = args.org_create_open;
    config.org_create_limits = args.org_limits;
    config.groups = args.groups;
    if args.test_recovery.any() {
        args.test_recovery.apply(&mut config);
        tracing::warn!(
            wait = ?config.recovery_wait,
            cooldown = ?config.recovery_cooldown,
            window = ?config.recovery_block_window,
            "시험 시계 — 메일 확인 끊기 대기를 줄였다(시험 relay 전용)"
        );
    }
    let app = Relay::with_mailer(config, Effects::system(), db, mailer);

    if let Some(host) = &args.public_host {
        // §12-29(#534): 앱은 접속 호스트로 서명하니 public_host 와 다른 --server 는 대개 WS 인증이 계속 실패한다(막지는 않음 — 내부 이름 운영).
        if !args.server.eq_ignore_ascii_case(host) {
            tracing::warn!(
                server = %args.server,
                public_host = %host,
                "--server 와 --public-host 가 다르다 — 앱이 접속 주소로 서명하면 WS 인증이 실패한다"
            );
        }
        tracing::info!(
            port = addr.port(),
            server = %args.server,
            public_host = %host,
            behind_cloudflare = args.behind_cloudflare,
            org_create_open = args.org_create_open,
            "원격 relay 준비"
        );
        // 원격은 늘 Cloudflare 뒤라는 운영 전제 — 아니면 IP 상한의 IP 가 cloudflared(127.0.0.1) 하나로 모인다(묶음 18 §3).
        if args.org_create_open && !args.behind_cloudflare {
            tracing::warn!("--org-create open 인데 --behind-cloudflare 가 없다 — 조직 만들기 IP 상한이 연결 주소로 센다");
        }
    } else {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "{}",
            serde_json::json!({"relay": "ready", "port": addr.port(), "server": args.server})
        );
        let _ = out.flush();
    }

    match serve(app, listener).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|a| (*a).to_owned()).collect())
    }

    fn serve(args: &[&str]) -> Args {
        match parse(args) {
            Ok(Command::Serve(a)) => *a,
            Ok(_) => panic!("serve 가 아님: {args:?}"),
            Err(e) => panic!("{e}: {args:?}"),
        }
    }

    /// #577 시험 시계: 로컬·시험용 도메인만, 주어진 칸만 Config 를 덮는다.
    #[test]
    fn test_recovery_clock_is_local_or_test_domain_only() {
        let a = serve(&[
            "--local",
            "--data",
            "/x",
            "--test-recovery-wait",
            "60",
            "--test-recovery-window",
            "600",
        ]);
        let mut c = Config::local("local");
        a.test_recovery.apply(&mut c);
        assert_eq!(c.recovery_wait, std::time::Duration::from_secs(60));
        assert_eq!(
            c.recovery_cooldown,
            Config::local("local").recovery_cooldown
        );
        assert_eq!(c.recovery_block_window, std::time::Duration::from_secs(600));

        let remote = |host: &str| {
            parse(&[
                "--data",
                "/x",
                "--public-host",
                host,
                "--port",
                "8787",
                "--privacy-version",
                "2026-10-25",
                "--test-recovery-cooldown",
                "30",
            ])
        };
        assert!(remote("relay.lodelai.test").is_ok());
        assert!(remote("relay.example.com").is_err());
        for bad in ["0", "-1", "x"] {
            assert!(parse(&["--local", "--data", "/x", "--test-recovery-wait", bad]).is_err());
        }
        // 손잡이가 없으면 기본(24h·24h·30일) 그대로.
        let a = serve(&["--local", "--data", "/x"]);
        assert!(!a.test_recovery.any());
    }
}
