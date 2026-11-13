//! lodelai-relay 실행 파일의 인자·하위 명령과 진입점 [`run`]. `main.rs` 와 앱이 번들하는 사이드카 bin 이 같은 [`run`] 을 부른다
//! (서버 로직은 라이브러리의 나머지 — 시험은 그것을 in-process 로 올린다).
//!
//! ```text
//! lodelai-relay --local --data <dir> [--port 0] [--server local] [--token-stdin [--exit-on-stdin-eof]] [--dev-mail <dir>]  같은 맥 로컬 relay(앱의 자식)
//! lodelai-relay --data <dir> --port 8787 --public-host <도메인> [--behind-cloudflare] [--blob-min-free <바이트>] [--blob-daily-max-bytes <바이트>] [--max-devices-per-user <수>] [--no-groups]
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
//! - `--test-extra-host <이름>`(휴대폰 실기): 받을 Host 하나를 더한다(Tailscale serve 가 넘기는 이름 등). Host 허용 목록에만 쓰고,
//!   `--dev-mail` 과 같은 조건 — 로컬이나 시험용 도메인 원격만. 켜면 시작 로그에 경고.
//! - `--test-invite-fail`(QA): 대상(이메일·아이디) 앞부분이 `fail` 인 group.invite 를 rate_limited 로 답한다 — 앱의
//!   '초대 안 됨' 행·다시 초대를 실제 relay 로 일으킨다(예 `fail1@x.test`). 같은 조건 — 로컬이나 시험용 도메인 원격만, 시작 로그에 경고.
//!   `--test-invite-fail-retry-secs <초>`: 그 거절의 다시 시도 시각(기본 3600). 그 시각이 지난 같은 대상의 두 번째 시도는 통과.
//!   `--test-invite-fail` 과 같이만.
//! - 시간·난수 주입 플래그는 없다.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::db::{BackupOffsite, Db};
use crate::{bind_local, serve, Config, Effects, Relay};

enum Command {
    Serve(Box<Args>),
    Bootstrap {
        data: PathBuf,
        op: BootstrapOp,
    },
    Backup {
        data: PathBuf,
        out: PathBuf,
    },
    BackupMark {
        data: PathBuf,
        mark: Mark,
    },
    PushSend(PushSend),
    /// 모바일 검증 S3: 보낸 duty·확정 수를 읽기 전용으로 센다.
    DutyLog {
        data: PathBuf,
        since_ms: i64,
    },
    /// #845 ⑤ 운영 멈춤(`--for 7d`·`36h` 면 그 뒤 풀림, 없으면 unsuspend 까지)·풀기.
    Suspend {
        data: PathBuf,
        user: String,
        for_ms: Option<i64>,
        lift: bool,
    },
}

/// `push-send`(모바일 검증): 손으로 푸시 하나. 자격은 env 에서만(`push::ENV_*`), 토큰·암호문은 출력하지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PushSend {
    platform: crate::push::Platform,
    env: crate::push::ApnsEnv,
    token: String,
    conv: Option<String>,
    sealed_file: Option<PathBuf>,
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
    /// 시험 전용 `--test-extra-host`: 받을 Host 하나 더(로컬·시험용 도메인 원격만).
    test_extra_host: Option<String>,
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
    /// #876 계정당 하루 첨부 합(`--blob-daily-max-bytes <바이트>`, 0 = 끔). 없으면 env `LODELAI_BLOB_DAILY_MAX_BYTES`, 그것도 없으면 기본.
    blob_daily_max: Option<u64>,
    /// 사용자당 기기 상한(묶음 16, `--max-devices-per-user <수>`). 없으면 4.
    max_devices: Option<usize>,
    /// 코드 없는 조직 만들기(묶음 18, `--org-create open`). 원격만.
    org_create_open: bool,
    /// #905 개인 공간 가입(`--personal-signup on|off`, 없으면 env `LODELAI_PERSONAL_SIGNUP`, 기본 on). 원격만 끌 수 있다.
    personal_signup: bool,
    /// #577 시험 시계(초): 메일 확인 끊기 대기·쿨다운·막기 창. 로컬·시험용 도메인만.
    test_recovery: TestRecovery,
    /// 조직 만들기 상한(묶음 18 §3). 없는 값은 기본.
    org_limits: crate::OrgCreateLimits,
    /// 그룹(묶음 16 §3b). 22 §12-30(#535)부터 기본 켬 — 끄기는 `--no-groups`, `--groups` 는 받기만(옛 서비스 파일).
    groups: bool,
    /// 시험 relay(`--mobile-push`): 푸시 자격이 없어도 기능 `push`·`no_duty` 를 알리고(등록만 받음) 보낸 duty 를 DB 에 적는다
    /// (`duty-log`). 정식 relay 는 이것 없이 APNs·FCM 자격 env 가 있으면 푸시가 켜진다.
    mobile_push: bool,
    /// QA 시험 전용 `--test-invite-fail`: 앞부분이 `fail` 인 대상의 group.invite 를 rate_limited 로(앱 '초대 안 됨'). 로컬·시험용 도메인만.
    test_invite_fail: bool,
    /// QA `--test-invite-fail-retry-secs`: 위 거절의 다시 시도 시각까지 초(없으면 3600).
    test_invite_fail_retry_secs: Option<u64>,
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

fn on_off(v: &str, what: &str) -> Result<bool, String> {
    match v {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("{what} 는 on|off")),
    }
}

fn parse_args(args: Vec<String>) -> Result<Command, String> {
    let mut it = args.into_iter().peekable();
    match it.peek().map(String::as_str) {
        // ⚠ bootstrap·suspend·unsuspend 의 인자는 운영자 sudoers 의 `*` 로 열려 있다(install.sh operator_sudoers, #906).
        // 파일을 읽거나 쓰는 인자, --data 를 바꾸는 길(다른 이름·`=` 꼴), 같은 인자 두 번 받기를 더하지 말 것 — 운영자가 이 데이터
        // 폴더 밖이나 lodelai 사용자의 파일을 건드리게 된다. 모르는 인자는 늘 거절한다.
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
        Some(cmd @ ("suspend" | "unsuspend")) => {
            let lift = cmd == "unsuspend";
            it.next();
            let (mut data, mut user, mut for_ms) = (None, None, None);
            let mut seen = std::collections::HashSet::new();
            while let Some(a) = it.next() {
                if a.starts_with("--") && !seen.insert(a.clone()) {
                    return Err(format!("같은 인자 두 번: {a}"));
                }
                match a.as_str() {
                    "--data" => data = Some(PathBuf::from(value(&mut it, "--data")?)),
                    "--user" => user = Some(value(&mut it, "--user")?),
                    "--for" if !lift => for_ms = Some(parse_ttl(&value(&mut it, "--for")?)?),
                    other => return Err(format!("모르는 인자: {other}")),
                }
            }
            return Ok(Command::Suspend {
                data: data_or_env(data)?,
                user: user.ok_or("--user 필요")?,
                for_ms,
                lift,
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
        Some("duty-log") => {
            it.next();
            let (mut data, mut since_ms) = (None, 0i64);
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--data" => data = Some(PathBuf::from(value(&mut it, "--data")?)),
                    "--since-ms" => {
                        since_ms = value(&mut it, "--since-ms")?
                            .parse()
                            .map_err(|_| "--since-ms 숫자(유닉스 ms)")?;
                    }
                    other => return Err(format!("모르는 인자: {other}")),
                }
            }
            return Ok(Command::DutyLog {
                data: data_or_env(data)?,
                since_ms,
            });
        }
        Some("push-send") => {
            it.next();
            let (mut platform, mut env, mut token, mut conv, mut sealed_file) =
                (None, None, None, None, None);
            let mut seen = std::collections::HashSet::new();
            while let Some(a) = it.next() {
                if a.starts_with("--") && !seen.insert(a.clone()) {
                    return Err(format!("{a} 가 두 번"));
                }
                match a.as_str() {
                    "--platform" => {
                        platform = Some(
                            crate::push::Platform::parse(&value(&mut it, "--platform")?)
                                .ok_or("--platform 은 apns|fcm")?,
                        );
                    }
                    "--env" => {
                        env = Some(
                            crate::push::ApnsEnv::parse(&value(&mut it, "--env")?)
                                .ok_or("--env 는 sandbox|prod")?,
                        );
                    }
                    "--token" => token = Some(value(&mut it, "--token")?),
                    "--collapse" => conv = Some(value(&mut it, "--collapse")?),
                    "--sealed-file" => {
                        sealed_file = Some(PathBuf::from(value(&mut it, "--sealed-file")?));
                    }
                    other => return Err(format!("모르는 인자: {other}")),
                }
            }
            let platform = platform.ok_or("--platform apns|fcm 필요")?;
            if env.is_some() && platform == crate::push::Platform::Fcm {
                return Err("--env 는 apns 만".into());
            }
            let token = token
                .filter(|t| !t.trim().is_empty() && !t.contains(char::is_whitespace))
                .ok_or("--token 필요(공백 없이)")?;
            return Ok(Command::PushSend(PushSend {
                platform,
                env: env.unwrap_or(crate::push::ApnsEnv::Sandbox),
                token,
                conv,
                sealed_file,
            }));
        }
        _ => {}
    }
    let (mut local, mut data, mut port, mut server, mut token_stdin) =
        (false, None, 0u16, None, false);
    let (mut public_host, mut behind_cloudflare) = (None, false);
    let mut test_extra_host: Option<String> = None;
    let (mut dev_mail, mut privacy_version, mut blob_min_free) = (None, None, None);
    let mut blob_daily_max = None;
    let mut privacy_url = None;
    let mut waitlist_url = None;
    let mut max_devices = None;
    let (mut org_create_open, mut org_limits) = (false, crate::OrgCreateLimits::default());
    let mut personal_signup: Option<bool> = None;
    let mut groups = None;
    let mut mobile_push = false;
    let mut test_invite_fail = false;
    let mut test_invite_fail_retry_secs: Option<u64> = None;
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
            "--test-extra-host" => {
                let h = value(&mut it, "--test-extra-host")?;
                // 정확한 이름 하나 — 와일드카드·포트·경로·빈 값은 받지 않는다.
                if h.is_empty()
                    || !h
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                {
                    return Err("--test-extra-host 는 이름 하나(예 my-mac.tailnet.ts.net)".into());
                }
                test_extra_host = Some(h);
            }
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
            "--blob-daily-max-bytes" => {
                blob_daily_max = Some(
                    value(&mut it, "--blob-daily-max-bytes")?
                        .parse()
                        .map_err(|_| "--blob-daily-max-bytes 바이트 숫자(0 = 끔)")?,
                );
            }
            "--groups" => groups = Some(true),
            "--no-groups" => groups = Some(false),
            "--mobile-push" => mobile_push = true,
            "--test-invite-fail" => test_invite_fail = true,
            "--test-invite-fail-retry-secs" => {
                test_invite_fail_retry_secs =
                    Some(count(&mut it, "--test-invite-fail-retry-secs")?);
            }
            "--max-devices-per-user" => {
                max_devices = Some(count(&mut it, "--max-devices-per-user")?);
            }
            "--personal-signup" => {
                personal_signup = Some(on_off(
                    &value(&mut it, "--personal-signup")?,
                    "--personal-signup",
                )?);
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
        if personal_signup.is_none() {
            personal_signup = env_opt("LODELAI_PERSONAL_SIGNUP")
                .map(|v| on_off(&v, "LODELAI_PERSONAL_SIGNUP"))
                .transpose()?;
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
        (true, None) if personal_signup == Some(false) => {
            return Err("--personal-signup off 는 원격 relay 만".into())
        }
        (false, Some(h)) if dev_mail.is_some() && !crate::is_test_domain(h) => {
            return Err(
                "원격 relay 는 개발용 가짜 메일(--dev-mail)을 쓰지 않는다(시험용 도메인 .test 등만 예외)".into(),
            )
        }
        (false, Some(h)) if test_extra_host.is_some() && !crate::is_test_domain(h) => {
            return Err(
                "원격 relay 는 시험 전용 --test-extra-host 를 쓰지 않는다(시험용 도메인 .test 등만 예외)".into(),
            )
        }
        _ if test_invite_fail_retry_secs.is_some() && !test_invite_fail => {
            return Err("--test-invite-fail-retry-secs 는 --test-invite-fail 과 같이만 쓴다".into())
        }
        (false, Some(h)) if test_invite_fail && !crate::is_test_domain(h) => {
            return Err(
                "원격 relay 는 시험 전용 --test-invite-fail 을 쓰지 않는다(시험용 도메인 .test 등만 예외)".into(),
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
        test_extra_host,
        behind_cloudflare,
        blob_min_free,
        blob_daily_max,
        max_devices,
        org_create_open,
        personal_signup: personal_signup.unwrap_or(true),
        org_limits,
        test_recovery,
        groups: groups.unwrap_or(true),
        mobile_push,
        test_invite_fail,
        test_invite_fail_retry_secs,
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
/// #845 ⑤ `suspend`·`unsuspend`: 도는 relay 는 다음 틱에 그 사람의 연결을 닫는다(다시 붙으면 account_suspended).
fn suspend(data: &Path, user: &str, for_ms: Option<i64>, lift: bool) -> ExitCode {
    let db = match existing_db(data) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::FAILURE;
        }
    };
    let now = Effects::system().clock.now().0;
    let res = if lift {
        db.unsuspend(user)
    } else {
        db.suspend(user, for_ms.map(|f| now + f), now)
    };
    match res {
        Ok(true) => {
            println!("{}: {user}", if lift { "풀림" } else { "멈춤" });
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("lodelai-relay: 그런 사용자 없음(또는 멈춰 있지 않음): {user}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

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

/// 모바일 검증 S3 판정 표(읽기 전용 — 돌고 있는 시험 relay 를 건드리지 않는다). `since_ms` 뒤의 것만:
/// `duty <기기> <사용자> <일> <수>` 줄들(보낸 duty — `--mobile-push` relay 만 적는다)과 `final <사용자> <수>`(확정된 Commit 을 낸
/// 사람별, 그룹마다 마지막 것).
fn duty_log(path: &Path, since_ms: i64) -> Result<String, String> {
    use std::fmt::Write as _;
    let c = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("DB(읽기 전용) {}: {e}", path.display()))?;
    let _ = c.busy_timeout(std::time::Duration::from_secs(5));
    let rows = |sql: &str| -> Result<Vec<(String, String, String, i64)>, String> {
        let mut st = c.prepare(sql).map_err(|e| e.to_string())?;
        let out = st
            .query_map([since_ms], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_else(|| "-".into()),
                    r.get::<_, Option<String>>(2)?.unwrap_or_else(|| "-".into()),
                    r.get(3)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        Ok(out)
    };
    let mut out = String::new();
    for (device, user, task, n) in rows(
        "SELECT s.device_id, d.user, s.task, COUNT(*) FROM mls_duty_sent s
           LEFT JOIN devices d ON d.device_id = s.device_id
          WHERE s.at_ms >= ?1 GROUP BY s.device_id, s.task ORDER BY d.user, s.device_id, s.task",
    )? {
        let _ = writeln!(out, "duty\t{device}\t{user}\t{task}\t{n}");
    }
    for (user, _, _, n) in rows(
        "SELECT sender_user, NULL, NULL, COUNT(*) FROM mls_outcomes
          WHERE final = 1 AND at_ms >= ?1 GROUP BY sender_user ORDER BY sender_user",
    )? {
        let _ = writeln!(out, "final\t{user}\t{n}");
    }
    Ok(out)
}

/// 푸시 하나를 보내고 결과 한 줄. 받음이면 0, 아니면 1, 자격·인자 문제면 2.
async fn push_send(p: PushSend) -> ExitCode {
    use crate::push::{H2Transport, Outcome, Push, Sender};
    let sender = match Sender::from_env(env_var, std::sync::Arc::new(H2Transport)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            return ExitCode::from(2);
        }
    };
    // 이미 감싼 본문(base64 한 줄, push::seal 꼴) — 손 시험용.
    let sealed = match &p.sealed_file {
        Some(f) => match std::fs::read_to_string(f) {
            Ok(b) => Some(b.trim().to_owned()),
            Err(e) => {
                eprintln!("lodelai-relay: {}: {e}", f.display());
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let push = Push {
        token: p.token,
        conv: p.conv,
        sealed,
        kind: None,
        live: None,
    };
    let who = crate::push::token_prefix(&push.token);
    let now = Effects::system().clock.now().0;
    match sender.send(p.platform, p.env, &push, now).await {
        Ok(Outcome::Sent { id }) => {
            println!("보냄 {who} id={}", id.unwrap_or_default());
            ExitCode::SUCCESS
        }
        Ok(o) => {
            println!("못 보냄 {who} {o:?}");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("lodelai-relay: {e}");
            ExitCode::from(2)
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

/// 로그 거르기: `RUST_LOG` 가 비었거나 없으면 info, 있으면 그 값(틀린 지시는 버림).
fn log_filter(env: Option<&str>) -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .parse_lossy(env.unwrap_or(""))
}

/// 실행 파일 진입점: `args` 는 프로그램 이름을 뺀 인자. 하위 명령(`bootstrap`·`backup`·`backup-mark`)이면 그것을 하고, 아니면
/// relay 를 띄워 끝날 때까지 돈다. 인자 오류는 2.
pub async fn run(args: Vec<String>) -> ExitCode {
    // 부르는 쪽이 이미 구독자를 걸었으면 그대로 둔다. 로그는 늘 stderr 로(systemd 는 journald, 시험·개발은 넘겨받은 파일).
    // `RUST_LOG` 가 없으면 info — 전에는 없을 때 error 만 남아 relay.env 없이 띄운 relay 의 로그가 비었다(0.2.5 관문).
    // 메시지 본문·이메일·코드·키는 어느 수준에서도 찍지 않는다(아이디·기기·msg_id 만).
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(log_filter(std::env::var("RUST_LOG").ok().as_deref()))
        .try_init();

    let args = match parse_args(args) {
        Ok(Command::Serve(a)) => a,
        Ok(Command::Bootstrap { data, op }) => return bootstrap(&data, op),
        Ok(Command::Backup { data, out }) => return backup(&data, &out),
        Ok(Command::Suspend {
            data,
            user,
            for_ms,
            lift,
        }) => return suspend(&data, &user, for_ms, lift),
        Ok(Command::BackupMark { data, mark }) => return backup_mark(&data, &mark),
        Ok(Command::PushSend(p)) => return push_send(p).await,
        Ok(Command::DutyLog { data, since_ms }) => {
            return match duty_log(&data.join("relay.sqlite3"), since_ms) {
                Ok(out) => {
                    print!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("lodelai-relay: {e}");
                    ExitCode::FAILURE
                }
            }
        }
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
    let mut durable_key = false;
    let email_key = match env_var("LODELAI_EMAIL_HMAC_KEY").map(|k| k.trim().to_owned()) {
        Some(k) if k.len() >= 32 => {
            durable_key = true;
            k.into_bytes()
        }
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
    // #738: 조직 만들기 코드 이메일은 고정 키(relay.env)일 때만 키 묶은 꼴로 바꾼다 — 기동 때 한 번, 뒤로는 만료 tick 마다.
    if durable_key {
        db.set_setup_email_key(email_key.clone());
        match db.setup_codes_rekey() {
            Ok(n) => tracing::info!(n, "조직 만들기 코드 이메일을 키 묶은 꼴로 바꿈"),
            Err(e) => tracing::warn!(error = %e, "조직 만들기 코드 이메일 바꾸기 실패"),
        }
    } else {
        tracing::info!("고정 이메일 키 없음 — 조직 만들기 코드 이메일은 SHA 꼴로 둔다");
    }
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
    config.test_extra_host = args.test_extra_host.clone();
    if let Some(h) = &config.test_extra_host {
        tracing::warn!(extra_host = %h, "시험 전용 --test-extra-host 켬 — 이 Host 도 받는다(정식 relay 에 쓰지 말 것)");
    }
    config.behind_cloudflare = args.behind_cloudflare;
    config.privacy_version = args.privacy_version.clone();
    config.privacy_url = args.privacy_url.clone();
    config.waitlist_url = args.waitlist_url.clone();
    // #845 ⑤ 초대 메일의 '문의하기' 주소 — 운영자가 정할 때만(없으면 그 줄을 싣지 않는다).
    config.contact_email =
        env_opt("LODELAI_CONTACT_EMAIL").and_then(|e| crate::http::normalize_email(&e));
    // #923 신고 받는 주소 — 메일을 보내는 원격 relay 에서만. 꼴이 아니거나 로컬·메일 없음이면 시작 안 함(늘 실패하는
    // 신고 단추를 만들지 않게).
    if let Some(e) = env_opt("LODELAI_REPORT_EMAIL") {
        let Some(n) = crate::http::normalize_email(&e) else {
            eprintln!("lodelai-relay: LODELAI_REPORT_EMAIL 이 이메일 꼴이 아니다");
            return ExitCode::from(2);
        };
        if args.public_host.is_none() || mailer.is_none() {
            eprintln!("lodelai-relay: LODELAI_REPORT_EMAIL 은 메일을 보내는 원격 relay 만(--public-host 와 메일 설정)");
            return ExitCode::from(2);
        }
        tracing::info!("신고 받기 켬");
        config.report_email = Some(n);
    }
    // #845 ⑤ 초대 메일은 운영자가 켤 때만(`LODELAI_INVITE_MAIL=on`).
    config.invite_mail = env_opt("LODELAI_INVITE_MAIL").as_deref() == Some("on");
    if config.invite_mail {
        tracing::info!("초대 메일 켬");
    }
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
    // #876: 플래그 → env → 기본. 숫자가 아니면 멈춘다(조용히 기본으로 돌지 않게).
    if let Some(b) = args.blob_daily_max {
        config.blob_daily_max = b;
    } else if let Some(v) = env_var("LODELAI_BLOB_DAILY_MAX_BYTES")
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
    {
        match v.parse::<u64>() {
            Ok(n) => config.blob_daily_max = n,
            Err(_) => {
                eprintln!("lodelai-relay: LODELAI_BLOB_DAILY_MAX_BYTES 는 바이트 수(0 = 끔)");
                return ExitCode::from(2);
            }
        }
    }
    if config.blob_daily_max == 0 {
        tracing::info!("첨부 하루 상한 끔");
    }
    if let Some(n) = args.max_devices {
        config.max_devices_per_user = n;
    }
    config.org_create_open = args.org_create_open;
    config.personal_signup = args.personal_signup;
    config.org_create_limits = args.org_limits;
    config.groups = args.groups;
    // 휴대폰 푸시: APNs·FCM 자격 env 가 있으면 켠다(키 값은 운영자가 relay.env 에). 자격이 틀리면 멈춘다(조용히 안 보내지 않게).
    let push_sender =
        match crate::push::Sender::from_env(env_var, std::sync::Arc::new(crate::push::H2Transport))
        {
            Ok(s) if s.apns.is_some() || s.fcm.is_some() => Some(s),
            Ok(_) => None,
            Err(e) => {
                eprintln!("lodelai-relay: {e}");
                return ExitCode::from(2);
            }
        };
    config.mobile_push = push_sender.is_some() || args.mobile_push;
    config.duty_log = args.mobile_push;
    config.test_invite_fail = args.test_invite_fail;
    if let Some(s) = args.test_invite_fail_retry_secs {
        config.test_invite_fail_retry_secs = s;
    }
    if config.test_invite_fail {
        tracing::warn!("시험 전용: 앞부분이 fail 인 대상의 group.invite 를 rate_limited 로 답한다(--test-invite-fail)");
    }
    config.push_app_ids = [crate::push::ENV_APNS_TOPIC, crate::push::ENV_FCM_APP_ID]
        .into_iter()
        .filter_map(env_opt)
        .collect();
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
    match push_sender {
        Some(s) => {
            tracing::info!(
                apns = s.apns.is_some(),
                fcm = s.fcm.is_some(),
                "휴대폰 푸시 켬"
            );
            std::sync::Arc::new(crate::push::Outbox::new(s)).install(&app);
        }
        None if args.mobile_push => tracing::warn!(
            "--mobile-push 인데 푸시 자격 env 가 없다 — 등록만 받고 보내지 않는다(시험 relay)"
        ),
        None => tracing::info!(
            "휴대폰 푸시 꺼짐 — APNs·FCM 자격 env 가 없다(LODELAI_APNS_*·LODELAI_FCM_*)"
        ),
    }

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
            personal_signup = args.personal_signup,
            "원격 relay 준비"
        );
        // #905: 개인 가입을 꺼도 코드 없는 조직 만들기가 열려 있으면 누구나 조직을 만들어 들어온다 — '초대받은 사람만'은 둘 다.
        if !args.personal_signup && args.org_create_open {
            tracing::warn!("--personal-signup off 인데 --org-create open — 누구나 조직을 만들어 가입할 수 있다(초대받은 사람만이면 --org-create code)");
        }
        // 원격은 늘 Cloudflare 뒤라는 운영 전제 — 아니면 IP 상한의 IP 가 cloudflared(127.0.0.1) 하나로 모인다(묶음 18 §3).
        if args.org_create_open && !args.behind_cloudflare {
            tracing::warn!("--org-create open 인데 --behind-cloudflare 가 없다 — 조직 만들기 IP 상한이 연결 주소로 센다");
        }
    } else {
        tracing::info!(port = addr.port(), server = %args.server, "로컬 relay 준비");
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

    #[test]
    fn log_filter_defaults_to_info() {
        use tracing_subscriber::filter::LevelFilter;
        let hint = |e: Option<&str>| log_filter(e).max_level_hint();
        assert_eq!(hint(None), Some(LevelFilter::INFO));
        assert_eq!(hint(Some("")), Some(LevelFilter::INFO));
        assert_eq!(hint(Some("warn")), Some(LevelFilter::WARN));
        assert_eq!(hint(Some("debug")), Some(LevelFilter::DEBUG));
    }

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|a| (*a).to_owned()).collect())
    }

    #[test]
    fn duty_log_reads_sent_duties_and_finals_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sqlite3");
        let db = Db::open(&path).unwrap();
        db.register_device("bob", None, "b-mac", "e", "x", "s", 0, false)
            .unwrap();
        db.duty_sent_put("b-mac", "remove_user", "g1", 0, 100)
            .unwrap();
        db.duty_sent_put("b-mac", "remove_user", "g2", 0, 200)
            .unwrap();
        db.duty_sent_put("b-mac", "remove_user", "g0", 0, 10)
            .unwrap();
        drop(db);
        let before = std::fs::read(&path).unwrap();
        let out = duty_log(&path, 50).unwrap();
        assert_eq!(out, "duty\tb-mac\tbob\tremove_user\t2\n", "since 뒤의 것만");
        assert_eq!(std::fs::read(&path).unwrap(), before, "읽기만");
        assert!(
            duty_log(&dir.path().join("none.sqlite3"), 0).is_err(),
            "없는 DB 를 만들지 않는다"
        );
        assert!(!dir.path().join("none.sqlite3").exists());
        let Ok(Command::DutyLog { since_ms, .. }) =
            parse(&["duty-log", "--data", "/x", "--since-ms", "5"])
        else {
            panic!("duty-log 아님");
        };
        assert_eq!(since_ms, 5);
        assert!(parse(&["duty-log", "--data", "/x", "--since-ms", "x"]).is_err());
    }

    #[test]
    fn suspend_args() {
        let Ok(Command::Suspend {
            user, for_ms, lift, ..
        }) = parse(&[
            "suspend", "--data", "/tmp/x", "--user", "ann", "--for", "7d",
        ])
        else {
            panic!("suspend")
        };
        assert_eq!(
            (user.as_str(), for_ms, lift),
            ("ann", Some(7 * 24 * 60 * 60 * 1000), false)
        );
        let Ok(Command::Suspend { for_ms, lift, .. }) =
            parse(&["unsuspend", "--data", "/tmp/x", "--user", "ann"])
        else {
            panic!("unsuspend")
        };
        assert_eq!((for_ms, lift), (None, true));
        assert!(parse(&[
            "unsuspend",
            "--data",
            "/tmp/x",
            "--user",
            "ann",
            "--for",
            "1d"
        ])
        .is_err());
        assert!(parse(&["suspend", "--data", "/tmp/x"]).is_err());
        assert!(parse(&["suspend", "--data", "/tmp/x", "--user", "a", "--user", "b"]).is_err());
        // #906: 운영자 sudoers 는 `suspend --data <폴더> --user *` — 뒤에 --data 를 또 붙여 다른 폴더로 못 바꾼다. 모르는 인자
        // (`--data=` 꼴·파일 인자)도 거절.
        for cmd in ["suspend", "unsuspend"] {
            assert!(parse(&[cmd, "--data", "/a", "--user", "x", "--data", "/b"]).is_err());
            assert!(parse(&[cmd, "--data", "/a", "--user", "x", "--data=/b"]).is_err());
            assert!(parse(&[cmd, "--data", "/a", "--user", "x", "--out", "/tmp/f"]).is_err());
        }
        // bootstrap 도 같다(sudoers `bootstrap --data <폴더> --email *`·`--revoke *`).
        for extra in [&["--data", "/b"][..], &["--data=/b"], &["--out", "/tmp/f"]] {
            let mut a = vec!["bootstrap", "--data", "/a", "--email", "x@y.io"];
            a.extend_from_slice(extra);
            assert!(parse(&a).is_err(), "{a:?}");
        }
    }

    #[test]
    fn push_send_args() {
        use crate::push::{ApnsEnv, Platform};
        let Ok(Command::PushSend(p)) = parse(&[
            "push-send",
            "--platform",
            "apns",
            "--token",
            "ab12",
            "--collapse",
            "c",
        ]) else {
            panic!("push-send 아님");
        };
        assert_eq!(
            p,
            PushSend {
                platform: Platform::Apns,
                env: ApnsEnv::Sandbox,
                token: "ab12".into(),
                conv: Some("c".into()),
                sealed_file: None,
            }
        );
        let Ok(Command::PushSend(p)) = parse(&[
            "push-send",
            "--platform",
            "apns",
            "--env",
            "prod",
            "--token",
            "t",
        ]) else {
            panic!("push-send 아님");
        };
        assert_eq!(p.env, ApnsEnv::Prod);
        for (args, want) in [
            (&["push-send", "--token", "t"][..], "--platform"),
            (
                &["push-send", "--platform", "x", "--token", "t"][..],
                "apns|fcm",
            ),
            (&["push-send", "--platform", "fcm"][..], "--token"),
            (
                &[
                    "push-send",
                    "--platform",
                    "fcm",
                    "--token",
                    "t",
                    "--env",
                    "prod",
                ][..],
                "apns 만",
            ),
            (
                &[
                    "push-send",
                    "--platform",
                    "apns",
                    "--token",
                    "t",
                    "--token",
                    "u",
                ][..],
                "두 번",
            ),
            (
                &[
                    "push-send",
                    "--platform",
                    "apns",
                    "--token",
                    "t",
                    "--title",
                    "x",
                ][..],
                "모르는 인자",
            ),
        ] {
            let e = parse(args)
                .err()
                .unwrap_or_else(|| panic!("통과하면 안 됨: {args:?}"));
            assert!(e.contains(want), "{args:?}: {e}");
        }
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
        // #905 개인 공간 가입: 기본 on, 원격만 off, on|off 밖은 시작 안 함.
        let hosted = |extra: &[&str]| {
            let mut a = vec![
                "--data",
                "/x",
                "--public-host",
                "relay.example.com",
                "--port",
                "8787",
                "--privacy-version",
                "2026-10-25",
            ];
            a.extend_from_slice(extra);
            parse(&a)
        };
        let signup = |extra: &[&str]| match hosted(extra) {
            Ok(Command::Serve(a)) => a.personal_signup,
            other => panic!("{extra:?}: {}", other.is_ok()),
        };
        assert!(signup(&[]));
        assert!(signup(&["--personal-signup", "on"]));
        assert!(!signup(&["--personal-signup", "off"]));
        assert!(hosted(&["--personal-signup", "no"]).is_err());
        assert!(parse(&["--local", "--data", "/x", "--personal-signup", "off"]).is_err());
        assert!(serve(&["--local", "--data", "/x", "--personal-signup", "on"]).personal_signup);
        // #904 판정 7: hosted 설치(install.sh --domain api.lodelai.com → --public-host)는 메일 링크에 서버 주소를 싣지 않는다.
        let official = serve(&[
            "--data",
            "/x",
            "--public-host",
            crate::OFFICIAL_HOST,
            "--port",
            "8787",
            "--privacy-version",
            "2026-10-25",
        ]);
        let host = crate::mail_host(official.public_host.as_deref(), &official.server);
        assert_eq!(host, "api.lodelai.com");
        assert_eq!(crate::invite_link(host), crate::INVITE_LINK);
        for bad in ["0", "-1", "x"] {
            assert!(parse(&["--local", "--data", "/x", "--test-recovery-wait", bad]).is_err());
        }
        // 손잡이가 없으면 기본(24h·24h·30일) 그대로.
        let a = serve(&["--local", "--data", "/x"]);
        assert!(a.test_extra_host.is_none());
        let a = serve(&["--local", "--data", "/x"]);
        assert!(!a.test_recovery.any());
    }

    /// QA: --test-invite-fail 은 로컬·시험용 도메인 원격만, 기본 꺼짐.
    #[test]
    fn test_invite_fail_is_local_or_test_domain_only() {
        assert!(serve(&["--local", "--data", "/x", "--test-invite-fail"]).test_invite_fail);
        assert!(!serve(&["--local", "--data", "/x"]).test_invite_fail);
        // 다시 시도 시각: --test-invite-fail 과 같이만, 0·꼴 틀림은 거절, 없으면 None(기본 3600).
        let a = serve(&[
            "--local",
            "--data",
            "/x",
            "--test-invite-fail",
            "--test-invite-fail-retry-secs",
            "5",
        ]);
        assert_eq!(a.test_invite_fail_retry_secs, Some(5));
        assert!(serve(&["--local", "--data", "/x", "--test-invite-fail"])
            .test_invite_fail_retry_secs
            .is_none());
        assert!(parse(&[
            "--local",
            "--data",
            "/x",
            "--test-invite-fail-retry-secs",
            "5"
        ])
        .is_err());
        for bad in ["0", "x"] {
            assert!(parse(&[
                "--local",
                "--data",
                "/x",
                "--test-invite-fail",
                "--test-invite-fail-retry-secs",
                bad
            ])
            .is_err());
        }
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
                "--test-invite-fail",
            ])
        };
        assert!(remote("relay.lodelai.test").is_ok());
        assert!(remote("relay.example.com").is_err());
    }

    /// 휴대폰 실기(Tailscale): --test-extra-host 는 로컬·시험용 도메인 원격만, 이름 하나만.
    #[test]
    fn test_extra_host_is_local_or_test_domain_only() {
        let remote = |host: &str, extra: &str| {
            parse(&[
                "--data",
                "/x",
                "--public-host",
                host,
                "--port",
                "8825",
                "--privacy-version",
                "1",
                "--test-extra-host",
                extra,
            ])
        };
        assert!(remote("mobile.test", "my-mac.tail0.ts.net").is_ok());
        assert!(remote("relay.example.com", "my-mac.tail0.ts.net").is_err());
        for bad in ["*.ts.net", "a.ts.net:443", "a/b", ""] {
            assert!(remote("mobile.test", bad).is_err(), "{bad}");
        }
        let a = serve(&["--local", "--data", "/x", "--test-extra-host", "a.ts.net"]);
        assert_eq!(a.test_extra_host.as_deref(), Some("a.ts.net"));
    }
}
