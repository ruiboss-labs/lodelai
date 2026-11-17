//! 실기 시험 씨앗(모바일 검증 S3·S4). **시험 relay 만** — 이 맥의 루프백 relay 가 아니면 시작하지 않는다.
//!
//! 새 시험 사용자(`--user`)를 등록하고, 그 기기 키·MLS 저장소는 이번 실행 동안만 둔다(키는 메모리, 저장소는 임시 폴더 —
//! 끝나면 지움). 보내는 글은 코어가 만드는 꼴(`envelope`)이라 받는 휴대폰은 보통 대화 글로 받는다.
//!
//! ```text
//! # S4: 글 1000개(첫 글 하나를 보낸 뒤 Enter 를 기다린다 — 휴대폰 대화에 보이는지 먼저 본다)
//! cargo run -p lodelai-relay-client --example seed -- --http 127.0.0.1:8823 --server <relay 이름> \
//!   --token-file <등록 토큰 파일> --user seed1 messages --to alice@<relay 이름> --count 1000 --confirm-first
//! # S3: 그룹 10개를 만든 뒤 모두 나간다 — 남은 멤버 기기에 remove_user duty 10개(맥이 Commit 으로 끝냄)
//! cargo run -p lodelai-relay-client --example seed -- --http 127.0.0.1:8823 --server <relay 이름> \
//!   --token-file <등록 토큰 파일> --user seed2 groups --to alice@<relay 이름> --count 10 --leave
//! # 이메일 가입 시험 relay(`--dev-mail`)면 등록 토큰 대신 이메일 가입 — 휴대폰과 같은 조직에 초대 코드로 든다.
//! #   --dev-mail <relay 의 --dev-mail 폴더> --email seed1@mobile.test --invite <맥 앱의 초대 코드> --privacy <동의 판>
//! ```

use std::io::BufRead as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use lodelai_crypto::DeviceKeys;
use lodelai_effects::{Clock, IdGen, OsRng, Rng, SystemClock, UlidGen, UnixMillis};
use lodelai_relay_client::envelope;
use lodelai_relay_client::register::{
    register_device, register_device_hosted, signup_start, signup_verify, DeviceInfo, HostedOrg,
};
use lodelai_relay_client::{Config, Inbound, Outgoing, RelayClient};
use tokio::sync::mpsc::Receiver;

/// 받는 쪽이 오래 열지 않아도 남게 7일.
const KEEP_MS: i64 = 7 * 24 * 3600 * 1000;
/// 한 단계에서 아무 진척이 없으면 멈추는 상한.
const STALL: Duration = Duration::from_secs(120);

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Messages { count: usize, confirm_first: bool },
    Groups { count: usize, leave: bool },
}

/// 시험 relay 에 드는 길.
#[derive(Debug, PartialEq, Eq)]
enum Join {
    /// 로컬 relay 의 기기 등록 토큰 파일.
    Token(PathBuf),
    /// 이메일 가입 relay(`--dev-mail`): 코드를 `<dev_mail>/<email>.txt` 에서 읽고, 초대 코드로 그 조직에 든다.
    DevMail {
        dir: PathBuf,
        email: String,
        invite: String,
        privacy: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    http: SocketAddr,
    server: String,
    join: Join,
    user: String,
    to: Vec<String>,
    mode: Mode,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut it = args.iter();
    let (mut http, mut server, mut token_file, mut user) = (None, None, None, None);
    let (mut dev_mail, mut email, mut invite, mut privacy) = (None, None, None, None);
    let mut to = Vec::new();
    let (mut mode, mut count, mut confirm_first, mut leave) = (None, None, false, false);
    while let Some(a) = it.next() {
        let mut val = |f: &str| it.next().cloned().ok_or_else(|| format!("{f} 값"));
        match a.as_str() {
            "--http" => {
                http = Some(
                    val("--http")?
                        .parse::<SocketAddr>()
                        .map_err(|_| "--http 는 127.0.0.1:<포트> 꼴")?,
                );
            }
            "--server" => server = Some(val("--server")?),
            "--token-file" => token_file = Some(PathBuf::from(val("--token-file")?)),
            "--user" => user = Some(val("--user")?),
            "--dev-mail" => dev_mail = Some(PathBuf::from(val("--dev-mail")?)),
            "--email" => email = Some(val("--email")?),
            "--invite" => invite = Some(val("--invite")?),
            "--privacy" => privacy = Some(val("--privacy")?),
            "--to" => to.push(val("--to")?),
            "--count" => {
                count = Some(
                    val("--count")?
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=10_000).contains(n))
                        .ok_or("--count 는 1~10000")?,
                );
            }
            "--confirm-first" => confirm_first = true,
            "--leave" => leave = true,
            "messages" | "groups" if mode.is_none() => mode = Some(a.clone()),
            other => return Err(format!("모르는 인자: {other}")),
        }
    }
    let http = http.ok_or("--http 필요")?;
    // 가드: 이 맥의 루프백 relay 만(hosted·남의 relay 에 시험 사용자·글을 넣지 않는다).
    if !http.ip().is_loopback() {
        return Err("시험 relay(루프백 127.0.0.1)만 — 다른 주소면 시작하지 않는다".into());
    }
    let server = server.ok_or("--server 필요")?;
    if server.to_ascii_lowercase().contains("lodelai.com") {
        return Err("정식 relay 이름이면 시작하지 않는다".into());
    }
    if to.is_empty() {
        return Err("--to <사람 주소> 필요".into());
    }
    let count = count.ok_or("--count 필요")?;
    let mode = match mode.as_deref() {
        Some("messages") if to.len() == 1 && !leave => Mode::Messages {
            count,
            confirm_first,
        },
        Some("messages") => return Err("messages 는 --to 하나, --leave 없이".into()),
        Some("groups") if !confirm_first => Mode::Groups { count, leave },
        Some("groups") => return Err("--confirm-first 는 messages 만".into()),
        _ => return Err("messages 또는 groups 필요".into()),
    };
    let join = match (token_file, dev_mail) {
        (Some(f), None) if email.is_none() && invite.is_none() && privacy.is_none() => Join::Token(f),
        (None, Some(dir)) => Join::DevMail {
            dir,
            email: email.ok_or("--dev-mail 엔 --email 필요")?,
            invite: invite.ok_or("--dev-mail 엔 --invite 필요(휴대폰과 같은 조직)")?,
            privacy: privacy.ok_or("--dev-mail 엔 --privacy <동의 판> 필요")?,
        },
        _ => {
            return Err(
                "--token-file(로컬 relay) 또는 --dev-mail·--email·--invite·--privacy(이메일 가입 relay) 중 하나".into(),
            )
        }
    };
    Ok(Args {
        http,
        server,
        join,
        user: user.ok_or("--user 필요")?,
        to,
        mode,
    })
}

struct Seed {
    client: RelayClient,
    rx: Receiver<Inbound>,
    ids: UlidGen,
    clock: Arc<dyn Clock>,
    me: String,
}

impl Seed {
    fn times(&self) -> (UnixMillis, UnixMillis) {
        let now = self.clock.now();
        (now, UnixMillis(now.0 + KEEP_MS))
    }

    /// 다음 받은 것 하나(받은 글은 ack 하고 건너뛴다 — relay 에 쌓이지 않게). 상한 안에 아무것도 없으면 오류.
    async fn next(&mut self, what: &str) -> Result<Inbound, String> {
        loop {
            match tokio::time::timeout(STALL, self.rx.recv()).await {
                Ok(Some(
                    Inbound::Deliver { ack, .. }
                    | Inbound::Held { ack, .. }
                    | Inbound::Unreadable { ack, .. },
                )) => ack.ack(),
                Ok(Some(i)) => return Ok(i),
                Ok(None) => return Err("연결 채널 닫힘".into()),
                Err(_) => return Err(format!("{what}: {}초 동안 진척 없음", STALL.as_secs())),
            }
        }
    }

    async fn ready(&mut self) -> Result<(), String> {
        loop {
            if let Inbound::Ready { .. } = self.next("ready").await? {
                return Ok(());
            }
        }
    }

    fn send(&self, to: &str, text: &str) -> Result<String, String> {
        let (now, exp) = self.times();
        let id = self.ids.next_ulid();
        let m = envelope::chat(&id, now, exp, &self.me, to, text);
        self.client
            .enqueue(&Outgoing::Send { message: m })
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// 보낸 글이 모두 relay 에 저장(ack)될 때까지. 거절(nack)은 세어 돌려준다.
    async fn until_acked(&mut self, mut ids: Vec<String>) -> Result<usize, String> {
        let mut nacks = 0;
        let total = ids.len();
        let mut shown = 0;
        while !ids.is_empty() {
            match self.next("ack").await? {
                Inbound::Ack { msg_id } => ids.retain(|i| *i != msg_id),
                Inbound::Nack { msg_id, reason, .. } => {
                    eprintln!("거절 {msg_id}: {reason:?}");
                    ids.retain(|i| *i != msg_id);
                    nacks += 1;
                }
                _ => {}
            }
            let done = total - ids.len();
            if done / 100 > shown {
                shown = done / 100;
                eprintln!("{done}/{total}");
            }
        }
        Ok(nacks)
    }

    fn change(
        &self,
        gid: &str,
        op: &str,
        subjects: &[&str],
        name: Option<&str>,
    ) -> Result<(), String> {
        let (now, exp) = self.times();
        let group = format!("+{gid}@{}", self.me.split_once('@').map_or("", |(_, s)| s));
        let m = envelope::group_change(
            &self.ids.next_ulid(),
            now,
            exp,
            &self.me,
            &group,
            op,
            subjects,
            name,
        );
        self.client
            .enqueue(&Outgoing::GroupChange { message: m })
            .map_err(|e| e.to_string())
    }

    async fn until_update(&mut self, gid: &str, op: &str) -> Result<(), String> {
        loop {
            if let Inbound::GroupUpdate { gid: g, op: o, .. } = self.next(op).await? {
                if g == gid && o == op {
                    return Ok(());
                }
            }
        }
    }
}

/// 이메일 가입 relay 의 개발용 메일 파일에서 확인 코드를 기다린다(같은 맥의 파일 — 0.5초마다, 30초 상한).
async fn dev_mail_code(dir: &std::path::Path, email: &str) -> Result<String, String> {
    let path = dir.join(format!("{}.txt", email.to_lowercase()));
    for _ in 0..60 {
        if let Ok(t) = std::fs::read_to_string(&path) {
            let code = t.trim().to_owned();
            if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(code);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("{} 에 확인 코드가 오지 않음(30초)", path.display()))
}

/// 시험 relay 에 든다. 돌려주는 값은 relay 가 정한 아이디.
async fn join(a: &Args, keys: &DeviceKeys) -> Result<String, String> {
    let info = DeviceInfo::of(&a.user, Some(&a.user), keys);
    match &a.join {
        Join::Token(f) => {
            let token = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
            register_device(a.http, token.trim(), &info)
                .await
                .map_err(|e| format!("등록: {e}"))?;
            Ok(a.user.clone())
        }
        Join::DevMail {
            dir,
            email,
            invite,
            privacy,
        } => {
            let ws = format!("ws://{}/v1/ws", a.http);
            // 지난 실행의 코드 파일을 새 코드로 잘못 읽지 않게 먼저 지운다(relay 가 덮어쓰지만 늦을 수 있다).
            let _ = std::fs::remove_file(dir.join(format!("{}.txt", email.to_lowercase())));
            signup_start(&ws, email, None, privacy)
                .await
                .map_err(|e| format!("가입 메일: {e}"))?;
            let code = dev_mail_code(dir, email).await?;
            let v = signup_verify(&ws, email, &code)
                .await
                .map_err(|e| format!("코드 확인: {e}"))?;
            if v.existing.is_some() {
                return Err(format!("{email} 은 이미 계정이 있다 — 새 이메일로"));
            }
            let r = register_device_hosted(
                &ws,
                &v.signup_token,
                &info,
                Some(&a.user),
                Some(&HostedOrg::Invite(invite.clone())),
                &[],
            )
            .await
            .map_err(|e| format!("가입: {e}"))?;
            if let Some(s) = r.server.as_deref() {
                if s != a.server {
                    return Err(format!("relay 이름이 {s} — --server 와 다름"));
                }
            }
            Ok(r.user)
        }
    }
}

async fn run(a: Args) -> Result<(), String> {
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let mut seed = [0u8; 64];
    rng.try_fill(&mut seed).map_err(|e| e.to_string())?;
    let keys = DeviceKeys::generate(&seed);
    seed.fill(0);
    let user = join(&a, &keys).await?;
    let mut store_key = zeroize::Zeroizing::new([0u8; 32]);
    rng.try_fill(store_key.as_mut())
        .map_err(|e| e.to_string())?;
    // MLS 저장소는 임시 폴더(끝나면 지움 — 이 사용자로 다시 보낼 일은 없다).
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut c = Config::new(
        format!("ws://{}/v1/ws", a.http),
        a.server.clone(),
        user.clone(),
        keys,
        store_key,
    );
    c.groups = true;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let (client, rx) =
        RelayClient::start(c, &dir.path().join("seed.db"), clock.clone(), rng.clone())
            .map_err(|e| e.to_string())?;
    let mut s = Seed {
        client,
        rx,
        ids: UlidGen::new(clock.clone(), rng),
        clock,
        me: format!("{user}@{}", a.server),
    };
    s.ready().await?;
    let result = match a.mode {
        Mode::Messages {
            count,
            confirm_first,
        } => {
            let to = &a.to[0];
            let first = s.send(to, &format!("씨앗 1/{count}"))?;
            let first_nacks = s.until_acked(vec![first]).await?;
            if confirm_first && count > 1 {
                eprintln!("첫 글을 보냈다 — 휴대폰 대화에 보이면 Enter(멈추려면 Ctrl-C)");
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
            }
            let ids = (2..=count)
                .map(|i| s.send(to, &format!("씨앗 {i}/{count}")))
                .collect::<Result<Vec<_>, _>>()?;
            let nacks = first_nacks + s.until_acked(ids).await?;
            println!("보냄 {count} · 거절 {nacks}");
            Ok(())
        }
        Mode::Groups { count, leave } => {
            let to: Vec<&str> = a.to.iter().map(String::as_str).collect();
            let mut gids = Vec::new();
            for i in 1..=count {
                let gid = s.ids.next_ulid().to_lowercase();
                s.change(&gid, "create", &to, Some(&format!("씨앗 그룹 {i}")))?;
                s.until_update(&gid, "create").await?;
                eprintln!("만듦 {i}/{count}");
                gids.push(gid);
            }
            if leave {
                for (i, gid) in gids.iter().enumerate() {
                    s.change(gid, "leave", &[], None)?;
                    s.until_update(gid, "leave").await?;
                    eprintln!("나감 {}/{count}", i + 1);
                }
            }
            println!("그룹 {count}{}", if leave { " · 모두 나감" } else { "" });
            Ok(())
        }
    };
    s.client.shutdown().await;
    drop(dir);
    result
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("seed: {e}");
            return ExitCode::from(2);
        }
    };
    match run(a).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("seed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Args, String> {
        parse(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }

    #[test]
    fn only_loopback_test_relays() {
        let base = "--server t --token-file /t --user s --to r@t --count 3";
        assert!(p(&format!("--http 127.0.0.1:8823 {base} messages")).is_ok());
        let e = p(&format!("--http 10.0.0.2:8823 {base} messages")).unwrap_err();
        assert!(e.contains("루프백"), "{e}");
        let e = p("--http 127.0.0.1:1 --server relay.lodelai.com --token-file /t --user s --to r@t --count 3 messages")
            .unwrap_err();
        assert!(e.contains("정식"), "{e}");
    }

    #[test]
    fn token_file_or_dev_mail_signup() {
        let tail = "--server t --user s --to r@t --count 3 messages";
        let a = p(&format!(
            "--http 127.0.0.1:8825 --dev-mail /m --email s@mobile.test --invite ABC --privacy 1 {tail}"
        ))
        .unwrap();
        assert_eq!(
            a.join,
            Join::DevMail {
                dir: "/m".into(),
                email: "s@mobile.test".into(),
                invite: "ABC".into(),
                privacy: "1".into()
            }
        );
        for bad in [
            format!("--http 127.0.0.1:1 {tail}"),
            format!("--http 127.0.0.1:1 --token-file /t --dev-mail /m --email e --invite i --privacy 1 {tail}"),
            format!("--http 127.0.0.1:1 --dev-mail /m --email e --privacy 1 {tail}"),
            format!("--http 127.0.0.1:1 --token-file /t --email e {tail}"),
        ] {
            assert!(p(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn modes_and_their_flags() {
        let base = "--http 127.0.0.1:8823 --server t --token-file /t --user s";
        assert_eq!(
            p(&format!(
                "{base} --to r@t --count 1000 --confirm-first messages"
            ))
            .unwrap()
            .mode,
            Mode::Messages {
                count: 1000,
                confirm_first: true
            }
        );
        assert_eq!(
            p(&format!(
                "{base} --to r@t --to q@t --count 10 --leave groups"
            ))
            .unwrap()
            .mode,
            Mode::Groups {
                count: 10,
                leave: true
            }
        );
        for bad in [
            format!("{base} --to r@t --to q@t --count 1 messages"),
            format!("{base} --to r@t --count 1 --leave messages"),
            format!("{base} --to r@t --count 1 --confirm-first groups"),
            format!("{base} --to r@t --count 0 messages"),
            format!("{base} --count 1 messages"),
            format!("{base} --to r@t --count 1"),
        ] {
            assert!(p(&bad).is_err(), "{bad}");
        }
    }
}
