//! 가입 확인 메일(#339·묶음 5). 서버 relay 는 [`ResendMailer`](Resend HTTPS API) 또는 [`SmtpMailer`](운영자 SMTP, TLS 필수 —
//! 묶음 29 §1-3), 로컬 개발은 가짜 [`FileMailer`]. 고르기·보내는 주소는 운영자 env([`mailer_from_env`]).
//!
//! 코드·이메일은 비밀이다 — 로그에 값을 찍지 않는다(파일 경로·HTTP 상태만).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 6자리 확인 코드를 그 이메일로 보낸다.
pub trait Mailer: Send + Sync {
    /// `locale` 은 `ko`·`en`(그 밖은 en).
    ///
    /// # Errors
    /// 보내지 못했다(진단 문자열 — 응답에는 싣지 않는다, 이메일·코드를 넣지 않는다).
    fn send_code(&self, email: &str, code: &str, locale: &str) -> Result<(), String> {
        let (subject, text) = code_mail(code, locale);
        self.send_text(email, &subject, &text)
    }

    /// 제목·본문(텍스트만, 링크 없음)을 그 이메일로 보낸다 — 계정 알림(#577 메일 확인 끊기).
    ///
    /// # Errors
    /// 보내지 못했다(진단 문자열 — 이메일·본문을 넣지 않는다).
    fn send_text(&self, email: &str, subject: &str, text: &str) -> Result<(), String>;

    /// #845 ⑤ 초대 메일 — 받지 않기 주소를 `List-Unsubscribe`·`List-Unsubscribe-Post`(RFC 8058) 머리로 싣는다. 기본은 머리 없이
    /// [`Mailer::send_text`].
    ///
    /// # Errors
    /// 보내지 못했다(진단 문자열 — 이메일·본문을 넣지 않는다).
    fn send_invite(
        &self,
        email: &str,
        subject: &str,
        text: &str,
        unsubscribe: &str,
    ) -> Result<(), String> {
        let _ = unsubscribe;
        self.send_text(email, subject, text)
    }

    /// 개발용 가짜 메일인가(원격 relay 는 거부한다, 묶음 5).
    fn is_dev(&self) -> bool {
        false
    }
}

const RESEND_HOST: &str = "api.resend.com";
/// 메일 하나 보내기의 시간 상한(연결·TLS·응답 전부) — Resend·SMTP 같게.
const MAIL_TIMEOUT: Duration = Duration::from_secs(10);

/// 운영자 env 로 메일을 고른다(묶음 29 §1-3). `get` 은 그 이름의 값(앞뒤 공백을 떼고 비면 없음).
/// - `LODELAI_MAIL` = `resend`(없으면 이것)|`smtp`
/// - `LODELAI_MAIL_FROM` = 보내는 사람(`lodelai <noreply@example.com>` 또는 주소만) — 늘 필요
/// - resend: `RESEND_API_KEY` · smtp: `SMTP_URL`(`smtps://user:pass@host[:465]` 또는 STARTTLS `smtp://user:pass@host[:587]`)
///
/// # Errors
/// 빠지거나 틀린 값 — 무엇을 채울지 한 줄(값·비밀은 싣지 않는다).
pub fn mailer_from_env(get: impl Fn(&str) -> Option<String>) -> Result<Arc<dyn Mailer>, String> {
    let get = |k: &str| {
        get(k)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let from = get("LODELAI_MAIL_FROM").ok_or(
        "LODELAI_MAIL_FROM 이 필요하다(보내는 주소, 예 \"lodelai <noreply@example.com>\")",
    )?;
    let from = MailFrom::parse(&from)
        .ok_or("LODELAI_MAIL_FROM 형식: \"이름 <주소>\" 또는 주소만(줄바꿈 없음)")?;
    match get("LODELAI_MAIL").as_deref() {
        None | Some("resend") => {
            let key = get("RESEND_API_KEY")
                .ok_or("LODELAI_MAIL=resend 는 RESEND_API_KEY 가 필요하다(가입 메일)")?;
            Ok(Arc::new(ResendMailer::new(key, from)))
        }
        Some("smtp") => {
            let url = get("SMTP_URL").ok_or(
                "LODELAI_MAIL=smtp 는 SMTP_URL 이 필요하다(smtps://사용자:비밀번호@호스트 또는 STARTTLS smtp://…)",
            )?;
            Ok(Arc::new(SmtpMailer::new(&smtp_url(&url)?, from)?))
        }
        Some(_) => Err("LODELAI_MAIL 은 resend|smtp".into()),
    }
}

/// 보내는 사람: 머리글 그대로(`header`)와 봉투 주소(`addr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFrom {
    pub header: String,
    pub addr: String,
}

impl MailFrom {
    /// `이름 <주소>` 또는 `주소`. 줄바꿈·제어 문자 없음, 주소는 ASCII 에 `@` 하나. 이름은 한글도 된다(머리글 인코딩은
    /// 보내는 쪽 — lettre·Resend).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.chars().any(char::is_control) {
            return None;
        }
        let addr = match (s.rfind('<'), s.strip_suffix('>')) {
            (Some(i), Some(rest)) => rest[i + 1..].trim(),
            (None, None) => s,
            _ => return None,
        };
        let ok = addr.is_ascii()
            && addr.matches('@').count() == 1
            && !addr.starts_with('@')
            && !addr.ends_with('@')
            && !addr.contains(|c: char| c.is_whitespace() || matches!(c, '<' | '>'));
        ok.then(|| Self {
            header: s.to_owned(),
            addr: addr.to_owned(),
        })
    }
}

/// 확인 메일의 (제목, 본문). 텍스트만 — 링크·조직·아이디 없음. `ko` 아니면 영어.
#[must_use]
pub fn code_mail(code: &str, locale: &str) -> (String, String) {
    if locale == "ko" {
        (
            format!("lodelai 확인 코드 {code}"),
            format!(
                "lodelai 확인 코드: {code}\n\n10분 동안 쓸 수 있어요.\n요청하지 않았다면 이 메일을 무시하세요.\n"
            ),
        )
    } else {
        (
            format!("Lodelai verification code {code}"),
            format!(
                "Your lodelai verification code: {code}\n\nIt expires in 10 minutes.\nIf you didn't request this, you can ignore this email.\n"
            ),
        )
    }
}

/// #845 ⑤ 초대 메일 내용(문안은 문안 확정 845-more §4).
pub struct InviteMail<'a> {
    /// contact | group | org
    pub kind: &'a str,
    pub from_name: &'a str,
    /// 보낸 사람의 확인된 이메일(§7-27 — 꾸밀 수 없는 표지). 이메일 없는 보낸 사람은 메일을 보내지 않는다(§7-30).
    pub from_email: &'a str,
    /// 조직 초대만.
    pub org_name: Option<&'a str>,
    /// 그룹 초대만: 지금 멤버 수.
    pub members: Option<i64>,
    /// 받기·가입 링크(`https://lodelai.com/i/`, 자체 호스팅이면 `#s=<host>` 붙음 — #904).
    pub link: &'a str,
    /// #904 자체 호스팅 relay 의 주소(공식 hosted 면 `None`). 링크를 못 읽는 옛 앱·직접 입력을 위해 본문에 한 줄.
    pub server: Option<&'a str>,
    /// 받지 않기 페이지.
    pub stop_url: &'a str,
    /// '문의' 주소(운영자 설정이 있을 때만).
    pub contact_email: Option<&'a str>,
}

/// #845 ⑤ 초대 메일의 (제목, 본문) — 위에 한국어, 가는 줄, 아래 영어. 링크는 받기 하나, 맨 아래 왜 받았나·받지 않기(·문의).
#[must_use]
pub fn invite_mail(m: &InviteMail<'_>) -> (String, String) {
    let clean = mail_name(m.from_name);
    let name = clean.as_str();
    let mark = m.from_email;
    let who_ko = format!("{name}({mark})");
    let who_en = format!("{name} ({mark})");
    let org = m.org_name.unwrap_or_default();
    let n = m.members.unwrap_or_default();
    let (subject, ko, en) = match m.kind {
        "org" => (
            format!("{name} 님이 {org}에 초대했어요 / {name} invited you to {org}"),
            format!(
                "{who_ko} 님이 lodelai 의 {org} 조직에 초대했어요.\n이 이메일 주소로 가입하면 {org}에 바로 들어가요. 초대는 30일 동안 쓸 수 있어요."
            ),
            format!(
                "{who_en} invited you to join {org} on lodelai.\nSign up with this email address to join {org}. The invite is open for 30 days."
            ),
        ),
        "group" => (
            format!("{name} 님이 lodelai 그룹에 초대했어요 / {name} invited you to a group on lodelai"),
            format!(
                "{who_ko} 님이 멤버 {n}명인 그룹 대화에 초대했어요.\n이 이메일 주소로 가입하면 그룹에 들어갈 수 있어요. 초대는 30일 동안 쓸 수 있어요."
            ),
            format!(
                "{who_en} invited you to a group chat with {n} members.\nSign up with this email address to join the group. The invite is open for 30 days."
            ),
        ),
        _ => (
            format!(
                "{name} 님이 lodelai 에서 연락처 요청을 보냈어요 / {name} sent you a contact request on lodelai"
            ),
            format!(
                "{who_ko} 님이 lodelai 에서 연락처 요청을 보냈어요.\n이 이메일 주소로 가입하면 요청을 받을 수 있어요. 요청은 30일 동안 남아 있어요."
            ),
            format!(
                "{who_en} sent you a contact request on lodelai.\nSign up with this email address to see the request. It stays for 30 days."
            ),
        ),
    };
    let (server_ko, server_en) = m.server.map_or_else(Default::default, |s| {
        (
            format!("\n서버 주소(가입할 때 넣기): {s}"),
            format!("\nServer address (enter it when you sign up): {s}"),
        )
    });
    let mut text = format!(
        "{ko}\n\nlodelai 받기: {link}{server_ko}\n\n——\n\n{en}\n\nGet lodelai: {link}{server_en}\n\n\
         {who_ko} 님이 이 주소를 넣어서 보낸 메일이에요. / {who_en} entered this address, so we sent this email.\n\
         이 주소로 lodelai 메일 받지 않기 / Stop lodelai emails to this address: {stop}\n",
        link = m.link,
        stop = m.stop_url,
    );
    if let Some(c) = m.contact_email {
        text.push_str(&format!("문의: {c} / Contact: {c}\n"));
    }
    (subject, text)
}

/// #923 신고 메일 한 통의 재료. 본문(`messages`·`note`)은 이 메일에만 실리고 relay 는 남기지 않는다.
pub struct ReportMail<'a> {
    pub server: &'a str,
    /// 받은 시각(RFC 3339).
    pub at: &'a str,
    pub reporter: &'a str,
    pub reported: &'a str,
    pub reason: &'a str,
    pub facts: &'a crate::db::ReportFacts,
    /// 대상이 지금 멈춤이면 풀리는 시각(RFC 3339) — `facts.suspended` 를 글로 바꾼 것.
    pub suspended_until: Option<&'a str>,
    pub group: Option<&'a str>,
    pub note: Option<&'a str>,
    pub messages: &'a [lodelai_protocol::ws::ReportedMessage],
}

/// #923 신고 메일(제목, 본문). 'relay 가 확인한 것'과 '신고자가 보낸 것(확인 못 함)'을 칸으로 나눈다. 운영자용이라 영어 고정.
#[must_use]
pub fn report_mail(m: &ReportMail<'_>) -> (String, String) {
    use std::fmt::Write as _;
    let subject = format!("[lodelai report] {} · {}", m.reason, m.reported);
    let mut t = String::new();
    let relation = if m.facts.relation.is_empty() {
        "none".to_owned()
    } else {
        m.facts
            .relation
            .iter()
            .map(|r| match (*r, m.group) {
                ("same_group", Some(g)) => format!("same_group {g}"),
                (r, _) => r.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let suspended = match (m.facts.suspended, m.suspended_until) {
        (None, _) => "no".to_owned(),
        (Some(_), Some(u)) => format!("yes, until {u}"),
        (Some(_), None) => "yes, until lifted".to_owned(),
    };
    let _ = writeln!(t, "== Checked by the relay ==");
    let _ = writeln!(t, "Server: {}", m.server);
    let _ = writeln!(t, "Received: {}", m.at);
    let _ = writeln!(t, "Reporter: {}", m.reporter);
    let _ = writeln!(t, "Reported: {}", m.reported);
    let _ = writeln!(t, "Relation: {relation}");
    let _ = writeln!(t, "Reported account suspended: {suspended}");
    let _ = writeln!(
        t,
        "Different reporters of this account in the last 30 days: {}",
        m.facts.reporters_30d
    );
    let _ = writeln!(t);
    let _ = writeln!(t, "== Sent by the reporter (not verified) ==");
    let _ = writeln!(t, "Reason: {}", m.reason);
    if let Some(g) = m.group {
        let _ = writeln!(t, "Group: {g}");
    }
    // 신고자가 낸 글은 줄마다 `> ` 로 인용한다 — 줄바꿈으로 'relay 가 확인한 것' 칸을 흉내 내지 못하게.
    let quote = |s: &str| -> String {
        // 줄을 끊는 글자는 모두 가른다(\n 만이 아니라 \r·U+0085·U+2028·U+2029·세로 탭·폼 피드 — 메일 읽기 앱이 줄로 볼 수 있음).
        s.split([
            '\n', '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{0B}', '\u{0C}',
        ])
        .map(|l| format!("> {l}"))
        .collect::<Vec<_>>()
        .join("\n")
    };
    match m.note {
        Some(n) => {
            let _ = writeln!(t, "Note:\n{}", quote(n));
        }
        None => {
            let _ = writeln!(t, "Note: (none)");
        }
    }
    let _ = writeln!(t, "Messages: {}", m.messages.len());
    for (i, msg) in m.messages.iter().enumerate() {
        let _ = writeln!(t);
        let who = match &msg.agent {
            Some(a) => format!("{} (agent {})", msg.author.as_str(), mail_name(a)),
            None => msg.author.as_str().to_owned(),
        };
        let _ = writeln!(
            t,
            "--- {} · {} · {who} · {}",
            i + 1,
            msg.at.as_str(),
            msg.msg_id.as_str()
        );
        let _ = writeln!(t, "{}", quote(&msg.text));
        for f in &msg.files {
            let _ = writeln!(t, "> [file] {} ({} bytes)", mail_name(&f.name), f.size);
        }
    }
    (subject, t)
}

/// #845 §7-27 메일에 넣는 표시 이름: 제어 문자·양방향 제어(U+202A~202E, U+2066~2069)를 빼고 64자까지 — 이름을 뒤집어 다른
/// 주소처럼 보이게 하지 못하게.
#[must_use]
pub fn mail_name(name: &str) -> String {
    name.chars()
        .filter(|c| {
            !c.is_control()
                && !('\u{202A}'..='\u{202E}').contains(c)
                && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .take(64)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Resend(https://api.resend.com/emails)로 보낸다. 키는 환경 변수 `RESEND_API_KEY`(main 이 읽어 넘긴다).
pub struct ResendMailer {
    key: String,
    from: MailFrom,
}

impl ResendMailer {
    #[must_use]
    pub fn new(key: String, from: MailFrom) -> Self {
        Self { key, from }
    }

    async fn post(&self, body: &str) -> std::io::Result<u16> {
        let req = format!(
            "POST /emails HTTP/1.1\r\nHost: {RESEND_HOST}\r\nAuthorization: Bearer {}\r\nUser-Agent: lodelai-relay/{}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.key,
            env!("CARGO_PKG_VERSION"),
            body.len()
        );
        let tcp = tokio::net::TcpStream::connect((RESEND_HOST, 443)).await?;
        let name = rustls::pki_types::ServerName::try_from(RESEND_HOST)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut s = tokio_rustls::TlsConnector::from(tls_config())
            .connect(name, tcp)
            .await?;
        s.write_all(req.as_bytes()).await?;
        // 상태 줄만 본다. close_notify 없이 닫혀도(UnexpectedEof) 받은 만큼으로 본다.
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out)
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP 응답 형식"))
    }
}

/// rustls 클라이언트 설정(한 번 만들어 같이 쓴다).
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring 은 기본 TLS 판을 지원한다")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

impl Mailer for ResendMailer {
    /// `spawn_blocking` 안에서 부른다(http::signup) — 그 스레드에서 런타임으로 요청 하나를 끝까지 기다린다.
    fn send_text(&self, email: &str, subject: &str, text: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "from": self.from.header,
            "to": [email],
            "subject": subject,
            "text": text,
        })
        .to_string();
        let handle = tokio::runtime::Handle::try_current().map_err(|e| e.to_string())?;
        match handle.block_on(tokio::time::timeout(MAIL_TIMEOUT, self.post(&body))) {
            Ok(Ok(status)) if (200..300).contains(&status) => Ok(()),
            // 응답 본문엔 주소가 들어 있을 수 있다 — 상태 코드만 남긴다.
            Ok(Ok(status)) => Err(format!("Resend HTTP {status}")),
            Ok(Err(e)) => Err(format!("Resend 연결: {}", e.kind())),
            Err(_) => Err("Resend 시간 초과".into()),
        }
    }

    fn send_invite(
        &self,
        email: &str,
        subject: &str,
        text: &str,
        unsubscribe: &str,
    ) -> Result<(), String> {
        let body = serde_json::json!({
            "from": self.from.header,
            "to": [email],
            "subject": subject,
            "text": text,
            "headers": {
                "List-Unsubscribe": format!("<{unsubscribe}>"),
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            },
        })
        .to_string();
        let handle = tokio::runtime::Handle::try_current().map_err(|e| e.to_string())?;
        match handle.block_on(tokio::time::timeout(MAIL_TIMEOUT, self.post(&body))) {
            Ok(Ok(status)) if (200..300).contains(&status) => Ok(()),
            Ok(Ok(status)) => Err(format!("Resend HTTP {status}")),
            Ok(Err(e)) => Err(format!("Resend 연결: {}", e.kind())),
            Err(_) => Err("Resend 시간 초과".into()),
        }
    }
}

/// `SMTP_URL` 을 lettre 주소로: `smtps://…`(처음부터 TLS) 그대로, `smtp://…` 는 STARTTLS 필수(`?tls=required`). TLS 를
/// 끄거나 고를 수 있게 하는 값(`tls=none`·`tls=opportunistic`)은 받지 않는다(TLS 필수).
///
/// # Errors
/// 형식이 틀림(값은 싣지 않는다 — 비밀번호가 들었을 수 있다).
pub fn smtp_url(url: &str) -> Result<String, String> {
    const BAD: &str =
        "SMTP_URL 형식: smtps://사용자:비밀번호@호스트[:포트] 또는 STARTTLS smtp://…(TLS 필수)";
    if url.contains("tls=") && !url.contains("tls=required") {
        return Err(BAD.into());
    }
    let url = if url.starts_with("smtps://") {
        url.to_owned()
    } else if url.starts_with("smtp://") {
        if url.contains("tls=required") {
            url.to_owned()
        } else if url.contains('?') {
            format!("{url}&tls=required")
        } else {
            format!("{url}?tls=required")
        }
    } else {
        return Err(BAD.into());
    };
    lettre::SmtpTransport::from_url(&url).map_err(|_| BAD.to_owned())?;
    Ok(url)
}

/// 운영자 SMTP 로 보낸다(묶음 29 §1-3, lettre — rustls·ring·webpki 루트). 본문은 UTF-8 text/plain.
pub struct SmtpMailer {
    transport: lettre::SmtpTransport,
    from: MailFrom,
}

impl SmtpMailer {
    /// `url` 은 [`smtp_url`] 이 돌려준 값.
    ///
    /// # Errors
    /// 주소를 읽지 못함.
    pub fn new(url: &str, from: MailFrom) -> Result<Self, String> {
        let transport = lettre::SmtpTransport::from_url(url)
            .map_err(|_| "SMTP_URL 을 읽지 못했다".to_owned())?
            .timeout(Some(MAIL_TIMEOUT))
            .build();
        Ok(Self { transport, from })
    }

    /// 시험 전용: TLS 없는 로컬 SMTP 서버(`127.0.0.1:port`)로, 인증 없이.
    #[doc(hidden)]
    #[must_use]
    pub fn plaintext_for_test(port: u16, from: MailFrom) -> Self {
        let transport = lettre::SmtpTransport::builder_dangerous("127.0.0.1")
            .port(port)
            .timeout(Some(MAIL_TIMEOUT))
            .build();
        Self { transport, from }
    }
}

impl SmtpMailer {
    /// 시험 전용(실제 SMTP 서버 시험, `scripts/smtp-real-check.sh`): STARTTLS 필수로 `host:port` 에, 인증서는 `root_pem`
    /// 하나만 믿는다(자체 서명 시험 서버).
    ///
    /// # Errors
    /// 인증서·TLS 설정 오류.
    #[doc(hidden)]
    pub fn starttls_for_test(
        host: &str,
        port: u16,
        root_pem: &[u8],
        user: &str,
        pass: &str,
        from: MailFrom,
    ) -> Result<Self, String> {
        use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
        let cert = Certificate::from_pem(root_pem).map_err(|e| e.to_string())?;
        let tls = TlsParameters::builder(host.to_owned())
            .add_root_certificate(cert)
            .build_rustls()
            .map_err(|e| e.to_string())?;
        let transport = lettre::SmtpTransport::builder_dangerous(host)
            .port(port)
            .tls(Tls::Required(tls))
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                user.to_owned(),
                pass.to_owned(),
            ))
            .timeout(Some(MAIL_TIMEOUT))
            .build();
        Ok(Self { transport, from })
    }
}

impl Mailer for SmtpMailer {
    /// `spawn_blocking` 안에서 부른다(http::signup) — lettre 의 막는(blocking) 전송을 그대로 쓴다.
    fn send_text(&self, email: &str, subject: &str, text: &str) -> Result<(), String> {
        self.send_with(email, subject, text, &[])
    }

    fn send_invite(
        &self,
        email: &str,
        subject: &str,
        text: &str,
        unsubscribe: &str,
    ) -> Result<(), String> {
        self.send_with(
            email,
            subject,
            text,
            &[
                ("List-Unsubscribe", format!("<{unsubscribe}>")),
                (
                    "List-Unsubscribe-Post",
                    "List-Unsubscribe=One-Click".to_owned(),
                ),
            ],
        )
    }
}

impl SmtpMailer {
    fn send_with(
        &self,
        email: &str,
        subject: &str,
        text: &str,
        headers: &[(&'static str, String)],
    ) -> Result<(), String> {
        use lettre::Transport as _;
        let from: lettre::message::Mailbox = self
            .from
            .header
            .parse()
            .map_err(|_| "LODELAI_MAIL_FROM 형식".to_owned())?;
        // 이메일은 http 가 검사한 값이지만 lettre 도 다시 본다 — 실패 문구에 주소를 싣지 않는다.
        let to: lettre::message::Mailbox =
            email.parse().map_err(|_| "받는 주소 형식".to_owned())?;
        let mut b = lettre::Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .header(lettre::message::header::ContentType::TEXT_PLAIN);
        for (name, value) in headers {
            b = b.raw_header(lettre::message::header::HeaderValue::new(
                lettre::message::header::HeaderName::new_from_ascii_str(name),
                value.clone(),
            ));
        }
        let msg = b
            .body(text.to_owned())
            .map_err(|_| "메일 만들기".to_owned())?;
        // 서버 응답엔 주소가 들어 있을 수 있다 — 종류만 남긴다.
        self.transport.send(&msg).map(drop).map_err(|e| {
            if e.is_timeout() {
                "SMTP 시간 초과".to_owned()
            } else if e.is_permanent() {
                "SMTP 거절(영구)".to_owned()
            } else if e.is_transient() {
                "SMTP 거절(일시)".to_owned()
            } else {
                "SMTP 연결·TLS".to_owned()
            }
        })
    }
}

/// 개발용 가짜 메일: `<dir>/<이메일>.txt`(0600, 폴더 0700)에 코드 한 줄을 덮어쓴다. 같은 맥의 사람이 파일을 열어 코드를 넣는다.
pub struct FileMailer {
    dir: PathBuf,
}

impl FileMailer {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl Mailer for FileMailer {
    fn is_dev(&self) -> bool {
        true
    }

    fn send_code(&self, email: &str, code: &str, _locale: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        // 이메일은 http 가 검사한 값이다(`/`·제어 문자 없음).
        let path = self.dir.join(format!("{email}.txt"));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut f, format!("{code}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        // 파일 이름이 이메일이라 폴더만 찍는다(로그에 이메일을 두지 않음).
        tracing::info!(dir = %self.dir.display(), "가입 코드(개발용 가짜 메일)를 파일에 썼다");
        Ok(())
    }

    /// 알림 메일은 `<dir>/<이메일>.notices.txt` 에 덧붙인다(제목 한 줄 + 본문 + 빈 줄) — 시험·개발이 읽는다.
    fn send_text(&self, email: &str, subject: &str, text: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let path = self.dir.join(format!("{email}.notices.txt"));
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut f, format!("{subject}\n{text}\n\n").as_bytes())
            .map_err(|e| e.to_string())?;
        tracing::info!(dir = %self.dir.display(), "알림 메일(개발용 가짜 메일)을 파일에 덧붙였다");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_mail_has_link_stop_and_optional_contact() {
        let m = InviteMail {
            kind: "contact",
            from_name: "앤",
            from_email: "ann@ann.io",
            org_name: None,
            members: None,
            link: "https://lodelai.com/i/",
            server: None,
            stop_url: "https://relay.example/v1/mail/stop?t=a.b",
            contact_email: None,
        };
        let (subject, text) = invite_mail(&m);
        assert_eq!(
            subject,
            "앤 님이 lodelai 에서 연락처 요청을 보냈어요 / 앤 sent you a contact request on lodelai"
        );
        assert!(text.contains("https://lodelai.com/i/") && text.contains("mail/stop?t=a.b"));
        assert!(text.contains("앤(ann@ann.io) 님이 이 주소를 넣어서 보낸 메일이에요."));
        assert!(text.contains("앤(ann@ann.io) 님이 lodelai 에서 연락처 요청을 보냈어요."));
        assert!(!text.contains("문의"), "설정이 없으면 문의 줄 없음");
        let (subject, text) = invite_mail(&InviteMail {
            contact_email: Some("help@example.com"),
            kind: "org",
            org_name: Some("루이보스"),
            ..m
        });
        assert_eq!(
            subject,
            "앤 님이 루이보스에 초대했어요 / 앤 invited you to 루이보스"
        );
        assert!(text.contains("문의: help@example.com / Contact: help@example.com"));
        let (_, text) = invite_mail(&InviteMail {
            kind: "group",
            members: Some(4),
            ..m
        });
        assert!(text.contains("멤버 4명인 그룹") && text.contains("with 4 members"));
        assert!(
            !text.contains("서버 주소"),
            "공식 hosted 면 서버 주소 줄 없음"
        );
        let (_, text) = invite_mail(&InviteMail {
            link: "https://lodelai.com/i/#s=relay.example.com",
            server: Some("relay.example.com"),
            ..m
        });
        assert!(text.contains(
            "lodelai 받기: https://lodelai.com/i/#s=relay.example.com\n서버 주소(가입할 때 넣기): relay.example.com\n"
        ));
        assert!(text.contains("\nServer address (enter it when you sign up): relay.example.com\n"));
    }

    #[test]
    fn mail_name_drops_bidi_and_control_and_caps_length() {
        assert_eq!(
            mail_name("고객센터 \u{202E}moc.elppa\u{202C}"),
            "고객센터 moc.elppa"
        );
        assert_eq!(mail_name("a\u{2066}b\u{2069}\n"), "ab");
        assert_eq!(mail_name(&"가".repeat(80)).chars().count(), 64);
    }

    /// #577 ②: --dev-mail 싱크는 알림 메일(recovery 넷)을 `<이메일>.notices.txt` 에 차례로 덧붙인다 — 가입 코드 파일은 따로.
    #[test]
    fn dev_mail_keeps_every_notice() {
        let d = tempfile::tempdir().unwrap();
        let m = FileMailer::new(d.path().join("mail"));
        m.send_code("a@x.test", "123456", "ko").unwrap();
        for s in ["scheduled", "blocked", "canceled", "done"] {
            m.send_text("a@x.test", &format!("lodelai: {s}"), "본문")
                .unwrap();
        }
        let notices = std::fs::read_to_string(d.path().join("mail/a@x.test.notices.txt")).unwrap();
        let subjects: Vec<&str> = notices
            .lines()
            .filter(|l| l.starts_with("lodelai: "))
            .collect();
        assert_eq!(
            subjects,
            [
                "lodelai: scheduled",
                "lodelai: blocked",
                "lodelai: canceled",
                "lodelai: done"
            ]
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("mail/a@x.test.txt")).unwrap(),
            "123456\n"
        );
    }

    fn env<'a>(kv: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            kv.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    /// 묶음 29 §1-3: 빠진 값마다 무엇을 채울지 한 줄 — 비밀 값은 싣지 않는다.
    #[test]
    fn mailer_env_says_what_is_missing() {
        let err = |kv: &[(&str, &str)]| mailer_from_env(env(kv)).err().unwrap();
        assert!(err(&[("RESEND_API_KEY", "k")]).contains("LODELAI_MAIL_FROM"));
        assert!(err(&[("LODELAI_MAIL_FROM", "  ")]).contains("LODELAI_MAIL_FROM"));
        let from = ("LODELAI_MAIL_FROM", "lodelai <noreply@example.org>");
        assert!(err(&[from]).contains("RESEND_API_KEY"));
        assert!(err(&[from, ("LODELAI_MAIL", "smtp")]).contains("SMTP_URL"));
        assert!(err(&[from, ("LODELAI_MAIL", "sendgrid")]).contains("resend|smtp"));
        let secret = "smtp://u:hunter2@mail.example.org?tls=none";
        let e = err(&[from, ("LODELAI_MAIL", "smtp"), ("SMTP_URL", secret)]);
        assert!(!e.contains("hunter2"), "{e}");
        assert!(mailer_from_env(env(&[from, ("RESEND_API_KEY", "k")])).is_ok());
        assert!(mailer_from_env(env(&[
            from,
            ("LODELAI_MAIL", "smtp"),
            ("SMTP_URL", "smtps://u:p%40ss@mail.example.org")
        ]))
        .is_ok());
    }

    /// TLS 필수: smtps 그대로, smtp 는 STARTTLS 필수로, TLS 를 끄는 값·다른 꼴은 거부.
    #[test]
    fn smtp_url_requires_tls() {
        assert_eq!(
            smtp_url("smtps://u:p@mail.example.org").unwrap(),
            "smtps://u:p@mail.example.org"
        );
        assert_eq!(
            smtp_url("smtp://u:p@mail.example.org:587").unwrap(),
            "smtp://u:p@mail.example.org:587?tls=required"
        );
        for bad in [
            "smtp://mail.example.org?tls=none",
            "smtp://mail.example.org?tls=opportunistic",
            "https://mail.example.org",
            "mail.example.org",
        ] {
            assert!(smtp_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mail_from_takes_name_and_address_or_address() {
        let f = MailFrom::parse("lodelai <noreply@example.org>").unwrap();
        assert_eq!(f.addr, "noreply@example.org");
        assert_eq!(
            MailFrom::parse("noreply@example.org").unwrap().addr,
            "noreply@example.org"
        );
        assert_eq!(
            MailFrom::parse("lodelai <noreply@example.org>")
                .unwrap()
                .addr,
            "noreply@example.org"
        );
        for bad in [
            "lodelai",
            "lodelai <noreply>",
            "a@b@c",
            "lodelai <a@b.c>\r\nBcc: x@y.z",
            "lodelai <한@b.c>",
        ] {
            assert!(MailFrom::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn code_mail_is_plain_text_with_code_ttl_and_ignore_line() {
        for (locale, ttl, ignore) in [
            ("ko", "10분", "무시하세요"),
            ("en", "10 minutes", "ignore this email"),
            ("fr", "10 minutes", "ignore this email"),
        ] {
            let (subject, body) = code_mail("123456", locale);
            assert!(subject.contains("123456") && body.contains("123456"));
            assert!(body.contains(ttl) && body.contains(ignore), "{body}");
            for bad in ["http", "://", "www.", "@"] {
                assert!(
                    !subject.contains(bad) && !body.contains(bad),
                    "{bad}: {body}"
                );
            }
        }
    }
}
