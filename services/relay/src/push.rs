//! 모바일 푸시 보내기(APNs·FCM, 모바일 검증 S1). 지금은 손 발송 명령(`lodelai-relay push-send`)이 쓰고, 뒤에 relay 보내기
//! 경로(접속 안 한 기기 앞 보관)가 그대로 부른다.
//!
//! - **APNs**: `.p8` 키(ES256 JWT, 팀 ID·키 ID) + HTTP/2. `aps.mutable-content` 로 iOS 알림 확장(NSE)이 깨어 암호문을 푼다.
//!   알림 글은 relay 가 정하지 않는다 — `loc-key` 로 앱의 문자열 표가 고른다.
//! - **FCM**: HTTP v1 + 서비스 계정 OAuth(RS256 JWT → access token). `notification` 없이 `data` 만 보내 Android 서비스가 받는다.
//! - 푸시에는 암호문 또는 빈 깨우기, 또는 알림 종류(kind)만 싣는다. 평문 제목·이름·본문은 없다. 로그에는 결과·상태·이유와 토큰 앞 6자만 남긴다.
//! - 시계는 부르는 쪽이 `now_ms` 로 넘긴다(relay 의 Effects 시계와 같은 값).

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};

/// APNs·FCM 둘 다 페이로드 상한 4KB. 넘으면 보내지 않고 [`PushError::TooLarge`] — 부르는 쪽이 빈 깨우기로 바꾼다.
pub const MAX_PAYLOAD: usize = 4096;
/// APNs `apns-collapse-id` 상한(바이트).
pub const MAX_COLLAPSE_ID: usize = 64;
/// APNs 토큰(JWT)은 20분~60분 사이에 새로 만든다(더 자주면 `TooManyProviderTokenUpdates`, 60분 넘으면 `ExpiredProviderToken`).
const APNS_JWT_REUSE_MS: i64 = 50 * 60 * 1000;
/// 앱 문자열 표에서 알림 글을 고르는 키(iOS `Localizable.strings`). 프론트가 ko·en 문구를 둔다.
pub const APNS_LOC_KEY: &str = "PUSH_NEW_MESSAGE";
/// '누가 이 기기를 끊으려 함' 알림의 제목·본문 키(iOS `Localizable.strings`). i18n 키 이름 그대로다 — 앱 문자열 표를
/// i18n 에서 뽑을 때 바꿔 적을 것이 없다. 본문은 인자 없는 `push_body` 다(`notify_body` 는 `{when}` 이 있어 못 쓴다).
pub const RECOVER_AGAINST_TITLE_KEY: &str = "recovery.against.title";
pub const RECOVER_AGAINST_BODY_KEY: &str = "recovery.against.push_body";
/// '내 맥에 승인 기다림' 알림(#870)의 제목·본문 키 — 에이전트 이름·내용 없는 고정 문구(문구는 앱 문자열 표).
pub const OWN_ALERT_TITLE_KEY: &str = "own.alert.title";
pub const OWN_ALERT_BODY_KEY: &str = "own.alert.push_body";
/// '사용량 한도 가까움' 알림(#890)의 본문 키 — 에이전트 이름·창·숫자 없는 고정 문구(숫자 든 문구는 붙어 있을 때 앱 로컬 알림).
/// 제목은 카드 알림과 같은 [`OWN_ALERT_TITLE_KEY`].
pub const OWN_USAGE_BODY_KEY: &str = "own.usage.near_push";
/// '새 초대' 알림(#845 §7-39)의 키 하나 — 보낸 사람·그룹·조직 이름 없는 고정 문구(인자 없음). 본문 키는 없다(새 메시지 알림과
/// 같은 꼴로 `loc-key` 하나).
pub const INVITE_TITLE_KEY: &str = "invite.push_title";
/// 초대 알림의 APNs `apns-collapse-id` — 안 읽은 초대 알림이 쌓이지 않고 하나로 바뀐다.
pub const INVITE_COLLAPSE_ID: &str = "invite";
/// 한 요청 끝까지(연결·TLS·응답) 기다리는 상한.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// 응답 본문 상한(오류 JSON 만 읽는다).
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Apns,
    Fcm,
}

impl Platform {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "apns" => Some(Self::Apns),
            "fcm" => Some(Self::Fcm),
            _ => None,
        }
    }
}

/// APNs 서버. 개발 서명 앱의 토큰은 sandbox 에서만 맞는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnv {
    Sandbox,
    Prod,
}

impl ApnsEnv {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sandbox" => Some(Self::Sandbox),
            "prod" => Some(Self::Prod),
            _ => None,
        }
    }

    #[must_use]
    pub fn host(self) -> &'static str {
        match self {
            Self::Sandbox => "api.sandbox.push.apple.com",
            Self::Prod => "api.push.apple.com",
        }
    }
}

/// 보낼 푸시 하나. 내용은 암호문(있으면)과 대화 해시뿐이다.
#[derive(Debug, Clone, Default)]
pub struct Push {
    /// 기기 토큰(APNs 16진, FCM 등록 토큰).
    pub token: String,
    /// 대화 해시 — APNs 는 `apns-collapse-id`·`thread-id` 로 같은 대화의 알림을 묶는다. FCM 은 data `conv` 로만 싣고
    /// 접지 않는다(앱이 알림 tag 로 하나로 바꿔 끼운다).
    pub conv: Option<String>,
    /// 기기 push 키로 감싼 본문(base64, [`seal`]) — 앱·확장이 풀어 MLS 응용 메시지와 msg_id 를 얻는다. 없으면 빈 깨우기
    /// (앱·확장이 "새 메시지" 일반 문구). 같은 메시지도 토큰마다 바이트가 다르다.
    pub sealed: Option<String>,
    /// 메시지가 아닌 알림의 종류. 있으면 conv·sealed 없이 kind 만 싣는다(앱이 그 kind 의 문자열로 띄운다).
    pub kind: Option<PushKind>,
    /// #882 실시간 현황(숫자만). 있으면 iOS 는 Live Activity 푸시(topic `.push-type.liveactivity`), FCM 은 kind own_live 데이터.
    pub live: Option<LivePush>,
}

/// #882 Live Activity 이벤트.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveEvent {
    Update,
    End,
    /// push-to-start(iOS 17.2+) — `token` 이 그 기기의 start 토큰.
    Start,
}

impl LiveEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::End => "end",
            Self::Start => "start",
        }
    }
}

/// #882 현황 푸시 하나(ADR 0014 — 숫자·시각뿐, 이름·글 없음).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePush {
    pub event: LiveEvent,
    /// 높음(apns-priority 10·FCM high): 기다림이 늘 때·끝남·맥 끊김.
    pub high: bool,
    pub state: crate::live::Agg,
    /// 보내는 때(ms).
    pub now_ms: i64,
    /// end 의 dismissal-date(ms).
    pub dismissal_ms: Option<i64>,
}

/// Live Activity 앱 쪽 ActivityAttributes 형 이름(모바일과 같이 정함).
pub const LIVE_ATTRIBUTES_TYPE: &str = "LodelaiLiveAttributes";
/// 낡음 표시까지(갱신마다 밂).
pub const LIVE_STALE_MS: i64 = 15 * 60_000;
/// push-to-start 알림 본문 키(인자 셋 busy·approval·question).
pub const LIVE_SUMMARY_KEY: &str = "live.summary";

fn secs(ms: i64) -> i64 {
    ms.div_euclid(1000)
}

/// iOS content-state(앱 `LodelaiLiveAttributes.ContentState` — 시각은 모두 초 Unix 정수).
fn live_content(a: &crate::live::Agg) -> Value {
    let mut v = json!({
        "busy": a.busy, "approval": a.approval, "question": a.question,
        "runStart": secs(a.run_ms), "macReachable": a.mac,
    });
    if let Some(o) = a.oldest_ms {
        v["oldestBusyStart"] = json!(secs(o));
    }
    if let Some(f) = a.frozen_ms {
        v["frozenAt"] = json!(secs(f));
    }
    v
}

fn live_apns_payload(l: &LivePush) -> Vec<u8> {
    let mut aps = json!({
        "timestamp": secs(l.now_ms),
        "event": l.event.as_str(),
        "content-state": live_content(&l.state),
        "stale-date": secs(l.now_ms + LIVE_STALE_MS),
    });
    if let Some(d) = l.dismissal_ms {
        aps["dismissal-date"] = json!(secs(d));
    }
    if l.event == LiveEvent::Start {
        aps["attributes-type"] = json!(LIVE_ATTRIBUTES_TYPE);
        aps["attributes"] = json!({});
        // 소리 없이(sound 없음) — push-to-start 는 alert 가 있어야 활동이 뜬다.
        aps["alert"] = json!({
            "title": {"loc-key": OWN_ALERT_TITLE_KEY},
            "body": {"loc-key": LIVE_SUMMARY_KEY, "loc-args": [
                l.state.busy.to_string(), l.state.approval.to_string(), l.state.question.to_string()]},
        });
    }
    serde_json::to_vec(&json!({"aps": aps})).unwrap_or_default()
}

/// 메시지가 아닌 알림의 종류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushKind {
    /// 새 기기가 메일 확인으로 이 기기를 끊으려 함(걸기가 받아들여질 때 한 번).
    RecoverAgainst,
    /// 내 맥에 사람 손을 기다리는 카드가 생김(#870 own_alert — 기기마다 1분에 1번).
    OwnAlert,
    /// 내 에이전트 사용량이 한도에 가까움(#890 own_alert kind usage — 기기마다 1분에 1번, 카드와 따로).
    OwnUsage,
    /// 받는 쪽 초대 카드가 생김(#845 §7-39 — 기기마다 1분에 1번). `id` 는 그 카드 id(무작위 ULID) — 앱이 그 카드를 여는 데만 쓴다.
    Invite { sub: InviteSub, id: String },
}

/// #845 §7-55 사람이 끌 수 있는 알림 갈래(`push.register.off`). relay 가 이미 아는 것(머리 kind·group, 푸시 kind)으로만 가른다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// 1:1 대화(머리 kind chat·reaction, group 없음).
    Chat,
    /// 그룹(머리 group 있음 — chat·request 모두).
    Group,
    /// 에이전트 요청·답·거절(그룹 아님)과 own_alert.
    Agents,
    /// 초대 카드(contact·group·org).
    Invite,
}

impl Category {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Group => "group",
            Self::Agents => "agents",
            Self::Invite => "invite",
        }
    }

    /// 보관된 메시지 머리의 갈래. 사람이 끌 수 없는 것(system 등)은 `None` — 늘 보낸다.
    #[must_use]
    pub fn of_header(h: &crate::frames::Header) -> Option<Self> {
        use crate::frames::Kind;
        if h.group.is_some() {
            return Some(Self::Group);
        }
        match h.kind {
            Kind::Chat | Kind::Reaction => Some(Self::Chat),
            Kind::Request | Kind::Reply | Kind::Rejected => Some(Self::Agents),
            _ => None,
        }
    }

    /// §7-56 음소거로 거르는 대화 주소 — chat·reaction 만(request·reply·승인 등은 음소거와 상관없이 감). 그룹이면 그룹 주소,
    /// 아니면 보낸 주소(사람·세션).
    #[must_use]
    pub fn mute_conv(h: &crate::frames::Header) -> Option<String> {
        use crate::frames::Kind;
        if !matches!(h.kind, Kind::Chat | Kind::Reaction) {
            return None;
        }
        Some(h.group.as_ref().unwrap_or(&h.from).conv_key())
    }

    /// 이 기기가 이 갈래를 껐나(`push_tokens.off`, 쉼표로 이음).
    #[must_use]
    pub fn muted_in(cat: Option<Self>, off: &str) -> bool {
        cat.is_some_and(|c| off.split(',').any(|x| x == c.as_str()))
    }
}

/// 초대 카드의 갈래.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteSub {
    Contact,
    Group,
    Org,
}

impl InviteSub {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contact => "contact",
            Self::Group => "group",
            Self::Org => "org",
        }
    }
}

impl PushKind {
    /// §7-55 끌 수 있는 갈래 — recover_against 는 끌 수 없다(내 기기를 끊으려는 시도는 늘 알림).
    #[must_use]
    pub fn category(&self) -> Option<Category> {
        match self {
            Self::RecoverAgainst => None,
            Self::OwnAlert | Self::OwnUsage => Some(Category::Agents),
            Self::Invite { .. } => Some(Category::Invite),
        }
    }

    /// 페이로드의 `kind` 값.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecoverAgainst => "recovery_against",
            Self::OwnAlert => "own_alert",
            Self::OwnUsage => "own_usage",
            Self::Invite { .. } => "invite",
        }
    }

    /// 페이로드에 `kind` 와 함께 싣는 칸(초대의 sub·id).
    fn fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Invite { sub, id } => vec![("sub", sub.as_str().to_owned()), ("id", id.clone())],
            _ => Vec::new(),
        }
    }
}

/// 보낸 결과. 뒤의 보내기 경로와 `/status` 셈이 이 갈래를 그대로 쓴다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 받음(APNs `apns-id`, FCM 메시지 이름).
    Sent { id: Option<String> },
    /// 토큰이 더는 맞지 않음 — 지운다(APNs 410 `Unregistered`, FCM `UNREGISTERED`).
    TokenGone { reason: String },
    /// 이 요청이 틀림 — 토큰은 지우지 않는다(sandbox·prod 섞임, 주제 틀림, 형식).
    Rejected { status: u16, reason: String },
    /// 운영자 자격 문제(키·서비스 계정) — 토큰 탓이 아니므로 지우지 않고 운영자에게 알린다.
    AuthFailed { status: u16, reason: String },
    /// 나중에 다시(429·5xx). `after_s` 는 `Retry-After`.
    Retry {
        status: u16,
        after_s: Option<u64>,
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("페이로드가 {0}바이트 — 상한 {MAX_PAYLOAD}")]
    TooLarge(usize),
    #[error("collapse 값이 {0}바이트 — 상한 {MAX_COLLAPSE_ID}")]
    CollapseTooLong(usize),
    #[error("자격: {0}")]
    Creds(String),
    #[error("연결: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0} 자격이 없다")]
    NotConfigured(&'static str),
}

/// HTTPS POST 한 번(요청·응답). 실제는 [`H2Transport`], 시험은 가짜.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Transport: Send + Sync {
    fn post(&self, req: Request) -> BoxFuture<'_, std::io::Result<Response>>;
}

/// 토큰 앞 6자(로그·출력용). 전체 토큰은 찍지 않는다.
#[must_use]
pub fn token_prefix(token: &str) -> String {
    let p: String = token.chars().take(6).collect();
    format!("{p}…")
}

fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// JWT 머리·몸을 붙인 서명 입력(`b64url(header).b64url(claims)`).
fn jwt_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    )
}

/// PKCS#8 PEM 머리 줄의 꼬리표. 머리 줄 글자를 소스에 통째로 두지 않는다 — 공개 트리 비밀 점검·gitleaks 가 비밀 꼴로 본다.
const PEM_PKCS8_LABEL: &str = "PRIVATE KEY";

/// PKCS#8 PEM(머리 줄 꼬리표 [`PEM_PKCS8_LABEL`])에서 DER 을 꺼낸다. `.p8` 과 서비스 계정 `private_key` 가 이 꼴이다.
fn pem_pkcs8(pem: &str) -> Result<Vec<u8>, PushError> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let head = format!("-----BEGIN {PEM_PKCS8_LABEL}-----");
    if !pem.contains(&head) || body.is_empty() {
        return Err(PushError::Creds("PKCS#8 PEM 이 아니다".into()));
    }
    STANDARD
        .decode(body)
        .map_err(|_| PushError::Creds("PEM 본문이 base64 가 아니다".into()))
}

/// 비밀 파일을 읽는다: 심볼릭 링크 거절(O_NOFOLLOW), 일반 파일만, 그룹·다른 사용자 권한이 있으면 거절(0600·0400).
/// 경로는 오류에 써도 되지만 내용은 어디에도 쓰지 않는다.
///
/// # Errors
/// 열기 실패·권한·종류.
pub fn read_secret_file(path: &Path) -> Result<String, PushError> {
    use rustix::fs::{FileType, Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| PushError::Creds(format!("{} 를 못 엶: {e}", path.display())))?;
    let st =
        rustix::fs::fstat(&fd).map_err(|e| PushError::Creds(format!("{}: {e}", path.display())))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(PushError::Creds(format!(
            "{} 는 일반 파일이 아니다",
            path.display()
        )));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(PushError::Creds(format!(
            "{} 권한이 {:o} — 0600 으로(그룹·다른 사용자 권한 없이)",
            path.display(),
            st.st_mode & 0o777
        )));
    }
    let mut s = String::new();
    std::io::Read::read_to_string(&mut std::fs::File::from(fd), &mut s)
        .map_err(|e| PushError::Creds(format!("{}: {e}", path.display())))?;
    Ok(s)
}

// ───────────────────────────── 감싸기·대화 태그 ─────────────────────────────

/// 감싼 본문(base64 글자 수)의 크기 칸. 크기로 메시지를 묶지 못하게 이 중 하나로 채운다. 가장 큰 칸도 APNs·FCM 4KB 안에
/// 대화 태그와 같이 든다.
pub const SEAL_BUCKETS: [usize; 4] = [512, 1024, 2048, 3072];
const SEAL_AAD: &[u8] = b"lodelai-push-v1";
const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// 기기 push 키(32B)로 (msg_id, MLS 응용 메시지 암호문)을 감싼다. 넘치면 `None` — 부르는 쪽은 빈 깨우기로 보낸다.
///
/// 꼴(v1): `base64(nonce 12B ‖ ChaCha20-Poly1305(key, nonce, aad = "lodelai-push-v1", plain))`,
/// `plain = 1 ‖ id_len(u8) ‖ id ‖ msg_len(u16 BE) ‖ msg ‖ 0…` 이고, 결과 base64 글자 수가 [`SEAL_BUCKETS`] 중 맞는 가장 작은
/// 칸이 되게 0 으로 채운다. base64 는 표준(패딩 있음)이다.
#[must_use]
pub fn seal(key: &[u8; 32], nonce: [u8; NONCE_LEN], msg_id: &str, msg: &[u8]) -> Option<String> {
    let id_len = u8::try_from(msg_id.len()).ok()?;
    let msg_len = u16::try_from(msg.len()).ok()?;
    let need = 1 + 1 + msg_id.len() + 2 + msg.len();
    // base64 글자 수 = 감싼 바이트 × 4/3(3 의 배수라 패딩 없음).
    let bucket = SEAL_BUCKETS
        .iter()
        .find(|b| (*b / 4 * 3).saturating_sub(NONCE_LEN + TAG_LEN) >= need)?;
    let plain_len = bucket / 4 * 3 - NONCE_LEN - TAG_LEN;
    let mut buf = Vec::with_capacity(plain_len + TAG_LEN);
    buf.push(SEAL_VERSION);
    buf.push(id_len);
    buf.extend_from_slice(msg_id.as_bytes());
    buf.extend_from_slice(&msg_len.to_be_bytes());
    buf.extend_from_slice(msg);
    buf.resize(plain_len, 0);
    let k = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, key).ok()?,
    );
    k.seal_in_place_append_tag(
        ring::aead::Nonce::assume_unique_for_key(nonce),
        ring::aead::Aad::from(SEAL_AAD),
        &mut buf,
    )
    .ok()?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buf);
    Some(STANDARD.encode(out))
}

/// [`seal`] 을 푼다(앱·확장 쪽 꼴의 기준, 시험용). (msg_id, 암호문).
#[must_use]
pub fn open(key: &[u8; 32], sealed: &str) -> Option<(String, Vec<u8>)> {
    let raw = STANDARD.decode(sealed).ok()?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (n, rest) = raw.split_at(NONCE_LEN);
    let mut buf = rest.to_vec();
    let k = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, key).ok()?,
    );
    let plain = k
        .open_in_place(
            ring::aead::Nonce::try_assume_unique_for_key(n).ok()?,
            ring::aead::Aad::from(SEAL_AAD),
            &mut buf,
        )
        .ok()?;
    if plain.first() != Some(&SEAL_VERSION) {
        return None;
    }
    let id_len = usize::from(*plain.get(1)?);
    let id = std::str::from_utf8(plain.get(2..2 + id_len)?)
        .ok()?
        .to_owned();
    let at = 2 + id_len;
    let msg_len = usize::from(u16::from_be_bytes([*plain.get(at)?, *plain.get(at + 1)?]));
    let msg = plain.get(at + 2..at + 2 + msg_len)?.to_vec();
    Some((id, msg))
}

/// 애플·구글에 나가는 대화 묶음 값(collapse·thread-id·`lodelai.conv`): HMAC-SHA256(키 = 토큰 행 salt 16B, 메시지 = MLS
/// group_id 문자열의 UTF-8 바이트) 앞 16바이트 소문자 hex. 기기마다 salt 가 달라 같은 대화도 값이 다르다.
#[must_use]
pub fn conv_tag(salt: &[u8], group_id: &str) -> String {
    use hmac::Mac as _;
    let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(salt)
        .expect("HMAC 는 어떤 길이의 키도 받는다");
    m.update(group_id.as_bytes());
    m.finalize().into_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ───────────────────────────── APNs ─────────────────────────────

/// APNs 자격(.p8 키). 토큰(JWT)은 50분 동안 다시 쓴다.
pub struct Apns {
    team_id: String,
    key_id: String,
    /// 앱 번들 ID(`apns-topic`).
    topic: String,
    key: ring::signature::EcdsaKeyPair,
    cached: Mutex<Option<(i64, String)>>,
}

impl std::fmt::Debug for Apns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Apns")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("topic", &self.topic)
            .finish_non_exhaustive()
    }
}

impl Apns {
    /// # Errors
    /// 키가 P-256 PKCS#8 이 아니거나 ID 가 비었다.
    pub fn new(team_id: &str, key_id: &str, topic: &str, p8_pem: &str) -> Result<Self, PushError> {
        Self::from_der(team_id, key_id, topic, &pem_pkcs8(p8_pem)?)
    }

    #[doc(hidden)]
    pub fn from_der(
        team_id: &str,
        key_id: &str,
        topic: &str,
        der: &[u8],
    ) -> Result<Self, PushError> {
        for (name, v) in [("팀 ID", team_id), ("키 ID", key_id), ("topic", topic)] {
            if v.trim().is_empty() || v.contains(char::is_whitespace) {
                return Err(PushError::Creds(format!(
                    "APNs {name} 이 비었거나 공백이 있다"
                )));
            }
        }
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            der,
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| PushError::Creds("APNs 키가 P-256 PKCS#8 이 아니다".into()))?;
        Ok(Self {
            team_id: team_id.to_owned(),
            key_id: key_id.to_owned(),
            topic: topic.to_owned(),
            key,
            cached: Mutex::new(None),
        })
    }

    /// 제공자 토큰(ES256 JWT). 만든 지 50분 안이면 같은 것.
    ///
    /// # Errors
    /// 서명 실패.
    pub fn jwt(&self, now_ms: i64) -> Result<String, PushError> {
        let mut cached = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, t)) = cached.as_ref() {
            if now_ms >= *at && now_ms - at < APNS_JWT_REUSE_MS {
                return Ok(t.clone());
            }
        }
        let input = jwt_input(
            &json!({"alg": "ES256", "kid": self.key_id}),
            &json!({"iss": self.team_id, "iat": now_ms / 1000}),
        );
        let sig = self
            .key
            .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
            .map_err(|_| PushError::Creds("APNs JWT 서명 실패".into()))?;
        let t = format!("{input}.{}", b64url(sig.as_ref()));
        *cached = Some((now_ms, t.clone()));
        Ok(t)
    }

    /// 받아 둔 JWT 를 버린다(APNs 403 `ExpiredProviderToken` — 다음 요청이 새로 서명한다).
    pub fn forget_jwt(&self) {
        *self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// 요청 하나를 만든다(보내지 않는다).
    ///
    /// # Errors
    /// 페이로드·collapse 상한, 서명.
    pub fn request(&self, env: ApnsEnv, push: &Push, now_ms: i64) -> Result<Request, PushError> {
        if let Some(l) = &push.live {
            return Ok(Request {
                host: env.host().into(),
                path: format!("/3/device/{}", push.token),
                headers: vec![
                    (
                        "authorization".into(),
                        format!("bearer {}", self.jwt(now_ms)?),
                    ),
                    (
                        "apns-topic".into(),
                        format!("{}.push-type.liveactivity", self.topic),
                    ),
                    ("apns-push-type".into(), "liveactivity".into()),
                    (
                        "apns-priority".into(),
                        if l.high { "10" } else { "5" }.into(),
                    ),
                    ("content-type".into(), "application/json".into()),
                ],
                body: live_apns_payload(l),
            });
        }
        let body = apns_payload(push)?;
        let mut headers = vec![
            (
                "authorization".into(),
                format!("bearer {}", self.jwt(now_ms)?),
            ),
            ("apns-topic".into(), self.topic.clone()),
            ("apns-push-type".into(), "alert".into()),
            ("apns-priority".into(), "10".into()),
            ("content-type".into(), "application/json".into()),
        ];
        if let Some(c) = &push.conv {
            if c.len() > MAX_COLLAPSE_ID {
                return Err(PushError::CollapseTooLong(c.len()));
            }
            headers.push(("apns-collapse-id".into(), c.clone()));
        } else if matches!(push.kind, Some(PushKind::Invite { .. })) {
            headers.push(("apns-collapse-id".into(), INVITE_COLLAPSE_ID.into()));
        }
        Ok(Request {
            host: env.host().into(),
            path: format!("/3/device/{}", push.token),
            headers,
            body,
        })
    }
}

/// APNs 페이로드. 알림 글은 앱 문자열 표(`loc-key`)가 정하고, `mutable-content` 로 NSE 가 깨어 암호문을 풀어 바꾼다.
/// 우리 칸은 `lodelai.conv`(대화 해시)·`lodelai.msg`(암호문 base64)뿐이다.
///
/// # Errors
/// 4KB 넘음.
pub fn apns_payload(push: &Push) -> Result<Vec<u8>, PushError> {
    if let Some(kind) = &push.kind {
        // NSE 를 깨우지 않는다(mutable-content 없음) — 잠김·확장 실패여도 시스템이 앱 문자열 표로 바로 띄운다.
        let alert = match kind {
            PushKind::RecoverAgainst => {
                json!({"title-loc-key": RECOVER_AGAINST_TITLE_KEY, "loc-key": RECOVER_AGAINST_BODY_KEY})
            }
            PushKind::OwnAlert => {
                json!({"title-loc-key": OWN_ALERT_TITLE_KEY, "loc-key": OWN_ALERT_BODY_KEY})
            }
            PushKind::OwnUsage => {
                json!({"title-loc-key": OWN_ALERT_TITLE_KEY, "loc-key": OWN_USAGE_BODY_KEY})
            }
            PushKind::Invite { .. } => json!({"loc-key": INVITE_TITLE_KEY}),
        };
        let mut ours = serde_json::Map::new();
        ours.insert("kind".into(), json!(kind.as_str()));
        for (k, v) in kind.fields() {
            ours.insert(k.into(), json!(v));
        }
        return Ok(serde_json::to_vec(&json!({
            "aps": {"alert": alert, "sound": "default"},
            "lodelai": ours,
        }))
        .unwrap_or_default());
    }
    let mut aps = json!({
        "alert": {"loc-key": APNS_LOC_KEY},
        "mutable-content": 1,
        "sound": "default",
    });
    let mut ours = serde_json::Map::new();
    if let Some(c) = &push.conv {
        aps["thread-id"] = json!(c);
        ours.insert("conv".into(), json!(c));
    }
    if let Some(b) = &push.sealed {
        ours.insert("p".into(), json!(b));
    }
    let body = serde_json::to_vec(&json!({"aps": aps, "lodelai": ours})).unwrap_or_default();
    if body.len() > MAX_PAYLOAD {
        return Err(PushError::TooLarge(body.len()));
    }
    Ok(body)
}

/// APNs 응답 갈래(<https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns>).
#[must_use]
pub fn classify_apns(r: &Response) -> Outcome {
    let reason = serde_json::from_slice::<Value>(&r.body)
        .ok()
        .and_then(|v| v["reason"].as_str().map(str::to_owned))
        .unwrap_or_default();
    match r.status {
        200 => Outcome::Sent {
            id: r.header("apns-id").map(str::to_owned),
        },
        410 => Outcome::TokenGone { reason },
        403 => Outcome::AuthFailed {
            status: 403,
            reason,
        },
        429 | 500..=599 => Outcome::Retry {
            status: r.status,
            after_s: retry_after(r),
            reason,
        },
        status => Outcome::Rejected { status, reason },
    }
}

fn retry_after(r: &Response) -> Option<u64> {
    r.header("retry-after").and_then(|v| v.trim().parse().ok())
}

// ───────────────────────────── FCM ─────────────────────────────

/// 서명만 따로(시험은 가짜, 실제는 서비스 계정 RSA 키).
pub trait Rs256Signer: Send + Sync {
    /// # Errors
    /// 서명 실패.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PushError>;
}

struct RingRsa(ring::signature::RsaKeyPair);

impl Rs256Signer for RingRsa {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PushError> {
        let mut sig = vec![0u8; self.0.public().modulus_len()];
        self.0
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                msg,
                &mut sig,
            )
            .map_err(|_| PushError::Creds("FCM 서비스 계정 서명 실패".into()))?;
        Ok(sig)
    }
}

/// FCM 자격(서비스 계정 JSON). access token 은 만료 60초 전까지 다시 쓴다.
pub struct Fcm {
    project_id: String,
    client_email: String,
    /// OAuth 토큰 주소(`https://oauth2.googleapis.com/token`). https 만.
    token_host: String,
    token_path: String,
    signer: Box<dyn Rs256Signer>,
    cached: Mutex<Option<(String, i64)>>,
}

impl std::fmt::Debug for Fcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fcm")
            .field("project_id", &self.project_id)
            .field("client_email", &self.client_email)
            .finish_non_exhaustive()
    }
}

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_HOST: &str = "fcm.googleapis.com";

impl Fcm {
    /// 서비스 계정 JSON 에서.
    ///
    /// # Errors
    /// 칸이 빠졌거나 키가 RSA PKCS#8 이 아니다.
    pub fn from_service_account(json_text: &str) -> Result<Self, PushError> {
        let v: Value = serde_json::from_str(json_text)
            .map_err(|_| PushError::Creds("서비스 계정 파일이 JSON 이 아니다".into()))?;
        let field = |k: &str| {
            v[k].as_str()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| PushError::Creds(format!("서비스 계정 JSON 에 {k} 가 없다")))
        };
        let der = pem_pkcs8(&field("private_key")?)?;
        let key = ring::signature::RsaKeyPair::from_pkcs8(&der)
            .map_err(|_| PushError::Creds("서비스 계정 키가 RSA PKCS#8 이 아니다".into()))?;
        Self::with_signer(
            &field("project_id")?,
            &field("client_email")?,
            &field("token_uri")?,
            Box::new(RingRsa(key)),
        )
    }

    /// # Errors
    /// 토큰 주소가 https 가 아니다.
    pub fn with_signer(
        project_id: &str,
        client_email: &str,
        token_uri: &str,
        signer: Box<dyn Rs256Signer>,
    ) -> Result<Self, PushError> {
        let rest = token_uri
            .strip_prefix("https://")
            .ok_or_else(|| PushError::Creds("token_uri 는 https:// 주소".into()))?;
        let (host, path) = rest
            .split_once('/')
            .map_or((rest, "/".to_owned()), |(h, p)| (h, format!("/{p}")));
        if host.is_empty() || project_id.contains('/') {
            return Err(PushError::Creds("token_uri·project_id 형식".into()));
        }
        Ok(Self {
            project_id: project_id.to_owned(),
            client_email: client_email.to_owned(),
            token_host: host.to_owned(),
            token_path: path,
            signer,
            cached: Mutex::new(None),
        })
    }

    /// OAuth 토큰 교환 요청(RS256 JWT 단언, 1시간).
    ///
    /// # Errors
    /// 서명.
    pub fn token_request(&self, now_ms: i64) -> Result<Request, PushError> {
        let iat = now_ms / 1000;
        let input = jwt_input(
            &json!({"alg": "RS256", "typ": "JWT"}),
            &json!({
                "iss": self.client_email,
                "scope": FCM_SCOPE,
                "aud": format!("https://{}{}", self.token_host, self.token_path),
                "iat": iat,
                "exp": iat + 3600,
            }),
        );
        let sig = self.signer.sign(input.as_bytes())?;
        let assertion = format!("{input}.{}", b64url(&sig));
        Ok(Request {
            host: self.token_host.clone(),
            path: self.token_path.clone(),
            headers: vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
            )
            .into_bytes(),
        })
    }

    /// access token. 받아 둔 것이 만료 60초 전이면 그대로.
    ///
    /// # Errors
    /// 교환 실패(상태·이유를 담음).
    pub async fn access_token(&self, t: &dyn Transport, now_ms: i64) -> Result<String, Outcome> {
        let reuse = self
            .cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|(_, exp)| now_ms < *exp)
            .map(|(tok, _)| tok.clone());
        if let Some(tok) = reuse {
            return Ok(tok);
        }
        let req = self
            .token_request(now_ms)
            .map_err(|e| Outcome::AuthFailed {
                status: 0,
                reason: e.to_string(),
            })?;
        let r = t.post(req).await.map_err(|e| Outcome::Retry {
            status: 0,
            after_s: None,
            reason: format!("OAuth 연결: {e}"),
        })?;
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        match (
            r.status,
            v["access_token"].as_str(),
            v["expires_in"].as_i64(),
        ) {
            (200, Some(tok), exp) => {
                let exp_ms = now_ms + (exp.unwrap_or(3600) - 60).max(0) * 1000;
                *self
                    .cached
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some((tok.to_owned(), exp_ms));
                Ok(tok.to_owned())
            }
            (s @ (429 | 500..=599), ..) => Err(Outcome::Retry {
                status: s,
                after_s: retry_after(&r),
                reason: "OAuth".into(),
            }),
            (s, ..) => Err(Outcome::AuthFailed {
                status: s,
                reason: v["error"].as_str().unwrap_or("OAuth").to_owned(),
            }),
        }
    }

    /// 보내기 요청(보내지 않는다).
    ///
    /// # Errors
    /// 4KB 넘음.
    pub fn request(&self, push: &Push, access_token: &str) -> Result<Request, PushError> {
        Ok(Request {
            host: FCM_HOST.into(),
            path: format!("/v1/projects/{}/messages:send", self.project_id),
            headers: vec![
                ("authorization".into(), format!("Bearer {access_token}")),
                ("content-type".into(), "application/json".into()),
            ],
            body: fcm_body(push)?,
        })
    }
}

/// FCM 본문: high priority **데이터 메시지**(`notification` 없음 — Android 서비스가 받아 풀고 로컬 알림을 낸다).
/// 데이터 상한 4KB 는 `data` 칸 기준이다.
///
/// # Errors
/// 4KB 넘음.
pub fn fcm_body(push: &Push) -> Result<Vec<u8>, PushError> {
    if let Some(l) = &push.live {
        // #882 현황: 숫자·시각(ms)뿐. 높음은 기다림이 늘 때·끝남·맥 끊김만(그 밖은 normal — 도즈 중엔 늦게 옴).
        let a = &l.state;
        let mut data = serde_json::Map::new();
        data.insert("kind".into(), json!("own_live"));
        data.insert("busy".into(), json!(a.busy.to_string()));
        data.insert("approval".into(), json!(a.approval.to_string()));
        data.insert("question".into(), json!(a.question.to_string()));
        data.insert("run".into(), json!(a.run_ms.to_string()));
        data.insert("mac".into(), json!(if a.mac { "1" } else { "0" }));
        if let Some(o) = a.oldest_ms {
            data.insert("oldest".into(), json!(o.to_string()));
        }
        if let Some(f) = a.frozen_ms {
            data.insert("frozen".into(), json!(f.to_string()));
        }
        return Ok(serde_json::to_vec(&json!({"message": {
            "token": push.token,
            "android": {"priority": if l.high { "high" } else { "normal" }},
            "data": data,
        }}))
        .unwrap_or_default());
    }
    let mut data = serde_json::Map::new();
    if let Some(k) = &push.kind {
        data.insert("kind".into(), json!(k.as_str()));
        for (f, v) in k.fields() {
            data.insert(f.into(), json!(v));
        }
    }
    if let Some(c) = &push.conv {
        data.insert("conv".into(), json!(c));
    }
    if let Some(b) = &push.sealed {
        data.insert("p".into(), json!(b));
    }
    let data_len = data
        .iter()
        .map(|(k, v)| k.len() + v.as_str().map_or(0, str::len))
        .sum();
    if data_len > MAX_PAYLOAD {
        return Err(PushError::TooLarge(data_len));
    }
    // collapse_key 는 달지 않는다(Android 실기 11-06): FCM 은 접히는 메시지를 기기·앱마다 몰아서 20개까지만 보내고 그 뒤는
    // 3분에 1개씩만 채운다. 그리고 접히면 앞 알림의 암호문(p)이 버려진다. 같은 대화 줄이기는 relay 의 2초 묶음·분당 상한이 한다.
    let android = json!({"priority": "high"});
    Ok(serde_json::to_vec(&json!({"message": {
        "token": push.token,
        "android": android,
        "data": data,
    }}))
    .unwrap_or_default())
}

/// FCM 응답 갈래(<https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode>).
#[must_use]
pub fn classify_fcm(r: &Response) -> Outcome {
    let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    if r.status == 200 {
        return Outcome::Sent {
            id: v["name"].as_str().map(str::to_owned),
        };
    }
    let code = v["error"]["details"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|d| d["errorCode"].as_str())
        .or_else(|| v["error"]["status"].as_str())
        .unwrap_or_default()
        .to_owned();
    match (r.status, code.as_str()) {
        // 토큰을 지우는 것은 UNREGISTERED 뿐이다 — 코드 없는 404 는 프로젝트 ID 가 틀린 것일 수 있어(모든 기기의 푸시가
        // 조용히 끊긴다) 운영자 자격 문제로 둔다.
        (_, "UNREGISTERED") => Outcome::TokenGone { reason: code },
        (404, _) => Outcome::AuthFailed {
            status: 404,
            reason: code,
        },
        (401, _) | (403, "THIRD_PARTY_AUTH_ERROR" | "PERMISSION_DENIED") => Outcome::AuthFailed {
            status: r.status,
            reason: code,
        },
        (429 | 500..=599, _) => Outcome::Retry {
            status: r.status,
            after_s: retry_after(r),
            reason: code,
        },
        (status, _) => Outcome::Rejected {
            status,
            reason: code,
        },
    }
}

// ───────────────────────────── 보내기 ─────────────────────────────

/// 자격 묶음 + 전송. 자격이 없는 쪽은 `NotConfigured`.
pub struct Sender {
    pub apns: Option<Apns>,
    pub fcm: Option<Fcm>,
    pub transport: Arc<dyn Transport>,
}

/// 운영자 env 이름(값은 레포·로그·메시지 어디에도 두지 않는다 — 비밀 파일은 0600).
pub const ENV_APNS_KEY_FILE: &str = "LODELAI_APNS_KEY_FILE";
pub const ENV_APNS_KEY_ID: &str = "LODELAI_APNS_KEY_ID";
pub const ENV_APNS_TEAM_ID: &str = "LODELAI_APNS_TEAM_ID";
pub const ENV_APNS_TOPIC: &str = "LODELAI_APNS_TOPIC";
pub const ENV_FCM_SERVICE_ACCOUNT_FILE: &str = "LODELAI_FCM_SERVICE_ACCOUNT_FILE";
/// FCM 앱 패키지 이름(push.register 의 app_id 대조).
pub const ENV_FCM_APP_ID: &str = "LODELAI_FCM_APP_ID";

impl Sender {
    /// env 에서 자격을 읽는다. 한 쪽 이름이 일부만 있으면 무엇이 빠졌는지 오류.
    ///
    /// # Errors
    /// 일부만 채움·파일 권한·키 형식.
    pub fn from_env(
        get: impl Fn(&str) -> Option<String>,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, PushError> {
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let names = [
            ENV_APNS_KEY_FILE,
            ENV_APNS_KEY_ID,
            ENV_APNS_TEAM_ID,
            ENV_APNS_TOPIC,
        ];
        let vals: Vec<_> = names.iter().map(|k| get(k)).collect();
        let apns = if vals.iter().all(Option::is_none) {
            None
        } else if let [Some(file), Some(key_id), Some(team), Some(topic)] = vals.as_slice() {
            let pem = read_secret_file(Path::new(file))?;
            Some(Apns::new(team, key_id, topic, &pem)?)
        } else {
            let missing: Vec<_> = names
                .iter()
                .zip(&vals)
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| *k)
                .collect();
            return Err(PushError::Creds(format!(
                "APNs env 가 빠짐: {}",
                missing.join(", ")
            )));
        };
        let fcm = match get(ENV_FCM_SERVICE_ACCOUNT_FILE) {
            Some(file) => Some(Fcm::from_service_account(&read_secret_file(Path::new(
                &file,
            ))?)?),
            None => None,
        };
        Ok(Self {
            apns,
            fcm,
            transport,
        })
    }

    /// 하나 보낸다. 연결 실패는 `Retry{status: 0}`.
    ///
    /// # Errors
    /// 자격 없음·페이로드 상한.
    pub async fn send(
        &self,
        platform: Platform,
        env: ApnsEnv,
        push: &Push,
        now_ms: i64,
    ) -> Result<Outcome, PushError> {
        let conn_err = |e: std::io::Error| Outcome::Retry {
            status: 0,
            after_s: None,
            reason: format!("연결: {e}"),
        };
        match platform {
            Platform::Apns => {
                let a = self.apns.as_ref().ok_or(PushError::NotConfigured("APNs"))?;
                let req = a.request(env, push, now_ms)?;
                let first = match self.transport.post(req).await {
                    Ok(r) => classify_apns(&r),
                    Err(e) => conn_err(e),
                };
                // 시계 어긋남·잠든 뒤 재개: 받아 둔 JWT 를 버리고 한 번만 새로 서명해 다시(설계 ②-4).
                if matches!(&first, Outcome::AuthFailed { reason, .. } if reason == "ExpiredProviderToken")
                {
                    a.forget_jwt();
                    let req = a.request(env, push, now_ms)?;
                    return Ok(match self.transport.post(req).await {
                        Ok(r) => classify_apns(&r),
                        Err(e) => conn_err(e),
                    });
                }
                Ok(first)
            }
            Platform::Fcm => {
                let f = self.fcm.as_ref().ok_or(PushError::NotConfigured("FCM"))?;
                // 데이터 상한은 토큰을 받기 전에 본다(넘는 것 때문에 OAuth 를 부르지 않게).
                fcm_body(push)?;
                let tok = match f.access_token(self.transport.as_ref(), now_ms).await {
                    Ok(t) => t,
                    Err(o) => return Ok(o),
                };
                let req = f.request(push, &tok)?;
                Ok(match self.transport.post(req).await {
                    Ok(r) => classify_fcm(&r),
                    Err(e) => conn_err(e),
                })
            }
        }
    }
}

// ───────────────────────────── 보관 때 보내기 ─────────────────────────────

/// 결과 셈(운영자 로그·상태용).
#[derive(Debug, Default)]
pub struct Counts {
    pub sent: std::sync::atomic::AtomicU64,
    pub token_gone: std::sync::atomic::AtomicU64,
    pub rejected: std::sync::atomic::AtomicU64,
    pub auth_failed: std::sync::atomic::AtomicU64,
    pub retry: std::sync::atomic::AtomicU64,
    /// 보내지 않은 것: 전체 분당 60 에 걸림, 또는 2초 창 안에서 더 늦은 글에 밀림(그 늦은 글은 창 끝에 감).
    pub limited: std::sync::atomic::AtomicU64,
}

/// relay 보내기 길(모바일 검증 ④): 접속 안 한 기기 앞 응용 메시지가 보관되면 그 기기 토큰으로 푸시 하나.
pub struct Outbox {
    pub sender: Sender,
    /// 기기·대화마다 2초에 한 번 — 창 안에 더 온 글은 가장 늦은 하나를 창 끝에 보낸다(trailing).
    slots: Mutex<std::collections::HashMap<String, Slot>>,
    /// 전체 분당 60.
    all: crate::limiter::Limiter,
    pub counts: Counts,
    /// 토큰이 더는 맞지 않음 — (기기, 토큰). 만료 tick 이 같은 토큰일 때만 지운다.
    gone: Mutex<Vec<(String, String)>>,
    /// 운영자 자격 실패 로그는 분마다 한 줄.
    auth_log_ms: Mutex<i64>,
    /// 창 끝에 보낼 때 그 기기가 그 사이 접속했는지 본다([`Outbox::install`]).
    relay: OnceLock<std::sync::Weak<crate::Relay>>,
}

impl Outbox {
    #[must_use]
    pub fn new(sender: Sender) -> Self {
        Self {
            sender,
            slots: Mutex::new(std::collections::HashMap::new()),
            all: crate::limiter::Limiter::with_rate(1.0, 60.0),
            counts: Counts::default(),
            gone: Mutex::new(Vec::new()),
            auth_log_ms: Mutex::new(i64::MIN),
            relay: OnceLock::new(),
        }
    }

    fn record(&self, device: &str, token: &str, o: &Outcome, now_ms: i64) {
        use std::sync::atomic::Ordering::Relaxed;
        let who = token_prefix(token);
        match o {
            Outcome::Sent { .. } => {
                self.counts.sent.fetch_add(1, Relaxed);
                tracing::debug!(device, token = %who, "푸시 보냄");
            }
            Outcome::TokenGone { reason } => {
                self.counts.token_gone.fetch_add(1, Relaxed);
                tracing::info!(device, token = %who, reason, "푸시 토큰이 더는 맞지 않음 — 지움");
                self.gone
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((device.to_owned(), token.to_owned()));
            }
            Outcome::Rejected { status, reason } => {
                self.counts.rejected.fetch_add(1, Relaxed);
                tracing::warn!(device, token = %who, status, reason, "푸시 거절");
            }
            Outcome::AuthFailed { status, reason } => {
                self.counts.auth_failed.fetch_add(1, Relaxed);
                let mut last = self
                    .auth_log_ms
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if now_ms.saturating_sub(*last) >= 60_000 {
                    *last = now_ms;
                    tracing::error!(
                        status,
                        reason,
                        "푸시 자격 실패 — 운영자 키·서비스 계정 확인(분마다 한 줄)"
                    );
                }
            }
            Outcome::Retry { status, reason, .. } => {
                self.counts.retry.fetch_add(1, Relaxed);
                tracing::warn!(device, token = %who, status, reason, "푸시 일시 실패");
            }
        }
    }

    /// 쥔 relay(약하게) — #882 현황 창 끝 보내기가 쓴다.
    pub(crate) fn relay_weak(&self) -> Option<std::sync::Weak<crate::Relay>> {
        self.relay.get().cloned()
    }

    /// #882 현황: 묶음·상한 없이 바로(창·상한은 [`crate::live`] 가 맡는다).
    pub(crate) fn send_direct(
        self: &Arc<Self>,
        rt: &tokio::runtime::Handle,
        device: &str,
        platform: Platform,
        env: ApnsEnv,
        push: Push,
        now_ms: i64,
    ) {
        let job = Job {
            device: device.to_owned(),
            platform,
            env,
            push,
        };
        self.spawn_send(rt, job, now_ms);
    }

    /// relay 에 보내기 길을 연다(창 끝 보내기가 그 기기의 접속을 다시 볼 수 있게 relay 를 약하게 쥔다).
    pub fn install(self: Arc<Self>, app: &crate::App) {
        let _ = self.relay.set(Arc::downgrade(app));
        let _ = app.push.set(self);
    }

    fn device_online(&self, device: &str) -> bool {
        self.relay
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|r| r.conns.device_online(device))
    }

    /// 지울 토큰을 꺼낸다(만료 tick).
    pub fn take_gone(&self) -> Vec<(String, String)> {
        std::mem::take(
            &mut *self
                .gone
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// push 행의 platform·env 글 → 보내기 갈래.
#[must_use]
pub fn platform_env(platform: &str, env: &str) -> (Platform, ApnsEnv) {
    match (platform, env) {
        ("apns", "sandbox") => (Platform::Apns, ApnsEnv::Sandbox),
        ("apns", _) => (Platform::Apns, ApnsEnv::Prod),
        _ => (Platform::Fcm, ApnsEnv::Prod),
    }
}

/// 기기·대화 묶음 간격(모바일 검증 — 같은 대화 알림은 2초에 한 번, 창 안 마지막 글은 끝에).
pub const PUSH_WINDOW_MS: i64 = 2_000;

/// 보낼 푸시 하나.
struct Job {
    device: String,
    platform: Platform,
    env: ApnsEnv,
    push: Push,
}

/// (기기|conv) 의 창: 마지막으로 보낸 시각, 창 끝에 보낼 가장 늦은 글, 창 끝 타이머가 걸렸나.
#[derive(Default)]
struct Slot {
    last_ms: Option<i64>,
    pending: Option<Job>,
    armed: bool,
}

impl Outbox {
    fn spawn_send(self: &Arc<Self>, rt: &tokio::runtime::Handle, job: Job, now_ms: i64) {
        let out = self.clone();
        rt.spawn(async move {
            match out.sender.send(job.platform, job.env, &job.push, now_ms).await {
                Ok(o) => out.record(&job.device, &job.push.token, &o, now_ms),
                Err(e) => tracing::warn!(device = job.device, token = %token_prefix(&job.push.token), error = %e, "푸시 못 만듦"),
            }
        });
    }

    /// 창 안이면 미뤄 두고(더 늦은 글이 오면 바꿈) 창 끝에 한 번, 아니면 바로.
    fn submit(
        self: &Arc<Self>,
        rt: &tokio::runtime::Handle,
        key: String,
        job: Job,
        now: lodelai_effects::UnixMillis,
    ) {
        let now_ms = now.0;
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots.len() > 10_000 {
            slots.retain(|_, s| s.armed || s.last_ms.is_some_and(|t| now_ms - t < 60_000));
        }
        let slot = slots.entry(key.clone()).or_default();
        let open = !slot.armed && slot.last_ms.is_none_or(|t| now_ms - t >= PUSH_WINDOW_MS);
        if open {
            if !self.all.allow("all", now) {
                self.counts
                    .limited
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            slot.last_ms = Some(now_ms);
            drop(slots);
            self.spawn_send(rt, job, now_ms);
            return;
        }
        if slot.pending.replace(job).is_some() {
            self.counts
                .limited
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if slot.armed {
            return;
        }
        slot.armed = true;
        let wait = slot.last_ms.map_or(PUSH_WINDOW_MS, |t| {
            (t + PUSH_WINDOW_MS - now_ms).clamp(0, PUSH_WINDOW_MS)
        });
        let fire_ms = slot.last_ms.map_or(now_ms, |t| t + PUSH_WINDOW_MS);
        drop(slots);
        let (out, rt2) = (self.clone(), rt.clone());
        rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(
                u64::try_from(wait).unwrap_or(0),
            ))
            .await;
            let job = {
                let mut slots = out
                    .slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(slot) = slots.get_mut(&key) else {
                    return;
                };
                slot.armed = false;
                slot.last_ms = Some(fire_ms);
                slot.pending.take()
            };
            // 그 사이 앱을 열어 접속했으면 받을 글은 연결로 갔다 — 배너를 하나 더 띄우지 않는다.
            if let Some(job) = job.filter(|j| !out.device_online(&j.device)) {
                out.spawn_send(&rt2, job, fire_ms);
            }
        });
    }
}

/// 보관 직후(1:1·그룹 응용 메시지): 접속해 있지 않고 토큰이 있는 받는 기기마다 푸시. 받지 않은 Handshake 가 그 그룹에 있거나
/// 암호문이 blob·칸을 넘으면 빈 깨우기. 푸시 자격이 없으면(`--mobile-push` 아님) 아무것도 안 한다.
pub fn on_stored(
    app: &crate::Relay,
    group: &str,
    msg_id: &str,
    payload: Option<&[u8]>,
    devices: &[String],
    category: Option<Category>,
    mute_conv: Option<&str>,
) {
    let Some(out) = app.push.get().cloned() else {
        return;
    };
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let now = app.effects.clock.now();
    for device in devices {
        if app.conns.device_online(device) {
            continue;
        }
        let Ok(Some(row)) = app.db.push_token(device) else {
            continue;
        };
        // §7-55 끈 갈래는 알림만 안 보낸다(메시지는 그대로 보관·전달).
        if Category::muted_in(category, &row.off) {
            continue;
        }
        // §7-56 그 사람이 이 대화를 음소거함(둘 중 하나라도 끄면 안 감).
        if mute_conv.is_some_and(|c| app.db.device_muted(device, c, now.0).unwrap_or(false)) {
            continue;
        }
        let conv = conv_tag(&row.salt, group);
        let sealed = payload
            .filter(|_| !app.db.handshake_waiting(device, group).unwrap_or(true))
            .and_then(|m| {
                let key: [u8; 32] = row.key.as_slice().try_into().ok()?;
                let mut nonce = [0u8; NONCE_LEN];
                app.effects.rng.try_fill(&mut nonce).ok()?;
                seal(&key, nonce, msg_id, m)
            });
        let (platform, env) = match (row.platform.as_str(), row.env.as_str()) {
            ("apns", "sandbox") => (Platform::Apns, ApnsEnv::Sandbox),
            ("apns", _) => (Platform::Apns, ApnsEnv::Prod),
            _ => (Platform::Fcm, ApnsEnv::Prod),
        };
        let key = format!("{device}|{conv}");
        let job = Job {
            device: device.clone(),
            platform,
            env,
            push: Push {
                token: row.token,
                conv: Some(conv),
                sealed,
                kind: None,
                live: None,
            },
        };
        out.submit(&rt, key, job, now);
    }
}

/// 메일 확인 끊기가 걸린 그때 한 번: 대상인 옛 기기 중 푸시 등록이 있는 기기마다 kind 알림(본문·이름·지문 없음).
/// 붙어 있는 기기에도 보낸다(앱이 뒤에 있어도 연결이 잠시 살아 있을 수 있다). 푸시 자격이 없으면 아무것도 안 한다.
pub fn on_recover_against(app: &crate::Relay, targets: &[String]) {
    on_kind(app, targets, PushKind::RecoverAgainst);
}

/// 푸시 등록이 있는 기기마다 kind 알림 하나(본문·이름 없음). 푸시 자격이 없으면 아무것도 안 한다.
pub fn on_kind(app: &crate::Relay, targets: &[String], kind: PushKind) {
    let Some(out) = app.push.get().cloned() else {
        return;
    };
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let now = app.effects.clock.now();
    for device in targets {
        let Ok(Some(row)) = app.db.push_token(device) else {
            continue;
        };
        if Category::muted_in(kind.category(), &row.off) {
            continue;
        }
        let (platform, env) = match (row.platform.as_str(), row.env.as_str()) {
            ("apns", "sandbox") => (Platform::Apns, ApnsEnv::Sandbox),
            ("apns", _) => (Platform::Apns, ApnsEnv::Prod),
            _ => (Platform::Fcm, ApnsEnv::Prod),
        };
        let job = Job {
            device: device.clone(),
            platform,
            env,
            push: Push {
                token: row.token,
                kind: Some(kind.clone()),
                ..Push::default()
            },
        };
        out.submit(&rt, format!("{device}|{}", kind.as_str()), job, now);
    }
}

/// #845 §7-39 받는 쪽 초대 카드가 막 생겼을 때: 받는 사람의 붙지 않은 기기 중 푸시 등록이 있는 기기마다 `invite` 알림
/// (sub·카드 id 뿐 — 이름 없음), 기기마다 1분에 1번. 붙은 기기는 directory.update 로 본다. 푸시를 맡긴 기기(시험용).
pub fn on_invite(app: &crate::Relay, user: &str, sub: InviteSub, id: &str) -> Vec<String> {
    if app.push.get().is_none() {
        return Vec::new();
    }
    let now = app.effects.clock.now().0;
    let targets: Vec<String> = app
        .db
        .devices_of(user)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.device_id)
        .filter(|d| !app.conns.device_online(d))
        .filter(|d| {
            app.db
                .push_token(d)
                .ok()
                .flatten()
                .is_some_and(|row| !Category::muted_in(Some(Category::Invite), &row.off))
        })
        .filter(|d| app.invite_push_gate.take(d, now))
        .collect();
    on_kind(
        app,
        &targets,
        PushKind::Invite {
            sub,
            id: id.to_owned(),
        },
    );
    targets
}

// ───────────────────────────── HTTP/2 전송 ─────────────────────────────

/// rustls(ring·webpki 루트) + ALPN `h2` + h2 클라이언트. 요청마다 새 연결(손 발송용) — 보내기 경로에 넣을 때 연결을 붙잡아 둔다.
#[derive(Debug, Default)]
pub struct H2Transport;

fn h2_tls() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring 은 기본 TLS 판을 지원한다")
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(config)
        })
        .clone()
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

async fn h2_post(req: Request) -> std::io::Result<Response> {
    let tcp = tokio::net::TcpStream::connect((req.host.as_str(), 443)).await?;
    let name = rustls::pki_types::ServerName::try_from(req.host.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let tls = tokio_rustls::TlsConnector::from(h2_tls())
        .connect(name, tcp)
        .await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(io_err("서버가 HTTP/2(ALPN h2)를 고르지 않았다"));
    }
    let (client, conn) = h2::client::handshake(tls).await.map_err(io_err)?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });
    let result = async {
        let mut client = client.ready().await.map_err(io_err)?;
        let mut b = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{}{}", req.host, req.path));
        for (k, v) in &req.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let (resp, mut stream) = client
            .send_request(b.body(()).map_err(io_err)?, false)
            .map_err(io_err)?;
        stream
            .send_data(bytes::Bytes::from(req.body), true)
            .map_err(io_err)?;
        let (parts, mut body) = resp.await.map_err(io_err)?.into_parts();
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(io_err)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if out.len() + chunk.len() > MAX_RESPONSE {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(Response {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
                .collect(),
            body: out,
        })
    }
    .await;
    driver.abort();
    result
}

impl Transport for H2Transport {
    fn post(&self, req: Request) -> BoxFuture<'_, std::io::Result<Response>> {
        Box::pin(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, h2_post(req))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "푸시 요청 시간 넘김")
                })?
        })
    }
}

#[cfg(test)]
mod tests {

    /// #845 §7-55: 머리로 가르는 갈래와 기기의 끈 목록.
    #[test]
    fn category_from_header_and_muted_list() {
        use crate::frames::{Address, Header, Kind};
        let m = serde_json::json!({
            "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": "01JB00000000000000000000R1",
            "thread_id": "01JB00000000000000000000R1", "kind": "chat",
            "from": {"address": "dana@local", "author": "human", "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"},
            "to": {"address": "kim@local"}, "mls_group": "01jb00000000000000000000g1", "epoch": 1,
            "body": {"enc": "mls", "wire": "app", "payload": {"data": "AAAA"}},
            "created_at": "2026-10-26T00:00:00.000Z", "expires_at": "2026-11-02T00:00:00.000Z",
        });
        let mut h = Header::from_value(&m).expect("chat 머리");
        let cat = |h: &Header| Category::of_header(h);
        assert_eq!(cat(&h), Some(Category::Chat));
        h.kind = Kind::Reaction;
        assert_eq!(cat(&h), Some(Category::Chat));
        for k in [Kind::Request, Kind::Reply, Kind::Rejected] {
            h.kind = k;
            assert_eq!(cat(&h), Some(Category::Agents));
        }
        h.kind = Kind::System;
        assert_eq!(cat(&h), None, "system 은 끌 수 없음");
        h.group = Address::parse("+01jb00000000000000000000g1@local");
        for k in [Kind::Chat, Kind::Request, Kind::Reply] {
            h.kind = k;
            assert_eq!(cat(&h), Some(Category::Group));
        }
        assert!(Category::muted_in(Some(Category::Group), "chat,group"));
        assert!(!Category::muted_in(Some(Category::Agents), "chat,group"));
        assert!(!Category::muted_in(None, "chat,group,agents,invite"));
        assert!(!Category::muted_in(Some(Category::Chat), ""));
        assert_eq!(
            PushKind::RecoverAgainst.category(),
            None,
            "recover 는 끌 수 없음"
        );
        assert_eq!(PushKind::OwnAlert.category(), Some(Category::Agents));
        // §7-56 음소거 대화: chat·reaction 만, 그룹이면 그룹 주소.
        assert_eq!(
            Category::mute_conv(&h).as_deref(),
            None,
            "reply 는 음소거 밖"
        );
        h.kind = Kind::Chat;
        assert_eq!(
            Category::mute_conv(&h).as_deref(),
            Some("+01jb00000000000000000000g1@local")
        );
        h.group = None;
        h.kind = Kind::Reaction;
        assert_eq!(Category::mute_conv(&h).as_deref(), Some("dana@local"));
    }

    use super::*;
    use ring::signature::KeyPair as _;

    /// 받은 요청을 남기고 정해 둔 응답을 차례로 준다.
    #[derive(Default)]
    struct Fake {
        seen: Mutex<Vec<Request>>,
        replies: Mutex<Vec<Response>>,
    }

    impl Transport for Fake {
        fn post(&self, req: Request) -> BoxFuture<'_, std::io::Result<Response>> {
            self.seen.lock().unwrap().push(req);
            let r = self.replies.lock().unwrap().remove(0);
            Box::pin(async move { Ok(r) })
        }
    }

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }

    /// 시험 키는 그때그때 만든다(레포에 키를 두지 않는다).
    fn apns() -> (Apns, ring::signature::UnparsedPublicKey<Vec<u8>>) {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let a =
            Apns::from_der("TEAM123456", "KEY1234567", "com.example.app", doc.as_ref()).unwrap();
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            a.key.public_key().as_ref().to_vec(),
        );
        (a, pk)
    }

    fn jwt_parts(t: &str) -> (Value, Value, Vec<u8>, String) {
        let p: Vec<_> = t.split('.').collect();
        assert_eq!(p.len(), 3);
        let dec = |s: &str| URL_SAFE_NO_PAD.decode(s).unwrap();
        (
            serde_json::from_slice(&dec(p[0])).unwrap(),
            serde_json::from_slice(&dec(p[1])).unwrap(),
            dec(p[2]),
            format!("{}.{}", p[0], p[1]),
        )
    }

    #[test]
    fn apns_jwt_is_es256_signed_and_reused_for_50_minutes() {
        let (a, pk) = apns();
        let t0 = a.jwt(1_700_000_000_000).unwrap();
        let (h, c, sig, input) = jwt_parts(&t0);
        assert_eq!(h, json!({"alg": "ES256", "kid": "KEY1234567"}));
        assert_eq!(c, json!({"iss": "TEAM123456", "iat": 1_700_000_000}));
        assert_eq!(sig.len(), 64, "JWT ES256 은 r||s 64바이트");
        pk.verify(input.as_bytes(), &sig).unwrap();
        assert_eq!(
            a.jwt(1_700_000_000_000 + APNS_JWT_REUSE_MS - 1).unwrap(),
            t0,
            "50분 안은 그대로"
        );
        assert_ne!(
            a.jwt(1_700_000_000_000 + APNS_JWT_REUSE_MS).unwrap(),
            t0,
            "50분이면 새로"
        );
    }

    #[test]
    fn kind_push_carries_only_kind_and_loc_keys() {
        let (a, _) = apns();
        let push = Push {
            token: "ab12cd34".into(),
            kind: Some(PushKind::RecoverAgainst),
            ..Push::default()
        };
        let r = a.request(ApnsEnv::Prod, &push, 1_700_000_000_000).unwrap();
        assert!(r.headers.iter().all(|(n, _)| n != "apns-collapse-id"));
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        // mutable-content 없음 — NSE 를 거치지 않고 시스템이 앱 문자열 표로 바로 띄운다.
        assert_eq!(
            v,
            json!({
                "aps": {"alert": {"title-loc-key": "recovery.against.title",
                    "loc-key": "recovery.against.push_body"}, "sound": "default"},
                "lodelai": {"kind": "recovery_against"},
            })
        );
        let f: Value = serde_json::from_slice(&fcm_body(&push).unwrap()).unwrap();
        assert_eq!(
            f,
            json!({"message": {"token": "ab12cd34", "android": {"priority": "high"},
                "data": {"kind": "recovery_against"}}})
        );
    }

    /// #890 사용량 한도 가까움: 카드와 같은 제목 키, 본문은 숫자 없는 고정 키. 갈래는 agents(끌 수 있음).
    #[test]
    fn own_usage_push_carries_fixed_keys_only() {
        let (a, _) = apns();
        let push = Push {
            token: "ab12cd34".into(),
            kind: Some(PushKind::OwnUsage),
            ..Push::default()
        };
        assert_eq!(PushKind::OwnUsage.category(), Some(Category::Agents));
        let r = a.request(ApnsEnv::Prod, &push, 1_700_000_000_000).unwrap();
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            v,
            json!({
                "aps": {"alert": {"title-loc-key": "own.alert.title",
                    "loc-key": "own.usage.near_push"}, "sound": "default"},
                "lodelai": {"kind": "own_usage"},
            })
        );
        let f: Value = serde_json::from_slice(&fcm_body(&push).unwrap()).unwrap();
        assert_eq!(
            f,
            json!({"message": {"token": "ab12cd34", "android": {"priority": "high"},
                "data": {"kind": "own_usage"}}})
        );
    }

    #[test]
    fn invite_push_carries_sub_and_card_id_only_and_collapses() {
        let (a, _) = apns();
        let push = Push {
            token: "ab12cd34".into(),
            kind: Some(PushKind::Invite {
                sub: InviteSub::Group,
                id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            }),
            ..Push::default()
        };
        let r = a.request(ApnsEnv::Prod, &push, 1_700_000_000_000).unwrap();
        assert!(r
            .headers
            .iter()
            .any(|(n, v)| n == "apns-collapse-id" && v == "invite"));
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            v,
            json!({
                "aps": {"alert": {"loc-key": "invite.push_title"}, "sound": "default"},
                "lodelai": {"kind": "invite", "sub": "group", "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
            })
        );
        let f: Value = serde_json::from_slice(&fcm_body(&push).unwrap()).unwrap();
        assert_eq!(
            f,
            json!({"message": {"token": "ab12cd34", "android": {"priority": "high"},
                "data": {"kind": "invite", "sub": "group", "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"}}})
        );
    }

    #[test]
    fn apns_request_has_topic_type_priority_collapse_and_no_plaintext() {
        let (a, _) = apns();
        let push = Push {
            token: "ab12cd34".into(),
            conv: Some("c0nv".into()),
            sealed: Some("AQID".into()),
            kind: None,
            live: None,
        };
        let r = a
            .request(ApnsEnv::Sandbox, &push, 1_700_000_000_000)
            .unwrap();
        assert_eq!(r.host, "api.sandbox.push.apple.com");
        assert_eq!(r.path, "/3/device/ab12cd34");
        let h = |k: &str| {
            r.headers
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(h("apns-topic"), Some("com.example.app"));
        assert_eq!(h("apns-push-type"), Some("alert"));
        assert_eq!(h("apns-priority"), Some("10"));
        assert_eq!(h("apns-collapse-id"), Some("c0nv"));
        assert!(h("authorization").unwrap().starts_with("bearer "));
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(
            v,
            json!({
                "aps": {"alert": {"loc-key": APNS_LOC_KEY}, "mutable-content": 1, "sound": "default", "thread-id": "c0nv"},
                "lodelai": {"conv": "c0nv", "p": "AQID"},
            })
        );
        assert_eq!(
            a.request(
                ApnsEnv::Prod,
                &Push {
                    token: "t".into(),
                    ..Push::default()
                },
                0
            )
            .unwrap()
            .host,
            "api.push.apple.com"
        );
    }

    #[test]
    fn payload_and_collapse_caps() {
        let (a, _) = apns();
        let fits = |n: usize| Push {
            token: "t".into(),
            conv: None,
            sealed: Some("A".repeat(n)),
            kind: None,
            live: None,
        };
        // 상한 바로 안쪽·바깥쪽을 찾는다(JSON 겉).
        let mut n = 3900;
        while apns_payload(&fits(n + 1)).is_ok() {
            n += 1;
        }
        assert!(apns_payload(&fits(n)).unwrap().len() <= MAX_PAYLOAD);
        assert!(matches!(
            apns_payload(&fits(n + 3)),
            Err(PushError::TooLarge(_))
        ));
        assert!(matches!(fcm_body(&fits(4100)), Err(PushError::TooLarge(_))));
        assert!(fcm_body(&fits(4000)).is_ok());
        // 가장 큰 크기 칸 + 대화 태그는 둘 다 들어간다.
        let big = Push {
            token: "t".into(),
            conv: Some("0".repeat(32)),
            sealed: Some("A".repeat(*SEAL_BUCKETS.last().unwrap())),
            kind: None,
            live: None,
        };
        assert!(apns_payload(&big).is_ok() && fcm_body(&big).is_ok());
        let long = Push {
            token: "t".into(),
            conv: Some("x".repeat(MAX_COLLAPSE_ID + 1)),
            sealed: None,
            kind: None,
            live: None,
        };
        assert!(matches!(
            a.request(ApnsEnv::Sandbox, &long, 0),
            Err(PushError::CollapseTooLong(65))
        ));
    }

    #[test]
    fn apns_responses_split_gone_auth_retry_rejected() {
        let mut ok = resp(200, "");
        ok.headers.push(("apns-id".into(), "ID-1".into()));
        assert_eq!(
            classify_apns(&ok),
            Outcome::Sent {
                id: Some("ID-1".into())
            }
        );
        assert_eq!(
            classify_apns(&resp(410, r#"{"reason":"Unregistered","timestamp":1}"#)),
            Outcome::TokenGone {
                reason: "Unregistered".into()
            }
        );
        assert_eq!(
            classify_apns(&resp(400, r#"{"reason":"BadDeviceToken"}"#)),
            Outcome::Rejected {
                status: 400,
                reason: "BadDeviceToken".into()
            },
            "sandbox·prod 섞임일 수 있어 토큰을 지우지 않는다"
        );
        assert_eq!(
            classify_apns(&resp(403, r#"{"reason":"InvalidProviderToken"}"#)),
            Outcome::AuthFailed {
                status: 403,
                reason: "InvalidProviderToken".into()
            }
        );
        let mut busy = resp(429, r#"{"reason":"TooManyRequests"}"#);
        busy.headers.push(("Retry-After".into(), "30".into()));
        assert_eq!(
            classify_apns(&busy),
            Outcome::Retry {
                status: 429,
                after_s: Some(30),
                reason: "TooManyRequests".into()
            }
        );
        assert!(matches!(
            classify_apns(&resp(503, "")),
            Outcome::Retry { status: 503, .. }
        ));
    }

    /// RS256 서명 바이트는 실제 서비스 계정으로만 확인한다(ring 은 RSA 키를 만들지 못하고, 레포에 키를 두지 않는다).
    /// 여기서는 머리·몸·서명 자리·교환 요청 꼴을 본다.
    struct FakeRsa;
    impl Rs256Signer for FakeRsa {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PushError> {
            Ok(<sha2::Sha256 as sha2::Digest>::digest(msg).to_vec())
        }
    }

    fn fcm() -> Fcm {
        Fcm::with_signer(
            "proj-1",
            "svc@proj-1.iam.gserviceaccount.com",
            "https://oauth2.googleapis.com/token",
            Box::new(FakeRsa),
        )
        .unwrap()
    }

    #[test]
    fn fcm_token_request_is_jwt_bearer_with_messaging_scope() {
        let f = fcm();
        let r = f.token_request(1_700_000_000_000).unwrap();
        assert_eq!(
            (r.host.as_str(), r.path.as_str()),
            ("oauth2.googleapis.com", "/token")
        );
        let body = String::from_utf8(r.body).unwrap();
        let assertion = body
            .strip_prefix(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=",
            )
            .unwrap();
        let (h, c, sig, input) = jwt_parts(assertion);
        assert_eq!(h, json!({"alg": "RS256", "typ": "JWT"}));
        assert_eq!(
            c,
            json!({"iss": "svc@proj-1.iam.gserviceaccount.com", "scope": FCM_SCOPE,
                "aud": "https://oauth2.googleapis.com/token", "iat": 1_700_000_000, "exp": 1_700_003_600})
        );
        assert_eq!(sig, FakeRsa.sign(input.as_bytes()).unwrap());
        assert!(Fcm::with_signer("p", "e", "http://x/token", Box::new(FakeRsa)).is_err());
    }

    #[test]
    fn fcm_body_is_data_only_high_priority_without_collapse() {
        let push = Push {
            token: "fcm-tok".into(),
            conv: Some("c0nv".into()),
            sealed: Some("AQID".into()),
            kind: None,
            live: None,
        };
        let v: Value = serde_json::from_slice(&fcm_body(&push).unwrap()).unwrap();
        assert_eq!(
            v,
            json!({"message": {"token": "fcm-tok",
                "android": {"priority": "high"},
                "data": {"conv": "c0nv", "p": "AQID"}}})
        );
        assert!(v["message"].get("notification").is_none());
    }

    #[test]
    fn fcm_responses_split_gone_auth_retry_rejected() {
        assert_eq!(
            classify_fcm(&resp(200, r#"{"name":"projects/p/messages/1"}"#)),
            Outcome::Sent {
                id: Some("projects/p/messages/1".into())
            }
        );
        let unreg = r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(
            classify_fcm(&resp(404, unreg)),
            Outcome::TokenGone {
                reason: "UNREGISTERED".into()
            }
        );
        // 코드 없는 404(프로젝트 ID 틀림 등)는 토큰을 지우지 않는다.
        assert_eq!(
            classify_fcm(&resp(404, r#"{"error":{"code":404,"status":"NOT_FOUND"}}"#)),
            Outcome::AuthFailed {
                status: 404,
                reason: "NOT_FOUND".into()
            }
        );
        assert!(matches!(
            classify_fcm(&resp(404, "")),
            Outcome::AuthFailed { status: 404, .. }
        ));
        let bad = r#"{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"errorCode":"INVALID_ARGUMENT"}]}}"#;
        assert_eq!(
            classify_fcm(&resp(400, bad)),
            Outcome::Rejected {
                status: 400,
                reason: "INVALID_ARGUMENT".into()
            }
        );
        assert_eq!(
            classify_fcm(&resp(401, r#"{"error":{"status":"UNAUTHENTICATED"}}"#)),
            Outcome::AuthFailed {
                status: 401,
                reason: "UNAUTHENTICATED".into()
            }
        );
        let mismatch = r#"{"error":{"details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}"#;
        assert!(matches!(
            classify_fcm(&resp(403, mismatch)),
            Outcome::Rejected { status: 403, .. }
        ));
        assert!(matches!(
            classify_fcm(&resp(503, "")),
            Outcome::Retry { status: 503, .. }
        ));
    }

    #[tokio::test]
    async fn fcm_send_exchanges_token_once_and_reuses_it() {
        let fake = Arc::new(Fake::default());
        fake.replies.lock().unwrap().extend([
            resp(200, r#"{"access_token":"at-1","expires_in":3600}"#),
            resp(200, r#"{"name":"m1"}"#),
            resp(200, r#"{"name":"m2"}"#),
            resp(200, r#"{"access_token":"at-2","expires_in":3600}"#),
            resp(200, r#"{"name":"m3"}"#),
        ]);
        let s = Sender {
            apns: None,
            fcm: Some(fcm()),
            transport: fake.clone(),
        };
        let push = Push {
            token: "tok".into(),
            ..Push::default()
        };
        let t0 = 1_700_000_000_000;
        for (now, id) in [(t0, "m1"), (t0 + 3_539_000, "m2"), (t0 + 3_540_000, "m3")] {
            assert_eq!(
                s.send(Platform::Fcm, ApnsEnv::Sandbox, &push, now)
                    .await
                    .unwrap(),
                Outcome::Sent {
                    id: Some(id.into())
                }
            );
        }
        let auth: Vec<_> = fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.host == FCM_HOST)
            .map(|r| r.headers[0].1.clone())
            .collect();
        assert_eq!(
            auth,
            ["Bearer at-1", "Bearer at-1", "Bearer at-2"],
            "만료 60초 전에 새로"
        );
        assert!(matches!(
            s.send(Platform::Apns, ApnsEnv::Sandbox, &push, t0).await,
            Err(PushError::NotConfigured("APNs"))
        ));
    }

    #[tokio::test]
    async fn fcm_oauth_failure_is_auth_failed_and_sends_nothing() {
        let fake = Arc::new(Fake::default());
        fake.replies
            .lock()
            .unwrap()
            .push(resp(400, r#"{"error":"invalid_grant"}"#));
        let s = Sender {
            apns: None,
            fcm: Some(fcm()),
            transport: fake.clone(),
        };
        let o = s
            .send(
                Platform::Fcm,
                ApnsEnv::Sandbox,
                &Push {
                    token: "t".into(),
                    ..Push::default()
                },
                0,
            )
            .await
            .unwrap();
        assert_eq!(
            o,
            Outcome::AuthFailed {
                status: 400,
                reason: "invalid_grant".into()
            }
        );
        assert_eq!(
            fake.seen.lock().unwrap().len(),
            1,
            "보내기 요청은 나가지 않는다"
        );
    }

    #[test]
    fn secret_file_must_be_private_regular_file_not_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.p8");
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = read_secret_file(&p).unwrap_err().to_string();
        assert!(e.contains("0600"), "{e}");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret_file(&p).unwrap(), "x");
        let link = dir.path().join("link.p8");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(read_secret_file(&link).is_err(), "링크는 거절");
        assert!(read_secret_file(dir.path()).is_err(), "폴더는 거절");
    }

    #[test]
    fn env_needs_all_four_apns_names_and_says_which_are_missing() {
        let t: Arc<dyn Transport> = Arc::new(H2Transport);
        let none = Sender::from_env(|_| None, t.clone()).unwrap();
        assert!(none.apns.is_none() && none.fcm.is_none());
        let e = Sender::from_env(
            |k| (k == ENV_APNS_KEY_ID).then(|| "K".to_owned()),
            t.clone(),
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            e.contains(ENV_APNS_KEY_FILE)
                && e.contains(ENV_APNS_TOPIC)
                && !e.contains(ENV_APNS_KEY_ID),
            "{e}"
        );
        // PEM 이 아닌 파일은 키 형식 오류(내용은 오류에 없다).
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.p8");
        std::fs::write(&p, "not-a-key-secret-text").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = p.display().to_string();
        let e = Sender::from_env(
            |k| match k {
                ENV_APNS_KEY_FILE => Some(path.clone()),
                ENV_APNS_KEY_ID | ENV_APNS_TEAM_ID | ENV_APNS_TOPIC => Some("v".into()),
                _ => None,
            },
            t,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(e.contains("PKCS#8") && !e.contains("not-a-key"), "{e}");
    }

    #[tokio::test]
    async fn apns_expired_provider_token_resigns_once() {
        let fake = Arc::new(Fake::default());
        fake.replies.lock().unwrap().extend([
            resp(403, r#"{"reason":"ExpiredProviderToken"}"#),
            resp(200, ""),
        ]);
        let (a, _) = apns();
        let s = Sender {
            apns: Some(a),
            fcm: None,
            transport: fake.clone(),
        };
        let push = Push {
            token: "ab".into(),
            ..Push::default()
        };
        let t0 = 1_700_000_000_000;
        // 받아 둔 JWT 를 만들어 둔다(같은 ms 면 새로 서명해도 같은 꼴이니 시각을 조금 옮겨 본다).
        let first = s.apns.as_ref().unwrap().jwt(t0 - 1_000).unwrap();
        let o = s
            .send(Platform::Apns, ApnsEnv::Sandbox, &push, t0)
            .await
            .unwrap();
        assert_eq!(o, Outcome::Sent { id: None });
        let auth: Vec<String> = fake
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.headers[0].1.clone())
            .collect();
        assert_eq!(auth.len(), 2, "한 번만 다시");
        assert_eq!(auth[0], format!("bearer {first}"));
        assert_ne!(auth[1], auth[0], "다시 보낼 때는 새로 서명");
        // 다시도 Expired 면 그대로 AuthFailed(되풀이하지 않음).
        fake.replies.lock().unwrap().extend([
            resp(403, r#"{"reason":"ExpiredProviderToken"}"#),
            resp(403, r#"{"reason":"ExpiredProviderToken"}"#),
        ]);
        let o = s
            .send(Platform::Apns, ApnsEnv::Sandbox, &push, t0 + 5_000)
            .await
            .unwrap();
        assert!(matches!(o, Outcome::AuthFailed { status: 403, .. }));
        assert_eq!(fake.seen.lock().unwrap().len(), 4);
    }

    #[test]
    fn seal_round_trips_pads_to_buckets_and_differs_per_key() {
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        let msg = vec![7u8; 100];
        let a = seal(&k1, [0; 12], "msg-1", &msg).unwrap();
        assert_eq!(a.len(), 512, "가장 작은 칸");
        assert_eq!(open(&k1, &a).unwrap(), ("msg-1".to_owned(), msg.clone()));
        assert!(open(&k2, &a).is_none(), "다른 기기 키로는 못 푼다");
        let b = seal(&k2, [0; 12], "msg-1", &msg).unwrap();
        assert_ne!(a, b, "같은 메시지도 기기마다 바이트가 다르다");
        for (n, want) in [(300, 512), (400, 1024), (1500, 2048), (2200, 3072)] {
            let s = seal(&k1, [3; 12], "m", &vec![1u8; n]).unwrap();
            assert_eq!(s.len(), want, "{n}");
            assert_eq!(open(&k1, &s).unwrap().1.len(), n);
        }
        assert!(
            seal(&k1, [3; 12], "m", &vec![1u8; 2300]).is_none(),
            "넘치면 빈 깨우기로"
        );
        let mut bad = STANDARD.decode(&a).unwrap();
        bad[20] ^= 1;
        assert!(
            open(&k1, &STANDARD.encode(bad)).is_none(),
            "고친 바이트는 거절"
        );
    }

    const SEAL_VECTOR: &str = "AAECAwQFBgcICQoLiOE4MWNVlXCHsw/DqC0+U/lAgtdhRJ2J1qcf9HXJy1CfrU6KknvCmDcydthllI8jfoSpdP0ouJsSuNkHkE+e1nl4vM3lFCzpxBZNvBh83PHa3kcyb2rwPg5X8A7YfQK/Td5s8/fZJ/SxW/O3opG3gOlvVjiJXUD4T20033k/v0ahZsO9qTPfbEkTf3osPGs6tHGHcgtvzF4y4acxpBugOT+5gei9RJTmjn5mEGex7wDeVKZKF1t6Fdgf7pFnNpQQ2Udfj2P9Dx8tSCUOzUZtDWLYxTxmD69XFikspfsafP1sQwqwjrAF4Nr6CEarGJSM8F+r+Gt7qp6+gGvb5f0BIoORAolpRLaUm9qfR2rx3u71AqTWFsl8qRtmfWwVYrlWJy9ZGPc98FUAd17VlAhaAzl3q9atxn6OF7wawyJjbqkCXo4FGVyRnu/sfY4XxJK6bqyIWKBofdRgT0OAB9tFOGhoDDtw83CLFOpIcnTa3QiTCw7h";
    const CONV_TAG_VECTOR: &str = "e3df79bab3d26c8d67ee93822499ac62";

    /// 코어(mobile-host open)와 맞추는 고정 값: key 0x00..0x1f, nonce 0x00..0x0b.
    #[test]
    fn seal_fixed_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);
        let p = seal(&key, nonce, "01JB0000000000000000000001", b"mls-bytes").unwrap();
        assert_eq!(p, SEAL_VECTOR);
    }

    /// 코어 시험과 맞추는 고정 값: salt = 0x00..0x0f, group_id = "grp-1".
    #[test]
    fn conv_tag_is_per_salt_hmac_prefix() {
        let salt: Vec<u8> = (0u8..16).collect();
        let t = conv_tag(&salt, "grp-1");
        assert_eq!(t.len(), 32);
        assert!(t
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(t, CONV_TAG_VECTOR);
        assert_ne!(
            conv_tag(&[9u8; 16], "grp-1"),
            t,
            "salt 가 다르면 값도 다르다"
        );
    }

    #[test]
    fn token_prefix_shows_six_chars_only() {
        assert_eq!(token_prefix("abcdef0123456789"), "abcdef…");
        assert_eq!(token_prefix("ab"), "ab…");
    }
}
