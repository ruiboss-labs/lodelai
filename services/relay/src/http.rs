//! HTTP: 헬스체크, 기기 등록, Host·Origin 검사(security §7.2, QA S-PEER-6).
//!
//! M1 로컬 relay 의 기기 등록(`POST /v1/devices`)은 가입·초대가 없다. 대신 앱이 relay 를 띄울 때 stdin 으로 넘긴
//! **등록 토큰**(`Authorization: Bearer …`)을 요구한다 — 같은 사용자의 에이전트(Bash 의 `curl`)가 localhost 로
//! 기기를 몰래 등록해 사람 행세를 하지 못하게. 토큰이 설정되지 않았으면 등록을 닫는다.
//! 주인 앱 전용 조회·정리(`GET /v1/connected`·`POST /v1/wipe`, #328)도 같은 토큰을 요구한다.
//!
//! hosted 가입(#339 결정 D, `Relay::mailer` 가 있을 때만): `POST /v1/signup {email}` → 메일에 6자리 코드 →
//! `POST /v1/signup/verify {email, code}` → `{signup_token}` → `POST /v1/devices {signup_token, …}`. 그 이메일에 계정이
//! 있으면 새 기기는 그 계정에 붙는다(추가 기기·분실 복구가 같은 길). 열거 방지: signup 은 이메일이 있든 없든 같은 응답,
//! verify 는 이메일 없음·틀림·만료·폐기를 같은 응답으로 답한다(protocol §7.2).
//!
//! 원격 relay(묶음 4, #364 — Cloudflare 등 프록시 뒤): 등록 토큰이 없다(띄운 앱이 없다). 묶음 5 부터 사람·기기는 모두
//! 이메일 가입으로 들어온다 — 첫 관리자는 `lodelai-relay bootstrap` 의 조직 만들기 코드로 새 조직을, 동료는 초대 코드로.
//! 공개 도메인 Host 도 받는다(`--public-host`). 클라이언트 IP 는 loopback 연결이고 `--behind-cloudflare` 일 때만
//! `CF-Connecting-IP` 를 믿는다 — 인증 전 시도 상한의 키.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use lodelai_crypto::{DeviceId, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::App;

/// 클라이언트 IP 상한 키(#364) — IPv4 는 주소, IPv6 는 /64(한 가입자가 보통 받는 범위라 주소를 바꿔 상한을 피하지 못하게).
/// 모르면(시험의 in-process·연결 정보 없음) `None` — IP 상한을 보지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp(pub Option<String>);

/// 연결 주소와 헤더로 클라이언트 IP 를 정한다. `CF-Connecting-IP` 는 연결이 loopback(cloudflared)이고 `behind_cloudflare`
/// 일 때만 믿는다 — 아니면 누구나 헤더로 IP 를 바꿔 상한을 피한다.
pub fn client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    behind_cloudflare: bool,
) -> Option<String> {
    let peer = peer?;
    if behind_cloudflare && peer.ip().is_loopback() {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
        {
            return Some(limit_key(ip));
        }
    }
    Some(limit_key(peer.ip()))
}

/// IPv4(·IPv4 대응 IPv6)는 주소 그대로, IPv6 는 앞 64비트 `a:b:c:d::/64`.
fn limit_key(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// 모든 경로 앞에서: `Origin` 이 있으면 거부(브라우저), `Host` 는 `127.0.0.1:<port>`·`localhost:<port>`·공개 도메인만
/// (DNS rebinding). 클라이언트 IP 를 요청에 붙인다.
pub async fn local_guard(State(app): State<App>, mut req: Request, next: Next) -> Response {
    if !host_allowed_with(
        req.headers(),
        app.config.port,
        app.config.public_host.as_deref(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(peer, req.headers(), app.config.behind_cloudflare);
    req.extensions_mut().insert(ClientIp(ip));
    // 정리(wipe) 뒤 종료 전까지는 아무것도 받지 않는다.
    if app.wiped.load(std::sync::atomic::Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(req).await
}

pub fn host_allowed(headers: &HeaderMap, port: u16) -> bool {
    host_allowed_with(headers, port, None)
}

/// [`host_allowed`] + 공개 도메인(`<도메인>`·`<도메인>:443`, #364).
pub fn host_allowed_with(headers: &HeaderMap, port: u16, public_host: Option<&str>) -> bool {
    if headers.contains_key(header::ORIGIN) {
        return false;
    }
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    host == format!("127.0.0.1:{port}")
        || host == format!("localhost:{port}")
        || public_host.is_some_and(|p| {
            host.eq_ignore_ascii_case(p) || host.eq_ignore_ascii_case(&format!("{p}:443"))
        })
}

/// `GET /v1/healthz`: 바깥 감시가 몇 분마다 부른다. DB 를 읽을 수 있으면 200 `ok`, 아니면 503.
/// 본문에 그 밖의 내용(판·사용자 수 등)은 싣지 않는다. 판 범위는 헤더로만(§12-28 ①: 101 헤더가 프록시에서 지워졌을 때 앱이 여기서 본다).
pub async fn healthz(State(app): State<App>) -> Response {
    match app.db.health() {
        Ok(()) => {
            let mut resp = (
                [(
                    crate::ws::PROTOCOL_HEADER,
                    crate::ws::protocol_header_value(),
                )],
                "ok",
            )
                .into_response();
            // §12-29 ①: 서버 이름도 같은 자리에(#534).
            if let Some(v) = crate::ws::server_header_value(&app.config.server_name) {
                resp.headers_mut().insert(crate::ws::SERVER_HEADER, v);
            }
            // §12-30 ②: 켜진 기능(#535).
            resp.headers_mut().insert(
                crate::ws::FEATURES_HEADER,
                crate::ws::features_header_value(&app.config),
            );
            resp
        }
        Err(e) => {
            tracing::warn!(error = %e, "healthz: DB 읽기 실패");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DevicePubkeys {
    pub ed25519: String,
    pub x25519: String,
    /// x25519 를 이 기기 키에 묶는 서명(#313, `lodelai-xkey-v1`). 필수 — 등록 때 검증한다(정직한 서버에서 쓰레기 키를 막는 용도.
    /// 진짜 방어는 피어 relay-client 의 검증).
    pub x25519_sig: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterDevice {
    /// M1 은 필수. hosted 는 새 계정일 때만 필요하다 — 이메일에 계정이 있으면 서버가 정한다(다르면 409).
    #[serde(default)]
    pub user: Option<String>,
    pub device_pubkeys: DevicePubkeys,
    #[serde(default)]
    pub display_name: Option<String>,
    /// 이미 있는 사용자에 기기를 더한다(주인 자신의 다른 기기). 없으면 거짓 — 이미 있는 사용자면 403. M1 전용.
    #[serde(default)]
    pub existing_user: bool,
    /// hosted: `POST /v1/signup/verify` 가 준 가입 토큰(#339).
    #[serde(default)]
    pub signup_token: Option<String>,
    /// hosted 새 계정의 조직(#355): `{invite: <토큰>}` 또는 `{create: {name}}`. 기존 계정이면 무시.
    #[serde(default)]
    pub org: Option<OrgRequest>,
    /// hosted 새 계정이 고른 팀(#355, 초대로 들어갈 때만).
    #[serde(default)]
    pub teams: Vec<String>,
    /// 원격 relay 의 설정 코드(#364, `lodelai-relay bootstrap`). 있으면 첫 관리자 등록.
    #[serde(default)]
    pub setup_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OrgRequest {
    Invite(String),
    /// 새 조직. 서버 relay 는 조직 만들기 코드(`setup_code`)가 있어야 한다(묶음 5).
    Create {
        name: String,
        #[serde(default)]
        setup_code: Option<String>,
    },
}

/// 이메일 없는 조직 만들기 코드의 유효 시간(#364 — 1시간, 1회용, m1-spec §17.1). 자체 호스팅 첫 관리자가 설치 직후 쓴다.
pub const SETUP_CODE_TTL_MS: i64 = 60 * 60 * 1000;
/// 이메일에 묶은 조직 만들기 코드(relay 0.1.2 — 대기 명단 초대 메일): 기본 7일, `--ttl` 상한 14일.
pub const SETUP_CODE_EMAIL_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const SETUP_CODE_MAX_TTL_MS: i64 = 14 * 24 * 60 * 60 * 1000;
/// 조직 만들기 코드 늦춤(relay 0.1.2 — 코드를 지우지 않고 마구 두드리기만 막는다): 이메일당 틀린 코드 5번·IP 당 시도
/// 20번·relay 전체 시도 200번이면 1시간.
pub const SETUP_CODE_EMAIL_FAILS: u32 = 5;
pub const SETUP_CODE_IP_PER_HOUR: u32 = 20;
pub const SETUP_CODE_ALL_PER_HOUR: u32 = 200;
pub const SETUP_CODE_THROTTLE_MS: i64 = 60 * 60 * 1000;

/// 설정 코드 글자(Crockford base32 — 헷갈리는 I·L·O·U 없음).
const SETUP_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 설정 코드 해시. 서버는 코드를 보관하지 않는다. 앞뒤 공백·대소문자·`-` 는 가리지 않는다(손으로 옮겨 적는 코드).
pub fn setup_code_hash(code: &str) -> Vec<u8> {
    let canon: String = code
        .trim()
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let mut h = Sha256::new();
    h.update(b"lodelai-setup-code-v1\0");
    h.update(canon.as_bytes());
    h.finalize().to_vec()
}

/// 이메일의 가린 꼴(`a***@d…`) — `bootstrap --list`·다른 이메일 거절에 보인다. 정규화한 이메일을 받는다.
#[must_use]
pub fn mask_email(normalized: &str) -> String {
    let (local, domain) = normalized.split_once('@').unwrap_or((normalized, ""));
    let first = |s: &str| s.chars().next().map(String::from).unwrap_or_default();
    format!("{}***@{}…", first(local), first(domain))
}

/// 새로 낸 조직 만들기 코드. `code` 는 돌려준 값이 유일한 사본이다.
#[derive(Debug, Clone)]
pub struct IssuedSetupCode {
    pub code: String,
    pub id: String,
    pub expires_ms: i64,
    pub email_mask: Option<String>,
}

/// `lodelai-relay bootstrap [--email <주소> [--ttl …]]`(#364·묶음 5·relay 0.1.2): 1회용 **조직 만들기 코드**를 내고 해시만
/// 저장한다. 코드를 가진 사람이 가입하며 새 조직의 첫 관리자가 된다. 꼴 `XXXX-XXXX-XXXX-XXXX`(80비트).
/// - 이메일 없음: 1시간, 앞의 이메일 없는 코드는 무효(지금까지 동작). `ttl_ms` 는 받지 않는다.
/// - 이메일: 그 이메일로 확인한 가입만 쓴다. 기본 7일·상한 14일, 같은 이메일의 앞 코드는 무효.
///
/// # Errors
/// 이메일 형식·기한(사람 글), 난수·sqlite 오류(문자열).
pub fn issue_setup_code(
    db: &crate::db::Db,
    rng: &dyn lodelai_effects::Rng,
    now_ms: i64,
    email: Option<&str>,
    ttl_ms: Option<i64>,
) -> Result<IssuedSetupCode, String> {
    let email = match email {
        None => None,
        Some(e) => Some(normalize_email(e).ok_or("이메일 형식이 아니다")?),
    };
    let ttl = match (&email, ttl_ms) {
        (None, Some(_)) => return Err("--ttl 은 --email 과 같이만".into()),
        (None, None) => SETUP_CODE_TTL_MS,
        (Some(_), None) => SETUP_CODE_EMAIL_TTL_MS,
        (Some(_), Some(t)) if t <= 0 || t > SETUP_CODE_MAX_TTL_MS => {
            return Err("--ttl 은 14일까지".into())
        }
        (Some(_), Some(t)) => t,
    };
    let mut raw = [0u8; 20];
    rng.try_fill(&mut raw).map_err(|e| e.to_string())?;
    let code = raw[..16]
        .chunks(4)
        .map(|g| {
            g.iter()
                .map(|b| char::from(SETUP_CODE_ALPHABET[usize::from(b & 31)]))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-");
    let id: String = raw[16..].iter().map(|b| format!("{b:02x}")).collect();
    let email_hash = email.as_deref().map(crate::db::setup_email_hash);
    let email_mask = email.as_deref().map(mask_email);
    db.add_setup_code(
        &id,
        &setup_code_hash(&code),
        email_hash.as_deref(),
        email_mask.as_deref(),
        now_ms + ttl,
        now_ms,
    )
    .map_err(|e| e.to_string())?;
    Ok(IssuedSetupCode {
        code,
        id,
        expires_ms: now_ms + ttl,
        email_mask,
    })
}

/// 이메일 없는 조직 만들기 코드(1시간) — [`issue_setup_code`] 의 짧은 꼴.
///
/// # Errors
/// 난수·sqlite 오류(문자열).
pub fn bootstrap_setup_code(
    db: &crate::db::Db,
    rng: &dyn lodelai_effects::Rng,
    now_ms: i64,
) -> Result<String, String> {
    issue_setup_code(db, rng, now_ms, None, None).map(|c| c.code)
}

/// 등록 요청의 기기 공개키 검사: ed25519 → device_id 재계산, x25519 와 그 서명(`lodelai-xkey-v1`). 틀리면 `None`.
pub fn checked_device(p: &DevicePubkeys) -> Option<(DeviceId, VerifyingKey)> {
    let vk = VerifyingKey::from_b64(&p.ed25519).ok()?;
    let x25519 = lodelai_crypto::encoding::decode_array::<32>(&p.x25519, "x25519").ok()?;
    let device_id = DeviceId::from_verifying_key(&vk);
    lodelai_crypto::xkey::verify(&vk, device_id.as_str(), &x25519, &p.x25519_sig)
        .then_some((device_id, vk))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registered {
    pub user: String,
    pub device_id: String,
    pub server: String,
    /// hosted: 이미 있던 계정에 기기를 더했으면 `true`(#339), 이미 그 계정의 기기라 그대로면 `false`(#389). 새 계정·M1 은
    /// 싣지 않는다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<bool>,
}

/// 가입 코드 유효 시간(#339 설계 — 10분, 1회용).
pub const SIGNUP_CODE_TTL_MS: i64 = 10 * 60 * 1000;
/// 가입 토큰 유효 시간(30분, 1회용).
pub const SIGNUP_TOKEN_TTL_MS: i64 = 30 * 60 * 1000;
/// 가입 메일 상한(묶음 5, m1-spec §17.3): 이메일당 1시간 5번·하루 10번, relay 전체 UTC 하루 80통(Resend 무료 한도
/// 아래). IP 당 1시간 20번은 [`crate::SIGNUP_IP_PER_HOUR`](메모리).
pub const SIGNUP_LIMITS: crate::db::SignupLimits = crate::db::SignupLimits {
    per_email_hour: 5,
    per_email_day: 10,
    global_day: 80,
};
/// 사용자당 기기 등록 상한(security §6 — 이메일 탈취 뒤 폐기→재등록 반복): 24시간에 5대.
pub const DEVICE_ADD_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
pub const DEVICE_ADD_MAX: i64 = 5;

#[derive(Debug, Deserialize)]
pub struct Signup {
    pub email: String,
    /// 메일 언어 `ko`·`en`(없거나 그 밖은 en).
    #[serde(default)]
    pub locale: Option<String>,
    /// 동의한 처리방침 판(묶음 5). 없거나 지금 판과 다르면 422 — 메일·저장 전에.
    #[serde(default)]
    pub privacy: Option<PrivacyConsent>,
}

#[derive(Debug, Deserialize)]
pub struct PrivacyConsent {
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct SignupVerify {
    pub email: String,
    pub code: String,
}

/// `POST /v1/signup/verify` 의 응답(묶음 5 — `kind`·`account`).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignupToken {
    pub signup_token: String,
    /// `existing` = 그 이메일에 내보내지 않은 계정이 있다(내 다른 맥), `new` = 없다(내보낸 사람 포함).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<SignupAccount>,
    /// `new` 일 때만: 이 relay 가 코드 없이 조직 만들기를 받나(`open`) 아니면 코드가 있어야 하나(`code`)(묶음 18 §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_create: Option<String>,
    /// #737: `open` 이 서버 전체 설정이 아니라 이 이메일이 승인돼서다(대기 명단 — 앱은 처음부터 조직 만들기 화면).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
    /// #737: `org_create` 가 `code` 이고 이 relay 에 대기 명단 주소가 있으면 그 주소 — 앱은 코드 칸 대신 대기 명단 안내.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waitlist_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignupAccount {
    pub user: String,
    pub display_name: String,
    /// verify 의 `existing` 계정 조직 이름(묶음 18 §1). 초대 확인의 `inviter` 엔 없다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyVersion {
    pub version: String,
    /// 운영자 처리방침 주소(묶음 29 §1-4). 없으면 앱이 hosted 기본.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InviteCheck {
    pub signup_token: String,
    pub invite: String,
}

/// `POST /v1/invites/check` 의 응답(묶음 5).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteCheckInfo {
    pub org_name: String,
    pub inviter: SignupAccount,
    pub teams: Vec<DirectoryTeamJson>,
    /// 조직 사진 PNG(#554, base64url 패딩 없음 — 다른 바이트 칸과 같은 꼴). 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_avatar: Option<String>,
    /// 조직 id(#554 — 초대 화면 타일 색 키, 가입 뒤 디렉터리 `org.id` 와 같은 값). 유효한 초대일 때(200)만.
    pub org_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryTeamJson {
    pub id: String,
    pub name: String,
}

/// 이메일 정규화(#339) — 규칙은 `lodelai_protocol::email`(앱도 같은 함수로 미리 검사한다).
pub fn normalize_email(s: &str) -> Option<String> {
    lodelai_protocol::email::normalize(s)
}

fn code_hash(email: &str, code: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"lodelai-signup-code-v1\0");
    h.update(email.as_bytes());
    h.update(b"\0");
    h.update(code.as_bytes());
    h.finalize().to_vec()
}

/// 초대 토큰 해시(#355). 서버는 토큰을 보관하지 않는다.
pub fn invite_hash(token: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"lodelai-invite-v1\0");
    h.update(token.as_bytes());
    h.finalize().to_vec()
}

/// 가입 토큰 해시(서버는 토큰을 보관하지 않는다). 시험도 이 함수로 행을 찾는다.
pub fn signup_token_hash(token: &str) -> Vec<u8> {
    token_hash(token)
}

fn token_hash(token: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"lodelai-signup-token-v1\0");
    h.update(token.as_bytes());
    h.finalize().to_vec()
}

/// 균등한 6자리 숫자(거부 표본 — `% 1_000_000` 의 치우침 없음).
fn six_digits(app: &App) -> Option<String> {
    loop {
        let mut b = [0u8; 4];
        app.effects.rng.try_fill(&mut b).ok()?;
        let n = u32::from_le_bytes(b);
        if n < 4_000_000_000 {
            return Some(format!("{:06}", n % 1_000_000));
        }
    }
}

/// 요청의 IP 가 가입 상한 안인가(원격 relay 만 — 로컬은 모두 127.0.0.1, 묶음 5).
fn signup_ip_ok(app: &App, ip: Option<&Extension<ClientIp>>) -> bool {
    match ip {
        Some(Extension(ClientIp(Some(ip)))) if app.config.remote => {
            app.signup_ip_limiter.allow(ip, app.effects.clock.now())
        }
        _ => true,
    }
}

/// `GET /v1/privacy` → `{version, url?}`(묶음 5·29 §1-4). 판을 정하지 않은 relay(로컬 개발)는 404.
pub async fn privacy(State(app): State<App>) -> Response {
    match &app.config.privacy_version {
        Some(v) => Json(PrivacyVersion {
            version: v.clone(),
            url: app.config.privacy_url.clone(),
        })
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /v1/signup {email, locale?, privacy: {version}}`(#339·묶음 5): 6자리 코드를 만들어 메일로 보낸다. 계정이 있든
/// 없든 같은 202(열거 방지). 동의 판이 없거나 지금 판과 다르면 **메일·저장 전에** 422. 상한(이메일·IP·전역)을 넘으면 429
/// (요청 횟수일 뿐 계정 여부는 드러나지 않는다). 메일 서비스 실패는 503(사유 없음, 로그에도 주소·코드 없음).
pub async fn signup(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(mailer) = app.mailer.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // 서버 relay 는 가짜 메일로 코드를 내지 않는다(묶음 5) — 시험용 도메인만 예외. main 도 같은 조건으로 거부한다.
    if app.config.remote
        && mailer.is_dev()
        && !app
            .config
            .public_host
            .as_deref()
            .is_some_and(crate::is_test_domain)
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Ok(req) = serde_json::from_slice::<Signup>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let consented = req.privacy.as_ref().map(|p| p.version.trim()).filter(|v| {
        !v.is_empty()
            && app
                .config
                .privacy_version
                .as_deref()
                .is_none_or(|want| want == *v)
    });
    let Some(privacy_version) = consented.map(str::to_owned) else {
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    };
    let Some(email) = normalize_email(&req.email) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !signup_ip_ok(&app, ip.as_ref()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let locale = match req.locale.as_deref() {
        Some("ko") => "ko",
        _ => "en",
    };
    let Some(code) = six_digits(&app) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let now = app.effects.clock.now().0;
    let hash = code_hash(&email, &code);
    let e = email.clone();
    let limits = crate::db::SignupLimits {
        global_day: app.config.mail_per_day,
        ..SIGNUP_LIMITS
    };
    let stored = crate::blocking(&app, move |r| {
        r.db.signup_request(
            &e,
            &hash,
            now,
            now + SIGNUP_CODE_TTL_MS,
            &privacy_version,
            &limits,
        )
    })
    .await;
    match stored {
        Some(Ok(crate::db::SignupOutcome::Sent)) => {}
        Some(Ok(crate::db::SignupOutcome::Limited)) => {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        Some(Err(_)) | None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let sent = tokio::task::spawn_blocking(move || mailer.send_code(&email, &code, locale)).await;
    if !matches!(sent, Ok(Ok(()))) {
        let why = match &sent {
            Ok(Err(e)) => e.as_str(),
            _ => "작업 실패",
        };
        tracing::error!(why, "가입 코드 메일 실패");
        let _ = crate::blocking(&app, move |r| r.db.mail_failed(now)).await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::ACCEPTED.into_response()
}

/// `POST /v1/signup/verify {email, code}`(#339·묶음 5): 맞으면 200 `{signup_token, kind, account?}`(토큰 30분, 1회용).
/// 이메일 없음·틀림·만료·폐기(틀린 시도 5번)는 모두 같은 400 — 같은 DB 일을 하므로 응답 시간도 갈리지 않는다.
pub async fn signup_verify(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    body: axum::body::Bytes,
) -> Response {
    if app.mailer.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    // 가입 메일과 같은 IP 상한(원격) — 남의 이메일로 틀린 확인을 되풀이해 그 사람의 코드를 계속 지우지 못하게(설계 10-25).
    if !signup_ip_ok(&app, ip.as_ref()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(req) = serde_json::from_slice::<SignupVerify>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // 형식이 틀린 이메일·코드도 같은 응답(아래 DB 판정이 거짓으로 끝난다).
    let email = normalize_email(&req.email).unwrap_or_default();
    let mut raw = [0u8; 32];
    if app.effects.rng.try_fill(&mut raw).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let token = lodelai_crypto::encoding::encode(&raw);
    let (ch, th) = (code_hash(&email, req.code.trim()), token_hash(&token));
    let now = app.effects.clock.now().0;
    let verify_email = email.clone();
    let ok = crate::blocking(&app, move |r| {
        r.db.signup_verify(&verify_email, &ch, now, &th, now + SIGNUP_TOKEN_TTL_MS)
    })
    .await;
    // 로컬 relay 는 설정과 상관없이 코드 없이 만든다(묶음 18 §2).
    let org_create = if !app.config.remote || app.config.org_create_open {
        "open"
    } else {
        "code"
    };
    // #737: 서버 relay 의 `code` 모드에서도 승인된 이메일(이메일에 묶인 코드가 살아 있음)이면 `open` — 코드 칸 없이 만든다.
    // 이 값은 코드가 맞은 뒤(verify)에만 나간다 — start 응답은 이메일과 상관없이 같다.
    let (org_create, approved) = match &ok {
        Some(Ok(Some(None))) if org_create == "code" => {
            let e = email.clone();
            match crate::blocking(&app, move |r| r.db.org_create_allowed(&e, now)).await {
                Some(Ok(true)) => ("open", true),
                _ => (org_create, false),
            }
        }
        _ => (org_create, false),
    };
    match ok {
        Some(Ok(Some(existing))) => Json(SignupToken {
            signup_token: token,
            kind: if existing.is_some() {
                "existing"
            } else {
                "new"
            }
            .into(),
            approved: approved.then_some(true),
            waitlist_url: (existing.is_none() && org_create == "code")
                .then(|| app.config.waitlist_url.clone())
                .flatten(),
            org_create: existing.is_none().then(|| org_create.into()),
            account: existing.map(|a| SignupAccount {
                user: a.user,
                display_name: a.display,
                org_name: a.org_name,
            }),
        })
        .into_response(),
        Some(Ok(None)) => StatusCode::BAD_REQUEST.into_response(),
        Some(Err(_)) | None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /v1/invites/check {signup_token, invite}`(묶음 5): 200 `{org_name, org_id, inviter, teams, org_avatar?}`(#554). 가입 토큰을 **소비하지
/// 않는다**. 토큰 없음·끝남·확인 실패 10번, 초대 없음·끝남·쓰임은 모두 같은 404. IP 상한(원격) 429.
pub async fn invites_check(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    body: axum::body::Bytes,
) -> Response {
    if app.mailer.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !signup_ip_ok(&app, ip.as_ref()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(req) = serde_json::from_slice::<InviteCheck>(&body) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (th, ih) = (
        token_hash(&req.signup_token),
        invite_hash(req.invite.trim()),
    );
    let now = app.effects.clock.now().0;
    let checked = crate::blocking(&app, move |r| {
        r.db.invite_check(&th, &ih, now).map(|i| {
            i.map(|i| {
                let png = i
                    .org_avatar
                    .as_deref()
                    .and_then(|id| crate::blob::read_avatar(r, id));
                (i, png)
            })
        })
    })
    .await;
    match checked {
        Some(Ok(Some((i, png)))) => Json(InviteCheckInfo {
            org_name: i.org_name,
            inviter: SignupAccount {
                user: i.inviter,
                display_name: i.inviter_display,
                org_name: None,
            },
            teams: i
                .teams
                .into_iter()
                .map(|(id, name)| DirectoryTeamJson { id, name })
                .collect(),
            org_avatar: png.as_deref().map(lodelai_crypto::encoding::encode),
            org_id: i.org_id,
        })
        .into_response(),
        Some(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Some(Err(_)) | None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn valid_user(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// 길이가 같을 때만 비교하는 상수 시간 비교.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `Authorization: Bearer <등록 토큰>` 이 맞나. 토큰이 설정되지 않았으면 언제나 거짓.
fn authorized(app: &App, headers: &HeaderMap) -> bool {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    match (&app.config.registration_token, presented) {
        (Some(expected), Some(got)) => ct_eq(expected.as_bytes(), got.as_bytes()),
        _ => false,
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connected {
    pub users: Vec<String>,
}

/// `GET /v1/connected`(등록 토큰, #328): 폐기되지 않은 기기로 지금 ws 인증된 연결이 하나 이상 있는 사용자(이름순).
/// 주인 넘기기 후보의 "연결됨" 표시용 — 폐기된 기기의 연결은 폐기 때 닫힌다.
pub async fn connected(State(app): State<App>, headers: HeaderMap) -> Response {
    if !authorized(&app, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut users = app.conns.users();
    users.sort();
    Json(Connected { users }).into_response()
}

/// `POST /v1/wipe`(등록 토큰, #328 주인 혼자 로그아웃): `secure_delete` 를 켠 채 모든 행을 지우고 WAL 을 잘라낸 뒤 200 으로
/// 답하고, 연결을 전부 닫고 서버를 끝낸다(프로세스 종료). 그 뒤 들어오는 요청은 503. 앱은 응답을 받고 자식이 끝나길 기다린 뒤
/// relay 폴더를 지운다.
pub async fn wipe(State(app): State<App>, headers: HeaderMap) -> Response {
    if !authorized(&app, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    app.wiped.store(true, std::sync::atomic::Ordering::SeqCst);
    match crate::blocking(&app, |r| {
        crate::blob::wipe(r);
        r.db.wipe()
    })
    .await
    {
        Some(Ok(())) => {}
        Some(Err(e)) => {
            tracing::error!(error = %e, "relay 정리 실패");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    tracing::info!("relay 정리 — 종료");
    app.conns.close_all();
    // 응답이 나간 뒤 끝나도록 서버 종료는 조금 미룬다.
    let stop = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stop.stop.notify_one();
    });
    StatusCode::OK.into_response()
}

/// 토큰을 본문 파싱보다 먼저 본다 — 토큰 없는 호출자는 본문이 어떻든 401 만 받는다.
pub async fn register_device(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 원격 relay 는 등록 토큰 경로가 없다(#364) — 가입 토큰(이메일 코드)으로만 등록한다(묶음 5). 인증 전 시도 IP 상한.
    if app.config.remote {
        if let Some(Extension(ClientIp(Some(ip)))) = &ip {
            if !app.ip_limiter.allow(ip, app.effects.clock.now()) {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
        }
    }
    let m1 = !app.config.remote && authorized(&app, &headers);
    // 등록 토큰이 없으면 hosted 가입이 켜져 있을 때만 본문을 본다(가입 토큰은 본문에 있다).
    if !m1 && app.mailer.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(req) = serde_json::from_slice::<RegisterDevice>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !m1 && req.signup_token.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if req.user.as_deref().is_some_and(|u| !valid_user(u)) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // 표시 이름은 profile.update 와 같은 규칙(#326) — 앞뒤 공백을 뺀 값을 저장한다.
    let display = match req.display_name.as_deref() {
        None => None,
        Some(d) => match lodelai_protocol::display_name::normalize(d) {
            Ok(d) => Some(d),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    let Some((device_id, vk)) = checked_device(&req.device_pubkeys) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let now = app.effects.clock.now().0;
    if !m1 {
        return register_hosted(&app, ip, req, display, device_id, vk, now).await;
    }
    let Some(req_user) = req.user else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (user, display, id, ed, x, xsig) = (
        req_user.clone(),
        display,
        device_id.as_str().to_owned(),
        vk.to_b64(),
        req.device_pubkeys.x25519.clone(),
        req.device_pubkeys.x25519_sig.clone(),
    );
    let existing = req.existing_user;
    let stored = crate::blocking(&app, move |r| {
        let res = r.db.register_device(
            &user,
            display.as_deref(),
            &id,
            &ed,
            &x,
            &xsig,
            now,
            existing,
        );
        // 새 사람·새 기기는 같은 조직의 디렉터리(사람·기기 공개키)를 바꾼다 — 접속 중인 코어에 바로 알린다
        // (주인 앱의 기기 추가가 기존 아이디를 대조하는 근거, #67).
        if res.is_ok() {
            crate::ws::broadcast_directory(
                r,
                &crate::rules::Authed {
                    user,
                    device_id: id,
                    // 디렉터리 알림의 보낸 쪽 표시일 뿐 — 연결 판과 무관.
                    v: u64::from(lodelai_protocol::PROTOCOL_VERSION),
                },
            );
        }
        res
    })
    .await;
    match stored {
        Some(Ok(())) => {}
        Some(Err(crate::db::DbError::TooManyDevices)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "too_many_devices"})),
            )
                .into_response();
        }
        Some(Err(crate::db::DbError::Conflict)) => return StatusCode::CONFLICT.into_response(),
        Some(Err(crate::db::DbError::UserExists)) => return StatusCode::FORBIDDEN.into_response(),
        Some(Err(_)) | None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    (
        StatusCode::CREATED,
        Json(Registered {
            user: req_user,
            device_id: device_id.as_str().to_owned(),
            server: app.config.server_name.clone(),
            added: None,
        }),
    )
        .into_response()
}

/// 거절 사유가 있는 응답 `{reason}`(묶음 18 — `account_exists`·`org_rate_limited`·`org_create_closed`).
fn reason(status: StatusCode, why: &str) -> Response {
    (status, Json(serde_json::json!({ "reason": why }))).into_response()
}

/// 맞는 조직 만들기 코드인데 쓸 수 없을 때(relay 0.1.2): 422 + 이유·사람 글(ko·en, 용어집 `account.setup_code.*`).
/// 옛 앱(0.1.x)은 422 를 '쓸 수 없는 코드'로 보이고, 새 앱은 `reason` 으로 문구를 고른다. 403·409 를 쓰면 옛 앱이 다른 오류로 보인다.
fn setup_code_refused(why: &str, mask: Option<&str>) -> Response {
    let mask = mask.filter(|m| !m.is_empty());
    let (ko, en) = setup_code_message(why, mask);
    let mut body = serde_json::json!({ "reason": why, "message": { "ko": ko, "en": en } });
    if let Some(m) = mask {
        body["email"] = serde_json::json!(m);
    }
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

/// [`setup_code_refused`] 의 사람 글(ko·en). 다른 이메일인데 가린 꼴이 없으면(손으로 넣은 행 등) 기한 문구가 아니라 앱의
/// 일반 '쓸 수 없는 코드' 문구(`error.invalid_invite`)로 떨어진다.
fn setup_code_message(why: &str, mask: Option<&str>) -> (String, String) {
    match (why, mask) {
        ("setup_code_other_email", Some(m)) => (
            format!("{m} 로 가입할 때만 쓸 수 있는 코드예요"),
            format!("This code only works if you sign up with {m}"),
        ),
        ("setup_code_expired", _) => (
            "기한이 지난 조직 만들기 코드예요".to_owned(),
            "This organization code has expired".to_owned(),
        ),
        _ => (
            "쓸 수 없는 코드예요".to_owned(),
            "This code can't be used".to_owned(),
        ),
    }
}

/// 429 + `Retry-After`(초, 올림) — 조직 만들기 코드 늦춤(relay 0.1.2, `reason` 없음: 옛 앱은 '시도가 너무 많아요').
fn slow_down(retry_ms: i64) -> Response {
    let secs = (retry_ms.max(1) + 999) / 1000;
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, secs.to_string())],
    )
        .into_response()
}

/// 409 `{reason: account_exists, account}`(묶음 18) — 경합으로 다른 기기가 먼저 가입했을 때 앱이 친 아이디로 계정을
/// 지어내지 않게 그 계정을 싣는다. 이메일 주인 확인(가입 토큰) 뒤라 열거가 아니다.
fn account_exists(a: &crate::db::ExistingAccount) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "reason": "account_exists",
            "account": SignupAccount {
                user: a.user.clone(),
                display_name: a.display.clone(),
                org_name: a.org_name.clone(),
            },
        })),
    )
        .into_response()
}

/// hosted 경로(#339): 가입 토큰 소모 + 새 계정 또는 그 이메일 계정에 기기 추가. 같은 조직에 directory.update — 내 다른
/// 기기는 그 안의 자기 `devices[]` 에서 새 기기를 본다.
async fn register_hosted(
    app: &App,
    ip: Option<Extension<ClientIp>>,
    req: RegisterDevice,
    display: Option<String>,
    device_id: DeviceId,
    vk: VerifyingKey,
    now: i64,
) -> Response {
    let Some(token) = req.signup_token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let id = device_id.as_str().to_owned();
    let (th, user, ed) = (token_hash(&token), req.user, vk.to_b64());
    let (x, xsig) = (req.device_pubkeys.x25519, req.device_pubkeys.x25519_sig);
    // 조직(#355): 이름은 표시 이름 규칙, 새 조직 id 는 여기서 만든다, 초대 토큰은 해시로.
    enum Org {
        Create(
            String,
            String,
            Option<Vec<u8>>,
            Option<crate::db::OrgQuota>,
            bool,
        ),
        Invite(Vec<u8>),
    }
    // 코드 없는 만들기의 IP(묶음 18 §3) — 모르면 IP 상한만 건너뛴다.
    let client_ip = match &ip {
        Some(Extension(ClientIp(Some(ip)))) => Some(ip.clone()),
        _ => None,
    };
    let mut counts_ip = false;
    let org = match req.org {
        None => None,
        Some(OrgRequest::Create { name, setup_code }) => {
            let Ok(n) = lodelai_protocol::display_name::normalize(&name) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            // 서버 relay(묶음 18 거절 순서): 토큰·기존 계정 → 코드를 줬으면 코드 검사(맞으면 상한 밖) → `code` 모드는 코드 없이
            // 거부 → `open` 이면 상한(등록 트랜잭션 안). 틀린 코드는 초대 실패와 같은 422(이유를 가르지 않음), 맞는 코드의 만료·다른
            // 이메일은 이유를 싣는 422(relay 0.1.2), 마구 두드리기는 429(메모리 늦춤). 거절은 모두 토큰을 쓰지 않는다.
            let (hash, quota, allowed) = if app.config.remote {
                let th = th.clone();
                let email = match crate::blocking(app, move |r| r.db.signup_token_account(&th, now))
                    .await
                {
                    Some(Ok(Some((email, None)))) => email,
                    Some(Ok(Some((_, Some(a))))) => return account_exists(&a),
                    Some(Ok(None)) => return StatusCode::UNAUTHORIZED.into_response(),
                    Some(Err(_)) | None => {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                };
                match setup_code {
                    Some(code) => {
                        // relay 0.1.2 늦춤: 전체·IP 는 모든 시도, 이메일은 틀린 코드만 센다. 막혀 있으면 코드를 보지 않는다.
                        let clock = app.effects.clock.now();
                        let ip_key = client_ip.as_deref();
                        let blocked = [
                            app.setup_code_all.blocked("all", clock),
                            ip_key.and_then(|ip| app.setup_code_ip.blocked(ip, clock)),
                            app.setup_code_email_fails.blocked(&email, clock),
                        ]
                        .into_iter()
                        .flatten()
                        .max();
                        if let Some(ms) = blocked {
                            return slow_down(ms);
                        }
                        if app.setup_code_all.hit("all", clock) {
                            tracing::warn!("조직 만들기 코드 시도가 relay 전체 상한에 닿았다 — 1시간 받지 않는다");
                        }
                        if let Some(ip) = ip_key {
                            app.setup_code_ip.hit(ip, clock);
                        }
                        let h = setup_code_hash(&code);
                        let check = h.clone();
                        let eh = normalize_email(&email);
                        match crate::blocking(app, move |r| {
                            r.db.check_setup_code(&check, eh.as_deref(), now)
                        })
                        .await
                        {
                            Some(Ok(crate::db::SetupCheck::Ok)) => {}
                            Some(Ok(crate::db::SetupCheck::Expired)) => {
                                return setup_code_refused("setup_code_expired", None);
                            }
                            Some(Ok(crate::db::SetupCheck::OtherEmail(mask))) => {
                                return setup_code_refused("setup_code_other_email", Some(&mask));
                            }
                            Some(Ok(crate::db::SetupCheck::Wrong)) => {
                                app.setup_code_email_fails.hit(&email, clock);
                                return StatusCode::UNPROCESSABLE_ENTITY.into_response();
                            }
                            Some(Err(_)) | None => {
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response()
                            }
                        }
                        (Some(h), None, false)
                    }
                    // #737: 대기 명단에서 승인된 이메일(이메일에 묶인 코드가 살아 있음)은 코드 없이 만든다 — 그 행을 쓴다.
                    None if !app.config.org_create_open => {
                        let e = email.clone();
                        match crate::blocking(app, move |r| r.db.org_create_allowed(&e, now)).await
                        {
                            Some(Ok(true)) => (None, None, true),
                            Some(Ok(false)) => {
                                return StatusCode::UNPROCESSABLE_ENTITY.into_response()
                            }
                            Some(Err(_)) | None => {
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response()
                            }
                        }
                    }
                    None => {
                        let l = app.config.org_create_limits;
                        let ip_over = client_ip.as_deref().is_some_and(|ip| {
                            !app.org_create_ip_limiter
                                .would_allow(ip, app.effects.clock.now())
                        });
                        counts_ip = client_ip.is_some();
                        (
                            None,
                            Some(crate::db::OrgQuota {
                                per_email_30d: l.per_email_30d,
                                per_day: l.per_day,
                                max_orgs: l.max_orgs,
                                ip_over,
                            }),
                            false,
                        )
                    }
                }
            } else {
                (None, None, false)
            };
            Some(Org::Create(
                app.effects.ids.next_ulid(),
                n,
                hash,
                quota,
                allowed,
            ))
        }
        Some(OrgRequest::Invite(token)) => Some(Org::Invite(invite_hash(token.trim()))),
    };
    let created = match &org {
        Some(Org::Create(id, ..)) => Some(id.clone()),
        _ => None,
    };
    let teams = req.teams;
    let stored = crate::blocking(app, move |r| {
        let org = org.as_ref().map(|o| match o {
            Org::Create(id, name, h, quota, allowed) => crate::db::OrgChoice::Create {
                id,
                name,
                setup_code_hash: h.as_deref(),
                quota: *quota,
                allowed_email: *allowed,
            },
            Org::Invite(h) => crate::db::OrgChoice::Invite { token_hash: h },
        });
        let res = r.db.register_hosted(&crate::db::HostedDevice {
            token_hash: &th,
            user: user.as_deref(),
            display: display.as_deref(),
            device_id: &id,
            ed25519: &ed,
            x25519: &x,
            x25519_sig: &xsig,
            now_ms: now,
            window_ms: DEVICE_ADD_WINDOW_MS,
            max_devices: DEVICE_ADD_MAX,
            org,
            teams: &teams,
        });
        // 같은 기기로 다시 가입(#389)은 아무것도 바뀌지 않았다 — 알리지 않는다.
        if let Some(reg) = res.as_ref().ok().filter(|reg| !reg.rejoined) {
            crate::ws::broadcast_directory(
                r,
                &crate::rules::Authed {
                    user: reg.user.clone(),
                    device_id: id,
                    v: u64::from(lodelai_protocol::PROTOCOL_VERSION),
                },
            );
        }
        res
    })
    .await;
    let reg = match stored {
        Some(Ok(reg)) => reg,
        Some(Err(crate::db::DbError::BadToken)) => return StatusCode::UNAUTHORIZED.into_response(),
        Some(Err(crate::db::DbError::UserMismatch | crate::db::DbError::Conflict)) => {
            return StatusCode::CONFLICT.into_response();
        }
        Some(Err(crate::db::DbError::TooManyDevices)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "too_many_devices"})),
            )
                .into_response();
        }
        Some(Err(crate::db::DbError::DeviceTaken)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "device_taken"})),
            )
                .into_response();
        }
        Some(Err(crate::db::DbError::UserExists)) => return StatusCode::FORBIDDEN.into_response(),
        Some(Err(crate::db::DbError::MissingUser | crate::db::DbError::BadOrg)) => {
            return StatusCode::BAD_REQUEST.into_response();
        }
        // 초대 토큰 실패는 사유를 가르지 않는다(없음·만료·사용됨·이메일 불일치, #355).
        Some(Err(crate::db::DbError::BadInvite)) => {
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        Some(Err(crate::db::DbError::RateLimited)) => {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        Some(Err(crate::db::DbError::AccountExists(a))) => return account_exists(&a),
        Some(Err(crate::db::DbError::OrgClosed)) => {
            return reason(StatusCode::FORBIDDEN, "org_create_closed");
        }
        Some(Err(crate::db::DbError::OrgRateLimited)) => {
            return reason(StatusCode::TOO_MANY_REQUESTS, "org_rate_limited");
        }
        Some(Err(_)) | None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if let Some(org) = created.as_ref().filter(|_| !reg.rejoined) {
        // IP 셈은 메모리라 성공한 뒤에 올린다(경합으로 1~2번 넘는 것은 허용, 911544fe).
        if let Some(ip) = client_ip.as_deref().filter(|_| counts_ip) {
            app.org_create_ip_limiter.allow(ip, app.effects.clock.now());
        }
        tracing::info!(org = %org, "조직 만들기");
    }
    tracing::info!(user = %reg.user, device = %device_id.as_str(), added = reg.added, rejoined = reg.rejoined, "hosted 기기 등록");
    (
        if reg.rejoined {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(Registered {
            user: reg.user,
            device_id: device_id.as_str().to_owned(),
            server: app.config.server_name.clone(),
            added: (reg.added || reg.rejoined).then_some(reg.added),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn setup_code_message_falls_back_without_a_mask() {
        // 다른 이메일인데 가린 꼴이 없으면 '기한 지남'이 아니라 일반 '쓸 수 없는 코드'(코어 대조 11-01).
        for mask in [None, Some("")] {
            let (ko, en) = super::setup_code_message(
                "setup_code_other_email",
                mask.filter(|m: &&str| !m.is_empty()),
            );
            assert_eq!(
                (ko.as_str(), en.as_str()),
                ("쓸 수 없는 코드예요", "This code can't be used")
            );
        }
        assert_eq!(
            super::setup_code_message("setup_code_other_email", Some("b***@x…")).0,
            "b***@x… 로 가입할 때만 쓸 수 있는 코드예요"
        );
        assert_eq!(
            super::setup_code_message("setup_code_expired", None).1,
            "This organization code has expired"
        );
    }

    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn host_and_origin() {
        let mut h = HeaderMap::new();
        assert!(!host_allowed(&h, 5000), "Host 없음");
        h.insert(header::HOST, HeaderValue::from_static("127.0.0.1:5000"));
        assert!(host_allowed(&h, 5000));
        assert!(!host_allowed(&h, 5001), "다른 포트");
        h.insert(header::HOST, HeaderValue::from_static("localhost:5000"));
        assert!(host_allowed(&h, 5000));
        h.insert(header::HOST, HeaderValue::from_static("evil.example:5000"));
        assert!(!host_allowed(&h, 5000), "DNS rebinding");
        h.insert(header::HOST, HeaderValue::from_static("127.0.0.1:5000"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:5000"),
        );
        assert!(!host_allowed(&h, 5000), "Origin 있으면 거부");
    }

    #[test]
    fn public_host_only_when_configured() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("lodelai.example"));
        assert!(!host_allowed(&h, 5000));
        assert!(host_allowed_with(&h, 5000, Some("lodelai.example")));
        h.insert(
            header::HOST,
            HeaderValue::from_static("lodelai.example:443"),
        );
        assert!(host_allowed_with(&h, 5000, Some("lodelai.example")));
        h.insert(
            header::HOST,
            HeaderValue::from_static("lodelai.example.evil"),
        );
        assert!(!host_allowed_with(&h, 5000, Some("lodelai.example")));
    }

    #[test]
    fn cf_connecting_ip_only_from_loopback_behind_cloudflare() {
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
        let lo: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let lan: SocketAddr = "192.168.0.20:50000".parse().unwrap();
        assert_eq!(
            client_ip(Some(lo), &h, true).as_deref(),
            Some("203.0.113.9")
        );
        // 위조: loopback 이 아닌 연결의 헤더, 또는 Cloudflare 뒤가 아닐 때는 무시.
        assert_eq!(
            client_ip(Some(lan), &h, true).as_deref(),
            Some("192.168.0.20")
        );
        assert_eq!(client_ip(Some(lo), &h, false).as_deref(), Some("127.0.0.1"));
        // 형식이 IP 가 아니면 연결 주소.
        h.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(Some(lo), &h, true).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn ipv6_limit_key_is_the_64_prefix() {
        let key = |s: &str| limit_key(s.parse().unwrap());
        assert_eq!(key("203.0.113.9"), "203.0.113.9");
        assert_eq!(key("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(key("2001:db8:1:2:bbbb:cccc:dddd:eeee"), "2001:db8:1:2::/64");
        assert_ne!(key("2001:db8:1:3::1"), key("2001:db8:1:2::1"));
    }

    #[test]
    fn setup_code_shape_and_hash_canon() {
        let db = crate::db::Db::memory().unwrap();
        let code = bootstrap_setup_code(&db, &lodelai_effects::OsRng, 0).unwrap();
        assert_eq!(code.len(), 19);
        assert!(code
            .split('-')
            .all(|g| g.len() == 4 && g.bytes().all(|b| SETUP_CODE_ALPHABET.contains(&b))));
        assert_eq!(
            setup_code_hash(&code),
            setup_code_hash(&format!(
                "  {}  ",
                code.to_ascii_lowercase().replace('-', "")
            ))
        );
    }

    #[test]
    fn user_pattern_and_ct_eq() {
        assert!(valid_user("dana"));
        assert!(valid_user("a.b_c-1"));
        assert!(!valid_user("Dana"));
        assert!(!valid_user("-dana"));
        assert!(!valid_user(""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
