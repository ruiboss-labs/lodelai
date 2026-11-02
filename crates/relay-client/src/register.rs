//! 기기 등록(`POST /v1/devices`, 등록 토큰)과 두 번째 프로필용 "기기 연결 코드"(protocol §7.1, #108).
//! hosted 가입·기기 추가(#339): [`signup_start`] → 메일의 6자리 코드 → [`signup_verify`] → [`register_device_hosted`].
//!
//! M1 로컬 relay 는 `127.0.0.1` 평문 HTTP 라 작은 HTTP/1.1 클라이언트로 충분하다(hosted M2 는 TLS 클라이언트로 바꾼다).

use std::net::SocketAddr;

use lodelai_crypto::{encoding, jcs, xkey, DeviceId, DeviceKeys, VerifyingKey};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Error, Result};

/// 등록 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registered {
    Created {
        device_id: String,
    },
    /// 이미 등록된 같은 기기(재기동). 성공으로 본다.
    AlreadyRegistered {
        device_id: String,
    },
}

/// 등록 요청 본문(공개 정보만).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub user: String,
    pub display_name: Option<String>,
    pub ed25519: String,
    pub x25519: String,
    /// x25519 를 이 기기 키에 묶는 서명(#313, `lodelai-xkey-v1`).
    pub x25519_sig: String,
    pub device_id: String,
}

impl DeviceInfo {
    pub fn of(user: &str, display_name: Option<&str>, keys: &DeviceKeys) -> Self {
        let device_id = keys.device_id().as_str().to_owned();
        let x = keys.exchange.public_key();
        Self {
            user: user.to_owned(),
            display_name: display_name.map(str::to_owned),
            ed25519: keys.signing.verifying_key().to_b64(),
            x25519: encoding::encode(&x),
            x25519_sig: xkey::sign(&keys.signing, &device_id, &x),
            device_id,
        }
    }

    fn body(&self) -> Value {
        let mut b = json!({"user": self.user, "device_pubkeys": {"ed25519": self.ed25519, "x25519": self.x25519, "x25519_sig": self.x25519_sig}});
        if let Some(d) = &self.display_name {
            b["display_name"] = json!(d);
        }
        b
    }
}

/// `POST /v1/devices` (등록 토큰). relay 주인 앱이 자기 기기와, 승인한 두 번째 프로필 기기를 등록할 때 쓴다.
///
/// # Errors
/// 연결 실패·401·400·그 밖의 응답.
pub async fn register_device(
    addr: SocketAddr,
    token: &str,
    info: &DeviceInfo,
) -> Result<Registered> {
    register_device_with(addr, token, info, false).await
}

/// [`register_device`] + `existing_user`: 이미 있는 사용자에 이 기기를 더해도 된다(주인 자신의 다른 기기). 거짓이면
/// 이미 있는 사용자는 [`Error::UserExists`](relay 가 판정한다, #298).
///
/// # Errors
/// 연결 실패·401·403(이미 있는 사용자)·400·그 밖의 응답.
pub async fn register_device_with(
    addr: SocketAddr,
    token: &str,
    info: &DeviceInfo,
    existing_user: bool,
) -> Result<Registered> {
    let mut body = info.body();
    if existing_user {
        body["existing_user"] = json!(true);
    }
    let (code, resp) = request(addr, "POST", "/v1/devices", token, &body.to_string()).await?;
    match code {
        201 => Ok(Registered::Created {
            device_id: info.device_id.clone(),
        }),
        409 if too_many_devices(&resp) => Err(Error::DeviceLimit),
        409 => Ok(Registered::AlreadyRegistered {
            device_id: info.device_id.clone(),
        }),
        401 => Err(Error::Relay("등록 토큰이 맞지 않는다".into())),
        403 => Err(Error::UserExists),
        c => Err(Error::Relay(format!("기기 등록 실패: HTTP {c}"))),
    }
}

/// 서버 relay 의 개인정보 처리방침(`GET /v1/privacy` → `{version, url?}`, 묶음 5·29 §1-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privacy {
    /// 지금 판(가입 동의에 싣는 값).
    pub version: String,
    /// 운영자 처리방침 주소(그대로 — https 판정은 화면·여는 쪽). 없으면 hosted 기본.
    pub url: Option<String>,
}

/// [`Privacy`] 를 받는다. 앱은 ①a 를 열 때·계정이 있으면 기동 때 받아 둔다.
///
/// # Errors
/// 닿지 않음 [`Error::Unreachable`], 그 밖의 응답·형식 `Error::Relay`.
pub async fn privacy(ws_url: &str) -> Result<Privacy> {
    let (status, body) = http(ws_url, "GET", "/v1/privacy", None).await?;
    match status {
        200 => {
            let v = serde_json::from_str::<Value>(&body)
                .map_err(|_| Error::Relay("응답 형식: privacy".into()))?;
            let version = v["version"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::Relay("응답 형식: version".into()))?;
            let url = v["url"].as_str().map(str::to_owned);
            Ok(Privacy { version, url })
        }
        c => Err(Error::Relay(format!("처리방침 판 실패: HTTP {c}"))),
    }
}

/// [`privacy`] 의 판만.
///
/// # Errors
/// [`privacy`] 와 같다.
pub async fn privacy_version(ws_url: &str) -> Result<String> {
    privacy(ws_url).await.map(|p| p.version)
}

/// 가입 확인 메일을 요청한다(`POST /v1/signup {email, locale?, privacy: {version}}`, #339·묶음 5). 계정이 있든 없든 같은
/// 답이다(열거 방지). `locale` 은 `ko`·`en`(없으면 relay 가 en).
///
/// # Errors
/// 동의 판이 없거나 옛 판 [`Error::PrivacyRequired`](422 — 메일·저장 전에 막힘), 이메일 형식 [`Error::InvalidEmail`](400),
/// 발송 상한 [`Error::RateLimited`](429 — 이메일·IP·전역), 메일 서비스 실패 [`Error::EmailUnavailable`](503), 닿지 않음
/// [`Error::Unreachable`].
pub async fn signup_start(
    ws_url: &str,
    email: &str,
    locale: Option<&str>,
    privacy_version: &str,
) -> Result<()> {
    let mut body = json!({"email": email, "privacy": {"version": privacy_version}});
    if let Some(l) = locale {
        body["locale"] = json!(l);
    }
    match http(ws_url, "POST", "/v1/signup", Some(&body.to_string()))
        .await?
        .0
    {
        202 => Ok(()),
        400 => Err(Error::InvalidEmail),
        422 => Err(Error::PrivacyRequired),
        429 => Err(Error::RateLimited),
        503 => Err(Error::EmailUnavailable),
        c => Err(Error::Relay(format!("가입 메일 요청 실패: HTTP {c}"))),
    }
}

/// 이메일에 이미 있는 계정(`kind: existing`, 묶음 5). 이메일 주인 확인 뒤라 열거가 아니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAccount {
    pub user: String,
    pub display_name: String,
    /// 그 계정의 조직 이름(묶음 18 §1 — 옛 relay·조직 없는 relay 면 없음). '이 이메일은 이미 {조직 이름}에 있어요'.
    pub org_name: Option<String>,
}

/// [`signup_verify`] 의 결과. `existing` 이 있으면 내 다른 맥(`kind=existing`), 없으면 새 사람(`new` — 내보낸 사람 포함).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupVerified {
    /// 가입 토큰(30분, 1회용). **코어 메모리에만** — UI·로그·DB 로 내보내지 않는다.
    pub signup_token: String,
    pub existing: Option<ExistingAccount>,
    /// 새 사람일 때 relay 가 코드 없이 조직 만들기를 받는다(묶음 18 §2 `org_create: open`). 거짓(`code`·옛 relay)이면 코드 칸.
    pub org_create_open: bool,
    /// #737: 새 사람이고 코드가 있어야 할 때(`code`) relay 의 대기 명단 주소(https 만) — 화면은 코드 칸 대신 대기 명단 안내.
    pub waitlist_url: Option<String>,
    /// #737: `open` 이 이 이메일 승인(대기 명단) 때문이다 — 서버 전체 `open`(자체 호스팅)과 갈라, 화면이 처음부터 조직 만들기로.
    pub approved: bool,
}

/// 메일의 6자리 코드를 가입 토큰으로 바꾼다(`POST /v1/signup/verify`, #339·묶음 5). 틀림·만료·폐기(5번 틀림)·모르는
/// 이메일은 relay 가 같은 400 으로 답한다 → [`Error::InvalidCode`].
///
/// # Errors
/// 코드가 맞지 않음 [`Error::InvalidCode`], 닿지 않음 [`Error::Unreachable`], 응답 형식 `Error::Relay`.
pub async fn signup_verify(ws_url: &str, email: &str, code: &str) -> Result<SignupVerified> {
    let body = json!({"email": email, "code": code}).to_string();
    let (status, resp) = http(ws_url, "POST", "/v1/signup/verify", Some(&body)).await?;
    match status {
        200 => {
            let v: Value =
                serde_json::from_str(&resp).map_err(|e| Error::Relay(format!("응답 형식: {e}")))?;
            let signup_token = v["signup_token"]
                .as_str()
                .ok_or_else(|| Error::Relay("응답 형식: signup_token".into()))?
                .to_owned();
            let existing = (v["kind"] == "existing")
                .then(|| {
                    Some(ExistingAccount {
                        user: v["account"]["user"].as_str()?.to_owned(),
                        display_name: v["account"]["display_name"].as_str()?.to_owned(),
                        org_name: v["account"]["org_name"].as_str().map(str::to_owned),
                    })
                })
                .flatten();
            if v["kind"] == "existing" && existing.is_none() {
                return Err(Error::Relay("응답 형식: account".into()));
            }
            let org_create_open = existing.is_none() && v["org_create"] == "open";
            let waitlist_url = (existing.is_none() && !org_create_open)
                .then(|| v["waitlist_url"].as_str())
                .flatten()
                .filter(|u| u.starts_with("https://") && u.len() <= 512)
                .map(str::to_owned);
            Ok(SignupVerified {
                approved: org_create_open && v["approved"] == true,
                org_create_open,
                waitlist_url,
                signup_token,
                existing,
            })
        }
        400 => Err(Error::InvalidCode),
        c => Err(Error::Relay(format!("가입 코드 확인 실패: HTTP {c}"))),
    }
}

/// 초대한 관리자(`invites.created_by`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inviter {
    pub user: String,
    pub display_name: String,
}

/// 조직의 팀 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamInfo {
    pub id: String,
    pub name: String,
}

/// [`invites_check`] 의 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub org_name: String,
    pub inviter: Inviter,
    pub teams: Vec<TeamInfo>,
    /// 조직 사진 PNG 바이트(#554 — 응답 `org_avatar`, base64url 패딩 없음). 없거나 풀 수 없으면 `None`(타일로). 검사·축소는
    /// 받는 쪽(코어)이 한다.
    pub org_avatar: Option<Vec<u8>>,
    /// 조직 id(#554 — 응답 `org_id`, 가입 뒤 디렉터리 `org.id` 와 같은 값). 옛 relay 면 `None`.
    pub org_id: Option<String>,
}

/// 초대 코드 확인(`POST /v1/invites/check {signup_token, invite}`, 묶음 5). 가입 토큰을 **소비하지 않는다**.
///
/// # Errors
/// 쓸 수 없는 초대(없음·끝남·쓰임 — 가르지 않음)·가입 토큰 없음 [`Error::InvalidInvite`](404·401), 시도 상한
/// [`Error::RateLimited`](429), 닿지 않음 [`Error::Unreachable`], 응답 형식 `Error::Relay`.
pub async fn invites_check(ws_url: &str, signup_token: &str, invite: &str) -> Result<InviteInfo> {
    let body = json!({"signup_token": signup_token, "invite": invite}).to_string();
    let (status, resp) = http(ws_url, "POST", "/v1/invites/check", Some(&body)).await?;
    match status {
        200 => {
            let v: Value =
                serde_json::from_str(&resp).map_err(|e| Error::Relay(format!("응답 형식: {e}")))?;
            let s = |x: &Value| x.as_str().map(str::to_owned);
            let bad = || Error::Relay("응답 형식: invites/check".into());
            Ok(InviteInfo {
                org_name: s(&v["org_name"]).ok_or_else(bad)?,
                inviter: Inviter {
                    user: s(&v["inviter"]["user"]).ok_or_else(bad)?,
                    display_name: s(&v["inviter"]["display_name"]).ok_or_else(bad)?,
                },
                teams: v["teams"]
                    .as_array()
                    .ok_or_else(bad)?
                    .iter()
                    .map(|t| {
                        Some(TeamInfo {
                            id: s(&t["id"])?,
                            name: s(&t["name"])?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(bad)?,
                org_id: s(&v["org_id"]),
                org_avatar: v["org_avatar"]
                    .as_str()
                    .and_then(|b| lodelai_crypto::encoding::decode(b, "org_avatar").ok())
                    .filter(|b| b.len() as u64 <= lodelai_protocol::constants::AVATAR_MAX_BYTES),
            })
        }
        401 | 404 => Err(Error::InvalidInvite),
        429 => Err(Error::RateLimited),
        c => Err(Error::Relay(format!("초대 확인 실패: HTTP {c}"))),
    }
}

/// hosted 등록 결과(#339).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRegistered {
    /// 서버가 정한 아이디(이메일에 계정이 있으면 그 계정, 내보낸 사람이 새 초대로 오면 옛 아이디).
    pub user: String,
    pub device_id: String,
    /// 이미 있던 계정에 기기를 더했다(내 다른 맥·분실 복구).
    pub added: bool,
    /// relay 의 서버 이름(`server_name`). 앱이 서명하는 접속 호스트와 다르면 WS 인증이 늘 실패한다(22 §12-29 ③ 그물).
    pub server: Option<String>,
}

/// 가입 토큰으로 이 기기를 등록한다(`POST /v1/devices {signup_token}`, #339 결정 D·묶음 5). 새 계정은 `org` 가 있어야
/// 한다(`teams` 는 초대로 들어갈 때 그 조직 팀만). `user` 는 새 계정일 때만 필요하다 — 이메일에 계정이 있으면 서버가 그
/// 계정에 기기를 더하고 `added` 로 알린다.
///
/// # Errors
/// 가입 토큰 없음·만료·사용됨 [`Error::InvalidCode`](401 → 앱 `expired`), 남이 쓰는 아이디 [`Error::UserExists`](403),
/// 초대·조직 만들기 코드가 맞지 않거나 코드가 있어야 하는 relay 에 코드 없이 만듦 [`Error::InvalidInvite`](422 — 이유를
/// 가르지 않음), 맞는 조직 만들기 코드인데 다른 이메일 전용·기한 지남 [`Error::SetupCodeRefused`](422 `reason`, relay 0.1.2),
/// 기기 등록 상한 [`Error::RateLimited`](429), 기존 계정의 이메일로 조직 만들기·초대 가입
/// [`Error::AccountExists`](409 `account_exists`, 묶음 18), 조직 만들기 상한 [`Error::OrgRateLimited`](429
/// `org_rate_limited`)·조직 수 상한 [`Error::OrgCreateClosed`](403 `org_create_closed`), 조직 없음·팀이 그 조직 것이 아님·이메일의 계정과 아이디가 다름(400·409) `Error::Relay`,
/// 닿지 않음 [`Error::Unreachable`].
pub async fn register_device_hosted(
    ws_url: &str,
    signup_token: &str,
    info: &DeviceInfo,
    user: Option<&str>,
    org: Option<&HostedOrg>,
    teams: &[String],
) -> Result<HostedRegistered> {
    let mut body = info.body();
    body["signup_token"] = json!(signup_token);
    match org {
        Some(HostedOrg::Create { name, setup_code }) => {
            body["org"] = if setup_code.is_empty() {
                json!({"create": {"name": name}})
            } else {
                json!({"create": {"name": name, "setup_code": setup_code}})
            };
        }
        Some(HostedOrg::Invite(token)) => body["org"] = json!({"invite": token}),
        None => {}
    }
    if !teams.is_empty() {
        body["teams"] = json!(teams);
    }
    match user {
        Some(u) => body["user"] = json!(u),
        None => {
            if let Some(o) = body.as_object_mut() {
                o.remove("user");
            }
        }
    }
    let (code, resp) = http(ws_url, "POST", "/v1/devices", Some(&body.to_string())).await?;
    match code {
        // 201 새로 등록, 200 이미 그 계정의 기기(added:false, #389) — 둘 다 성공.
        200 | 201 => {
            let v: Value =
                serde_json::from_str(&resp).map_err(|e| Error::Relay(format!("응답 형식: {e}")))?;
            Ok(HostedRegistered {
                user: v["user"]
                    .as_str()
                    .ok_or_else(|| Error::Relay("응답 형식: user".into()))?
                    .to_owned(),
                device_id: info.device_id.clone(),
                added: v["added"].as_bool().unwrap_or(false),
                server: v["server"].as_str().map(str::to_owned),
            })
        }
        401 => Err(Error::InvalidCode),
        403 if reason(&resp) == Some("org_create_closed") => Err(Error::OrgCreateClosed),
        403 => Err(Error::UserExists),
        409 if reason(&resp) == Some("account_exists") => Err(Error::AccountExists(
            account_in(&resp).ok_or_else(|| Error::Relay("응답 형식: account".into()))?,
        )),
        409 if serde_json::from_str::<Value>(&resp).is_ok_and(|v| v["error"] == "device_taken") => {
            Err(Error::DeviceTaken)
        }
        409 if too_many_devices(&resp) => Err(Error::DeviceLimit),
        422 => Err(setup_code_refused(&resp)),
        429 if reason(&resp) == Some("org_rate_limited") => Err(Error::OrgRateLimited),
        429 => Err(Error::RateLimited),
        c => Err(Error::Relay(format!("기기 등록 실패: HTTP {c}"))),
    }
}

/// hosted 새 계정의 조직(#355·묶음 5). 기존 계정(내 다른 맥)이면 relay 가 409 `account_exists` 로 거절한다(묶음 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostedOrg {
    /// 새 조직 — 이 사용자가 첫 관리자. 서버 relay 는 운영자가 `lodelai-relay bootstrap` 으로 낸 조직 만들기 코드가 있어야 한다
    /// — 단 [`SignupVerified::org_create_open`] 이면 코드 없이(`setup_code` 가 빈 문자열이면 보내지 않는다, 묶음 18).
    Create { name: String, setup_code: String },
    /// 조직 관리자가 발급한 초대 코드.
    Invite(String),
}

/// 원격 relay 첫 관리자 등록(#364): `POST /v1/devices {setup_code, …}`. 대상은 `ws_url` 의 호스트(`wss://` 면 HTTPS,
/// 로컬 `ws://` 면 평문 — 시험·로컬 개발). 같은 기기의 재시도도 [`Registered::Created`] 다(relay 가 성공으로 답한다).
///
/// # Errors
/// 코드 틀림·끝남·폐기 [`Error::InvalidSetupCode`](401), 아이디가 bootstrap 의 관리자와 다름 [`Error::HandleMismatch`](400),
/// IP 상한 [`Error::RateLimited`](429), 닿지 않음 [`Error::Unreachable`], 서버 주소 형식 `Error::Relay`.
pub async fn register_with_setup_code(
    ws_url: &str,
    setup_code: &str,
    info: &DeviceInfo,
) -> Result<Registered> {
    let mut body = info.body();
    body["setup_code"] = json!(setup_code);
    let (code, _) = http(ws_url, "POST", "/v1/devices", Some(&body.to_string())).await?;
    match code {
        // 같은 관리자 기기의 재시도도 201(relay 가 그렇게 답한다).
        201 => Ok(Registered::Created {
            device_id: info.device_id.clone(),
        }),
        409 => Err(Error::Relay(
            "이 기기는 다른 아이디로 이미 등록돼 있다".into(),
        )),
        401 => Err(Error::InvalidSetupCode),
        400 => Err(Error::HandleMismatch),
        429 => Err(Error::RateLimited),
        c => Err(Error::Relay(format!("기기 등록 실패: HTTP {c}"))),
    }
}

/// 409 `account_exists` 본문의 `account`(verify 의 existing 과 같은 꼴, 묶음 18).
fn account_in(resp: &str) -> Option<ExistingAccount> {
    let v: Value = serde_json::from_str(resp).ok()?;
    let a = &v["account"];
    Some(ExistingAccount {
        user: a["user"].as_str()?.to_owned(),
        display_name: a["display_name"].as_str()?.to_owned(),
        org_name: a["org_name"].as_str().map(str::to_owned),
    })
}

/// 거절 응답의 `{reason}`(묶음 18).
/// 422 본문 → 조직 만들기 코드 거절 이유(relay 0.1.2 `{reason, email?, message}` — `message` 는 사람 글이라 읽지 않는다).
/// 이유가 없거나(옛 relay·틀린 코드·초대 실패) 모르는 값이면 [`Error::InvalidInvite`] 그대로. `email` 은 다른 이메일 전용일
/// 때만, 254자 안의 글일 때만 싣는다(relay 가 가린 꼴 그대로 — 화면 문구에만).
fn setup_code_refused(resp: &str) -> Error {
    use crate::SetupCodeRefusal as R;
    let Ok(v) = serde_json::from_str::<Value>(resp) else {
        return Error::InvalidInvite;
    };
    let reason = match v["reason"].as_str() {
        Some("setup_code_other_email") => R::OtherEmail,
        Some("setup_code_expired") => R::Expired,
        _ => return Error::InvalidInvite,
    };
    let email = (reason == R::OtherEmail)
        .then(|| v["email"].as_str())
        .flatten()
        .filter(|e| !e.is_empty() && e.chars().count() <= 254)
        .map(str::to_owned);
    Error::SetupCodeRefused { reason, email }
}

fn reason(resp: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(resp).ok()?;
    ["account_exists", "org_rate_limited", "org_create_closed"]
        .into_iter()
        .find(|r| v["reason"] == *r)
}

/// 인증 없는 JSON 요청 하나(원격 relay — `ws_url` 의 호스트, `wss://` 면 HTTPS). 15초. (상태 코드, 본문)
///
/// # Errors
/// 서버 주소 형식 `Error::Relay`, 닿지 않음·시간 초과 [`Error::Unreachable`].
async fn http(ws_url: &str, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let target = crate::tls::target(ws_url)?;
    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        http_once(&target, method, path, body),
    )
    .await
    {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, path, "relay HTTP: 연결 실패");
            Err(Error::Unreachable)
        }
        Err(_) => Err(Error::Unreachable),
    }
}

async fn http_once(
    t: &crate::tls::Target,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<(u16, String)> {
    let body = body.unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        t.host_header(),
        body.len()
    );
    let tcp = TcpStream::connect((t.host.as_str(), t.port)).await?;
    let mut out = Vec::new();
    if t.tls {
        let name = rustls::pki_types::ServerName::try_from(t.host.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut s = tokio_rustls::TlsConnector::from(crate::tls::client_config())
            .connect(name, tcp)
            .await?;
        s.write_all(req.as_bytes()).await?;
        // 서버가 TLS close_notify 없이 닫아도(UnexpectedEof) 받은 만큼으로 본다.
        let _ = s.read_to_end(&mut out).await;
    } else {
        let mut s = tcp;
        s.write_all(req.as_bytes()).await?;
        s.read_to_end(&mut out).await?;
    }
    let text = String::from_utf8_lossy(&out);
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP 응답 형식"))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|x| x.1.to_owned())
        .unwrap_or_default();
    Ok((code, body))
}

/// 409 `too_many_devices`(묶음 16 §3a — 사용자당 기기 상한).
fn too_many_devices(resp: &str) -> bool {
    serde_json::from_str::<Value>(resp).is_ok_and(|v| v["error"] == "too_many_devices")
}

/// 등록 토큰을 실은 HTTP/1.1 요청 하나. (상태 코드, 본문)
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> Result<(u16, String)> {
    request_with(addr, method, path, Some(token), body).await
}

/// HTTP/1.1 요청 하나(토큰은 있을 때만). 평문 HTTP — hosted 배포는 TLS 클라이언트로 바꾼다(M2 hosted).
async fn request_with(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<(u16, String)> {
    let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        addr.port(),
        body.len()
    );
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(req.as_bytes()).await?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).await?;
    let text = String::from_utf8_lossy(&out);
    let code: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| Error::Relay("HTTP 응답 형식".into()))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|x| x.1.to_owned())
        .unwrap_or_default();
    Ok((code, body))
}

/// `GET /v1/connected`(등록 토큰, #328): 지금 relay 에 연결된 사용자(아이디, 이름순). 주인 넘기기 후보의 "연결됨" 표시용.
///
/// # Errors
/// 연결 실패·401·응답 형식.
pub async fn connected_users(addr: SocketAddr, token: &str) -> Result<Vec<String>> {
    let (code, body) = request(addr, "GET", "/v1/connected", token, "").await?;
    match code {
        200 => {
            let v: Value =
                serde_json::from_str(&body).map_err(|e| Error::Relay(format!("응답 형식: {e}")))?;
            v["users"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|u| u.as_str().map(str::to_owned))
                        .collect()
                })
                .ok_or_else(|| Error::Relay("응답 형식: users".into()))
        }
        401 => Err(Error::Relay("등록 토큰이 맞지 않는다".into())),
        c => Err(Error::Relay(format!("연결 조회 실패: HTTP {c}"))),
    }
}

/// `POST /v1/wipe`(등록 토큰, #328 주인 혼자 로그아웃): relay 가 모든 행을 지우고 WAL 을 잘라낸 뒤 200 으로 답하고 끝난다.
/// 호출자는 이 뒤 자식 프로세스가 끝나길 기다리고 relay 폴더를 지운다.
///
/// # Errors
/// 연결 실패·401·500(정리 실패)·그 밖의 응답.
pub async fn wipe_relay(addr: SocketAddr, token: &str) -> Result<()> {
    match request(addr, "POST", "/v1/wipe", token, "").await?.0 {
        200 => Ok(()),
        401 => Err(Error::Relay("등록 토큰이 맞지 않는다".into())),
        c => Err(Error::Relay(format!("relay 정리 실패: HTTP {c}"))),
    }
}

/// 기기 연결 코드 접두.
pub const CONNECTION_CODE_PREFIX: &str = "lodelai-dev1.";

/// `lodelai-dev1.` + base64url(JCS({user, display_name, device_pubkeys:{ed25519, x25519, x25519_sig}, device_id})). 공개 정보만.
///
/// # Errors
/// JCS 직렬화 실패.
pub fn connection_code(info: &DeviceInfo) -> Result<String> {
    let mut v = info.body();
    v["device_id"] = json!(info.device_id);
    Ok(format!(
        "{CONNECTION_CODE_PREFIX}{}",
        encoding::encode(&jcs::to_vec(&v)?)
    ))
}

/// 기기 연결 코드를 읽는다. 코드의 `device_id` 는 믿지 않고 **공개키로 재계산해 대조**하고, `x25519_sig` 도 검증한다(#108·#313 —
/// 주인 앱이 승인 전에 확인한다. 클립보드를 바꿔치기한 x25519 를 사람이 지문 대조로는 못 잡는다).
///
/// # Errors
/// 형식 오류·지문 불일치.
pub fn parse_connection_code(code: &str) -> Result<DeviceInfo> {
    let bad = |m: &str| Error::Message(format!("기기 연결 코드: {m}"));
    let rest = code
        .trim()
        .strip_prefix(CONNECTION_CODE_PREFIX)
        .ok_or_else(|| bad("접두가 아니다"))?;
    let bytes =
        encoding::decode(rest, "connection code").map_err(|_| bad("base64url 이 아니다"))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| bad("JSON 이 아니다"))?;
    let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_owned);
    let info = DeviceInfo {
        user: s("/user").ok_or_else(|| bad("user 없음"))?,
        display_name: s("/display_name"),
        ed25519: s("/device_pubkeys/ed25519").ok_or_else(|| bad("ed25519 없음"))?,
        x25519: s("/device_pubkeys/x25519").ok_or_else(|| bad("x25519 없음"))?,
        x25519_sig: s("/device_pubkeys/x25519_sig").ok_or_else(|| bad("x25519_sig 없음"))?,
        device_id: s("/device_id").ok_or_else(|| bad("device_id 없음"))?,
    };
    let vk = VerifyingKey::from_b64(&info.ed25519).map_err(|_| bad("공개키 형식"))?;
    let id = DeviceId::parse(&info.device_id).ok_or_else(|| bad("device_id 형식"))?;
    if !id.matches(&vk) {
        return Err(bad("device_id 가 공개키 지문과 다르다"));
    }
    let x = encoding::decode_array::<32>(&info.x25519, "x25519").map_err(|_| bad("x25519 형식"))?;
    if !xkey::verify(&vk, &info.device_id, &x, &info.x25519_sig) {
        return Err(bad("x25519_sig 가 맞지 않는다"));
    }
    Ok(info)
}

impl DeviceInfo {
    /// 사람이 두 화면에서 대조하는 지문([`fingerprint_of`]).
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.device_id)
    }
}

/// 지문 = `device_id` 에서 `k1_` 을 뺀 앞 12자(72비트)를 4-4-4 로 띄어 쓴 것(`Ab3x Y9kQ 7mZp`, #67 설계).
/// 같은 사용자 권한의 에이전트가 키를 갈아 앞 몇 자를 맞추는 것(클립보드 바꿔치기)을 막을 만큼 길게. 대소문자 그대로.
#[must_use]
pub fn fingerprint_of(device_id: &str) -> String {
    let s = device_id.strip_prefix("k1_").unwrap_or(device_id);
    let head: Vec<char> = s.chars().take(12).collect();
    head.chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// relay 0.1.2 의 422(`setup_code_refused` 꼴 그대로) → 이유·가린 이메일. 이유 없음·모르는 값·깨진 본문은 InvalidInvite.
    #[test]
    fn 조직_만들기_코드_거절_이유를_읽는다() {
        use crate::SetupCodeRefusal as R;
        let other = r#"{"reason":"setup_code_other_email","message":{"ko":"a***@d… 로 가입할 때만 쓸 수 있는 코드예요","en":"x"},"email":"a***@d…"}"#;
        assert!(matches!(
            setup_code_refused(other),
            Error::SetupCodeRefused { reason: R::OtherEmail, email: Some(e) } if e == "a***@d…"
        ));
        let expired = r#"{"reason":"setup_code_expired","message":{"ko":"기한이 지난 조직 만들기 코드예요","en":"x"}}"#;
        assert!(matches!(
            setup_code_refused(expired),
            Error::SetupCodeRefused {
                reason: R::Expired,
                email: None
            }
        ));
        // 다른 이메일 전용인데 email 이 없다 — 이유는 싣고 화면은 email 없는 문구로.
        assert!(matches!(
            setup_code_refused(r#"{"reason":"setup_code_other_email"}"#),
            Error::SetupCodeRefused {
                reason: R::OtherEmail,
                email: None
            }
        ));
        // 기한 지남엔 email 을 싣지 않는다.
        assert!(matches!(
            setup_code_refused(r#"{"reason":"setup_code_expired","email":"b@c"}"#),
            Error::SetupCodeRefused {
                reason: R::Expired,
                email: None
            }
        ));
        let long = format!(
            r#"{{"reason":"setup_code_other_email","email":"{}"}}"#,
            "a".repeat(255)
        );
        assert!(matches!(
            setup_code_refused(&long),
            Error::SetupCodeRefused { email: None, .. }
        ));
        for old in [
            "",
            "{}",
            r#"{"reason":"privacy_required"}"#,
            r#"{"reason":"setup_code_new_kind"}"#,
            "<html>",
        ] {
            assert!(
                matches!(setup_code_refused(old), Error::InvalidInvite),
                "{old}"
            );
        }
    }

    #[test]
    fn connection_code_round_trip_and_tamper() {
        let k = DeviceKeys::generate(&[5u8; 64]);
        let info = DeviceInfo::of("dana", Some("다나 맥북"), &k);
        let code = connection_code(&info).unwrap();
        assert!(code.starts_with("lodelai-dev1."));
        assert_eq!(parse_connection_code(&code).unwrap(), info);
        let fp = info.fingerprint();
        assert_eq!(fp.len(), 14, "12자 + 공백 둘: {fp}");
        assert_eq!(fp.replace(' ', ""), info.device_id[3..15], "k1_ 뒤 앞 12자");
        assert_eq!(fingerprint_of("k1_Ab3xY9kQ7mZpQQQQ"), "Ab3x Y9kQ 7mZp");

        // device_id 를 다른 기기 것으로 바꾸면 거부
        let other = DeviceKeys::generate(&[6u8; 64]);
        let mut forged = info.clone();
        forged.device_id = other.device_id().as_str().to_owned();
        assert!(parse_connection_code(&connection_code(&forged).unwrap()).is_err());
        assert!(parse_connection_code("lodelai-dev1.!!!").is_err());
        assert!(parse_connection_code("other.abc").is_err());

        // #313: x25519 를 바꿔 낀 코드(클립보드 바꿔치기 — 지문은 그대로라 사람 대조로 못 잡는다)·서명 없는 코드는 거부
        let mut swapped = info.clone();
        swapped.x25519 = encoding::encode(&other.exchange.public_key());
        assert!(parse_connection_code(&connection_code(&swapped).unwrap()).is_err());
        let mut unsigned = info.clone();
        unsigned.x25519_sig = String::new();
        assert!(parse_connection_code(&connection_code(&unsigned).unwrap()).is_err());
        let v = serde_json::json!({"user": "dana", "device_id": info.device_id,
            "device_pubkeys": {"ed25519": info.ed25519, "x25519": info.x25519}});
        let no_field = format!(
            "{CONNECTION_CODE_PREFIX}{}",
            encoding::encode(&jcs::to_vec(&v).unwrap())
        );
        assert!(parse_connection_code(&no_field).is_err());
    }
}
