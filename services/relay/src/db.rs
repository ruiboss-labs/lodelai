//! SQLite 저장소. 표: `users`, `devices`, `sessions_public`, `envelopes`(+ 기기별 대상 `envelope_devices`), `blocks` (m1-plan U4).
//!
//! M1 로컬: 조직은 하나(`local`), 등록된 사용자는 모두 서로의 동료(고정 동료 목록), `blocks` 는 비어 있다.
//! 연결 하나(`Mutex<Connection>`)로 충분하다 — 로컬 relay 는 사용자 두셋이다. M2 hosted 는 PostgreSQL(ADR 0002).
//! 호출은 모두 동기라 비동기 쪽에서는 [`crate::blocking`] 으로 부른다(#169). 비동기 저장소 트레이트는 M2 에서.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::frames::RevokedBy;

pub const LOCAL_ORG: &str = "local";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("DB 파일: {0}")]
    Io(#[from] std::io::Error),
    #[error("이미 있다")]
    Conflict,
    /// 봉투 `recipients` 중 폐기되지 않은 기기가 하나도 없다(검사 뒤 폐기된 경합, protocol §7.2-6).
    #[error("전달 대상 기기 없음")]
    NoTargets,
    /// 헤더 `blobs` 중 보낸 사용자가 올린 묶이지 않은 첨부가 아닌 것이 있다(묶음 15).
    #[error("첨부를 묶을 수 없음")]
    BlobUnavailable,
    /// 그 사용자의 폐기 안 된 기기가 상한에 닿았다(묶음 16 §3a — 409 `too_many_devices`).
    #[error("기기 수 상한")]
    TooManyDevices,
    /// 이메일 HMAC 키가 없다(묶음 5 — 원격 relay 는 main 이 키 없이 뜨지 않는다).
    #[error("이메일 HMAC 키 없음")]
    NoEmailKey,
    /// 기존 계정의 가입 토큰으로 조직을 만들거나 초대로 들어오려 했다(묶음 18 §1, ADR 0011 — 409 `account_exists`).
    /// 그 계정(409 본문 `account` — verify 의 existing 과 같은 꼴, 이메일 주인 확인 뒤라 열거가 아니다).
    #[error("이미 계정이 있는 이메일")]
    AccountExists(Box<ExistingAccount>),
    /// 조직 수 상한(묶음 18 §3 `--max-orgs` — 403 `org_create_closed`).
    #[error("새 조직을 받지 않음")]
    OrgClosed,
    /// 조직 만들기 속도 상한(묶음 18 §3 이메일 30일·IP 하루·전역 하루 — 429 `org_rate_limited`, 어느 것인지 가르지 않음).
    #[error("조직 만들기 상한")]
    OrgRateLimited,
    /// #845 ⑤ 멈춘 계정 — 코드 확인 뒤 기기 추가·다시 가입(403 `account_suspended`).
    #[error("멈춘 계정")]
    Suspended,
    /// 다른 기기로 이미 있는 사용자 — 기존 사용자에 기기를 더하는 것은 명시했을 때만(#298).
    #[error("이미 있는 사용자")]
    UserExists,
    /// hosted 가입 토큰이 없거나 만료·사용됨(#339).
    #[error("가입 토큰")]
    BadToken,
    /// 이메일의 계정과 요청의 `user` 가 다르다(#339 — 409).
    #[error("이메일의 계정과 아이디가 다르다")]
    UserMismatch,
    /// 새 계정인데 `user` 가 없다.
    #[error("아이디 없음")]
    MissingUser,
    /// 사용자당 기기 등록 상한(#339, security §6).
    #[error("기기 등록 상한")]
    RateLimited,
    /// hosted 새 계정인데 조직(`org`)이 없거나, 새 조직인데 팀을 골랐거나, 그 조직의 팀이 아니다(#355 — 400).
    #[error("조직·팀 요청 형식")]
    BadOrg,
    /// 초대 토큰이 없거나 만료·사용됨·이메일 불일치(#355 — 사유를 가르지 않는다).
    #[error("초대 토큰")]
    BadInvite,
    /// 원격 relay 설정 코드가 없거나 만료·사용됨·틀림(#364 — 사유를 가르지 않는다).
    #[error("설정 코드")]
    BadSetupCode,
    /// 설정 코드는 맞는데 아이디가 bootstrap 의 `--admin` 과 다르다(#364 — 400).
    #[error("설정 코드의 관리자와 다른 아이디")]
    AdminMismatch,
    /// 같은 기기 키가 이미 있는데 확인한 이메일 계정의 폐기 안 된 기기가 아니다(#389 — 409 `device_taken`, 누구 것인지
    /// 알리지 않는다).
    #[error("다른 사용자의 기기")]
    DeviceTaken,
}

/// hosted 새 계정의 조직(#355). 기존 계정(추가 기기)은 무시된다.
pub enum OrgChoice<'a> {
    /// 새 조직 — 이 사용자가 첫 관리자. `id` 는 호출자가 만든 것, `name` 은 검사한 것. `setup_code_hash` 가 있으면
    /// (서버 relay, 묶음 5) 그 조직 만들기 코드를 같은 트랜잭션에서 소비한다 — 없거나 끝났으면 [`DbError::BadInvite`].
    Create {
        id: &'a str,
        name: &'a str,
        setup_code_hash: Option<&'a [u8]>,
        /// 코드 없는 만들기(묶음 18 `--org-create open`)의 상한 — 같은 트랜잭션에서 확인하고 기록한다.
        quota: Option<OrgQuota>,
        /// #737: 코드 없이, 이 이메일에 묶인 살아 있는 조직 만들기 코드(대기 명단 승인)를 같은 트랜잭션에서 쓴다 — 없으면
        /// [`DbError::BadInvite`].
        allowed_email: bool,
    },
    /// 초대 토큰(해시)으로 그 조직에.
    Invite { token_hash: &'a [u8] },
    /// #845 개인 공간: 사람 하나인 `orgs` 행(kind personal, org_admins 없음). `id` 는 호출자가 만든 것.
    Personal { id: &'a str },
    /// #845 ⑤(§7-3) 가입 확인 때 보인 걸린 초대(`signup_pending` id)를 같이 받는다. 조직 초대는 하나까지(없으면 `personal_id`
    /// 로 개인 공간), 그룹 초대·연락 요청은 여럿.
    Join {
        personal_id: &'a str,
        ids: &'a [String],
    },
}

/// #845 ⑤ 가입 확인 응답 `pending` 한 줄.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCard {
    pub id: String,
    /// org | group | contact
    pub kind: &'static str,
    pub from_name: String,
    pub space_name: Option<String>,
}

/// #845 ⑤ 초대 메일 상한(§3·§7-1·§7-2 처음 값).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailLimits {
    /// 사람(연락 요청·그룹 초대) 하루.
    pub person_per_day: i64,
    /// 같은 주소 30일(누가 보냈든).
    pub address_per_30d: i64,
    /// 조직 하루.
    pub org_per_day: i64,
    /// relay 전체 하루.
    pub global_per_day: i64,
}

impl Default for MailLimits {
    fn default() -> Self {
        Self {
            person_per_day: 5,
            address_per_30d: 3,
            org_per_day: 50,
            global_per_day: 2000,
        }
    }
}

/// #845 ⑤ 지금 보낼 초대 메일 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailToSend {
    pub job: String,
    /// contact | group | org
    pub kind: String,
    pub to: String,
    pub email_mac: Vec<u8>,
    pub sender: String,
    /// 보낸 사람 표시 이름(없으면 아이디).
    pub from_name: String,
    /// 보낸 사람의 확인된 이메일(§3·§7-27 — 세 메일 모두).
    pub from_email: String,
    /// 조직 초대: 조직 이름.
    pub org_name: Option<String>,
    pub org_id: Option<String>,
    /// 그룹 초대: 지금 멤버 수.
    pub members: Option<i64>,
}

/// 메일 일 한 번에 보낼 수 상한(틱 하나가 오래 걸리지 않게).
pub const MAIL_PER_TICK: usize = 20;
/// 보내기 실패를 다시 해 볼 횟수(그 뒤 버림).
pub const MAIL_MAX_TRIES: i64 = 3;

/// #845 ⑤ 가입 확인 때 보이는 걸린 초대 상한.
pub const SIGNUP_PENDING_MAX: usize = 20;

/// #845 연락 요청이 살아 있는 기간(30일). 지나면 '응답 없음'으로 끝나고 다시 요청할 수 있다.
pub const LINK_EXPIRE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// #845 ③ 하루 연락 요청 상한(§7-1). 수락되면 그날 것은 돌려준다.
pub const LINK_DAILY_MAX: i64 = 100;
/// 서로 다른 [`LINK_THROTTLE_BLOCKERS`] 명에게 막힌 사람의 하루 상한([`LINK_THROTTLE_MS`] 동안).
pub const LINK_THROTTLED_DAILY_MAX: i64 = 5;
/// 걸린 요청 상한(만료 전 requested·declined + 가입 안 한 이메일).
pub const LINK_PENDING_MAX: i64 = 100;
pub const LINK_THROTTLE_BLOCKERS: i64 = 3;
pub const LINK_THROTTLE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 막음을 세는 기간.
pub const LINK_BLOCK_WINDOW_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// 연락 요청 상한에 걸렸으면 다시 될 가장 이른 시각.
/// 줄임: 지난 30일, 지난 줄임이 끝난 뒤 나를 막은 사람이 3명 이상이면 7일 줄인다(줄임 중엔 다시 세지 않아 늘어나지 않음,
/// 끝난 뒤엔 새 막음 3이 있어야 다시).
fn link_limit(tx: &rusqlite::Transaction<'_>, me: &str, now: i64) -> Result<Option<i64>, DbError> {
    let since = now - LINK_EXPIRE_MS;
    let prev: Option<i64> = tx
        .query_row(
            "SELECT throttled_until FROM users WHERE user = ?1",
            [me],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let mut throttled = prev.filter(|t| *t > now);
    if throttled.is_none() {
        let from = (now - LINK_BLOCK_WINDOW_MS).max(prev.unwrap_or(0));
        let n: i64 = tx.query_row(
            "SELECT COUNT(*) FROM blocks WHERE blocked = ?1 AND at_ms > ?2",
            params![me, from],
            |r| r.get(0),
        )?;
        if n >= LINK_THROTTLE_BLOCKERS {
            let until = now + LINK_THROTTLE_MS;
            tx.execute(
                "UPDATE users SET throttled_until = ?2 WHERE user = ?1",
                params![me, until],
            )?;
            throttled = Some(until);
        }
    }
    let day = now.div_euclid(DAY_MS);
    let next_day = (day + 1) * DAY_MS;
    let used: i64 = tx
        .query_row(
            "SELECT requested - refunded FROM link_counts WHERE user = ?1 AND day = ?2",
            params![me, day],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if used >= LINK_DAILY_MAX {
        return Ok(Some(next_day));
    }
    if let Some(t) = throttled {
        if used >= LINK_THROTTLED_DAILY_MAX {
            return Ok(Some(next_day.min(t)));
        }
    }
    let (pending, oldest): (i64, Option<i64>) = tx.query_row(
        "SELECT COUNT(*), MIN(at) FROM (
           SELECT requested_ms AS at FROM links WHERE user = ?1 AND state IN ('requested', 'declined') AND requested_ms > ?2
           UNION ALL
           SELECT at_ms FROM link_invites WHERE requester = ?1 AND at_ms > ?2
           UNION ALL
           SELECT at_ms FROM group_invites WHERE by = ?1 AND accepted_ms IS NULL AND at_ms > ?2)",
        params![me, since],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if pending >= LINK_PENDING_MAX {
        return Ok(Some(oldest.unwrap_or(now) + LINK_EXPIRE_MS));
    }
    Ok(None)
}

/// 새 요청 하나를 센다.
fn link_charge(tx: &rusqlite::Transaction<'_>, me: &str, now: i64) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO link_counts(user, day, requested) VALUES (?1, ?2, 1)
         ON CONFLICT(user, day) DO UPDATE SET requested = requested + 1",
        params![me, now.div_euclid(DAY_MS)],
    )?;
    Ok(())
}

/// 수락된 요청의 셈을 돌려준다 — 요청한 날 = 오늘일 때만.
fn link_refund(
    tx: &rusqlite::Transaction<'_>,
    requester: &str,
    asked_ms: i64,
    now: i64,
) -> Result<(), DbError> {
    let day = now.div_euclid(DAY_MS);
    if asked_ms.div_euclid(DAY_MS) == day {
        tx.execute(
            "UPDATE link_counts SET refunded = refunded + 1 WHERE user = ?1 AND day = ?2 AND refunded < requested",
            params![requester, day],
        )?;
    }
    Ok(())
}

/// #845 `link.request` 의 대상(이메일은 정규화한 것).
#[derive(Debug, Clone, Copy)]
pub enum LinkTarget<'a> {
    Email(&'a str),
    User(&'a str),
}

/// #845 ④ 이메일 초대 기한(메일 초대·가입한 사람 앞 카드, §7-2). 링크 초대(7일)와 따로.
pub const ORG_INVITE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// #845 ④ `org.invite` 결과.
#[derive(Debug, PartialEq, Eq)]
pub enum OrgInviteOut {
    /// 보냄(어느 경우든). `notify` = 카드가 생긴 사람(디렉터리 다시 보냄), `org` = 보낸 기록이 바뀐 조직(관리자에게).
    Sent { notify: Option<String>, org: String },
    /// 관리자 시간 상한 — 다시 될 시각.
    RateLimited { until_ms: i64 },
    /// 관리자가 아님.
    Refused,
}

/// #845 ④ 받은 조직 초대 카드.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgInviteCard {
    pub id: String,
    pub org_name: String,
    pub by_display: Option<String>,
    pub at_ms: i64,
    /// 이미 다른 조직에 들어 있어 받을 수 없음.
    pub other_org: bool,
    /// 그 조직 고유색(없으면 자동).
    pub org_color: Option<String>,
}

/// #845 ④ `group.invite` 결과.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupInviteOut {
    /// 보냄(어느 경우든). `card` = 카드가 생긴 사람, `joining` = 바로 '들어가는 중'에 넣었다(멤버에게 groups 다시).
    Sent { card: Option<String>, joining: bool },
    /// 연락 요청 셈(§7-1)에 걸림 — 다시 될 시각.
    RateLimited { until_ms: i64 },
    /// 그 그룹의 지금 멤버가 아님.
    Refused,
}

/// #845 ④ 받은 그룹 초대 카드.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInviteCard {
    pub id: String,
    pub gid: String,
    pub by: String,
    pub by_display: Option<String>,
    pub at_ms: i64,
    pub members: i64,
    pub joining: bool,
}

/// #845 `link.request` 입력.
#[derive(Debug)]
pub struct LinkRequestIn<'a> {
    pub me: &'a str,
    pub to: LinkTarget<'a>,
    /// 요청한 사람이 친 값(outgoing 에만 보임).
    pub shown: &'a str,
    pub id: &'a str,
    pub now_ms: i64,
}

/// #845 `link.request` 결과.
#[derive(Debug, PartialEq, Eq)]
pub struct LinkRequestOut {
    /// 아이디로 물었는데 없음.
    pub unknown: bool,
    /// 디렉터리를 다시 보낼 사람.
    pub notify: Vec<String>,
    /// 상한(하루·걸린 요청)에 걸림 — 다시 될 가장 이른 시각(ms). 받는 사람은 찾지 않았다.
    pub limited_until: Option<i64>,
    /// 받는 사람에게 요청 카드가 새로 생김(막힌 사이·중복·서로 요청 수락은 아님) — 초대 푸시 대상.
    pub card: Option<String>,
}

/// #845 `link.answer` 의 답.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAnswer {
    Accept,
    Decline,
    Block,
}

/// 코드 없는 조직 만들기 상한(묶음 18 §3). 거절 순서: `max_orgs`(403) → 속도(IP·이메일 30일·전역 하루, 429).
#[derive(Debug, Clone, Copy)]
pub struct OrgQuota {
    pub per_email_30d: i64,
    pub per_day: i64,
    pub max_orgs: i64,
    /// IP 상한은 메모리라 호출자가 미리 본다(성공한 뒤에 센다) — 넘었으면 `max_orgs` 다음에 429.
    pub ip_over: bool,
}

/// 이메일 셈(`org_creates`) 보관 기간 — 30일.
pub const ORG_CREATE_EMAIL_WINDOW_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 가입 확인한 이메일에 이미 있는 계정(`kind: existing`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingAccount {
    pub user: String,
    pub display: String,
    /// 그 계정의 조직 이름(묶음 18 §1 — 조직 없는 relay 면 없음).
    pub org_name: Option<String>,
}

/// 그 사용자의 계정 정보(verify 의 existing 과 같은 꼴 — 409 `account_exists` 본문, 묶음 18).
fn account_of(c: &Connection, user: &str) -> Result<ExistingAccount, DbError> {
    let (display, org_name): (Option<String>, Option<String>) = c.query_row(
        "SELECT u.display, o.name FROM users u LEFT JOIN orgs o ON o.org_id = u.org WHERE u.user = ?1",
        [user],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(ExistingAccount {
        user: user.to_owned(),
        display: display.unwrap_or_else(|| user.to_owned()),
        org_name,
    })
}

/// 조직 관리자 동작의 결과(#355).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminOutcome {
    Done,
    /// 관리자가 아니거나 남의 조직 것·모르는 id·이름 겹침 — 모두 `error{protocol}`.
    Refused,
    /// 초대 발급 상한.
    RateLimited,
    /// 팀 이름이 그 조직의 다른 팀과 겹친다(관리자 판정 뒤).
    NameTaken,
}

/// 대상 지정 기기 폐기의 판정(`device.revoke {device_id}`, #339).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// 폐기했다. 폐기된 기기의 사용자.
    Revoked { user: String },
    /// 같은 사용자의 이미 폐기된 기기 — 멱등.
    AlreadyRevoked,
    /// 대상이 먼저 등록된 기기이고 요청 기기가 등록된 지 아직 대기 시간이 안 됐다.
    TooEarly,
    /// 남의 기기·모르는 id — 모르는 기기와 같게 답한다(열거 방지).
    Unknown,
}

/// 자기 기기 폐기의 결과(`device.revoke`, #325·묶음 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfRevoke {
    Revoked,
    /// 이미 폐기됐거나 없는 기기.
    Gone,
    /// 조직의 유일한 관리자의 마지막 기기다 — 폐기하지 않았다.
    LastAdmin,
}

/// 관리자 주기·빼기·내보내기·나가기의 결과(묶음 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOutcome {
    /// 바꿨다. 내보내기·나가기면 폐기한 기기 id 들.
    Done { revoked: Vec<String> },
    /// 이미 그 상태 — 방송하지 않는다(`org.admin`).
    Unchanged,
    /// 관리자가 0명이 된다.
    LastAdmin,
    /// 관리자 아님·조직 밖·내보낸 사람·관리자 대상·로컬 relay — 모두 `error{protocol}`.
    Refused,
}

/// #877 `org.leave` 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgLeaveOut {
    /// 옮김 — 옛 조직.
    Moved { old_org: String },
    /// 지금 공간이 조직이 아님(개인 공간·지운 계정·로컬 relay).
    NotOrg,
    /// 유일한 관리자이고 조직에 다른 사람이 있다.
    LastAdmin,
}

/// hosted 기기 등록 결과(#339).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedRegistered {
    pub user: String,
    /// 이미 있던 계정에 기기를 더했다(추가 기기·분실 복구).
    pub added: bool,
    /// 이미 그 계정의 폐기 안 된 기기였다 — 아무것도 바꾸지 않았다(같은 기기로 다시 가입, #389).
    pub rejoined: bool,
    /// #845 ⑤ 걸린 초대를 옮겨 디렉터리를 다시 받을 사람(요청한 사람·초대한 사람).
    pub notify: Vec<String>,
    /// #845 ⑤ 같이 받아 '들어가는 중'이 된 그룹(멤버에게 groups 다시).
    pub joining_groups: Vec<String>,
}

/// `set_org_color` 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgColorOut {
    /// 바뀜 — 그 조직.
    Changed { org: String },
    /// 같은 값(방송 안 함).
    Same,
    /// 관리자 아님·개인 공간.
    Refused,
}

/// 조직 관리자 동작(#355). 이름은 검사한 값, id·토큰 해시는 호출자가 만든 것.
pub enum AdminAct<'a> {
    OrgRename {
        name: &'a str,
    },
    TeamCreate {
        id: &'a str,
        name: &'a str,
    },
    TeamRename {
        id: &'a str,
        name: &'a str,
    },
    TeamDelete {
        id: &'a str,
    },
    Invite {
        token_hash: &'a [u8],
        email: Option<&'a str>,
        now_ms: i64,
        expires_ms: i64,
        /// 관리자당 발급 상한: 이 시간 안에 `max` 개.
        window_ms: i64,
        max: i64,
    },
}

/// 가입 메일 상한(묶음 5, m1-spec §17.3).
#[derive(Debug, Clone, Copy)]
pub struct SignupLimits {
    pub per_email_hour: i64,
    pub per_email_day: i64,
    /// relay 전체, UTC 하루.
    pub global_day: i64,
}

/// [`Db::signup_request`] 의 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupOutcome {
    Sent,
    Limited,
}

/// `invites/check` 의 갈래(#845 §7-42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCheckOut {
    /// 쓸 수 있는 초대 — 조직 카드.
    Ok(InviteInfo),
    /// 살아 있는 초대지만 다른 이메일에 묶임 — 묶인 이메일(정규화, 가리기는 부르는 쪽). 카드는 싣지 않는다.
    OtherEmail(String),
    /// 가입 토큰·초대가 없음·끝남·쓰임(모두 같은 빈 404).
    NotFound,
}

/// #845 §7-44 ② 그룹 초대 카드·초대 메일의 멤버 수: 들어가면 함께 있을 사람 — 지금 멤버 ∪ 그 그룹의 살아 있는 다른 아이디
/// 초대(대기·들어가는 중) + 살아 있는 다른 이메일 초대, 받는 사람 자신은 뺀다. `since` = 살아 있는 초대의 at_ms 하한.
fn group_card_members_in(
    c: &rusqlite::Connection,
    invite_id: &str,
    since: i64,
) -> Result<i64, DbError> {
    Ok(c.query_row(
        "WITH me AS (SELECT gid, user, id FROM group_invites WHERE id = ?1)
         SELECT (SELECT COUNT(*) FROM (
                   SELECT m.user FROM group_members m, me
                    WHERE m.gid = me.gid AND m.left_seq IS NULL AND m.user IS NOT me.user
                   UNION SELECT i.user FROM group_invites i, me
                    WHERE i.gid = me.gid AND i.user IS NOT NULL AND i.at_ms > ?2 AND i.user IS NOT me.user))
              + (SELECT COUNT(DISTINCT i.email) FROM group_invites i, me
                  WHERE i.gid = me.gid AND i.user IS NULL AND i.email IS NOT NULL AND i.at_ms > ?2 AND i.id <> me.id)",
        params![invite_id, since],
        |r| r.get(0),
    )?)
}
/// #845 ④·§7-46 개인 공간 → 조직 옮김(조직 초대 수락·코드로 들기·조직 만들기가 같이 씀). 지금 공간이 `kind='personal'` 이고
/// 대상이 조직(`kind='org'`)일 때만: `users.org`·`invited_by` 바꿈, 개인 `orgs` 행 지움, 내 공개 에이전트의 범위 '조직 전체'를
/// '나만'(`[]`)으로 좁힘, 남은 조직 초대 카드 닫음, 보낸 조직 초대 기록 joined. `by` 는 초대한 관리자(만들기는 `None`). 옮겼으면 옛 개인 공간 id, 아니면 `None`(일 없음).
///
/// # Errors
/// sqlite 오류.
fn move_personal_to_org_in(
    tx: &rusqlite::Transaction<'_>,
    me: &str,
    org: &str,
    by: Option<&str>,
    now_ms: i64,
) -> Result<Option<String>, DbError> {
    let mine: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT u.org, o.kind FROM users u LEFT JOIN orgs o ON o.org_id = u.org
             WHERE u.user = ?1 AND u.removed_ms IS NULL",
            [me],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let target_ok: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM orgs WHERE org_id = ?1 AND COALESCE(kind, 'org') = 'org')",
        [org],
        |r| r.get(0),
    )?;
    let Some((old, Some(kind))) = mine else {
        return Ok(None);
    };
    if kind != "personal" || !target_ok || old == org {
        return Ok(None);
    }
    tx.execute(
        "UPDATE users SET org = ?2, invited_by = ?3 WHERE user = ?1",
        params![me, org, by],
    )?;
    tx.execute(
        "DELETE FROM orgs WHERE org_id = ?1 AND kind = 'personal'",
        [&old],
    )?;
    tx.execute(
        "UPDATE sessions_public SET audience = '[]' WHERE user = ?1 AND audience IS NULL",
        [me],
    )?;
    tx.execute("UPDATE org_invites SET done = 1 WHERE user = ?1", [me])?;
    // #845 둘째: 옮기며 같은 조직도 연락처도 아니게 된 사람은 목록에서 빠진다(개인 공간은 혼자라 보통 없음).
    prune_lists_in(tx, me)?;
    // #845 둘째 ②: 밖 연락을 막은 조직에 들면 조직 밖과의 걸린 요청·내가 보낸 미가입 초대를 지운다(연락처는 얼림).
    if closed_c(tx, me)? {
        drop_outside_pending_in(tx, me)?;
    }
    tx.execute(
        "UPDATE invites_sent SET joined_ms = ?3 WHERE kind = 'org' AND scope = ?2 AND joined_ms IS NULL
           AND (target_user = ?1 OR target_email = (SELECT email FROM users WHERE user = ?1))",
        params![me, org, now_ms],
    )?;
    Ok(Some(old))
}

/// 초대 카드(조직 이름·사진·초대한 사람·팀) — 가입의 `invites/check` 와 §7-46 `org.code.check` 가 같이 쓴다.
fn invite_info_in(
    tx: &rusqlite::Transaction<'_>,
    org: String,
    by: String,
) -> Result<InviteInfo, DbError> {
    let (org_name, org_color): (String, Option<String>) = tx.query_row(
        "SELECT name, color FROM orgs WHERE org_id = ?1",
        [&org],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let org_avatar = org_avatar_in(tx, &org)?;
    let inviter_display: Option<String> = tx
        .query_row("SELECT display FROM users WHERE user = ?1", [&by], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    let teams = {
        let mut st =
            tx.prepare("SELECT team_id, name FROM teams WHERE org_id = ?1 ORDER BY name")?;
        let rows = st
            .query_map([&org], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<(String, String)>, _>>()?;
        rows
    };
    Ok(InviteInfo {
        org_name,
        inviter_display: inviter_display.unwrap_or_else(|| by.clone()),
        inviter: by,
        teams,
        org_avatar,
        org_color,
        org_id: org,
    })
}

/// §7-46 옮기기(`org.join`·`org.create`) 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgMoveOut {
    /// 옮김 — (옛 개인 공간, 새 조직).
    Moved(String, String),
    /// 지금 공간이 개인이 아님(조직 사람·나간 사람) — 아무것도 안 함.
    NotPersonal,
    /// 초대 코드가 없음·끝남·회수, 또는 조직 만들기 코드가 틀림·코드 없이 못 만듦.
    BadCode,
    /// 살아 있는 초대가 다른 이메일에 묶임 — 묶인 이메일(가리기는 부르는 쪽). 초대는 그대로 남는다.
    OtherEmail(String),
}

/// #880 `pins` 줄(별칭 없이 `pins`)이 아직 살아 있나 — 그룹 고정은 그 사람이 지금 그 그룹 멤버일 때만(나가면 대화가
/// 사라진다). `?1` = 사용자. 사람 고정은 늘 산다(연락처 끊김·계정 지움 때 따로 지운다).
const PIN_LIVE: &str = "(substr(pins.conv, 1, 1) <> '+' OR EXISTS(SELECT 1 FROM group_members m
     WHERE m.user = ?1 AND m.left_seq IS NULL
       AND '+' || lower(m.gid) || '@' = substr(pins.conv, 1, length(m.gid) + 2)))";

/// #880 `pins.conv` 가 사람 `?2` 와의 1:1 대화인가(`아이디@서버`, 세션 주소 아님).
const PERSON_CONV_OF: &str =
    "substr(conv, 1, length(?2) + 1) = lower(?2) || '@' AND instr(conv, '/') = 0";

/// 이 사람이 지금 개인 공간인가(§7-46 — 옮기기 셋의 문턱).
fn is_personal_in(tx: &rusqlite::Transaction<'_>, me: &str) -> Result<bool, DbError> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.org_id = u.org
           WHERE u.user = ?1 AND u.removed_ms IS NULL AND o.kind = 'personal')",
        [me],
        |r| r.get(0),
    )?)
}

/// 가입한 사람의 이메일(정규화된 값, 없으면 `None` — 자체 호스팅 등).
fn user_email_in(tx: &rusqlite::Transaction<'_>, me: &str) -> Result<Option<String>, DbError> {
    Ok(tx
        .query_row("SELECT email FROM users WHERE user = ?1", [me], |r| {
            r.get(0)
        })
        .optional()?
        .flatten())
}

/// 이메일 묶인 초대를 이 사람이 쓸 수 있나 — 이메일이 없는 사람은 묶인 초대를 못 쓴다(§7-46 덧 1 — '다름'으로).
fn invite_email_ok_for(bound: Option<&str>, email: Option<&str>) -> bool {
    match (bound, email) {
        (None, _) => true,
        (Some(b), Some(e)) => b == e,
        (Some(_), None) => false,
    }
}

/// 이메일 묶인 초대를 이 가입 이메일이 쓸 수 있나(check·register 가 같이 쓴다). 둘 다 정규화한 값.
fn invite_email_ok(bound: Option<&str>, email: &str) -> bool {
    bound.is_none_or(|b| b == email)
}

/// 초대 확인 결과(`invites/check`, 묶음 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteInfo {
    pub org_name: String,
    /// 초대를 만든 관리자(`invites.created_by`).
    pub inviter: String,
    pub inviter_display: String,
    /// (id, 이름), 이름순.
    pub teams: Vec<(String, String)>,
    /// 조직 사진 blob(#554 — 확인 화면에 base64 로 싣는다).
    pub org_avatar: Option<String>,
    /// 조직 id(#554 — 초대 화면 타일 색 키, 가입 뒤 디렉터리 `org.id` 와 같은 값).
    pub org_id: String,
    /// 조직 고유색(없으면 자동 — 화면이 org_id 로 고름).
    pub org_color: Option<String>,
}

/// 가입 토큰당 초대 확인 실패 상한(묶음 5) — 다다르면 그 토큰으로는 더 확인하지 않는다.
pub const INVITE_CHECK_MAX_FAILURES: i64 = 10;

/// UTC 하루의 시작(ms).
fn utc_day_start(now_ms: i64) -> i64 {
    now_ms - now_ms.rem_euclid(24 * 60 * 60 * 1000)
}

/// KeyPackage 소비 상한(묶음 22 §3).
#[derive(Debug, Clone, Copy)]
pub struct KpClaimLimits {
    pub per_hour: i64,
    pub pair_per_day: i64,
    /// 대상 기기의 주인이 가져갈 때의 (가져가는 사람, 대상) 하루 상한.
    pub owner_pair_per_day: i64,
    pub target_per_day: i64,
}

/// [`Db::kp_claim`] 의 결과.
#[derive(Debug, Default)]
pub struct KpClaimed {
    /// (기기, KeyPackage MLSMessage 바이트).
    pub items: Vec<(String, Vec<u8>)>,
    /// 보통 것이 20 아래가 된 (기기, 주인, 남은 수).
    pub low: Vec<(String, String, u64)>,
}

/// KeyPackage lifetime 비교용 벽시계(ms). lifetime 은 openmls 가 벽시계로 만든다 — relay 시계 주입과 무관.
fn now_wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// hosted 기기 등록 요청(#339). 해시·검사는 호출자(`http`)가 끝낸 값.
pub struct HostedDevice<'a> {
    pub token_hash: &'a [u8],
    pub user: Option<&'a str>,
    pub display: Option<&'a str>,
    pub device_id: &'a str,
    pub ed25519: &'a str,
    pub x25519: &'a str,
    pub x25519_sig: &'a str,
    pub now_ms: i64,
    /// 이 시간 안에 이 사용자에게 등록된 기기가 `max_devices` 이상이면 [`DbError::RateLimited`].
    pub window_ms: i64,
    pub max_devices: i64,
    /// 새 계정의 조직(#355). 없으면 [`DbError::BadOrg`](M2 hosted 는 새 계정에 조직이 있어야 한다).
    pub org: Option<OrgChoice<'a>>,
    /// 새 계정이 고른 팀 id(초대로 들어갈 때만 — 그 조직의 것만).
    pub teams: &'a [String],
    /// #845 ⑤ 고르지 않은 조직 메일 초대를 카드(`org_invites`)로 옮길 때 쓸 id(호출자가 만든 ULID).
    pub card_ids: &'a [String],
}

/// 가입 코드 하나당 틀린 시도 상한(#339 설계) — 다다르면 그 코드를 폐기한다.
pub const SIGNUP_CODE_MAX_FAILURES: i64 = 5;

/// 조직 만들기 코드는 만료 뒤에도 이만큼 남겨 둔다 — 그동안 지난 코드를 넣으면 '기한 지남'을 알린다(relay 0.1.2).
pub const SETUP_CODE_KEEP_EXPIRED_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// #845 ③ 초대 링크 토큰의 찾기 값(토큰 원문은 저장하지 않는다).
fn token_hash(token: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"lodelai-contact-link-hash-v1\0");
    h.update(token.as_bytes());
    h.finalize().to_vec()
}

/// 조직 만들기 코드에 묶은 이메일의 해시(relay 0.1.2 — 원문은 두지 않는다). 정규화한 이메일을 받는다.
#[must_use]
pub fn setup_email_hash(normalized_email: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"lodelai-setup-email-v1\0");
    h.update(normalized_email.as_bytes());
    h.finalize().to_vec()
}

/// #738: 조직 만들기 코드 이메일의 키 묶은 꼴 — HMAC-SHA256(relay.env 이메일 키, 'lodelai-setup-email-v2\0' ‖ [`setup_email_hash`]).
/// 키 없이 도는 `bootstrap` CLI 가 SHA 꼴로 쓰고(`email_keyed = 0`), 키를 쥔 relay 가 이 꼴로 바꿔 쓴다(`email_keyed = 1`) —
/// 원문 없이 바꿀 수 있게 SHA 값 위에 건다.
#[must_use]
pub fn setup_email_mac(key: &[u8], sha: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut m =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC 은 어떤 길이의 키든 받는다");
    m.update(b"lodelai-setup-email-v2\0");
    m.update(sha);
    m.finalize().into_bytes().to_vec()
}

/// 조직 만들기 코드 확인 결과(relay 0.1.2). 만료·다른 이메일은 맞는 코드일 때만 나온다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupCheck {
    Ok,
    /// 없는 코드(틀림·쓰임·지워짐 — 가르지 않는다).
    Wrong,
    Expired,
    /// 다른 이메일에 묶인 코드 — 그 이메일의 가린 꼴.
    OtherEmail(String),
}

/// `bootstrap --list` 한 줄 — 코드는 없다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCodeInfo {
    pub id: String,
    pub email_mask: Option<String>,
    pub expires_ms: i64,
}

/// 기기마다 받지 않은 Handshake 보관 상한(§5a — 기본 2 000개·64 MiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeCap {
    pub count: i64,
    pub bytes: i64,
}

/// [`Db::store_handshake`] 결과.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HandshakeStored {
    /// 이 메시지를 받을 (사용자, 기기) — rejoin 표시가 있거나 이번에 그 그룹이 비워진 기기는 빠진다.
    pub targets: Vec<(String, String)>,
    /// 이번에 rejoin 표시가 새로 생긴 (사용자, 기기).
    pub marked: Vec<(String, String)>,
    /// 받을 기기가 없어져 함께 지운 Handshake blob(파일은 호출자가, §5c).
    pub removed_blobs: Vec<String>,
}

/// [`Db::expire_handshakes`] 결과: (새로 rejoin 표시가 생긴 (사용자, 기기), 함께 지운 blob).
pub type ExpiredHandshakes = (Vec<(String, String)>, Vec<String>);

/// 그룹의 지금 GroupInfo blob(§5b·§5c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GiPin {
    pub blob_id: String,
    pub size: u64,
    pub sha256: String,
}

/// 그룹 멤버 변경 한 건(묶음 16, kind group 의 평문 헤더).
pub struct GroupOp<'a> {
    pub gid: &'a str,
    pub op: &'a str,
    pub sender: &'a str,
    pub subject: Option<&'a str>,
    /// 보낸 사람이 유효 관리자인가(묶음 22 §12-25 — MLS 그룹의 `admins` ∩ 잎 사용자, 비면 가장 작은 잎 번호). `None` 이면
    /// 표(group_members)의 관리자 표시로 본다(MLS 밖·확정 때 반영).
    pub admin: Option<bool>,
    /// #877 지금(relay 시계) — 기한이 지난 운영 멈춤은 정리 틱 전이라도 멈춤이 아니다.
    pub now_ms: i64,
}

/// 확정 전 Commit(묶음 22 §4-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCommit {
    pub group_id: String,
    pub epoch: u64,
    pub msg_id: String,
    pub commit_hash: String,
    pub sender_user: String,
    pub sender_device: String,
    pub op: String,
    pub subject: Option<String>,
    /// merge 뒤(N+1) 공개 상태·GroupInfo.
    pub storage: Vec<u8>,
    pub group_info: Vec<u8>,
    pub gi_pin: Option<GiPin>,
    /// N+1 잎 기기.
    pub leaves: Vec<String>,
    /// Add 로 드는 기기(Welcome 은 확정 뒤에만).
    pub joining: Vec<String>,
    /// 응답을 세지 않는 사용자(보낸 사람·Remove 대상).
    pub excluded: Vec<String>,
    pub delivered_ms: i64,
    /// Commit 메시지(state 포함)와 봉투 머리.
    pub message: String,
    pub from_address: String,
    pub to_address: String,
    pub expires_ms: i64,
}

/// [`Db::mls_finalize`] 결과.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Finalized {
    pub group_seq: Option<u64>,
    /// 확정된 Commit 메시지(새 잎에 보낼 것 — 아직 남아 있으면).
    pub commit_message: Option<String>,
    /// 이제 Commit(Welcome)을 받을 새 잎.
    pub welcome: Vec<String>,
    /// 풀린 N+1 응용 메시지와 받을 기기.
    pub released: Vec<(String, Vec<String>)>,
    pub removed_blobs: Vec<String>,
}

/// [`Db::mls_void`] 결과.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Voided {
    /// (보낸 기기, msg_id) — nack commit_void.
    pub nacks: Vec<(String, String)>,
    pub removed_blobs: Vec<String>,
}

/// 그룹의 마지막 결과(§12-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub group_id: String,
    pub epoch: u64,
    pub commit_hash: String,
    pub is_final: bool,
    pub group_seq: Option<u64>,
}

/// 확정 뒤 처리 못 함 관리자 줄(§4-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unprocessed {
    pub sender: String,
    pub failed: u64,
    pub acked: Vec<String>,
    pub admins: Vec<String>,
}

/// 결과·무효 nack 을 남기는 기간(§12-14 — 30일).
const OUTCOME_KEEP_MS: i64 = 30 * 24 * 3600 * 1000;

const PENDING_SELECT: &str = "SELECT group_id, epoch, msg_id, commit_hash, sender_user, sender_device, op, subject,
    storage, group_info, gi_blob, gi_size, gi_sha, leaves, joining, excluded, delivered_ms, message, from_address,
    to_address, expires_ms FROM mls_pending";

fn pending_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingCommit> {
    let gi_blob: Option<String> = r.get(10)?;
    let gi_pin = match gi_blob {
        Some(blob_id) => Some(GiPin {
            blob_id,
            size: u64::try_from(r.get::<_, Option<i64>>(11)?.unwrap_or(0)).unwrap_or(0),
            sha256: r.get::<_, Option<String>>(12)?.unwrap_or_default(),
        }),
        None => None,
    };
    Ok(PendingCommit {
        group_id: r.get(0)?,
        epoch: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
        msg_id: r.get(2)?,
        commit_hash: r.get(3)?,
        sender_user: r.get(4)?,
        sender_device: r.get(5)?,
        op: r.get(6)?,
        subject: r.get(7)?,
        storage: r.get(8)?,
        group_info: r.get(9)?,
        gi_pin,
        leaves: split_lines(&r.get::<_, String>(13)?),
        joining: split_lines(&r.get::<_, String>(14)?),
        excluded: split_lines(&r.get::<_, String>(15)?),
        delivered_ms: r.get(16)?,
        message: r.get(17)?,
        from_address: r.get(18)?,
        to_address: r.get(19)?,
        expires_ms: r.get(20)?,
    })
}

/// #819 나눠 줄 일 하나([`Db::duties_due`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DutyDue {
    pub group_id: String,
    pub task: String,
    pub subject: String,
    /// 이 일의 Commit 을 냈다가 무효가 된 기기 — 다른 접속 후보가 있으면 이 기기엔 주지 않는다.
    pub voided_by: Vec<String>,
}

/// #819 상한에 닿은 일(`mls_duty_stuck` 행).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DutyStuck {
    pub group_id: String,
    pub task: String,
    pub subject: String,
    /// 마지막으로 무효가 된 Commit.
    pub epoch: u64,
    pub commit_hash: String,
    pub sender_user: String,
    /// 그 Commit 에 fail 을 낸 사용자.
    pub failed: Vec<String>,
    /// fail 사용자 중 잎 기기의 hello.v 가 지금 판보다 낮거나 모르는 사람(failed 순서).
    pub stale: Vec<String>,
    pub voids: u64,
    pub at_ms: i64,
}

const DUTY_STUCK_COLS: &str =
    "s.group_id, s.task, s.subject, s.epoch, s.commit_hash, s.sender_user, s.failed, s.stale, s.voids, s.at_ms";

fn duty_stuck_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DutyStuck> {
    Ok(DutyStuck {
        group_id: r.get(0)?,
        task: r.get(1)?,
        subject: r.get(2)?,
        epoch: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
        commit_hash: r.get(4)?,
        sender_user: r.get(5)?,
        failed: split_lines(&r.get::<_, String>(6)?),
        stale: split_lines(&r.get::<_, String>(7)?),
        voids: u64::try_from(r.get::<_, i64>(8)?).unwrap_or(0),
        at_ms: r.get(9)?,
    })
}

fn split_lines(s: &str) -> Vec<String> {
    s.split('\n')
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 그룹 라우팅 판단에 쓰는 값(묶음 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub org: String,
    pub members: Vec<String>,
    pub devices: Vec<String>,
}

/// 첨부 예약 결과(#876).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserve {
    /// 예약됨.
    Done,
    /// 아직 안 받은 첨부 합 상한(`quota`).
    Pending,
    /// 계정당 UTC 하루 합 상한(`daily_quota`).
    Daily,
}

/// 첨부 예약 한 건(묶음 15).
pub struct NewBlob<'a> {
    pub blob_id: &'a str,
    pub user: &'a str,
    pub device: &'a str,
    pub avatar: bool,
    /// 조직 사진(#554 `blob.reserve{for: org}`) — 예약 때 관리자였던 조직. PUT 끝에서 다시 본다.
    pub for_org: Option<&'a str>,
    /// #881 지난 대화 옮기기 조각 — 받을 기기 하나(검사는 호출자가). 있으면 미전달·하루 합이 옮기기 통으로 간다.
    pub for_device: Option<&'a str>,
    pub ct_len: u64,
    pub put_token_hash: &'a [u8],
    pub put_token_exp: i64,
    pub now_ms: i64,
}

/// PUT 시작 결과(사용자, avatar 인가, 길이, 조직 사진이면 그 조직 #554) — [`Db::blob_put_begin`].
pub type PutBegin = (String, bool, u64, Option<String>);

/// 파일 한 종류의 (암호문 합계 바이트, 개수) — [`Db::blob_totals`].
pub type FileTotals = (u64, u64);

/// 0.2.6 #809: 못 엶 보고를 적은 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableReport {
    /// 적었다 — 알리기는 [`Db::unreadable_due`] 가.
    Recorded,
    /// 보통 ack 로(만료·이미 받음·더 셀 것 없음).
    Plain,
    /// 이 기기는 받는 대상이 아니었다 — 무시.
    NotTarget,
    /// 시간당 상한을 넘음 — 보통 ack 로.
    Limited,
}

/// 알릴 때가 된 못 엶 보고(0.2.6 #809).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableDue {
    pub msg_id: String,
    pub device_id: String,
    pub from_user: String,
    /// 보고한 기기의 사람(status `by`).
    pub to_user: String,
    /// n=2 — `recipient_unreadable_final`.
    pub final_: bool,
    /// 같은 사람의 다른 기기가 열었다 — final 을 보내지 않고 닫는다.
    pub opened: bool,
}

/// 서버가 보관하는 봉투 헤더(본문 제외) + 상태.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHeader {
    pub msg_id: String,
    pub kind: String,
    pub from_user: String,
    pub from_address: String,
    pub to_user: String,
    pub to_address: String,
    pub expires_ms: i64,
    /// `envelope_server` 상태 이름.
    pub env_state: String,
    /// `request_sender_view` 상태 이름(rank 규칙으로 추적).
    pub sender_view: String,
    pub abort_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSession {
    pub user: String,
    pub slug: String,
    pub grade: String,
    pub liveness: String,
    pub display: Option<String>,
    pub title: Option<String>,
    pub folder: Option<String>,
    /// 프로젝트 (id, 구분 이름)(묶음 23 §5). 없으면 옛 앱.
    pub project: Option<(String, String)>,
    /// 턴 처리 중(A15, `session.publish.busy`).
    pub busy: bool,
    /// 공개 범위(묶음 20). `None` = 조직 전체, `Some` = 그 아이디들(주인은 늘 범위 안). 다른 사람에게 싣지 않는다.
    pub audience: Option<Vec<String>>,
    /// #845 둘째: 범위에 고른 주인의 친구 목록 id(`audience` 가 `Some` 일 때만). 다른 사람에게 싣지 않는다.
    pub audience_lists: Vec<String>,
    /// 읽을 때 채움: 고른 목록에 **지금** 든 사람(주인의 목록 안에서만 찾음, 없는 id 는 빈 목록). 저장하지 않는다.
    pub listed: Vec<String>,
    /// 에이전트 종류(Codex C2, `session.publish.agent`). `None` = claude_code(옛 앱 포함).
    pub agent: Option<String>,
    /// 주인 코어의 같은 이름 번호(관문 Y2, `session.publish.no`, 1..=999). `None` = 번호 없음(옛 앱 포함).
    pub no: Option<u16>,
    /// #739: relay 가 그 기기 끊김으로 dead 로 바꿨다(주인이 끝낸 것이 아님). publish 는 늘 거짓으로 쓴다.
    pub offline: bool,
}

impl PublicSession {
    /// liveness 가 dead 인가.
    #[must_use]
    pub fn liveness_is_dead(&self) -> bool {
        self.liveness == "dead"
    }

    /// `user` 가 이 세션에 요청할 수 있고 디렉터리에서 볼 수 있나(묶음 20 — 주인이거나 범위 안).
    #[must_use]
    pub fn reaches(&self, user: &str) -> bool {
        self.user == user || self.audience.is_none() || self.picks(user)
    }

    /// 범위가 '고른 사람'이고 `user` 가 그 안(직접 고름 또는 고른 목록에 지금 있음)인가. 조직 전체 범위는 `false`.
    #[must_use]
    pub fn picks(&self, user: &str) -> bool {
        self.audience
            .as_ref()
            .is_some_and(|a| a.iter().any(|u| u == user))
            || (self.audience.is_some() && self.listed.iter().any(|u| u == user))
    }
}

/// 범위 저장 꼴. 목록을 고르지 않았으면 옛 꼴 그대로 JSON 배열, 골랐으면 `{"users":[…],"lists":[…]}`. 없으면 조직 전체.
fn audience_text(a: Option<&Vec<String>>, lists: &[String]) -> Option<String> {
    a.map(|u| {
        if lists.is_empty() {
            serde_json::to_string(u)
        } else {
            serde_json::to_string(&serde_json::json!({ "users": u, "lists": lists }))
        }
        .unwrap_or_else(|_| "[]".to_owned())
    })
}

/// 저장한 범위를 (사람, 목록 id)로 읽는다. 읽지 못하면 빈 목록 — 주인 말고는 아무도 범위 안이 아니다(넓히는 쪽으로 틀리지 않게).
fn audience_of(t: Option<String>) -> Option<(Vec<String>, Vec<String>)> {
    t.map(|t| {
        if let Ok(users) = serde_json::from_str::<Vec<String>>(&t) {
            return (users, Vec::new());
        }
        let v: serde_json::Value = serde_json::from_str(&t).unwrap_or_default();
        let strs = |k: &str| -> Vec<String> {
            v[k].as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        };
        (strs("users"), strs("lists"))
    })
}

/// #845 둘째 친구 목록 하나(주인만 본다).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserList {
    pub list_id: String,
    pub name: String,
    pub users: Vec<String>,
}

/// `org.update.external` 결과(#845 둘째 ②).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgExternalOut {
    /// 바뀜 — 조직과 조직 밖에서 directory.update 받을 사람.
    Changed {
        org: String,
        outsiders: Vec<String>,
    },
    Same,
    /// 관리자 아님·개인 공간.
    Refused,
}

/// #845 둘째 ③ 조직 밖 막기를 켜기 전 셈(`org.external.preview`). 조직 전체 — 멤버 누구의 것이든.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrgExternalPreview {
    /// 얼 연락처 — (멤버, 조직 밖 사람) 수락된 쌍. 디렉터리 `links` 와 같은 거름(상대 조직이 이미 닫아 언 쌍은 빼고 센다).
    pub frozen: u64,
    /// 지워질 걸린 요청 — 멤버와 조직 밖 사람 사이 만료 전 요청 쌍(받은·보낸, 엇갈린 둘은 한 쌍).
    pub pending: u64,
    /// 지워질 미가입 이메일 초대 — 멤버가 보낸 만료 전 것.
    pub invites: u64,
}

/// `list.put` 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListPutOut {
    /// 저장함 — 들고 난 사람(directory.update 받을 사람, 주인 빼고).
    Done(Vec<String>),
    /// 사람 하나라도 같은 조직도 수락된 연락처도 아님(또는 나 자신·중복).
    Refused,
    /// 주인당 목록 상한을 넘는 새 목록.
    Quota,
}

/// 주인당 친구 목록 상한(845-둘째 ①-1).
pub const LISTS_MAX: i64 = 32;
/// 목록 하나에 든 사람 상한(audience users 와 같다).
pub const LIST_USERS_MAX: usize = 256;
/// audience 하나에 고를 수 있는 목록 수.
pub const AUDIENCE_LISTS_MAX: usize = 16;

fn users_json(u: &[String]) -> String {
    serde_json::to_string(u).unwrap_or_else(|_| "[]".to_owned())
}

fn users_of_json(t: &str) -> Vec<String> {
    serde_json::from_str(t).unwrap_or_default()
}

/// 주인 `owner` 의 목록 `ids` 에 지금 든 사람(합집합, 중복 없음). 주인의 목록 안에서만 찾고 없는 id 는 빈 목록.
fn list_members_c(c: &Connection, owner: &str, ids: &[String]) -> Result<Vec<String>, DbError> {
    let mut out: Vec<String> = Vec::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let mut st = c.prepare_cached("SELECT users FROM lists WHERE owner = ?1 AND list_id = ?2")?;
    for id in ids {
        if let Some(t) = st
            .query_row(params![owner, id], |r| r.get::<_, String>(0))
            .optional()?
        {
            for u in users_of_json(&t) {
                if !out.contains(&u) {
                    out.push(u);
                }
            }
        }
    }
    Ok(out)
}

/// #845 둘째 ②: 그 사람의 조직이 밖 연락을 막았나.
fn closed_c(c: &Connection, user: &str) -> Result<bool, DbError> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.org_id = u.org
           WHERE u.user = ?1 AND o.external = 'closed')",
        [user],
        |r| r.get(0),
    )?)
}

/// #845 둘째 ②: 두 사람이 다른 조직이고 어느 한쪽 조직이 밖 연락을 막았나(연락처가 얼린 사이).
fn closed_between_c(c: &Connection, a: &str, b: &str) -> Result<bool, DbError> {
    Ok(c.query_row(
        "SELECT COALESCE((SELECT ua.org <> ub.org FROM users ua, users ub WHERE ua.user = ?1 AND ub.user = ?2), 1)
           AND EXISTS(SELECT 1 FROM users x JOIN orgs o ON o.org_id = x.org
                      WHERE x.user IN (?1, ?2) AND o.external = 'closed')",
        params![a, b],
        |r| r.get(0),
    )?)
}

/// #845 둘째 ②: 그 사용자와 조직 밖 사람 사이의 걸린 요청(수락 안 된 links)과 그 사용자가 보낸 미가입 이메일 초대를 지운다.
/// 걸렸던 상대를 돌려준다(directory.update 받을 사람).
fn drop_outside_pending_in(
    tx: &rusqlite::Transaction<'_>,
    user: &str,
) -> Result<Vec<String>, DbError> {
    let peers: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT CASE WHEN l.user = ?1 THEN l.peer ELSE l.user END FROM links l
             WHERE (l.user = ?1 OR l.peer = ?1) AND l.state <> 'accepted'
               AND COALESCE((SELECT a.org <> b.org FROM users a, users b
                             WHERE a.user = l.user AND b.user = l.peer), 1)",
        )?;
        let r = st.query_map([user], |r| r.get(0))?;
        r.collect::<Result<_, _>>()?
    };
    for p in &peers {
        tx.execute(
            "DELETE FROM links WHERE ((user = ?1 AND peer = ?2) OR (user = ?2 AND peer = ?1)) AND state <> 'accepted'",
            params![user, p],
        )?;
    }
    tx.execute("DELETE FROM link_invites WHERE requester = ?1", [user])?;
    Ok(peers)
}

/// #845 둘째 관계 술어: `a` 가 `b` 를 목록·공개 범위에 넣을 수 있나 = 같은 조직(둘 다 살아 있음) || 수락된 연락처.
/// 정지·기기 유무는 보지 않는다(일시 정지로 목록이 깨지지 않게 — 배달 때 `can_reach` 가 한 번 더 본다).
fn related_c(c: &Connection, a: &str, b: &str) -> Result<bool, DbError> {
    Ok(c.query_row(
        "SELECT COALESCE((SELECT ua.org = ub.org FROM users ua, users ub
                  WHERE ua.user = ?1 AND ub.user = ?2 AND ua.removed_ms IS NULL AND ub.removed_ms IS NULL), 0)
           OR EXISTS(SELECT 1 FROM links WHERE user = ?1 AND peer = ?2 AND state = 'accepted')",
        params![a, b],
        |r| r.get(0),
    )?)
}

/// 백업 기록(m1-spec §17.3 `server.status.backup`). `meta` 의 `backup_*` 키.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecord {
    pub last_attempt_ms: Option<i64>,
    pub last_ok_ms: Option<i64>,
    pub last: BackupLast,
    pub offsite: BackupOffsite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupLast {
    Ok,
    Failed,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupOffsite {
    Ok,
    Failed,
    Skipped,
    None,
}

impl BackupOffsite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::None => "none",
        }
    }

    /// 저장된 값 읽기. `backup-mark --offsite` 는 이 중 `ok|failed|skipped` 만 받는다(main).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ok" => Some(Self::Ok),
            "failed" => Some(Self::Failed),
            "skipped" => Some(Self::Skipped),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// 사용자당 기기 기본 상한(묶음 16 §3a — 사람 16 × 4 = 그룹 수신 기기 64).
pub const DEFAULT_MAX_DEVICES: usize = 4;

pub struct Db {
    conn: Mutex<Connection>,
    /// 이메일 HMAC 키(묶음 5 정보 파기 A — `users.email_mac`). DB 밖(relay.env)에서 온다 — DB 백업만으로 이메일을
    /// 하나씩 대입해 맞혀 보지 못하게. 없으면 내보내기·나가기·되살리기가 [`DbError::NoEmailKey`].
    email_key: std::sync::OnceLock<Vec<u8>>,
    /// #738: 조직 만들기 코드 이메일을 키 묶은 꼴로 바꿀 키 — relay.env 에서 온 고정 키일 때만(로컬의 프로세스마다 새 키면
    /// 다시 켠 뒤 맞출 수 없어 SHA 꼴로 둔다). [`Db::setup_codes_rekey`]·이메일 맞추기가 쓴다.
    setup_key: std::sync::OnceLock<Vec<u8>>,
    /// 사용자당 폐기 안 된 기기 상한(묶음 16 §3a — relay `--max-devices-per-user`, 기본 4).
    max_devices: std::sync::atomic::AtomicUsize,
}

/// HMAC-SHA256(키, 정규화한 이메일) — 내보내거나 나간 사람을 같은 이메일로 다시 초대받았을 때 같은 아이디로 되살리는 데만 쓴다.
#[must_use]
pub fn email_mac(key: &[u8], email: &str) -> Vec<u8> {
    use hmac::Mac;
    let mut m =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC 은 어떤 길이의 키든 받는다");
    m.update(b"lodelai-email-mac-v1\0");
    m.update(email.as_bytes());
    m.finalize().into_bytes().to_vec()
}

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS users (
  user    TEXT PRIMARY KEY,
  org     TEXT NOT NULL,
  display TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  user        TEXT NOT NULL REFERENCES users(user),
  ed25519     TEXT NOT NULL,
  x25519      TEXT NOT NULL,
  created_ms  INTEGER NOT NULL,
  revoked_ms  INTEGER,
  x25519_sig  TEXT,
  name        TEXT,
  last_seen_day INTEGER,
  hello_v     INTEGER,
  own         INTEGER
);
CREATE TABLE IF NOT EXISTS sessions_public (
  user     TEXT NOT NULL,
  slug     TEXT NOT NULL,
  grade    TEXT NOT NULL,
  liveness TEXT NOT NULL,
  display  TEXT,
  title    TEXT,
  folder   TEXT,
  busy     INTEGER NOT NULL DEFAULT 0,
  audience TEXT,
  PRIMARY KEY (user, slug)
);
-- #845 §7-56 계정 단위 대화 음소거(내 모든 기기가 같이). conv = 그룹·사람·세션 주소, until_ms NULL = 풀 때까지.
-- relay 는 받는 사람의 이 줄로 chat·reaction 푸시만 거른다. 지난 줄은 읽을 때 빼고 쓸 때 지운다.
-- #845 둘째 친구 목록(주인만 본다). users = JSON 배열(아이디, 0~256). list_id 는 앱이 만든다.
CREATE TABLE IF NOT EXISTS lists (
  owner      TEXT NOT NULL,
  list_id    TEXT NOT NULL,
  name       TEXT NOT NULL,
  users      TEXT NOT NULL,
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY (owner, list_id)
);
CREATE TABLE IF NOT EXISTS mutes (
  user     TEXT NOT NULL,
  conv     TEXT NOT NULL,
  until_ms INTEGER,
  PRIMARY KEY (user, conv)
);
-- #880 계정 단위 대화 고정(내 모든 기기가 같이). conv = 그룹·사람 주소(Address::conv_key 꼴), pos = 0 부터 위에서의 자리.
CREATE TABLE IF NOT EXISTS pins (
  user TEXT NOT NULL,
  conv TEXT NOT NULL,
  pos  INTEGER NOT NULL,
  PRIMARY KEY (user, conv)
);
CREATE TABLE IF NOT EXISTS blocks (
  user    TEXT NOT NULL,
  blocked TEXT NOT NULL,
  PRIMARY KEY (user, blocked)
);
-- #845 연락처: 수락되면 양쪽 두 줄(state accepted), 요청은 요청한 사람 줄 하나(state requested). task_ok = 줄 주인이 상대에게
-- task 를 열었나.
CREATE TABLE IF NOT EXISTS links (
  user         TEXT NOT NULL,
  peer         TEXT NOT NULL,
  state        TEXT NOT NULL,
  requested_ms INTEGER NOT NULL,
  accepted_ms  INTEGER,
  task_ok      INTEGER NOT NULL DEFAULT 0,
  via          TEXT,
  PRIMARY KEY (user, peer)
);
CREATE INDEX IF NOT EXISTS links_peer ON links(peer, state);
-- #845 가입 안 한 이메일 앞 연락 요청. email_shown 은 요청한 사람에게만, 메일은 일 대기열(send_after_ms·sent_ms)이 보낸다.
CREATE TABLE IF NOT EXISTS link_invites (
  id            TEXT PRIMARY KEY,
  requester     TEXT NOT NULL,
  email_mac     BLOB NOT NULL,
  email_shown   TEXT NOT NULL,
  at_ms         INTEGER NOT NULL,
  send_after_ms INTEGER NOT NULL,
  sent_ms       INTEGER
);
CREATE INDEX IF NOT EXISTS link_invites_mac ON link_invites(email_mac, at_ms);
CREATE INDEX IF NOT EXISTS link_invites_req ON link_invites(requester, at_ms);
-- #845 ③ 하루 연락 요청 셈(§7-1). day = UTC 날(ms / 하루). 그날 낸 요청이 그날 수락되면 refunded+1.
-- #881 지난 대화 옮기기 조각의 하루 통(보통 첨부 blob_daily 와 따로). 숫자만 — 2일 뒤 지운다.
CREATE TABLE IF NOT EXISTS blob_history_daily (
  user  TEXT NOT NULL,
  day   INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY (user, day)
);
-- #876 계정당 UTC 하루 첨부 예약 암호문 합(사진 제외). 숫자만 — 2일 뒤 지운다(expire_tick).
CREATE TABLE IF NOT EXISTS blob_daily (
  user  TEXT NOT NULL,
  day   INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY (user, day)
);
CREATE TABLE IF NOT EXISTS link_counts (
  user      TEXT NOT NULL,
  day       INTEGER NOT NULL,
  requested INTEGER NOT NULL DEFAULT 0,
  refunded  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user, day)
);
-- #845 ③ 내 초대 링크(연락처). 토큰은 저장하지 않는다 — 찾기는 sha256(토큰), 다시 보이기는 email_key HMAC(nonce).
-- 사람마다 살아 있는 것(revoked_ms NULL) 하나, 만료 없음·여러 번 쓰임.
CREATE TABLE IF NOT EXISTS contact_links (
  token_hash BLOB PRIMARY KEY,
  user       TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  revoked_ms INTEGER
);
CREATE INDEX IF NOT EXISTS contact_links_user ON contact_links(user, revoked_ms);
-- #845 ④ 가입한 사람 앞 조직 초대(§7-2). 부를 때마다 한 줄(관리자 시간 상한을 경우마다 같게 센다). 카드는 같은 조직 줄 하나로.
CREATE TABLE IF NOT EXISTS org_invites (
  id     TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  user   TEXT NOT NULL,
  by     TEXT NOT NULL,
  at_ms  INTEGER NOT NULL,
  -- 답함(수락·거절·옮김) — 카드에서 빠지되 관리자 시간 셈엔 남는다.
  done   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS org_invites_user ON org_invites(user, at_ms);
CREATE INDEX IF NOT EXISTS org_invites_by ON org_invites(by, at_ms);
-- #845 ④ 그룹 초대(§7-2·§7-12). user 가 없으면 가입 안 한 이메일(메일은 ⑤). accepted_ms 가 있으면 '들어가는 중'(joining) —
-- 멤버 기기가 add 하면 지운다, 30일 뒤에도 지운다.
CREATE TABLE IF NOT EXISTS group_invites (
  id          TEXT PRIMARY KEY,
  gid         TEXT NOT NULL,
  user        TEXT,
  email       TEXT,
  by          TEXT NOT NULL,
  at_ms       INTEGER NOT NULL,
  accepted_ms INTEGER
);
CREATE INDEX IF NOT EXISTS group_invites_user ON group_invites(user);
CREATE INDEX IF NOT EXISTS group_invites_gid ON group_invites(gid);
-- #845 §7-26 보낸 초대 기록 — 받는 쪽 표와 따로, '수락돼 들어옴'(joined_ms) 말고는 30일 동안 바뀌지 않는다(거절·막힘·다른 조직·
-- 가입 안 함이 보낸 쪽에 드러나지 않게). recv_ref 는 받는 쪽 줄(org_invites id·invites token 해시 base64url·group_invites id).
CREATE TABLE IF NOT EXISTS invites_sent (
  id           TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('org','group')),
  scope        TEXT NOT NULL,
  by           TEXT NOT NULL,
  shown        TEXT NOT NULL,
  target_user  TEXT,
  target_email TEXT,
  recv_ref     TEXT,
  at_ms        INTEGER NOT NULL,
  joined_ms    INTEGER
);
CREATE INDEX IF NOT EXISTS invites_sent_scope ON invites_sent(kind, scope);
CREATE INDEX IF NOT EXISTS invites_sent_by ON invites_sent(by);
-- #845 ⑤ 초대 메일 일(가입 안 한 이메일 앞 연락 요청·그룹 초대·조직 초대). ref 가 가리키는 줄이 보낼 때도 살아 있어야 보낸다.
CREATE TABLE IF NOT EXISTS mail_jobs (
  id       TEXT PRIMARY KEY,
  kind     TEXT NOT NULL CHECK (kind IN ('contact','group','org')),
  ref      TEXT NOT NULL,
  email    TEXT NOT NULL,
  sender   TEXT NOT NULL,
  org_id   TEXT,
  at_ms    INTEGER NOT NULL,
  after_ms INTEGER NOT NULL,
  tries    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS mail_jobs_after ON mail_jobs(after_ms);
-- 보낸 초대 메일(상한 셈 — 사람 하루·주소 30일·조직 하루·전체 하루).
CREATE TABLE IF NOT EXISTS mail_log (
  email_mac BLOB NOT NULL,
  kind      TEXT NOT NULL,
  sender    TEXT NOT NULL,
  org_id    TEXT,
  at_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_log_at ON mail_log(at_ms);
-- '이 주소로 lodelai 메일 받지 않기'(§7-18 2).
CREATE TABLE IF NOT EXISTS mail_blocks (
  email_mac BLOB PRIMARY KEY,
  at_ms     INTEGER NOT NULL
);
-- #845 ⑤ 가입 확인 때 보인 걸린 초대(§7-3) — 그 가입 토큰에만 묶인 일회 id. kind org 의 ref 는 invites.token_hash(base64url),
-- group·contact 는 group_invites·link_invites id.
CREATE TABLE IF NOT EXISTS signup_pending (
  token_hash BLOB NOT NULL,
  id         TEXT NOT NULL,
  kind       TEXT NOT NULL,
  ref        TEXT NOT NULL,
  PRIMARY KEY (token_hash, id)
);
CREATE TABLE IF NOT EXISTS envelopes (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  msg_id       TEXT NOT NULL UNIQUE,
  kind         TEXT NOT NULL,
  from_user    TEXT NOT NULL,
  from_address TEXT NOT NULL,
  to_user      TEXT NOT NULL,
  to_address   TEXT NOT NULL,
  expires_ms   INTEGER NOT NULL,
  env_state    TEXT NOT NULL,
  sender_view  TEXT NOT NULL,
  abort_reason TEXT,
  message      TEXT
);
CREATE INDEX IF NOT EXISTS envelopes_to ON envelopes(to_user, seq);
CREATE INDEX IF NOT EXISTS envelopes_exp ON envelopes(expires_ms);
-- 기기별 보관(protocol §7.2-6): 저장 때 받는 사용자의 폐기되지 않은 기기 전부. 행이 없는 봉투는 옛 규칙(첫 ack 에 삭제).
CREATE TABLE IF NOT EXISTS envelope_devices (
  msg_id    TEXT NOT NULL REFERENCES envelopes(msg_id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  acked_ms  INTEGER,
  PRIMARY KEY (msg_id, device_id)
);
-- 기기 앞 받지 않은 봉투 집계(§5a 상한 — 잎 200 Commit 이면 대상마다 한 번).
CREATE INDEX IF NOT EXISTS envelope_devices_dev ON envelope_devices(device_id, acked_ms);
-- 내 기기 서명(#393, e2e-envelope §7a): 서명자 기기가 같은 사용자의 대상 기기에 한 lodelai-devcert-v1 서명. 쌍 하나에 하나.
CREATE TABLE IF NOT EXISTS device_certs (
  signer     TEXT NOT NULL,
  target     TEXT NOT NULL,
  sig        TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY (signer, target)
);
-- 첨부(묶음 15, ADR 0009 §1·§4). 파일은 <blob_dir>/<id 앞 2자>/<blob_id>, 여기는 메타데이터만. 토큰은 SHA-256 만.
CREATE TABLE IF NOT EXISTS blobs (
  blob_id        TEXT PRIMARY KEY,
  user           TEXT NOT NULL,
  device         TEXT NOT NULL,
  purpose        TEXT NOT NULL CHECK (purpose IN ('message','avatar')),
  ct_len         INTEGER NOT NULL,
  state          TEXT NOT NULL CHECK (state IN ('reserved','uploaded','attached')),
  msg_id         TEXT,
  put_token_hash BLOB,
  put_token_exp  INTEGER,
  created_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS blobs_msg ON blobs(msg_id);
CREATE TABLE IF NOT EXISTS blob_fetch (
  blob_id    TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  fetched_ms INTEGER NOT NULL,
  PRIMARY KEY (blob_id, device_id)
);
CREATE TABLE IF NOT EXISTS blob_tickets (
  token_hash BLOB PRIMARY KEY,
  blob_id    TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  exp_ms     INTEGER NOT NULL
);
-- 그룹 라우팅 표(묶음 16, ADR 0010 §1). 이름·멤버 상태의 정본은 클라이언트(E2E) — 서버는 group 메시지의 평문 헤더로만 맞춘다.
CREATE TABLE IF NOT EXISTS groups (
  gid        TEXT PRIMARY KEY,
  org        TEXT NOT NULL,
  seq        INTEGER NOT NULL DEFAULT 0,
  created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  gid        TEXT NOT NULL,
  user       TEXT NOT NULL,
  role       TEXT NOT NULL CHECK (role IN ('member','admin')),
  joined_seq INTEGER NOT NULL,
  left_seq   INTEGER,
  -- 조직 빠짐으로 나감(묶음 16 §3a ④) — groups.items[].org_left 힌트. op 로 나간 사람은 0.
  org_left   INTEGER NOT NULL DEFAULT 0,
  -- #845 ④: 조직 빠짐 때 그 사람 조직 — org_left 힌트는 같은 조직 멤버에게만(섞인 그룹). 옛 행은 NULL(누구에게나).
  left_org   TEXT,
  PRIMARY KEY (gid, user)
);
CREATE INDEX IF NOT EXISTS group_members_user ON group_members(user);
CREATE TABLE IF NOT EXISTS group_log (
  gid    TEXT NOT NULL,
  seq    INTEGER NOT NULL,
  msg_id TEXT NOT NULL,
  PRIMARY KEY (gid, seq)
);
CREATE TABLE IF NOT EXISTS signup_codes (
  email      TEXT PRIMARY KEY,
  code_hash  BLOB NOT NULL,
  expires_ms INTEGER NOT NULL,
  failures   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS signup_tokens (
  token_hash BLOB PRIMARY KEY,
  email      TEXT NOT NULL,
  expires_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signup_requests (
  email   TEXT NOT NULL,
  at_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signup_requests_email ON signup_requests(email, at_ms);
CREATE TABLE IF NOT EXISTS org_creates (
  email_mac BLOB NOT NULL,
  at_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS org_creates_email ON org_creates(email_mac, at_ms);
CREATE TABLE IF NOT EXISTS orgs (
  org_id     TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  admin      TEXT NOT NULL,
  created_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_admins (
  org_id TEXT NOT NULL,
  user   TEXT NOT NULL,
  PRIMARY KEY (org_id, user)
);
CREATE TABLE IF NOT EXISTS teams (
  team_id TEXT PRIMARY KEY,
  org_id  TEXT NOT NULL,
  name    TEXT NOT NULL,
  UNIQUE (org_id, name)
);
CREATE TABLE IF NOT EXISTS user_teams (
  user    TEXT NOT NULL,
  team_id TEXT NOT NULL,
  PRIMARY KEY (user, team_id)
);
CREATE TABLE IF NOT EXISTS invites (
  token_hash BLOB PRIMARY KEY,
  org_id     TEXT NOT NULL,
  email      TEXT,
  created_by TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS setup_codes (
  id         TEXT PRIMARY KEY,
  code_hash  BLOB NOT NULL UNIQUE,
  email_hash BLOB,
  email_mask TEXT,
  expires_ms INTEGER NOT NULL,
  created_ms INTEGER NOT NULL,
  email_keyed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mls_key_packages (
  device_id   TEXT NOT NULL,
  kp_ref      BLOB NOT NULL,
  data        BLOB NOT NULL,
  last_resort INTEGER NOT NULL DEFAULT 0,
  not_after   INTEGER NOT NULL,
  created_ms  INTEGER NOT NULL,
  PRIMARY KEY (device_id, kp_ref)
);
CREATE TABLE IF NOT EXISTS mls_kp_claims (
  claimer TEXT NOT NULL,
  target  TEXT NOT NULL,
  owner   INTEGER NOT NULL,
  at_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mls_kp_claims_claimer ON mls_kp_claims(claimer, at_ms);
CREATE INDEX IF NOT EXISTS mls_kp_claims_target ON mls_kp_claims(target, at_ms);
-- 묶음 22 §4: 그룹마다 비밀 없는 공개 상태(openmls PublicGroup 저장 값을 한 덩어리로)·지금 epoch·최신 GroupInfo.
CREATE TABLE IF NOT EXISTS mls_groups (
  group_id         TEXT PRIMARY KEY,
  kind             TEXT NOT NULL,
  epoch            INTEGER NOT NULL,
  storage          BLOB NOT NULL,
  group_info       BLOB NOT NULL,
  created_ms       INTEGER NOT NULL
);
-- §4-6 속도: 그룹·기기마다 Commit(복구 external 은 recovery = 1 로 따로 센다).
CREATE TABLE IF NOT EXISTS mls_commits (
  group_id  TEXT NOT NULL,
  device_id TEXT NOT NULL,
  recovery  INTEGER NOT NULL,
  at_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mls_commits_group ON mls_commits(group_id, at_ms);
-- §4-7 group 종류 2단계: 그룹마다 확정 전 Commit 하나(epoch N). storage·group_info 는 merge 뒤(N+1) 값.
CREATE TABLE IF NOT EXISTS mls_pending (
  group_id      TEXT PRIMARY KEY,
  epoch         INTEGER NOT NULL,
  msg_id        TEXT NOT NULL,
  commit_hash   TEXT NOT NULL,
  sender_user   TEXT NOT NULL,
  sender_device TEXT NOT NULL,
  op            TEXT NOT NULL,
  subject       TEXT,
  storage       BLOB NOT NULL,
  group_info    BLOB NOT NULL,
  gi_blob       TEXT,
  gi_size       INTEGER,
  gi_sha        TEXT,
  leaves        TEXT NOT NULL,
  joining       TEXT NOT NULL,
  excluded      TEXT NOT NULL,
  delivered_ms  INTEGER NOT NULL,
  -- Commit 메시지와 봉투 머리 — 옛 잎이 모두 받아 봉투가 지워져도 확정 때 새 잎(Welcome)에 보내려고.
  message       TEXT NOT NULL,
  from_address  TEXT NOT NULL,
  to_address    TEXT NOT NULL,
  expires_ms    INTEGER NOT NULL
);
-- 응답(사용자당 한 표 — 어느 기기든 ack 하나면 ack). 확정 뒤 fail 도 여기(관리자 줄 판정).
CREATE TABLE IF NOT EXISTS mls_votes (
  group_id    TEXT NOT NULL,
  epoch       INTEGER NOT NULL,
  commit_hash TEXT NOT NULL,
  user        TEXT NOT NULL,
  ack         INTEGER NOT NULL DEFAULT 0,
  fail        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, epoch, commit_hash, user)
);
-- 그룹마다 마지막 결과(§12-14 — 접속 때 다시 보냄, 확정 뒤 fail 판정).
CREATE TABLE IF NOT EXISTS mls_outcomes (
  group_id    TEXT PRIMARY KEY,
  epoch       INTEGER NOT NULL,
  commit_hash TEXT NOT NULL,
  final       INTEGER NOT NULL,
  group_seq   INTEGER,
  sender_user TEXT NOT NULL,
  excluded    TEXT NOT NULL,
  notified    INTEGER NOT NULL DEFAULT 0,
  at_ms       INTEGER NOT NULL
);
-- 확정 뒤 처리 못 함 알림(§12-20): 관리자 기기마다 접속 때 보낼 것(프레임 JSON), 30일.
CREATE TABLE IF NOT EXISTS mls_alerts (
  device_id TEXT NOT NULL,
  group_id  TEXT NOT NULL,
  hash      TEXT NOT NULL,
  frame     TEXT NOT NULL,
  at_ms     INTEGER NOT NULL,
  PRIMARY KEY (device_id, group_id, hash)
);
-- 무효로 돌아간 쥔 N+1 응용 메시지(§12-14 3): 보낸 기기가 꺼져 있었으면 접속 때 nack commit_void.
CREATE TABLE IF NOT EXISTS mls_void_nacks (
  device_id TEXT NOT NULL,
  msg_id    TEXT NOT NULL,
  at_ms     INTEGER NOT NULL,
  PRIMARY KEY (device_id, msg_id)
);
-- §7 duty: 그룹마다 지금 잎 기기(start·commit 때 같은 트랜잭션에서 새로).
CREATE TABLE IF NOT EXISTS mls_leaves (
  group_id  TEXT NOT NULL,
  device_id TEXT NOT NULL,
  PRIMARY KEY (group_id, device_id)
);
CREATE INDEX IF NOT EXISTS mls_leaves_dev ON mls_leaves(device_id);
-- §7 duty: 끝나지 않은 일(task = add_device·remove_device, subject = device_id). 다 되면(잎이 됨·빠짐·대상 폐기) 지운다.
CREATE TABLE IF NOT EXISTS mls_duties (
  group_id   TEXT NOT NULL,
  task       TEXT NOT NULL,
  subject    TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY (group_id, task, subject)
);
-- §7 duty: 그 일을 받은 기기와 줄 자리(rank). 다시 접속하면 같은 자리로 다시 준다.
CREATE TABLE IF NOT EXISTS mls_duty_ranks (
  group_id  TEXT NOT NULL,
  task      TEXT NOT NULL,
  subject   TEXT NOT NULL,
  device_id TEXT NOT NULL,
  rank      INTEGER NOT NULL,
  PRIMARY KEY (group_id, task, subject, device_id)
);
-- 모바일 검증(시험 relay 만, --mobile-push): 기기당 푸시 토큰 하나. salt 는 그 행의 무작위 16바이트 — 애플·구글에 나가는
-- 대화 묶음 값을 기기마다 다르게 만든다(push::conv_tag). key 는 그 기기 push 키 32바이트(push::seal — 같은 메시지도
-- 토큰마다 바이트가 다르게). 같은 OS 토큰에 기기 여럿(휴대폰 한 대의 여러 계정, 상한 PUSH_TOKEN_DEVICES — 넘으면 오래된
-- 등록부터 뺌). 애플·구글이 '없는 토큰'이라 답하면 그 토큰의 행을 모두 지운다(다시 깐 휴대폰). 기기 폐기 때 같이 지운다.
CREATE TABLE IF NOT EXISTS push_tokens (
  device_id  TEXT PRIMARY KEY,
  platform   TEXT NOT NULL,
  token      TEXT NOT NULL,
  env        TEXT NOT NULL,
  app_id     TEXT NOT NULL,
  salt       BLOB NOT NULL,
  key        BLOB NOT NULL,
  updated_ms INTEGER NOT NULL
);
-- 모바일 검증 S3(시험 relay 만, --mobile-push): 보낸 duty 기록 — duty 가 끝나면 rank 표는 지워져, 실기 판정(휴대폰 0)을
-- 뒤에 셀 수 있게 남긴다. `lodelai-relay duty-log` 가 읽기 전용으로 센다.
CREATE TABLE IF NOT EXISTS mls_duty_sent (
  device_id TEXT NOT NULL,
  task      TEXT NOT NULL,
  group_id  TEXT NOT NULL,
  rank      INTEGER NOT NULL,
  at_ms     INTEGER NOT NULL
);
-- #819: 무효 수가 상한에 닿아 관리자에게 알린 일(duty_stuck). 일이 지워지면 tick 이 done 을 알리고 이 행을 지운다.
CREATE TABLE IF NOT EXISTS mls_duty_stuck (
  group_id    TEXT NOT NULL,
  task        TEXT NOT NULL,
  subject     TEXT NOT NULL,
  epoch       INTEGER NOT NULL,
  commit_hash TEXT NOT NULL,
  sender_user TEXT NOT NULL,
  failed      TEXT NOT NULL,
  stale       TEXT NOT NULL,
  voids       INTEGER NOT NULL,
  at_ms       INTEGER NOT NULL,
  PRIMARY KEY (group_id, task, subject)
);
-- §5b·§5c: 그룹의 지금 GroupInfo 가 blob 이면 그 blob 을 붙잡는다(다음 Commit 으로 바뀔 때까지 지우지 않음, 멤버 사용자 기기가 받음).
CREATE TABLE IF NOT EXISTS mls_gi_blobs (
  group_id TEXT PRIMARY KEY,
  blob_id  TEXT NOT NULL,
  size     INTEGER NOT NULL,
  sha256   TEXT NOT NULL
);
-- §5a: 보관 상한·30일로 그 기기 앞 Handshake 를 비운 그룹. 접속마다 rejoin_needed, 그 기기가 그 그룹 잎으로 다시 들면 지운다.
CREATE TABLE IF NOT EXISTS mls_rejoin (
  device_id TEXT NOT NULL,
  group_id  TEXT NOT NULL,
  at_ms     INTEGER NOT NULL,
  PRIMARY KEY (device_id, group_id)
);
-- #598 ② recipient_outdated: 판 10 글을 전하지 않은 판 9 기기. 보낸 기기에 status{failed, recipient_outdated}(notified),
-- 같은 보낸 사람이 같은 msg_id 를 v9 로 다시 보내면 message 에 두고 이 기기에만 전한다(원래 봉투는 그대로 — 10 기기 몫).
CREATE TABLE IF NOT EXISTS outdated_devices (
  msg_id      TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  from_user   TEXT NOT NULL,
  from_device TEXT NOT NULL,
  expires_ms  INTEGER NOT NULL,
  message     TEXT,
  group_seq   INTEGER,
  notified    INTEGER NOT NULL DEFAULT 0,
  acked_ms    INTEGER,
  PRIMARY KEY (msg_id, device_id)
);
CREATE INDEX IF NOT EXISTS outdated_devices_from ON outdated_devices(from_device, notified);
-- 0.2.6 #809: 받는 기기가 열지 못했다고 보고한 글(delivered_ack.unreadable). 보낸 사람에게 status{failed,
-- recipient_unreadable(n=1)·recipient_unreadable_final(n=2)} — 그 기기가 대화의 지금 잎이고 다시 들기 표시가 없을 때.
-- 같은 보낸 사람이 같은 msg_id 로 다시 보내면 message 에 두고 이 기기에만 전한다(원래 봉투는 그대로 — 다른 기기 몫).
-- opened = 같은 사람의 다른 기기가 그 글을 열었다(n=2 알림을 내지 않음).
CREATE TABLE IF NOT EXISTS unreadable_reports (
  msg_id     TEXT NOT NULL,
  device_id  TEXT NOT NULL,
  from_user  TEXT NOT NULL,
  to_user    TEXT NOT NULL,
  group_id   TEXT NOT NULL,
  n          INTEGER NOT NULL,
  at_ms      INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  notified   INTEGER NOT NULL DEFAULT 0,
  opened     INTEGER NOT NULL DEFAULT 0,
  message    TEXT,
  group_seq  INTEGER,
  acked_ms   INTEGER,
  -- 다시 보낸 본문을 둔 뒤 그 기기가 스스로 다시 들었다(§1-9 (다)) — 그 뒤 또 못 열면 final 대신 한 번 더 알림.
  rejoined   INTEGER NOT NULL DEFAULT 0,
  -- 보낸 알림 수(최대 3 — n=1 둘 + final).
  sent       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (msg_id, device_id)
);
CREATE INDEX IF NOT EXISTS unreadable_reports_dev ON unreadable_reports(device_id, at_ms);
";

impl Db {
    /// 파일 DB 를 연다(없으면 만든다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        // envelopes.message 에 전달 전 본문이 있다 → umask 에 맡기지 않고 0600 으로 먼저 만든다(-wal·-shm 도 같은 모드).
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Self::init(Connection::open(path)?)
    }

    /// 메모리 DB(시험).
    ///
    /// # Errors
    /// sqlite 오류.
    /// 이메일 HMAC 키를 넣는다(한 번만 — 두 번째는 무시). main 이 relay.env 의 `LODELAI_EMAIL_HMAC_KEY` 로 부른다.
    pub fn set_email_key(&self, key: Vec<u8>) {
        let _ = self.email_key.set(key);
    }

    /// #738: relay.env 의 고정 이메일 키(한 번만). 이 뒤로 [`Db::setup_codes_rekey`] 가 조직 만들기 코드 이메일을 바꿔 쓴다.
    pub fn set_setup_email_key(&self, key: Vec<u8>) {
        let _ = self.setup_key.set(key);
    }

    /// 조직 만들기 코드 이메일 맞추기 값: (SHA 꼴, 키 묶은 꼴 — 키가 없으면 `None`). 정규화한 이메일을 받는다.
    fn setup_email_forms(&self, normalized: &str) -> (Vec<u8>, Option<Vec<u8>>) {
        let sha = setup_email_hash(normalized);
        let mac = self.setup_key.get().map(|k| setup_email_mac(k, &sha));
        (sha, mac)
    }

    /// #738: SHA 꼴(`email_keyed = 0`)로 남은 조직 만들기 코드 이메일을 키 묶은 꼴로 바꾸고, 같은 이메일 코드가 여럿이면 가장
    /// 늦게 만든 것만 남긴다(CLI 가 키 없이 지우지 못한 옛 코드) — 한 트랜잭션. 키가 없으면 하지 않는다. 바꾼 행 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn setup_codes_rekey(&self) -> Result<usize, DbError> {
        let Some(key) = self.setup_key.get() else {
            return Ok(0);
        };
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let rows: Vec<(String, Vec<u8>)> = {
            let mut st = tx.prepare(
                "SELECT id, email_hash FROM setup_codes WHERE email_keyed = 0 AND email_hash IS NOT NULL",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        if rows.is_empty() {
            return Ok(0);
        }
        // 막 바꾼 행은 잠시 2 로 둔다 — 지난 바꾸기 뒤에 CLI 가 쓴 것이라 이미 1 인 같은 이메일 행보다 늘 새것이다(같은 ms 여도
        // 무작위 id 로 갈리지 않게).
        for (id, sha) in &rows {
            tx.execute(
                "UPDATE setup_codes SET email_hash = ?2, email_keyed = 2 WHERE id = ?1",
                params![id, setup_email_mac(key, sha)],
            )?;
        }
        tx.execute(
            "DELETE FROM setup_codes WHERE email_keyed = 1 AND email_hash IN (
               SELECT email_hash FROM setup_codes WHERE email_keyed = 2)",
            [],
        )?;
        // 막 바꾼 것끼리(CLI 는 같은 이메일 SHA 행을 지우고 쓰니 보통 없음)는 늦게 만든 것, 같은 ms 면 늦게 넣은 행(rowid).
        tx.execute(
            "DELETE FROM setup_codes WHERE email_keyed = 2 AND EXISTS(
               SELECT 1 FROM setup_codes n WHERE n.email_keyed = 2 AND n.email_hash = setup_codes.email_hash
                 AND (n.created_ms > setup_codes.created_ms
                      OR (n.created_ms = setup_codes.created_ms AND n.rowid > setup_codes.rowid)))",
            [],
        )?;
        tx.execute(
            "UPDATE setup_codes SET email_keyed = 1 WHERE email_keyed = 2",
            [],
        )?;
        tx.commit()?;
        Ok(rows.len())
    }

    /// 이메일 HMAC 키를 쥐었나 — 없으면 contact_link·이메일 연락 요청이 못 돈다(그때 relay 는 contacts 를 알리지 않는다).
    #[must_use]
    pub fn has_email_key(&self) -> bool {
        self.email_key.get().is_some()
    }

    fn mac_of(&self, email: &str) -> Result<Vec<u8>, DbError> {
        self.email_key
            .get()
            .map(|k| email_mac(k, email))
            .ok_or(DbError::NoEmailKey)
    }

    pub fn memory() -> Result<Self, DbError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, DbError> {
        // 지운 행의 내용을 0 으로 덮는다(전달 즉시 지운 봉투 암호문이 free page 에 남지 않게, e2e-envelope §1·A-4).
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // 서비스가 도는 동안 `bootstrap`·`backup`·`backup-mark` 가 같은 파일에 쓴다 — 잠겨 있으면 기다린다.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        // relay 0.1.2: 한 행짜리 `setup_code` → 코드마다 한 행 `setup_codes`. 남은 코드는 이메일 없이 기한 그대로 옮긴다.
        let old_setup: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'setup_code')",
            [],
            |r| r.get(0),
        )?;
        if old_setup {
            conn.execute_batch(
                "BEGIN IMMEDIATE;
                 INSERT OR IGNORE INTO setup_codes(id, code_hash, email_hash, email_mask, expires_ms, created_ms)
                   SELECT lower(hex(randomblob(4))), code_hash, NULL, NULL, expires_ms, expires_ms - 3600000 FROM setup_code;
                 DROP TABLE setup_code;
                 COMMIT;",
            )?;
        }
        // #325 전 DB: revoked_ms 열이 없으면 더한다(그 전 기기는 NULL = 폐기 안 됨).
        let has_revoked: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'revoked_ms')",
            [],
            |r| r.get(0),
        )?;
        if !has_revoked {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN revoked_ms INTEGER")?;
        }
        // #313 전 DB: x25519_sig 열이 없으면 더한다(그 전 기기는 NULL — 디렉터리에 싣지 않고 피어가 버린다).
        let has_sig: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'x25519_sig')",
            [],
            |r| r.get(0),
        )?;
        if !has_sig {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN x25519_sig TEXT")?;
        }
        // #490 전 DB: devices.name(기기 이름 — 본인 디렉터리에만, 폐기 때 지움).
        let has_name: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'name')",
            [],
            |r| r.get(0),
        )?;
        if !has_name {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN name TEXT")?;
        }
        // 묶음 22 §12-27 ⓑ 전 DB: devices.last_seen_day(마지막 접속한 날의 UTC 0시 ms, 그 전 기기는 NULL).
        let has_seen: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'last_seen_day')",
            [],
            |r| r.get(0),
        )?;
        if !has_seen {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN last_seen_day INTEGER")?;
        }
        // #598 ② 전 DB: devices.hello_v(그 기기가 마지막으로 붙은 hello.v — NULL 은 모름 = 9 로 본다).
        let has_hello_v: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'hello_v')",
            [],
            |r| r.get(0),
        )?;
        if !has_hello_v {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN hello_v INTEGER")?;
        }
        // #870 전 DB: devices.own(마지막으로 붙은 연결이 hello.own 을 실었나 — NULL·0 은 내 기기끼리 글을 전하지 않음).
        let has_own: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name = 'own')",
            [],
            |r| r.get(0),
        )?;
        if !has_own {
            conn.execute_batch("ALTER TABLE devices ADD COLUMN own INTEGER")?;
        }
        // #886 ⑧ 전 DB: links.via — 'link' 면 그 줄 주인의 초대 링크로 상대가 들어와 맺어짐(주인 줄만). 그 전 줄은 NULL.
        let has_via: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('links') WHERE name = 'via')",
            [],
            |r| r.get(0),
        )?;
        if !has_via {
            conn.execute_batch("ALTER TABLE links ADD COLUMN via TEXT")?;
        }
        // #339 전 DB: users.email(hosted 가입한 사용자만, 한 이메일 = 한 아이디).
        let has_email: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'email')",
            [],
            |r| r.get(0),
        )?;
        if !has_email {
            conn.execute_batch("ALTER TABLE users ADD COLUMN email TEXT")?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email) WHERE email IS NOT NULL",
        )?;
        // 세션 이름(m1-spec §2) 전 DB: title·folder 열이 없으면 더한다(그 전 공개 세션은 NULL = 안 실음).
        let has_title: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('sessions_public') WHERE name = 'title')",
            [],
            |r| r.get(0),
        )?;
        if !has_title {
            conn.execute_batch(
                "ALTER TABLE sessions_public ADD COLUMN title TEXT;
                 ALTER TABLE sessions_public ADD COLUMN folder TEXT;",
            )?;
        }
        // 묶음 5: 내보내기·처리방침 동의·누가 끊었나·초대 확인 시도 수. 없으면 더한다(옛 행은 NULL·0).
        for (table, col, decl) in [
            ("users", "removed_ms", "INTEGER"),
            ("users", "privacy_version", "TEXT"),
            ("users", "privacy_ms", "INTEGER"),
            ("devices", "revoked_by", "TEXT"),
            ("users", "email_mac", "BLOB"),
            ("users", "invited_by", "TEXT"),
            ("sessions_public", "busy", "INTEGER NOT NULL DEFAULT 0"),
            ("sessions_public", "audience", "TEXT"),
            // 묶음 14 B1: 접속 표시를 같은 조직에 보일지(presence.set, 기본 켬).
            ("users", "share_presence", "INTEGER NOT NULL DEFAULT 1"),
            // 묶음 15: 프로필 사진 blob.
            ("users", "avatar_blob", "TEXT"),
            // 묶음 16: kind group 의 서버 순서(ack·deliver·replay 가 싣는다).
            ("envelopes", "group_seq", "INTEGER"),
            // 묶음 16 §3a: 그룹 맥락의 메시지(to = 그룹이거나 헤더 group) — 빠진 사람의 미전달 몫을 지울 때 쓴다.
            ("envelopes", "gid", "TEXT"),
            ("group_members", "org_left", "INTEGER NOT NULL DEFAULT 0"),
            ("group_members", "left_org", "TEXT"),
            // 묶음 23 §5: 세션의 프로젝트(id·구분 이름). 옛 행은 NULL = 안 실음.
            ("sessions_public", "project_id", "TEXT"),
            ("sessions_public", "project_name", "TEXT"),
            // #569 ③: 공개한 연결의 기기 — 그 기기가 끊기면 dead 로. 옛 행은 NULL = 손대지 않음.
            ("sessions_public", "device_id", "TEXT"),
            // Codex C2: 세션의 에이전트 종류. 옛 행은 NULL = claude_code.
            ("sessions_public", "agent", "TEXT"),
            // 관문 Y2: 주인 코어의 같은 이름 번호. 옛 행은 NULL = 번호 없음.
            ("sessions_public", "no", "INTEGER"),
            // #739: relay 가 그 기기 끊김으로 dead 로 바꾼 세션(주인이 끝낸 dead 와 가른다). publish 하면 0.
            ("sessions_public", "offline", "INTEGER NOT NULL DEFAULT 0"),
            ("signup_codes", "privacy_version", "TEXT"),
            ("signup_codes", "privacy_ms", "INTEGER"),
            ("signup_tokens", "privacy_version", "TEXT"),
            ("signup_tokens", "privacy_ms", "INTEGER"),
            (
                "signup_tokens",
                "check_failures",
                "INTEGER NOT NULL DEFAULT 0",
            ),
            // 묶음 22 §5a: Handshake 봉투의 그룹(base64url). 응용 메시지·옛 봉투는 NULL — 7일 만료 작업은 NULL 만 본다.
            ("envelopes", "handshake_group", "TEXT"),
            // 묶음 22 §5b·§6: 그룹 id 를 이루는 사용자(줄바꿈으로 이음 — pair 둘, self 하나). 멤버 판정은 잎이 아니라 이것으로.
            ("mls_groups", "users", "TEXT"),
            // 묶음 22 §12-11 ⓐ devrevoke: 증명 있는 폐기(at·서명자·서명). 있으면 그 기기의 devcert 를 남기고 디렉터리 revocations 에.
            ("devices", "revoke_at", "TEXT"),
            ("devices", "revoke_signer", "TEXT"),
            ("devices", "revoke_sig", "TEXT"),
            // 묶음 22 §4-7: 확정 전 Commit 의 N+1 응용 메시지 — 그 그룹 열쇠, 확정되면 NULL(그때 배달), 무효면 지움.
            ("envelopes", "mls_hold", "TEXT"),
            // #554: 조직 사진 blob, 그리고 조직 사진으로 예약한 blob 의 조직(PUT 끝에서 관리자를 다시 본다).
            ("orgs", "avatar_blob", "TEXT"),
            ("blobs", "for_org", "TEXT"),
            // #881 지난 대화 옮기기 조각 — 받을 기기 하나(메시지에 묶이지 않음).
            ("blobs", "for_device", "TEXT"),
            // #577: 마지막으로 붙어 있던 시각(인증 때·그 기기의 마지막 연결이 끊길 때). 옛 행은 NULL.
            ("devices", "last_auth_ms", "INTEGER"),
            // #738: 조직 만들기 코드 이메일 꼴 — 0 = SHA(옛 행·CLI), 1 = 키 묶은 꼴(relay 가 바꿔 씀).
            ("setup_codes", "email_keyed", "INTEGER NOT NULL DEFAULT 0"),
            // #819: 그 일의 Commit 이 무효가 된 수, 그 전엔 나눠 주지 않는 시각(상한 뒤 하루 늦춤), 무효를 낸 기기(줄바꿈).
            ("mls_duties", "voids", "INTEGER NOT NULL DEFAULT 0"),
            ("mls_duties", "next_ms", "INTEGER NOT NULL DEFAULT 0"),
            ("mls_duties", "voided_by", "TEXT NOT NULL DEFAULT ''"),
            // 기기가 스스로 알린 OS(`device.name.os`, 판 15) — 화면의 '이름 없는 기기' 대신 글. 표시용(신뢰 근거 아님).
            ("devices", "os", "TEXT"),
            // #874: 고른 기본 이미지(정규 JSON — {kind:character,seed}·{kind:initial,tone}). NULL = 기본.
            ("users", "look_json", "TEXT"),
            // #845: 공간 종류 — 'org'(옛 행·조직) | 'personal'(사람 하나인 개인 공간, org_admins 없음).
            ("orgs", "kind", "TEXT NOT NULL DEFAULT 'org'"),
            // 조직 고유색(org.update.color, #rrggbb 소문자) — NULL = 자동 색.
            ("orgs", "color", "TEXT"),
            // #845 둘째 ② 조직 밖 연락 막기('closed'). NULL = 열림.
            ("orgs", "external", "TEXT"),
            // #870 맥 잠듦: 그 기기의 마지막 연결이 어떻게 끝났나 — 'sleep'|'quit'|'lost'. 붙을 때 'lost' 로 적고 닫는 이유로 덮는다.
            ("devices", "away", "TEXT"),
            // #845: 운영 멈춤 시각(`lodelai-relay suspend`). NULL = 멈추지 않음.
            ("users", "suspended_ms", "INTEGER"),
            // #845 ⑤ 멈춤이 풀리는 때(없으면 운영자가 풀 때까지).
            ("users", "suspended_until", "INTEGER"),
            // #845 ②: 요청 id(ULID — link.answer 가 가리킴)와 요청한 사람이 친 값(이메일·아이디 그대로, outgoing 에만).
            ("links", "id", "TEXT"),
            ("links", "shown", "TEXT"),
            // #845 ③: 막은 시각(30일 안 서로 다른 3명이 막으면 줄임, §7-1). 옛 줄은 NULL — 세지 않는다.
            ("blocks", "at_ms", "INTEGER"),
            // #845 ③: 요청 상한을 줄인 끝 시각(그때까지 하루 5).
            ("users", "throttled_until", "INTEGER"),
            // #845 §7-55 이 기기가 끈 알림 갈래(쉼표로 이음, chat·group·agents·invite). NULL·'' = 다 켬.
            ("push_tokens", "off", "TEXT"),
            // #882 실시간 현황(ADR 0014): 이 기기가 현황 푸시를 받나·iOS push-to-start 토큰·떠 있는 활동의 갱신 토큰과 시작 시각·
            // 활동 토큰 없이 start 를 보낸 시각(토큰이 올 때까지 다시 보내지 않게). 같은 행이라 행을 지우면 같이 지워진다.
            ("push_tokens", "live_on", "INTEGER"),
            ("push_tokens", "live_start_token", "TEXT"),
            ("push_tokens", "live_activity_token", "TEXT"),
            ("push_tokens", "live_activity_ms", "INTEGER"),
            ("push_tokens", "live_start_sent_ms", "INTEGER"),
        ] {
            add_column(&conn, table, col, decl)?;
        }
        unique_push_token_off(&conn)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS push_tokens_token ON push_tokens(platform, token)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS envelopes_hs ON envelopes(handshake_group) WHERE handshake_group IS NOT NULL",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS users_email_mac ON users(email_mac) WHERE email_mac IS NOT NULL",
            [],
        )?;
        // #577 메일 확인 끊기(계약 6490433889 §4): 사용자당 걸기 하나(끝난 뒤에도 창 동안 남는다 — 디렉터리 recovery),
        // 막기 기록(쿨다운·30일 상한 집계, 30일 보관).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS recoveries (
               user       TEXT PRIMARY KEY,
               requester  TEXT NOT NULL,
               created_ms INTEGER NOT NULL,
               at_ms      INTEGER NOT NULL,
               targets    TEXT NOT NULL,
               state      TEXT NOT NULL,
               ended_ms   INTEGER,
               blocked_by TEXT
             );
             CREATE TABLE IF NOT EXISTS recovery_blocks (
               user  TEXT NOT NULL,
               at_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS recovery_blocks_user ON recovery_blocks(user, at_ms);
             -- §9 ②: 폐기된 기기 큐에만 있던 글 — 보낸 사람에게 status{failed, recipient_device_changed}(notified), 같은
             -- msg_id 로 다시 오면 옛 봉투를 지우고 다시 받는다.
             CREATE TABLE IF NOT EXISTS device_changed (
               msg_id    TEXT PRIMARY KEY,
               from_user TEXT NOT NULL,
               at_ms     INTEGER NOT NULL,
               expires_ms INTEGER NOT NULL,
               notified  INTEGER NOT NULL DEFAULT 0
             );",
        )?;
        // #737: 걸기 뒤 대상(옛 기기)이 붙었는지·그래서 한 번 미뤘는지. 붙은 적이 있으면 시각에 실행하지 않고 한 번만 미룬다.
        add_column(
            &conn,
            "recoveries",
            "seen_after",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column(
            &conn,
            "recoveries",
            "deferred",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            email_key: std::sync::OnceLock::new(),
            setup_key: std::sync::OnceLock::new(),
            max_devices: std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_DEVICES),
        })
    }

    fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ---------------------------------------------------------------- users·devices

    /// 기기 등록. 사용자가 없으면 만든다(조직 `local`). 같은 기기가 이미 있으면 [`DbError::Conflict`](재기동의 재등록).
    /// 사용자가 이미 있으면 `existing_user` 일 때만 기기를 더한다 — 아니면 [`DbError::UserExists`]. 남의 아이디로 만든
    /// 기기 연결 코드가 그 사람 계정에 기기를 끼워 넣지 못하게, 판정은 서버가 한다(#298 리뷰, 디렉터리 캐시에 기대지 않음).
    ///
    /// # Errors
    /// sqlite 오류, 같은 기기, 이미 있는 사용자.
    #[allow(clippy::too_many_arguments)]
    pub fn register_device(
        &self,
        user: &str,
        display: Option<&str>,
        device_id: &str,
        ed25519: &str,
        x25519: &str,
        x25519_sig: &str,
        now_ms: i64,
        existing_user: bool,
    ) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let same_device: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1)",
            [device_id],
            |r| r.get(0),
        )?;
        if same_device {
            return Err(DbError::Conflict);
        }
        let user_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1)",
            [user],
            |r| r.get(0),
        )?;
        if user_exists && !existing_user {
            return Err(DbError::UserExists);
        }
        self.check_device_room(&tx, user)?;
        tx.execute(
            "INSERT INTO users(user, org, display) VALUES (?1, ?2, ?3)
             ON CONFLICT(user) DO UPDATE SET display = COALESCE(excluded.display, users.display)",
            params![user, LOCAL_ORG, display],
        )?;
        let n = tx.execute(
            // #888: hosted 등록과 같이 그 사용자의 어느 기기보다 늦게(같은 ms·시계 뒤로 가기에 뿌리가 바뀌지 않게).
            "INSERT OR IGNORE INTO devices(device_id, user, ed25519, x25519, created_ms, x25519_sig) VALUES (?1, ?2, ?3, ?4,
               MAX(?5, COALESCE((SELECT MAX(created_ms) + 1 FROM devices WHERE user = ?2), ?5)), ?6)",
            params![device_id, user, ed25519, x25519, now_ms, x25519_sig],
        )?;
        if n == 0 {
            return Err(DbError::Conflict);
        }
        tx.commit()?;
        Ok(())
    }

    // ---------------------------------------------------------------- MLS 그룹 (묶음 22 §4)

    /// 그룹 행: (종류, epoch, 공개 상태 저장 값, GroupInfo).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::type_complexity)]
    pub fn mls_group(
        &self,
        group_id: &str,
    ) -> Result<Option<(String, u64, Vec<u8>, Vec<u8>)>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT kind, epoch, storage, group_info FROM mls_groups WHERE group_id = ?1",
                [group_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        r.get(2)?,
                        r.get(3)?,
                    ))
                },
            )
            .optional()?)
    }

    /// 새 그룹(epoch 0). 이미 있으면 `false`(§2a — pair·self 의 시작은 한 번만).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn mls_group_start(
        &self,
        group_id: &str,
        kind: &str,
        users: &[String],
        storage: &[u8],
        group_info: &[u8],
        gi_pin: Option<(&GiPin, &str, &str)>,
        leaves: &[String],
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO mls_groups(group_id, kind, epoch, storage, group_info, created_ms, users)
             VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6)",
            params![group_id, kind, storage, group_info, now_ms, users.join("\n")],
        )?;
        if n != 1 {
            return Ok(false);
        }
        if let Some((p, msg_id, user)) = gi_pin {
            // 새 그룹이라 풀 옛 blob 이 없다.
            set_gi_pin_in(&tx, group_id, Some(p), msg_id, user)?;
        }
        set_leaves_in(&tx, group_id, leaves)?;
        tx.commit()?;
        Ok(true)
    }

    /// 그룹의 지금 GroupInfo blob(§5b — 없으면 DB 의 바이트를 프레임 안으로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn gi_pin(&self, group_id: &str) -> Result<Option<GiPin>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT blob_id, size, sha256 FROM mls_gi_blobs WHERE group_id = ?1",
                [group_id],
                |r| {
                    Ok(GiPin {
                        blob_id: r.get(0)?,
                        size: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        sha256: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// Handshake 의 blob 칸이 묶을 수 있는가(§5c, 15 의 blobs_bindable 과 같은 조건 + 예약 길이 = `size` ≤
    /// [`crate::mls::MLS_BLOB_MAX_BYTES`] — 큰 것은 읽기 전에 거름).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_blobs_bindable(&self, user: &str, refs: &[(String, u64)]) -> Result<bool, DbError> {
        let mut seen = std::collections::HashSet::new();
        if !refs.iter().all(|(b, _)| seen.insert(b))
            || refs
                .iter()
                .any(|(_, n)| *n > crate::mls::MLS_BLOB_MAX_BYTES)
        {
            return Ok(false);
        }
        let c = self.c();
        for (b, size) in refs {
            let ok: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id = ?1 AND user = ?2 AND purpose = 'message'
                   AND state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL AND ct_len = ?3)",
                params![b, user, i64::try_from(*size).unwrap_or(-1)],
                |r| r.get(0),
            )?;
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 그룹 id 를 이루는 사용자(§5b 멤버 판정). 없는 그룹이면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_group_users(&self, group_id: &str) -> Result<Option<Vec<String>>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT users FROM mls_groups WHERE group_id = ?1",
                [group_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .map(|u| {
                u.unwrap_or_default()
                    .split('\n')
                    .filter(|x| !x.is_empty())
                    .map(str::to_owned)
                    .collect()
            }))
    }

    /// Commit 적용(§4): epoch 가 `from` 일 때만 `from + 1` 로 올리고 상태·GroupInfo 를 바꾼다. 그 사이 다른 Commit 이 이겼으면
    /// `None`(stale_epoch). 속도 기록·본문 blob 칸(`attach`) 묶기도 같은 트랜잭션. 돌려주는 값: 풀려서 지운 옛 GroupInfo blob
    /// (파일은 호출자가 — 커밋 뒤).
    ///
    /// # Errors
    /// 묶을 수 없는 blob 이면 BlobUnavailable(아무것도 바꾸지 않음 — epoch 그대로), 그 밖 sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn mls_group_commit(
        &self,
        group_id: &str,
        from: u64,
        storage: &[u8],
        group_info: &[u8],
        device_id: &str,
        recovery: bool,
        gi_pin: (Option<&GiPin>, &str, &str),
        attach: &[String],
        leaves: &[String],
        now_ms: i64,
    ) -> Result<Option<Vec<String>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let n = tx.execute(
            "UPDATE mls_groups SET epoch = epoch + 1, storage = ?3, group_info = ?4
             WHERE group_id = ?1 AND epoch = ?2",
            params![
                group_id,
                i64::try_from(from).unwrap_or(-1),
                storage,
                group_info
            ],
        )?;
        if n != 1 {
            return Ok(None);
        }
        // §5c: 묶기 검사(mls_blobs_bindable)는 트랜잭션 밖 — 그 사이 다른 메시지가 먼저 묶었으면 여기서 통째로 되돌린다.
        bind_mls_blobs_in(&tx, gi_pin.1, gi_pin.2, attach)?;
        tx.execute(
            "INSERT INTO mls_commits(group_id, device_id, recovery, at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![group_id, device_id, recovery, now_ms],
        )?;
        // 지금 GroupInfo 가 바뀌었다 — 옛 blob 은 풀고(그 Commit 의 수명대로, 수명이 끝났으면 지금), 새것이 blob 이면 붙잡는다.
        let removed = set_gi_pin_in(&tx, group_id, gi_pin.0, gi_pin.1, gi_pin.2)?;
        set_leaves_in(&tx, group_id, leaves)?;
        tx.commit()?;
        Ok(Some(removed))
    }

    /// 속도 셈(§4-6): (이 기기의 이 그룹 시간당 보통 Commit, 같은 것 복구, 그룹 하루 전체).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_commit_counts(
        &self,
        group_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, i64), DbError> {
        const HOUR: i64 = 60 * 60 * 1000;
        let c = self.c();
        c.execute(
            "DELETE FROM mls_commits WHERE at_ms <= ?1",
            [now_ms - 24 * HOUR],
        )?;
        let q = |recovery: bool| -> rusqlite::Result<i64> {
            c.query_row(
                "SELECT COUNT(*) FROM mls_commits WHERE group_id = ?1 AND device_id = ?2 AND recovery = ?3 AND at_ms > ?4",
                params![group_id, device_id, recovery, now_ms - HOUR],
                |r| r.get(0),
            )
        };
        let day: i64 = c.query_row(
            "SELECT COUNT(*) FROM mls_commits WHERE group_id = ?1 AND recovery = 0",
            [group_id],
            |r| r.get(0),
        )?;
        Ok((q(false)?, q(true)?, day))
    }

    /// 봉투를 정한 (사용자, 기기) 대상으로 저장한다(묶음 22 — 잎 목록, 받는 사용자 밖의 기기도). 같은 msg_id 면 Conflict.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn store_envelope_to(
        &self,
        h: &StoredHeader,
        message: &str,
        targets: &[(String, String)],
        blobs: &[String],
    ) -> Result<(), DbError> {
        // 받을 잎이 없으면 저장하지 않는다(§5d — 행 없는 봉투는 옛 규칙으로 받는 사용자의 아무 기기에 간다).
        if targets.is_empty() {
            return Ok(());
        }
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        // 헤더 첨부(묶음 15)를 이 메시지에 묶는다 — 받는 잎의 blob.get·'모두 받음'은 아래 기기 행으로(§5d).
        for b in blobs {
            let n = tx.execute(
                "UPDATE blobs SET state = 'attached', msg_id = ?1
                 WHERE blob_id = ?2 AND user = ?3 AND purpose = 'message' AND state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL",
                params![h.msg_id, b, h.from_user],
            )?;
            if n != 1 {
                return Err(DbError::BlobUnavailable);
            }
        }
        insert_envelope(&tx, h, message, None)?;
        for (_, d) in targets {
            tx.execute(
                "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                params![h.msg_id, d],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Handshake 저장(§5a·§12-12). 한 트랜잭션에: ① `rejoined` 기기의 그 그룹 rejoin 표시를 지운다(다시 잎이 됨)
    /// ② rejoin 표시가 남은 대상은 빼고 저장한다(다시 들어갈 땐 최신 GroupInfo — 쌓으면 다시 넘친다) ③ 대상 기기마다
    /// 받지 않은 Handshake 가 `cap` 을 넘으면 가장 오래 기다린 그룹부터 통째로 비우고 rejoin 표시를 한다.
    /// 돌려주는 값: 이 메시지를 실제로 받을 대상, 새로 rejoin 표시가 생긴 (사용자, 기기).
    ///
    /// # Errors
    /// 같은 msg_id 면 Conflict, 묶을 수 없는 blob 이면 BlobUnavailable(아무것도 쓰지 않음), 그 밖 sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn store_handshake(
        &self,
        h: &StoredHeader,
        message: &str,
        group: &str,
        targets: &[(String, String)],
        rejoined: &[String],
        attach: &[String],
        cap: HandshakeCap,
        now_ms: i64,
    ) -> Result<HandshakeStored, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        for d in rejoined {
            tx.execute(
                "DELETE FROM mls_rejoin WHERE device_id = ?1 AND group_id = ?2",
                params![d, group],
            )?;
            // 0.2.6 #809 §1-9 (다): 1:1·내 기기 그룹의 다시 들기 — 그룹 길(mls_finalize)과 같다.
            tx.execute(
                "UPDATE unreadable_reports SET rejoined = 1
                 WHERE device_id = ?1 AND group_id = ?2 AND message IS NOT NULL",
                params![d, group],
            )?;
        }
        insert_envelope(&tx, h, message, Some(group))?;
        // §5c: 본문 blob 칸을 이 Handshake 에 묶는다(Commit 은 mls_group_commit 이 이미 묶음 — 그대로 둠).
        bind_mls_blobs_in(&tx, &h.msg_id, &h.from_user, attach)?;
        let mut out = HandshakeStored::default();
        for (u, d) in targets {
            let marked: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM mls_rejoin WHERE device_id = ?1 AND group_id = ?2)",
                params![d, group],
                |r| r.get(0),
            )?;
            if marked {
                continue;
            }
            tx.execute(
                "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                params![h.msg_id, d],
            )?;
            let mut evicted_here = false;
            loop {
                let (n, bytes): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(length(CAST(e.message AS BLOB))), 0)
                     FROM envelope_devices x JOIN envelopes e ON e.msg_id = x.msg_id
                     WHERE x.device_id = ?1 AND x.acked_ms IS NULL
                       AND e.handshake_group IS NOT NULL AND e.message IS NOT NULL",
                    [d],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if n <= cap.count && bytes <= cap.bytes {
                    break;
                }
                let oldest: String = tx.query_row(
                    "SELECT e.handshake_group FROM envelope_devices x JOIN envelopes e ON e.msg_id = x.msg_id
                     WHERE x.device_id = ?1 AND x.acked_ms IS NULL
                       AND e.handshake_group IS NOT NULL AND e.message IS NOT NULL
                     ORDER BY e.seq LIMIT 1",
                    [d],
                    |r| r.get(0),
                )?;
                out.removed_blobs
                    .extend(evict_handshakes(&tx, d, &oldest, now_ms)?);
                evicted_here |= oldest == group;
                if !out.marked.iter().any(|(_, x)| x == d) {
                    out.marked.push((u.clone(), d.clone()));
                }
            }
            if !evicted_here {
                out.targets.push((u.clone(), d.clone()));
            }
        }
        // 확정을 기다리는 group Commit(§4-7)은 지금 잎이 없어도(혼자 만든 그룹의 첫 Commit) 두어야 한다 — 새 잎은 확정 때
        // 받을 기기가 되고, 그때 Welcome·GroupInfo blob(§5c)이 있어야 한다.
        let pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_pending WHERE msg_id = ?1)",
            [&h.msg_id],
            |r| r.get(0),
        )?;
        if !pending {
            out.removed_blobs.extend(drop_if_no_target(&tx, &h.msg_id)?);
        }
        tx.commit()?;
        truncate_wal(&c);
        Ok(out)
    }

    /// 30일 지난 Handshake(§5a — `expires_ms` 는 relay 가 받은 시각 + 30일): 아직 받지 않은 기기마다 그 그룹을 비우고 rejoin
    /// 표시, 헤더를 지운다. 상태기계·`status expired` 는 거치지 않는다. 돌려주는 값: 새로 표시가 생긴 (사용자, 기기).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn expire_handshakes(&self, now_ms: i64) -> Result<ExpiredHandshakes, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let rows: Vec<(String, String, Option<String>, Option<String>)> = {
            let mut st = tx.prepare(
                "SELECT e.msg_id, e.handshake_group, x.device_id, d.user FROM envelopes e
                 LEFT JOIN envelope_devices x ON x.msg_id = e.msg_id AND x.acked_ms IS NULL
                 LEFT JOIN devices d ON d.device_id = x.device_id
                 WHERE e.handshake_group IS NOT NULL AND e.expires_ms <= ?1 ORDER BY e.seq",
            )?;
            let rows = st.query_map([now_ms], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let mut marked: Vec<(String, String)> = Vec::new();
        let mut removed: Vec<String> = Vec::new();
        for (msg_id, group, device, user) in &rows {
            if let (Some(d), Some(u)) = (device, user) {
                removed.extend(evict_handshakes(&tx, d, group, now_ms)?);
                if !marked.iter().any(|(_, x)| x == d) {
                    marked.push((u.clone(), d.clone()));
                }
            }
            // Handshake 행과 그 blob 을 같은 트랜잭션에서(§5c — 7일 첨부 규칙이 아니라 Handshake 수명).
            removed.extend(drop_blobs_of(&tx, msg_id)?);
            tx.execute("DELETE FROM envelopes WHERE msg_id = ?1", [msg_id])?;
        }
        tx.commit()?;
        if !rows.is_empty() {
            truncate_wal(&c);
        }
        removed.sort();
        removed.dedup();
        Ok((marked, removed))
    }

    /// 이 기기가 다시 들어가야 할 그룹(§5a `rejoin_needed`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn rejoin_for(&self, device_id: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT group_id FROM mls_rejoin WHERE device_id = ?1 ORDER BY at_ms, group_id",
        )?;
        let rows = st.query_map([device_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 그룹에 다시 들어가야 한다고 표시된 기기(#599 — 확정·무효 결과를 보탠다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn rejoin_devices(&self, group_id: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT device_id FROM mls_rejoin WHERE group_id = ?1 ORDER BY at_ms, device_id",
        )?;
        let rows = st.query_map([group_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 이 기기가 그 그룹에 다시 들어가야 한다고 표시한다(#599 ①). 새로 남겼으면 `true`(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn rejoin_mark(
        &self,
        device_id: &str,
        group_id: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let n = self.c().execute(
            "INSERT OR IGNORE INTO mls_rejoin(device_id, group_id, at_ms) VALUES (?1, ?2, ?3)",
            params![device_id, group_id, now_ms],
        )?;
        Ok(n > 0)
    }

    // ---------------------------------------------------------------- MLS duty (묶음 22 §7)

    /// 그 사용자의 기기가 잎으로 든 그룹.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn groups_with_user_leaves(&self, user: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT DISTINCT l.group_id FROM mls_leaves l JOIN devices d ON d.device_id = l.device_id
             WHERE d.user = ?1 ORDER BY l.group_id",
        )?;
        let rows = st.query_map([user], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 그룹의 지금 잎 기기.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_leaves(&self, group_id: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st =
            c.prepare("SELECT device_id FROM mls_leaves WHERE group_id = ?1 ORDER BY device_id")?;
        let rows = st.query_map([group_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 일 하나를 남긴다(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_add(
        &self,
        group_id: &str,
        task: &str,
        subject: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_duties(group_id, task, subject, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![group_id, task, subject, now_ms],
        )?;
        Ok(())
    }

    /// 그 사용자의 산 기기 중 그 그룹에 add_device 일이 남은 것이 있나(#577 §9 ② — 끊기 완료가 남긴 일, 새 기기가 아직 안 듦).
    ///
    /// # Errors
    /// DB 오류.
    pub fn add_duty_pending_for_user(&self, group_id: &str, user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_duties t JOIN devices d ON d.device_id = t.subject
               WHERE t.group_id = ?1 AND t.task = 'add_device' AND d.user = ?2 AND d.revoked_ms IS NULL)",
            params![group_id, user],
            |r| r.get(0),
        )?)
    }

    /// 끝나지 않은 일 전부(그룹, task, subject) — 만든 순.
    ///
    /// # Errors
    /// sqlite 오류.
    /// 그 사람이 그 MLS 그룹에 다시 들어도 되나 — group 종류(groups 표에 있음)면 지금 멤버(left_seq 없음)일 때만, pair·self 는 늘.
    /// 나간 사람의 잎은 remove_user 전까지 남아 있어 잎 기준 일만으로는 가르지 못한다(g025f 리뷰 🟡).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn may_rejoin(&self, group_id: &str, user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM groups WHERE gid = ?1)
                 OR EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = ?2 AND left_seq IS NULL)",
            params![group_id, user],
            |r| r.get(0),
        )?)
    }

    /// 받는 사람의 새 잎이 1:1 에 들기 전에 봉인돼 그 사람의 어느 기기에도 아직 닿지 않은 `from` → `to` 1:1 글(g025g) — (msg_id,
    /// 보관 기한). 그 사람 기기 하나라도 받은 글·새 잎 앞으로 실린 글은 뺀다(다시 보내면 같은 글이 두 번 가지 않게).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn undelivered_before_join(
        &self,
        to_user: &str,
        from_user: &str,
        new_device: &str,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT e.msg_id, e.expires_ms FROM envelopes e
             WHERE e.to_user = ?1 AND e.from_user = ?2 AND e.kind = 'chat'
               AND EXISTS(SELECT 1 FROM envelope_devices ed JOIN devices d ON d.device_id = ed.device_id
                          WHERE ed.msg_id = e.msg_id AND d.user = ?1 AND ed.acked_ms IS NULL)
               AND NOT EXISTS(SELECT 1 FROM envelope_devices ed JOIN devices d ON d.device_id = ed.device_id
                              WHERE ed.msg_id = e.msg_id AND d.user = ?1 AND ed.acked_ms IS NOT NULL)
               AND NOT EXISTS(SELECT 1 FROM envelope_devices ed WHERE ed.msg_id = e.msg_id AND ed.device_id = ?3)
             ORDER BY e.seq",
        )?;
        let rows = st.query_map(params![to_user, from_user, new_device], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 사람이 지금 그 그룹(묶음 16)의 멤버인가(left_seq 없음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_member_now(&self, gid: &str, user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = ?2 AND left_seq IS NULL)",
            params![gid, user],
            |r| r.get(0),
        )?)
    }

    /// 이 task 의 일과 남긴 때(ms) — (그룹, 대상, created_ms).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duties_of(&self, task: &str) -> Result<Vec<(String, String, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT group_id, subject, created_ms FROM mls_duties WHERE task = ?1 ORDER BY created_ms, group_id, subject",
        )?;
        let rows = st.query_map([task], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 남은 일 모두 — (그룹, task, 대상).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duties(&self) -> Result<Vec<(String, String, String)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT group_id, task, subject FROM mls_duties ORDER BY created_ms, group_id, task, subject",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 지금 나눠 줄 일(#819: 상한 뒤 늦춘 일은 `next_ms` 가 지날 때까지 뺀다) — (그룹, task, 대상, 무효를 낸 기기).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duties_due(&self, now_ms: i64) -> Result<Vec<DutyDue>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT group_id, task, subject, voided_by FROM mls_duties WHERE next_ms <= ?1
             ORDER BY created_ms, group_id, task, subject",
        )?;
        let rows = st.query_map([now_ms], |r| {
            Ok(DutyDue {
                group_id: r.get(0)?,
                task: r.get(1)?,
                subject: r.get(2)?,
                voided_by: split_lines(&r.get::<_, String>(3)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 그룹의 남은 일 (task, 대상).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duties_in(&self, group_id: &str) -> Result<Vec<(String, String)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT task, subject FROM mls_duties WHERE group_id = ?1 ORDER BY created_ms, task, subject",
        )?;
        let rows = st.query_map([group_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #819: 그 일의 Commit 이 무효가 됐다 — 무효 수를 하나 올리고 보낸 기기를 적는다. 수가 `max` 이상이면 `next_ms` 를
    /// `now + delay_ms` 로 늦춘다. 올린 뒤의 수(일이 없으면 0).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn duty_note_void(
        &self,
        group_id: &str,
        task: &str,
        subject: &str,
        device_id: &str,
        now_ms: i64,
        max: u64,
        delay_ms: i64,
    ) -> Result<u64, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let row: Option<(i64, String)> = tx
            .query_row(
                "SELECT voids, voided_by FROM mls_duties WHERE group_id = ?1 AND task = ?2 AND subject = ?3",
                params![group_id, task, subject],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((voids, by)) = row else {
            return Ok(0);
        };
        let voids = u64::try_from(voids).unwrap_or(0).saturating_add(1);
        let mut by = split_lines(&by);
        if !by.iter().any(|d| d == device_id) {
            by.push(device_id.to_owned());
        }
        let next = if voids >= max {
            now_ms.saturating_add(delay_ms)
        } else {
            0
        };
        tx.execute(
            "UPDATE mls_duties SET voids = ?4, voided_by = ?5, next_ms = ?6
             WHERE group_id = ?1 AND task = ?2 AND subject = ?3",
            params![
                group_id,
                task,
                subject,
                i64::try_from(voids).unwrap_or(i64::MAX),
                by.join("\n"),
                next
            ],
        )?;
        tx.commit()?;
        Ok(voids)
    }

    /// #819: 상한에 닿은 일을 적는다(이미 있으면 마지막 무효로 바꿔 씀). 처음 적었으면 `true`(알림은 그때 한 번).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_stuck_put(&self, s: &DutyStuck) -> Result<bool, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let had: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_duty_stuck WHERE group_id = ?1 AND task = ?2 AND subject = ?3)",
            params![s.group_id, s.task, s.subject],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO mls_duty_stuck(group_id, task, subject, epoch, commit_hash, sender_user, failed, stale, voids, at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                s.group_id,
                s.task,
                s.subject,
                i64::try_from(s.epoch).unwrap_or(i64::MAX),
                s.commit_hash,
                s.sender_user,
                s.failed.join("\n"),
                s.stale.join("\n"),
                i64::try_from(s.voids).unwrap_or(i64::MAX),
                s.at_ms
            ],
        )?;
        tx.commit()?;
        Ok(!had)
    }

    /// 그룹의 지금 관리자(나가지 않은).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_admins(&self, gid: &str) -> Result<Vec<String>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let out = group_members_in(&tx, gid)?
            .into_iter()
            .filter(|(_, a)| *a)
            .map(|(m, _)| m)
            .collect();
        tx.commit()?;
        Ok(out)
    }

    /// #819: 걸린 일 중 그 사용자가 관리자인 그룹 것(관리자 기기가 접속할 때 다시 보낸다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_stuck_for_admin(&self, user: &str) -> Result<Vec<DutyStuck>, DbError> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {DUTY_STUCK_COLS} FROM mls_duty_stuck s
             WHERE EXISTS(SELECT 1 FROM group_members m WHERE m.gid = s.group_id AND m.user = ?1
                           AND m.role = 'admin' AND m.left_seq IS NULL)
             ORDER BY s.at_ms, s.group_id, s.task, s.subject"
        ))?;
        let rows = st.query_map([user], duty_stuck_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #819: 걸렸던 일이 끝났다(일 행이 지워짐) — 그 행을 지우고 (행, 그 그룹 관리자들)을 돌려준다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_stuck_take_done(&self) -> Result<Vec<(DutyStuck, Vec<String>)>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let done: Vec<DutyStuck> = {
            let mut st = tx.prepare(&format!(
                "SELECT {DUTY_STUCK_COLS} FROM mls_duty_stuck s
                 WHERE NOT EXISTS(SELECT 1 FROM mls_duties d WHERE d.group_id = s.group_id
                                  AND d.task = s.task AND d.subject = s.subject)
                 ORDER BY s.at_ms, s.group_id, s.task, s.subject"
            ))?;
            let rows = st.query_map([], duty_stuck_row)?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for s in done {
            tx.execute(
                "DELETE FROM mls_duty_stuck WHERE group_id = ?1 AND task = ?2 AND subject = ?3",
                params![s.group_id, s.task, s.subject],
            )?;
            let admins: Vec<String> = group_members_in(&tx, &s.group_id)?
                .into_iter()
                .filter(|(_, a)| *a)
                .map(|(m, _)| m)
                .collect();
            out.push((s, admins));
        }
        tx.commit()?;
        Ok(out)
    }

    /// 그 일을 받은 기기와 rank.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_ranks(
        &self,
        group_id: &str,
        task: &str,
        subject: &str,
    ) -> Result<Vec<(String, u64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT device_id, rank FROM mls_duty_ranks WHERE group_id = ?1 AND task = ?2 AND subject = ?3",
        )?;
        let rows = st.query_map(params![group_id, task, subject], |r| {
            Ok((r.get(0)?, u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0)))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 기기에 준 rank 를 적는다(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_rank_put(
        &self,
        group_id: &str,
        task: &str,
        subject: &str,
        device_id: &str,
        rank: u64,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_duty_ranks(group_id, task, subject, device_id, rank) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![group_id, task, subject, device_id, i64::try_from(rank).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- MLS KeyPackage (묶음 22 §3)

    /// 이 기기의 KeyPackage 를 더한다(보통 것) — 더한 뒤 보통 것이 `max` 를 넘으면 아무것도 저장하지 않고 `false`. 마지막 수단은
    /// 하나만(새로 주면 바꿈). 지난 것(`not_after` ≤ 지금)은 먼저 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_publish(
        &self,
        device_id: &str,
        items: &[crate::mls::CheckedKeyPackage],
        last_resort: Option<&crate::mls::CheckedKeyPackage>,
        max: usize,
        reset: bool,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let now_ms = now_wall_ms();
        if reset {
            // 데이터를 잃은 기기의 첫 올리기(g025f B) — 남은 것은 그 기기가 열 수 없다. 넣기와 한 트랜잭션이라 그 사이 claim 이
            // 옛 것을 집지 않는다.
            tx.execute(
                "DELETE FROM mls_key_packages WHERE device_id = ?1",
                [device_id],
            )?;
        }
        tx.execute(
            "DELETE FROM mls_key_packages WHERE device_id = ?1 AND not_after * 1000 <= ?2",
            params![device_id, now_ms],
        )?;
        for k in items {
            tx.execute(
                "INSERT OR IGNORE INTO mls_key_packages(device_id, kp_ref, data, last_resort, not_after, created_ms)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5)",
                params![device_id, k.kp_ref, k.data, k.not_after, now_ms],
            )?;
        }
        let n: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 0",
            [device_id],
            |r| r.get(0),
        )?;
        if usize::try_from(n).unwrap_or(usize::MAX) > max {
            return Ok(false);
        }
        if let Some(k) = last_resort {
            tx.execute(
                "DELETE FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 1",
                [device_id],
            )?;
            tx.execute(
                "INSERT INTO mls_key_packages(device_id, kp_ref, data, last_resort, not_after, created_ms)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                params![device_id, k.kp_ref, k.data, k.not_after, now_ms],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// (남은 보통 KeyPackage 수, 마지막 수단이 있나) — 접속 때 `low` 판정.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_state(&self, device_id: &str) -> Result<(u64, bool), DbError> {
        // #896: 만료된 마지막 수단은 없음으로 센다(보통 것과 같은 규칙) — 90일 넘게 안 붙은 기기가 돌아오면 '마지막 수단 없음'
        // low 를 받아 다시 올리게.
        let has_last: bool = self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 1 AND not_after * 1000 > ?2)",
            params![device_id, now_wall_ms()],
            |r| r.get(0),
        )?;
        Ok((self.kp_count(device_id)?, has_last))
    }

    /// 만료된 것까지 쳐서 마지막 수단을 올린 적이 있나(#896 — 판 16 아래 연결의 `low` 판정을 예전 그대로 두려고).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_had_last(&self, device_id: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 1)",
            [device_id],
            |r| r.get(0),
        )?)
    }

    /// 이 기기의 남은 보통 KeyPackage 수(지난 것 빼고).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_count(&self, device_id: &str) -> Result<u64, DbError> {
        let n: i64 = self.c().query_row(
            "SELECT COUNT(*) FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 0 AND not_after * 1000 > ?2",
            params![device_id, now_wall_ms()],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// [`Self::kp_claim`] 가 상한으로 거절했을 때 같은 가져가기가 다시 될 가장 이른 시각(ms) — 걸린 상한마다 넘친 만큼의
    /// 기록이 창(시간·하루)을 벗어나는 때 중 가장 늦은 것. 안 걸렸으면 `now_ms`. 읽기만 한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_claim_free_at(
        &self,
        claimer: &str,
        targets: &[(String, String)],
        now_ms: i64,
        l: &KpClaimLimits,
    ) -> Result<i64, DbError> {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        let c = self.c();
        // `sql` 의 기록(at_ms 오래된 것부터)에서 `over` 번째(0부터)가 창을 벗어나는 때.
        let nth =
            |sql: &str, p: &[&dyn rusqlite::ToSql], over: i64, win: i64| -> Result<i64, DbError> {
                if over < 0 {
                    return Ok(now_ms);
                }
                let at: Option<i64> = c
                    .query_row(
                        &format!("{sql} ORDER BY at_ms LIMIT 1 OFFSET {over}"),
                        p,
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(at.map_or(now_ms, |a| a + win + 1))
            };
        let mut free = now_ms;
        let hour: i64 = c.query_row(
            "SELECT COUNT(*) FROM mls_kp_claims WHERE claimer = ?1 AND at_ms > ?2",
            params![claimer, now_ms - HOUR],
            |r| r.get(0),
        )?;
        free = free.max(nth(
            "SELECT at_ms FROM mls_kp_claims WHERE claimer = ?1 AND at_ms > ?2",
            &[&claimer, &(now_ms - HOUR)],
            hour + targets.len() as i64 - l.per_hour - 1,
            HOUR,
        )?);
        for (device, owner) in targets {
            let mine = owner == claimer;
            let cap = if mine {
                l.owner_pair_per_day
            } else {
                l.pair_per_day
            };
            let pair: i64 = c.query_row(
                "SELECT COUNT(*) FROM mls_kp_claims WHERE claimer = ?1 AND target = ?2 AND at_ms > ?3",
                params![claimer, device, now_ms - DAY],
                |r| r.get(0),
            )?;
            free = free.max(nth(
                "SELECT at_ms FROM mls_kp_claims WHERE claimer = ?1 AND target = ?2 AND at_ms > ?3",
                &[&claimer, device, &(now_ms - DAY)],
                pair - cap,
                DAY,
            )?);
            if !mine {
                let total: i64 = c.query_row(
                    "SELECT COUNT(*) FROM mls_kp_claims WHERE target = ?1 AND owner = 0 AND at_ms > ?2",
                    params![device, now_ms - DAY],
                    |r| r.get(0),
                )?;
                free = free.max(nth(
                    "SELECT at_ms FROM mls_kp_claims WHERE target = ?1 AND owner = 0 AND at_ms > ?2",
                    &[device, &(now_ms - DAY)],
                    total - l.target_per_day,
                    DAY,
                )?);
            }
        }
        Ok(free)
    }

    /// 가져가기(§3): `targets` = (대상 기기, 그 주인) — 호출자가 같은 조직·폐기 안 됨을 이미 걸렀다. 소비 상한을 넘으면 `None`
    /// (아무것도 가져가지 않음). 기기마다 보통 것(오래된 것부터, 가져가면 지움) 또는 마지막 수단(남김). 남은 보통 것이 20 아래가
    /// 된 기기는 `low` 로.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn kp_claim(
        &self,
        claimer: &str,
        targets: &[(String, String)],
        now_ms: i64,
        l: &KpClaimLimits,
    ) -> Result<Option<KpClaimed>, DbError> {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM mls_kp_claims WHERE at_ms <= ?1",
            [now_ms - DAY],
        )?;
        let hour: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mls_kp_claims WHERE claimer = ?1 AND at_ms > ?2",
            params![claimer, now_ms - HOUR],
            |r| r.get(0),
        )?;
        if hour + targets.len() as i64 > l.per_hour {
            return Ok(None);
        }
        for (device, owner) in targets {
            let mine = owner == claimer;
            let pair: i64 = tx.query_row(
                "SELECT COUNT(*) FROM mls_kp_claims WHERE claimer = ?1 AND target = ?2 AND at_ms > ?3",
                params![claimer, device, now_ms - DAY],
                |r| r.get(0),
            )?;
            if pair
                >= if mine {
                    l.owner_pair_per_day
                } else {
                    l.pair_per_day
                }
            {
                return Ok(None);
            }
            if !mine {
                let total: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM mls_kp_claims WHERE target = ?1 AND owner = 0 AND at_ms > ?2",
                    params![device, now_ms - DAY],
                    |r| r.get(0),
                )?;
                if total >= l.target_per_day {
                    return Ok(None);
                }
            }
        }
        let mut got = KpClaimed::default();
        for (device, owner) in targets {
            let normal: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT kp_ref, data FROM mls_key_packages
                     WHERE device_id = ?1 AND last_resort = 0 AND not_after * 1000 > ?2
                     ORDER BY created_ms, kp_ref LIMIT 1",
                    params![device, now_wall_ms()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let data = match normal {
                Some((kp_ref, data)) => {
                    tx.execute(
                        "DELETE FROM mls_key_packages WHERE device_id = ?1 AND kp_ref = ?2",
                        params![device, kp_ref],
                    )?;
                    Some(data)
                }
                None => tx
                    .query_row(
                        "SELECT data FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 1 AND not_after * 1000 > ?2",
                        params![device, now_wall_ms()],
                        |r| r.get(0),
                    )
                    .optional()?,
            };
            let Some(data) = data else { continue };
            tx.execute(
                "INSERT INTO mls_kp_claims(claimer, target, owner, at_ms) VALUES (?1, ?2, ?3, ?4)",
                params![claimer, device, owner == claimer, now_ms],
            )?;
            let left: i64 = tx.query_row(
                "SELECT COUNT(*) FROM mls_key_packages WHERE device_id = ?1 AND last_resort = 0",
                [device],
                |r| r.get(0),
            )?;
            if left < crate::mls::KP_LOW as i64 {
                got.low.push((
                    device.clone(),
                    owner.clone(),
                    u64::try_from(left).unwrap_or(0),
                ));
            }
            got.items.push((device.clone(), data));
        }
        tx.commit()?;
        Ok(Some(got))
    }

    /// 사용자당 기기 상한을 정한다(relay 설정, 묶음 16 §3a).
    pub fn set_max_devices(&self, n: usize) {
        self.max_devices
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// 그 사용자에게 기기를 하나 더 붙일 수 있는가 — 폐기 안 된 기기만 센다. 이미 넘은 계정은 그대로 두고 새 등록만 막는다.
    fn check_device_room(&self, tx: &rusqlite::Transaction<'_>, user: &str) -> Result<(), DbError> {
        let n: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE user = ?1 AND revoked_ms IS NULL",
            [user],
            |r| r.get(0),
        )?;
        let max = self.max_devices.load(std::sync::atomic::Ordering::Relaxed);
        if usize::try_from(n).unwrap_or(usize::MAX) >= max {
            return Err(DbError::TooManyDevices);
        }
        Ok(())
    }

    /// 폐기되지 않은 기기의 (사용자, Ed25519 공개키 b64). 폐기된 기기는 `None` — 인증·서명 검사에서 모르는 기기와 같다(#325).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device(&self, device_id: &str) -> Result<Option<(String, String)>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT user, ed25519 FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// 폐기된 기기의 (사용자, Ed25519 공개키 b64). 폐기 안 됐거나 없으면 `None`. 핸드셰이크가 서명이 맞을 때만 "폐기됨" 을
    /// 알리는 데 쓴다(#339 — 비밀키를 가진 쪽만 알 수 있다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revoked_device(&self, device_id: &str) -> Result<Option<(String, String)>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT user, ed25519 FROM devices WHERE device_id = ?1 AND revoked_ms IS NOT NULL",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// 폐기된 기기를 누가(묶음 5, `devices.revoked_by` — 묶음 5 전에 폐기된 행은 `None`) 언제(#577, `revoked_ms`) 끊었나.
    /// 폐기 안 된 기기는 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revoked_by(&self, device_id: &str) -> Result<Option<(Option<RevokedBy>, i64)>, DbError> {
        let row: Option<(Option<String>, i64)> = self
            .c()
            .query_row(
                "SELECT revoked_by, revoked_ms FROM devices WHERE device_id = ?1 AND revoked_ms IS NOT NULL",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(by, ms)| (by.as_deref().and_then(RevokedBy::parse), ms)))
    }

    /// 기기 폐기(`device.revoke`, #325). 사용자 행은 남긴다(아이디는 그 사람의 것 — #67). 그 사용자에게 남은 기기가 없으면
    /// 전달을 기다리던 본문도 지운다(받을 기기가 없다 — 헤더는 `expires_at` 까지 남아 발신자에게 만료로 끝난다).
    /// 조직의 유일한 관리자의 마지막 기기면 [`SelfRevoke::LastAdmin`](묶음 5 — 조직에 다른 사람이 없으면 검사 안 함).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revoke_device(
        &self,
        device_id: &str,
        now_ms: i64,
        proof: Option<&RevokeProof>,
    ) -> Result<SelfRevoke, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let user: Option<String> = tx
            .query_row(
                "SELECT user FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                [device_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(user) = user else {
            return Ok(SelfRevoke::Gone);
        };
        let live: i64 = tx.query_row(
            "SELECT COUNT(*) FROM devices WHERE user = ?1 AND revoked_ms IS NULL",
            [&user],
            |r| r.get(0),
        )?;
        if live == 1 && last_admin_with_others(&tx, &user)? {
            return Ok(SelfRevoke::LastAdmin);
        }
        revoke_in(&tx, device_id, now_ms, RevokedBy::Device, proof)?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(SelfRevoke::Revoked)
    }

    /// 같은 사용자의 다른 기기 폐기(`device.revoke {device_id}`, #339). 판정과 폐기를 한 트랜잭션에서 한다.
    /// 먼저 등록된 기기(`created_ms` — 문서의 `added_ms`, 같으면 행 순서)는 나중 기기를 언제든, 나중 기기는 먼저 기기를
    /// 자기 등록 뒤 `wait_ms` 가 지나야 폐기한다 — 이메일을 뺏은 새 기기가 진짜 기기를 먼저 지워 알림을 없애지 못하게.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revoke_other(
        &self,
        requester: &str,
        target: &str,
        now_ms: i64,
        wait_ms: i64,
        proof: Option<&RevokeProof>,
        requester_trusted: bool,
    ) -> Result<RevokeOutcome, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row = |id: &str| -> Result<Option<(String, i64, i64, bool)>, DbError> {
            Ok(tx
                .query_row(
                    "SELECT user, created_ms, rowid, revoked_ms IS NOT NULL FROM devices WHERE device_id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?)
        };
        let Some((req_user, req_at, req_row, req_revoked)) = row(requester)? else {
            return Ok(RevokeOutcome::Unknown);
        };
        let Some((t_user, t_at, t_row, t_revoked)) = row(target)? else {
            return Ok(RevokeOutcome::Unknown);
        };
        if req_revoked {
            return Ok(RevokeOutcome::Unknown);
        }
        if t_user != req_user {
            // 조직 관리자는 같은 조직 사람의 기기를 시간 제한 없이 끊는다(#355 — REST DELETE /v1/devices 대신).
            let admin_of_same_org: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM orgs o JOIN users a ON a.org = o.org_id JOIN users t ON t.org = o.org_id
                 JOIN org_admins x ON x.org_id = o.org_id AND x.user = a.user
                 WHERE a.user = ?1 AND t.user = ?2)",
                params![req_user, t_user],
                |r| r.get(0),
            )?;
            // 다른 관리자의 기기는 끊지 않는다(묶음 5 — 먼저 `org.admin {admin:false}`).
            if !admin_of_same_org || Self::admin_org(&tx, &t_user)?.is_some() {
                return Ok(RevokeOutcome::Unknown);
            }
            if t_revoked {
                return Ok(RevokeOutcome::AlreadyRevoked);
            }
        } else {
            if t_revoked {
                return Ok(RevokeOutcome::AlreadyRevoked);
            }
            let target_is_older = (t_at, t_row) < (req_at, req_row);
            // #577: 잎 자격 없는(pending) 나중 기기는 먼저 기기를 끊지 못한다 — 메일 확인 끊기(막기를 거침)로만.
            if target_is_older && !requester_trusted {
                return Ok(RevokeOutcome::Unknown);
            }
            if target_is_older && now_ms.saturating_sub(req_at) < wait_ms {
                return Ok(RevokeOutcome::TooEarly);
            }
        }
        let by = if t_user == req_user {
            RevokedBy::Device
        } else {
            RevokedBy::Admin
        };
        let Some(user) = revoke_in(&tx, target, now_ms, by, proof)? else {
            return Ok(RevokeOutcome::Unknown);
        };
        tx.commit()?;
        truncate_wal(&c);
        Ok(RevokeOutcome::Revoked { user })
    }

    // ---------------------------------------------------------------- hosted 가입(#339)

    /// 가입 코드 발급 기록(#339·묶음 5). 상한(모두 같은 `Limited` — 계정 여부는 드러나지 않는다)을 넘으면 코드를 바꾸지
    /// 않는다: 이메일당 [`SignupLimits::per_email_hour`]·[`SignupLimits::per_email_day`], relay 전체 UTC 하루
    /// [`SignupLimits::global_day`]. 아니면 그 이메일의 이전 코드를 이 코드로 바꾸고(이전 코드 무효) 동의한 처리방침 판을 붙인다.
    /// 기록은 24시간 남는다(전역 하루 수·`server.status.mail.sent_today` 가 재시작에도 맞게).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn signup_request(
        &self,
        email: &str,
        code_hash: &[u8],
        now_ms: i64,
        expires_ms: i64,
        privacy_version: &str,
        limits: &SignupLimits,
    ) -> Result<SignupOutcome, DbError> {
        const HOUR: i64 = 60 * 60 * 1000;
        const DAY: i64 = 24 * HOUR;
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM signup_requests WHERE at_ms <= ?1",
            [now_ms.saturating_sub(DAY)],
        )?;
        let count = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Result<i64, DbError> {
            Ok(tx.query_row(sql, p, |r| r.get(0))?)
        };
        let hour = count(
            "SELECT COUNT(*) FROM signup_requests WHERE email = ?1 AND at_ms > ?2",
            &[&email, &(now_ms - HOUR)],
        )?;
        let day = count(
            "SELECT COUNT(*) FROM signup_requests WHERE email = ?1",
            &[&email],
        )?;
        let global = count(
            "SELECT COUNT(*) FROM signup_requests WHERE at_ms >= ?1",
            &[&utc_day_start(now_ms)],
        )?;
        if hour >= limits.per_email_hour
            || day >= limits.per_email_day
            || global >= limits.global_day
        {
            return Ok(SignupOutcome::Limited);
        }
        tx.execute(
            "INSERT INTO signup_requests(email, at_ms) VALUES (?1, ?2)",
            params![email, now_ms],
        )?;
        tx.execute(
            "INSERT INTO signup_codes(email, code_hash, expires_ms, failures, privacy_version, privacy_ms)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)
             ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash, expires_ms = excluded.expires_ms,
               failures = 0, privacy_version = excluded.privacy_version, privacy_ms = excluded.privacy_ms",
            params![email, code_hash, expires_ms, privacy_version, now_ms],
        )?;
        tx.commit()?;
        Ok(SignupOutcome::Sent)
    }

    /// 메일 서비스 실패 시각(`server.status.mail.last_failed_ms`, 묶음 5).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mail_failed(&self, now_ms: i64) -> Result<(), DbError> {
        self.set_meta(&[("mail_last_failed_ms", &now_ms.to_string())])
    }

    /// 마지막 메일 서비스 실패 시각.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mail_last_failed(&self) -> Result<Option<i64>, DbError> {
        Ok(self
            .meta("mail_last_failed_ms")?
            .and_then(|v| v.parse().ok()))
    }

    /// 오늘(UTC) 보낸 가입 메일 수(`server.status.mail.sent_today`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn signup_sent_today(&self, now_ms: i64) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM signup_requests WHERE at_ms >= ?1",
            [utc_day_start(now_ms)],
            |r| r.get(0),
        )?)
    }

    /// 가입 코드 확인. 맞으면 코드를 지우고 가입 토큰(해시, 동의 판을 이어받음)을 남겨 `Some`. 그 이메일에 내보내지 않은 계정이
    /// 있으면 `Some(Some((user, 표시 이름)))`(묶음 5 `kind: existing` — 이메일 주인 확인 뒤라 열거가 아니다), 없거나 내보낸
    /// 사람이면 `Some(None)`(`new`). 없음·만료·틀림은 모두 `None` — 틀리면 실패 수를 올리고
    /// [`SIGNUP_CODE_MAX_FAILURES`] 에 다다르면 코드를 지운다. 호출자는 실패를 모두 같은 응답으로 준다.
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::type_complexity)]
    pub fn signup_verify(
        &self,
        email: &str,
        code_hash: &[u8],
        now_ms: i64,
        token_hash: &[u8],
        token_expires_ms: i64,
    ) -> Result<Option<Option<ExistingAccount>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(Vec<u8>, i64, i64, Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT code_hash, expires_ms, failures, privacy_version, privacy_ms FROM signup_codes WHERE email = ?1",
                [email],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let out = match row {
            None => None,
            Some((_, exp, ..)) if exp <= now_ms => {
                tx.execute("DELETE FROM signup_codes WHERE email = ?1", [email])?;
                None
            }
            Some((stored, _, failures, pv, pms)) => {
                if ct_eq(&stored, code_hash) {
                    tx.execute("DELETE FROM signup_codes WHERE email = ?1", [email])?;
                    tx.execute("DELETE FROM signup_tokens WHERE expires_ms <= ?1", [now_ms])?;
                    tx.execute(
                        "INSERT INTO signup_tokens(token_hash, email, expires_ms, privacy_version, privacy_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![token_hash, email, token_expires_ms, pv, pms],
                    )?;
                    let existing: Option<(String, Option<String>, Option<String>)> = tx
                        .query_row(
                            "SELECT u.user, u.display, o.name FROM users u LEFT JOIN orgs o ON o.org_id = u.org
                             WHERE u.email = ?1 AND u.removed_ms IS NULL",
                            [email],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .optional()?;
                    Some(existing.map(|(user, d, org_name)| ExistingAccount {
                        display: d.unwrap_or_else(|| user.clone()),
                        user,
                        org_name,
                    }))
                } else {
                    if failures + 1 >= SIGNUP_CODE_MAX_FAILURES {
                        tx.execute("DELETE FROM signup_codes WHERE email = ?1", [email])?;
                    } else {
                        tx.execute(
                            "UPDATE signup_codes SET failures = failures + 1 WHERE email = ?1",
                            [email],
                        )?;
                    }
                    None
                }
            }
        };
        tx.commit()?;
        Ok(out)
    }

    /// 그 사람이 동의한 처리방침 (판, 시각)(묶음 5). 없으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn privacy_of(&self, user: &str) -> Result<Option<(String, i64)>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT privacy_version, privacy_ms FROM users WHERE user = ?1",
                [user],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<i64>>(1)?)),
            )
            .optional()?
            .and_then(|(v, at)| Some((v?, at?))))
    }

    /// 그 가입 토큰의 초대 확인 실패 수(시험·진단).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_check_failures(&self, token_hash: &[u8]) -> Result<i64, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT check_failures FROM signup_tokens WHERE token_hash = ?1",
                [token_hash],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// 조직 만들기 코드 확인(묶음 5·relay 0.1.2 — `lodelai-relay bootstrap` 의 코드, 코드마다 한 행). 읽기만 한다 — 소비는 등록
    /// 트랜잭션 [`OrgChoice::Create`] 의 `setup_code_hash`, 틀린 시도는 지우지 않고 http 가 늦춘다(5번에 다 지우면 남의 초대까지
    /// 날린다). `email` 은 가입 토큰의 정규화한 이메일 — 행의 꼴(`email_keyed`)에 맞춰 SHA 나 키 묶은 꼴과 맞춘다(#738).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn check_setup_code(
        &self,
        code_hash: &[u8],
        email: Option<&str>,
        now_ms: i64,
    ) -> Result<SetupCheck, DbError> {
        // (이메일 값, 키 묶은 꼴인가, 가린 이메일, 기한)
        type Row = (Option<Vec<u8>>, bool, Option<String>, i64);
        let row: Option<Row> = self
            .c()
            .query_row(
                "SELECT email_hash, email_keyed, email_mask, expires_ms FROM setup_codes WHERE code_hash = ?1",
                [code_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        // #738: 행의 꼴(email_keyed)에 맞는 값 하나와만 맞춘다.
        let forms = email.map(|e| self.setup_email_forms(e));
        let matches = |bound: &[u8], keyed: bool| {
            forms.as_ref().is_some_and(|(sha, mac)| {
                if keyed {
                    mac.as_deref().is_some_and(|m| ct_eq(bound, m))
                } else {
                    ct_eq(bound, sha)
                }
            })
        };
        Ok(match row {
            None => SetupCheck::Wrong,
            Some((_, _, _, exp)) if exp <= now_ms => SetupCheck::Expired,
            Some((Some(bound), keyed, mask, _)) if !matches(&bound, keyed) => {
                SetupCheck::OtherEmail(mask.unwrap_or_default())
            }
            Some(_) => SetupCheck::Ok,
        })
    }

    /// 초대 코드 확인(`POST /v1/invites/check`, 묶음 5). 가입 토큰은 **소비하지 않는다**. 토큰이 없거나 끝났거나 확인 실패가
    /// [`INVITE_CHECK_MAX_FAILURES`] 에 다다랐으면, 또는 초대가 없거나 끝났으면 `None`(모두 같은 응답) — 초대가 틀리면 그
    /// 토큰의 실패 수를 올린다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_check(
        &self,
        token_hash: &[u8],
        invite_hash: &[u8],
        now_ms: i64,
    ) -> Result<InviteCheckOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let token_email: Option<String> = tx
            .query_row(
                "SELECT email FROM signup_tokens WHERE token_hash = ?1 AND expires_ms > ?2 AND check_failures < ?3",
                params![token_hash, now_ms, INVITE_CHECK_MAX_FAILURES],
                |r| r.get(0),
            )
            .optional()?;
        let Some(token_email) = token_email else {
            return Ok(InviteCheckOut::NotFound);
        };
        let inv: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT org_id, created_by, email FROM invites WHERE token_hash = ?1 AND expires_ms > ?2",
                params![invite_hash, now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((org, by, bound)) = inv else {
            tx.execute(
                "UPDATE signup_tokens SET check_failures = check_failures + 1 WHERE token_hash = ?1",
                [token_hash],
            )?;
            tx.commit()?;
            return Ok(InviteCheckOut::NotFound);
        };
        // §7-42: 맞는 토큰 둘이라 추측이 아니다 — 실패로 세지 않는다. 조직 카드는 맞는 이메일만 본다.
        if !invite_email_ok(bound.as_deref(), &token_email) {
            return Ok(InviteCheckOut::OtherEmail(bound.unwrap_or_default()));
        }
        let info = invite_info_in(&tx, org, by)?;
        tx.commit()?;
        Ok(InviteCheckOut::Ok(info))
    }

    /// hosted 기기 등록(`POST /v1/devices {signup_token}`, #339 결정 D·묶음 5). 토큰 소모와 기기 추가가 한 트랜잭션이다
    /// (실패하면 토큰도 그대로). 그 이메일에 내보내지 않은 계정이 있으면 **그 계정에 기기를 더한다**(`user` 가 있는데 다르면
    /// [`DbError::UserMismatch`], 표시 이름·조직은 무시). 내보낸 사람(`removed_ms`)이면 새 조직 선택(초대 등)으로 **같은
    /// 아이디가 되살아난다**(요청의 `user` 는 무시하되 다르면 409). 없으면 `user` 로 새 계정을 만든다(남이 쓰는 아이디면
    /// [`DbError::UserExists`]). 토큰의 처리방침 판·동의 시각을 그 사람 행에 남긴다(있던 사람은 갱신).
    ///
    /// # Errors
    /// sqlite 오류, [`DbError`] 의 판정들.
    pub fn register_hosted(&self, d: &HostedDevice<'_>) -> Result<HostedRegistered, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let token: Option<(String, Option<String>, Option<i64>)> = tx
            .query_row(
                "DELETE FROM signup_tokens WHERE token_hash = ?1 AND expires_ms > ?2
                 RETURNING email, privacy_version, privacy_ms",
                params![d.token_hash, d.now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((email, privacy_version, privacy_ms)) = token else {
            return Err(DbError::BadToken);
        };
        // #845 ⑤ 멈춘 계정은 코드 확인 뒤 가른다(정책 §2 — 코드 전엔 가르지 않음). 커밋하지 않으니 토큰은 남는다.
        let suspended: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1 AND removed_ms IS NULL AND suspended_ms IS NOT NULL
                             AND (suspended_until IS NULL OR suspended_until > ?2))",
            params![email, d.now_ms],
            |r| r.get(0),
        )?;
        if suspended {
            return Err(DbError::Suspended);
        }
        // 같은 기기로 다시 가입(protocol §7.1, #389): 이 이메일 계정의 폐기 안 된 기기면 토큰만 쓰고 그대로 돌려준다.
        // 그 밖(남의 기기·폐기된 기기·계정 없음)은 device_taken — 커밋하지 않으니 토큰은 남는다.
        let existing: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT user, revoked_ms FROM devices WHERE device_id = ?1",
                [d.device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((owner, revoked)) = existing {
            let mine = revoked.is_none()
                && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1 AND email = ?2 AND removed_ms IS NULL)",
                    params![owner, email],
                    |r| r.get::<_, bool>(0),
                )?;
            if !mine {
                return Err(DbError::DeviceTaken);
            }
            // 기존 계정이다 — 조직을 실었으면 다시 가입이어도 거절(ADR 0011, 토큰 남음).
            if d.org.is_some() {
                return Err(DbError::AccountExists(Box::new(account_of(&tx, &owner)?)));
            }
            if d.user.is_some_and(|req| req != owner) {
                return Err(DbError::UserMismatch);
            }
            tx.commit()?;
            return Ok(HostedRegistered {
                user: owner,
                added: false,
                rejoined: true,
                notify: Vec::new(),
                joining_groups: Vec::new(),
            });
        }
        let mut account: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT user, removed_ms FROM users WHERE email = ?1",
                [&email],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        // 내보내거나 나간 사람은 평문 이메일이 없다 — email_mac 으로 찾는다(묶음 5 정보 파기 A).
        if account.is_none() {
            if let Some(key) = self.email_key.get() {
                account = tx
                    .query_row(
                        "SELECT user, removed_ms FROM users WHERE email_mac = ?1 AND removed_ms IS NOT NULL",
                        [email_mac(key, &email)],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
            }
        }
        let mut adopted: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        let (user, added) = match account {
            Some((u, None)) => {
                // 이메일 하나 = 조직 하나(ADR 0011): 기존 계정은 조직을 만들거나 다른 초대로 들어올 수 없다. 커밋하지 않으니
                // 토큰은 남는다 — 같은 토큰으로 기기 추가를 바로 이어 한다.
                if d.org.is_some() {
                    return Err(DbError::AccountExists(Box::new(account_of(&tx, &u)?)));
                }
                if d.user.is_some_and(|req| req != u) {
                    return Err(DbError::UserMismatch);
                }
                let recent: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM devices WHERE user = ?1 AND created_ms > ?2",
                    params![u, d.now_ms.saturating_sub(d.window_ms)],
                    |r| r.get(0),
                )?;
                if recent >= d.max_devices {
                    return Err(DbError::RateLimited);
                }
                (u, true)
            }
            revived => {
                // 새 사람, 또는 내보낸 사람이 새 초대로 돌아옴(같은 아이디, 기기는 새로).
                let u = match &revived {
                    Some((old, Some(_))) => {
                        if d.user.is_some_and(|req| req != old) {
                            return Err(DbError::UserMismatch);
                        }
                        old.clone()
                    }
                    _ => {
                        let Some(u) = d.user else {
                            return Err(DbError::MissingUser);
                        };
                        let taken: bool = tx.query_row(
                            "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1)",
                            [u],
                            |r| r.get(0),
                        )?;
                        if taken {
                            return Err(DbError::UserExists);
                        }
                        u.to_owned()
                    }
                };
                // 초대 가입이면 그 초대를 만든 관리자(M1 결함 ① — 디렉터리의 `invited_by_me`).
                let mut inviter: Option<String> = None;
                // #845 ⑤ 같이 받은 연락 요청(link_invites id)·그룹 초대(group_invites id).
                let (mut picked_contacts, mut picked_groups): (Vec<String>, Vec<String>) =
                    (Vec::new(), Vec::new());
                let org = match &d.org {
                    None => return Err(DbError::BadOrg),
                    Some(OrgChoice::Create {
                        id,
                        name,
                        setup_code_hash,
                        quota,
                        allowed_email,
                    }) => {
                        if !d.teams.is_empty() {
                            return Err(DbError::BadOrg);
                        }
                        if let Some(q) = quota {
                            self.take_org_quota(&tx, q, &email, d.now_ms)?;
                        }
                        if !self.use_setup_code_in(
                            &tx,
                            *setup_code_hash,
                            *allowed_email,
                            Some(&email),
                            d.now_ms,
                        )? {
                            return Err(DbError::BadInvite);
                        }
                        tx.execute(
                            "INSERT INTO orgs(org_id, name, admin, created_ms) VALUES (?1, ?2, ?3, ?4)",
                            params![id, name, u, d.now_ms],
                        )?;
                        tx.execute(
                            "INSERT INTO org_admins(org_id, user) VALUES (?1, ?2)",
                            params![id, u],
                        )?;
                        (*id).to_owned()
                    }
                    Some(OrgChoice::Personal { id }) => {
                        if !d.teams.is_empty() {
                            return Err(DbError::BadOrg);
                        }
                        // 이름은 표시 이름(없으면 아이디) — 화면은 개인 공간 이름을 쓰지 않는다. admin 은 NOT NULL 이라 나.
                        tx.execute(
                            "INSERT INTO orgs(org_id, name, admin, created_ms, kind) VALUES (?1, ?2, ?3, ?4, 'personal')",
                            params![id, d.display.unwrap_or(&u), u, d.now_ms],
                        )?;
                        (*id).to_owned()
                    }
                    Some(OrgChoice::Join { personal_id, ids }) => {
                        let mut org_pick: Option<Vec<u8>> = None;
                        for id in *ids {
                            let row: Option<(String, String)> = tx
                                .query_row(
                                    "SELECT kind, ref FROM signup_pending WHERE token_hash = ?1 AND id = ?2",
                                    params![d.token_hash, id],
                                    |r| Ok((r.get(0)?, r.get(1)?)),
                                )
                                .optional()?;
                            match row {
                                None => return Err(DbError::BadInvite),
                                Some((k, r)) if k == "org" => {
                                    if org_pick.is_some() {
                                        return Err(DbError::BadOrg);
                                    }
                                    org_pick = Some(
                                        lodelai_crypto::encoding::decode(&r, "invite")
                                            .map_err(|_| DbError::BadInvite)?,
                                    );
                                }
                                Some((k, r)) if k == "group" => picked_groups.push(r),
                                Some((_, r)) => picked_contacts.push(r),
                            }
                        }
                        match org_pick {
                            Some(h) => {
                                let inv: Option<(String, String)> = tx
                                    .query_row(
                                        "DELETE FROM invites WHERE token_hash = ?1 AND expires_ms > ?2 AND email = ?3
                                         RETURNING org_id, created_by",
                                        params![h, d.now_ms, email],
                                        |r| Ok((r.get(0)?, r.get(1)?)),
                                    )
                                    .optional()?;
                                let Some((org, by)) = inv else {
                                    return Err(DbError::BadInvite);
                                };
                                tx.execute(
                                    "UPDATE invites_sent SET joined_ms = ?2, target_user = ?3 WHERE recv_ref = ?1",
                                    params![lodelai_crypto::encoding::encode(&h), d.now_ms, u],
                                )?;
                                inviter = Some(by);
                                org
                            }
                            None => {
                                if !d.teams.is_empty() {
                                    return Err(DbError::BadOrg);
                                }
                                tx.execute(
                                    "INSERT INTO orgs(org_id, name, admin, created_ms, kind) VALUES (?1, ?2, ?3, ?4, 'personal')",
                                    params![personal_id, d.display.unwrap_or(&u), u, d.now_ms],
                                )?;
                                (*personal_id).to_owned()
                            }
                        }
                    }
                    Some(OrgChoice::Invite { token_hash }) => {
                        let inv: Option<(String, Option<String>, String)> = tx
                            .query_row(
                                "DELETE FROM invites WHERE token_hash = ?1 AND expires_ms > ?2 RETURNING org_id, email, created_by",
                                params![token_hash, d.now_ms],
                                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                            )
                            .optional()?;
                        match inv {
                            Some((org, bound, by)) if invite_email_ok(bound.as_deref(), &email) => {
                                inviter = Some(by);
                                org
                            }
                            _ => return Err(DbError::BadInvite),
                        }
                    }
                };
                for team in d.teams {
                    let ok: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM teams WHERE team_id = ?1 AND org_id = ?2)",
                        params![team, org],
                        |r| r.get(0),
                    )?;
                    if !ok {
                        return Err(DbError::BadOrg);
                    }
                }
                if revived.is_some() {
                    tx.execute("DELETE FROM user_teams WHERE user = ?1", [&u])?;
                    tx.execute(
                        "UPDATE users SET org = ?2, display = ?3, removed_ms = NULL, email = ?4, email_mac = NULL, invited_by = ?5 WHERE user = ?1",
                        params![u, org, d.display, email, inviter],
                    )?;
                } else {
                    tx.execute(
                        "INSERT INTO users(user, org, display, email, invited_by) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![u, org, d.display, email, inviter],
                    )?;
                }
                for team in d.teams {
                    tx.execute(
                        "INSERT OR IGNORE INTO user_teams(user, team_id) VALUES (?1, ?2)",
                        params![u, team],
                    )?;
                }
                adopted = self.adopt_email_invites(
                    &tx,
                    &u,
                    &email,
                    &picked_contacts,
                    &picked_groups,
                    d.card_ids,
                    d.now_ms,
                )?;
                (u, false)
            }
        };
        tx.execute(
            "UPDATE users SET privacy_version = ?2, privacy_ms = ?3 WHERE user = ?1",
            params![user, privacy_version, privacy_ms],
        )?;
        self.check_device_room(&tx, &user)?;
        // #888: 등록 시각은 그 사용자의 어느 기기(폐기 포함)보다도 늦게 — 같은 ms·relay 시계가 뒤로 가도 새 기기가 잎 자격 뿌리
        // (가장 이른 기기)를 가로채 옛 기기를 '확인 전'으로 만들지 않게. 뿌리 규칙(created_ms·device_id)은 코어와 같이 그대로.
        tx.execute(
            "INSERT INTO devices(device_id, user, ed25519, x25519, created_ms, x25519_sig) VALUES (?1, ?2, ?3, ?4,
               MAX(?5, COALESCE((SELECT MAX(created_ms) + 1 FROM devices WHERE user = ?2), ?5)), ?6)",
            params![d.device_id, user, d.ed25519, d.x25519, d.now_ms, d.x25519_sig],
        )?;
        tx.execute(
            "DELETE FROM signup_pending WHERE token_hash = ?1",
            [d.token_hash],
        )?;
        tx.commit()?;
        Ok(HostedRegistered {
            user,
            added,
            rejoined: false,
            notify: adopted.0,
            joining_groups: adopted.1,
        })
    }

    /// 코드 없는 조직 만들기 상한을 보고 이번 만들기를 센다(묶음 18 §3, 등록 트랜잭션 안 — 동시 요청이 상한을 넘지 않게).
    /// 실패하면 호출자가 커밋하지 않으니 기록도 남지 않는다.
    fn take_org_quota(
        &self,
        tx: &rusqlite::Transaction<'_>,
        q: &OrgQuota,
        email: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        // 빈 조직(멤버가 모두 빠짐)은 세지 않는다 — 정리 전까지 쌓여 영영 닫히지 않게(911544fe).
        let live: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT u.org) FROM users u JOIN orgs o ON o.org_id = u.org WHERE u.removed_ms IS NULL AND o.kind = 'org'",
            [],
            |r| r.get(0),
        )?;
        if live >= q.max_orgs {
            return Err(DbError::OrgClosed);
        }
        if q.ip_over {
            return Err(DbError::OrgRateLimited);
        }
        let mac = self.mac_of(email)?;
        tx.execute(
            "DELETE FROM org_creates WHERE at_ms <= ?1",
            [now_ms - ORG_CREATE_EMAIL_WINDOW_MS],
        )?;
        let mine: i64 = tx.query_row(
            "SELECT COUNT(*) FROM org_creates WHERE email_mac = ?1",
            [&mac],
            |r| r.get(0),
        )?;
        let today: i64 = tx.query_row(
            "SELECT COUNT(*) FROM org_creates WHERE at_ms >= ?1",
            [utc_day_start(now_ms)],
            |r| r.get(0),
        )?;
        if mine >= q.per_email_30d || today >= q.per_day {
            return Err(DbError::OrgRateLimited);
        }
        tx.execute(
            "INSERT INTO org_creates(email_mac, at_ms) VALUES (?1, ?2)",
            params![mac, now_ms],
        )?;
        Ok(())
    }

    /// 30일 지난 조직 만들기 기록을 지운다(묶음 18 §3 — 청소 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_creates_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM org_creates WHERE at_ms <= ?1",
            [now_ms - ORG_CREATE_EMAIL_WINDOW_MS],
        )?)
    }

    /// 기한이 지나고 [`SETUP_CODE_KEEP_EXPIRED_MS`](30일)가 지난 조직 만들기 코드·승인을 지운다(처리방침 0.2.0 3항 — 청소 때).
    /// 30일 동안은 남겨 '기한 지남' 안내에 쓴다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn setup_codes_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM setup_codes WHERE expires_ms <= ?1",
            [now_ms - SETUP_CODE_KEEP_EXPIRED_MS],
        )?)
    }

    /// 가입 토큰이 아직 쓸 수 있으면 `Some((그 이메일, 그 이메일에 내보내지 않은 계정이 있나))`, 아니면 `None`(묶음 18 거절
    /// 순서 — 조직 만들기 코드 검사보다 토큰·기존 계정을 먼저 본다, relay 0.1.2 — 이메일은 코드 묶음·늦춤에). 읽기만 한다 —
    /// 판정은 등록 트랜잭션이 다시 한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn signup_token_account(
        &self,
        token_hash: &[u8],
        now_ms: i64,
    ) -> Result<Option<(String, Option<ExistingAccount>)>, DbError> {
        let c = self.c();
        let row: Option<(String, Option<String>)> = c
            .query_row(
                "SELECT t.email, (SELECT u.user FROM users u WHERE u.email = t.email AND u.removed_ms IS NULL)
                 FROM signup_tokens t WHERE t.token_hash = ?1 AND t.expires_ms > ?2",
                params![token_hash, now_ms],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((email, None)) => Ok(Some((email, None))),
            Some((email, Some(u))) => Ok(Some((email, Some(account_of(&c, &u)?)))),
        }
    }

    /// relay 정리(#328 주인 혼자 로그아웃): 모든 표의 행을 지우고(`secure_delete` 로 0 덮음) WAL 을 잘라낸다. 파일 삭제는 앱이
    /// 프로세스가 끝난 뒤 한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn wipe(&self) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute_batch(
            "DELETE FROM envelope_devices; DELETE FROM device_certs; DELETE FROM blob_fetch; DELETE FROM blob_tickets; DELETE FROM blobs; DELETE FROM group_log; DELETE FROM group_members; DELETE FROM groups; DELETE FROM envelopes; DELETE FROM sessions_public; DELETE FROM blocks; DELETE FROM links; DELETE FROM link_invites; DELETE FROM link_counts; DELETE FROM blob_daily; DELETE FROM blob_history_daily; DELETE FROM contact_links; DELETE FROM org_invites; DELETE FROM group_invites; DELETE FROM signup_pending; DELETE FROM mail_jobs; DELETE FROM invites_sent;
             DELETE FROM devices; DELETE FROM users; DELETE FROM meta; DELETE FROM setup_codes;
             DELETE FROM signup_codes; DELETE FROM signup_tokens; DELETE FROM signup_requests; DELETE FROM org_creates;
             DELETE FROM orgs; DELETE FROM org_admins; DELETE FROM teams; DELETE FROM user_teams; DELETE FROM invites;
             DELETE FROM mls_key_packages; DELETE FROM mls_kp_claims; DELETE FROM mls_groups; DELETE FROM mls_commits;
             DELETE FROM mls_rejoin; DELETE FROM mls_leaves; DELETE FROM mls_duties; DELETE FROM mls_duty_ranks;
             DELETE FROM mls_gi_blobs; DELETE FROM mls_duty_stuck; DELETE FROM push_tokens; DELETE FROM mls_duty_sent; DELETE FROM mutes; DELETE FROM pins;",
        )?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(())
    }

    // ---------------------------------------------------------------- 조직·팀(#355)

    /// 그 조직의 (이름, 관리자들 — 이름순). M1 `local` 은 행이 없어 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_info(&self, org: &str) -> Result<Option<(String, Vec<String>)>, DbError> {
        let c = self.c();
        let Some(name) = c
            .query_row("SELECT name FROM orgs WHERE org_id = ?1", [org], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
        else {
            return Ok(None);
        };
        let mut st = c.prepare("SELECT user FROM org_admins WHERE org_id = ?1 ORDER BY user")?;
        let admins = st
            .query_map([org], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(Some((name, admins)))
    }

    /// #845 둘째 ② 그 조직이 밖 연락을 막았나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_external_closed(&self, org: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM orgs WHERE org_id = ?1 AND external = 'closed')",
            [org],
            |r| r.get(0),
        )?)
    }

    /// 조직 고유색(org.update.color). 없거나 지웠으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_color(&self, org: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row("SELECT color FROM orgs WHERE org_id = ?1", [org], |r| {
                r.get(0)
            })
            .optional()?
            .flatten())
    }

    /// 관리자가 조직 고유색을 정하거나(`Some`) 지운다(`None`) — 꼴은 호출자(생성 타입)가 봤다. 관리자 아님·개인 공간이면
    /// `Refused`, 같은 값이면 `Same`(방송 안 함).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_org_color(&self, admin: &str, color: Option<&str>) -> Result<OrgColorOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(OrgColorOut::Refused);
        };
        let kind: String = tx.query_row(
            "SELECT COALESCE(kind, 'org') FROM orgs WHERE org_id = ?1",
            [&org],
            |r| r.get(0),
        )?;
        if kind == "personal" {
            return Ok(OrgColorOut::Refused);
        }
        let n = tx.execute(
            "UPDATE orgs SET color = ?2 WHERE org_id = ?1 AND color IS NOT ?2",
            params![org, color],
        )?;
        tx.commit()?;
        Ok(if n == 0 {
            OrgColorOut::Same
        } else {
            OrgColorOut::Changed { org }
        })
    }

    /// #845 둘째 ② 조직 밖 연락 막기(`closed`)·풀기(`false`). 관리자·조직(개인 공간 아님)만. 막을 때는 멤버와 조직 밖 사람
    /// 사이의 걸린 요청·멤버가 보낸 미가입 초대를 지운다(연락처 행은 얼림 — 그대로). 바뀌면 조직 밖에서 영향받는 사람
    /// (그 멤버들의 연락처·걸렸던 요청 상대)을 돌려준다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_org_external(&self, admin: &str, closed: bool) -> Result<OrgExternalOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(OrgExternalOut::Refused);
        };
        let kind: String = tx.query_row(
            "SELECT COALESCE(kind, 'org') FROM orgs WHERE org_id = ?1",
            [&org],
            |r| r.get(0),
        )?;
        if kind == "personal" {
            return Ok(OrgExternalOut::Refused);
        }
        let val = closed.then_some("closed");
        let n = tx.execute(
            "UPDATE orgs SET external = ?2 WHERE org_id = ?1 AND external IS NOT ?2",
            params![org, val],
        )?;
        if n == 0 {
            return Ok(OrgExternalOut::Same);
        }
        let mut outsiders: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT DISTINCT l.peer FROM links l JOIN users u ON u.user = l.user
                 JOIN users p ON p.user = l.peer
                 WHERE u.org = ?1 AND u.removed_ms IS NULL AND p.org <> ?1 AND l.state = 'accepted'",
            )?;
            let r = st.query_map([&org], |r| r.get(0))?;
            r.collect::<Result<_, _>>()?
        };
        if closed {
            let members: Vec<String> = {
                let mut st =
                    tx.prepare("SELECT user FROM users WHERE org = ?1 AND removed_ms IS NULL")?;
                let r = st.query_map([&org], |r| r.get(0))?;
                r.collect::<Result<_, _>>()?
            };
            for m in &members {
                for p in drop_outside_pending_in(&tx, m)? {
                    if !outsiders.contains(&p) {
                        outsiders.push(p);
                    }
                }
            }
        }
        tx.commit()?;
        Ok(OrgExternalOut::Changed { org, outsiders })
    }

    /// #845 둘째 ③ 조직 밖 막기를 켜기 전 셈 — 읽기만. 관리자·조직(개인 공간 아님)만, 아니면 `None`. 이미 닫힌 조직이면
    /// 얼 것·지울 것이 남지 않아 셋 다 0 꼴이다(켤 때 지움, 연락처는 이미 언 상태).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_external_preview(
        &self,
        admin: &str,
        now_ms: i64,
    ) -> Result<Option<OrgExternalPreview>, DbError> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(None);
        };
        let kind: String = tx.query_row(
            "SELECT COALESCE(kind, 'org') FROM orgs WHERE org_id = ?1",
            [&org],
            |r| r.get(0),
        )?;
        if kind == "personal" {
            return Ok(None);
        }
        // 수락된 링크는 방향마다 한 줄 — 멤버 쪽 줄만 세면 쌍 하나가 한 번.
        let frozen: i64 = tx.query_row(
            "SELECT COUNT(*) FROM links l
             JOIN users u ON u.user = l.user AND u.org = ?1 AND u.removed_ms IS NULL
             JOIN users p ON p.user = l.peer AND p.removed_ms IS NULL AND p.org <> ?1
             WHERE l.state = 'accepted'
               AND NOT EXISTS(SELECT 1 FROM users x JOIN orgs xo ON xo.org_id = x.org
                              WHERE x.user IN (l.user, l.peer) AND xo.external = 'closed')",
            [&org],
            |r| r.get(0),
        )?;
        // 지우는 조건은 drop_outside_pending_in 과 같게(조직 다름·상대 행 없음도 밖), 보이는 것만(만료 전 requested·declined).
        let pending: i64 = tx.query_row(
            "SELECT COUNT(DISTINCT CASE WHEN l.user < l.peer THEN l.user || char(0) || l.peer
                                        ELSE l.peer || char(0) || l.user END)
             FROM links l
             WHERE l.state IN ('requested', 'declined') AND l.requested_ms > ?2 AND l.id IS NOT NULL
               AND EXISTS(SELECT 1 FROM users m WHERE m.user IN (l.user, l.peer) AND m.org = ?1 AND m.removed_ms IS NULL)
               AND COALESCE((SELECT a.org <> b.org FROM users a, users b
                             WHERE a.user = l.user AND b.user = l.peer), 1)",
            params![org, now_ms - LINK_EXPIRE_MS],
            |r| r.get(0),
        )?;
        let invites: i64 = tx.query_row(
            "SELECT COUNT(*) FROM link_invites i
             JOIN users m ON m.user = i.requester AND m.org = ?1 AND m.removed_ms IS NULL
             WHERE i.at_ms > ?2",
            params![org, now_ms - LINK_EXPIRE_MS],
            |r| r.get(0),
        )?;
        let n = |v: i64| u64::try_from(v).unwrap_or(0);
        Ok(Some(OrgExternalPreview {
            frozen: n(frozen),
            pending: n(pending),
            invites: n(invites),
        }))
    }

    /// 그 조직의 갈래(`orgs.kind` — `personal`·`org`, #845 §7-46 덧 4). 행이 없으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_kind(&self, org: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT COALESCE(kind, 'org') FROM orgs WHERE org_id = ?1",
                [org],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 내보냈거나 나간 사람인가(묶음 5 `removed_ms`). 없는 사용자는 `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn is_removed(&self, user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1 AND removed_ms IS NOT NULL)",
            [user],
            |r| r.get(0),
        )?)
    }

    /// 이 사용자가 자기 조직의 관리자인가(묶음 5 `ready.admin`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn is_org_admin(&self, user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM org_admins x JOIN users u ON u.org = x.org_id AND u.user = x.user WHERE x.user = ?1)",
            [user],
            |r| r.get(0),
        )?)
    }

    /// 그 조직의 팀 (id, 이름), 이름순.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn teams_of_org(&self, org: &str) -> Result<Vec<(String, String)>, DbError> {
        let c = self.c();
        let mut st =
            c.prepare("SELECT team_id, name FROM teams WHERE org_id = ?1 ORDER BY name, team_id")?;
        let rows = st.query_map([org], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 사용자의 이메일·팀 id(hosted). M1 사용자는 (None, []).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn user_meta(&self, user: &str) -> Result<(Option<String>, Vec<String>), DbError> {
        let c = self.c();
        let email: Option<String> = c
            .query_row("SELECT email FROM users WHERE user = ?1", [user], |r| {
                r.get(0)
            })
            .optional()?
            .flatten();
        let mut st =
            c.prepare("SELECT team_id FROM user_teams WHERE user = ?1 ORDER BY team_id")?;
        let teams = st
            .query_map([user], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        Ok((email, teams))
    }

    /// 내 팀 바꾸기(`profile.update {teams}`, 덮어씀). 하나라도 내 조직의 팀이 아니면 바꾸지 않고 `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_user_teams(&self, user: &str, teams: &[String]) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        for team in teams {
            let ok: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM teams t JOIN users u ON u.org = t.org_id WHERE t.team_id = ?1 AND u.user = ?2)",
                params![team, user],
                |r| r.get(0),
            )?;
            if !ok {
                return Ok(false);
            }
        }
        tx.execute("DELETE FROM user_teams WHERE user = ?1", [user])?;
        for team in teams {
            tx.execute(
                "INSERT OR IGNORE INTO user_teams(user, team_id) VALUES (?1, ?2)",
                params![user, team],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// 그 조직에 `except` 가 아닌 같은 이름의 팀이 있나.
    fn team_name_taken(
        tx: &rusqlite::Transaction<'_>,
        org: &str,
        name: &str,
        except: &str,
    ) -> Result<bool, DbError> {
        Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE org_id = ?1 AND name = ?2 AND team_id <> ?3)",
            params![org, name, except],
            |r| r.get(0),
        )?)
    }

    /// 이 사용자가 관리자인 조직 id.
    fn admin_org(tx: &rusqlite::Transaction<'_>, user: &str) -> Result<Option<String>, DbError> {
        Ok(tx
            .query_row(
                "SELECT x.org_id FROM org_admins x JOIN users u ON u.org = x.org_id AND u.user = x.user WHERE x.user = ?1",
                [user],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 조직 관리자 동작 하나(#355). `name` 은 호출자가 `display_name::normalize` 로 검사한 값.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn admin_act(&self, admin: &str, act: &AdminAct<'_>) -> Result<AdminOutcome, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(AdminOutcome::Refused);
        };
        let n = match act {
            AdminAct::OrgRename { name } => tx.execute(
                "UPDATE orgs SET name = ?2 WHERE org_id = ?1",
                params![org, name],
            )?,
            AdminAct::TeamCreate { id, name } => {
                if Self::team_name_taken(&tx, &org, name, "")? {
                    return Ok(AdminOutcome::NameTaken);
                }
                tx.execute(
                    "INSERT OR IGNORE INTO teams(team_id, org_id, name) VALUES (?1, ?2, ?3)",
                    params![id, org, name],
                )?
            }
            AdminAct::TeamRename { id, name } => {
                if Self::team_name_taken(&tx, &org, name, id)? {
                    return Ok(AdminOutcome::NameTaken);
                }
                {
                    tx.execute(
                        "UPDATE teams SET name = ?3 WHERE team_id = ?1 AND org_id = ?2",
                        params![id, org, name],
                    )?
                }
            }
            AdminAct::TeamDelete { id } => {
                let n = tx.execute(
                    "DELETE FROM teams WHERE team_id = ?1 AND org_id = ?2",
                    params![id, org],
                )?;
                if n == 1 {
                    tx.execute("DELETE FROM user_teams WHERE team_id = ?1", [id])?;
                }
                n
            }
            AdminAct::Invite {
                token_hash,
                email,
                now_ms,
                expires_ms,
                window_ms,
                max,
            } => {
                // #845 ④: org.invite(가입한 사람 앞 줄)와 같은 통.
                let recent: i64 = tx.query_row(
                    "SELECT (SELECT COUNT(*) FROM invites WHERE created_by = ?1 AND created_ms > ?2)
                          + (SELECT COUNT(*) FROM org_invites WHERE by = ?1 AND at_ms > ?2)",
                    params![admin, now_ms.saturating_sub(*window_ms)],
                    |r| r.get(0),
                )?;
                if recent >= *max {
                    return Ok(AdminOutcome::RateLimited);
                }
                tx.execute("DELETE FROM invites WHERE expires_ms <= ?1", [now_ms])?;
                tx.execute(
                    "INSERT INTO invites(token_hash, org_id, email, created_by, created_ms, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![token_hash, org, email, admin, now_ms, expires_ms],
                )?
            }
        };
        if n == 0 {
            return Ok(AdminOutcome::Refused);
        }
        tx.commit()?;
        Ok(AdminOutcome::Done)
    }

    /// 관리자 주기·빼기(`org.admin {user, admin}`, 묶음 5). 요청자는 관리자, 대상은 같은 조직의 내보내지 않은 사람(자기
    /// 자신도 된다). 관리자가 0명이 되면 [`MemberOutcome::LastAdmin`] — 혼자 남은 조직도 예외 없다(관리자 0명인 조직이
    /// 남지 않게. 나가기·로그아웃은 막히지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_admin(&self, by: &str, user: &str, admin: bool) -> Result<MemberOutcome, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, by)? else {
            return Ok(MemberOutcome::Refused);
        };
        let member: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1 AND org = ?2 AND removed_ms IS NULL)",
            params![user, org],
            |r| r.get(0),
        )?;
        if !member {
            return Ok(MemberOutcome::Refused);
        }
        let n = if admin {
            tx.execute(
                "INSERT OR IGNORE INTO org_admins(org_id, user) VALUES (?1, ?2)",
                params![org, user],
            )?
        } else {
            tx.execute(
                "DELETE FROM org_admins WHERE org_id = ?1 AND user = ?2",
                params![org, user],
            )?
        };
        if n == 0 {
            return Ok(MemberOutcome::Unchanged);
        }
        if !admin {
            // 내려간 관리자가 만든 아직 안 쓴 초대는 같이 끝난다(QA — 내보낸 뒤에도 미리 뿌린 초대로 사람을 들이지 못하게).
            tx.execute(
                "DELETE FROM invites WHERE org_id = ?1 AND created_by = ?2",
                params![org, user],
            )?;
            let left: i64 = tx.query_row(
                "SELECT COUNT(*) FROM org_admins x JOIN users a ON a.user = x.user AND a.org = x.org_id
                 WHERE x.org_id = ?1 AND a.removed_ms IS NULL",
                [&org],
                |r| r.get(0),
            )?;
            if left == 0 {
                return Ok(MemberOutcome::LastAdmin);
            }
        }
        tx.commit()?;
        Ok(MemberOutcome::Done {
            revoked: Vec::new(),
        })
    }

    /// 내보내기(`member.remove {user}`, 묶음 5). 요청자는 관리자, 대상은 같은 조직의 내보내지 않은 다른 사람이고
    /// 관리자가 아니어야 한다. 대상의 기기 전부 폐기(`by: admin`) + `removed_ms`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn member_remove(
        &self,
        by: &str,
        user: &str,
        now_ms: i64,
    ) -> Result<MemberOutcome, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, by)? else {
            return Ok(MemberOutcome::Refused);
        };
        let member: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1 AND org = ?2 AND removed_ms IS NULL)",
            params![user, org],
            |r| r.get(0),
        )?;
        if by == user || !member || Self::admin_org(&tx, user)?.is_some() {
            return Ok(MemberOutcome::Refused);
        }
        let revoked = remove_user_in(&tx, user, now_ms, RevokedBy::Admin, &|e| self.mac_of(e))?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(MemberOutcome::Done { revoked })
    }

    /// 조직 나가기(`member.leave`, 묶음 5): 내 기기 전부 폐기(`by: left`) + `removed_ms` + 관리자 행 지움. 서버 조직(`orgs`
    /// 행)이 없으면(로컬 relay) [`MemberOutcome::Refused`]. 유일한 관리자이고 조직에 다른 사람이 있으면 `LastAdmin`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn member_leave(&self, user: &str, now_ms: i64) -> Result<MemberOutcome, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let hosted: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users u JOIN orgs o ON o.org_id = u.org WHERE u.user = ?1 AND u.removed_ms IS NULL)",
            [user],
            |r| r.get(0),
        )?;
        if !hosted {
            return Ok(MemberOutcome::Refused);
        }
        if last_admin_with_others(&tx, user)? {
            return Ok(MemberOutcome::LastAdmin);
        }
        let revoked = remove_user_in(&tx, user, now_ms, RevokedBy::Left, &|e| self.mac_of(e))?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(MemberOutcome::Done { revoked })
    }

    /// #877 묶음 B `org.leave`: 조직(kind='org')에서 나가 새 개인 공간(`personal_id`)으로 옮긴다 — 한 트랜잭션. 아이디·기기·이메일·
    /// 이름·얼굴·연락처·막음·mutes·pins 는 남기고 조직 것만 끊는다: 조직 역할·팀·조직 초대(받은·보낸)·초대 관계(양쪽)·기기 바꾸기
    /// 요청과 막은 기록, 공개 에이전트 범위는 전부 '나만', 운영 멈춤은 그대로(계정 제재라 조직을 나가도 안 풀림), 옛 조직이 주인인 그룹은 org_left(+남은
    /// 기기가 그 사람 잎을 빼는 remove_user 일). 다른 공간이 주인인 섞인 그룹은 그대로.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_leave(
        &self,
        user: &str,
        personal_id: &str,
        now_ms: i64,
    ) -> Result<OrgLeaveOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT u.org, u.display FROM users u JOIN orgs o ON o.org_id = u.org
                 WHERE u.user = ?1 AND u.removed_ms IS NULL AND COALESCE(o.kind, 'org') = 'org'",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((old, display)) = row else {
            return Ok(OrgLeaveOut::NotOrg);
        };
        if last_admin_with_others(&tx, user)? {
            return Ok(OrgLeaveOut::LastAdmin);
        }
        // 이름은 가입 때 개인 공간과 같은 꼴(표시 이름, 없으면 아이디) — 화면은 쓰지 않는다.
        tx.execute(
            "INSERT INTO orgs(org_id, name, admin, created_ms, kind) VALUES (?1, ?2, ?3, ?4, 'personal')",
            params![personal_id, display.as_deref().unwrap_or(user), user, now_ms],
        )?;
        // 옛 조직이 주인인 그룹 — 조직 바꾸기 전에(left_org = 옛 조직).
        tx.execute(
            "UPDATE group_members SET left_seq = (SELECT seq FROM groups g WHERE g.gid = group_members.gid), org_left = 1,
                    left_org = ?2
             WHERE user = ?1 AND left_seq IS NULL AND gid IN (SELECT gid FROM groups WHERE org = ?2)",
            params![user, old],
        )?;
        drop_left_rejoin_in(&tx, None, user)?;
        drop_empty_groups_in(&tx)?;
        tx.execute(
            "INSERT OR IGNORE INTO mls_duties(group_id, task, subject, created_ms)
             SELECT m.gid, 'remove_user', ?1, ?3 FROM group_members m
               JOIN mls_groups g ON g.group_id = m.gid
               JOIN groups gr ON gr.gid = m.gid AND gr.org = ?2
             WHERE m.user = ?1 AND m.org_left = 1
               AND EXISTS(SELECT 1 FROM mls_leaves l JOIN devices d ON d.device_id = l.device_id
                          WHERE l.group_id = m.gid AND d.user = ?1)",
            params![user, old, now_ms],
        )?;
        tx.execute(
            "UPDATE users SET org = ?2, invited_by = NULL WHERE user = ?1",
            params![user, personal_id],
        )?;
        tx.execute(
            "UPDATE users SET invited_by = NULL WHERE invited_by = ?1",
            [user],
        )?;
        tx.execute("DELETE FROM org_admins WHERE user = ?1", [user])?;
        tx.execute("DELETE FROM user_teams WHERE user = ?1", [user])?;
        tx.execute("DELETE FROM invites WHERE created_by = ?1", [user])?;
        tx.execute("DELETE FROM org_invites WHERE user = ?1 OR by = ?1", [user])?;
        tx.execute(
            "DELETE FROM invites_sent WHERE kind = 'org' AND (by = ?1 OR target_user = ?1)",
            [user],
        )?;
        // 처리방침 0.2.0 3항: 기기 바꾸기 요청·막은 기록은 조직을 나가면 함께 지운다.
        tx.execute("DELETE FROM recoveries WHERE user = ?1", [user])?;
        tx.execute("DELETE FROM recovery_blocks WHERE user = ?1", [user])?;
        // 팀·조직·사람을 가리키던 범위 모두 '나만' — 사용자가 다시 넓힌다.
        tx.execute(
            "UPDATE sessions_public SET audience = '[]' WHERE user = ?1",
            [user],
        )?;
        // #845 둘째: 옛 조직 사람(연락처 아님)은 내 목록에서, 나는 그들 목록에서 빠진다(연락처는 남음).
        prune_lists_in(&tx, user)?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(OrgLeaveOut::Moved { old_org: old })
    }

    // ---------------------------------------------------------------- 백업 기록(m1-spec §17.3)

    fn set_meta(&self, pairs: &[(&str, &str)]) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        for (k, v) in pairs {
            tx.execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [k, v],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    /// `lodelai-relay backup` 시작: 시도 시각, 바깥 사본 결과는 이번 판 것이 올 때까지 `none`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_started(&self, now_ms: i64) -> Result<(), DbError> {
        self.set_meta(&[
            ("backup_last_attempt_ms", &now_ms.to_string()),
            ("backup_offsite", BackupOffsite::None.as_str()),
        ])
    }

    /// 로컬 사본 성공(`backup-mark --local-ok` — gzip 사본이 생긴 뒤).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_succeeded(&self, now_ms: i64) -> Result<(), DbError> {
        self.set_meta(&[
            ("backup_last_ok_ms", &now_ms.to_string()),
            ("backup_last", "ok"),
        ])
    }

    /// 실패(`backup` 의 사본 실패, `backup-mark --failed` = 스크립트 중간 실패). 마지막 성공 시각은 그대로.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_failed(&self) -> Result<(), DbError> {
        self.set_meta(&[("backup_last", "failed")])
    }

    /// 바깥 사본(R2) 결과(`backup-mark --offsite …`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_offsite(&self, offsite: BackupOffsite) -> Result<(), DbError> {
        self.set_meta(&[("backup_offsite", offsite.as_str())])
    }

    /// 백업 기록(묶음 5 `server.status` 가 읽는다). 기록이 없으면 `last`·`offsite` 가 `none`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_record(&self) -> Result<BackupRecord, DbError> {
        let ms =
            |k| -> Result<Option<i64>, DbError> { Ok(self.meta(k)?.and_then(|v| v.parse().ok())) };
        Ok(BackupRecord {
            last_attempt_ms: ms("backup_last_attempt_ms")?,
            last_ok_ms: ms("backup_last_ok_ms")?,
            last: match self.meta("backup_last")?.as_deref() {
                Some("ok") => BackupLast::Ok,
                Some("failed") => BackupLast::Failed,
                _ => BackupLast::None,
            },
            offsite: self
                .meta("backup_offsite")?
                .as_deref()
                .and_then(BackupOffsite::parse)
                .unwrap_or(BackupOffsite::None),
        })
    }

    /// healthz 용: 실제 표를 한 번 읽는다(연결만 살아 있고 파일이 깨진 경우를 잡는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn health(&self) -> Result<(), DbError> {
        self.c()
            .query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0))?;
        Ok(())
    }

    // ---------------------------------------------------------------- 원격 relay 관리자(#364)

    /// 원격 relay 의 관리자 아이디(설정 코드로 처음 등록한 사람). 없으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn admin(&self) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row("SELECT value FROM meta WHERE key = 'admin'", [], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// 조직 만들기 코드 하나를 더한다(`lodelai-relay bootstrap`, relay 0.1.2). 이메일 없는 코드는 앞의 **이메일 없는** 코드만,
    /// 이메일 코드는 같은 이메일의 앞 코드만 덮어쓴다(사람마다 하나). 오래 지난 행은 이때 지운다. 서비스가 도는 동안에도
    /// 같은 DB 에 트랜잭션으로.
    ///
    /// # Errors
    /// sqlite 오류(같은 id·코드 해시가 이미 있으면 [`DbError::Sqlite`]).
    #[allow(clippy::too_many_arguments)]
    pub fn add_setup_code(
        &self,
        id: &str,
        code_hash: &[u8],
        email_hash: Option<&[u8]>,
        email_mask: Option<&str>,
        expires_ms: i64,
        now_ms: i64,
    ) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM setup_codes WHERE expires_ms <= ?1",
            [now_ms - SETUP_CODE_KEEP_EXPIRED_MS],
        )?;
        match email_hash {
            None => tx.execute("DELETE FROM setup_codes WHERE email_hash IS NULL", [])?,
            // 키 묶은 꼴로 바뀐 같은 이메일 옛 코드는 relay 의 바꾸기(가장 늦은 것만)가 지운다(#738).
            Some(e) => tx.execute(
                "DELETE FROM setup_codes WHERE email_keyed = 0 AND email_hash = ?1",
                [e],
            )?,
        };
        tx.execute(
            "INSERT INTO setup_codes(id, code_hash, email_hash, email_mask, expires_ms, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, code_hash, email_hash, email_mask, expires_ms, now_ms],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 이메일 없는 조직 만들기 코드(시험·옛 호출용) — [`Self::add_setup_code`] 의 짧은 꼴. `admin` 은 쓰지 않는다(묶음 5).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_setup_code(
        &self,
        _admin: &str,
        code_hash: &[u8],
        expires_ms: i64,
    ) -> Result<(), DbError> {
        let id: String = code_hash
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect();
        self.add_setup_code(
            &id,
            code_hash,
            None,
            None,
            expires_ms,
            expires_ms - 60 * 60 * 1000,
        )
    }

    /// 아직 쓸 수 있는 조직 만들기 코드(`bootstrap --list`) — 기한 순. 코드는 없다(해시만 있다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn list_setup_codes(&self, now_ms: i64) -> Result<Vec<SetupCodeInfo>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT id, email_mask, expires_ms FROM setup_codes WHERE expires_ms > ?1 ORDER BY expires_ms, id",
        )?;
        let rows = st.query_map([now_ms], |r| {
            Ok(SetupCodeInfo {
                id: r.get(0)?,
                email_mask: r.get(1)?,
                expires_ms: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 조직 만들기 코드 하나를 지운다(`bootstrap --revoke <id>`). 있었으면 `true`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revoke_setup_code(&self, id: &str) -> Result<bool, DbError> {
        Ok(self
            .c()
            .execute("DELETE FROM setup_codes WHERE id = ?1", [id])?
            > 0)
    }

    /// 표시 이름 변경(`profile.update`, #326). 값은 호출자가 `display_name::normalize` 로 검사한 것.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_display(&self, user: &str, display: &str) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE users SET display = ?2 WHERE user = ?1",
            params![user, display],
        )?;
        Ok(())
    }

    /// 사용자의 조직.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn user_org(&self, user: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT org FROM users WHERE user = ?1",
                params![user],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// `user` 가 `other` 를 차단했는지.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn is_blocked(&self, user: &str, other: &str) -> Result<bool, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT 1 FROM blocks WHERE user = ?1 AND blocked = ?2",
                params![user, other],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// #845 `can_reach(a, b)`: a 가 b 에게 닿을 수 있나 = (같은 조직 || 열린 수락된 연락처 — 둘째 ② 어느 쪽 조직도 밖 연락을
    /// 막지 않음) && b 가 a 를 막지 않음 && b 에 폐기 안 된
    /// 기기 있음 && b 가 멈추지 않음. 지연이 경우별로 다르지 않게 조회는 늘 끝까지 한다(한 SQL). 오류는 `false` 로 접는다.
    #[must_use]
    pub fn can_reach(&self, a: &str, b: &str, now_ms: i64) -> bool {
        self.c()
            .query_row(
                "SELECT
                   COALESCE((SELECT ua.org = ub.org FROM users ua, users ub
                             WHERE ua.user = ?1 AND ub.user = ?2 AND ua.removed_ms IS NULL AND ub.removed_ms IS NULL), 0)
                   + (EXISTS(SELECT 1 FROM links WHERE user = ?1 AND peer = ?2 AND state = 'accepted')
                      AND NOT EXISTS(SELECT 1 FROM users x JOIN orgs o ON o.org_id = x.org
                                     WHERE x.user IN (?1, ?2) AND o.external = 'closed')),
                   EXISTS(SELECT 1 FROM blocks WHERE user = ?2 AND blocked = ?1),
                   EXISTS(SELECT 1 FROM devices WHERE user = ?2 AND revoked_ms IS NULL),
                   EXISTS(SELECT 1 FROM users WHERE user = ?2 AND suspended_ms IS NOT NULL
                                 AND (suspended_until IS NULL OR suspended_until > ?3))",
                params![a, b, now_ms],
                |r| {
                    Ok(r.get::<_, i64>(0)? > 0
                        && !r.get::<_, bool>(1)?
                        && r.get::<_, bool>(2)?
                        && !r.get::<_, bool>(3)?)
                },
            )
            .unwrap_or(false)
    }

    /// #845 둘째 내 친구 목록 전부(이름·id 순).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn lists_of(&self, owner: &str) -> Result<Vec<UserList>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT list_id, name, users FROM lists WHERE owner = ?1 ORDER BY name, list_id",
        )?;
        let rows = st.query_map([owner], |r| {
            Ok(UserList {
                list_id: r.get(0)?,
                name: r.get(1)?,
                users: users_of_json(&r.get::<_, String>(2)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 둘째 `list.put`: 목록 통째 덮어쓰기. 나 자신·중복이 있으면 [`ListPutOut::Refused`]. [`related_c`](같은 조직 ||
    /// 수락된 연락처 — 얼린 연락처 포함)가 아닌 사람(연락처를 뺐거나·막았거나·조직을 나감)은 거절하지 않고 빼고 저장한다
    /// (845-둘째 '새 기기의 얼린 아이디' — 옛 범위를 쥔 기기의 put 이 통째로 거절되지 않게, 좁아지기만). 새 id 가 [`LISTS_MAX`] 를 넘으면 [`ListPutOut::Quota`]. 꼴(이름·id·수)은
    /// 부르는 쪽이 본다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn list_put(
        &self,
        owner: &str,
        list_id: &str,
        name: &str,
        users: &[String],
        now_ms: i64,
    ) -> Result<ListPutOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let mut seen = std::collections::HashSet::new();
        if users.iter().any(|u| u == owner || !seen.insert(u.as_str())) {
            return Ok(ListPutOut::Refused);
        }
        let mut kept: Vec<String> = Vec::with_capacity(users.len());
        for u in users {
            if related_c(&tx, owner, u)? {
                kept.push(u.clone());
            }
        }
        let users = kept.as_slice();
        let old: Option<String> = tx
            .query_row(
                "SELECT users FROM lists WHERE owner = ?1 AND list_id = ?2",
                params![owner, list_id],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_none() {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM lists WHERE owner = ?1",
                [owner],
                |r| r.get(0),
            )?;
            if n >= LISTS_MAX {
                return Ok(ListPutOut::Quota);
            }
        }
        tx.execute(
            "INSERT INTO lists(owner, list_id, name, users, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(owner, list_id) DO UPDATE SET name = excluded.name, users = excluded.users,
               updated_ms = excluded.updated_ms",
            params![owner, list_id, name, users_json(users), now_ms],
        )?;
        tx.commit()?;
        let old = old.map(|t| users_of_json(&t)).unwrap_or_default();
        let mut changed: Vec<String> = old.iter().filter(|u| !users.contains(u)).cloned().collect();
        changed.extend(users.iter().filter(|u| !old.contains(u)).cloned());
        Ok(ListPutOut::Done(changed))
    }

    /// #845 둘째 `list.delete`: 목록을 지운다. 그 목록에 있던 사람(없던 id 면 `None`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn list_delete(&self, owner: &str, list_id: &str) -> Result<Option<Vec<String>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT users FROM lists WHERE owner = ?1 AND list_id = ?2",
                params![owner, list_id],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute(
            "DELETE FROM lists WHERE owner = ?1 AND list_id = ?2",
            params![owner, list_id],
        )?;
        tx.commit()?;
        Ok(old.map(|t| users_of_json(&t)))
    }

    /// #845 수락된 연락처 수(KP 가져가기 `owner_pair_per_day` 에 더한다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_count(&self, user: &str) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM links WHERE user = ?1 AND state = 'accepted'",
            [user],
            |r| r.get(0),
        )?)
    }

    /// #845 수락된 연락처(줄 주인 쪽에서 본 상대).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn linked(&self, user: &str, peer: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM links WHERE user = ?1 AND peer = ?2 AND state = 'accepted')",
            params![user, peer],
            |r| r.get(0),
        )?)
    }

    /// #845 §5: `user` 가 연락처 `peer` 에게 task 를 열었나(수락된 줄의 task_ok).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_task_ok(&self, user: &str, peer: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM links WHERE user = ?1 AND peer = ?2 AND state = 'accepted' AND task_ok = 1)",
            params![user, peer],
            |r| r.get(0),
        )?)
    }

    /// 시험용: 그 기기의 못 엶 보고를 `n` 줄 채운다(시간당 상한 시험 — 알림은 이미 보낸 것으로, 하루 뒤 만료).
    ///
    /// # Errors
    /// sqlite 오류.
    #[doc(hidden)]
    pub fn unreadable_fill_for_test(
        &self,
        device_id: &str,
        n: i64,
        at_ms: i64,
    ) -> Result<(), DbError> {
        let c = self.c();
        for i in 0..n {
            c.execute(
                "INSERT INTO unreadable_reports(msg_id, device_id, from_user, to_user, group_id, n, at_ms, expires_ms,
                   notified, sent) VALUES (?1, ?2, 'x', 'x', 'g', 2, ?3, ?4, 1, 3)",
                params![format!("fill-{i}"), device_id, at_ms, at_ms + 86_400_000],
            )?;
        }
        Ok(())
    }

    /// 시험·관리용: `user` 가 연락처 `peer` 에게 task 를 연다/닫는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_link_task_ok(&self, user: &str, peer: &str, ok: bool) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE links SET task_ok = ?3 WHERE user = ?1 AND peer = ?2 AND state = 'accepted'",
            params![user, peer, ok],
        )? > 0)
    }

    /// #845 연락 요청(설계 §7-7, 한 트랜잭션). 받는 사람을 찾고 줄을 만든다 — 답 꼴은 이 결과와 무관하게 같다(이메일).
    /// - 없는·내보낸 아이디: `unknown`. 없는 이메일: `link_invites`(같은 주소 앞 살아 있는 내 것이 있으면 그대로).
    /// - 나 자신·이미 연락처·만료 전 내 요청이 있음: 아무것도.
    /// - 내가 그 사람을 막았으면 막음을 풀고 보통 요청.
    /// - 그 사람의 만료 전 requested 가 나에게 있으면 바로 수락. declined·만료 줄은 지우고 새로.
    /// - 그 사람이 나를 막았으면 줄을 declined 로 만든다(내 outgoing 엔 만료까지 기다림 — 차단이 드러나지 않음).
    ///
    /// 상한(§7-1, 찾기 전에 [`link_limit`]): 하루 requested−refunded < 100(줄임 중 5), 걸린 요청(requested·declined·
    /// 가입 안 한 이메일) < 100. 새 줄을 만들 때만 센다(requested·declined·새 link_invites). 나 자신·이미 연락처·만료 전
    /// 같은 요청·없는 아이디·서로 요청(바로 수락)은 세지 않는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_request(&self, r: &LinkRequestIn<'_>) -> Result<LinkRequestOut, DbError> {
        let since = r.now_ms - LINK_EXPIRE_MS;
        let mac = match r.to {
            LinkTarget::Email(e) => Some(self.mac_of(e)?),
            LinkTarget::User(_) => None,
        };
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        // 상한은 받는 사람을 찾기 전에(걸렸을 때 답이 대상과 무관하게 같게).
        if let Some(until) = link_limit(&tx, r.me, r.now_ms)? {
            tx.commit()?;
            return Ok(LinkRequestOut {
                card: None,
                unknown: false,
                notify: Vec::new(),
                limited_until: Some(until),
            });
        }
        let target: Option<String> = match r.to {
            LinkTarget::User(u) => tx
                .query_row(
                    "SELECT user FROM users WHERE user = ?1 AND removed_ms IS NULL",
                    [u],
                    |row| row.get(0),
                )
                .optional()?,
            LinkTarget::Email(e) => tx
                .query_row(
                    "SELECT user FROM users WHERE email = ?1 AND removed_ms IS NULL",
                    [e],
                    |row| row.get(0),
                )
                .optional()?,
        };
        let Some(t) = target else {
            // #845 둘째 ②: 밖 연락을 막은 조직 멤버는 미가입 이메일 초대를 만들지 않는다(보낸 듯 같은 답).
            if closed_c(&tx, r.me)? {
                tx.commit()?;
                return Ok(LinkRequestOut {
                    card: None,
                    unknown: false,
                    notify: Vec::new(),
                    limited_until: None,
                });
            }
            if let (LinkTarget::Email(_), Some(mac)) = (r.to, mac) {
                let live: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM link_invites WHERE requester = ?1 AND email_mac = ?2 AND at_ms > ?3)",
                    params![r.me, mac, since],
                    |row| row.get(0),
                )?;
                if !live {
                    tx.execute(
                        "DELETE FROM link_invites WHERE requester = ?1 AND email_mac = ?2",
                        params![r.me, mac],
                    )?;
                    tx.execute(
                        "INSERT INTO link_invites(id, requester, email_mac, email_shown, at_ms, send_after_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        params![r.id, r.me, mac, r.shown, r.now_ms],
                    )?;
                    link_charge(&tx, r.me, r.now_ms)?;
                    if let LinkTarget::Email(e) = r.to {
                        mail_enqueue_in(&tx, "contact", r.id, e, r.me, None, r.now_ms)?;
                    }
                }
                tx.commit()?;
                return Ok(LinkRequestOut {
                    card: None,
                    unknown: false,
                    notify: vec![r.me.to_owned()],
                    limited_until: None,
                });
            }
            tx.commit()?;
            return Ok(LinkRequestOut {
                card: None,
                unknown: true,
                notify: Vec::new(),
                limited_until: None,
            });
        };
        let none = LinkRequestOut {
            card: None,
            unknown: false,
            notify: Vec::new(),
            limited_until: None,
        };
        if t == r.me {
            tx.commit()?;
            return Ok(none);
        }
        let mine: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, requested_ms FROM links WHERE user = ?1 AND peer = ?2",
                params![r.me, t],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match &mine {
            Some((st, _)) if st == "accepted" => {
                tx.commit()?;
                return Ok(none);
            }
            Some((_, at)) if *at > since => {
                tx.commit()?;
                return Ok(none);
            }
            Some(_) => {
                tx.execute(
                    "DELETE FROM links WHERE user = ?1 AND peer = ?2",
                    params![r.me, t],
                )?;
            }
            None => {}
        }
        tx.execute(
            "DELETE FROM blocks WHERE user = ?1 AND blocked = ?2",
            params![r.me, t],
        )?;
        let theirs: Option<(String, i64)> = tx
            .query_row(
                "SELECT state, requested_ms FROM links WHERE user = ?1 AND peer = ?2",
                params![t, r.me],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        // #845 둘째 ②: 조직 밖 연락을 막은 조직이 끼면 막힌 것과 같은 답(상대가 그 조직의 정책을 알 필요 없음).
        let blocked_me: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE user = ?1 AND blocked = ?2)",
            params![t, r.me],
            |row| row.get(0),
        )? || closed_between_c(&tx, r.me, &t)?;
        let mut accepted = false;
        match theirs {
            Some((st, at)) if st == "requested" && at > since && !blocked_me => {
                tx.execute(
                    "UPDATE links SET state = 'accepted', accepted_ms = ?3 WHERE user = ?1 AND peer = ?2",
                    params![t, r.me, r.now_ms],
                )?;
                // 서로 요청 = 그 사람 요청의 수락 — 그 사람 셈을 돌려주고, 이 요청은 세지 않는다.
                link_refund(&tx, &t, at, r.now_ms)?;
                accepted = true;
            }
            Some((st, _)) if st != "accepted" => {
                tx.execute(
                    "DELETE FROM links WHERE user = ?1 AND peer = ?2",
                    params![t, r.me],
                )?;
            }
            _ => {}
        }
        let state = if accepted {
            "accepted"
        } else if blocked_me {
            "declined"
        } else {
            "requested"
        };
        tx.execute(
            "INSERT INTO links(user, peer, state, requested_ms, accepted_ms, id, shown)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                r.me,
                t,
                state,
                r.now_ms,
                accepted.then_some(r.now_ms),
                r.id,
                r.shown
            ],
        )?;
        // 막힌 요청(declined)도 똑같이 센다 — 셈으로 막음이 드러나지 않게.
        if !accepted {
            link_charge(&tx, r.me, r.now_ms)?;
        }
        tx.commit()?;
        Ok(LinkRequestOut {
            unknown: false,
            card: (state == "requested").then(|| t.clone()),
            notify: vec![r.me.to_owned(), t],
            limited_until: None,
        })
    }

    /// #845 받은 요청에 답. 모르는·만료된·이미 답한 id 는 `None`(조용히 무시). 돌려주는 값 = 요청한 사람.
    /// 차단: 막음을 넣고 두 사람 사이 수락된 줄과 내가 보낸 요청을 지운다. 요청한 사람의 줄은 declined 로 남겨 만료까지
    /// 기다림으로 보인다(거절과 같은 꼴 — 차단이 드러나지 않음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_answer(
        &self,
        me: &str,
        id: &str,
        answer: LinkAnswer,
        now_ms: i64,
    ) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let from: Option<(String, i64)> = tx
            .query_row(
                "SELECT user, requested_ms FROM links WHERE id = ?1 AND peer = ?2 AND state = 'requested' AND requested_ms > ?3",
                params![id, me, now_ms - LINK_EXPIRE_MS],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((from, asked_ms)) = from else {
            return Ok(None);
        };
        match answer {
            LinkAnswer::Accept => {
                link_refund(&tx, &from, asked_ms, now_ms)?;
                tx.execute(
                    "UPDATE links SET state = 'accepted', accepted_ms = ?3 WHERE user = ?1 AND peer = ?2",
                    params![from, me, now_ms],
                )?;
                tx.execute(
                    "INSERT INTO links(user, peer, state, requested_ms, accepted_ms) VALUES (?1, ?2, 'accepted', ?3, ?3)
                     ON CONFLICT(user, peer) DO UPDATE SET state = 'accepted', accepted_ms = ?3",
                    params![me, from, now_ms],
                )?;
            }
            LinkAnswer::Decline => {
                tx.execute(
                    "UPDATE links SET state = 'declined' WHERE user = ?1 AND peer = ?2",
                    params![from, me],
                )?;
            }
            LinkAnswer::Block => {
                tx.execute(
                    "UPDATE links SET state = 'declined' WHERE user = ?1 AND peer = ?2",
                    params![from, me],
                )?;
                tx.execute(
                    "DELETE FROM links WHERE user = ?1 AND peer = ?2",
                    params![me, from],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO blocks(user, blocked, at_ms) VALUES (?1, ?2, ?3)",
                    params![me, from, now_ms],
                )?;
            }
        }
        tx.commit()?;
        Ok(Some(from))
    }

    /// #845 연락처 빼기·보낸 요청 거두기: 내 줄(어느 상태든)과 수락된 상대 줄을 지운다. 상대가 나에게 건 요청은 남긴다.
    /// `block`(§7-8)이면 두 방향 줄을 모두 지우고 막음을 넣는다 — 상대에겐 빼기와 같게 보인다. 바뀐 게 있으면 `true`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_remove(
        &self,
        me: &str,
        peer: &str,
        block: bool,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let theirs = if block {
            "DELETE FROM links WHERE user = ?2 AND peer = ?1"
        } else {
            "DELETE FROM links WHERE user = ?2 AND peer = ?1 AND state = 'accepted'"
        };
        let mut n = tx.execute(
            "DELETE FROM links WHERE user = ?1 AND peer = ?2",
            params![me, peer],
        )? + tx.execute(theirs, params![me, peer])?;
        // #880: 연락처가 끝나면 서로의 1:1 고정도 뺀다(디렉터리가 바뀌는 쪽이라 n 에 넣지 않음 — 링크 줄이 이미 셈).
        for (who, other) in [(me, peer), (peer, me)] {
            tx.execute(
                &format!("DELETE FROM pins WHERE user = ?1 AND {PERSON_CONV_OF}"),
                params![who, other],
            )?;
        }
        if block {
            let known: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE user = ?1)",
                [peer],
                |r| r.get(0),
            )?;
            if known {
                n += tx.execute(
                    "INSERT OR IGNORE INTO blocks(user, blocked, at_ms) VALUES (?1, ?2, ?3)",
                    params![me, peer, now_ms],
                )?;
            }
        }
        if n > 0 {
            // §7-17: 서로의 '고른 사람' 범위에서 상대를 뺀다 — 다시 연락처가 돼도 옛 범위로 세션이 말없이 다시 보이지 않게
            // (주인 앱이 꺼져 있어도).
            drop_from_audiences_in(&tx, me, peer)?;
            drop_from_audiences_in(&tx, peer, me)?;
        }
        tx.commit()?;
        Ok(n > 0)
    }

    /// #845 §7-9 내가 보낸 요청 거두기: 내 links 줄(기다림·거절당함 어느 쪽이든 — 갈리면 막음이 드러난다)이나
    /// 내 link_invites 줄을 id 로 지운다. 하루 요청 셈은 돌려주지 않는다. 지운 게 없으면 `None`,
    /// 있으면 `Some(상대)` — links 줄이면 그 사람(받은 요청 줄을 바로 빼도록 디렉터리를 보냄), 이메일 초대면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_withdraw(&self, me: &str, id: &str) -> Result<Option<Option<String>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let peer: Option<String> = tx
            .query_row(
                "DELETE FROM links WHERE user = ?1 AND id = ?2 AND state IN ('requested', 'declined') RETURNING peer",
                params![me, id],
                |r| r.get(0),
            )
            .optional()?;
        let n = tx.execute(
            "DELETE FROM link_invites WHERE requester = ?1 AND id = ?2",
            params![me, id],
        )?;
        tx.commit()?;
        Ok((peer.is_some() || n > 0).then_some(peer))
    }

    /// #845 연락처 하나의 task 열기. 수락된 연락처가 아니거나 값이 같으면 `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_update(&self, me: &str, peer: &str, task_ok: bool) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE links SET task_ok = ?3 WHERE user = ?1 AND peer = ?2 AND state = 'accepted' AND task_ok != ?3",
            params![me, peer, task_ok],
        )? > 0)
    }

    /// #845 수락된 연락처(내보내지 않은 사람): (상대, 내가 연 task_ok, 상대가 연 task_ok, 수락 ms, 내 링크로 들어옴 #886 ⑧).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn links_of(&self, me: &str) -> Result<Vec<LinkRow>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT l.peer, l.task_ok, COALESCE(o.task_ok, 0), l.accepted_ms, COALESCE(l.via = 'link', 0) FROM links l
             JOIN users u ON u.user = l.peer AND u.removed_ms IS NULL
             LEFT JOIN links o ON o.user = l.peer AND o.peer = l.user AND o.state = 'accepted'
             WHERE l.user = ?1 AND l.state = 'accepted'
               AND NOT EXISTS(SELECT 1 FROM users x JOIN orgs xo ON xo.org_id = x.org
                              WHERE x.user IN (l.user, l.peer) AND xo.external = 'closed')
             ORDER BY l.peer",
        )?;
        let rows = st.query_map([me], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 받은 요청(만료 전, requested 만): (id, 요청한 사람, 표시 이름, 이메일, 시각).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::type_complexity)]
    pub fn link_incoming(
        &self,
        me: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, Option<String>, Option<String>, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT l.id, l.user, u.display, u.email, l.requested_ms FROM links l
             JOIN users u ON u.user = l.user AND u.removed_ms IS NULL
             WHERE l.peer = ?1 AND l.state = 'requested' AND l.requested_ms > ?2 AND l.id IS NOT NULL
             ORDER BY l.requested_ms, l.id",
        )?;
        let rows = st.query_map(params![me, now_ms - LINK_EXPIRE_MS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 보낸 요청(만료 전 — requested·declined 를 가르지 않음, 가입 안 한 이메일 포함): (id, 친 값, 시각).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_outgoing(
        &self,
        me: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT id, COALESCE(shown, peer), requested_ms FROM links
               WHERE user = ?1 AND state IN ('requested', 'declined') AND requested_ms > ?2 AND id IS NOT NULL
             UNION ALL
             SELECT id, email_shown, at_ms FROM link_invites WHERE requester = ?1 AND at_ms > ?2
             ORDER BY 3, 1",
        )?;
        let rows = st.query_map(params![me, now_ms - LINK_EXPIRE_MS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 디렉터리 갱신을 같이 받을 사람: 수락된 연락처 + 걸린 요청의 양쪽(만료 전).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_watchers(&self, me: &str, now_ms: i64) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT peer FROM links WHERE user = ?1 AND (state = 'accepted' OR requested_ms > ?2)
             UNION SELECT user FROM links WHERE peer = ?1 AND (state = 'accepted' OR requested_ms > ?2)",
        )?;
        let rows = st.query_map(params![me, now_ms - LINK_EXPIRE_MS], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// §7-57 그 사람들의 가입 표시 이름(들어온 순서 그대로) — 지운(나간·내보낸) 계정과 이름이 비었으면 뺀다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn display_names(&self, users: &[String]) -> Result<Vec<(String, String)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT display FROM users WHERE user = ?1 AND removed_ms IS NULL AND COALESCE(display, '') <> ''",
        )?;
        let mut out = Vec::new();
        for u in users {
            if let Some(d) = st.query_row([u], |r| r.get::<_, String>(0)).optional()? {
                out.push((u.clone(), d));
            }
        }
        Ok(out)
    }

    /// #845 디렉터리 links 항목의 사람 정보: (표시 이름, 사진 blob, 고른 기본 이미지, 접속 표시 숨김).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::type_complexity)]
    pub fn person_bits(
        &self,
        user: &str,
    ) -> Result<(Option<String>, Option<String>, Option<String>, bool), DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT display, avatar_blob, look_json, share_presence = 0 FROM users WHERE user = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .unwrap_or((None, None, None, true)))
    }

    /// #845 만료(30일)된 요청 줄과 가입 안 한 이메일 요청을 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_sweep(&self, now_ms: i64) -> Result<(), DbError> {
        let c = self.c();
        let before = now_ms - LINK_EXPIRE_MS;
        c.execute(
            "DELETE FROM links WHERE state != 'accepted' AND requested_ms <= ?1",
            [before],
        )?;
        c.execute("DELETE FROM link_invites WHERE at_ms <= ?1", [before])?;
        c.execute("DELETE FROM group_invites WHERE at_ms <= ?1", [before])?;
        c.execute("DELETE FROM invites_sent WHERE at_ms <= ?1", [before])?;
        c.execute(
            "DELETE FROM org_invites WHERE at_ms <= ?1",
            [now_ms - ORG_INVITE_TTL_MS],
        )?;
        // 하루 셈은 오늘 것만 쓴다.
        c.execute(
            "DELETE FROM link_counts WHERE day < ?1",
            [now_ms.div_euclid(DAY_MS)],
        )?;
        // #876 하루 첨부 합(#881 옮기기 통도): 2일 뒤 지운다(숫자만).
        c.execute(
            "DELETE FROM blob_daily WHERE day < ?1",
            [now_ms.div_euclid(DAY_MS) - 1],
        )?;
        c.execute(
            "DELETE FROM blob_history_daily WHERE day < ?1",
            [now_ms.div_euclid(DAY_MS) - 1],
        )?;
        Ok(())
    }

    fn contact_token(&self, nonce: &str) -> Result<String, DbError> {
        use base64::Engine;
        use hmac::Mac;
        let key = self.email_key.get().ok_or(DbError::NoEmailKey)?;
        let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
            .expect("HMAC 은 어떤 길이의 키든 받는다");
        m.update(b"lodelai-contact-link-v1\0");
        m.update(nonce.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(m.finalize().into_bytes()))
    }

    /// #845 ③ 내 초대 링크 토큰 — 살아 있는 것이 있으면 같은 토큰(nonce 로 다시 만듦), 없으면 `nonce` 로 새로.
    /// `rotate` 면 살아 있는 것을 끝내고 새로 만든다(옛 토큰으로 들어오면 link.join 이 조용히 ok 만).
    ///
    /// # Errors
    /// sqlite 오류·이메일 키 없음.
    pub fn contact_link(
        &self,
        me: &str,
        nonce: &str,
        rotate: bool,
        now_ms: i64,
    ) -> Result<String, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        if rotate {
            tx.execute(
                "UPDATE contact_links SET revoked_ms = ?2 WHERE user = ?1 AND revoked_ms IS NULL",
                params![me, now_ms],
            )?;
        }
        let live: Option<String> = tx
            .query_row(
                "SELECT nonce FROM contact_links WHERE user = ?1 AND revoked_ms IS NULL",
                [me],
                |r| r.get(0),
            )
            .optional()?;
        let token = match live {
            Some(n) => self.contact_token(&n)?,
            None => {
                let token = self.contact_token(nonce)?;
                tx.execute(
                    "INSERT INTO contact_links(token_hash, user, nonce, created_ms) VALUES (?1, ?2, ?3, ?4)",
                    params![token_hash(&token), me, nonce, now_ms],
                )?;
                token
            }
        };
        tx.commit()?;
        Ok(token)
    }

    /// #845 ④ `org.invite{email}`(§7-2): 관리자만. 정규화한 이메일 `email` 이
    /// - 가입한 사람이면 `org_invites` 줄(같은 조직·막힌 사이면 카드 없이 줄만, 다른 조직이면 받을 수 없는 카드)
    /// - 없으면 그 이메일에 묶인 `invites` 토큰(30일, 메일은 ⑤).
    ///
    /// 관리자 시간 상한([`crate::ws::INVITE_MAX`]/[`crate::ws::INVITE_WINDOW_MS`] — 링크 초대 만들기와 같은 통)은 모든 경우를 같이 센다.
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn org_invite(
        &self,
        admin: &str,
        email: &str,
        shown: &str,
        id: &str,
        token_hash: &[u8],
        now_ms: i64,
        window_ms: i64,
        max: i64,
    ) -> Result<OrgInviteOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(OrgInviteOut::Refused);
        };
        let since = now_ms.saturating_sub(window_ms);
        let (recent, oldest): (i64, Option<i64>) = tx.query_row(
            "SELECT COUNT(*), MIN(t) FROM (
               SELECT created_ms AS t FROM invites WHERE created_by = ?1 AND created_ms > ?2
               UNION ALL SELECT at_ms FROM org_invites WHERE by = ?1 AND at_ms > ?2)",
            params![admin, since],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if recent >= max {
            return Ok(OrgInviteOut::RateLimited {
                until_ms: oldest.unwrap_or(now_ms) + window_ms,
            });
        }
        tx.execute(
            "DELETE FROM org_invites WHERE at_ms <= ?1",
            [now_ms - ORG_INVITE_TTL_MS],
        )?;
        let target: Option<(String, String)> = tx
            .query_row(
                "SELECT user, org FROM users WHERE email = ?1 AND removed_ms IS NULL",
                [email],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let notify = match target {
            Some((user, user_org)) => {
                // 어느 쪽이든 막힌 사이면 카드 없이(답한 줄로 남겨 셈만 — 갈래가 셈으로 새지 않게, §7-16).
                let blocked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM blocks WHERE (user = ?1 AND blocked = ?2) OR (user = ?2 AND blocked = ?1))",
                    params![admin, user],
                    |r| r.get(0),
                )?;
                tx.execute(
                    "INSERT INTO org_invites(id, org_id, user, by, at_ms, done) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, org, user, admin, now_ms, blocked],
                )?;
                if user_org != org {
                    sent_in(
                        &tx,
                        id,
                        "org",
                        &org,
                        admin,
                        shown,
                        Some(&user),
                        Some(email),
                        Some(id),
                        now_ms,
                        false,
                    )?;
                }
                (user_org != org && !blocked).then_some(user)
            }
            None => {
                tx.execute("DELETE FROM invites WHERE expires_ms <= ?1", [now_ms])?;
                tx.execute(
                    "INSERT INTO invites(token_hash, org_id, email, created_by, created_ms, expires_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![token_hash, org, email, admin, now_ms, now_ms + ORG_INVITE_TTL_MS],
                )?;
                let r = lodelai_crypto::encoding::encode(token_hash);
                mail_enqueue_in(&tx, "org", &r, email, admin, Some(&org), now_ms)?;
                sent_in(
                    &tx,
                    id,
                    "org",
                    &org,
                    admin,
                    shown,
                    None,
                    Some(email),
                    Some(&r),
                    now_ms,
                    false,
                )?;
                None
            }
        };
        tx.commit()?;
        Ok(OrgInviteOut::Sent { notify, org })
    }

    /// #845 ④ 디렉터리 `org_invites`: 만료 전, 지금 내 조직이 아닌 조직마다 가장 최근 줄 하나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_invites_of(&self, user: &str, now_ms: i64) -> Result<Vec<OrgInviteCard>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT i.id, o.name, b.display, i.at_ms, COALESCE(mo.kind, 'org') <> 'personal', o.color
             FROM org_invites i
             JOIN orgs o ON o.org_id = i.org_id
             JOIN users me ON me.user = i.user
             LEFT JOIN orgs mo ON mo.org_id = me.org
             LEFT JOIN users b ON b.user = i.by
             WHERE i.user = ?1 AND i.at_ms > ?2 AND me.org <> i.org_id AND i.done = 0
               AND i.at_ms = (SELECT MAX(at_ms) FROM org_invites x
                              WHERE x.user = i.user AND x.org_id = i.org_id AND x.done = 0)
             GROUP BY i.org_id
             ORDER BY i.at_ms DESC",
        )?;
        let rows = st.query_map(params![user, now_ms - ORG_INVITE_TTL_MS], |r| {
            Ok(OrgInviteCard {
                id: r.get(0)?,
                org_name: r.get(1)?,
                by_display: r.get(2)?,
                at_ms: r.get(3)?,
                other_org: r.get(4)?,
                org_color: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 ④ `org.invite.answer`. 거절은 그 조직 줄을 지운다(조용). 수락은 내가 개인 공간일 때만 옮긴다(§1·정책 §3):
    /// `users.org` 를 그 조직으로, 개인 행을 지우고, 내 공개 에이전트의 범위 '조직 전체'를 '나만'(people [])으로 좁힌다.
    /// 돌려주는 값: 옮겼으면 (옛 조직, 새 조직). 모르는·만료·받을 수 없는 id 는 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_invite_answer(
        &self,
        me: &str,
        id: &str,
        accept: bool,
        now_ms: i64,
    ) -> Result<Option<(String, String)>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(String, String)> = tx
            .query_row(
                "SELECT org_id, by FROM org_invites WHERE id = ?1 AND user = ?2 AND at_ms > ?3 AND done = 0",
                params![id, me, now_ms - ORG_INVITE_TTL_MS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((org, by)) = row else {
            return Ok(None);
        };
        if !accept {
            tx.execute(
                "UPDATE org_invites SET done = 1 WHERE user = ?1 AND org_id = ?2",
                params![me, org],
            )?;
            tx.commit()?;
            return Ok(None);
        }
        let Some(old) = move_personal_to_org_in(&tx, me, &org, Some(&by), now_ms)? else {
            return Ok(None);
        };
        tx.commit()?;
        Ok(Some((old, org)))
    }

    /// 조직 만들기 코드 쓰기(등록 `OrgChoice::Create`·§7-46 `org.create` 가 같이 씀). 코드를 줬으면 그 코드를(확인 뒤
    /// 경합에도 그 이메일 것이거나 이메일 없는 코드만), 코드 없이 승인된 이메일(#737)이면 그 이메일에 묶인 살아 있는 코드를
    /// 모두 쓴다(승인 한 번이 조직 하나). 둘 다 아니면 쓸 것 없음(참). 쓸 코드가 없으면 거짓.
    fn use_setup_code_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        code_hash: Option<&[u8]>,
        allowed_email: bool,
        email: Option<&str>,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        if code_hash.is_none() && !allowed_email {
            return Ok(true);
        }
        let (sha, mac) = email
            .and_then(lodelai_protocol::email::normalize)
            .map(|e| self.setup_email_forms(&e))
            .map_or((None, None), |(s, m)| (Some(s), m));
        let used = if let Some(h) = code_hash {
            tx.execute(
                "DELETE FROM setup_codes WHERE code_hash = ?1 AND expires_ms > ?2
                   AND (email_hash IS NULL OR (email_keyed = 0 AND email_hash = ?3)
                        OR (email_keyed = 1 AND email_hash = ?4))",
                params![h, now_ms, sha, mac],
            )?
        } else {
            if sha.is_none() {
                return Ok(false);
            }
            tx.execute(
                "DELETE FROM setup_codes WHERE expires_ms > ?2
                   AND ((email_keyed = 0 AND email_hash = ?1) OR (email_keyed = 1 AND email_hash = ?3))",
                params![sha, now_ms, mac],
            )?
        };
        Ok(used > 0)
    }

    /// 이 사람의 이메일(정규화, 없으면 `None`) — §7-46 ws 가 조직 만들기 코드 확인·승인 이메일 확인에 쓴다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn user_email(&self, me: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row("SELECT email FROM users WHERE user = ?1", [me], |r| {
                r.get(0)
            })
            .optional()?
            .flatten())
    }

    /// §7-46 `org.code.check`: 가입한 사람이 낸 조직 초대 코드의 카드(가입의 `invites/check` 와 같은 꼴). 읽기만 — 초대를
    /// 쓰지 않는다. 이메일 묶인 초대는 내 이메일과 같을 때만 카드(이메일 없는 사람은 다름). 틀린 시도 셈은 부르는 쪽(메모리).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_code_check(
        &self,
        me: &str,
        invite_hash: &[u8],
        now_ms: i64,
    ) -> Result<InviteCheckOut, DbError> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let inv: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT org_id, created_by, email FROM invites WHERE token_hash = ?1 AND expires_ms > ?2",
                params![invite_hash, now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((org, by, bound)) = inv else {
            return Ok(InviteCheckOut::NotFound);
        };
        let email = user_email_in(&tx, me)?;
        if !invite_email_ok_for(bound.as_deref(), email.as_deref()) {
            return Ok(InviteCheckOut::OtherEmail(bound.unwrap_or_default()));
        }
        Ok(InviteCheckOut::Ok(invite_info_in(&tx, org, by)?))
    }

    /// §7-46 `org.join`: 개인 공간인 사람이 초대 코드로 그 조직에 든다 — 초대를 쓰고(가입 `OrgChoice::Invite` 와 같은 검사)
    /// 옮김 함수. `teams` 는 그 조직 것만(아니면 [`DbError::BadOrg`]). 이메일이 다르면 커밋하지 않는다 — 초대는 남는다.
    ///
    /// # Errors
    /// sqlite 오류, [`DbError::BadOrg`].
    pub fn org_join(
        &self,
        me: &str,
        invite_hash: &[u8],
        teams: &[String],
        now_ms: i64,
    ) -> Result<OrgMoveOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        if !is_personal_in(&tx, me)? {
            return Ok(OrgMoveOut::NotPersonal);
        }
        let inv: Option<(String, Option<String>, String)> = tx
            .query_row(
                "DELETE FROM invites WHERE token_hash = ?1 AND expires_ms > ?2 RETURNING org_id, email, created_by",
                params![invite_hash, now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((org, bound, by)) = inv else {
            return Ok(OrgMoveOut::BadCode);
        };
        let email = user_email_in(&tx, me)?;
        if !invite_email_ok_for(bound.as_deref(), email.as_deref()) {
            return Ok(OrgMoveOut::OtherEmail(bound.unwrap_or_default()));
        }
        for team in teams {
            let ok: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM teams WHERE team_id = ?1 AND org_id = ?2)",
                params![team, org],
                |r| r.get(0),
            )?;
            if !ok {
                return Err(DbError::BadOrg);
            }
        }
        let Some(old) = move_personal_to_org_in(&tx, me, &org, Some(&by), now_ms)? else {
            return Ok(OrgMoveOut::NotPersonal);
        };
        tx.execute("DELETE FROM user_teams WHERE user = ?1", [me])?;
        for team in teams {
            tx.execute(
                "INSERT OR IGNORE INTO user_teams(user, team_id) VALUES (?1, ?2)",
                params![me, team],
            )?;
        }
        tx.execute(
            "UPDATE invites_sent SET joined_ms = ?2, target_user = ?3 WHERE recv_ref = ?1",
            params![lodelai_crypto::encoding::encode(invite_hash), now_ms, me],
        )?;
        tx.commit()?;
        Ok(OrgMoveOut::Moved(old, org))
    }

    /// §7-46 `org.create`: 개인 공간인 사람이 조직을 만들고 그리로 옮긴다 — 가입 `OrgChoice::Create` 와 같은 코드 쓰기·상한
    /// (`quota` 가 있으면), 새 `orgs`(kind org)·`org_admins` 나, 옮김 함수. 거절은 커밋하지 않는다.
    ///
    /// # Errors
    /// sqlite 오류, [`DbError::OrgClosed`]·[`DbError::OrgRateLimited`].
    #[allow(clippy::too_many_arguments)]
    pub fn org_create_move(
        &self,
        me: &str,
        id: &str,
        name: &str,
        setup_code_hash: Option<&[u8]>,
        quota: Option<OrgQuota>,
        allowed_email: bool,
        now_ms: i64,
    ) -> Result<OrgMoveOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        if !is_personal_in(&tx, me)? {
            return Ok(OrgMoveOut::NotPersonal);
        }
        let email = user_email_in(&tx, me)?;
        if let Some(q) = quota {
            let Some(e) = email.as_deref() else {
                return Ok(OrgMoveOut::BadCode);
            };
            self.take_org_quota(&tx, &q, e, now_ms)?;
        }
        if !self.use_setup_code_in(
            &tx,
            setup_code_hash,
            allowed_email,
            email.as_deref(),
            now_ms,
        )? {
            return Ok(OrgMoveOut::BadCode);
        }
        tx.execute(
            "INSERT INTO orgs(org_id, name, admin, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![id, name, me, now_ms],
        )?;
        tx.execute(
            "INSERT INTO org_admins(org_id, user) VALUES (?1, ?2)",
            params![id, me],
        )?;
        let Some(old) = move_personal_to_org_in(&tx, me, id, None, now_ms)? else {
            return Ok(OrgMoveOut::NotPersonal);
        };
        tx.commit()?;
        Ok(OrgMoveOut::Moved(old, id.to_owned()))
    }

    /// #845 §7-56 음소거 넣기·바꾸기·풀기. `until` = `None` 이면 풂, `Some(None)` 계속, `Some(Some(ms))` 그때까지. 지난 줄은
    /// 먼저 지운다. 돌려주는 값: 바뀌었나(`Some(bool)`), 새 대화가 `max` 를 넘으면 `None`(아무것도 안 함).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mute_set(
        &self,
        user: &str,
        conv: &str,
        until: Option<Option<i64>>,
        now_ms: i64,
        max: i64,
    ) -> Result<Option<bool>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM mutes WHERE user = ?1 AND until_ms IS NOT NULL AND until_ms <= ?2",
            params![user, now_ms],
        )?;
        let old: Option<Option<i64>> = tx
            .query_row(
                "SELECT until_ms FROM mutes WHERE user = ?1 AND conv = ?2",
                params![user, conv],
                |r| r.get(0),
            )
            .optional()?;
        let changed = match (old, until) {
            (None, None) => false,
            (Some(_), None) => {
                tx.execute(
                    "DELETE FROM mutes WHERE user = ?1 AND conv = ?2",
                    params![user, conv],
                )?;
                true
            }
            (Some(o), Some(u)) if o == u => false,
            (old, Some(u)) => {
                if old.is_none() {
                    let n: i64 =
                        tx.query_row("SELECT COUNT(*) FROM mutes WHERE user = ?1", [user], |r| {
                            r.get(0)
                        })?;
                    if n >= max {
                        return Ok(None);
                    }
                }
                tx.execute(
                    "INSERT INTO mutes(user, conv, until_ms) VALUES (?1, ?2, ?3)
                     ON CONFLICT(user, conv) DO UPDATE SET until_ms = excluded.until_ms",
                    params![user, conv, u],
                )?;
                true
            }
        };
        tx.commit()?;
        Ok(Some(changed))
    }

    /// #880 고정 한 동작: `index` 자리에 넣기(이미 있으면 옮기기, 목록 길이로 자름), `None` 이면 풂. 나간 그룹의 줄은 먼저
    /// 지운다. 돌려주는 값: 바뀌었나(`Some(bool)`), 새 대화가 `max` 를 넘으면 `None`(아무것도 안 함).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pin_set(
        &self,
        user: &str,
        conv: &str,
        index: Option<usize>,
        max: usize,
    ) -> Result<Option<bool>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            &format!("DELETE FROM pins WHERE user = ?1 AND NOT ({PIN_LIVE})"),
            [user],
        )?;
        let old: Vec<String> = {
            let mut st = tx.prepare("SELECT conv FROM pins WHERE user = ?1 ORDER BY pos")?;
            let rows = st.query_map([user], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut new: Vec<String> = old.iter().filter(|c| *c != conv).cloned().collect();
        if let Some(i) = index {
            if new.len() == old.len() && new.len() >= max {
                return Ok(None);
            }
            new.insert(i.min(new.len()), conv.to_owned());
        }
        if new == old {
            return Ok(Some(false));
        }
        tx.execute("DELETE FROM pins WHERE user = ?1", [user])?;
        for (pos, c) in new.iter().enumerate() {
            tx.execute(
                "INSERT INTO pins(user, conv, pos) VALUES (?1, ?2, ?3)",
                params![user, c, i64::try_from(pos).unwrap_or(0)],
            )?;
        }
        tx.commit()?;
        Ok(Some(true))
    }

    /// #880 내 고정 목록(위에서부터). 나간 그룹의 줄은 빼고 돌려준다(지우는 것은 다음 `pin_set`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pins_of(&self, user: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT conv FROM pins WHERE user = ?1 AND {PIN_LIVE} ORDER BY pos"
        ))?;
        let rows = st.query_map([user], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 §7-56 내 음소거 목록(지난 것 빼고, 대화 순).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mutes_of(&self, user: &str, now_ms: i64) -> Result<Vec<(String, Option<i64>)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT conv, until_ms FROM mutes WHERE user = ?1 AND (until_ms IS NULL OR until_ms > ?2) ORDER BY conv",
        )?;
        let rows = st
            .query_map(params![user, now_ms], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// #845 §7-56 이 기기의 사람이 이 대화를 지금 음소거했나(푸시 거름). 세션 주소(`아이디@서버/slug`)에서 온 글은 그 사람
    /// 주소(`아이디@서버`)를 음소거해도 걸린다 — 앱의 1:1 대화는 사람 단위라(그 사람의 세션 글이 한 대화에 모인다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_muted(&self, device_id: &str, conv: &str, now_ms: i64) -> Result<bool, DbError> {
        let person = conv.split('/').next().unwrap_or(conv);
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM mutes m JOIN devices d ON d.user = m.user
               WHERE d.device_id = ?1 AND m.conv IN (?2, ?4) AND (m.until_ms IS NULL OR m.until_ms > ?3))",
            params![device_id, conv, now_ms, person],
            |r| r.get(0),
        )?)
    }

    /// #845 ④ `group.invite`(§7-2·§7-12): 그 그룹의 지금 멤버 누구나. 대상이
    /// - 지금 멤버·나·막힌 사이·이미 초대된 사람이면 일 없음
    /// - 나와 닿으면(같은 조직·연락처) 바로 '들어가는 중'(카드 없음, 셈 없음)
    /// - 가입했으면 카드(연락 요청 셈에 넣음, 수락되면 돌려줌)
    /// - 가입 안 한 이메일이면 그 이메일 줄(메일은 ⑤, 셈에 넣음).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn group_invite(
        &self,
        me: &str,
        gid: &str,
        to: LinkTarget<'_>,
        shown: &str,
        id: &str,
        now_ms: i64,
    ) -> Result<GroupInviteOut, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let member = |u: &str| -> Result<bool, DbError> {
            Ok(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = ?2 AND left_seq IS NULL)",
                params![gid, u],
                |r| r.get(0),
            )?)
        };
        if !member(me)? {
            return Ok(GroupInviteOut::Refused);
        }
        // §7-26: 보낸 기록은 나·이미 멤버 말고는 늘 한 줄(막힘·중복·없는 아이디도 — 받는 쪽 사정을 드러내지 않게).
        let sent = |tx: &rusqlite::Transaction<'_>,
                    tu: Option<&str>,
                    te: Option<&str>,
                    r: Option<&str>,
                    joined: bool|
         -> Result<(), DbError> {
            sent_in(tx, id, "group", gid, me, shown, tu, te, r, now_ms, joined)
        };
        let target: Option<String> = match to {
            LinkTarget::User(u) => tx
                .query_row(
                    "SELECT user FROM users WHERE user = ?1 AND removed_ms IS NULL",
                    [u],
                    |r| r.get(0),
                )
                .optional()?,
            LinkTarget::Email(e) => tx
                .query_row(
                    "SELECT user FROM users WHERE email = ?1 AND removed_ms IS NULL",
                    [e],
                    |r| r.get(0),
                )
                .optional()?,
        };
        let email = match to {
            LinkTarget::Email(e) => Some(e),
            LinkTarget::User(_) => None,
        };
        let since = now_ms - LINK_EXPIRE_MS;
        let mut out = GroupInviteOut::Sent {
            card: None,
            joining: false,
        };
        match target {
            None => {
                if let Some(e) = email {
                    let dup: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM group_invites WHERE gid = ?1 AND email = ?2 AND user IS NULL AND at_ms > ?3)",
                        params![gid, e, since],
                        |r| r.get(0),
                    )?;
                    if dup {
                        sent(&tx, None, Some(e), None, false)?;
                    } else {
                        if let Some(until_ms) = link_limit(&tx, me, now_ms)? {
                            return Ok(GroupInviteOut::RateLimited { until_ms });
                        }
                        link_charge(&tx, me, now_ms)?;
                        tx.execute(
                            "INSERT INTO group_invites(id, gid, email, by, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![id, gid, e, me, now_ms],
                        )?;
                        mail_enqueue_in(&tx, "group", id, e, me, None, now_ms)?;
                        sent(&tx, None, Some(e), Some(id), false)?;
                    }
                } else {
                    sent(&tx, None, None, None, false)?;
                }
            }
            Some(t) => {
                if t == me || member(&t)? {
                    return Ok(out);
                }
                let blocked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM blocks WHERE (user = ?1 AND blocked = ?2) OR (user = ?2 AND blocked = ?1))",
                    params![me, t],
                    |r| r.get(0),
                )?;
                let dup: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM group_invites WHERE gid = ?1 AND user = ?2 AND at_ms > ?3)",
                    params![gid, t, since],
                    |r| r.get(0),
                )?;
                let reach: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM users ua, users ub
                                     WHERE ua.user = ?1 AND ub.user = ?2 AND (ub.suspended_ms IS NULL OR ub.suspended_until <= ?3) AND ua.org = ub.org)
                            OR EXISTS(SELECT 1 FROM links l JOIN users ub ON ub.user = l.peer
                                     WHERE l.user = ?1 AND l.peer = ?2 AND l.state = 'accepted' AND (ub.suspended_ms IS NULL OR ub.suspended_until <= ?3))",
                    params![me, t, now_ms],
                    |r| r.get(0),
                )?;
                // §7-30: 막힌 사이는 group_invites 줄을 넣지 않으니 거듭 보냄은 내 보낸 기록으로 본다 — 카드 갈래의 dup 과 같게.
                let dup = dup
                    || (blocked
                        && tx.query_row(
                            "SELECT EXISTS(SELECT 1 FROM invites_sent WHERE kind = 'group' AND scope = ?1 AND by = ?2
                                             AND target_user = ?3 AND at_ms > ?4)",
                            params![gid, me, t, since],
                            |r| r.get::<_, bool>(0),
                        )?);
                if blocked && !dup {
                    // §7-30: 막힌 사이도 카드 갈래와 같게 상한을 보고 센다 — 상한 끝에서 갈래가 갈리면 막힘이 샌다.
                    if let Some(until_ms) = link_limit(&tx, me, now_ms)? {
                        return Ok(GroupInviteOut::RateLimited { until_ms });
                    }
                    link_charge(&tx, me, now_ms)?;
                    sent(&tx, Some(&t), email, None, false)?;
                } else if dup {
                    sent(&tx, Some(&t), email, None, false)?;
                } else if reach {
                    tx.execute(
                        "INSERT INTO group_invites(id, gid, user, by, at_ms, accepted_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        params![id, gid, t, me, now_ms],
                    )?;
                    // 닿는 사람은 바로 '들어가는 중' — 보낸 기록엔 들어온 것으로(행 대신 joining 이 보인다).
                    sent(&tx, Some(&t), email, Some(id), true)?;
                    out = GroupInviteOut::Sent {
                        card: None,
                        joining: true,
                    };
                } else {
                    if let Some(until_ms) = link_limit(&tx, me, now_ms)? {
                        return Ok(GroupInviteOut::RateLimited { until_ms });
                    }
                    link_charge(&tx, me, now_ms)?;
                    tx.execute(
                        "INSERT INTO group_invites(id, gid, user, by, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, gid, t, me, now_ms],
                    )?;
                    sent(&tx, Some(&t), email, Some(id), false)?;
                    out = GroupInviteOut::Sent {
                        card: Some(t),
                        joining: false,
                    };
                }
            }
        }
        tx.commit()?;
        Ok(out)
    }

    /// #845 §7-26 디렉터리 `org_invites_sent`: 그 조직 관리자에게 — 만료 전·아직 안 들어온 보낸 초대 (id, 친 글자, 보낸 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_invites_sent_of(
        &self,
        user: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT s.id, s.shown, s.at_ms FROM invites_sent s
             JOIN users me ON me.user = ?1 AND me.removed_ms IS NULL
             JOIN org_admins a ON a.org_id = me.org AND a.user = ?1
             WHERE s.kind = 'org' AND s.scope = me.org AND s.joined_ms IS NULL AND s.at_ms > ?2
             ORDER BY s.at_ms DESC",
        )?;
        let rows = st.query_map(params![user, now_ms - ORG_INVITE_TTL_MS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 §7-26 디렉터리 `group_invites_sent`: 내가 보낸 그룹 초대(보낸 사람 본인에게만) (id, 그룹, 친 글자, 보낸 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_invites_sent_of(
        &self,
        user: &str,
        now_ms: i64,
    ) -> Result<Vec<(String, String, String, i64)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT id, scope, shown, at_ms FROM invites_sent
             WHERE kind = 'group' AND by = ?1 AND joined_ms IS NULL AND at_ms > ?2
             ORDER BY at_ms DESC",
        )?;
        let rows = st.query_map(params![user, now_ms - LINK_EXPIRE_MS], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 §7-26 그 조직 관리자(보낸 기록이 바뀌면 디렉터리 다시).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_admins_of(&self, org: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare("SELECT user FROM org_admins WHERE org_id = ?1 ORDER BY user")?;
        let rows = st.query_map([org], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 §7-26 `org.invite.withdraw{id}`(그 조직 관리자 누구나): 보낸 줄·받는 쪽 카드·안 간 메일을 없앤다. 셈은 그대로(카드는
    /// 답한 것으로, 메일 초대는 기한을 지금으로). 돌려주는 값: 거뒀으면 (조직, 카드가 있던 사람).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_invite_withdraw(
        &self,
        admin: &str,
        id: &str,
        now_ms: i64,
    ) -> Result<Option<(String, Option<String>)>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(org) = Self::admin_org(&tx, admin)? else {
            return Ok(None);
        };
        let row: Option<(Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT recv_ref, target_user FROM invites_sent
                 WHERE id = ?1 AND kind = 'org' AND scope = ?2 AND joined_ms IS NULL",
                params![id, org],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((recv, target)) = row else {
            return Ok(None);
        };
        if let Some(r) = &recv {
            tx.execute("UPDATE org_invites SET done = 1 WHERE id = ?1", [r])?;
            if let Ok(h) = lodelai_crypto::encoding::decode(r, "invite") {
                tx.execute(
                    "UPDATE invites SET expires_ms = ?2 WHERE token_hash = ?1 AND expires_ms > ?2",
                    params![h, now_ms],
                )?;
            }
            tx.execute("DELETE FROM mail_jobs WHERE id = ?1", [format!("org:{r}")])?;
        }
        tx.execute("DELETE FROM invites_sent WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(Some((org, target)))
    }

    /// #845 §7-26 `group.invite.withdraw{id}`(보낸 사람만): 보낸 줄·받는 쪽 카드·안 간 메일을 없앤다. 이미 수락해 '들어가는
    /// 중'이면 거두지 않는다. 하루 셈은 돌려주지 않는다. 돌려주는 값: 거뒀으면 카드가 있던 사람.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_invite_withdraw(
        &self,
        me: &str,
        id: &str,
    ) -> Result<Option<(String, Option<String>)>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(Option<String>, Option<String>, String)> = tx
            .query_row(
                "SELECT recv_ref, target_user, scope FROM invites_sent
                 WHERE id = ?1 AND kind = 'group' AND by = ?2 AND joined_ms IS NULL",
                params![id, me],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((recv, target, gid)) = row else {
            return Ok(None);
        };
        if let Some(r) = &recv {
            let accepted: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM group_invites WHERE id = ?1 AND accepted_ms IS NOT NULL)",
                [r],
                |row| row.get(0),
            )?;
            if accepted {
                return Ok(None);
            }
            tx.execute("DELETE FROM group_invites WHERE id = ?1", [r])?;
            tx.execute(
                "DELETE FROM mail_jobs WHERE id = ?1",
                [format!("group:{r}")],
            )?;
        }
        tx.execute("DELETE FROM invites_sent WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(Some((gid, target)))
    }

    /// #845 ④ `group.invite.answer`. 거절은 줄을 지운다(조용). 수락은 초대한 사람과 연락처(양쪽 accepted)를 만들고 셈을
    /// 돌려준 뒤 '들어가는 중'으로 둔다 — 멤버 기기가 add 한다. 돌려주는 값: 바뀌었으면 (그룹, 초대한 사람, 수락했나).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_invite_answer(
        &self,
        me: &str,
        id: &str,
        accept: bool,
        now_ms: i64,
    ) -> Result<Option<(String, String, bool)>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(String, String, i64)> = tx
            .query_row(
                "SELECT gid, by, at_ms FROM group_invites
                 WHERE id = ?1 AND user = ?2 AND accepted_ms IS NULL AND at_ms > ?3",
                params![id, me, now_ms - LINK_EXPIRE_MS],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((gid, by, at)) = row else {
            return Ok(None);
        };
        let blocked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE (user = ?1 AND blocked = ?2) OR (user = ?2 AND blocked = ?1))",
            params![me, by],
            |r| r.get(0),
        )?;
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND left_seq IS NULL)",
            [&gid],
            |r| r.get(0),
        )?;
        if !accept || blocked || !live {
            tx.execute("DELETE FROM group_invites WHERE id = ?1", [id])?;
            tx.commit()?;
            return Ok(Some((gid, by, false)));
        }
        let same_org: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users a, users b WHERE a.user = ?1 AND b.user = ?2 AND a.org = b.org)",
            params![me, by],
            |r| r.get(0),
        )?;
        if !same_org {
            for (u, p) in [(me, by.as_str()), (by.as_str(), me)] {
                tx.execute(
                    "INSERT INTO links(user, peer, state, requested_ms, accepted_ms) VALUES (?1, ?2, 'accepted', ?3, ?3)
                     ON CONFLICT(user, peer) DO UPDATE SET state = 'accepted', accepted_ms = ?3",
                    params![u, p, now_ms],
                )?;
            }
        }
        link_refund(&tx, &by, at, now_ms)?;
        tx.execute(
            "UPDATE group_invites SET accepted_ms = ?2 WHERE id = ?1",
            params![id, now_ms],
        )?;
        tx.execute(
            "UPDATE invites_sent SET joined_ms = ?2 WHERE kind = 'group' AND recv_ref = ?1",
            params![id, now_ms],
        )?;
        tx.commit()?;
        Ok(Some((gid, by, true)))
    }

    /// #845 ④ 디렉터리 `group_invites`: 받은 그룹 초대(만료 전, 수락 뒤 add 기다림은 joining).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_invites_of(
        &self,
        user: &str,
        now_ms: i64,
    ) -> Result<Vec<GroupInviteCard>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT i.id, i.gid, i.by, b.display, i.at_ms, i.accepted_ms IS NOT NULL
             FROM group_invites i LEFT JOIN users b ON b.user = i.by
             WHERE i.user = ?1 AND i.at_ms > ?2 ORDER BY i.at_ms DESC",
        )?;
        let since = now_ms - LINK_EXPIRE_MS;
        let rows = st.query_map(params![user, since], |r| {
            Ok(GroupInviteCard {
                id: r.get(0)?,
                gid: r.get(1)?,
                by: r.get(2)?,
                by_display: r.get(3)?,
                at_ms: r.get(4)?,
                members: 0,
                joining: r.get(5)?,
            })
        })?;
        let mut cards: Vec<GroupInviteCard> = rows.collect::<Result<_, _>>()?;
        for card in &mut cards {
            card.members = group_card_members_in(&c, &card.id, since)?;
        }
        Ok(cards)
    }

    /// #845 ④ 디렉터리 `group_members`: 내 그룹들의 지금 멤버 중 나와 닿지 않는 사람(같은 조직도 연락처도 아님) — (아이디,
    /// 표시 이름).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_strangers(&self, user: &str) -> Result<Vec<(String, Option<String>)>, DbError> {
        let c = self.c();
        // §7-25: 잎 검증에 쓰는 키 — 내 그룹의 지금 멤버 + 수락한 joining 사람, 내가 수락한 joining 인 그룹의 지금 멤버.
        // 수락 전 카드인 사람은 넣지 않는다(동의 전엔 드러내지 않음).
        let mut st = c.prepare(
            "WITH my_groups(gid) AS (
               SELECT gid FROM group_members WHERE user = ?1 AND left_seq IS NULL
               UNION SELECT gid FROM group_invites WHERE user = ?1 AND accepted_ms IS NOT NULL
             ),
             people(user) AS (
               SELECT m.user FROM group_members m JOIN my_groups g ON g.gid = m.gid WHERE m.left_seq IS NULL
               UNION SELECT i.user FROM group_invites i JOIN my_groups g ON g.gid = i.gid
                 WHERE i.user IS NOT NULL AND i.accepted_ms IS NOT NULL
             )
             SELECT p.user, u.display FROM people p
             JOIN users u ON u.user = p.user AND u.removed_ms IS NULL
             JOIN users me ON me.user = ?1
             WHERE p.user <> ?1 AND u.org <> me.org
               AND NOT EXISTS(SELECT 1 FROM links l WHERE l.user = ?1 AND l.peer = p.user AND l.state = 'accepted')
             ORDER BY p.user",
        )?;
        let rows = st.query_map([user], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 §7-25 그 그룹의 지금 멤버와 수락한 joining 사람(키가 바뀌는 사람 — directory.update 를 groups 보다 먼저).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_circle(&self, gid: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user FROM group_members WHERE gid = ?1 AND left_seq IS NULL
             UNION SELECT user FROM group_invites WHERE gid = ?1 AND user IS NOT NULL AND accepted_ms IS NOT NULL
             ORDER BY 1",
        )?;
        let rows = st.query_map([gid], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 ④ KP 가져가기 좁은 예외(§7-12 4): `claimant` 가 그룹의 지금 멤버이고 `owner` 가 그 그룹 '들어가는 중'이다.
    #[must_use]
    pub fn joining_claim_ok(&self, claimant: &str, owner: &str) -> bool {
        self.c()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM group_invites i JOIN group_members m
                                 ON m.gid = i.gid AND m.user = ?1 AND m.left_seq IS NULL
                               WHERE i.user = ?2 AND i.accepted_ms IS NOT NULL)",
                params![claimant, owner],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }

    /// #845 §7-44 ② 그 그룹의 살아 있는 대기 초대(아이디, 아직 수락 안 함)를 받은 사람 — 멤버 수가 바뀌면 카드를 다시 보낸다.
    /// 많아도 `GROUP_MAX_MEMBERS - 1` 까지.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_invitees_pending(&self, gid: &str, now_ms: i64) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT DISTINCT user FROM group_invites
             WHERE gid = ?1 AND user IS NOT NULL AND accepted_ms IS NULL AND at_ms > ?2
             ORDER BY user LIMIT ?3",
        )?;
        let rows = st.query_map(
            params![
                gid,
                now_ms - LINK_EXPIRE_MS,
                i64::try_from(lodelai_protocol::constants::GROUP_MAX_MEMBERS - 1)
                    .unwrap_or(i64::MAX)
            ],
            |r| r.get(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 ④ 그 그룹의 지금 멤버(groups 프레임을 다시 보낼 사람).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_members_now(&self, gid: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user FROM group_members WHERE gid = ?1 AND left_seq IS NULL ORDER BY user",
        )?;
        let rows = st.query_map([gid], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 ⑤ 운영 멈춤(`lodelai-relay suspend`). `until_ms` 가 없으면 풀 때까지. 그 사람이 보낼 대기 메일(가입 안 한 이메일 앞
    /// 연락 요청·그룹 초대)은 지운다(정책 §1). 돌려주는 값: 그런 사람이 있었나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn suspend(&self, user: &str, until_ms: Option<i64>, now_ms: i64) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let n = tx.execute(
            "UPDATE users SET suspended_ms = ?2, suspended_until = ?3 WHERE user = ?1 AND removed_ms IS NULL",
            params![user, now_ms, until_ms],
        )?;
        if n == 1 {
            tx.execute(
                "DELETE FROM link_invites WHERE requester = ?1 AND sent_ms IS NULL",
                [user],
            )?;
            tx.execute(
                "DELETE FROM group_invites WHERE by = ?1 AND user IS NULL",
                [user],
            )?;
        }
        tx.commit()?;
        Ok(n == 1)
    }

    /// #845 ⑤ 멈춤 풀기. 돌려주는 값: 멈춰 있었나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unsuspend(&self, user: &str) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE users SET suspended_ms = NULL, suspended_until = NULL WHERE user = ?1 AND suspended_ms IS NOT NULL",
            [user],
        )? == 1)
    }

    /// #845 ⑤ 지금 멈춰 있으면 `Some(풀리는 때)`(없으면 운영자가 풀 때까지). 기한이 지났으면 풀고 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn suspended(&self, user: &str, now_ms: i64) -> Result<Option<Option<i64>>, DbError> {
        let row: Option<Option<i64>> = self
            .c()
            .query_row(
                "SELECT suspended_until FROM users WHERE user = ?1 AND suspended_ms IS NOT NULL",
                [user],
                |r| r.get(0),
            )
            .optional()?;
        match row {
            Some(Some(until)) if until <= now_ms => {
                self.unsuspend(user)?;
                Ok(None)
            }
            other => Ok(other),
        }
    }

    /// #845 ⑤ 지금 멈춘 사람과 풀리는 때(틱 — 기한 지난 것은 [`Db::suspend_sweep`] 이 먼저 푼다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn suspended_users(&self) -> Result<Vec<(String, Option<i64>)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user, suspended_until FROM users WHERE suspended_ms IS NOT NULL AND removed_ms IS NULL",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #845 ⑤ 기한이 지난 멈춤을 푼다(틱).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn suspend_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "UPDATE users SET suspended_ms = NULL, suspended_until = NULL
             WHERE suspended_ms IS NOT NULL AND suspended_until IS NOT NULL AND suspended_until <= ?1",
            [now_ms],
        )?)
    }

    /// #845 ⑤(§7-3) 새 이메일로 코드를 맞힌 뒤: 그 이메일 앞 걸린 초대(조직 메일 초대·그룹 메일 초대·연락 요청, 만료·멈춤·나간
    /// 사람 뺌, [`SIGNUP_PENDING_MAX`] 까지)를 이 가입 토큰에 묶은 일회 id 로 돌려준다. 초대한 사람의 이메일은 싣지 않는다.
    /// `ids` 는 호출자가 만든 ULID([`SIGNUP_PENDING_MAX`] 개).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn signup_pending(
        &self,
        email: &str,
        token_hash: &[u8],
        now_ms: i64,
        ids: &[String],
    ) -> Result<Vec<PendingCard>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM signup_pending WHERE token_hash NOT IN (SELECT token_hash FROM signup_tokens)",
            [],
        )?;
        let since = now_ms - LINK_EXPIRE_MS;
        // (kind, ref, from_name, space_name)
        let mut rows: Vec<(&'static str, String, String, Option<String>)> = Vec::new();
        {
            let mut st = tx.prepare(
                "SELECT i.token_hash, COALESCE(u.display, i.created_by), o.name FROM invites i
                 JOIN orgs o ON o.org_id = i.org_id
                 JOIN users u ON u.user = i.created_by AND u.removed_ms IS NULL AND (u.suspended_ms IS NULL OR u.suspended_until <= ?2)
                 WHERE i.email = ?1 AND i.expires_ms > ?2 ORDER BY i.created_ms DESC",
            )?;
            let r = st.query_map(params![email, now_ms], |r| {
                Ok((
                    lodelai_crypto::encoding::encode(&r.get::<_, Vec<u8>>(0)?),
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for x in r {
                let (h, from, org) = x?;
                rows.push(("org", h, from, Some(org)));
            }
            let mut st = tx.prepare(
                "SELECT g.id, COALESCE(b.display, g.by) FROM group_invites g
                 JOIN users b ON b.user = g.by AND b.removed_ms IS NULL AND (b.suspended_ms IS NULL OR b.suspended_until <= ?3)
                 WHERE g.email = ?1 AND g.user IS NULL AND g.at_ms > ?2 ORDER BY g.at_ms DESC",
            )?;
            let r = st.query_map(params![email, since, now_ms], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            for x in r {
                let (id, from) = x?;
                rows.push(("group", id, from, None));
            }
            if let Some(key) = self.email_key.get() {
                let mut st = tx.prepare(
                    "SELECT l.id, COALESCE(r.display, l.requester) FROM link_invites l
                     JOIN users r ON r.user = l.requester AND r.removed_ms IS NULL AND (r.suspended_ms IS NULL OR r.suspended_until <= ?3)
                     WHERE l.email_mac = ?1 AND l.at_ms > ?2 ORDER BY l.at_ms DESC",
                )?;
                let r = st.query_map(params![email_mac(key, email), since, now_ms], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?;
                for x in r {
                    let (id, from) = x?;
                    rows.push(("contact", id, from, None));
                }
            }
        }
        let mut out = Vec::new();
        for ((kind, r, from, space), id) in rows.into_iter().zip(ids).take(SIGNUP_PENDING_MAX) {
            tx.execute(
                "INSERT INTO signup_pending(token_hash, id, kind, ref) VALUES (?1, ?2, ?3, ?4)",
                params![token_hash, id, kind, r],
            )?;
            out.push(PendingCard {
                id: id.clone(),
                kind,
                from_name: from,
                space_name: space,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    /// #845 ⑤(§7-3·§7-18 4) 새 계정의 이메일 앞 걸린 초대를 옮긴다. 같이 받은 것: 연락 요청 → 양쪽 accepted(셈 돌려줌), 그룹
    /// 초대 → '들어가는 중'(초대한 사람과 연락처). 고르지 않은 것: 연락 요청 → 받은 요청 카드(요청한 사람 쪽 표시 글자 그대로),
    /// 그룹 메일 초대 → 카드, 조직 메일 초대 → org_invites 카드. 돌려주는 값: (디렉터리를 다시 받을 사람, '들어가는 중' 그룹).
    #[allow(clippy::too_many_arguments)]
    fn adopt_email_invites(
        &self,
        tx: &rusqlite::Transaction<'_>,
        u: &str,
        email: &str,
        picked_contacts: &[String],
        picked_groups: &[String],
        card_ids: &[String],
        now_ms: i64,
    ) -> Result<(Vec<String>, Vec<String>), DbError> {
        let since = now_ms - LINK_EXPIRE_MS;
        let mut notify: Vec<String> = Vec::new();
        let mut groups: Vec<String> = Vec::new();
        let accept_link = |a: &str, b: &str| -> Result<(), DbError> {
            let same: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users x, users y WHERE x.user = ?1 AND y.user = ?2 AND x.org = y.org)",
                params![a, b],
                |r| r.get(0),
            )?;
            if !same {
                for (p, q) in [(a, b), (b, a)] {
                    tx.execute(
                        "INSERT INTO links(user, peer, state, requested_ms, accepted_ms) VALUES (?1, ?2, 'accepted', ?3, ?3)
                         ON CONFLICT(user, peer) DO UPDATE SET state = 'accepted', accepted_ms = ?3",
                        params![p, q, now_ms],
                    )?;
                }
            }
            Ok(())
        };
        if let Some(key) = self.email_key.get() {
            let mac = email_mac(key, email);
            let rows: Vec<(String, String, String, i64)> = {
                let mut st = tx.prepare(
                    "SELECT l.id, l.requester, l.email_shown, l.at_ms FROM link_invites l
                     JOIN users r ON r.user = l.requester AND r.removed_ms IS NULL
                     WHERE l.email_mac = ?1 AND l.at_ms > ?2",
                )?;
                let r = st.query_map(params![mac, since], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?;
                r.collect::<Result<_, _>>()?
            };
            for (id, requester, shown, at) in rows {
                if requester == u {
                    continue;
                }
                if picked_contacts.contains(&id) {
                    accept_link(&requester, u)?;
                    link_refund(tx, &requester, at, now_ms)?;
                } else {
                    tx.execute(
                        "INSERT OR IGNORE INTO links(user, peer, state, requested_ms, id, shown)
                         VALUES (?1, ?2, 'requested', ?3, ?4, ?5)",
                        params![requester, u, at, id, shown],
                    )?;
                }
                notify.push(requester);
            }
            tx.execute("DELETE FROM link_invites WHERE email_mac = ?1", [mac])?;
        }
        let rows: Vec<(String, String, String, i64)> = {
            let mut st = tx.prepare(
                "SELECT id, gid, by, at_ms FROM group_invites WHERE email = ?1 AND user IS NULL AND at_ms > ?2",
            )?;
            let r = st.query_map(params![email, since], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            r.collect::<Result<_, _>>()?
        };
        for (id, gid, by, at) in rows {
            let picked = picked_groups.contains(&id);
            tx.execute(
                "UPDATE group_invites SET user = ?2, email = NULL, accepted_ms = ?3 WHERE id = ?1",
                params![id, u, picked.then_some(now_ms)],
            )?;
            tx.execute(
                "UPDATE invites_sent SET target_user = ?2, joined_ms = ?3 WHERE kind = 'group' AND recv_ref = ?1",
                params![id, u, picked.then_some(now_ms)],
            )?;
            if picked {
                accept_link(&by, u)?;
                link_refund(tx, &by, at, now_ms)?;
                groups.push(gid);
            }
            notify.push(by);
        }
        let rows: Vec<(Vec<u8>, String, String, i64)> = {
            let mut st = tx.prepare(
                "SELECT token_hash, org_id, created_by, created_ms FROM invites WHERE email = ?1 AND expires_ms > ?2",
            )?;
            let r = st.query_map(params![email, now_ms], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?;
            r.collect::<Result<_, _>>()?
        };
        for ((h, org, by, at), id) in rows.into_iter().zip(card_ids) {
            tx.execute(
                "INSERT INTO org_invites(id, org_id, user, by, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, org, u, by, at],
            )?;
            tx.execute(
                "UPDATE invites_sent SET recv_ref = ?2, target_user = ?3 WHERE recv_ref = ?1",
                params![lodelai_crypto::encoding::encode(&h), id, u],
            )?;
            tx.execute("DELETE FROM invites WHERE token_hash = ?1", [h])?;
        }
        notify.sort();
        notify.dedup();
        groups.sort();
        groups.dedup();
        Ok((notify, groups))
    }

    /// #845 ⑤ 지금 보낼 초대 메일을 고른다(틱). 가리키는 줄이 사라졌거나(거둠·가입해 옮김·만료) 보낸 사람이 멈춤·나감이면
    /// 일을 버리고, 받지 않기 주소면 메일만 안 보내고 일을 끝낸다(줄·셈은 그대로). 상한에 걸리면 다음 UTC 날로 미룬다.
    /// 고른 것은 상한 셈에 넣은 것으로 친다 — 보낸 뒤 [`Db::invite_mail_sent`], 실패면 [`Db::invite_mail_failed`].
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_mail_take(
        &self,
        now_ms: i64,
        l: &MailLimits,
    ) -> Result<Vec<MailToSend>, DbError> {
        let Some(key) = self.email_key.get() else {
            return Ok(Vec::new());
        };
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM mail_jobs WHERE at_ms <= ?1 OR tries >= ?2",
            params![now_ms - LINK_EXPIRE_MS, MAIL_MAX_TRIES],
        )?;
        tx.execute(
            "DELETE FROM mail_log WHERE at_ms <= ?1",
            [now_ms - LINK_EXPIRE_MS],
        )?;
        let jobs: Vec<(String, String, String, String, String, Option<String>)> = {
            let mut st = tx.prepare(
                "SELECT id, kind, ref, email, sender, org_id FROM mail_jobs WHERE after_ms <= ?1
                 ORDER BY after_ms, at_ms LIMIT ?2",
            )?;
            let r = st.query_map(params![now_ms, MAIL_PER_TICK as i64 * 5], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?;
            r.collect::<Result<_, _>>()?
        };
        let day = now_ms.div_euclid(DAY_MS) * DAY_MS;
        let next_day = day + DAY_MS;
        let count = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Result<i64, DbError> {
            Ok(tx.query_row(sql, p, |r| r.get(0))?)
        };
        let mut out: Vec<MailToSend> = Vec::new();
        for (job, kind, r, email, sender, org_id) in jobs {
            if out.len() >= MAIL_PER_TICK {
                break;
            }
            let alive: bool = match kind.as_str() {
                "contact" => count(
                    "SELECT EXISTS(SELECT 1 FROM link_invites WHERE id = ?1)",
                    &[&r],
                )? == 1,
                "group" => count(
                    "SELECT EXISTS(SELECT 1 FROM group_invites WHERE id = ?1 AND user IS NULL)",
                    &[&r],
                )? == 1,
                _ => match lodelai_crypto::encoding::decode(&r, "invite") {
                    Ok(h) => count(
                        "SELECT EXISTS(SELECT 1 FROM invites WHERE token_hash = ?1 AND expires_ms > ?2)",
                        &[&h, &now_ms],
                    )? == 1,
                    Err(_) => false,
                },
            };
            let who: Option<(Option<String>, Option<String>)> = tx
                .query_row(
                    "SELECT display, email FROM users WHERE user = ?1 AND removed_ms IS NULL
                       AND (suspended_ms IS NULL OR suspended_until <= ?2)",
                    params![&sender, now_ms],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            // §7-30: 확인된 이메일이 없는 보낸 사람은 메일을 보내지 않는다(이름만이면 사칭 통로) — 줄·셈·카드·답은 그대로.
            let (Some((display, Some(sender_email))), true) = (who, alive) else {
                tx.execute("DELETE FROM mail_jobs WHERE id = ?1", [&job])?;
                continue;
            };
            let mac = email_mac(key, &email);
            if count(
                "SELECT EXISTS(SELECT 1 FROM mail_blocks WHERE email_mac = ?1)",
                &[&mac],
            )? == 1
            {
                tx.execute("DELETE FROM mail_jobs WHERE id = ?1", [&job])?;
                continue;
            }
            let taken =
                |f: &dyn Fn(&MailToSend) -> bool| out.iter().filter(|m| f(m)).count() as i64;
            let global = count("SELECT COUNT(*) FROM mail_log WHERE at_ms >= ?1", &[&day])?
                + out.len() as i64;
            let address = count(
                "SELECT COUNT(*) FROM mail_log WHERE email_mac = ?1 AND at_ms > ?2",
                &[&mac, &(now_ms - LINK_EXPIRE_MS)],
            )? + taken(&|m| m.email_mac == mac);
            let own = if kind == "org" {
                count(
                    "SELECT COUNT(*) FROM mail_log WHERE kind = 'org' AND org_id = ?1 AND at_ms >= ?2",
                    &[&org_id, &day],
                )? + taken(&|m| m.kind == "org" && m.org_id == org_id)
                    >= l.org_per_day
            } else {
                count(
                    "SELECT COUNT(*) FROM mail_log WHERE kind <> 'org' AND sender = ?1 AND at_ms >= ?2",
                    &[&sender, &day],
                )? + taken(&|m| m.kind != "org" && m.sender == sender)
                    >= l.person_per_day
            };
            if global >= l.global_per_day || own {
                tx.execute(
                    "UPDATE mail_jobs SET after_ms = ?2 WHERE id = ?1",
                    params![job, next_day],
                )?;
                continue;
            }
            if address >= l.address_per_30d {
                // 같은 주소 30일 3통 — 이 초대의 메일은 보내지 않는다(줄은 그대로, 가입하면 앱 안에서 보인다).
                tx.execute("DELETE FROM mail_jobs WHERE id = ?1", [&job])?;
                continue;
            }
            let org_name: Option<String> = match &org_id {
                Some(o) => tx
                    .query_row("SELECT name FROM orgs WHERE org_id = ?1", [o], |r| r.get(0))
                    .optional()?,
                None => None,
            };
            let members: Option<i64> = if kind == "group" {
                Some(group_card_members_in(&tx, &r, now_ms - LINK_EXPIRE_MS)?)
            } else {
                None
            };
            out.push(MailToSend {
                members,
                job,
                from_name: display.unwrap_or_else(|| sender.clone()),
                from_email: sender_email,
                kind,
                to: email,
                email_mac: mac,
                sender,
                org_name,
                org_id,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    /// #845 ⑤ 보내지 않는 relay(초대 메일 끔·메일 설정 없음): 30일 지난 일만 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_mail_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM mail_jobs WHERE at_ms <= ?1",
            [now_ms - LINK_EXPIRE_MS],
        )?)
    }

    /// #845 ⑤ 초대 메일을 보냈다 — 일을 지우고 셈에 남긴다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_mail_sent(&self, m: &MailToSend, now_ms: i64) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute("DELETE FROM mail_jobs WHERE id = ?1", [&m.job])?;
        tx.execute(
            "INSERT INTO mail_log(email_mac, kind, sender, org_id, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.email_mac, m.kind, m.sender, m.org_id, now_ms],
        )?;
        if m.kind == "contact" {
            if let Some(r) = m.job.strip_prefix("contact:") {
                tx.execute(
                    "UPDATE link_invites SET sent_ms = ?2 WHERE id = ?1",
                    params![r, now_ms],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// #845 ⑤ 보내기 실패 — 한 시간 뒤 다시([`MAIL_MAX_TRIES`] 번까지).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invite_mail_failed(&self, job: &str, now_ms: i64) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE mail_jobs SET tries = tries + 1, after_ms = ?2 WHERE id = ?1",
            params![job, now_ms + 60 * 60 * 1000],
        )?;
        Ok(())
    }

    /// #845 ⑤ 받지 않기 토큰: base64url(email_mac) "." base64url(HMAC(email_key, 꼬리표 ‖ email_mac)). 기한 없음.
    #[must_use]
    pub fn mail_stop_token(&self, email: &str) -> Option<String> {
        use hmac::Mac;
        let key = self.email_key.get()?;
        let mac = email_mac(key, email);
        let mut h = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).ok()?;
        h.update(b"lodelai-mail-stop-v1\0");
        h.update(&mac);
        Some(format!(
            "{}.{}",
            lodelai_crypto::encoding::encode(&mac),
            lodelai_crypto::encoding::encode(&h.finalize().into_bytes())
        ))
    }

    /// #845 ⑤ 받지 않기 — 맞는 토큰이면 그 주소를 막음 표에. 틀린 토큰은 아무것도 안 한다(호출자는 같은 결과 페이지).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mail_stop(&self, token: &str, now_ms: i64) -> Result<bool, DbError> {
        use hmac::Mac;
        let Some(key) = self.email_key.get() else {
            return Ok(false);
        };
        let Some((m, sig)) = token.split_once('.') else {
            return Ok(false);
        };
        let (Ok(mac), Ok(sig)) = (
            lodelai_crypto::encoding::decode(m, "mail"),
            lodelai_crypto::encoding::decode(sig, "mail"),
        ) else {
            return Ok(false);
        };
        let Ok(mut h) = hmac::Hmac::<sha2::Sha256>::new_from_slice(key) else {
            return Ok(false);
        };
        h.update(b"lodelai-mail-stop-v1\0");
        h.update(&mac);
        if h.verify_slice(&sig).is_err() {
            return Ok(false);
        }
        self.c().execute(
            "INSERT OR IGNORE INTO mail_blocks(email_mac, at_ms) VALUES (?1, ?2)",
            params![mac, now_ms],
        )?;
        Ok(true)
    }

    /// #845 §7-23 `contact_link.preview`: 살아 있는 링크의 주인(나간 사람·다시 만든 옛 토큰은 `None`). 막힘은 보지 않는다 — 막힌
    /// 사이도 같은 답(드러내지 않음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn contact_link_owner(&self, token: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT l.user FROM contact_links l JOIN users u ON u.user = l.user
                 WHERE l.token_hash = ?1 AND l.revoked_ms IS NULL AND u.removed_ms IS NULL",
                [token_hash(token)],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// #845 ③ 남의 초대 링크로 연락처 맺기(셈 없음). 모르는·끝난 토큰·내 링크·어느 쪽이든 막힌 사이·이미 연락처면 `None`
    /// (답은 똑같이 link.sent — 열거 막기). 둘 사이 걸린 요청은 지우고(그날 것이면 셈을 돌려줌) 양쪽 accepted. 링크 주인을 돌려준다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_join(&self, me: &str, token: &str, now_ms: i64) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let owner: Option<String> = tx
            .query_row(
                "SELECT l.user FROM contact_links l JOIN users u ON u.user = l.user
                 WHERE l.token_hash = ?1 AND l.revoked_ms IS NULL AND u.removed_ms IS NULL",
                [token_hash(token)],
                |r| r.get(0),
            )
            .optional()?;
        let Some(owner) = owner.filter(|o| o != me) else {
            return Ok(None);
        };
        let blocked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE (user = ?1 AND blocked = ?2) OR (user = ?2 AND blocked = ?1))",
            params![me, owner],
            |r| r.get(0),
        )?;
        let linked: i64 = tx.query_row(
            "SELECT COUNT(*) FROM links WHERE ((user = ?1 AND peer = ?2) OR (user = ?2 AND peer = ?1)) AND state = 'accepted'",
            params![me, owner],
            |r| r.get(0),
        )?;
        if blocked || linked == 2 || closed_between_c(&tx, me, &owner)? {
            return Ok(None);
        }
        let pending: Vec<(String, i64)> = {
            let mut st = tx.prepare(
                "SELECT user, requested_ms FROM links
                 WHERE ((user = ?1 AND peer = ?2) OR (user = ?2 AND peer = ?1)) AND state != 'accepted'",
            )?;
            let rows = st.query_map(params![me, owner], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (requester, at) in &pending {
            link_refund(&tx, requester, *at, now_ms)?;
        }
        // #886 ⑧: 링크 주인 줄에만 via 'link'(디렉터리 links 항목 joined_my_link) — 들어온 쪽 줄은 NULL.
        for (a, b, via) in [
            (me, owner.as_str(), None),
            (owner.as_str(), me, Some("link")),
        ] {
            tx.execute(
                "INSERT INTO links(user, peer, state, requested_ms, accepted_ms, via) VALUES (?1, ?2, 'accepted', ?3, ?3, ?4)
                 ON CONFLICT(user, peer) DO UPDATE SET state = 'accepted', accepted_ms = ?3, via = ?4",
                params![a, b, now_ms, via],
            )?;
        }
        tx.commit()?;
        Ok(Some(owner))
    }

    /// 시험·관리용: 두 사람을 수락된 연락처로(양쪽 줄).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn link_accept(&self, a: &str, b: &str, now_ms: i64) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = c.transaction()?;
        for (u, p) in [(a, b), (b, a)] {
            tx.execute(
                "INSERT INTO links(user, peer, state, requested_ms, accepted_ms) VALUES (?1, ?2, 'accepted', ?3, ?3)
                 ON CONFLICT(user, peer) DO UPDATE SET state = 'accepted', accepted_ms = ?3",
                params![u, p, now_ms],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 관문 A6 `user` 가 막은 `other` 풀기 — 막음 줄만 지운다(연락처·요청은 만들지 않음). 지운 게 있으면 `true`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unblock(&self, user: &str, other: &str) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "DELETE FROM blocks WHERE user = ?1 AND blocked = ?2",
            params![user, other],
        )? > 0)
    }

    /// 시험·관리용.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn block(&self, user: &str, other: &str) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR IGNORE INTO blocks(user, blocked) VALUES (?1, ?2)",
            params![user, other],
        )?;
        Ok(())
    }

    /// `viewer` 가 초대해 들어온 같은 조직 사람들(M1 결함 ① — 디렉터리의 `invited_by_me`). 내보낸 사람은 빠진다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn invited_by(&self, viewer: &str) -> Result<std::collections::HashSet<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT u.user FROM users u JOIN users v ON v.user = ?1 AND v.org = u.org
             WHERE u.invited_by = ?1 AND u.removed_ms IS NULL",
        )?;
        let rows = st.query_map([viewer], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 이 사람이 접속 표시를 켜 두었나(묶음 14 B1 — 없는 사람은 거짓). 입력 중 표시(#613)도 같은 설정을 따른다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn share_presence(&self, user: &str) -> Result<bool, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT share_presence FROM users WHERE user = ?1",
                [user],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|v| v != 0))
    }

    /// 접속 표시 숨기기 설정(묶음 14 B1). 바뀌었으면 `true`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_share_presence(&self, user: &str, share: bool) -> Result<bool, DbError> {
        let n = self.c().execute(
            "UPDATE users SET share_presence = ?2 WHERE user = ?1 AND share_presence <> ?2",
            params![user, share],
        )?;
        Ok(n > 0)
    }

    /// 접속 표시를 숨긴 그 조직 사람들(묶음 14 B1 — 디렉터리의 `online` 을 싣지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn presence_hidden_in_org(
        &self,
        org: &str,
    ) -> Result<std::collections::HashSet<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare("SELECT user FROM users WHERE org = ?1 AND share_presence = 0")?;
        let rows = st.query_map([org], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `viewer` 를 초대한 같은 조직 사람(§17.3 — 디렉터리의 `invited_me`). 그 사람이 내보내졌거나 나갔으면 없다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn inviter_of(&self, viewer: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT u.user FROM users v JOIN users u ON u.user = v.invited_by AND u.org = v.org
                 WHERE v.user = ?1 AND u.removed_ms IS NULL",
                [viewer],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 같은 조직의 사람들 (user, display).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn people_in_org(&self, org: &str) -> Result<Vec<(String, Option<String>)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user, display FROM users WHERE org = ?1 AND removed_ms IS NULL ORDER BY user",
        )?;
        let rows = st.query_map(params![org], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 사용자의 폐기되지 않은 기기 (device_id, ed25519, x25519). 등록 순.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn devices_of(&self, user: &str) -> Result<Vec<DeviceRow>, DbError> {
        let c = self.c();
        let mut st = c.prepare("SELECT device_id, ed25519, x25519, x25519_sig, created_ms, name, last_seen_day, hello_v, last_auth_ms, os, away FROM devices WHERE user = ?1 AND revoked_ms IS NULL ORDER BY created_ms, device_id")?;
        let rows = st.query_map(params![user], |r| {
            Ok(DeviceRow {
                device_id: r.get(0)?,
                ed25519: r.get(1)?,
                x25519: r.get(2)?,
                x25519_sig: r.get(3)?,
                created_ms: r.get(4)?,
                name: r.get(5)?,
                last_seen_day: r.get(6)?,
                hello_v: r.get(7)?,
                last_auth_ms: r.get(8)?,
                os: r.get(9)?,
                away: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 기기가 붙은 hello.v 를 남긴다(#598 ② — 디렉터리 `v`, 보내는 코어가 10 전용 칸을 실을지 가른다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_device_hello_v(&self, device_id: &str, v: u64) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE devices SET hello_v = ?2 WHERE device_id = ?1",
            params![device_id, i64::try_from(v).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    /// 그 기기가 마지막으로 붙은 연결의 hello.own(#870).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_device_own(&self, device_id: &str, own: bool) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE devices SET own = ?2 WHERE device_id = ?1",
            params![device_id, i64::from(own)],
        )?;
        Ok(())
    }

    /// 그 기기들 중 마지막으로 hello.own 을 싣고 붙은 기기(#870).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn devices_own(
        &self,
        device_ids: &[String],
    ) -> Result<std::collections::HashSet<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare("SELECT own FROM devices WHERE device_id = ?1")?;
        let mut out = std::collections::HashSet::new();
        for id in device_ids {
            let v: Option<Option<i64>> = st.query_row([id], |r| r.get(0)).optional()?;
            if v == Some(Some(1)) {
                out.insert(id.clone());
            }
        }
        Ok(out)
    }

    /// 그 기기들이 마지막으로 붙은 hello.v(#598 ②). 모르는 기기(NULL·없음)는 맵에 없다 — 부르는 쪽이 9 로 본다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_hello_v(
        &self,
        device_ids: &[String],
    ) -> Result<std::collections::HashMap<String, u64>, DbError> {
        let c = self.c();
        let mut st = c.prepare("SELECT hello_v FROM devices WHERE device_id = ?1")?;
        let mut out = std::collections::HashMap::new();
        for id in device_ids {
            let v: Option<Option<i64>> = st.query_row([id], |r| r.get(0)).optional()?;
            if let Some(Some(v)) = v {
                if let Ok(v) = u64::try_from(v) {
                    out.insert(id.clone(), v);
                }
            }
        }
        Ok(out)
    }

    /// 폐기 안 된 기기의 이름(#490 묶음 28 §4). 없는 기기면 `None`, 이름이 없으면 `Some(None)`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_name(&self, device_id: &str) -> Result<Option<Option<String>>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT name FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                [device_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 기기 이름을 바꾼다(`None` = 지우기). 바뀌었으면 참 — 같은 값·폐기된 기기는 거짓.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_device_name(&self, device_id: &str, name: Option<&str>) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE devices SET name = ?2 WHERE device_id = ?1 AND revoked_ms IS NULL AND name IS NOT ?2",
            params![device_id, name],
        )? == 1)
    }

    /// 폐기 안 된 기기가 알린 OS(판 15). 없는 기기·알리지 않음 = `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_os(&self, device_id: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT os FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                [device_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    /// 기기가 알린 OS 를 남긴다(판 15). 바뀌었으면 참 — 같은 값·폐기된 기기는 거짓.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_device_os(&self, device_id: &str, os: &str) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE devices SET os = ?2 WHERE device_id = ?1 AND revoked_ms IS NULL AND os IS NOT ?2",
            params![device_id, os],
        )? == 1)
    }

    /// 그 기기가 `day_ms`(UTC 날짜의 0시)에 접속했다고 남긴다(묶음 22 §12-27 ⓑ). 이미 다른 날이 적혀 있다가 바뀌었을 때만
    /// 참 — 부르는 쪽은 그때만 내 다른 기기에 `directory.update` 를 보낸다(방송을 하루 한 번으로). 처음 적을 때(등록 직후
    /// 첫 접속·이 값 전 기기)는 거짓: 새 기기는 등록이 이미 알렸고, 처음 값 하나로 방송을 늘리지 않는다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn touch_device_day(&self, device_id: &str, day_ms: i64) -> Result<bool, DbError> {
        let c = self.c();
        let before: Option<Option<i64>> = c
            .query_row(
                "SELECT last_seen_day FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                params![device_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(before) = before else {
            return Ok(false);
        };
        if before == Some(day_ms) {
            return Ok(false);
        }
        c.execute(
            "UPDATE devices SET last_seen_day = ?2 WHERE device_id = ?1",
            params![device_id, day_ms],
        )?;
        Ok(before.is_some())
    }

    /// 마지막으로 붙어 있던 시각을 쓴다(#577 — 인증 때·그 기기의 마지막 연결이 끊길 때). 폐기된 기기는 그대로.
    ///
    /// # Errors
    /// DB 오류.
    pub fn touch_last_auth(&self, device_id: &str, now_ms: i64) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE devices SET last_auth_ms = ?2 WHERE device_id = ?1 AND revoked_ms IS NULL",
            params![device_id, now_ms],
        )?;
        Ok(())
    }

    /// 그 기기의 마지막 연결이 어떻게 끝났나를 쓴다(#870 — 붙을 때 `lost`, 마지막 연결이 끊길 때 닫는 이유). 폐기된 기기는 그대로.
    ///
    /// # Errors
    /// DB 오류.
    pub fn set_away(&self, device_id: &str, away: &str) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE devices SET away = ?2 WHERE device_id = ?1 AND revoked_ms IS NULL",
            params![device_id, away],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- 메일 확인 끊기(#577)

    /// 그 기기보다 먼저 등록된(등록 시각, 행 순서 — `revoke_other` 와 같은 순서) 같은 사용자의 폐기 안 된 기기.
    ///
    /// # Errors
    /// DB 오류.
    pub fn older_live_devices(&self, user: &str, device_id: &str) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT o.device_id FROM devices o JOIN devices me ON me.device_id = ?2 AND me.user = ?1
             WHERE o.user = ?1 AND o.revoked_ms IS NULL AND o.device_id != ?2
               AND (o.created_ms < me.created_ms OR (o.created_ms = me.created_ms AND o.rowid < me.rowid))
             ORDER BY o.created_ms, o.rowid",
        )?;
        let rows = st.query_map(params![user, device_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 사용자의 걸기(끝난 것 포함).
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery(&self, user: &str) -> Result<Option<RecoveryRow>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT user, requester, created_ms, at_ms, targets, state, ended_ms, blocked_by, deferred FROM recoveries WHERE user = ?1",
                [user],
                recovery_row,
            )
            .optional()?
            .flatten())
    }

    /// 걸기를 쓴다(같은 사용자의 이전 행 — 끝난 것 — 은 덮는다).
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_schedule(
        &self,
        user: &str,
        requester: &str,
        now_ms: i64,
        at_ms: i64,
        targets: &[String],
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR REPLACE INTO recoveries(user, requester, created_ms, at_ms, targets, state, ended_ms, blocked_by,
               seen_after, deferred)
             VALUES (?1, ?2, ?3, ?4, ?5, 'scheduled', NULL, NULL, 0, 0)",
            params![
                user,
                requester,
                now_ms,
                at_ms,
                serde_json::to_string(targets).unwrap_or_default()
            ],
        )?;
        Ok(())
    }

    /// #737: 걸린 걸기의 대상 기기가 붙었다 — 표시한다(이미 미뤘으면 그대로). 표시했으면 `true`.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_mark_seen(&self, user: &str, device_id: &str) -> Result<bool, DbError> {
        let n = self.c().execute(
            "UPDATE recoveries SET seen_after = 1
             WHERE user = ?1 AND state = 'scheduled' AND seen_after = 0
               AND EXISTS(SELECT 1 FROM json_each(recoveries.targets) WHERE value = ?2)",
            params![user, device_id],
        )?;
        Ok(n > 0)
    }

    /// #737: 시각이 된 걸기인데 그동안 대상이 붙었고 아직 미루지 않았으면 `at` 을 `new_at` 으로 한 번 미룬다. 미뤘으면
    /// 그 행. 미룬 시각에는 `seen_after` 를 보지 않고 실행한다(끝없는 대기 금지).
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_defer(
        &self,
        user: &str,
        now_ms: i64,
        new_at: i64,
    ) -> Result<Option<RecoveryRow>, DbError> {
        let n = self.c().execute(
            "UPDATE recoveries SET at_ms = ?3, deferred = 1
             WHERE user = ?1 AND state = 'scheduled' AND at_ms <= ?2 AND seen_after = 1 AND deferred = 0",
            params![user, now_ms, new_at],
        )?;
        if n == 0 {
            return Ok(None);
        }
        self.recovery(user)
    }

    /// #737 관리자 폐기(ADR 0006): `admin` 이 같은 조직의 다른 사람 `user` 의 기기를 끊는다 — 그 사람이 걸어 둔 메일 확인
    /// 끊기의 대상 기기만, 24시간 없이. 조건이 하나라도 아니면 아무것도 하지 않고 `false`.
    ///
    /// # Errors
    /// DB 오류.
    pub fn admin_revoke_device(
        &self,
        admin: &str,
        user: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let ok: bool = tx.query_row(
            "SELECT ?1 != ?2
               AND EXISTS(SELECT 1 FROM users a JOIN org_admins x ON x.org_id = a.org AND x.user = a.user
                          JOIN users u ON u.org = a.org
                          WHERE a.user = ?1 AND a.removed_ms IS NULL AND u.user = ?2 AND u.removed_ms IS NULL)
               AND EXISTS(SELECT 1 FROM recoveries r WHERE r.user = ?2 AND r.state = 'scheduled'
                          AND EXISTS(SELECT 1 FROM json_each(r.targets) WHERE value = ?3))
               AND EXISTS(SELECT 1 FROM devices WHERE device_id = ?3 AND user = ?2 AND revoked_ms IS NULL)",
            params![admin, user, device_id],
            |r| r.get(0),
        )?;
        if !ok {
            return Ok(false);
        }
        revoke_in(&tx, device_id, now_ms, RevokedBy::AdminDevice, None)?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(true)
    }

    /// #737: 이 이메일에 묶인 살아 있는 조직 만들기 코드(대기 명단 승인)가 있나 — 있으면 코드 없이 조직을 만든다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn org_create_allowed(&self, email: &str, now_ms: i64) -> Result<bool, DbError> {
        let Some((sha, mac)) =
            lodelai_protocol::email::normalize(email).map(|e| self.setup_email_forms(&e))
        else {
            return Ok(false);
        };
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM setup_codes WHERE expires_ms > ?2
               AND ((email_keyed = 0 AND email_hash = ?1) OR (email_keyed = 1 AND email_hash = ?3)))",
            params![sha, now_ms, mac],
            |r| r.get(0),
        )?)
    }

    /// 걸려 있는(scheduled) 걸기를 끝낸다 — 실행과 한 IMMEDIATE 트랜잭션 순서(A7). `state = None` 이면 행을 지운다
    /// (certified·요청 기기 사라짐). `blocked_by` 가 있으면 막기 기록도 한 줄. 끝낸 행(끝나기 전 모습)을 돌려주고, 이미
    /// scheduled 가 아니면 `None`.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_end(
        &self,
        user: &str,
        state: Option<RecoveryState>,
        now_ms: i64,
        blocked_by: Option<&str>,
    ) -> Result<Option<RecoveryRow>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row = tx
            .query_row(
                "SELECT user, requester, created_ms, at_ms, targets, state, ended_ms, blocked_by, deferred FROM recoveries
                 WHERE user = ?1 AND state = 'scheduled'",
                [user],
                recovery_row,
            )
            .optional()?
            .flatten();
        let Some(row) = row else {
            return Ok(None);
        };
        match state {
            Some(s) => {
                tx.execute(
                    "UPDATE recoveries SET state = ?2, ended_ms = ?3, blocked_by = ?4 WHERE user = ?1",
                    params![user, s.as_str(), now_ms, blocked_by],
                )?;
            }
            None => {
                tx.execute("DELETE FROM recoveries WHERE user = ?1", [user])?;
            }
        }
        if blocked_by.is_some() {
            tx.execute(
                "INSERT INTO recovery_blocks(user, at_ms) VALUES (?1, ?2)",
                params![user, now_ms],
            )?;
        }
        tx.commit()?;
        Ok(Some(row))
    }

    /// 걸려 있는 걸기의 대상을 바꾼다(지금 끊기로 대상 하나가 폐기됨).
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_set_targets(&self, user: &str, targets: &[String]) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE recoveries SET targets = ?2 WHERE user = ?1 AND state = 'scheduled'",
            params![user, serde_json::to_string(targets).unwrap_or_default()],
        )?;
        Ok(())
    }

    /// 그 사용자의 막기 시각(`since_ms` 뒤, 오랜 것 먼저) — 30일 상한 집계.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_blocks_since(&self, user: &str, since_ms: i64) -> Result<Vec<i64>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT at_ms FROM recovery_blocks WHERE user = ?1 AND at_ms > ?2 ORDER BY at_ms",
        )?;
        let rows = st.query_map(params![user, since_ms], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 걸려 있고 `at` 이 지난 걸기의 사용자.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recoveries_due(&self, now_ms: i64) -> Result<Vec<String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user FROM recoveries WHERE state = 'scheduled' AND at_ms <= ?1 ORDER BY at_ms",
        )?;
        let rows = st.query_map([now_ms], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 걸려 있는 걸기 전부 — 대상 기기가 인증할 때 recover_against 를 다시 보낼지 본다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recoveries_scheduled_for(&self, user: &str) -> Result<Option<RecoveryRow>, DbError> {
        Ok(self
            .recovery(user)?
            .filter(|r| r.state == RecoveryState::Scheduled))
    }

    /// 실행(§4): 한 IMMEDIATE 트랜잭션에서 아직 scheduled 이고 `at` 이 지났는지 다시 본 뒤 대상을 모두 끊는다(by =
    /// recovery, 증명 없음) — 막기와 겹치면 둘 중 하나만 이긴다(A7). 끊은 대상을 돌려주고, 실행하지 않았으면 `None`.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_execute(
        &self,
        user: &str,
        now_ms: i64,
    ) -> Result<Option<(String, Vec<String>)>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row = tx
            .query_row(
                "SELECT user, requester, created_ms, at_ms, targets, state, ended_ms, blocked_by, deferred FROM recoveries
                 WHERE user = ?1 AND state = 'scheduled' AND at_ms <= ?2",
                params![user, now_ms],
                recovery_row,
            )
            .optional()?
            .flatten();
        let Some(row) = row else {
            return Ok(None);
        };
        let mut cut = Vec::new();
        for t in &row.targets {
            if revoke_in(&tx, t, now_ms, RevokedBy::Recovery, None)?.is_some() {
                cut.push(t.clone());
            }
        }
        tx.execute(
            "UPDATE recoveries SET state = 'done', ended_ms = ?2 WHERE user = ?1",
            params![user, now_ms],
        )?;
        tx.commit()?;
        truncate_wal(&c);
        Ok(Some((row.requester, cut)))
    }

    /// 보낼 때 이미 받는 사람의 잎이 모두 폐기돼 있던 글(§9 ② — 끊긴 뒤 새 기기가 들기 전, 설계 리뷰 6493882795 🟡2)을
    /// 적는다. 같은 msg_id 를 다시 적으면 다시 알린다(다시 보낸 글이 또 못 간 경우).
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_mark(
        &self,
        msg_id: &str,
        from_user: &str,
        now_ms: i64,
        expires_ms: i64,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR REPLACE INTO device_changed(msg_id, from_user, at_ms, expires_ms, notified)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![msg_id, from_user, now_ms, expires_ms],
        )?;
        Ok(())
    }

    /// 보관 기한이 지난 §9 ② 표시를 지운다(봉투 없이 적힌 1:1 글도 있어 봉투가 아니라 기한으로).
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_sweep(&self, now_ms: i64) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM device_changed WHERE expires_ms <= ?1",
            [now_ms],
        )?;
        Ok(())
    }

    /// 아직 알리지 않은 §9 ② 실패(msg_id, 보낸 사람).
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_pending(&self) -> Result<Vec<(String, String)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT msg_id, from_user FROM device_changed WHERE notified = 0 ORDER BY at_ms",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 보낸 사람에게 알렸다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_notified(&self, msg_id: &str) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE device_changed SET notified = 1 WHERE msg_id = ?1",
            [msg_id],
        )?;
        Ok(())
    }

    /// 그 보낸 사람의 §9 ② 실패 글인가(같은 msg_id 로 다시 오면 재생 ack 대신 다시 받는다).
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_has(&self, msg_id: &str, from_user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM device_changed WHERE msg_id = ?1 AND from_user = ?2)",
            params![msg_id, from_user],
            |r| r.get(0),
        )?)
    }

    /// 같은 보낸 사람이 §9 ② 실패 글을 같은 msg_id 로 다시 보냈고 받을 잎이 정해졌다 — 저장 직전에 옛 봉투·표시를 지운다
    /// (받는 쪽은 msg_id 로 거른다). 그런 글이 아니면 `false`.
    ///
    /// # Errors
    /// DB 오류.
    pub fn device_changed_resend(&self, msg_id: &str, from_user: &str) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let n = tx.execute(
            "DELETE FROM device_changed WHERE msg_id = ?1 AND from_user = ?2",
            params![msg_id, from_user],
        )?;
        if n > 0 {
            tx.execute("DELETE FROM envelopes WHERE msg_id = ?1", [msg_id])?;
        }
        tx.commit()?;
        if n > 0 {
            truncate_wal(&c);
        }
        Ok(n > 0)
    }

    /// 30일보다 오랜 막기 기록을 지운다.
    ///
    /// # Errors
    /// DB 오류.
    pub fn recovery_prune(&self, before_ms: i64) -> Result<(), DbError> {
        self.c()
            .execute("DELETE FROM recovery_blocks WHERE at_ms < ?1", [before_ms])?;
        Ok(())
    }

    // ---------------------------------------------------------------- sessions

    /// 일관된 사본 하나를 `out` 에 쓴다(`VACUUM INTO` — WAL 없는 단일 파일, 서비스가 도는 중에도 된다). `out` 이 이미 있으면
    /// 실패한다(덮어쓰지 않음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn backup_to(&self, out: &Path) -> Result<(), DbError> {
        let out = out
            .to_str()
            .ok_or_else(|| rusqlite::Error::InvalidPath(out.to_path_buf()))?;
        self.c().execute("VACUUM INTO ?1", [out])?;
        Ok(())
    }

    /// `device` = 공개한 연결의 기기(인증된 값, #569 ③ — 그 기기가 끊기면 [`Self::sessions_dead_for_device`]).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn publish_session(&self, s: &PublicSession, device: Option<&str>) -> Result<(), DbError> {
        self.c().execute(
            "INSERT INTO sessions_public(user, slug, grade, liveness, display, title, folder, busy, audience,
               project_id, project_name, device_id, agent, no, offline)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0)
             ON CONFLICT(user, slug) DO UPDATE SET grade = excluded.grade, liveness = excluded.liveness, offline = 0,
               display = excluded.display, title = excluded.title, folder = excluded.folder,
               busy = excluded.busy, audience = excluded.audience,
               project_id = excluded.project_id, project_name = excluded.project_name,
               device_id = excluded.device_id, agent = excluded.agent, no = excluded.no",
            params![
                s.user,
                s.slug,
                s.grade,
                s.liveness,
                s.display,
                s.title,
                s.folder,
                s.busy,
                audience_text(s.audience.as_ref(), &s.audience_lists),
                s.project.as_ref().map(|p| p.0.clone()),
                s.project.as_ref().map(|p| p.1.clone()),
                device,
                s.agent,
                s.no
            ],
        )?;
        Ok(())
    }

    /// 그 기기가 공개한 세션을 `dead`·`busy=0` 으로(#569 ③ — 그 기기의 마지막 연결이 끊긴 뒤). 바뀐 행 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn sessions_dead_for_device(&self, user: &str, device: &str) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "UPDATE sessions_public SET offline = CASE WHEN liveness != 'dead' THEN 1 ELSE offline END,
               liveness = 'dead', busy = 0
             WHERE user = ?1 AND device_id = ?2 AND (liveness != 'dead' OR busy != 0)",
            params![user, device],
        )?)
    }

    /// 기기를 아는 공개 세션을 모두 `dead`·`busy=0` 으로(#569 ③ — relay 기동 때, 연결이 하나도 없으니). 옛 행(기기 없음)은
    /// 그대로. 바뀐 행 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn sessions_dead_all(&self) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "UPDATE sessions_public SET offline = CASE WHEN liveness != 'dead' THEN 1 ELSE offline END,
               liveness = 'dead', busy = 0
             WHERE device_id IS NOT NULL AND (liveness != 'dead' OR busy != 0)",
            [],
        )?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn unpublish_session(&self, user: &str, slug: &str) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM sessions_public WHERE user = ?1 AND slug = ?2",
            params![user, slug],
        )?;
        Ok(())
    }

    /// 공개된 세션의 (등급, 범위)(묶음 20). 비공개·없음이면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::type_complexity)]
    pub fn session_grade(
        &self,
        user: &str,
        slug: &str,
    ) -> Result<Option<(String, Option<Vec<String>>)>, DbError> {
        let c = self.c();
        let row: Option<(String, Option<(Vec<String>, Vec<String>)>)> = c
            .query_row(
                "SELECT grade, audience FROM sessions_public WHERE user = ?1 AND slug = ?2",
                params![user, slug],
                |r| Ok((r.get(0)?, audience_of(r.get(1)?))),
            )
            .optional()?;
        // 범위 = 고른 사람 ∪ 고른 목록에 지금 든 사람(#845 둘째).
        row.map(|(grade, a)| {
            let a = match a {
                None => None,
                Some((mut users, lists)) => {
                    for u in list_members_c(&c, user, &lists)? {
                        if !users.contains(&u) {
                            users.push(u);
                        }
                    }
                    Some(users)
                }
            };
            Ok((grade, a))
        })
        .transpose()
    }

    /// 조직의 공개 세션 전부.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn sessions_in_org(&self, org: &str) -> Result<Vec<PublicSession>, DbError> {
        self.sessions_where("u.org = ?1", org)
    }

    /// #845 한 사람의 공개 세션 전부(연락처의 세션 — 부르는 쪽이 범위를 거른다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn sessions_of(&self, user: &str) -> Result<Vec<PublicSession>, DbError> {
        self.sessions_where("s.user = ?1 AND u.removed_ms IS NULL", user)
    }

    fn sessions_where(&self, cond: &str, arg: &str) -> Result<Vec<PublicSession>, DbError> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT s.user, s.slug, s.grade, s.liveness, s.display, s.title, s.folder, s.busy, s.audience,
               s.project_id, s.project_name, s.agent, s.no, s.offline FROM sessions_public s
             JOIN users u ON u.user = s.user WHERE {cond} ORDER BY s.user, s.slug"
        ))?;
        let rows = st.query_map(params![arg], |r| {
            let (audience, audience_lists) = match audience_of(r.get(8)?) {
                Some((u, l)) => (Some(u), l),
                None => (None, Vec::new()),
            };
            Ok(PublicSession {
                user: r.get(0)?,
                slug: r.get(1)?,
                grade: r.get(2)?,
                liveness: r.get(3)?,
                display: r.get(4)?,
                title: r.get(5)?,
                folder: r.get(6)?,
                busy: r.get(7)?,
                audience,
                audience_lists,
                listed: Vec::new(),
                project: match (r.get(9)?, r.get(10)?) {
                    (Some(id), Some(name)) => Some((id, name)),
                    _ => None,
                },
                agent: r.get(11)?,
                // 옛 relay 가 쓴 행·손댄 값도 1..=999 밖이면 싣지 않는다.
                no: r
                    .get::<_, Option<i64>>(12)?
                    .and_then(|n| u16::try_from(n).ok())
                    .filter(|n| (1..=999).contains(n)),
                offline: r.get::<_, i64>(13)? != 0,
            })
        })?;
        let mut out: Vec<PublicSession> = rows.collect::<Result<_, _>>()?;
        drop(st);
        for ps in &mut out {
            ps.listed = list_members_c(&c, &ps.user, &ps.audience_lists)?;
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- device certs

    /// 내 기기 서명 저장(#393). 서명 검증은 호출자가 끝냈다. 같은 (서명자, 대상) 은 덮어쓴다. 바뀌었으면 참 — 같은 sig 가
    /// 다시 오면 아무것도 쓰지 않고 거짓(호출자는 방송하지 않는다 — 자동 재서명 버그로 certify ↔ directory.update 고리가
    /// 생기지 않게).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_device_cert(
        &self,
        signer: &str,
        target: &str,
        sig: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let n = self.c().execute(
            "INSERT INTO device_certs(signer, target, sig, created_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(signer, target) DO UPDATE SET sig = excluded.sig, created_ms = excluded.created_ms
               WHERE device_certs.sig <> excluded.sig",
            params![signer, target, sig, now_ms],
        )?;
        Ok(n > 0)
    }

    /// 그 사용자의 기기들에 붙은 서명 (대상, 서명자, sig) — 서명자·대상 모두 폐기 안 된 것만, 대상·서명자 순.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_certs_of(&self, user: &str) -> Result<Vec<(String, String, String)>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT c.target, c.signer, c.sig FROM device_certs c
               JOIN devices t ON t.device_id = c.target
               JOIN devices s ON s.device_id = c.signer
             WHERE t.user = ?1 AND s.user = ?1
               AND (t.revoked_ms IS NULL OR t.revoke_sig IS NOT NULL)
               AND (s.revoked_ms IS NULL OR s.revoke_sig IS NOT NULL)
             ORDER BY c.target, c.signer",
        )?;
        let rows = st.query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 사용자의 증명 있는 폐기(디렉터리 `revocations[]`, 묶음 22 §12-11 ⓐ) — 등록 순.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn revocations_of(&self, user: &str) -> Result<Vec<RevocationRow>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT device_id, created_ms, ed25519, x25519, revoke_at, revoke_signer, revoke_sig FROM devices
             WHERE user = ?1 AND revoked_ms IS NOT NULL AND revoke_sig IS NOT NULL
               AND revoke_at IS NOT NULL AND revoke_signer IS NOT NULL AND x25519 IS NOT NULL AND x25519 <> ''
             ORDER BY created_ms, device_id",
        )?;
        let rows = st.query_map([user], |r| {
            Ok(RevocationRow {
                device_id: r.get(0)?,
                created_ms: r.get(1)?,
                ed25519: r.get(2)?,
                x25519: r.get(3)?,
                proof: RevokeProof {
                    at: r.get(4)?,
                    signer: r.get(5)?,
                    sig: r.get(6)?,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---------------------------------------------------------------- envelopes

    /// [`Self::store_envelope`] 가 이 첨부들을 묶을 수 있는가(보낸 사용자가 올린, 묶이지 않은 message blob, 겹침 없음). 고치기가
    /// 원 메시지를 거두기 **전에** 본다(묶음 15 리뷰 ⑥ — 묶기가 실패하면 원문만 사라지고 고친 글은 가지 않으므로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blobs_bindable(&self, user: &str, blobs: &[String]) -> Result<bool, DbError> {
        let mut seen = std::collections::HashSet::new();
        if !blobs.iter().all(|b| seen.insert(b)) {
            return Ok(false);
        }
        let c = self.c();
        for b in blobs {
            let ok: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id = ?1 AND user = ?2 AND purpose = 'message'
                   AND state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL)",
                params![b, user],
                |r| r.get(0),
            )?;
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 이 첨부들의 예약 길이(`ct_len`) 합 — 그룹 첨부 합계 상한(묶음 22 §5d) 검사용. 보낸 사용자의 message blob 이 아닌 것은
    /// 세지 않는다(묶기에서 blob_unavailable).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blobs_ct_sum(&self, user: &str, blobs: &[String]) -> Result<u64, DbError> {
        let c = self.c();
        let mut sum = 0u64;
        for b in blobs {
            let n: Option<i64> = c
                .query_row(
                    "SELECT ct_len FROM blobs WHERE blob_id = ?1 AND user = ?2 AND purpose = 'message'",
                    params![b, user],
                    |r| r.get(0),
                )
                .optional()?;
            sum = sum.saturating_add(n.and_then(|n| u64::try_from(n).ok()).unwrap_or(0));
        }
        Ok(sum)
    }

    /// 봉투 저장(평문 system — 묶음 22 부터 box 없음, #503). 전달 대상은 후보(`pool`, 없으면 `to_user`)의 폐기되지 않은
    /// 기기 — 돌려준다. `msg_id` 중복이면 [`DbError::Conflict`], `pool` 이 있는데 남는 대상이 없으면 [`DbError::NoTargets`]
    /// (아무것도 쓰지 않는다).
    ///
    /// # Errors
    /// sqlite 오류 또는 중복.
    pub fn store_envelope(
        &self,
        h: &StoredHeader,
        message: &str,
        blobs: &[String],
        pool: Option<&[String]>,
        gid: Option<&str>,
    ) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let devices = insert_envelope_in(&tx, h, message, blobs, pool, gid.map(|g| (g, None)))?;
        tx.commit()?;
        Ok(devices)
    }

    /// 그 기기가 받았다고 표시하고, 본문을 지워도 되는지 — 대상이 모두 ack 했거나 행이 없는 옛 봉투(첫 ack 에 삭제)면
    /// `Some(true)`. 대상 행이 있는데 그 기기가 대상이 아니면 `None`(아무 일도 하지 않는다, protocol §7.2-6).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn ack_device(
        &self,
        msg_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<Option<bool>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let (any, mine): (bool, bool) = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1),
                    EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND device_id = ?2)",
            params![msg_id, device_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if any && !mine {
            return Ok(None);
        }
        tx.execute(
            "UPDATE envelope_devices SET acked_ms = ?3 WHERE msg_id = ?1 AND device_id = ?2 AND acked_ms IS NULL",
            params![msg_id, device_id, now_ms],
        )?;
        let open: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL)",
            [msg_id],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(Some(!open))
    }

    /// 헤더 조회. 만료로 지워졌으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn header(&self, msg_id: &str) -> Result<Option<StoredHeader>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT msg_id, kind, from_user, from_address, to_user, to_address, expires_ms,
                        env_state, sender_view, abort_reason
                 FROM envelopes WHERE msg_id = ?1",
                params![msg_id],
                |r| {
                    Ok(StoredHeader {
                        msg_id: r.get(0)?,
                        kind: r.get(1)?,
                        from_user: r.get(2)?,
                        from_address: r.get(3)?,
                        to_user: r.get(4)?,
                        to_address: r.get(5)?,
                        expires_ms: r.get(6)?,
                        env_state: r.get(7)?,
                        sender_view: r.get(8)?,
                        abort_reason: r.get(9)?,
                    })
                },
            )
            .optional()?)
    }

    /// 상태 조건부 갱신(compare-and-swap). 읽은 뒤 다른 갱신이 끼어들었으면 0행 → `false`.
    /// 호출자는 다시 읽고 다시 계산한다(#110: 겹친 status 가 rank 를 되돌리지 않게).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn update_states_if(
        &self,
        expected: &StoredHeader,
        env_state: &str,
        sender_view: &str,
        abort_reason: Option<&str>,
    ) -> Result<bool, DbError> {
        let n = self.c().execute(
            "UPDATE envelopes SET env_state = ?5, sender_view = ?6, abort_reason = ?7
             WHERE msg_id = ?1 AND env_state = ?2 AND sender_view = ?3 AND abort_reason IS ?4",
            params![
                expected.msg_id,
                expected.env_state,
                expected.sender_view,
                expected.abort_reason,
                env_state,
                sender_view,
                abort_reason
            ],
        )?;
        Ok(n == 1)
    }

    /// 수신 기기가 받았다: 본문 봉투를 지운다(헤더는 `expires_at` 까지 보관).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_body(&self, msg_id: &str) -> Result<(), DbError> {
        let c = self.c();
        c.execute(
            "UPDATE envelopes SET message = NULL WHERE msg_id = ?1",
            params![msg_id],
        )?;
        truncate_wal(&c);
        Ok(())
    }

    /// 첨부 예약(묶음 15). message 면 그 사용자의 남은 첨부 합계 + `ct_len` 이 `pending_max` 를 넘으면 `Ok(false)`.
    ///
    /// # Errors
    /// sqlite 오류·같은 id.
    pub fn blob_reserve(&self, b: &NewBlob<'_>, pending_max: u64) -> Result<bool, DbError> {
        Ok(self.blob_reserve_daily(b, pending_max, 0)? == Reserve::Done)
    }

    /// [`Db::blob_reserve`] + #876 계정당 UTC 하루 합(`daily_max`, 0 = 끔, 사진 제외). 하루 합은 다른 검사를 다 지난 뒤 같은 tx 의
    /// 맨 끝에서 '넘는지 보기 + 더하기' 한 문장으로 — 동시 예약이 넘기지 못하게. 거절되면 tx 가 롤백돼 세지 않는다.
    ///
    /// # Errors
    /// sqlite 오류·같은 id.
    pub fn blob_reserve_daily(
        &self,
        b: &NewBlob<'_>,
        pending_max: u64,
        daily_max: u64,
    ) -> Result<Reserve, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let history = b.for_device.is_some();
        if !b.avatar {
            // 보통 첨부의 미전달 합과 옮기기 조각의 진행 중 합은 따로 센다(#881).
            let (sql, max) = if history {
                (
                    "SELECT COALESCE(SUM(ct_len), 0) FROM blobs WHERE user = ?1 AND purpose = 'message' AND for_device IS NOT NULL",
                    lodelai_protocol::constants::BLOB_HISTORY_PENDING_MAX_BYTES,
                )
            } else {
                (
                    "SELECT COALESCE(SUM(ct_len), 0) FROM blobs WHERE user = ?1 AND purpose = 'message' AND for_device IS NULL",
                    pending_max,
                )
            };
            let pending: i64 = tx.query_row(sql, [b.user], |r| r.get(0))?;
            if (pending.max(0) as u64).saturating_add(b.ct_len) > max {
                return Ok(Reserve::Pending);
            }
        }
        tx.execute(
            "INSERT INTO blobs(blob_id, user, device, purpose, ct_len, state, put_token_hash, put_token_exp, created_ms, for_org, for_device)
             VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', ?6, ?7, ?8, ?9, ?10)",
            params![
                b.blob_id,
                b.user,
                b.device,
                if b.avatar { "avatar" } else { "message" },
                b.ct_len as i64,
                b.put_token_hash,
                b.put_token_exp,
                b.now_ms,
                b.for_org,
                b.for_device
            ],
        )?;
        if !b.avatar && daily_max > 0 {
            let len = i64::try_from(b.ct_len).unwrap_or(i64::MAX);
            // 옮기기 조각은 하루 통도 따로(#881) — 0 이면 둘 다 끔.
            let (sql, max) = if history {
                (
                    "INSERT INTO blob_history_daily(user, day, bytes) SELECT ?1, ?2, ?3 WHERE ?3 <= ?4
                     ON CONFLICT(user, day) DO UPDATE SET bytes = bytes + excluded.bytes WHERE bytes + excluded.bytes <= ?4",
                    lodelai_protocol::constants::BLOB_HISTORY_DAILY_MAX_BYTES,
                )
            } else {
                (
                    "INSERT INTO blob_daily(user, day, bytes) SELECT ?1, ?2, ?3 WHERE ?3 <= ?4
                     ON CONFLICT(user, day) DO UPDATE SET bytes = bytes + excluded.bytes WHERE bytes + excluded.bytes <= ?4",
                    daily_max,
                )
            };
            let max = i64::try_from(max).unwrap_or(i64::MAX);
            let n = tx.execute(sql, params![b.user, b.now_ms.div_euclid(DAY_MS), len, max])?;
            if n == 0 {
                return Ok(Reserve::Daily);
            }
        }
        tx.commit()?;
        Ok(Reserve::Done)
    }

    /// #881 지난 대화 옮기기 조각인가(받을 기기가 있는 blob).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_is_history(&self, blob_id: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id = ?1 AND for_device IS NOT NULL)",
            [blob_id],
            |r| r.get(0),
        )?)
    }

    /// 그 사용자의 남은 message 첨부 합계(바이트, 묶음 15 — 예약 합계 상한).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_pending(&self, user: &str) -> Result<u64, DbError> {
        Ok(self.c().query_row(
            "SELECT COALESCE(SUM(ct_len), 0) FROM blobs WHERE user = ?1 AND purpose = 'message' AND for_device IS NULL",
            [user],
            |r| r.get::<_, i64>(0),
        )?.max(0) as u64)
    }

    /// PUT 시작(묶음 15): 토큰이 맞고 안 지났고 아직 예약 상태면 토큰을 **소진**하고 (사용자, avatar 인가, 길이, 조직 사진이면
    /// 그 조직 #554). 한 문장 — 같은 토큰으로 둘이 동시에 들어와도 하나만 통과.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_put_begin(
        &self,
        blob_id: &str,
        token_hash: &[u8],
        now_ms: i64,
    ) -> Result<Option<PutBegin>, DbError> {
        Ok(self
            .c()
            .query_row(
                "UPDATE blobs SET put_token_hash = NULL
                 WHERE blob_id = ?1 AND put_token_hash = ?2 AND put_token_exp > ?3 AND state = 'reserved'
                 RETURNING user, purpose, ct_len, for_org",
                params![blob_id, token_hash, now_ms],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)? == "avatar",
                        r.get::<_, i64>(2)?.max(0) as u64,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?)
    }

    /// 토큰을 쓴 PUT 이 실패했다 — 행을 지운다(다시 올리려면 새 예약, 묶음 15).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_put_failed(&self, blob_id: &str) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM blobs WHERE blob_id = ?1 AND state = 'reserved'",
            [blob_id],
        )?;
        Ok(())
    }

    /// PUT 끝(묶음 15): 예약 → 올림. 그 사이 청소로 행이 지워졌으면 `false`(호출자가 파일을 지운다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_put_done(&self, blob_id: &str) -> Result<bool, DbError> {
        let n = self.c().execute(
            "UPDATE blobs SET state = 'uploaded' WHERE blob_id = ?1 AND state = 'reserved'",
            [blob_id],
        )?;
        Ok(n == 1)
    }

    /// 프로필 사진 교체(묶음 15). 옛 사진 id(행은 지움 — 파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류.
    /// 프로필 사진 지우기(묶음 15 §2, `profile.update{avatar: null}`): `avatar_blob = NULL`·`blobs` 행 삭제. 지운 blob_id
    /// (파일은 호출자가 지운다), 원래 없었으면 `None`.
    pub fn clear_avatar(&self, user: &str) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT avatar_blob FROM users WHERE user = ?1",
                [user],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(o) = &old {
            tx.execute(
                "UPDATE users SET avatar_blob = NULL WHERE user = ?1",
                [user],
            )?;
            delete_blob_rows(&tx, std::slice::from_ref(o))?;
        }
        tx.commit()?;
        Ok(old)
    }

    pub fn set_avatar(&self, user: &str, blob_id: &str) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT avatar_blob FROM users WHERE user = ?1",
                [user],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        tx.execute(
            "UPDATE users SET avatar_blob = ?2 WHERE user = ?1",
            params![user, blob_id],
        )?;
        let old = old.filter(|o| o != blob_id);
        if let Some(o) = &old {
            delete_blob_rows(&tx, std::slice::from_ref(o))?;
        }
        tx.commit()?;
        Ok(old)
    }

    /// 기본 이미지 고르기(#874, `profile.update{look}`). `Some` 이면 저장하고 프로필 사진을 같이 지운다(한 트랜잭션), `None` 이면
    /// 기본으로(사진은 그대로). (바뀌었나, 지운 사진 blob_id).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_look(
        &self,
        user: &str,
        look_json: Option<&str>,
    ) -> Result<(bool, Option<String>), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let (old_look, old_avatar): (Option<String>, Option<String>) = tx
            .query_row(
                "SELECT look_json, avatar_blob FROM users WHERE user = ?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or_default();
        let removed = if look_json.is_some() {
            old_avatar
        } else {
            None
        };
        tx.execute(
            "UPDATE users SET look_json = ?2 WHERE user = ?1",
            params![user, look_json],
        )?;
        if let Some(o) = &removed {
            tx.execute(
                "UPDATE users SET avatar_blob = NULL WHERE user = ?1",
                [user],
            )?;
            delete_blob_rows(&tx, std::slice::from_ref(o))?;
        }
        tx.commit()?;
        Ok((
            old_look.as_deref() != look_json || removed.is_some(),
            removed,
        ))
    }

    /// 그 조직 사람들의 고른 기본 이미지(#874 — 디렉터리 `look`, 정규 JSON).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn looks_in_org(
        &self,
        org: &str,
    ) -> Result<std::collections::HashMap<String, String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user, look_json FROM users WHERE org = ?1 AND look_json IS NOT NULL AND removed_ms IS NULL",
        )?;
        let rows = st.query_map([org], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 조직 사람들의 프로필 사진(묶음 15 — 디렉터리 `avatar`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn avatars_in_org(
        &self,
        org: &str,
    ) -> Result<std::collections::HashMap<String, String>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user, avatar_blob FROM users WHERE org = ?1 AND avatar_blob IS NOT NULL AND removed_ms IS NULL",
        )?;
        let rows = st.query_map([org], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 사람이 관리자인 자기 조직(#554 조직 사진 — 예약 때와 PUT 끝에). 관리자가 아니거나 나간 사람이면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_admin_of(&self, user: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT u.org FROM users u JOIN org_admins x ON x.org_id = u.org AND x.user = u.user
                 JOIN orgs o ON o.org_id = u.org
                 WHERE u.user = ?1 AND u.removed_ms IS NULL",
                [user],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 조직 사진 교체(#554, 사람 사진 [`Db::set_avatar`] 와 같은 꼴). `admin` 이 지금 그 조직의 관리자인지 같은 트랜잭션에서
    /// 본다 — 아니면 그 blob 행을 지우고 `None`(파일은 호출자가, 403). 맞으면 `Some(옛 사진 id)`(옛 행은 지움 — 파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_org_avatar(
        &self,
        org: &str,
        admin: &str,
        blob_id: &str,
    ) -> Result<Option<Option<String>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let still: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users u JOIN org_admins x ON x.org_id = u.org AND x.user = u.user
                           WHERE u.user = ?1 AND u.org = ?2 AND u.removed_ms IS NULL)",
            params![admin, org],
            |r| r.get(0),
        )?;
        if !still {
            delete_blob_rows(&tx, &[blob_id.to_owned()])?;
            tx.commit()?;
            return Ok(None);
        }
        let old = org_avatar_in(&tx, org)?;
        tx.execute(
            "UPDATE orgs SET avatar_blob = ?2 WHERE org_id = ?1",
            params![org, blob_id],
        )?;
        let old = old.filter(|o| o != blob_id);
        if let Some(o) = &old {
            delete_blob_rows(&tx, std::slice::from_ref(o))?;
        }
        tx.commit()?;
        Ok(Some(old))
    }

    /// 조직 사진 지우기(#554 `org.update{avatar: null}`). 지운 blob_id(파일은 호출자가), 원래 없었으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn clear_org_avatar(&self, org: &str) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let old = org_avatar_in(&tx, org)?;
        tx.execute(
            "UPDATE orgs SET avatar_blob = NULL WHERE org_id = ?1",
            [org],
        )?;
        if let Some(o) = &old {
            delete_blob_rows(&tx, std::slice::from_ref(o))?;
        }
        tx.commit()?;
        Ok(old)
    }

    /// 그 조직의 사진 blob(#554 — 디렉터리 `org.avatar`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn org_avatar(&self, org: &str) -> Result<Option<String>, DbError> {
        let mut c = self.c();
        let tx = c.transaction()?;
        org_avatar_in(&tx, org)
    }

    /// `blob.get` 인가(묶음 15): message 면 이 기기가 그 blob 이 묶인 메시지의 수신 기기, avatar 면 요청 사용자와 사진 주인이
    /// 같은 조직(#845: 또는 수락된 연락처). 맞으면 1회용 표를 저장한다. 아니면(모름·지워짐 포함) `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_grant(
        &self,
        blob_id: &str,
        user: &str,
        device_id: &str,
        token_hash: &[u8],
        exp_ms: i64,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let ok: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs b JOIN envelope_devices d ON d.msg_id = b.msg_id
                           WHERE b.blob_id = ?1 AND b.purpose = 'message' AND b.state = 'attached' AND d.device_id = ?3)
                 OR EXISTS(SELECT 1 FROM blobs b JOIN devices d ON d.device_id = b.for_device
                           WHERE b.blob_id = ?1 AND b.state = 'uploaded' AND b.for_device = ?3 AND b.user = ?2
                             AND d.user = ?2 AND d.revoked_ms IS NULL)
                 OR EXISTS(SELECT 1 FROM mls_gi_blobs g JOIN mls_groups m ON m.group_id = g.group_id
                           WHERE g.blob_id = ?1 AND instr(char(10) || m.users || char(10), char(10) || ?2 || char(10)) > 0)
                 OR EXISTS(SELECT 1 FROM mls_gi_blobs g JOIN mls_groups m ON m.group_id = g.group_id AND m.kind = 'group'
                           JOIN group_members gm ON gm.gid = m.group_id
                           WHERE g.blob_id = ?1 AND gm.user = ?2 AND gm.left_seq IS NULL)
                 OR EXISTS(SELECT 1 FROM users owner JOIN users me ON me.user = ?2 AND me.org = owner.org
                           JOIN blobs b ON b.blob_id = owner.avatar_blob AND b.state = 'uploaded'
                           WHERE owner.avatar_blob = ?1 AND owner.removed_ms IS NULL AND me.removed_ms IS NULL)
                 OR EXISTS(SELECT 1 FROM users owner JOIN links l ON l.user = ?2 AND l.peer = owner.user AND l.state = 'accepted'
                           JOIN blobs b ON b.blob_id = owner.avatar_blob AND b.state = 'uploaded'
                           WHERE owner.avatar_blob = ?1 AND owner.removed_ms IS NULL)
                 OR EXISTS(SELECT 1 FROM users owner
                           JOIN blobs b ON b.blob_id = owner.avatar_blob AND b.state = 'uploaded'
                           JOIN group_members o ON o.user = owner.user AND o.left_seq IS NULL
                           JOIN group_members mine ON mine.gid = o.gid AND mine.user = ?2 AND mine.left_seq IS NULL
                           WHERE owner.avatar_blob = ?1 AND owner.removed_ms IS NULL)
                 OR EXISTS(SELECT 1 FROM orgs o JOIN users me ON me.user = ?2 AND me.org = o.org_id
                           JOIN blobs b ON b.blob_id = o.avatar_blob AND b.state = 'uploaded'
                           WHERE o.avatar_blob = ?1 AND me.removed_ms IS NULL)",
            params![blob_id, user, device_id],
            |r| r.get(0),
        )?;
        if ok {
            tx.execute(
                "INSERT INTO blob_tickets(token_hash, blob_id, device_id, exp_ms) VALUES (?1, ?2, ?3, ?4)",
                params![token_hash, blob_id, device_id, exp_ms],
            )?;
        }
        tx.commit()?;
        Ok(ok)
    }

    /// GET 표 쓰기(묶음 15): 1회 — 지우면서 그 blob 이 경로의 것이고 안 지났는지 본다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_take_ticket(
        &self,
        token_hash: &[u8],
        blob_id: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let got: Option<(String, i64)> = self
            .c()
            .query_row(
                "DELETE FROM blob_tickets WHERE token_hash = ?1 RETURNING blob_id, exp_ms",
                [token_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(got.is_some_and(|(b, exp)| b == blob_id && exp > now_ms))
    }

    /// 이 기기가 받았다(묶음 15). 수신 기기가 아니면 `None`. 수신 기기(폐기 안 된) 모두 받았으면 그 blob 행을 지우고
    /// `Some(true)`(호출자가 파일을 지운다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_fetched(
        &self,
        blob_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<Option<bool>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        // #881 지난 대화 조각: 받을 기기나 올린 기기가 받음·치움을 알리면 바로 지운다.
        let history: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id = ?1 AND for_device IS NOT NULL
                           AND (for_device = ?2 OR device = ?2))",
            params![blob_id, device_id],
            |r| r.get(0),
        )?;
        if history {
            let gone = !delete_blob_rows(&tx, &[blob_id.to_owned()])?.is_empty();
            tx.commit()?;
            return Ok(Some(gone));
        }
        let target: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs b JOIN envelope_devices d ON d.msg_id = b.msg_id
                           WHERE b.blob_id = ?1 AND b.state = 'attached' AND d.device_id = ?2)",
            params![blob_id, device_id],
            |r| r.get(0),
        )?;
        if !target {
            return Ok(None);
        }
        tx.execute(
            "INSERT OR IGNORE INTO blob_fetch(blob_id, device_id, fetched_ms) VALUES (?1, ?2, ?3)",
            params![blob_id, device_id, now_ms],
        )?;
        let all = !tx.query_row(ALL_FETCHED_OPEN, [blob_id], |r| r.get::<_, bool>(0))?;
        let all = all && !delete_blob_rows(&tx, &[blob_id.to_owned()])?.is_empty();
        tx.commit()?;
        Ok(Some(all))
    }

    /// 그 메시지에 묶인 첨부를 지금 지운다(거두기·고치기, 묶음 15 §2.6). 지운 id(파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn take_blobs_of(&self, msg_id: &str) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let ids: Vec<String> = {
            let mut st = tx.prepare("SELECT blob_id FROM blobs WHERE msg_id = ?1")?;
            let rows = st.query_map([msg_id], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let ids = delete_blob_rows(&tx, &ids)?;
        tx.commit()?;
        Ok(ids)
    }

    /// 청소(묶음 15 §2.6, expire_tick): 시작 안 한 만료 예약, 묶이지 않은 채 `unattached_ms` 지난 것(시작했지만 안 끝난
    /// 예약 포함), 지금 사진이 아닌 옛 사진, 메시지가 만료돼 사라진 첨부, 수신 기기(폐기 안 된) 모두 받은 첨부, 만료된 표.
    /// 지운 id(파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_sweep(&self, now_ms: i64, unattached_ms: i64) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let mut ids: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT blob_id FROM blobs b WHERE
                   (state = 'reserved' AND put_token_hash IS NOT NULL AND put_token_exp <= ?1)
                   OR (state IN ('reserved','uploaded') AND purpose = 'message' AND for_device IS NULL AND created_ms + ?2 <= ?1)
                   OR (for_device IS NOT NULL AND created_ms + ?3 <= ?1)
                   OR (purpose = 'avatar' AND created_ms + ?2 <= ?1
                       AND NOT EXISTS(SELECT 1 FROM users u WHERE u.avatar_blob = b.blob_id)
                       AND NOT EXISTS(SELECT 1 FROM orgs o WHERE o.avatar_blob = b.blob_id))
                   OR (state = 'attached' AND NOT EXISTS(SELECT 1 FROM envelopes e WHERE e.msg_id = b.msg_id))",
            )?;
            let rows = st.query_map(
                params![
                    now_ms,
                    unattached_ms,
                    lodelai_protocol::constants::BLOB_HISTORY_TTL_S as i64 * 1000
                ],
                |r| r.get(0),
            )?;
            rows.collect::<Result<_, _>>()?
        };
        // 폐기로 수신 기기가 줄어 '모두 받음' 이 된 것.
        let fetched: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT b.blob_id FROM blobs b WHERE b.state = 'attached'
                   AND EXISTS(SELECT 1 FROM blob_fetch f WHERE f.blob_id = b.blob_id)",
            )?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for b in fetched {
            if !ids.contains(&b)
                && !tx.query_row(ALL_FETCHED_OPEN, [&b], |r| r.get::<_, bool>(0))?
            {
                ids.push(b);
            }
        }
        let ids = delete_blob_rows(&tx, &ids)?;
        tx.execute("DELETE FROM blob_tickets WHERE exp_ms <= ?1", [now_ms])?;
        tx.commit()?;
        Ok(ids)
    }

    /// 이 id 의 행이 있는가(청소의 고아 파일 판정, 묶음 15).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_known(&self, blob_id: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE blob_id = ?1)",
            [blob_id],
            |r| r.get(0),
        )?)
    }

    /// 파일 합계 ((첨부 바이트, 첨부 수), (프로필 사진 바이트, 사진 수)) — 서버 상태 '파일 저장 공간'(묶음 15 §2.7·§23.7: 첨부는
    /// 받으면 지워지고 사진은 남으니 따로 센다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blob_totals(&self) -> Result<(FileTotals, FileTotals), DbError> {
        Ok(self.c().query_row(
            "SELECT COALESCE(SUM(ct_len) FILTER (WHERE purpose = 'message'), 0),
                    COUNT(*) FILTER (WHERE purpose = 'message'),
                    COALESCE(SUM(ct_len) FILTER (WHERE purpose = 'avatar'), 0),
                    COUNT(*) FILTER (WHERE purpose = 'avatar') FROM blobs",
            [],
            |r| {
                let n = |i: usize| r.get::<_, i64>(i).map(|v| v.max(0) as u64);
                Ok(((n(0)?, n(1)?), (n(2)?, n(3)?)))
            },
        )?)
    }

    /// 저장된 메시지 본문(없거나 지워졌으면 `None`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn envelope_message(&self, msg_id: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT message FROM envelopes WHERE msg_id = ?1",
                [msg_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    /// 기기의 사용자(폐기된 기기도).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn device_user(&self, device_id: &str) -> Result<Option<String>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT user FROM devices WHERE device_id = ?1",
                [device_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 봉투를 그룹 맥락으로 표시한다(빠진 사람의 미전달 몫 지우기 — 묶음 16 §3a).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_envelope_gid(&self, msg_id: &str, gid: &str) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE envelopes SET gid = ?2 WHERE msg_id = ?1",
            params![msg_id, gid],
        )?;
        Ok(())
    }

    /// 그룹 응용 메시지 저장(§5d): 첨부 묶기·그룹 맥락·받을 기기(잎). `hold` 면 확정 전 Commit 의 N+1 — 확정 때 배달(§4-7).
    ///
    /// # Errors
    /// 같은 msg_id 면 Conflict, 묶을 수 없는 첨부면 BlobUnavailable, 그 밖 sqlite 오류.
    pub fn store_group_app(
        &self,
        h: &StoredHeader,
        message: &str,
        gid: &str,
        targets: &[String],
        blobs: &[String],
        hold: bool,
    ) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        for b in blobs {
            let n = tx.execute(
                "UPDATE blobs SET state = 'attached', msg_id = ?1
                 WHERE blob_id = ?2 AND user = ?3 AND purpose = 'message' AND state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL",
                params![h.msg_id, b, h.from_user],
            )?;
            if n != 1 {
                return Err(DbError::BlobUnavailable);
            }
        }
        insert_envelope(&tx, h, message, None)?;
        tx.execute(
            "UPDATE envelopes SET gid = ?2, mls_hold = ?3 WHERE msg_id = ?1",
            params![h.msg_id, gid, hold.then_some(gid)],
        )?;
        for d in targets {
            tx.execute(
                "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                params![h.msg_id, d],
            )?;
        }
        if !hold {
            drop_if_no_target(&tx, &h.msg_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 사람 op 권한(묶음 16 §2 → 22 §4-3·4·§12-13·15). Commit 을 받을 때와 확정 때 둘 다 본다.
    /// create: 그룹 없음·조직 있음·그룹 수 상한 / add: 같은 조직 멤버가, 같은 조직·차단 없음·아직 멤버 아님·50명 아래 대상
    /// remove·admin: 관리자가 멤버를(remove 는 자기 빼고) / leave: 자기(app), 또는 그 사람이 나간 기록이 있을 때 남은 멤버(commit)
    /// org_left: 조직 빠짐 기록이 있을 때 남은 멤버 / update: 멤버.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_op_allowed(&self, g: &GroupOp<'_>) -> Result<bool, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        group_op_allowed_in(&tx, g)
    }

    /// group 종류 만들기(§12-13 ①): 표 만들기 + epoch 0 공개 상태 + seq 1 을 한 트랜잭션에. 권한이 없으면 `Ok(None)`,
    /// 같은 id 의 MLS 그룹이 이미 있으면 [`DbError::Conflict`]. 단 그 그룹이 같은 사람·같은 기기가 start 한 뒤 만들기가 끝내
    /// 실패한 빈 그룹이면(epoch 0·잎은 이 기기 하나·확정 전 Commit 없음·다른 멤버 없음) 딸린 행을 모두 지우고 다시 받는다 —
    /// 사람이 같은 방을 다시 만들기(0.2.5). 돌려주는 것은 (seq, 지운 첨부 id — 파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류·묶을 수 없는 blob.
    #[allow(clippy::too_many_arguments)]
    pub fn group_create_mls(
        &self,
        gid: &str,
        sender: &str,
        storage: &[u8],
        group_info: &[u8],
        gi_pin: Option<(&GiPin, &str)>,
        leaf: &str,
        msg_id: &str,
        now_ms: i64,
    ) -> Result<Option<(u64, Vec<String>)>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let failed_start: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_groups g WHERE g.group_id = ?1 AND g.kind = 'group' AND g.epoch = 0
               AND (SELECT COUNT(*) FROM mls_leaves l WHERE l.group_id = ?1) = 1
               AND EXISTS(SELECT 1 FROM mls_leaves l WHERE l.group_id = ?1 AND l.device_id = ?2)
               AND EXISTS(SELECT 1 FROM devices d WHERE d.device_id = ?2 AND d.user = ?3)
               AND NOT EXISTS(SELECT 1 FROM mls_pending p WHERE p.group_id = ?1)
               AND NOT EXISTS(SELECT 1 FROM group_members m WHERE m.gid = ?1 AND m.user <> ?3))",
            params![gid, leaf, sender],
            |r| r.get(0),
        )?;
        let removed = if failed_start {
            drop_group_in(&tx, gid, None)?
        } else {
            Vec::new()
        };
        let g = GroupOp {
            gid,
            op: "create",
            sender,
            subject: None,
            admin: None,
            now_ms,
        };
        if !group_op_allowed_in(&tx, &g)? {
            return Ok(None);
        }
        let n = tx.execute(
            "INSERT OR IGNORE INTO mls_groups(group_id, kind, epoch, storage, group_info, created_ms, users)
             VALUES (?1, 'group', 0, ?2, ?3, ?4, NULL)",
            params![gid, storage, group_info, now_ms],
        )?;
        if n != 1 {
            return Err(DbError::Conflict);
        }
        if let Some((p, msg)) = gi_pin {
            set_gi_pin_in(&tx, gid, Some(p), msg, sender)?;
        }
        set_leaves_in(&tx, gid, std::slice::from_ref(&leaf.to_owned()))?;
        let seq = group_apply_in(&tx, &g, msg_id, now_ms)?;
        tx.commit()?;
        Ok(seq
            .and_then(|s| u64::try_from(s).ok())
            .map(|s| (s, removed)))
    }

    /// wire app 인 kind `group`(나가는 사람의 leave §12-13 ②·이름 바꾸기 §12-23): 받은 때 표에 반영하고 seq 를 매기고, 그
    /// 메시지를 `targets`(그룹 잎 − 보낸 기기) 앞으로 저장한다. `op` = `leave`(subject = 보낸 사람)·`rename`(subject 없음).
    /// 권한이 없으면 `Ok(None)`. 마지막 멤버의 leave 면 같은 트랜잭션에서 그룹을 지우고 `(seq, true)`(#532 — 그 leave 봉투만
    /// 남긴다: 나간 사람의 다른 기기가 받을 것). 그때 호출자는 duty 를 넣지 않는다.
    ///
    /// # Errors
    /// sqlite 오류·같은 msg_id.
    pub fn group_app_op_now(
        &self,
        gid: &str,
        op: &str,
        h: &StoredHeader,
        message: &str,
        targets: &[String],
        now_ms: i64,
    ) -> Result<Option<(u64, bool)>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let g = GroupOp {
            gid,
            op,
            sender: &h.from_user,
            subject: (op == "leave").then_some(h.from_user.as_str()),
            admin: None,
            now_ms,
        };
        if !group_op_allowed_in(&tx, &g)? {
            return Ok(None);
        }
        let seq = group_apply_in(&tx, &g, &h.msg_id, now_ms)?;
        insert_envelope(&tx, h, message, None)?;
        tx.execute(
            "UPDATE envelopes SET gid = ?2, group_seq = ?3 WHERE msg_id = ?1",
            params![h.msg_id, gid, seq],
        )?;
        for d in targets {
            tx.execute(
                "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                params![h.msg_id, d],
            )?;
        }
        drop_if_no_target(&tx, &h.msg_id)?;
        // #532: 지금 멤버가 없게 됐으면 그룹·딸린 MLS 상태·대기 봉투를 바로(첨부 파일은 청소가 — 행이 없으면 고아).
        let empty: bool = tx.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND left_seq IS NULL)",
            [gid],
            |r| r.get(0),
        )?;
        if empty {
            drop_group_in(&tx, gid, Some(&h.msg_id))?;
        }
        tx.commit()?;
        Ok(seq.and_then(|s| u64::try_from(s).ok()).map(|s| (s, empty)))
    }

    /// 확정 전 Commit 을 둔다(§4-7). 그 그룹에 이미 있으면 `false`(stale_epoch — 하나씩). 속도 기록도 같은 트랜잭션.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_pending_put(&self, p: &PendingCommit, recovery: bool) -> Result<bool, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO mls_pending(group_id, epoch, msg_id, commit_hash, sender_user, sender_device, op,
               subject, storage, group_info, gi_blob, gi_size, gi_sha, leaves, joining, excluded, delivered_ms,
               message, from_address, to_address, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                p.group_id,
                i64::try_from(p.epoch).unwrap_or(-1),
                p.msg_id,
                p.commit_hash,
                p.sender_user,
                p.sender_device,
                p.op,
                p.subject,
                p.storage,
                p.group_info,
                p.gi_pin.as_ref().map(|g| g.blob_id.clone()),
                p.gi_pin
                    .as_ref()
                    .map(|g| i64::try_from(g.size).unwrap_or(i64::MAX)),
                p.gi_pin.as_ref().map(|g| g.sha256.clone()),
                p.leaves.join("\n"),
                p.joining.join("\n"),
                p.excluded.join("\n"),
                p.delivered_ms,
                p.message,
                p.from_address,
                p.to_address,
                p.expires_ms
            ],
        )?;
        if n != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO mls_commits(group_id, device_id, recovery, at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![p.group_id, p.sender_device, recovery, p.delivered_ms],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// 그 그룹의 확정 전 Commit.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_pending(&self, group_id: &str) -> Result<Option<PendingCommit>, DbError> {
        let c = self.c();
        Ok(c.query_row(
            &format!("{PENDING_SELECT} WHERE group_id = ?1"),
            [group_id],
            pending_row,
        )
        .optional()?)
    }

    /// 확정 전 Commit 전부(창 판정 작업).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_pendings(&self) -> Result<Vec<PendingCommit>, DbError> {
        let c = self.c();
        let mut st = c.prepare(PENDING_SELECT)?;
        let rows = st.query_map([], pending_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 확정 전 Commit 을 지운다(저장 실패 되돌림).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_pending_drop(&self, group_id: &str, msg_id: &str) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM mls_pending WHERE group_id = ?1 AND msg_id = ?2",
            params![group_id, msg_id],
        )?;
        Ok(())
    }

    /// 응답 하나(사용자당 한 표 — ack 와 fail 은 따로 쌓고 판정에서 ack 가 이긴다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_vote(
        &self,
        group_id: &str,
        epoch: u64,
        commit_hash: &str,
        user: &str,
        ack: bool,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT INTO mls_votes(group_id, epoch, commit_hash, user, ack, fail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id, epoch, commit_hash, user) DO UPDATE SET
               ack = MAX(ack, excluded.ack), fail = MAX(fail, excluded.fail)",
            params![
                group_id,
                i64::try_from(epoch).unwrap_or(-1),
                commit_hash,
                user,
                ack,
                !ack
            ],
        )?;
        Ok(())
    }

    /// 그 Commit 의 (ack 한 사용자, fail 한 사용자) — `excluded` 는 세지 않는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_tally(
        &self,
        group_id: &str,
        epoch: u64,
        commit_hash: &str,
        excluded: &[String],
    ) -> Result<(Vec<String>, Vec<String>), DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT user, ack, fail FROM mls_votes WHERE group_id = ?1 AND epoch = ?2 AND commit_hash = ?3 ORDER BY user",
        )?;
        let rows = st.query_map(
            params![group_id, i64::try_from(epoch).unwrap_or(-1), commit_hash],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, bool>(2)?,
                ))
            },
        )?;
        let (mut acks, mut fails) = (Vec::new(), Vec::new());
        for row in rows {
            let (u, a, f) = row?;
            if excluded.contains(&u) {
                continue;
            }
            if a {
                acks.push(u);
            } else if f {
                fails.push(u);
            }
        }
        Ok((acks, fails))
    }

    /// 확정(§4-7): epoch N → N+1(merge 뒤 상태), GroupInfo·잎, 사람 op 면 표·seq, Commit 봉투에 seq·새 잎 몫(Welcome),
    /// 쥔 N+1 응용 메시지 풀기, 결과 기록. 그 사이 epoch 가 바뀌었으면 `Ok(None)`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_finalize(
        &self,
        p: &PendingCommit,
        now_ms: i64,
    ) -> Result<Option<Finalized>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let n = tx.execute(
            "UPDATE mls_groups SET epoch = epoch + 1, storage = ?3, group_info = ?4 WHERE group_id = ?1 AND epoch = ?2",
            params![
                p.group_id,
                i64::try_from(p.epoch).unwrap_or(-1),
                p.storage,
                p.group_info
            ],
        )?;
        tx.execute(
            "DELETE FROM mls_pending WHERE group_id = ?1 AND msg_id = ?2",
            params![p.group_id, p.msg_id],
        )?;
        if n != 1 {
            tx.commit()?;
            return Ok(None);
        }
        let mut removed_blobs = set_gi_pin_in(
            &tx,
            &p.group_id,
            p.gi_pin.as_ref(),
            &p.msg_id,
            &p.sender_user,
        )?;
        set_leaves_in(&tx, &p.group_id, &p.leaves)?;
        // update 는 표를 바꾸지 않아 seq 를 새로 매기지 않는다. 다만 봉투·결과에는 지금 seq 를 실어 '이미 확정'을 알린다 — 꺼져 있던
        // 기기가 접속 때 이 결과를 쌓인 봉투보다 먼저 받아 흘려도, 뒤에 온 봉투를 쥐고 기다리지 않고 바로 merge 한다(11-04).
        let seq = if p.op == "update" {
            tx.query_row(
                "SELECT seq FROM groups WHERE gid = ?1",
                [&p.group_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .filter(|s| *s > 0)
        } else {
            let g = GroupOp {
                gid: &p.group_id,
                op: &p.op,
                sender: &p.sender_user,
                subject: p.subject.as_deref(),
                admin: None,
                now_ms,
            };
            group_apply_in(&tx, &g, &p.msg_id, now_ms)?
        };
        tx.execute(
            "UPDATE envelopes SET group_seq = ?2 WHERE msg_id = ?1",
            params![p.msg_id, seq],
        )?;
        // 새 잎(Welcome)은 확정 뒤에만(§5d). 옛 잎이 모두 받아 봉투가 지워졌으면 되살린다(새 잎이 있을 때).
        let mut welcome = Vec::new();
        let mut commit_message = None;
        if !p.joining.is_empty() {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM envelopes WHERE msg_id = ?1)",
                [&p.msg_id],
                |r| r.get(0),
            )?;
            if exists {
                tx.execute(
                    "UPDATE envelopes SET message = ?2 WHERE msg_id = ?1 AND message IS NULL",
                    params![p.msg_id, p.message],
                )?;
            } else {
                let h = StoredHeader {
                    msg_id: p.msg_id.clone(),
                    kind: "group".into(),
                    from_user: p.sender_user.clone(),
                    from_address: p.from_address.clone(),
                    to_user: format!("+{}", p.group_id),
                    to_address: p.to_address.clone(),
                    expires_ms: p.expires_ms,
                    env_state: lodelai_statechart::envelope_server::INITIAL
                        .as_str()
                        .to_owned(),
                    sender_view: lodelai_statechart::request_sender_view::State::Stored
                        .as_str()
                        .to_owned(),
                    abort_reason: None,
                };
                insert_envelope(&tx, &h, &p.message, Some(&p.group_id))?;
            }
            tx.execute(
                "UPDATE envelopes SET gid = ?2, group_seq = ?3 WHERE msg_id = ?1",
                params![p.msg_id, p.group_id, seq],
            )?;
            for d in &p.joining {
                tx.execute(
                    "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                    params![p.msg_id, d],
                )?;
                welcome.push(d.clone());
            }
            commit_message = Some(p.message.clone());
        }
        // 다시 잎이 된 기기의 rejoin 표시는 확정 때 지운다(설계 ⑧ 권고).
        for d in p.joining.iter().chain(std::iter::once(&p.sender_device)) {
            tx.execute(
                "DELETE FROM mls_rejoin WHERE device_id = ?1 AND group_id = ?2",
                params![d, p.group_id],
            )?;
        }
        // 0.2.6 #809 §1-9 (다): 다시 보낸 본문을 둔 뒤 그 기기가 스스로 다시 들었다(external commit 은 op update) — 그 본문을
        // 또 못 열어도 final 이 아니라 한 번 더 알린다.
        if p.op == "update" {
            tx.execute(
                "UPDATE unreadable_reports SET rejoined = 1
                 WHERE device_id = ?1 AND group_id = ?2 AND message IS NOT NULL",
                params![p.sender_device, p.group_id],
            )?;
        }
        // 쥔 N+1 응용 메시지: 새 잎(보낸 기기 빼고)에게 풀어 준다.
        let held: Vec<(String, String, Option<String>)> = {
            let mut st = tx.prepare(
                "SELECT msg_id, message, json_extract(message, '$.from.device_id') FROM envelopes
                 WHERE mls_hold = ?1 AND message IS NOT NULL ORDER BY seq",
            )?;
            let rows = st.query_map([&p.group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut released = Vec::new();
        for (msg_id, message, sender) in held {
            for d in p.leaves.iter().filter(|d| Some(*d) != sender.as_ref()) {
                tx.execute(
                    "INSERT OR IGNORE INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
                    params![msg_id, d],
                )?;
            }
            tx.execute(
                "UPDATE envelopes SET mls_hold = NULL WHERE msg_id = ?1",
                [&msg_id],
            )?;
            let targets: Vec<String> = {
                let mut st = tx.prepare(
                    "SELECT device_id FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL",
                )?;
                let rows = st.query_map([&msg_id], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            released.push((message, targets));
        }
        // 받을 기기가 끝내 없는 Commit(새 잎 없음·지금 잎 없음)은 확정과 함께 지운다 — 30일 남지 않게(h4 리뷰 🟡).
        removed_blobs.extend(drop_if_no_target(&tx, &p.msg_id)?);
        put_outcome_in(&tx, p, true, seq, now_ms)?;
        removed_blobs.extend(drop_empty_groups_in(&tx)?);
        removed_blobs.sort();
        tx.commit()?;
        Ok(Some(Finalized {
            group_seq: seq.and_then(|s| u64::try_from(s).ok()),
            commit_message,
            welcome,
            released,
            removed_blobs,
        }))
    }

    /// 그 그룹의 duty 순서를 비운다(#577 — 무효가 된 Commit 뒤 남은 일을 다시 나눠 주게).
    ///
    /// # Errors
    /// DB 오류.
    pub fn duty_ranks_reset(&self, group_id: &str) -> Result<(), DbError> {
        self.c()
            .execute("DELETE FROM mls_duty_ranks WHERE group_id = ?1", [group_id])?;
        Ok(())
    }

    /// 무효(§4-7): 확정 전 Commit 을 버리고, 아직 받지 않은 기기 몫을 지우고, 쥔 N+1 응용 메시지를 지운다(보낸 기기마다
    /// `nack commit_void` — 꺼져 있으면 접속 때). 돌려주는 값: (보낸 기기, msg_id) 와 지운 blob.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_void(&self, p: &PendingCommit, now_ms: i64) -> Result<Voided, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        tx.execute(
            "DELETE FROM mls_pending WHERE group_id = ?1 AND msg_id = ?2",
            params![p.group_id, p.msg_id],
        )?;
        tx.execute(
            "DELETE FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL",
            [&p.msg_id],
        )?;
        let mut removed_blobs = drop_if_no_target(&tx, &p.msg_id)?;
        let held: Vec<(String, Option<String>)> = {
            let mut st = tx.prepare(
                "SELECT msg_id, json_extract(message, '$.from.device_id') FROM envelopes WHERE mls_hold = ?1",
            )?;
            let rows = st.query_map([&p.group_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut nacks = Vec::new();
        for (msg_id, dev) in held {
            removed_blobs.extend(drop_blobs_of(&tx, &msg_id)?);
            tx.execute("DELETE FROM envelope_devices WHERE msg_id = ?1", [&msg_id])?;
            tx.execute("DELETE FROM envelopes WHERE msg_id = ?1", [&msg_id])?;
            if let Some(d) = dev {
                tx.execute(
                    "INSERT OR IGNORE INTO mls_void_nacks(device_id, msg_id, at_ms) VALUES (?1, ?2, ?3)",
                    params![d, msg_id, now_ms],
                )?;
                nacks.push((d, msg_id));
            }
        }
        put_outcome_in(&tx, p, false, None, now_ms)?;
        tx.commit()?;
        Ok(Voided {
            nacks,
            removed_blobs,
        })
    }

    /// 관리자 기기 앞 알림 저장(꺼져 있던 기기 — 접속 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_alert_put(
        &self,
        device_id: &str,
        group_id: &str,
        hash: &str,
        frame: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_alerts(device_id, group_id, hash, frame, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device_id, group_id, hash, frame, now_ms],
        )?;
        Ok(())
    }

    /// 그 기기 앞 저장된 알림을 꺼낸다(지운다). 30일 지난 것은 버린다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_alerts_take(&self, device_id: &str, now_ms: i64) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "DELETE FROM mls_alerts WHERE at_ms < ?1",
            [now_ms - OUTCOME_KEEP_MS],
        )?;
        let out: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT frame FROM mls_alerts WHERE device_id = ?1 ORDER BY at_ms, group_id, hash",
            )?;
            let rows = st.query_map([device_id], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        tx.execute("DELETE FROM mls_alerts WHERE device_id = ?1", [device_id])?;
        tx.commit()?;
        Ok(out)
    }

    /// 보낸 nack commit_void 를 지운다(접속 중인 기기에 바로 갔을 때·접속 때 보낸 뒤).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_void_nack_done(&self, device_id: &str, msg_id: &str) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM mls_void_nacks WHERE device_id = ?1 AND msg_id = ?2",
            params![device_id, msg_id],
        )?;
        Ok(())
    }

    /// 그 기기 앞으로 남은 nack commit_void(msg_id) — 30일 지난 것은 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_void_nacks_for(&self, device_id: &str, now_ms: i64) -> Result<Vec<String>, DbError> {
        let c = self.c();
        c.execute(
            "DELETE FROM mls_void_nacks WHERE at_ms < ?1",
            [now_ms - OUTCOME_KEEP_MS],
        )?;
        let mut st = c.prepare(
            "SELECT msg_id FROM mls_void_nacks WHERE device_id = ?1 ORDER BY at_ms, msg_id",
        )?;
        let rows = st.query_map([device_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그 기기가 잎인 그룹들의 마지막 결과(§12-14 — 접속 때 다시 보냄, 30일).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_outcomes_for(&self, device_id: &str, now_ms: i64) -> Result<Vec<Outcome>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT o.group_id, o.epoch, o.commit_hash, o.final, o.group_seq FROM mls_outcomes o
               JOIN mls_leaves l ON l.group_id = o.group_id AND l.device_id = ?1
             WHERE o.at_ms >= ?2 ORDER BY o.group_id",
        )?;
        let rows = st.query_map(params![device_id, now_ms - OUTCOME_KEEP_MS], |r| {
            Ok(Outcome {
                group_id: r.get(0)?,
                epoch: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                commit_hash: r.get(2)?,
                is_final: r.get(3)?,
                group_seq: r
                    .get::<_, Option<i64>>(4)?
                    .and_then(|s| u64::try_from(s).ok()),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 확정 뒤 fail(§4-7): 그 Commit 의 자격 있는 fail 사용자가 둘 이상이고 아직 알리지 않았으면 알린 것으로 표시하고
    /// (보낸 사람, fail 수, ack 한 사용자, 관리자들)을 돌려준다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mls_unprocessed(
        &self,
        group_id: &str,
        epoch: u64,
        commit_hash: &str,
    ) -> Result<Option<Unprocessed>, DbError> {
        let row: Option<(String, String)> = self
            .c()
            .query_row(
                "SELECT sender_user, excluded FROM mls_outcomes
                 WHERE group_id = ?1 AND epoch = ?2 AND commit_hash = ?3 AND final = 1 AND notified = 0",
                params![group_id, i64::try_from(epoch).unwrap_or(-1), commit_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((sender, excluded)) = row else {
            return Ok(None);
        };
        let excluded: Vec<String> = split_lines(&excluded);
        let (acks, fails) = self.mls_tally(group_id, epoch, commit_hash, &excluded)?;
        if fails.len() < 2 {
            return Ok(None);
        }
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        tx.execute(
            "UPDATE mls_outcomes SET notified = 1 WHERE group_id = ?1",
            [group_id],
        )?;
        let admins: Vec<String> = group_members_in(&tx, group_id)?
            .into_iter()
            .filter(|(_, a)| *a)
            .map(|(m, _)| m)
            .collect();
        tx.commit()?;
        Ok(Some(Unprocessed {
            sender,
            failed: fails.len() as u64,
            acked: acks,
            admins,
        }))
    }

    /// 그룹 라우팅 판단(묶음 16): 그 그룹의 조직, 지금 멤버, 그 멤버들의 폐기 안 된 기기. 없는 그룹이면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_view(&self, gid: &str) -> Result<Option<GroupView>, DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let org: Option<String> = tx
            .query_row("SELECT org FROM groups WHERE gid = ?1", [gid], |r| r.get(0))
            .optional()?;
        let Some(org) = org else {
            return Ok(None);
        };
        let members: Vec<String> = group_members_in(&tx, gid)?
            .into_iter()
            .map(|(m, _)| m)
            .collect();
        let devices = live_devices_in(&tx, &members)?;
        Ok(Some(GroupView {
            org,
            members,
            devices,
        }))
    }

    /// 내가 지금 멤버인 그룹과 마지막 seq, 조직 빠짐으로 나간 멤버 (아이디, left_seq)(묶음 16 `groups`, §3a ④). 만들기
    /// Commit 이 확정되지 않은 그룹(seq 1 — start 만 받음)은 뺀다(#817): 만들기가 실패한 빈 그룹을 만든 사람의 다른 기기가
    /// 스스로 들기(§7) 후보로 보고 external commit 으로 들어가지 않게. #845 §7-29: 단 들어가는 중(수락한 초대)인 사람이 있으면
    /// 넣는다 — 넣을 사람 없이 시작만으로 만든 혼자 그룹에 초대로 들일 때 멤버 기기가 joining 을 받아야 Add 를 낸다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn groups_of(&self, user: &str) -> Result<Vec<GroupRow>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT g.gid, g.seq FROM groups g JOIN group_members m ON m.gid = g.gid
             WHERE m.user = ?1 AND m.left_seq IS NULL
               AND (g.seq > 1 OR EXISTS(SELECT 1 FROM group_invites i
                                        WHERE i.gid = g.gid AND i.user IS NOT NULL AND i.accepted_ms IS NOT NULL))
             ORDER BY g.gid",
        )?;
        let rows = st
            .query_map([user], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        // #845 ④: 조직 빠짐 힌트는 그 사람과 같은 조직이던 멤버에게만 — 다른 조직 멤버에겐 보통 빠짐(Commit)으로만 보인다.
        let mut left = c.prepare(
            "SELECT user, left_seq FROM group_members WHERE gid = ?1 AND org_left = 1 AND left_seq IS NOT NULL
               AND (left_org IS NULL OR left_org = (SELECT org FROM users WHERE user = ?2))
             ORDER BY left_seq, user",
        )?;
        let mut joining = c.prepare(
            "SELECT user FROM group_invites WHERE gid = ?1 AND user IS NOT NULL AND accepted_ms IS NOT NULL
             ORDER BY accepted_ms, user",
        )?;
        rows.into_iter()
            .map(|(gid, seq)| {
                let org_left = left
                    .query_map(params![&gid, user], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let joining = joining
                    .query_map([&gid], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(GroupRow {
                    gid,
                    seq,
                    org_left,
                    joining,
                })
            })
            .collect()
    }

    /// `groups.replay`(묶음 16): 그 그룹의 `from_seq` 부터 group 메시지 중 아직 보관 중이고 이 기기가 받지 않은 수신
    /// 기기인 것(본문, seq). 지금 멤버가 아니면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_replay(
        &self,
        gid: &str,
        user: &str,
        device_id: &str,
        from_seq: u64,
    ) -> Result<Option<Vec<(String, u64)>>, DbError> {
        let c = self.c();
        let member: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = ?2 AND left_seq IS NULL)",
            params![gid, user],
            |r| r.get(0),
        )?;
        if !member {
            return Ok(None);
        }
        let mut st = c.prepare(
            "SELECT e.message, l.seq FROM group_log l JOIN envelopes e ON e.msg_id = l.msg_id
             WHERE l.gid = ?1 AND l.seq >= ?2 AND e.message IS NOT NULL
               AND EXISTS(SELECT 1 FROM envelope_devices d WHERE d.msg_id = e.msg_id AND d.device_id = ?3 AND d.acked_ms IS NULL)
             ORDER BY l.seq",
        )?;
        let rows = st.query_map(
            params![gid, i64::try_from(from_seq).unwrap_or(i64::MAX), device_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64)),
        )?;
        Ok(Some(rows.collect::<Result<_, _>>()?))
    }

    /// 그 기기가 그 봉투의 수신 기기인가(묶음 16 — 그룹 메시지의 ack·status 는 to_user 가 아니라 기기 행으로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn is_target_device(&self, msg_id: &str, device_id: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND device_id = ?2)",
            params![msg_id, device_id],
            |r| r.get(0),
        )?)
    }

    /// 그 봉투의 group_seq(같은 msg_id 재생 ack 가 같은 seq 를 싣게).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_seq_of(&self, msg_id: &str) -> Result<Option<u64>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT group_seq FROM envelopes WHERE msg_id = ?1",
                [msg_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .and_then(|s| u64::try_from(s).ok()))
    }

    /// 다시 받을 수 없게 된 로그 행(본문이 지워졌거나 만료된 봉투)을 지운다(묶음 16 §2 정리).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_log_sweep(&self) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM group_log WHERE msg_id NOT IN (SELECT msg_id FROM envelopes WHERE message IS NOT NULL)",
            [],
        )?)
    }

    /// 만들기가 끝내 실패한 빈 그룹(#805, 묶음 22 §12-26 ②)을 지운다: kind `group`·`groups.seq` 가 start 만 반영한 1(create
    /// Commit 이 확정된 적 없음)·확정 전 Commit 없음·지금 멤버 하나 이하·`created_ms + older_than_ms` 가 지남. 만들기는 처음
    /// 멤버가 둘 이상이라 이 꼴은 다시 만들지 않고 둔 실패뿐이다. epoch·잎 수는 보지 않는다 — 만든 사람의 다른 기기가 스스로
    /// 들거나(external commit) 주기 update 가 확정돼도 op `update` 는 seq 를 올리지 않아(`mls_finalize`) 그대로 걸린다. 같은
    /// 기기의 다시 start(`group_create_mls`)는 기한 전엔 이 행을 지우고 다시 받고, 기한 뒤엔 행이 없어 새로 받는다.
    /// #845 §7-29: 살아 있는 그룹 초대(답 기다림·들어가는 중, 30일 안)가 걸린 그룹은 남긴다.
    /// (지운 그룹 수, 지운 첨부 id — 파일은 호출자가).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn failed_group_starts_sweep(
        &self,
        now_ms: i64,
        older_than_ms: i64,
    ) -> Result<(usize, Vec<String>), DbError> {
        let mut conn = self.c();
        let tx = immediate(&mut conn)?;
        let gids: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT g.group_id FROM mls_groups g JOIN groups t ON t.gid = g.group_id
                 WHERE g.kind = 'group' AND t.seq = 1 AND g.created_ms + ?2 <= ?1
                   AND NOT EXISTS(SELECT 1 FROM mls_pending p WHERE p.group_id = g.group_id)
                   AND NOT EXISTS(SELECT 1 FROM group_invites i WHERE i.gid = g.group_id AND i.at_ms > ?1 - ?3)
                   AND (SELECT COUNT(*) FROM group_members m
                        WHERE m.gid = g.group_id AND m.left_seq IS NULL) <= 1
                 ORDER BY g.group_id",
            )?;
            let rows =
                st.query_map(params![now_ms, older_than_ms, LINK_EXPIRE_MS], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut removed = Vec::new();
        for gid in &gids {
            removed.extend(drop_group_in(&tx, gid, None)?);
        }
        tx.commit()?;
        Ok((gids.len(), removed))
    }

    /// 거두기·고치기(묶음 14 #403·#404, `drop_unacked_devices`): 아직 받지 않은 기기 몫을 지우고, 남은 대상(모두 받은
    /// 기기)이 없으니 본문도 지운다. 헤더는 `expires_at` 까지 남는다. 돌려주는 값: 원래 수신 기기 전부(받은 기기 포함).
    /// 대상 행이 없는 옛 봉투면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn withdraw_envelope(&self, msg_id: &str) -> Result<Option<Vec<String>>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let devices: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT device_id FROM envelope_devices WHERE msg_id = ?1 ORDER BY device_id",
            )?;
            let rows = st.query_map([msg_id], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        tx.execute(
            "DELETE FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL",
            [msg_id],
        )?;
        tx.execute(
            "UPDATE envelopes SET message = NULL WHERE msg_id = ?1",
            [msg_id],
        )?;
        tx.commit()?;
        truncate_wal(&c);
        Ok((!devices.is_empty()).then_some(devices))
    }

    /// #598 ②: 판 10 글을 전하지 않은 판 9 기기를 표시한다(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_mark(
        &self,
        msg_id: &str,
        from_user: &str,
        from_device: &str,
        devices: &[String],
        expires_ms: i64,
    ) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        for d in devices {
            tx.execute(
                "INSERT OR IGNORE INTO outdated_devices(msg_id, device_id, from_user, from_device, expires_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![msg_id, d, from_user, from_device, expires_ms],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 그 보낸 기기에 아직 알리지 않은 표시(msg_id 마다 하나, 만든 순) — 알린 것으로 바꾼다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_take_notices(&self, from_device: &str) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        // send 마다 불린다 — 없으면 쓰기 잠금 없이 바로.
        let any: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM outdated_devices WHERE from_device = ?1 AND notified = 0)",
            [from_device],
            |r| r.get(0),
        )?;
        if !any {
            return Ok(Vec::new());
        }
        let tx = immediate(&mut c)?;
        let ids: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT msg_id FROM outdated_devices WHERE from_device = ?1 AND notified = 0
                 GROUP BY msg_id ORDER BY MIN(rowid)",
            )?;
            let rows = st.query_map([from_device], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        tx.execute(
            "UPDATE outdated_devices SET notified = 1 WHERE from_device = ?1 AND notified = 0",
            [from_device],
        )?;
        tx.commit()?;
        Ok(ids)
    }

    /// 같은 보낸 사람의 다시 보내기를 기다리는 표시가 있나(message 가 빈 행).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_waiting(&self, msg_id: &str, from_user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM outdated_devices WHERE msg_id = ?1 AND from_user = ?2 AND message IS NULL)",
            params![msg_id, from_user],
            |r| r.get(0),
        )?)
    }

    /// 다시 보낸 v9 를 표시된 기기(폐기 안 됨) 몫으로 둔다 — 그 기기들을 돌려준다. 원래 봉투는 건드리지 않는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_fill(
        &self,
        msg_id: &str,
        from_user: &str,
        message: &str,
        group_seq: Option<u64>,
    ) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let seq = group_seq.and_then(|s| i64::try_from(s).ok());
        let devices: Vec<String> = {
            let mut st = tx.prepare(
                "UPDATE outdated_devices SET message = ?3, group_seq = ?4
                 WHERE msg_id = ?1 AND from_user = ?2 AND message IS NULL
                   AND device_id IN (SELECT device_id FROM devices WHERE revoked_ms IS NULL)
                 RETURNING device_id",
            )?;
            let rows = st.query_map(params![msg_id, from_user, message, seq], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        tx.commit()?;
        Ok(devices)
    }

    /// 다시 보낸 v9 를 받은 기기의 ack — 그 기기의 곁 행이면 기록하고 참(원래 봉투의 상태는 움직이지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_ack(
        &self,
        msg_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE outdated_devices SET acked_ms = ?3
             WHERE msg_id = ?1 AND device_id = ?2 AND message IS NOT NULL AND acked_ms IS NULL",
            params![msg_id, device_id, now_ms],
        )? > 0)
    }

    /// 보관 기한이 지난 표시를 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM outdated_devices WHERE expires_ms <= ?1 OR acked_ms IS NOT NULL",
            [now_ms],
        )?)
    }

    /// 보통 길로 다시 받은 글(모두 판 9 라 원래 봉투를 남기지 않은 경우)의 표시를 지운다 — 남으면 같은 글을 한 번 더 보냈을 때
    /// 곁 표로 가로채 판 9 기기에 두 번 간다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn outdated_clear(&self, msg_id: &str, from_user: &str) -> Result<(), DbError> {
        self.c().execute(
            "DELETE FROM outdated_devices WHERE msg_id = ?1 AND from_user = ?2",
            params![msg_id, from_user],
        )?;
        Ok(())
    }

    /// 0.2.6 #809: 그 기기의 못 엶 보고(`delivered_ack.unreadable`)를 적는다. 보낸 사람에게 알리는 것은 [`Self::unreadable_due`]
    /// 로 따로 한다(계약 §1-2·§1-9). 받아들이지 않으면 보통 ack 로 다룬다 — 헤더가 없거나 만료됨, 이 기기가 받는 대상이 아님(보낼
    /// 때 정해진 기기 행 없음), 이미 받음, 시간당 `max_per_hour` 넘음.
    ///
    /// 처음 보고면 n=1 행. 다시 보낸 것(곁 본문이 이 기기에 간 뒤)의 보고면: 그 기기가 다시 보낸 본문 저장 뒤 스스로 다시 들었고
    /// (`rejoined`) 알림이 아직 둘 아래면 n=1 로 한 번 더(§1-9 (다)), 아니면 n=2(final). 그 밖(알림 기다리는 중·final 뒤)은 그대로.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_report(
        &self,
        msg_id: &str,
        device_id: &str,
        now_ms: i64,
        max_per_hour: i64,
    ) -> Result<UnreadableReport, DbError> {
        const HOUR: i64 = 60 * 60 * 1000;
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let row: Option<(i64, i64, Option<i64>, i64, i64)> = tx
            .query_row(
                "SELECT n, notified, CASE WHEN message IS NULL THEN NULL ELSE 1 END, rejoined, sent
                 FROM unreadable_reports WHERE msg_id = ?1 AND device_id = ?2",
                params![msg_id, device_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        if let Some((n, _, resent, rejoined, sent)) = row {
            // 다시 보낸 것이 이 기기에 간 뒤의 보고만 센다.
            if n >= 2 || resent.is_none() {
                return Ok(UnreadableReport::Plain);
            }
            let again = rejoined != 0 && sent < 2;
            tx.execute(
                "UPDATE unreadable_reports SET n = ?3, at_ms = ?4, notified = 0, rejoined = 0,
                   message = CASE WHEN ?3 = 1 THEN NULL ELSE message END,
                   group_seq = CASE WHEN ?3 = 1 THEN NULL ELSE group_seq END,
                   acked_ms = CASE WHEN ?3 = 1 THEN NULL ELSE ?4 END
                 WHERE msg_id = ?1 AND device_id = ?2",
                params![msg_id, device_id, if again { 1 } else { 2 }, now_ms],
            )?;
            tx.commit()?;
            return Ok(UnreadableReport::Recorded);
        }
        let head: Option<(String, i64, Option<String>)> = tx
            .query_row(
                "SELECT from_user, expires_ms, COALESCE(gid, json_extract(message, '$.mls_group'))
                 FROM envelopes WHERE msg_id = ?1",
                [msg_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((from_user, expires_ms, Some(group_id))) = head else {
            return Ok(UnreadableReport::Plain);
        };
        if expires_ms <= now_ms {
            return Ok(UnreadableReport::Plain);
        }
        let target: Option<Option<i64>> = tx
            .query_row(
                "SELECT acked_ms FROM envelope_devices WHERE msg_id = ?1 AND device_id = ?2",
                params![msg_id, device_id],
                |r| r.get(0),
            )
            .optional()?;
        match target {
            None => return Ok(UnreadableReport::NotTarget),
            Some(Some(_)) => return Ok(UnreadableReport::Plain),
            Some(None) => {}
        }
        let Some(to_user) = tx
            .query_row(
                "SELECT user FROM devices WHERE device_id = ?1",
                [device_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        else {
            return Ok(UnreadableReport::NotTarget);
        };
        let recent: i64 = tx.query_row(
            "SELECT COUNT(*) FROM unreadable_reports WHERE device_id = ?1 AND at_ms > ?2",
            params![device_id, now_ms - HOUR],
            |r| r.get(0),
        )?;
        if recent >= max_per_hour {
            return Ok(UnreadableReport::Limited);
        }
        // 같은 사람의 다른 기기가 이미 열었나(보고 없이 받은 기기, 또는 앞서 연 표시).
        let opened: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM envelope_devices ed JOIN devices d ON d.device_id = ed.device_id
                 WHERE ed.msg_id = ?1 AND d.user = ?2 AND ed.device_id <> ?3 AND ed.acked_ms IS NOT NULL
                   AND NOT EXISTS(SELECT 1 FROM unreadable_reports r WHERE r.msg_id = ?1 AND r.device_id = ed.device_id))
               OR EXISTS(SELECT 1 FROM unreadable_reports WHERE msg_id = ?1 AND to_user = ?2 AND opened = 1)",
            params![msg_id, to_user, device_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO unreadable_reports(msg_id, device_id, from_user, to_user, group_id, n, at_ms, expires_ms, opened)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
            params![msg_id, device_id, from_user, to_user, group_id, now_ms, expires_ms, opened],
        )?;
        tx.commit()?;
        Ok(UnreadableReport::Recorded)
    }

    /// 0.2.6 #809: 그 기기가 그 글을 보통 ack 했다(열었다) — 같은 사람의 보고 행에 opened, 그 기기 행은 닫는다(알리지 않음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_opened(
        &self,
        msg_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<(), DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        tx.execute(
            "UPDATE unreadable_reports SET opened = 1
             WHERE msg_id = ?1 AND to_user = (SELECT user FROM devices WHERE device_id = ?2)",
            params![msg_id, device_id],
        )?;
        tx.execute(
            "UPDATE unreadable_reports SET notified = 1, n = 2, acked_ms = COALESCE(acked_ms, ?3)
             WHERE msg_id = ?1 AND device_id = ?2",
            params![msg_id, device_id, now_ms],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 0.2.6 #809: 알릴 때가 된 보고 — 아직 알리지 않았고, 보고한 지 `settle_ms` 가 지났고(§1-9 (나)), 그 기기가 그 대화의 지금 잎이며
    /// 다시 들기 표시(`mls_rejoin`)도, 그 기기가 보낸 확정 전 Commit(§1-9 (가))도 없는 것.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_due(
        &self,
        now_ms: i64,
        settle_ms: i64,
    ) -> Result<Vec<UnreadableDue>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT r.msg_id, r.device_id, r.from_user, r.to_user, r.n, r.opened FROM unreadable_reports r
             WHERE r.notified = 0 AND r.at_ms + ?2 <= ?1 AND r.expires_ms > ?1
               AND EXISTS(SELECT 1 FROM mls_leaves l WHERE l.group_id = r.group_id AND l.device_id = r.device_id)
               AND NOT EXISTS(SELECT 1 FROM mls_rejoin j WHERE j.group_id = r.group_id AND j.device_id = r.device_id)
               AND NOT EXISTS(SELECT 1 FROM mls_pending p WHERE p.group_id = r.group_id AND p.sender_device = r.device_id)
             ORDER BY r.at_ms, r.msg_id, r.device_id",
        )?;
        let rows = st.query_map(params![now_ms, settle_ms], |r| {
            Ok(UnreadableDue {
                msg_id: r.get(0)?,
                device_id: r.get(1)?,
                from_user: r.get(2)?,
                to_user: r.get(3)?,
                final_: r.get::<_, i64>(4)? >= 2,
                opened: r.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 0.2.6 #809: 그 보고를 알렸다(`sent` = 실제로 보냈나 — opened 로 닫은 final 은 세지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_notified(
        &self,
        msg_id: &str,
        device_id: &str,
        sent: bool,
    ) -> Result<(), DbError> {
        self.c().execute(
            "UPDATE unreadable_reports SET notified = 1, sent = sent + ?3 WHERE msg_id = ?1 AND device_id = ?2",
            params![msg_id, device_id, i64::from(sent)],
        )?;
        Ok(())
    }

    /// 0.2.6 #809: 그 보낸 사람이 같은 msg_id 로 다시 보내면 받을 보고(알렸고 n=1·아직 다시 받지 않음)가 있나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_waiting(&self, msg_id: &str, from_user: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM unreadable_reports
               WHERE msg_id = ?1 AND from_user = ?2 AND n = 1 AND notified = 1 AND message IS NULL)",
            params![msg_id, from_user],
            |r| r.get(0),
        )?)
    }

    /// 0.2.6 #809 §1-3: 다시 보낸 본문을 보고한 기기 몫으로 둔다 — 그 대화(`group_id`)의 지금 잎이고 폐기 안 됐고, 그룹이면 그
    /// 사람이 지금 멤버인 기기만. 그 기기들을 돌려준다. 원래 봉투는 건드리지 않는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_fill(
        &self,
        msg_id: &str,
        from_user: &str,
        group_id: &str,
        message: &str,
        group_seq: Option<u64>,
    ) -> Result<Vec<String>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let seq = group_seq.and_then(|s| i64::try_from(s).ok());
        let devices: Vec<String> = {
            let mut st = tx.prepare(
                "UPDATE unreadable_reports SET message = ?4, group_seq = ?5
                 WHERE msg_id = ?1 AND from_user = ?2 AND group_id = ?3 AND n = 1 AND notified = 1 AND message IS NULL
                   AND device_id IN (SELECT device_id FROM devices WHERE revoked_ms IS NULL)
                   AND device_id IN (SELECT device_id FROM mls_leaves WHERE group_id = ?3)
                   AND (NOT EXISTS(SELECT 1 FROM groups WHERE gid = ?3)
                        OR EXISTS(SELECT 1 FROM group_members m
                                  WHERE m.gid = ?3 AND m.user = unreadable_reports.to_user AND m.left_seq IS NULL))
                 RETURNING device_id",
            )?;
            let rows = st.query_map(params![msg_id, from_user, group_id, message, seq], |r| {
                r.get(0)
            })?;
            rows.collect::<Result<_, _>>()?
        };
        tx.commit()?;
        Ok(devices)
    }

    /// 0.2.6 #809: 그 기기가 다시 보낸 본문을 받았다(ack 의 종류와 상관없이 곁 배달을 멈춘다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_side_acked(
        &self,
        msg_id: &str,
        device_id: &str,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        Ok(self.c().execute(
            "UPDATE unreadable_reports SET acked_ms = ?3
             WHERE msg_id = ?1 AND device_id = ?2 AND message IS NOT NULL AND acked_ms IS NULL",
            params![msg_id, device_id, now_ms],
        )? > 0)
    }

    /// 보관 기한이 지난 보고를 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unreadable_sweep(&self, now_ms: i64) -> Result<usize, DbError> {
        Ok(self.c().execute(
            "DELETE FROM unreadable_reports WHERE expires_ms <= ?1",
            [now_ms],
        )?)
    }

    /// 그 기기 앞으로 남아 있고 아직 ack 하지 않은 수신 봉투(저장 순, protocol §7.2-6). 대상 행이 없는 옛 봉투는
    /// 어느 기기에나 간다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pending_for(
        &self,
        user: &str,
        device_id: &str,
    ) -> Result<Vec<(String, Option<u64>)>, DbError> {
        let c = self.c();
        // 기기 행이 있으면 받는 사용자와 무관하게(그룹 메시지는 여러 사용자의 기기로 간다, 묶음 16).
        let mut st = c.prepare(
            // 대상 기기 행이 있으면 받는 사용자와 상관없이 그 기기 몫(묶음 22 MLS 는 보낸 사람의 다른 기기도 잎이다).
            "SELECT e.message, e.group_seq FROM envelopes e WHERE e.message IS NOT NULL AND e.mls_hold IS NULL
               AND (EXISTS(SELECT 1 FROM envelope_devices d
                           WHERE d.msg_id = e.msg_id AND d.device_id = ?2 AND d.acked_ms IS NULL)
                    OR (e.to_user = ?1 AND NOT EXISTS(SELECT 1 FROM envelope_devices d WHERE d.msg_id = e.msg_id)))
             ORDER BY e.seq",
        )?;
        let rows = st.query_map(params![user, device_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?
                    .and_then(|s| u64::try_from(s).ok()),
            ))
        })?;
        let mut out: Vec<(String, Option<u64>)> = rows.collect::<Result<_, _>>()?;
        // #598 ②: 판 9 라 따로 다시 받은 글(곁 표) — 그 기기 몫만.
        let mut st = c.prepare(
            "SELECT message, group_seq FROM outdated_devices
             WHERE device_id = ?1 AND message IS NOT NULL AND acked_ms IS NULL ORDER BY rowid",
        )?;
        let side = st.query_map([device_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?
                    .and_then(|s| u64::try_from(s).ok()),
            ))
        })?;
        for row in side {
            out.push(row?);
        }
        // 0.2.6 #809: 못 엶 보고 뒤 다시 보낸 글(곁 표) — 보고한 그 기기 몫만.
        let mut st = c.prepare(
            "SELECT message, group_seq FROM unreadable_reports
             WHERE device_id = ?1 AND message IS NOT NULL AND acked_ms IS NULL ORDER BY at_ms, msg_id",
        )?;
        let side = st.query_map([device_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?
                    .and_then(|s| u64::try_from(s).ok()),
            ))
        })?;
        for row in side {
            out.push(row?);
        }
        Ok(out)
    }

    /// 전달을 기다리는 봉투 수(`server.status.queue.pending` — 받는 사람별로 나누지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pending_count(&self) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM envelopes WHERE message IS NOT NULL",
            [],
            |r| r.get(0),
        )?)
    }

    /// 그 조직(내보내지 않은 사람)의 폐기되지 않은 기기 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn live_device_count(&self, org: &str) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM devices d JOIN users u ON u.user = d.user
             WHERE u.org = ?1 AND u.removed_ms IS NULL AND d.revoked_ms IS NULL",
            [org],
            |r| r.get(0),
        )?)
    }

    /// 조직의 (내보내지 않은) 사람 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn member_count(&self, org: &str) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM users WHERE org = ?1 AND removed_ms IS NULL",
            [org],
            |r| r.get(0),
        )?)
    }

    /// `expires_ms <= now` 인 헤더들.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn expired(&self, now_ms: i64) -> Result<Vec<StoredHeader>, DbError> {
        let ids: Vec<String> = {
            let c = self.c();
            let mut st =
                // Handshake 는 §5a 로만 지운다(expire_handshakes).
                c.prepare("SELECT msg_id FROM envelopes WHERE expires_ms <= ?1 AND handshake_group IS NULL ORDER BY seq")?;
            let rows = st.query_map(params![now_ms], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(h) = self.header(&id)? {
                out.push(h);
            }
        }
        Ok(out)
    }

    /// 헤더 삭제(`delete_header`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn delete_envelope(&self, msg_id: &str) -> Result<(), DbError> {
        let c = self.c();
        c.execute("DELETE FROM envelopes WHERE msg_id = ?1", params![msg_id])?;
        truncate_wal(&c);
        Ok(())
    }
}

/// WAL 을 본 DB 로 옮기고 0 바이트로 자른다 — 지운 본문이 `-wal` 에 남지 않게(e2e-envelope §1). 본 DB 쪽은
/// `secure_delete` 가 덮는다. 다른 연결이 읽는 중이면 이번엔 못 자를 수 있다(다음 삭제 때 다시). 실패는 삭제를 막지 않는다.
fn truncate_wal(c: &Connection) {
    let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
}

/// `recoveries` 행. 모르는 state·깨진 targets 면 `None`(행을 버린 것과 같게).
fn recovery_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<RecoveryRow>> {
    let targets: String = r.get(4)?;
    let state: String = r.get(5)?;
    let (Some(state), Ok(targets)) = (
        RecoveryState::parse(&state),
        serde_json::from_str::<Vec<String>>(&targets),
    ) else {
        return Ok(None);
    };
    Ok(Some(RecoveryRow {
        user: r.get(0)?,
        requester: r.get(1)?,
        created_ms: r.get(2)?,
        at_ms: r.get(3)?,
        targets,
        state,
        ended_ms: r.get(6)?,
        blocked_by: r.get(7)?,
        deferred: r.get::<_, i64>(8)? != 0,
    }))
}

/// #882 현황 푸시를 받는 기기 하나(그 기기의 push 행).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveTarget {
    pub device_id: String,
    pub platform: String,
    pub token: String,
    pub env: String,
    /// #845 §7-55 끈 알림 갈래.
    pub off: String,
    pub start_token: Option<String>,
    pub activity_token: Option<String>,
    pub activity_ms: Option<i64>,
    pub start_sent_ms: Option<i64>,
}

impl Db {
    /// #882 `push.live`: 그 기기의 현황 받기·토큰을 지금 상태 전부로 바꾼다(없는 토큰은 지움, `on` 거짓이면 둘 다 지움).
    /// 활동 토큰이 오면 start 보낸 표시를 지운다. 돌려주는 값: 행이 없으면 `None`, 있으면 `Some(전에 on 이었나)`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_live_set(
        &self,
        device_id: &str,
        on: bool,
        start_token: Option<&str>,
        activity: Option<(&str, i64)>,
    ) -> Result<Option<bool>, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let Some(was) = tx
            .query_row(
                "SELECT COALESCE(live_on, 0) FROM push_tokens WHERE device_id = ?1",
                [device_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
        else {
            return Ok(None);
        };
        let (start, act) = if on {
            (start_token, activity)
        } else {
            (None, None)
        };
        tx.execute(
            "UPDATE push_tokens SET live_on = ?2, live_start_token = ?3, live_activity_token = ?4, live_activity_ms = ?5,
               live_start_sent_ms = CASE WHEN ?4 IS NULL THEN live_start_sent_ms ELSE NULL END
             WHERE device_id = ?1",
            params![
                device_id,
                i64::from(on),
                start,
                act.map(|a| a.0),
                act.map(|a| a.1)
            ],
        )?;
        tx.commit()?;
        Ok(Some(was != 0))
    }

    /// #882 그 사용자의 현황 받는 기기(폐기 안 됨, live_on).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn live_targets(&self, user: &str) -> Result<Vec<LiveTarget>, DbError> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT p.device_id, p.platform, p.token, p.env, COALESCE(p.off, ''), p.live_start_token,
                    p.live_activity_token, p.live_activity_ms, p.live_start_sent_ms
             FROM push_tokens p JOIN devices d ON d.device_id = p.device_id
             WHERE d.user = ?1 AND d.revoked_ms IS NULL AND p.live_on = 1 ORDER BY p.device_id",
        )?;
        let rows = st.query_map([user], |r| {
            Ok(LiveTarget {
                device_id: r.get(0)?,
                platform: r.get(1)?,
                token: r.get(2)?,
                env: r.get(3)?,
                off: r.get(4)?,
                start_token: r.get(5)?,
                activity_token: r.get(6)?,
                activity_ms: r.get(7)?,
                start_sent_ms: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// #882 relay 가 보낸 것에 따라 활동 칸을 바꾼다: end 를 보냈으면 활동 토큰을 지우고, start 를 보냈으면 그 시각을 적는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn live_mark(
        &self,
        device_id: &str,
        ended: bool,
        start_sent_ms: Option<i64>,
    ) -> Result<(), DbError> {
        let c = self.c();
        if ended {
            c.execute(
                "UPDATE push_tokens SET live_activity_token = NULL, live_activity_ms = NULL WHERE device_id = ?1",
                [device_id],
            )?;
        }
        if let Some(ms) = start_sent_ms {
            c.execute(
                "UPDATE push_tokens SET live_start_sent_ms = ?2 WHERE device_id = ?1",
                params![device_id, ms],
            )?;
        }
        Ok(())
    }
}

/// 기기의 푸시 토큰 행(모바일 검증).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushToken {
    pub platform: String,
    pub token: String,
    pub env: String,
    pub app_id: String,
    pub salt: Vec<u8>,
    pub key: Vec<u8>,
    /// #845 §7-55 끈 알림 갈래(쉼표로 이음, 빈 값 = 다 켬).
    pub off: String,
}

impl Db {
    /// 기기의 푸시 토큰을 넣거나 바꾼다(기기당 하나, salt 도 새 값). 같은 토큰의 다른 기기는 [`PUSH_TOKEN_DEVICES`] 까지 남긴다.
    /// 폐기된 기기면 `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_token_put(
        &self,
        device_id: &str,
        t: &PushToken,
        now_ms: i64,
    ) -> Result<bool, DbError> {
        let mut c = self.c();
        let tx = immediate(&mut c)?;
        let live = tx
            .query_row(
                "SELECT 1 FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL",
                [device_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !live {
            return Ok(false);
        }
        // 같은 OS 토큰에 다른 기기(같은 휴대폰의 다른 계정)는 남긴다 — 상한을 넘으면 오래 전에 등록한 것부터 뺀다.
        tx.execute(
            "DELETE FROM push_tokens WHERE platform = ?1 AND token = ?2 AND device_id <> ?3
               AND device_id NOT IN (SELECT device_id FROM push_tokens
                 WHERE platform = ?1 AND token = ?2 AND device_id <> ?3 ORDER BY updated_ms DESC LIMIT ?4)",
            params![t.platform, t.token, device_id, PUSH_TOKEN_DEVICES - 1],
        )?;
        let n = tx.execute(
            "INSERT INTO push_tokens(device_id, platform, token, env, app_id, salt, key, updated_ms, off)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL
             ON CONFLICT(device_id) DO UPDATE SET platform = excluded.platform, token = excluded.token,
               env = excluded.env, app_id = excluded.app_id, salt = excluded.salt, key = excluded.key,
               updated_ms = excluded.updated_ms, off = excluded.off",
            params![device_id, t.platform, t.token, t.env, t.app_id, t.salt, t.key, now_ms, t.off],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// 보낸 duty 하나를 적는다(모바일 검증 S3, 시험 relay 만).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn duty_sent_put(
        &self,
        device_id: &str,
        task: &str,
        group_id: &str,
        rank: u64,
        at_ms: i64,
    ) -> Result<(), DbError> {
        self.c().execute(
            "INSERT INTO mls_duty_sent(device_id, task, group_id, rank, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![device_id, task, group_id, i64::try_from(rank).unwrap_or(i64::MAX), at_ms],
        )?;
        Ok(())
    }

    /// 토큰이 더는 맞지 않을 때(애플·구글이 '없는 토큰') — 그 토큰을 쥔 행을 **모두** 지운다(다시 깐 휴대폰의 여러 계정).
    /// 그 사이 이 기기가 다시 등록돼 토큰이 바뀌었으면 이 기기 행은 남는다(같은 토큰이 아니니까).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_token_drop_if(&self, _device_id: &str, token: &str) -> Result<bool, DbError> {
        Ok(self
            .c()
            .execute("DELETE FROM push_tokens WHERE token = ?1", params![token])?
            > 0)
    }

    /// 같은 OS 토큰을 쥔 기기 수(시험·운영 확인).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_token_devices(&self, platform: &str, token: &str) -> Result<i64, DbError> {
        Ok(self.c().query_row(
            "SELECT COUNT(*) FROM push_tokens WHERE platform = ?1 AND token = ?2",
            params![platform, token],
            |r| r.get(0),
        )?)
    }

    /// 그 기기가 그 그룹에서 아직 받지 않은 Handshake(Commit·Welcome)가 있나 — 있으면 푸시 확장이 응용 메시지를 풀 수
    /// 없으니(Commit 은 앱만 처리) 빈 깨우기로 보낸다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn handshake_waiting(&self, device_id: &str, group: &str) -> Result<bool, DbError> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM envelope_devices ed JOIN envelopes e ON e.msg_id = ed.msg_id
               WHERE ed.device_id = ?1 AND ed.acked_ms IS NULL AND e.message IS NOT NULL
                 AND e.handshake_group = ?2)",
            params![device_id, group],
            |r| r.get(0),
        )?)
    }

    /// 기기의 푸시 토큰을 지운다(`push.unregister`, 토큰이 더는 맞지 않을 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_token_drop(&self, device_id: &str) -> Result<bool, DbError> {
        Ok(self
            .c()
            .execute("DELETE FROM push_tokens WHERE device_id = ?1", [device_id])?
            > 0)
    }

    /// 기기의 푸시 토큰.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_token(&self, device_id: &str) -> Result<Option<PushToken>, DbError> {
        Ok(self
            .c()
            .query_row(
                "SELECT platform, token, env, app_id, salt, key, off FROM push_tokens WHERE device_id = ?1",
                [device_id],
                |r| {
                    Ok(PushToken {
                        platform: r.get(0)?,
                        token: r.get(1)?,
                        env: r.get(2)?,
                        app_id: r.get(3)?,
                        salt: r.get(4)?,
                        key: r.get(5)?,
                        off: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    })
                },
            )
            .optional()?)
    }
}

/// 기기 하나를 폐기하고 그 사용자를 돌려준다(이미 폐기됐거나 없으면 `None`). 남은 기기가 없으면 기다리던 본문·공개 세션을 지운다.
fn revoke_in(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    now_ms: i64,
    by: RevokedBy,
    proof: Option<&RevokeProof>,
) -> Result<Option<String>, DbError> {
    let user: Option<String> = tx
        .query_row(
            // 기기 이름도 지운다(#490 — 처리방침 나감 파기와 같게).
            "UPDATE devices SET revoked_ms = ?2, revoked_by = ?3, name = NULL, os = NULL, last_seen_day = NULL, last_auth_ms = NULL, away = NULL
             WHERE device_id = ?1 AND revoked_ms IS NULL RETURNING user",
            params![device_id, now_ms, by.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(user) = user else {
        return Ok(None);
    };
    tx.execute("DELETE FROM push_tokens WHERE device_id = ?1", [device_id])?;
    // #881: 이 기기가 올렸거나 받을 지난 대화 조각은 바로 지운다(파일은 청소가 고아로 지움).
    let history: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT blob_id FROM blobs WHERE for_device IS NOT NULL AND (device = ?1 OR for_device = ?1)",
        )?;
        let rows = st.query_map([device_id], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    delete_blob_rows(tx, &history)?;
    // 증명 있는 폐기(묶음 22 §12-11 ⓐ·e73b25bd)면 증명을 남기고 그 기기가 서명자·대상인 devcert 를 둘 다 남긴다(뿌리 그래프의
    // 고리). 증명 없는 폐기는 그 서명을 지운다(#393, protocol §7.2 device.certify) — 상대쪽이 증명 폐기된 기기여도.
    if let Some(p) = proof {
        tx.execute(
            "UPDATE devices SET revoke_at = ?2, revoke_signer = ?3, revoke_sig = ?4 WHERE device_id = ?1",
            params![device_id, p.at, p.signer, p.sig],
        )?;
    } else {
        tx.execute(
            "DELETE FROM device_certs WHERE signer = ?1 OR target = ?1",
            [device_id],
        )?;
    }
    tx.execute("DELETE FROM mls_rejoin WHERE device_id = ?1", [device_id])?;
    // §7 duty: 그 기기의 잎이 든 그룹마다 remove_device, 그 기기를 들이던 일·받은 줄 자리는 끝.
    tx.execute(
        "INSERT OR IGNORE INTO mls_duties(group_id, task, subject, created_ms)
         SELECT group_id, 'remove_device', ?1, ?2 FROM mls_leaves WHERE device_id = ?1",
        params![device_id, now_ms],
    )?;
    tx.execute(
        "DELETE FROM mls_duties WHERE task = 'add_device' AND subject = ?1",
        [device_id],
    )?;
    tx.execute(
        "DELETE FROM mls_duty_ranks WHERE device_id = ?1 OR (task = 'add_device' AND subject = ?1)",
        [device_id],
    )?;
    // 그 기기를 대상에서 뺀다(protocol §7.2-6). 남은 대상이 모두 ack 했으면 본문을 지운다.
    let dropped: Vec<String> = {
        let mut st = tx.prepare(
            "DELETE FROM envelope_devices WHERE device_id = ?1 AND acked_ms IS NULL RETURNING msg_id",
        )?;
        let rows = st.query_map([device_id], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for msg_id in &dropped {
        // #577 §9 ②: 같은 사용자의 다른 기기 몫이 없는 MLS 응용 글(Handshake·내 글의 사본 빼고) — 산 기기가 남아 있으면(기기
        // 바꾸기) 보낸 쪽이 다시 보내게. 마지막 기기 로그아웃은 지금처럼 조용히 만료.
        tx.execute(
            "INSERT OR IGNORE INTO device_changed(msg_id, from_user, at_ms, expires_ms)
             SELECT e.msg_id, e.from_user, ?3, e.expires_ms FROM envelopes e
             WHERE e.msg_id = ?1 AND e.kind != 'mls' AND e.from_user != ?2 AND e.message IS NOT NULL
               AND json_extract(e.message, '$.mls_group') IS NOT NULL
               AND NOT EXISTS(SELECT 1 FROM envelope_devices ed JOIN devices d ON d.device_id = ed.device_id
                              WHERE ed.msg_id = ?1 AND d.user = ?2)
               AND EXISTS(SELECT 1 FROM devices WHERE user = ?2 AND revoked_ms IS NULL)",
            params![msg_id, user, now_ms],
        )?;
        tx.execute(
            "UPDATE envelopes SET message = NULL WHERE msg_id = ?1 AND message IS NOT NULL
               AND NOT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL)",
            [msg_id],
        )?;
    }
    let left: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE user = ?1 AND revoked_ms IS NULL)",
        [&user],
        |r| r.get(0),
    )?;
    if !left {
        tx.execute(
            "UPDATE envelopes SET message = NULL WHERE to_user = ?1 AND message IS NOT NULL",
            [&user],
        )?;
        // 받을 기기가 없으니 공개 세션도 내린다 — 거두기 전에 끊긴 로그아웃·offline_ok 뒤에 유령 세션이 남지 않게.
        tx.execute("DELETE FROM sessions_public WHERE user = ?1", [&user])?;
    }
    Ok(Some(user))
}

/// `user` 가 자기 조직의 유일한 관리자이고 조직에 (내보내지 않은) 다른 사람이 있다(묶음 5 `last_admin`). 혼자 남은
/// 사람은 갇히지 않게 검사하지 않는다. 로컬 relay 는 `org_admins` 가 비어 늘 `false`.
fn last_admin_with_others(tx: &rusqlite::Transaction<'_>, user: &str) -> Result<bool, DbError> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users me JOIN org_admins x ON x.org_id = me.org AND x.user = me.user
           WHERE me.user = ?1)
         AND (SELECT COUNT(*) FROM org_admins x JOIN users a ON a.user = x.user AND a.org = x.org_id
              WHERE x.org_id = (SELECT org FROM users WHERE user = ?1) AND a.removed_ms IS NULL) = 1
         AND EXISTS(SELECT 1 FROM users o WHERE o.org = (SELECT org FROM users WHERE user = ?1)
              AND o.user <> ?1 AND o.removed_ms IS NULL)",
        [user],
        |r| r.get(0),
    )?)
}

/// 사람을 조직에서 뺀다(내보내기·나가기, 묶음 5): 살아 있는 기기 전부 폐기(`by`) + `removed_ms` + 관리자 행 지움.
/// 폐기한 기기 id 들.
/// 봉투 한 건을 넣는다([`Db::store_envelope`]·그룹 변경의 트랜잭션 안). 전달 대상 = 후보(`pool` — 그룹이면 멤버 기기,
/// 거두기면 원 메시지의 수신 기기 — 없으면 `to_user` 의 기기) 중 폐기 안 된 것.
fn insert_envelope_in(
    tx: &rusqlite::Transaction<'_>,
    h: &StoredHeader,
    message: &str,
    blobs: &[String],
    pool: Option<&[String]>,
    group: Option<(&str, Option<i64>)>,
) -> Result<Vec<String>, DbError> {
    // 그룹 맥락(gid, kind group 이면 서버 순서).
    let (gid, group_seq) = group.map_or((None, None), |(g, s)| (Some(g), s));
    // 첨부 묶기(묶음 15): 보낸 사용자가 올린(uploaded) 묶이지 않은 message blob 만. 하나라도 아니면 아무것도 쓰지 않는다.
    for b in blobs {
        let n = tx.execute(
            "UPDATE blobs SET state = 'attached', msg_id = ?1
             WHERE blob_id = ?2 AND user = ?3 AND purpose = 'message' AND state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL",
            params![h.msg_id, b, h.from_user],
        )?;
        if n != 1 {
            return Err(DbError::BlobUnavailable);
        }
    }
    let n = tx.execute(
        "INSERT OR IGNORE INTO envelopes(msg_id, kind, from_user, from_address, to_user, to_address,
           expires_ms, env_state, sender_view, abort_reason, message, group_seq, gid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            h.msg_id,
            h.kind,
            h.from_user,
            h.from_address,
            h.to_user,
            h.to_address,
            h.expires_ms,
            h.env_state,
            h.sender_view,
            h.abort_reason,
            message,
            group_seq,
            gid
        ],
    )?;
    if n == 0 {
        return Err(DbError::Conflict);
    }
    let devices: Vec<String> = match pool {
        Some(p) => {
            let mut out: Vec<String> = Vec::new();
            for d in p {
                let live: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1 AND revoked_ms IS NULL)",
                    [d],
                    |r| r.get(0),
                )?;
                if live && !out.contains(d) {
                    out.push(d.clone());
                }
            }
            out
        }
        None => {
            let mut st =
                tx.prepare("SELECT device_id FROM devices WHERE user = ?1 AND revoked_ms IS NULL")?;
            let rows = st.query_map([&h.to_user], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        }
    };
    if pool.is_some() && devices.is_empty() {
        return Err(DbError::NoTargets);
    }
    for d in &devices {
        tx.execute(
            "INSERT INTO envelope_devices(msg_id, device_id) VALUES (?1, ?2)",
            params![h.msg_id, d],
        )?;
    }
    Ok(devices)
}

/// 그 사람 기기의 그 그룹 메시지 중 아직 받지 않은 몫을 지우고(묶음 16 §3a ②), 그래서 남은 대상이 모두 받은 봉투는 본문도 지운다.
/// 사람 op 권한([`Db::group_op_allowed`]).
fn group_op_allowed_in(tx: &rusqlite::Transaction<'_>, g: &GroupOp<'_>) -> Result<bool, DbError> {
    use lodelai_protocol::constants as c;
    let org_of = |u: &str| -> Result<Option<String>, DbError> {
        Ok(tx
            .query_row(
                "SELECT org FROM users WHERE user = ?1 AND removed_ms IS NULL",
                [u],
                |r| r.get(0),
            )
            .optional()?)
    };
    let row: Option<String> = tx
        .query_row("SELECT org FROM groups WHERE gid = ?1", [g.gid], |r| {
            r.get(0)
        })
        .optional()?;
    let sender_org = org_of(g.sender)?;
    if g.op == "create" && g.subject.is_some() {
        // 만들기 Commit(§12-22): 만든 사람 혼자인 그룹에 처음 멤버(subject = 줄바꿈으로 이은 아이디들).
        let Some(org) = row else {
            return Ok(false);
        };
        let members = group_members_in(tx, g.gid)?;
        let list: Vec<&str> = g.subject.unwrap_or_default().split('\n').collect();
        let unique: std::collections::HashSet<&&str> = list.iter().collect();
        if members.len() != 1
            || members[0] != (g.sender.to_owned(), true)
            || sender_org.as_deref() != Some(org.as_str())
            || unique.len() != list.len()
            || list.is_empty()
            || list.len() as u64 > c::GROUP_MAX_MEMBERS - 1
            || list.contains(&g.sender)
        {
            return Ok(false);
        }
        for u in list {
            if !add_ok_in(tx, g.gid, &org, g.sender, u, 1, g.now_ms)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    if g.op == "create" {
        return Ok(row.is_none()
            && sender_org.is_some()
            && (groups_of_in(tx, g.sender)? as u64) < c::GROUPS_PER_USER);
    }
    let Some(org) = row else {
        return Ok(false);
    };
    let members = group_members_in(tx, g.gid)?;
    let is_member = |u: &str| members.iter().any(|(m, _)| m == u);
    let is_admin = |u: &str| members.iter().any(|(m, a)| m == u && *a);
    // #845 ④: 그룹 조직이 아니라 '내가 지금 멤버'(다른 조직 사람이 섞인 그룹).
    let _ = &org;
    if sender_org.is_none() || !is_member(g.sender) {
        return Ok(false);
    }
    let sender_admin = g.admin.unwrap_or_else(|| is_admin(g.sender));
    // 나간 기록(left_seq) — org_left 면 조직 빠짐으로.
    let left = |u: &str, by_org: bool| -> Result<bool, DbError> {
        Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE gid = ?1 AND user = ?2 AND left_seq IS NOT NULL
               AND org_left = ?3)",
            params![g.gid, u, by_org],
            |r| r.get(0),
        )?)
    };
    Ok(match (g.op, g.subject) {
        ("add", Some(u)) => {
            !is_member(u) && add_ok_in(tx, g.gid, &org, g.sender, u, members.len(), g.now_ms)?
        }
        ("remove", Some(u)) => sender_admin && is_member(u) && u != g.sender,
        ("admin", Some(u)) => sender_admin && is_member(u),
        ("leave", Some(u)) if u == g.sender => true,
        ("leave", Some(u)) => left(u, false)?,
        ("org_left", Some(u)) => left(u, true)?,
        ("update", None) => true,
        // 이름 바꾸기(§12-23) — 멤버 누구나(16 '`rename`: 멤버'). 이름은 MLS 평문 안이라 relay 는 모른다.
        ("rename", None) => true,
        _ => false,
    })
}

/// 그 사람을 그 그룹에 더할 수 있나(더하는 사람과 같은 조직 또는 수락된 연락처(#845 ④ 섞인 그룹)·차단 없음·멈춤
/// 없음·그룹 수 상한, 지금 멤버 수 `now` < 상한).
fn add_ok_in(
    tx: &rusqlite::Transaction<'_>,
    gid: &str,
    org: &str,
    sender: &str,
    u: &str,
    now: usize,
    now_ms: i64,
) -> Result<bool, DbError> {
    use lodelai_protocol::constants as c;
    let _ = org;
    let reach: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users ua, users ub
                         WHERE ua.user = ?1 AND ub.user = ?2 AND ua.removed_ms IS NULL AND ub.removed_ms IS NULL
                           AND (ub.suspended_ms IS NULL OR ub.suspended_until <= ?3) AND ua.org = ub.org)
                OR EXISTS(SELECT 1 FROM links l JOIN users ub ON ub.user = l.peer
                         WHERE l.user = ?1 AND l.peer = ?2 AND l.state = 'accepted'
                           AND ub.removed_ms IS NULL AND (ub.suspended_ms IS NULL OR ub.suspended_until <= ?3))",
        params![sender, u, now_ms],
        |r| r.get(0),
    )?;
    // #845 ④: 수락한 그룹 초대('들어가는 중')면 그 그룹의 어느 멤버든 더한다(연락처는 초대한 사람과만 생김).
    let joining: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM group_invites WHERE gid = ?1 AND user = ?2 AND accepted_ms IS NOT NULL)",
        params![gid, u],
        |r| r.get(0),
    )?;
    let reach = reach || joining;
    let blocked: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE (user = ?1 AND blocked = ?2) OR (user = ?2 AND blocked = ?1))",
        params![u, sender],
        |r| r.get(0),
    )?;
    Ok(reach
        && !blocked
        && (now as u64) < c::GROUP_MAX_MEMBERS
        && (groups_of_in(tx, u)? as u64) < c::GROUPS_PER_USER)
}

/// 사람 op 를 표에 반영하고 seq·로그를 남긴다(create·add·remove·admin·나가는 사람의 leave). 남은 기기의 leave·org_left
/// Commit 은 표가 이미 바뀌어 seq·로그만. 돌려주는 값: 새 seq.
fn group_apply_in(
    tx: &rusqlite::Transaction<'_>,
    g: &GroupOp<'_>,
    msg_id: &str,
    now_ms: i64,
) -> Result<Option<i64>, DbError> {
    let seq: i64 = tx
        .query_row("SELECT seq FROM groups WHERE gid = ?1", [g.gid], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or(0)
        + 1;
    match (g.op, g.subject) {
        ("create", Some(list)) => {
            // 만들기 Commit(§12-22): 처음 멤버를 한 seq 로.
            for u in list.split('\n') {
                tx.execute(
                    "INSERT INTO group_members(gid, user, role, joined_seq) VALUES (?1, ?2, 'member', ?3)
                     ON CONFLICT(gid, user) DO UPDATE SET role = 'member', joined_seq = ?3, left_seq = NULL, org_left = 0, left_org = NULL",
                    params![g.gid, u, seq],
                )?;
                tx.execute(
                    "DELETE FROM group_invites WHERE gid = ?1 AND user = ?2",
                    params![g.gid, u],
                )?;
            }
        }
        ("create", None) => {
            let org: Option<String> = tx
                .query_row(
                    "SELECT org FROM users WHERE user = ?1 AND removed_ms IS NULL",
                    [g.sender],
                    |r| r.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT INTO groups(gid, org, seq, created_ms) VALUES (?1, ?2, 0, ?3)",
                params![g.gid, org, now_ms],
            )?;
            tx.execute(
                "INSERT INTO group_members(gid, user, role, joined_seq) VALUES (?1, ?2, 'admin', ?3)",
                params![g.gid, g.sender, seq],
            )?;
        }
        ("add", Some(u)) => {
            tx.execute(
                "INSERT INTO group_members(gid, user, role, joined_seq) VALUES (?1, ?2, 'member', ?3)
                 ON CONFLICT(gid, user) DO UPDATE SET role = 'member', joined_seq = ?3, left_seq = NULL, org_left = 0, left_org = NULL",
                params![g.gid, u, seq],
            )?;
            // #845 ④: 들어갔으니 초대·'들어가는 중'은 끝.
            tx.execute(
                "DELETE FROM group_invites WHERE gid = ?1 AND user = ?2",
                params![g.gid, u],
            )?;
        }
        ("remove", Some(u)) => {
            tx.execute(
                "UPDATE group_members SET left_seq = ?3 WHERE gid = ?1 AND user = ?2",
                params![g.gid, u, seq],
            )?;
            // 빼는 그 메시지(Commit·leave)는 남긴다 — 꺼져 있던 그 사람이 빠졌음을 알게.
            drop_group_pending_in(tx, g.gid, u, msg_id)?;
            drop_left_rejoin_in(tx, Some(g.gid), u)?;
        }
        ("leave", Some(u)) if u == g.sender => {
            tx.execute(
                "UPDATE group_members SET left_seq = ?3 WHERE gid = ?1 AND user = ?2",
                params![g.gid, u, seq],
            )?;
            // 빼는 그 메시지(Commit·leave)는 남긴다 — 꺼져 있던 그 사람이 빠졌음을 알게.
            drop_group_pending_in(tx, g.gid, u, msg_id)?;
            drop_left_rejoin_in(tx, Some(g.gid), u)?;
        }
        ("admin", Some(u)) => {
            tx.execute(
                "UPDATE group_members SET role = CASE role WHEN 'admin' THEN 'member' ELSE 'admin' END
                 WHERE gid = ?1 AND user = ?2",
                params![g.gid, u],
            )?;
        }
        _ => {}
    }
    tx.execute(
        "UPDATE groups SET seq = ?2 WHERE gid = ?1",
        params![g.gid, seq],
    )?;
    tx.execute(
        "INSERT INTO group_log(gid, seq, msg_id) VALUES (?1, ?2, ?3)",
        params![g.gid, seq, msg_id],
    )?;
    Ok(Some(seq))
}

/// 그룹의 마지막 결과를 바꾸고 이전 Commit 들의 응답을 지운다(이 Commit 것은 확정 뒤 fail 판정에 남김).
fn put_outcome_in(
    tx: &rusqlite::Transaction<'_>,
    p: &PendingCommit,
    is_final: bool,
    seq: Option<i64>,
    now_ms: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO mls_outcomes(group_id, epoch, commit_hash, final, group_seq, sender_user, excluded, notified, at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
         ON CONFLICT(group_id) DO UPDATE SET epoch = ?2, commit_hash = ?3, final = ?4, group_seq = ?5,
           sender_user = ?6, excluded = ?7, notified = 0, at_ms = ?8",
        params![
            p.group_id,
            i64::try_from(p.epoch).unwrap_or(-1),
            p.commit_hash,
            is_final,
            seq,
            p.sender_user,
            p.excluded.join("\n"),
            now_ms
        ],
    )?;
    tx.execute(
        "DELETE FROM mls_votes WHERE group_id = ?1 AND commit_hash <> ?2",
        params![p.group_id, p.commit_hash],
    )?;
    Ok(())
}

fn drop_group_pending_in(
    tx: &rusqlite::Transaction<'_>,
    gid: &str,
    user: &str,
    keep: &str,
) -> Result<(), DbError> {
    let touched: Vec<String> = {
        let mut st = tx.prepare(
            "DELETE FROM envelope_devices WHERE acked_ms IS NULL
               AND device_id IN (SELECT device_id FROM devices WHERE user = ?2)
               AND msg_id IN (SELECT msg_id FROM envelopes WHERE gid = ?1) AND msg_id <> ?3
             RETURNING msg_id",
        )?;
        let rows = st.query_map(params![gid, user, keep], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for m in touched {
        tx.execute(
            "UPDATE envelopes SET message = NULL WHERE msg_id = ?1
               AND NOT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL)",
            [&m],
        )?;
    }
    Ok(())
}

/// #816 ①: 그룹에서 빠진 사람(나감·내보냄·조직 빠짐)의 기기에 남은 다시 들기 표시(`mls_rejoin`)와 add_device 일을 지운다 —
/// 나가기 전에 생긴 표시가 접속 때 `rejoin_needed` 로 다시 가지 않게. `gid` 가 없으면 그 사람이 나간 모든 그룹.
fn drop_left_rejoin_in(
    tx: &rusqlite::Transaction<'_>,
    gid: Option<&str>,
    user: &str,
) -> Result<(), DbError> {
    let left = "SELECT gid FROM group_members WHERE user = ?1 AND left_seq IS NOT NULL AND (?2 IS NULL OR gid = ?2)";
    tx.execute(
        &format!(
            "DELETE FROM mls_rejoin WHERE device_id IN (SELECT device_id FROM devices WHERE user = ?1)
               AND group_id IN ({left})"
        ),
        params![user, gid],
    )?;
    tx.execute(
        &format!(
            "DELETE FROM mls_duties WHERE task = 'add_device'
               AND subject IN (SELECT device_id FROM devices WHERE user = ?1) AND group_id IN ({left})"
        ),
        params![user, gid],
    )?;
    tx.execute(
        "DELETE FROM mls_duty_ranks WHERE NOT EXISTS(
           SELECT 1 FROM mls_duties d WHERE d.group_id = mls_duty_ranks.group_id
             AND d.task = mls_duty_ranks.task AND d.subject = mls_duty_ranks.subject)",
        [],
    )?;
    Ok(())
}

/// 그룹 지금 멤버(아이디, 관리자인가) — 들어온 순서.
fn group_members_in(
    tx: &rusqlite::Transaction<'_>,
    gid: &str,
) -> Result<Vec<(String, bool)>, DbError> {
    let mut st = tx.prepare(
        "SELECT user, role FROM group_members WHERE gid = ?1 AND left_seq IS NULL ORDER BY joined_seq, user",
    )?;
    let rows = st.query_map([gid], |r| {
        Ok((r.get(0)?, r.get::<_, String>(1)? == "admin"))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// 그 사용자들의 폐기 안 된 기기.
fn live_devices_in(
    tx: &rusqlite::Transaction<'_>,
    users: &[String],
) -> Result<Vec<String>, DbError> {
    let mut out = Vec::new();
    let mut st =
        tx.prepare("SELECT device_id FROM devices WHERE user = ?1 AND revoked_ms IS NULL")?;
    for u in users {
        let rows = st.query_map([u], |r| r.get::<_, String>(0))?;
        for d in rows {
            out.push(d?);
        }
    }
    Ok(out)
}

/// #845 §7-26 보낸 초대 한 줄.
#[allow(clippy::too_many_arguments)]
fn sent_in(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    kind: &str,
    scope: &str,
    by: &str,
    shown: &str,
    target_user: Option<&str>,
    target_email: Option<&str>,
    recv_ref: Option<&str>,
    now_ms: i64,
    joined: bool,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT OR IGNORE INTO invites_sent(id, kind, scope, by, shown, target_user, target_email, recv_ref, at_ms, joined_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            id,
            kind,
            scope,
            by,
            shown.chars().take(254).collect::<String>(),
            target_user,
            target_email,
            recv_ref,
            now_ms,
            joined.then_some(now_ms)
        ],
    )?;
    Ok(())
}

/// #845 ⑤ 초대 메일 일 하나(id 는 그 줄 ref 와 같게 — 같은 줄의 일은 하나).
fn mail_enqueue_in(
    tx: &rusqlite::Transaction<'_>,
    kind: &str,
    r: &str,
    email: &str,
    sender: &str,
    org_id: Option<&str>,
    now_ms: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT OR IGNORE INTO mail_jobs(id, kind, ref, email, sender, org_id, at_ms, after_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            format!("{kind}:{r}"),
            kind,
            r,
            email,
            sender,
            org_id,
            now_ms
        ],
    )?;
    Ok(())
}

/// #845 §7-17 `owner` 의 공개 세션 범위(people 목록)에서 `who` 를 뺀다.
fn drop_from_audiences_in(
    tx: &rusqlite::Transaction<'_>,
    owner: &str,
    who: &str,
) -> Result<(), DbError> {
    let rows: Vec<(String, String)> = {
        let mut st = tx.prepare(
            "SELECT slug, audience FROM sessions_public WHERE user = ?1 AND audience IS NOT NULL",
        )?;
        let r = st.query_map([owner], |r| Ok((r.get(0)?, r.get(1)?)))?;
        r.collect::<Result<_, _>>()?
    };
    for (slug, text) in rows {
        let Some((list, lists)) = audience_of(Some(text)) else {
            continue;
        };
        if list.iter().any(|u| u == who) {
            let kept: Vec<String> = list.into_iter().filter(|u| u != who).collect();
            tx.execute(
                "UPDATE sessions_public SET audience = ?3 WHERE user = ?1 AND slug = ?2",
                params![owner, slug, audience_text(Some(&kept), &lists)],
            )?;
        }
    }
    drop_from_lists_in(tx, owner, who)?;
    Ok(())
}

/// #845 둘째: `owner` 의 모든 목록에서 `who` 를 뺀다(연락처 빼기·차단 — 저장에서 지움).
fn drop_from_lists_in(
    tx: &rusqlite::Transaction<'_>,
    owner: &str,
    who: &str,
) -> Result<(), DbError> {
    let rows: Vec<(String, String)> = {
        let mut st = tx.prepare(
            "SELECT list_id, users FROM lists WHERE owner = ?1
               AND EXISTS(SELECT 1 FROM json_each(lists.users) WHERE value = ?2)",
        )?;
        let r = st.query_map(params![owner, who], |r| Ok((r.get(0)?, r.get(1)?)))?;
        r.collect::<Result<_, _>>()?
    };
    for (id, t) in rows {
        let kept: Vec<String> = users_of_json(&t).into_iter().filter(|u| u != who).collect();
        tx.execute(
            "UPDATE lists SET users = ?3 WHERE owner = ?1 AND list_id = ?2",
            params![owner, id, users_json(&kept)],
        )?;
    }
    Ok(())
}

/// #845 둘째: `user` 가 들고 난 관계(조직 나가기·옮기기)로 같은 조직도 수락된 연락처도 아니게 된 사람을 목록에서 뺀다 —
/// `user` 의 목록에서 그런 사람, 남의 목록에서 그런 `user`. 목록이 바뀐 주인들을 돌려준다(directory.update 받을 사람).
fn prune_lists_in(tx: &rusqlite::Transaction<'_>, user: &str) -> Result<Vec<String>, DbError> {
    let mut owners: Vec<String> = Vec::new();
    let mine: Vec<(String, String)> = {
        let mut st = tx.prepare("SELECT list_id, users FROM lists WHERE owner = ?1")?;
        let r = st.query_map([user], |r| Ok((r.get(0)?, r.get(1)?)))?;
        r.collect::<Result<_, _>>()?
    };
    for (id, t) in mine {
        let all = users_of_json(&t);
        let mut kept = Vec::with_capacity(all.len());
        for u in &all {
            if related_c(tx, user, u)? {
                kept.push(u.clone());
            }
        }
        if kept.len() != all.len() {
            tx.execute(
                "UPDATE lists SET users = ?3 WHERE owner = ?1 AND list_id = ?2",
                params![user, id, users_json(&kept)],
            )?;
            if !owners.iter().any(|o| o == user) {
                owners.push(user.to_owned());
            }
        }
    }
    let theirs: Vec<(String, String, String)> = {
        let mut st = tx.prepare(
            "SELECT owner, list_id, users FROM lists WHERE owner <> ?1
               AND EXISTS(SELECT 1 FROM json_each(lists.users) WHERE value = ?1)",
        )?;
        let r = st.query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        r.collect::<Result<_, _>>()?
    };
    for (owner, id, t) in theirs {
        if related_c(tx, &owner, user)? {
            continue;
        }
        let kept: Vec<String> = users_of_json(&t)
            .into_iter()
            .filter(|u| u != user)
            .collect();
        tx.execute(
            "UPDATE lists SET users = ?3 WHERE owner = ?1 AND list_id = ?2",
            params![owner, id, users_json(&kept)],
        )?;
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    Ok(owners)
}

/// 그 사용자가 지금 멤버인 그룹 수.
fn groups_of_in(tx: &rusqlite::Transaction<'_>, user: &str) -> Result<i64, DbError> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM group_members WHERE user = ?1 AND left_seq IS NULL",
        [user],
        |r| r.get(0),
    )?)
}

/// 쓰기 트랜잭션은 처음부터 쓰기 잠금으로(#537). 기본(deferred)은 읽은 뒤 쓰려는 때 다른 연결이 먼저 썼으면 busy_timeout 을
/// 거치지 않고 바로 BUSY 라, relay 가 도는 중 같은 DB 를 쓰는 명령(bootstrap 등)과 겹치면 요청이 internal 로 끝났다.
fn immediate(c: &mut Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

/// 지금 멤버가 없는 그룹마다 [`drop_group_in`]. 지운 첨부 id(파일은 호출자나 청소가).
fn drop_empty_groups_in(tx: &rusqlite::Transaction<'_>) -> Result<Vec<String>, DbError> {
    let gids: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT gid FROM groups WHERE NOT EXISTS(SELECT 1 FROM group_members m WHERE m.gid = groups.gid AND m.left_seq IS NULL)",
        )?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut removed = Vec::new();
    for gid in gids {
        removed.extend(drop_group_in(tx, &gid, None)?);
    }
    Ok(removed)
}

/// 그룹 하나를 지운다(#532): 그룹·멤버·로그, 묶음 22 MLS 상태 전부, 그 그룹 봉투(`gid`·`handshake_group`)와 그 첨부 —
/// `keep` 봉투만 남긴다. GroupInfo 붙잡기(`mls_gi_blobs`)를 먼저 풀어야 그 blob 도 지워진다. 지운 첨부 id.
fn drop_group_in(
    tx: &rusqlite::Transaction<'_>,
    gid: &str,
    keep: Option<&str>,
) -> Result<Vec<String>, DbError> {
    for sql in [
        "DELETE FROM groups WHERE gid = ?1",
        "DELETE FROM group_members WHERE gid = ?1",
        // #845 §7-29: 그 그룹 초대의 안 간 메일·보낸 기록도 — 없는 그룹 초대가 남지 않게(메일 줄은 초대 줄보다 먼저).
        "DELETE FROM mail_jobs WHERE kind = 'group' AND ref IN (SELECT id FROM group_invites WHERE gid = ?1)",
        "DELETE FROM invites_sent WHERE kind = 'group' AND scope = ?1",
        "DELETE FROM group_invites WHERE gid = ?1",
        "DELETE FROM group_log WHERE gid = ?1",
        "DELETE FROM mls_gi_blobs WHERE group_id = ?1",
        "DELETE FROM mls_leaves WHERE group_id = ?1",
        "DELETE FROM mls_pending WHERE group_id = ?1",
        "DELETE FROM mls_outcomes WHERE group_id = ?1",
        "DELETE FROM mls_duties WHERE group_id = ?1",
        "DELETE FROM mls_duty_ranks WHERE group_id = ?1",
        "DELETE FROM mls_duty_stuck WHERE group_id = ?1",
        "DELETE FROM mls_votes WHERE group_id = ?1",
        "DELETE FROM mls_rejoin WHERE group_id = ?1",
        "DELETE FROM mls_alerts WHERE group_id = ?1",
        "DELETE FROM mls_commits WHERE group_id = ?1",
        "DELETE FROM mls_groups WHERE group_id = ?1 AND kind = 'group'",
    ] {
        tx.execute(sql, [gid])?;
    }
    let msgs: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT msg_id FROM envelopes WHERE (gid = ?1 OR handshake_group = ?1) AND msg_id IS NOT ?2",
        )?;
        let rows = st.query_map(params![gid, keep], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut removed = Vec::new();
    for m in msgs {
        removed.extend(drop_blobs_of(tx, &m)?);
        tx.execute("DELETE FROM envelopes WHERE msg_id = ?1", [&m])?;
    }
    Ok(removed)
}

/// 그 blob 의 수신 기기(폐기 안 된) 중 아직 안 받은 기기가 있는가(묶음 15).
const ALL_FETCHED_OPEN: &str = "SELECT EXISTS(
    SELECT 1 FROM blobs b JOIN envelope_devices d ON d.msg_id = b.msg_id
      JOIN devices dv ON dv.device_id = d.device_id AND dv.revoked_ms IS NULL
    WHERE b.blob_id = ?1
      AND NOT EXISTS(SELECT 1 FROM blob_fetch f WHERE f.blob_id = b.blob_id AND f.device_id = d.device_id))";

/// 그 blob 행들을 지운다 — 그룹의 지금 GroupInfo 로 붙잡힌 것(묶음 22 §5c)은 빼고. 실제로 지운 id(파일은 호출자가).
/// 그 조직의 사진 blob(#554) — 올림이 끝난 것만(예약 중인 id 를 싣지 않게).
fn org_avatar_in(tx: &rusqlite::Transaction<'_>, org: &str) -> Result<Option<String>, DbError> {
    Ok(tx
        .query_row(
            "SELECT o.avatar_blob FROM orgs o JOIN blobs b ON b.blob_id = o.avatar_blob AND b.state = 'uploaded'
             WHERE o.org_id = ?1",
            [org],
            |r| r.get(0),
        )
        .optional()?)
}

fn delete_blob_rows(
    tx: &rusqlite::Transaction<'_>,
    ids: &[String],
) -> Result<Vec<String>, DbError> {
    let mut done = Vec::new();
    for id in ids {
        let pinned: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_gi_blobs WHERE blob_id = ?1)",
            [id],
            |r| r.get(0),
        )?;
        if pinned {
            continue;
        }
        tx.execute("DELETE FROM blobs WHERE blob_id = ?1", [id])?;
        tx.execute("DELETE FROM blob_fetch WHERE blob_id = ?1", [id])?;
        tx.execute("DELETE FROM blob_tickets WHERE blob_id = ?1", [id])?;
        done.push(id.clone());
    }
    Ok(done)
}

fn remove_user_in(
    tx: &rusqlite::Transaction<'_>,
    user: &str,
    now_ms: i64,
    by: RevokedBy,
    mac: &dyn Fn(&str) -> Result<Vec<u8>, DbError>,
) -> Result<Vec<String>, DbError> {
    let devices = {
        let mut st =
            tx.prepare("SELECT device_id FROM devices WHERE user = ?1 AND revoked_ms IS NULL")?;
        let rows = st.query_map([user], |r| r.get(0))?;
        rows.collect::<Result<Vec<String>, _>>()?
    };
    for d in &devices {
        revoke_in(tx, d, now_ms, by, None)?;
    }
    // 정보 파기 A(10-25 결정, m1-spec §17.3): 평문 이메일·표시 이름·동의 기록·팀·기기 암호화 키를 지우고 아이디·
    // email_mac(되살리기용)·기기 행(id·서명 공개키 — 꺼져 있던 기기에 서명 확인 뒤 '빠졌다'를 알리려고)만 남긴다.
    let email: Option<String> =
        tx.query_row("SELECT email FROM users WHERE user = ?1", [user], |r| {
            r.get(0)
        })?;
    let email_mac = email.as_deref().map(mac).transpose()?;
    tx.execute(
        "UPDATE users SET removed_ms = ?2, email = NULL, email_mac = ?3, display = NULL,
         privacy_version = NULL, privacy_ms = NULL, invited_by = NULL WHERE user = ?1",
        params![user, now_ms, email_mac],
    )?;
    // 초대 관계는 양쪽 다 끊는다(#382, protocol 조직 절 '내보내기·나가기 때 지움'): 이 사람이 초대한 사람들의 invited_by 도
    // 지운다 — 같은 아이디로 돌아와도 옛 초대 관계(invited_by_me·invited_me)가 되살아나지 않게.
    tx.execute(
        "UPDATE users SET invited_by = NULL WHERE invited_by = ?1",
        [user],
    )?;
    tx.execute("DELETE FROM user_teams WHERE user = ?1", [user])?;
    // 처리방침 0.2.0 3항: 기기 바꾸기 요청·막은 기록은 조직을 나가면 함께 지운다(나간 뒤 남기는 것에 들지 않음).
    tx.execute("DELETE FROM recoveries WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM recovery_blocks WHERE user = ?1", [user])?;
    // #845: 연락처 관계는 양쪽 줄 다 지운다(계정이 끝나면 연락처도 끝남 — 둘째 묶음 전까지).
    tx.execute("DELETE FROM links WHERE user = ?1 OR peer = ?1", [user])?;
    tx.execute("DELETE FROM link_invites WHERE requester = ?1", [user])?;
    tx.execute("DELETE FROM link_counts WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM blob_daily WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM blob_history_daily WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM contact_links WHERE user = ?1", [user])?;
    // #877: 이 사람이 남을 막은 줄은 지운다. 남이 이 사람을 막은 줄(blocked = 이 사람)은 둔다 — 같은 아이디로 돌아오면
    // 30일 막음 셈(LINK_BLOCK_WINDOW_MS)이 그대로 걸리게.
    tx.execute("DELETE FROM blocks WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM mutes WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM pins WHERE user = ?1", [user])?;
    // #845 둘째: 이 사람의 목록은 지우고, 남의 목록에서도 뺀다.
    tx.execute("DELETE FROM lists WHERE owner = ?1", [user])?;
    let owners: Vec<String> = {
        let mut st = tx.prepare(
            "SELECT DISTINCT owner FROM lists WHERE EXISTS(SELECT 1 FROM json_each(lists.users) WHERE value = ?1)",
        )?;
        let r = st.query_map([user], |r| r.get(0))?;
        r.collect::<Result<_, _>>()?
    };
    for o in &owners {
        drop_from_lists_in(tx, o, user)?;
    }
    tx.execute("DELETE FROM org_invites WHERE user = ?1 OR by = ?1", [user])?;
    tx.execute(
        "DELETE FROM group_invites WHERE user = ?1 OR by = ?1",
        [user],
    )?;
    tx.execute(
        "DELETE FROM invites_sent WHERE by = ?1 OR target_user = ?1",
        [user],
    )?;
    // 묶음 15: 올렸지만 묶이지 않은 첨부·프로필 사진. 파일은 청소(`Db::blob_sweep` 뒤 고아 파일)가 지운다.
    tx.execute(
        "DELETE FROM blobs WHERE user = ?1 AND state IN ('reserved','uploaded')",
        [user],
    )?;
    tx.execute(
        "UPDATE users SET avatar_blob = NULL WHERE user = ?1",
        [user],
    )?;
    // 묶음 16: 모든 그룹에서 뺀다(서버는 group 메시지를 만들지 않는다). 지금 멤버가 없게 된 그룹은 지운다.
    tx.execute(
        "UPDATE group_members SET left_seq = (SELECT seq FROM groups g WHERE g.gid = group_members.gid), org_left = 1,
                left_org = (SELECT org FROM users WHERE user = ?1)
         WHERE user = ?1 AND left_seq IS NULL",
        [user],
    )?;
    drop_left_rejoin_in(tx, None, user)?;
    // 첨부 파일은 청소가(위와 같이).
    drop_empty_groups_in(tx)?;
    // 묶음 22 §12-13 ②: 남은 그룹마다 남은 기기가 그 사람의 잎을 모두 빼는 org_left Commit 을 내도록(subject = 아이디).
    tx.execute(
        "INSERT OR IGNORE INTO mls_duties(group_id, task, subject, created_ms)
         SELECT m.gid, 'remove_user', ?1, ?2 FROM group_members m
           JOIN mls_groups g ON g.group_id = m.gid
         WHERE m.user = ?1 AND m.org_left = 1
           AND EXISTS(SELECT 1 FROM mls_leaves l JOIN devices d ON d.device_id = l.device_id
                      WHERE l.group_id = m.gid AND d.user = ?1)",
        params![user, now_ms],
    )?;
    // 폐기가 먼저 만든 기기 단위 일(remove_device)은 그 그룹에선 사람 단위 일 하나로 — org_left Commit 이 나가게(화면 줄).
    tx.execute(
        "DELETE FROM mls_duties WHERE task = 'remove_device'
           AND subject IN (SELECT device_id FROM devices WHERE user = ?1)
           AND group_id IN (SELECT group_id FROM mls_duties WHERE task = 'remove_user' AND subject = ?1)",
        [user],
    )?;
    tx.execute(
        "UPDATE devices SET x25519 = '', x25519_sig = NULL, revoke_at = NULL, revoke_signer = NULL, revoke_sig = NULL
         WHERE user = ?1",
        [user],
    )?;
    tx.execute("DELETE FROM org_admins WHERE user = ?1", [user])?;
    tx.execute("DELETE FROM invites WHERE created_by = ?1", [user])?;
    Ok(devices)
}

/// [`Db::groups_of`] 의 한 줄(묶음 16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub gid: String,
    pub seq: u64,
    /// 조직 빠짐으로 나간 멤버 (아이디, left_seq).
    pub org_left: Vec<(String, u64)>,
    /// #845 ④ 그룹 초대를 수락해 add 를 기다리는 사람(아이디).
    pub joining: Vec<String>,
}

/// 그룹의 잎 기기 표를 새로 하고(§7), 그로써 끝난 일을 지운다: add_device 는 대상이 잎이 됨, remove_device 는 대상이 빠짐.
fn set_leaves_in(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    leaves: &[String],
) -> Result<(), DbError> {
    tx.execute("DELETE FROM mls_leaves WHERE group_id = ?1", [group_id])?;
    for d in leaves {
        tx.execute(
            "INSERT OR IGNORE INTO mls_leaves(group_id, device_id) VALUES (?1, ?2)",
            params![group_id, d],
        )?;
    }
    tx.execute(
        "DELETE FROM mls_duties WHERE group_id = ?1 AND (
           (task = 'add_device' AND subject IN (SELECT device_id FROM mls_leaves WHERE group_id = ?1))
           OR (task = 'remove_device' AND subject NOT IN (SELECT device_id FROM mls_leaves WHERE group_id = ?1))
           OR (task = 'remove_user' AND NOT EXISTS(SELECT 1 FROM mls_leaves l JOIN devices d ON d.device_id = l.device_id
                 WHERE l.group_id = ?1 AND d.user = mls_duties.subject)))",
        [group_id],
    )?;
    tx.execute(
        "DELETE FROM mls_duty_ranks WHERE group_id = ?1 AND NOT EXISTS(
           SELECT 1 FROM mls_duties d WHERE d.group_id = mls_duty_ranks.group_id
             AND d.task = mls_duty_ranks.task AND d.subject = mls_duty_ranks.subject)",
        [group_id],
    )?;
    Ok(())
}

/// 봉투 헤더·본문 한 줄. 같은 msg_id 면 Conflict.
fn insert_envelope(
    tx: &rusqlite::Transaction<'_>,
    h: &StoredHeader,
    message: &str,
    handshake_group: Option<&str>,
) -> Result<(), DbError> {
    let n = tx.execute(
        "INSERT OR IGNORE INTO envelopes(msg_id, kind, from_user, from_address, to_user, to_address,
           expires_ms, env_state, sender_view, abort_reason, message, handshake_group)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            h.msg_id,
            h.kind,
            h.from_user,
            h.from_address,
            h.to_user,
            h.to_address,
            h.expires_ms,
            h.env_state,
            h.sender_view,
            h.abort_reason,
            message,
            handshake_group
        ],
    )?;
    if n == 0 {
        return Err(DbError::Conflict);
    }
    Ok(())
}

/// 받을 기기 행이 하나도 없으면 봉투를 지운다 — 행 없는 봉투는 옛 규칙(받는 사용자의 아무 기기)으로 헤더까지 나가므로
/// (§5d 잎 목록만). 보낸 쪽에는 ack 만 간다.
fn drop_if_no_target(tx: &rusqlite::Transaction<'_>, msg_id: &str) -> Result<Vec<String>, DbError> {
    let none: bool = tx.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1)",
        [msg_id],
        |r| r.get(0),
    )?;
    if !none {
        return Ok(Vec::new());
    }
    let removed = drop_blobs_of(tx, msg_id)?;
    tx.execute("DELETE FROM envelopes WHERE msg_id = ?1", [msg_id])?;
    Ok(removed)
}

/// 그 메시지에 묶인 blob 행을 지운다(붙잡힌 GroupInfo 는 빼고). 지운 id.
fn drop_blobs_of(tx: &rusqlite::Transaction<'_>, msg_id: &str) -> Result<Vec<String>, DbError> {
    let ids: Vec<String> = {
        let mut st = tx.prepare("SELECT blob_id FROM blobs WHERE msg_id = ?1")?;
        let rows = st.query_map([msg_id], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    delete_blob_rows(tx, &ids)
}

/// 그룹의 지금 GroupInfo blob 을 바꾼다(없으면 풀기). 새 blob 은 묶인 상태로(보낸 사용자 것, `msg_id` 는 그 Commit·start —
/// 묶을 수 없으면 [`DbError::BlobUnavailable`]). 푼 옛 blob 의 메시지가 이미 없거나(start 는 봉투를 남기지 않음) 모두 받았으면
/// 그 행을 지금 지운다 — 붙잡혀 있던 동안 청소가 건너뛰어 고아로 남지 않게. 지운 id(파일은 호출자가).
fn set_gi_pin_in(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    pin: Option<&GiPin>,
    msg_id: &str,
    user: &str,
) -> Result<Vec<String>, DbError> {
    let old: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT g.blob_id, b.msg_id FROM mls_gi_blobs g LEFT JOIN blobs b ON b.blob_id = g.blob_id
             WHERE g.group_id = ?1",
            [group_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    tx.execute("DELETE FROM mls_gi_blobs WHERE group_id = ?1", [group_id])?;
    if let Some(p) = pin {
        tx.execute(
            "INSERT INTO mls_gi_blobs(group_id, blob_id, size, sha256) VALUES (?1, ?2, ?3, ?4)",
            params![
                group_id,
                p.blob_id,
                i64::try_from(p.size).unwrap_or(i64::MAX),
                p.sha256
            ],
        )?;
        bind_mls_blobs_in(tx, msg_id, user, std::slice::from_ref(&p.blob_id))?;
    }
    let Some((old, old_msg)) = old else {
        return Ok(Vec::new());
    };
    if pin.is_some_and(|p| p.blob_id == old) {
        return Ok(Vec::new());
    }
    let live = match old_msg {
        Some(m) => {
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM envelopes WHERE msg_id = ?1)",
                [&m],
                |r| r.get::<_, bool>(0),
            )? && tx.query_row(ALL_FETCHED_OPEN, [&old], |r| r.get::<_, bool>(0))?
        }
        None => false,
    };
    if live {
        return Ok(Vec::new());
    }
    delete_blob_rows(tx, std::slice::from_ref(&old))
}

/// Handshake 의 blob 칸을 이 메시지에 묶는다(§5c). 이미 이 메시지에 묶인 것은 그대로. 하나라도 묶을 수 없으면(묶기 검사는
/// 트랜잭션 밖이라 그 사이 다른 메시지가 먼저 묶었을 수 있다) [`DbError::BlobUnavailable`] — 호출자 트랜잭션째 되돌린다.
fn bind_mls_blobs_in(
    tx: &rusqlite::Transaction<'_>,
    msg_id: &str,
    user: &str,
    ids: &[String],
) -> Result<(), DbError> {
    for b in ids {
        let n = tx.execute(
            "UPDATE blobs SET state = 'attached', msg_id = ?1
             WHERE blob_id = ?2 AND user = ?3 AND purpose = 'message'
               AND ((state = 'uploaded' AND msg_id IS NULL AND for_device IS NULL) OR (state = 'attached' AND msg_id = ?1))",
            params![msg_id, b, user],
        )?;
        if n != 1 {
            return Err(DbError::BlobUnavailable);
        }
    }
    Ok(())
}

/// 그 기기 앞 그 그룹의 받지 않은 Handshake 를 비우고(남은 대상이 모두 받았으면 본문도) rejoin 표시를 한다(§5a).
fn evict_handshakes(
    tx: &rusqlite::Transaction<'_>,
    device_id: &str,
    group: &str,
    now_ms: i64,
) -> Result<Vec<String>, DbError> {
    let dropped: Vec<String> = {
        let mut st = tx.prepare(
            "DELETE FROM envelope_devices WHERE device_id = ?1 AND acked_ms IS NULL
               AND msg_id IN (SELECT msg_id FROM envelopes WHERE handshake_group = ?2)
             RETURNING msg_id",
        )?;
        let rows = st.query_map(params![device_id, group], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for msg_id in &dropped {
        tx.execute(
            "UPDATE envelopes SET message = NULL WHERE msg_id = ?1 AND message IS NOT NULL
               AND NOT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1 AND acked_ms IS NULL)",
            [msg_id],
        )?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO mls_rejoin(device_id, group_id, at_ms) VALUES (?1, ?2, ?3)",
        params![device_id, group, now_ms],
    )?;
    // 받을 기기가 하나도 안 남은 Handshake 의 blob 은 같이 지운다(§5c — 헤더는 30일까지 남아도 blob 은 쓸 데가 없다).
    let mut removed = Vec::new();
    for msg_id in &dropped {
        let none: bool = tx.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM envelope_devices WHERE msg_id = ?1)",
            [msg_id],
            |r| r.get(0),
        )?;
        if none {
            removed.extend(drop_blobs_of(tx, msg_id)?);
        }
    }
    Ok(removed)
}

/// 열이 없으면 더한다(이관). `table`·`col`·`decl` 은 이 파일의 상수다(사용자 입력 아님).
/// OS 푸시 토큰 하나를 쥘 수 있는 기기(계정) 수 — 휴대폰 계정 상한(multi-account-mobile 판정 §6, 5)과 같다.
pub const PUSH_TOKEN_DEVICES: i64 = 5;

/// 옛 DB 의 `push_tokens UNIQUE(platform, token)` 을 푼다(휴대폰 여러 계정). sqlite 는 제약만 못 지우니 지금 열 그대로
/// 표를 다시 만들어 옮긴다. 이미 풀렸으면 아무 일 없음.
fn unique_push_token_off(conn: &Connection) -> Result<(), DbError> {
    let old: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'push_tokens'
           AND sql LIKE '%UNIQUE (platform, token)%')",
        [],
        |r| r.get(0),
    )?;
    if !old {
        return Ok(());
    }
    let cols: Vec<(String, String, bool, Option<String>, bool)> = conn
        .prepare("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('push_tokens') ORDER BY cid")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? > 0)))?
        .collect::<Result<_, _>>()?;
    let defs: Vec<String> = cols
        .iter()
        .map(|(name, ty, notnull, dflt, pk)| {
            let mut d = format!("{name} {ty}");
            if *pk {
                d.push_str(" PRIMARY KEY");
            } else if *notnull {
                d.push_str(" NOT NULL");
            }
            if let Some(v) = dflt {
                d.push_str(" DEFAULT ");
                d.push_str(v);
            }
            d
        })
        .collect();
    let names = cols
        .iter()
        .map(|c| c.0.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;
         ALTER TABLE push_tokens RENAME TO push_tokens_unique;
         CREATE TABLE push_tokens ({});
         INSERT INTO push_tokens({names}) SELECT {names} FROM push_tokens_unique;
         DROP TABLE push_tokens_unique;
         COMMIT;",
        defs.join(", ")
    ))?;
    Ok(())
}

fn add_column(conn: &Connection, table: &str, col: &str, decl: &str) -> Result<(), DbError> {
    let has: bool = conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)"),
        [col],
        |r| r.get(0),
    )?;
    if !has {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {decl}"))?;
    }
    Ok(())
}

/// 길이가 같을 때만 비교하는 상수 시간 비교.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// devrevoke 증명(묶음 22 §12-11 ⓐ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeProof {
    /// 받은 RFC 3339 문자열 그대로(서명 입력).
    pub at: String,
    pub signer: String,
    pub sig: String,
}

/// 증명 있는 폐기 하나(디렉터리 `revocations[]`, 묶음 22 §12-11 ⓐ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRow {
    pub device_id: String,
    pub created_ms: i64,
    pub ed25519: String,
    pub x25519: String,
    pub proof: RevokeProof,
}

/// 등록된 기기 하나의 공개 정보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub device_id: String,
    pub ed25519: String,
    pub x25519: String,
    /// `x25519_sig`(#313). #313 전에 등록한 기기는 `None` — 디렉터리에 그대로 싣지 않는다.
    pub x25519_sig: Option<String>,
    /// 등록 시각(문서의 `added_ms`, #339).
    pub created_ms: i64,
    /// 기기 이름(#490). 디렉터리는 본인 항목에만 싣는다 — 관리자 목록·감사·로그에 쓰지 않는다.
    pub name: Option<String>,
    /// 마지막 접속한 날의 UTC 0시(ms, 묶음 22 §12-27 ⓑ). 그 전 기기는 `None`.
    pub last_seen_day: Option<i64>,
    /// 마지막으로 붙은 hello.v(#598 ②). 그 판 뒤로 안 붙은 기기는 `None`.
    pub hello_v: Option<i64>,
    /// 마지막으로 붙어 있던 시각(ms, #577 — 인증 때·마지막 연결이 끊길 때). 그 전 기기는 `None`.
    pub last_auth_ms: Option<i64>,
    /// 기기가 스스로 알린 OS(판 15 `device.name.os`). 본인 항목에만 — 표시용.
    pub os: Option<String>,
    /// 마지막 연결이 어떻게 끝났나(#870 — `sleep`·`quit`·`lost`). 그 전 기기는 `None`.
    pub away: Option<String>,
}

/// #845 수락된 연락처 한 줄: (상대, 내가 task 를 열었나, 상대가 나에게 열었나, 수락 시각 ms).
pub type LinkRow = (String, bool, bool, Option<i64>, bool);

/// #577 메일 확인 끊기 한 줄(사용자당 하나).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRow {
    pub user: String,
    pub requester: String,
    pub created_ms: i64,
    /// scheduled: 끊길 시각.
    pub at_ms: i64,
    /// 끊길(끊긴) 옛 기기.
    pub targets: Vec<String>,
    pub state: RecoveryState,
    /// 끝난 시각(blocked·canceled·done).
    pub ended_ms: Option<i64>,
    /// blocked: 막은 기기.
    pub blocked_by: Option<String>,
    /// #737: 대상이 붙어서 한 번 미뤘다.
    pub deferred: bool,
}

/// [`RecoveryRow::state`]. `certified`·요청 기기 사라짐은 행을 지운다(정상 경로 — 창 없음).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Scheduled,
    Blocked,
    Canceled,
    Done,
}

impl RecoveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Blocked => "blocked",
            Self::Canceled => "canceled",
            Self::Done => "done",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scheduled" => Self::Scheduled,
            "blocked" => Self::Blocked,
            "canceled" => Self::Canceled,
            "done" => Self::Done,
            _ => return None,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// #490 묶음 28 §4: 같은 값은 바뀐 것이 아니고, 폐기하면 기기 이름도 지운다(처리방침 나감 파기와 같게).
    #[test]
    fn device_name_set_is_idempotent_and_revoke_clears_it() {
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('a', 'o');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES ('k1', 'a', 'e', 'x', 0);",
            )
            .unwrap();
        assert_eq!(db.device_name("k1").unwrap(), Some(None));
        assert!(db.set_device_name("k1", Some("맥")).unwrap());
        assert!(!db.set_device_name("k1", Some("맥")).unwrap(), "같은 값");
        assert_eq!(db.device_name("k1").unwrap(), Some(Some("맥".into())));
        assert_eq!(db.devices_of("a").unwrap()[0].name.as_deref(), Some("맥"));
        db.touch_last_auth("k1", 86_400_000).unwrap();
        db.c()
            .execute(
                "UPDATE devices SET last_seen_day = 86400000 WHERE device_id = 'k1'",
                [],
            )
            .unwrap();
        db.revoke_device("k1", 1, None).unwrap();
        // 처리방침 0.2.0: 폐기된 기기는 마지막 접속 날·인증 시각도 남기지 않는다.
        let seen: (Option<i64>, Option<i64>) = db
            .c()
            .query_row(
                "SELECT last_seen_day, last_auth_ms FROM devices WHERE device_id = 'k1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(seen, (None, None));
        let name: Option<String> = db
            .c()
            .query_row("SELECT name FROM devices WHERE device_id = 'k1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(name, None, "폐기하면 지움");
        assert_eq!(db.device_name("k1").unwrap(), None);
        assert!(
            !db.set_device_name("k1", Some("다시")).unwrap(),
            "폐기된 기기"
        );
    }

    /// 묶음 15 §23.7: 파일 저장 공간은 첨부와 프로필 사진을 따로 센다(바이트는 합계).
    #[test]
    fn blob_totals_split_attachments_and_avatars() {
        let db = Db::memory().unwrap();
        assert_eq!(db.blob_totals().unwrap(), ((0, 0), (0, 0)));
        for (id, avatar, len) in [("b1", false, 100), ("b2", false, 50), ("b3", true, 7)] {
            assert!(db
                .blob_reserve(
                    &NewBlob {
                        blob_id: id,
                        user: "a",
                        device: "k1",
                        avatar,
                        for_org: None,
                        for_device: None,
                        ct_len: len,
                        put_token_hash: b"h",
                        put_token_exp: 1,
                        now_ms: 0,
                    },
                    u64::MAX,
                )
                .unwrap());
        }
        assert_eq!(db.blob_totals().unwrap(), ((150, 2), (7, 1)));
    }

    /// #888: 같은 사용자의 기기 등록 시각은 늘 직전보다 크다 — 같은 ms(시계 고정)·시계가 뒤로 가도. 뿌리(가장 이른 기기)는
    /// 아이디 순이 아니라 먼저 등록한 기기로 남는다.
    #[test]
    fn device_created_ms_is_strictly_increasing_per_user() {
        let db = Db::memory().unwrap();
        // 첫 기기는 아이디가 뒤(Z), 둘째는 앞(A) — 같은 ms 면 전엔 둘째가 뿌리가 됐다.
        for (id, now, existing) in [
            ("k1_ZZZZZZZZZZZZZZZZZZZZZZ", 1_000, false),
            ("k1_AAAAAAAAAAAAAAAAAAAAAA", 1_000, true),
            ("k1_BBBBBBBBBBBBBBBBBBBBBB", 400, true),
        ] {
            db.register_device("a", None, id, "e", "x", "s", now, existing)
                .unwrap();
        }
        // 다른 사용자는 따로 센다.
        db.register_device(
            "b",
            None,
            "k1_CCCCCCCCCCCCCCCCCCCCCC",
            "e",
            "x",
            "s",
            1_000,
            false,
        )
        .unwrap();
        let at = |u: &str| -> Vec<(String, i64)> {
            db.devices_of(u)
                .unwrap()
                .into_iter()
                .map(|d| (d.device_id, d.created_ms))
                .collect()
        };
        assert_eq!(
            at("a"),
            vec![
                ("k1_ZZZZZZZZZZZZZZZZZZZZZZ".to_owned(), 1_000),
                ("k1_AAAAAAAAAAAAAAAAAAAAAA".to_owned(), 1_001),
                ("k1_BBBBBBBBBBBBBBBBBBBBBB".to_owned(), 1_002),
            ]
        );
        assert_eq!(
            at("b"),
            vec![("k1_CCCCCCCCCCCCCCCCCCCCCC".to_owned(), 1_000)]
        );
    }

    #[test]
    fn db_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("lodelai-relay-db-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("relay.sqlite3");
        let _ = std::fs::remove_file(&path);
        let db = Db::open(&path).unwrap();
        db.register_device(
            "a",
            None,
            "k1_AAAAAAAAAAAAAAAAAAAAAA",
            "e",
            "x",
            "s",
            0,
            false,
        )
        .unwrap();
        for name in ["relay.sqlite3", "relay.sqlite3-wal", "relay.sqlite3-shm"] {
            let p = d.join(name);
            if p.exists() {
                assert_eq!(
                    std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{name}"
                );
            }
        }
        drop(db);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn backup_record_follows_attempt_ok_offsite_failed() {
        let db = Db::memory().unwrap();
        let r = db.backup_record().unwrap();
        assert_eq!(
            (r.last, r.offsite, r.last_ok_ms),
            (BackupLast::None, BackupOffsite::None, None)
        );
        db.backup_started(10).unwrap();
        db.backup_succeeded(11).unwrap();
        db.backup_offsite(BackupOffsite::Ok).unwrap();
        let r = db.backup_record().unwrap();
        assert_eq!(
            r,
            BackupRecord {
                last_attempt_ms: Some(10),
                last_ok_ms: Some(11),
                last: BackupLast::Ok,
                offsite: BackupOffsite::Ok
            }
        );
        // 다음 시도가 중간에 실패: 시도 시각만 새로, 마지막 성공은 그대로, 바깥 사본은 이번 것 없음
        db.backup_started(20).unwrap();
        db.backup_failed().unwrap();
        let r = db.backup_record().unwrap();
        assert_eq!(
            (r.last_attempt_ms, r.last_ok_ms, r.last, r.offsite),
            (Some(20), Some(11), BackupLast::Failed, BackupOffsite::None)
        );
    }

    #[test]
    fn health_reads_a_real_table() {
        let db = Db::memory().unwrap();
        db.health().unwrap();
        db.c().execute_batch("DROP TABLE meta").unwrap();
        assert!(db.health().is_err());
    }

    #[test]
    fn old_sessions_public_gets_title_and_folder() {
        // 세션 이름(m1-spec §2) 전 DB: 열이 없던 공개 세션 행은 그대로 남고 title·folder 는 NULL.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (user TEXT PRIMARY KEY, org TEXT NOT NULL, display TEXT);
             INSERT INTO users(user, org) VALUES ('a', 'o');
             CREATE TABLE sessions_public (user TEXT NOT NULL, slug TEXT NOT NULL, grade TEXT NOT NULL,
               liveness TEXT NOT NULL, display TEXT, PRIMARY KEY (user, slug));
             INSERT INTO sessions_public VALUES ('a', 'old', 'task', 'dead', '옛 세션');",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        let old = &db.sessions_in_org("o").unwrap()[0];
        assert_eq!(
            (
                old.display.as_deref(),
                old.title.as_deref(),
                old.folder.as_deref()
            ),
            (Some("옛 세션"), None, None)
        );
        db.publish_session(
            &PublicSession {
                user: "a".into(),
                slug: "old".into(),
                grade: "task".into(),
                liveness: "live:pty".into(),
                display: Some("제목 · lodelai".into()),
                title: Some("제목".into()),
                folder: Some("lodelai".into()),
                project: None,
                busy: false,
                audience: Some(vec!["b".into()]),
                audience_lists: Vec::new(),
                listed: Vec::new(),
                agent: Some("codex".into()),
                no: Some(6),
                offline: false,
            },
            None,
        )
        .unwrap();
        let s = &db.sessions_in_org("o").unwrap()[0];
        assert_eq!(s.audience.as_deref(), Some(&["b".to_owned()][..]));
        assert_eq!(s.agent.as_deref(), Some("codex"), "옛 표에 더한 agent 열");
        assert_eq!(s.no, Some(6), "옛 표에 더한 no 열");
        assert!(
            s.reaches("a") && s.reaches("b") && !s.reaches("c"),
            "주인·범위 안만"
        );
        assert_eq!(
            (s.title.as_deref(), s.folder.as_deref()),
            (Some("제목"), Some("lodelai"))
        );
        // 다시 열어도(열이 이미 있음) 그대로.
        assert!(Db::init(db.conn.into_inner().unwrap()).is_ok());
    }
    #[test]
    fn envelope_without_device_rows_keeps_first_ack_rule() {
        // 기기별 보관 이전에 저장된 봉투(대상 행 없음)는 어느 기기에나 가고 첫 ack 에 지운다(protocol §7.2-6).
        let db = Db::memory().unwrap();
        let h = StoredHeader {
            msg_id: "01JB0000000000000000000009".into(),
            kind: "chat".into(),
            from_user: "alice".into(),
            from_address: "alice@local".into(),
            to_user: "bob".into(),
            to_address: "bob@local".into(),
            expires_ms: i64::MAX,
            env_state: "stored".into(),
            sender_view: "stored".into(),
            abort_reason: None,
        };
        assert!(db
            .store_envelope(&h, "{}", &[], None, None)
            .unwrap()
            .is_empty());
        assert_eq!(db.pending_for("bob", "any-device").unwrap().len(), 1);
        assert_eq!(
            db.ack_device(&h.msg_id, "any-device", 1).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn group_holds_up_to_50_members() {
        // #553: 상한은 GROUP_MAX_MEMBERS(50, 22 §4-3) — 17~50번째 add 는 되고 51번째는 안 된다. 만들기 Commit 의 처음 멤버는 나 빼고 49.
        assert_eq!(lodelai_protocol::constants::GROUP_MAX_MEMBERS, 50);
        let db = Db::memory().unwrap();
        let u = |n: usize| format!("u{n:02}");
        for n in 0..=51 {
            db.c()
                .execute("INSERT INTO users(user, org) VALUES (?1, 'o')", [u(n)])
                .unwrap();
        }
        let ulid = |n: u32| format!("01JB{n:022}");
        let created = |gid: &str, n: u32| {
            db.group_create_mls(gid, &u(0), b"s", b"gi", None, "u00-d1", &ulid(n), 1)
                .unwrap()
                .is_some()
        };
        let op = |gid: &'static str, op: &'static str, subject: String| {
            db.group_op_allowed(&GroupOp {
                gid,
                op,
                sender: "u00",
                subject: Some(&subject),
                admin: None,
                now_ms: 0,
            })
            .unwrap()
        };
        assert!(created("g1", 1));
        let names = |r: std::ops::RangeInclusive<usize>| r.map(u).collect::<Vec<_>>().join("\n");
        assert!(op("g1", "create", names(1..=49)));
        assert!(!op("g1", "create", names(1..=50)));

        // 멤버를 하나씩: 지금 n명이면 n+1 번째 add.
        for n in 1..=50 {
            let next = u(n);
            if n < 50 {
                assert!(op("g1", "add", next.clone()), "{}번째", n + 1);
                db.c()
                    .execute(
                        "INSERT INTO group_members(gid, user, role, joined_seq) VALUES ('g1', ?1, 'member', 1)",
                        [&next],
                    )
                    .unwrap();
            } else {
                assert!(!op("g1", "add", next), "51번째는 거절");
            }
        }
    }

    #[test]
    fn setup_rekey_keeps_newly_written_code_on_same_ms() {
        // #738: 같은 ms 에 같은 이메일 코드가 둘이어도 '가장 늦은 것'이 무작위 id 로 갈리지 않는다 — 지난 바꾸기 뒤 CLI 가 쓴
        // 행이 남고, 막 바꾼 것끼리는 늦게 넣은 행이 남는다.
        let db = Db::memory().unwrap();
        db.set_setup_email_key(b"k".repeat(32));
        let sha = setup_email_hash("boss@x.io");
        let ids = |db: &Db| -> Vec<String> {
            let c = db.c();
            let mut st = c
                .prepare("SELECT id FROM setup_codes WHERE email_hash IS NOT NULL ORDER BY rowid")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        db.add_setup_code("zz", b"c1", Some(&sha), Some("b***"), 1_000, 100)
            .unwrap();
        assert_eq!(db.setup_codes_rekey().unwrap(), 1);
        db.add_setup_code("aa", b"c2", Some(&sha), Some("b***"), 1_000, 100)
            .unwrap();
        assert_eq!(db.setup_codes_rekey().unwrap(), 1);
        assert_eq!(ids(&db), ["aa"]);
        db.c()
            .execute_batch(&format!(
                "INSERT INTO setup_codes(id, code_hash, email_hash, email_mask, expires_ms, created_ms)
                   VALUES ('zz', x'03', x'{0}', NULL, 1000, 100), ('ab', x'04', x'{0}', NULL, 1000, 100);",
                sha.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ))
            .unwrap();
        assert_eq!(db.setup_codes_rekey().unwrap(), 2);
        assert_eq!(ids(&db), ["ab"]);
    }

    #[test]
    fn failed_start_is_taken_again_only_by_same_device_without_pending() {
        // 0.2.5: start 뒤 만들기가 끝내 실패한 빈 그룹(epoch 0·잎은 그 기기 하나·확정 전 Commit 없음)은 같은 사람·같은 기기의
        // 다시 start 로 딸린 행을 지우고 다시 받는다. 다른 계정·다른 기기·확정 전 Commit 이 남은 그룹은 Conflict 그대로.
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('alice', 'o'), ('bob', 'o');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES
                   ('alice-d1', 'alice', 'e', 'x', 0), ('alice-d2', 'alice', 'e', 'x', 0), ('bob-d1', 'bob', 'e', 'x', 0);",
            )
            .unwrap();
        let ulid = |n: u32| format!("01JB{n:022}");
        let start = |user: &str, dev: &str, n: u32| {
            db.group_create_mls("g1", user, b"s", b"gi", None, dev, &ulid(n), 1)
        };
        assert_eq!(start("alice", "alice-d1", 1).unwrap().map(|r| r.0), Some(1));
        // 남은 옛 결과·봉투 — 다시 받을 때 같이 지워져야 새 그룹을 흔들지 않는다.
        db.c()
            .execute_batch(
                "INSERT INTO mls_outcomes(group_id, epoch, commit_hash, final, group_seq, sender_user, excluded, at_ms, notified)
                   VALUES ('g1', 0, 'old', 0, NULL, 'alice', '', 1, 0);",
            )
            .unwrap();
        assert!(matches!(
            start("bob", "bob-d1", 2),
            Err(DbError::Conflict) | Ok(None)
        ));
        assert!(matches!(
            start("alice", "alice-d2", 3),
            Err(DbError::Conflict) | Ok(None)
        ));
        assert_eq!(start("alice", "alice-d1", 4).unwrap().map(|r| r.0), Some(1));
        let outcomes: i64 = db
            .c()
            .query_row(
                "SELECT COUNT(*) FROM mls_outcomes WHERE group_id = 'g1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(outcomes, 0);
        // 확정 전 Commit 이 남아 있으면 지우지 않는다(늦게 확정되면 두 그룹이 겹침).
        db.c()
            .execute_batch(
                "INSERT INTO mls_pending(group_id, epoch, msg_id, commit_hash, sender_user, sender_device, op, storage,
                   group_info, leaves, joining, excluded, delivered_ms, message, from_address, to_address, expires_ms)
                 VALUES ('g1', 0, 'm', 'h', 'alice', 'alice-d1', 'create', x'00', x'00', '', '', '', 1, '{}', 'a', 'b', 9);",
            )
            .unwrap();
        assert!(matches!(
            start("alice", "alice-d1", 5),
            Err(DbError::Conflict) | Ok(None)
        ));
    }

    #[test]
    fn failed_group_starts_sweep_drops_only_old_empty_starts() {
        // #805: create 확정 전(seq 1)·확정 전 Commit 없음·멤버 하나인 그룹만, 만든 지 30일이 지나면 지운다. 만든 사람의 다른
        // 기기가 스스로 들어 epoch·잎이 늘어난 실패 그룹도.
        const DAY: i64 = 24 * 60 * 60 * 1000;
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('alice', 'o'), ('bob', 'o');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES
                   ('alice-d1', 'alice', 'e', 'x', 0), ('alice-d2', 'alice', 'e', 'x', 0),
                   ('bob-d1', 'bob', 'e', 'x', 0);",
            )
            .unwrap();
        for (i, gid) in ["old", "young", "pending", "joined", "self_joined"]
            .iter()
            .enumerate()
        {
            let created = if *gid == "young" { DAY } else { 0 };
            db.group_create_mls(
                gid,
                "alice",
                b"s",
                b"gi",
                None,
                "alice-d1",
                &format!("01JB{:022}", i + 1),
                created,
            )
            .unwrap()
            .unwrap();
        }
        db.c()
            .execute_batch(
                "INSERT INTO mls_pending(group_id, epoch, msg_id, commit_hash, sender_user, sender_device, op, storage,
                   group_info, leaves, joining, excluded, delivered_ms, message, from_address, to_address, expires_ms)
                 VALUES ('pending', 0, 'm', 'h', 'alice', 'alice-d1', 'create', x'00', x'00', '', '', '', 1, '{}', 'a', 'b', 9);
                 UPDATE mls_groups SET epoch = 1 WHERE group_id IN ('joined', 'self_joined');
                 UPDATE groups SET seq = 2 WHERE gid = 'joined';
                 INSERT INTO group_members(gid, user, role, joined_seq) VALUES ('joined', 'bob', 'member', 2);
                 INSERT INTO mls_leaves(group_id, device_id) VALUES ('self_joined', 'alice-d2');",
            )
            .unwrap();
        let left = |db: &Db| -> Vec<String> {
            let c = db.c();
            let mut st = c
                .prepare("SELECT group_id FROM mls_groups ORDER BY group_id")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            db.failed_group_starts_sweep(30 * DAY - 1, 30 * DAY)
                .unwrap()
                .0,
            0
        );
        assert_eq!(
            db.failed_group_starts_sweep(30 * DAY, 30 * DAY).unwrap().0,
            2
        );
        assert_eq!(left(&db), ["joined", "pending", "young"]);
        let groups: i64 = db
            .c()
            .query_row("SELECT COUNT(*) FROM groups WHERE gid = 'old'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(groups, 0);
        assert_eq!(
            db.failed_group_starts_sweep(31 * DAY, 30 * DAY).unwrap().0,
            1
        );
        assert_eq!(left(&db), ["joined", "pending"]);
    }

    #[test]
    fn groups_of_lists_start_only_group_once_someone_is_joining() {
        // #845 §7-29: 시작만 받은 그룹(seq 1)은 빠지되(#817), 수락한 초대(들어가는 중)가 있으면 멤버에게 joining 과 함께 간다.
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('alice', 'o'), ('bob', 'p');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES ('alice-d1', 'alice', 'e', 'x', 0);",
            )
            .unwrap();
        db.group_create_mls(
            "solo",
            "alice",
            b"s",
            b"gi",
            None,
            "alice-d1",
            &format!("01JB{:022}", 1),
            0,
        )
        .unwrap()
        .unwrap();
        assert!(db.groups_of("alice").unwrap().is_empty());
        db.c()
            .execute_batch(
                "INSERT INTO group_invites(id, gid, user, by, at_ms) VALUES ('i1', 'solo', 'bob', 'alice', 1);",
            )
            .unwrap();
        assert!(
            db.groups_of("alice").unwrap().is_empty(),
            "수락 전엔 그대로"
        );
        db.c()
            .execute_batch("UPDATE group_invites SET accepted_ms = 2 WHERE id = 'i1';")
            .unwrap();
        let rows = db.groups_of("alice").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].gid.as_str(), rows[0].seq), ("solo", 1));
        assert_eq!(rows[0].joining, ["bob"]);
    }

    #[test]
    fn failed_group_starts_sweep_keeps_groups_with_live_invites() {
        // #845 §7-29: 29일째 다시 보낸 초대가 살아 있는 혼자 그룹은 30일 청소에서 남고, 초대가 다 끝난 그룹은 지우며 그 초대의
        // 줄·보낸 기록·안 간 메일도 같이 지운다.
        const DAY: i64 = 24 * 60 * 60 * 1000;
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('alice', 'o');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES ('alice-d1', 'alice', 'e', 'x', 0);",
            )
            .unwrap();
        for (i, gid) in ["live", "stale"].iter().enumerate() {
            db.group_create_mls(
                gid,
                "alice",
                b"s",
                b"gi",
                None,
                "alice-d1",
                &format!("01JB{:022}", i + 1),
                0,
            )
            .unwrap()
            .unwrap();
        }
        let day29 = 29 * DAY;
        db.c()
            .execute(
                "INSERT INTO group_invites(id, gid, email, by, at_ms) VALUES ('i1', 'live', 'b@x.l', 'alice', ?1), ('i2', 'stale', 'c@x.l', 'alice', 0)",
                [day29],
            )
            .unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO invites_sent(id, kind, scope, by, shown, target_email, recv_ref, at_ms)
                   VALUES ('i2', 'group', 'stale', 'alice', 'c@x.l', 'c@x.l', 'i2', 0);
                 INSERT INTO mail_jobs(id, kind, ref, email, sender, at_ms, after_ms)
                   VALUES ('j2', 'group', 'i2', 'c@x.l', 'alice', 0, 0);",
            )
            .unwrap();
        assert_eq!(
            db.failed_group_starts_sweep(30 * DAY, 30 * DAY).unwrap().0,
            1
        );
        let count = |sql: &str| -> i64 { db.c().query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(
            count("SELECT COUNT(*) FROM mls_groups WHERE group_id = 'live'"),
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM mls_groups WHERE group_id = 'stale'"),
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM group_invites WHERE gid = 'stale'"),
            0
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM invites_sent WHERE scope = 'stale'"),
            0
        );
        assert_eq!(count("SELECT COUNT(*) FROM mail_jobs WHERE ref = 'i2'"), 0);
        assert_eq!(
            count("SELECT COUNT(*) FROM group_invites WHERE gid = 'live'"),
            1
        );
    }

    /// #809 시험 바탕: alice 가 g1 에 보낸 m1(bob-d1·bob-d2·carol-d1 대상), 그 셋 다 g1 잎.
    fn unreadable_db() -> Db {
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('alice', 'o'), ('bob', 'o'), ('carol', 'o');
                 INSERT INTO devices(device_id, user, ed25519, x25519, created_ms) VALUES
                   ('alice-d1', 'alice', 'e', 'x', 0), ('bob-d1', 'bob', 'e', 'x', 0),
                   ('bob-d2', 'bob', 'e', 'x', 0), ('carol-d1', 'carol', 'e', 'x', 0);
                 INSERT INTO envelopes(msg_id, kind, from_user, from_address, to_user, to_address, expires_ms,
                   env_state, sender_view, message, gid)
                   VALUES ('m1', 'chat', 'alice', 'alice@l', '+g1', '+g1@l', 1000000, 'stored', 'sent', '{}', 'g1');
                 INSERT INTO envelope_devices(msg_id, device_id) VALUES
                   ('m1', 'bob-d1'), ('m1', 'bob-d2'), ('m1', 'carol-d1');
                 INSERT INTO mls_leaves(group_id, device_id) VALUES
                   ('g1', 'alice-d1'), ('g1', 'bob-d1'), ('g1', 'bob-d2'), ('g1', 'carol-d1');",
            )
            .unwrap();
        db
    }

    #[test]
    fn unreadable_report_gates_and_counts() {
        use UnreadableReport::{Limited, NotTarget, Plain, Recorded};
        let db = unreadable_db();
        assert_eq!(
            db.unreadable_report("m1", "alice-d1", 10, 100).unwrap(),
            NotTarget
        );
        assert_eq!(
            db.unreadable_report("nope", "bob-d1", 10, 100).unwrap(),
            Plain
        );
        assert_eq!(
            db.unreadable_report("m1", "bob-d1", 10, 100).unwrap(),
            Recorded
        );
        // 알림 전의 같은 보고는 셀 것이 없다.
        assert_eq!(
            db.unreadable_report("m1", "bob-d1", 11, 100).unwrap(),
            Plain
        );
        // 시간당 상한(이 기기에 이미 1 — 상한 1 이면 넘음).
        assert_eq!(
            db.unreadable_report("m1", "bob-d2", 12, 1).unwrap(),
            Recorded
        );
        db.c()
            .execute_batch(
                "INSERT INTO envelopes(msg_id, kind, from_user, from_address, to_user, to_address, expires_ms,
                   env_state, sender_view, message, gid)
                   VALUES ('m2', 'chat', 'alice', 'alice@l', '+g1', '+g1@l', 1000000, 'stored', 'sent', '{}', 'g1');
                 INSERT INTO envelope_devices(msg_id, device_id) VALUES ('m2', 'bob-d1');",
            )
            .unwrap();
        assert_eq!(
            db.unreadable_report("m2", "bob-d1", 13, 1).unwrap(),
            Limited
        );
        // 만료된 글은 받지 않는다.
        assert_eq!(
            db.unreadable_report("m2", "bob-d1", 1_000_000, 100)
                .unwrap(),
            Plain
        );
    }

    #[test]
    fn unreadable_due_waits_for_settle_rejoin_and_own_pending_commit() {
        let db = unreadable_db();
        db.unreadable_report("m1", "bob-d1", 0, 100).unwrap();
        db.unreadable_report("m1", "carol-d1", 0, 100).unwrap();
        let ids = |db: &Db, now: i64| -> Vec<String> {
            db.unreadable_due(now, 30_000)
                .unwrap()
                .into_iter()
                .map(|d| d.device_id)
                .collect()
        };
        assert!(ids(&db, 29_999).is_empty());
        assert_eq!(ids(&db, 30_000), ["bob-d1", "carol-d1"]);
        // 다시 들기 표시·그 기기가 보낸 확정 전 Commit·잎이 아님이면 미룬다.
        db.rejoin_mark("bob-d1", "g1", 1).unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO mls_pending(group_id, epoch, msg_id, commit_hash, sender_user, sender_device, op, storage,
                   group_info, leaves, joining, excluded, delivered_ms, message, from_address, to_address, expires_ms)
                 VALUES ('g1', 2, 'c', 'h', 'carol', 'carol-d1', 'update', x'00', x'00', '', '', '', 1, '{}', 'a', 'b', 9);",
            )
            .unwrap();
        assert!(ids(&db, 30_000).is_empty());
        db.c()
            .execute_batch(
                "DELETE FROM mls_pending; DELETE FROM mls_leaves WHERE device_id = 'carol-d1';",
            )
            .unwrap();
        assert!(ids(&db, 30_000).is_empty());
        db.c().execute_batch("DELETE FROM mls_rejoin;").unwrap();
        assert_eq!(ids(&db, 30_000), ["bob-d1"]);
    }

    #[test]
    fn unreadable_resend_then_rejoin_notifies_again_up_to_three() {
        let db = unreadable_db();
        let due = |db: &Db| db.unreadable_due(500_000, 0).unwrap();
        db.unreadable_report("m1", "bob-d1", 0, 100).unwrap();
        let round = |db: &Db| {
            let d = due(db);
            assert_eq!(d.len(), 1);
            db.unreadable_notified("m1", "bob-d1", true).unwrap();
            assert!(db.unreadable_waiting("m1", "alice").unwrap());
            assert_eq!(
                db.unreadable_fill("m1", "alice", "g1", "{}", None).unwrap(),
                ["bob-d1"]
            );
            d[0].final_
        };
        assert!(!round(&db));
        // 다시 보낸 본문을 둔 뒤 bob-d1 이 스스로 다시 들었다(확정 때 표시) — 또 못 열어도 n=1 로 한 번 더.
        db.c()
            .execute("UPDATE unreadable_reports SET rejoined = 1", [])
            .unwrap();
        assert_eq!(
            db.unreadable_report("m1", "bob-d1", 2, 100).unwrap(),
            UnreadableReport::Recorded
        );
        assert!(!round(&db));
        // 알림 둘 뒤에는 다시 들었어도 final.
        db.c()
            .execute("UPDATE unreadable_reports SET rejoined = 1", [])
            .unwrap();
        db.unreadable_report("m1", "bob-d1", 4, 100).unwrap();
        let d = due(&db);
        assert!(d[0].final_ && !d[0].opened);
        assert!(!db.unreadable_waiting("m1", "alice").unwrap());
    }

    #[test]
    fn unreadable_final_closes_when_same_person_opened() {
        let db = unreadable_db();
        db.unreadable_report("m1", "bob-d1", 0, 100).unwrap();
        // 같은 사람의 다른 기기(bob-d2)가 열었다 — 다른 사람(carol)이 연 것은 세지 않는다.
        db.unreadable_opened("m1", "carol-d1", 1).unwrap();
        assert!(!db.unreadable_due(1, 0).unwrap()[0].opened);
        db.unreadable_opened("m1", "bob-d2", 1).unwrap();
        assert!(db.unreadable_due(1, 0).unwrap()[0].opened);
        // 보고 전에 이미 연 기기가 있으면 처음부터 opened.
        db.ack_device("m1", "bob-d2", 1).unwrap();
        db.c()
            .execute_batch("DELETE FROM unreadable_reports;")
            .unwrap();
        db.unreadable_report("m1", "bob-d1", 2, 100).unwrap();
        assert!(db.unreadable_due(2, 0).unwrap()[0].opened);
    }

    #[test]
    fn invite_mail_skips_sender_without_verified_email() {
        // §7-30: 확인된 이메일이 없는 보낸 사람(옛 M1·자체 호스팅 초대 가입)은 메일을 보내지 않는다 — 요청 줄은 그대로.
        let db = Db::memory().unwrap();
        db.set_email_key(b"k-0123456789abcdef0123456789abcdef".to_vec());
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org, display) VALUES ('alice', 'o', '앤');
                 INSERT INTO users(user, org, display, email) VALUES ('bob', 'p', '밥', 'bob@x.io');",
            )
            .unwrap();
        let ulid = |n: u32| format!("01JB{n:022}");
        for (i, me) in ["alice", "bob"].iter().enumerate() {
            db.link_request(&LinkRequestIn {
                me,
                to: LinkTarget::Email("new@z.io"),
                shown: "new@z.io",
                id: &ulid(i as u32 + 1),
                now_ms: 1_000,
            })
            .unwrap();
        }
        let got = db.invite_mail_take(2_000, &MailLimits::default()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].sender.as_str(), got[0].from_email.as_str()),
            ("bob", "bob@x.io")
        );
        let jobs: i64 = db
            .c()
            .query_row(
                "SELECT COUNT(*) FROM mail_jobs WHERE sender = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(jobs, 0, "alice 의 메일 일은 버림");
        let kept: i64 = db
            .c()
            .query_row(
                "SELECT COUNT(*) FROM link_invites WHERE requester = 'alice'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, 1, "요청은 그대로");
    }

    #[test]
    fn display_names_skip_removed_and_empty() {
        // §7-57: 들어가는 중인 사람 이름 — 지운(나간) 계정·이름 없음은 빼고, 순서는 그대로.
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org, display) VALUES ('kai', 'o', 'Kai'), ('ann', 'o', 'Ann'), ('nobody', 'o', '');
                 INSERT INTO users(user, org, display, removed_ms) VALUES ('gone', 'o', 'Gone', 1);",
            )
            .unwrap();
        let names: Vec<String> = ["kai", "gone", "nobody", "zed", "ann"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            db.display_names(&names).unwrap(),
            [
                ("kai".to_owned(), "Kai".to_owned()),
                ("ann".to_owned(), "Ann".to_owned())
            ]
        );
    }

    #[test]
    fn pins_keep_order_cap_and_drop_with_group_or_link() {
        // #880: 한 동작씩 — 자리에 넣기·옮기기·풀기, 상한, 나간 그룹은 빠지고 연락처를 끊으면 서로의 1:1 고정이 빠진다.
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch(
                "INSERT INTO users(user, org) VALUES ('ann', 'o'), ('bob', 'p');
                 INSERT INTO group_members(gid, user, role, joined_seq) VALUES ('G1', 'ann', 'member', 1);
                 INSERT INTO links(user, peer, state, requested_ms) VALUES ('ann', 'bob', 'accepted', 0), ('bob', 'ann', 'accepted', 0);",
            )
            .unwrap();
        let set = |c: &str, i: Option<usize>| db.pin_set("ann", c, i, 3).unwrap();
        assert_eq!(set("bob@local", Some(0)), Some(true));
        assert_eq!(set("+g1@local", Some(0)), Some(true));
        assert_eq!(set("cy@local", Some(9)), Some(true), "길이로 자름");
        assert_eq!(
            db.pins_of("ann").unwrap(),
            ["+g1@local", "bob@local", "cy@local"]
        );
        // 찬 뒤 새 대화는 None, 있던 대화 옮기기는 된다. 같은 자리면 조용.
        assert_eq!(set("dan@local", Some(0)), None);
        assert_eq!(set("cy@local", Some(0)), Some(true));
        assert_eq!(set("cy@local", Some(0)), Some(false));
        assert_eq!(
            db.pins_of("ann").unwrap(),
            ["cy@local", "+g1@local", "bob@local"]
        );
        // 다른 기기가 동시에 한 동작씩 — 앞 고정이 사라지지 않는다(통째 교체 아님).
        assert_eq!(set("cy@local", None), Some(true));
        assert_eq!(set("dan@local", Some(1)), Some(true));
        assert_eq!(
            db.pins_of("ann").unwrap(),
            ["+g1@local", "dan@local", "bob@local"]
        );
        // 그룹에서 나가면 목록에서 빠지고, 다음 동작 때 줄도 지워져 자리가 빈다.
        db.c()
            .execute_batch(
                "UPDATE group_members SET left_seq = 2 WHERE gid = 'G1' AND user = 'ann';",
            )
            .unwrap();
        assert_eq!(db.pins_of("ann").unwrap(), ["dan@local", "bob@local"]);
        assert_eq!(set("eve@local", Some(0)), Some(true));
        assert_eq!(
            db.pins_of("ann").unwrap(),
            ["eve@local", "dan@local", "bob@local"]
        );
        // 연락처 끊기 → 서로의 1:1 고정이 빠진다(같은 접두의 다른 아이디는 그대로).
        assert_eq!(
            db.pin_set("bob", "ann@local", Some(0), 3).unwrap(),
            Some(true)
        );
        assert_eq!(
            db.pin_set("bob", "anna@local", Some(1), 3).unwrap(),
            Some(true)
        );
        assert!(db.link_remove("ann", "bob", false, 1).unwrap());
        assert_eq!(db.pins_of("ann").unwrap(), ["eve@local", "dan@local"]);
        assert_eq!(db.pins_of("bob").unwrap(), ["anna@local"]);
    }

    #[test]
    fn last_member_leave_drops_group_and_its_rows() {
        // #532: 마지막 멤버의 leave 는 같은 트랜잭션에서 그룹·딸린 MLS 상태·대기 봉투를 지운다 — 그 leave 봉투만 남는다.
        let db = Db::memory().unwrap();
        db.c()
            .execute_batch("INSERT INTO users(user, org) VALUES ('alice', 'o'), ('bob', 'o');")
            .unwrap();
        let ulid = |n: u32| format!("01JB{n:022}");
        assert!(db
            .group_create_mls("g1", "alice", b"s", b"gi", None, "alice-d1", &ulid(1), 1)
            .unwrap()
            .is_some());
        db.c()
            .execute_batch(
                "INSERT INTO group_members(gid, user, role, joined_seq) VALUES ('g1', 'bob', 'member', 1);
                 INSERT INTO mls_votes(group_id, epoch, commit_hash, user) VALUES ('g1', 1, 'h', 'bob');
                 INSERT INTO mls_rejoin(device_id, group_id, at_ms) VALUES ('alice-d1', 'g1', 1);
                 INSERT INTO mls_duties(group_id, task, subject, created_ms) VALUES ('g1', 'remove_user', 'bob', 1);
                 INSERT INTO mls_duty_ranks(group_id, task, subject, device_id, rank)
                   VALUES ('g1', 'remove_user', 'bob', 'alice-d1', 0);
                 INSERT INTO mls_alerts(device_id, group_id, hash, frame, at_ms) VALUES ('alice-d1', 'g1', 'h', '{}', 1);
                 INSERT INTO mls_commits(group_id, device_id, recovery, at_ms) VALUES ('g1', 'alice-d1', 0, 1);",
            )
            .unwrap();
        let header = |msg_id: String, from: &str| StoredHeader {
            msg_id,
            kind: "group".into(),
            from_user: from.into(),
            from_address: format!("{from}@local"),
            to_user: "alice".into(),
            to_address: "alice@local".into(),
            expires_ms: i64::MAX,
            env_state: "stored".into(),
            sender_view: "stored".into(),
            abort_reason: None,
        };
        // 그 그룹 앞 대기 봉투 둘(그룹 메시지·Handshake).
        for (n, col) in [(2, "gid"), (3, "handshake_group")] {
            db.store_envelope(&header(ulid(n), "bob"), "{}", &[], None, None)
                .unwrap();
            db.c()
                .execute(
                    &format!("UPDATE envelopes SET {col} = 'g1' WHERE msg_id = ?1"),
                    [ulid(n)],
                )
                .unwrap();
        }
        let count = |sql: &str| -> i64 { db.c().query_row(sql, [], |r| r.get(0)).unwrap() };

        // bob 이 나가도 alice 가 남아 그룹은 그대로.
        let (_, dropped) = db
            .group_app_op_now("g1", "leave", &header(ulid(4), "bob"), "{}", &[], 2)
            .unwrap()
            .unwrap();
        assert!(!dropped);
        assert_eq!(count("SELECT COUNT(*) FROM groups"), 1);

        // 마지막 alice — 본인 다른 기기가 그 leave 를 받는다.
        let keep = ulid(5);
        let (_, dropped) = db
            .group_app_op_now(
                "g1",
                "leave",
                &header(keep.clone(), "alice"),
                "{}",
                &["alice-d2".into()],
                3,
            )
            .unwrap()
            .unwrap();
        assert!(dropped);
        for t in [
            "groups",
            "group_members",
            "group_log",
            "mls_groups",
            "mls_leaves",
            "mls_pending",
            "mls_outcomes",
            "mls_duties",
            "mls_duty_ranks",
            "mls_duty_stuck",
            "mls_votes",
            "mls_rejoin",
            "mls_alerts",
            "mls_commits",
            "mls_gi_blobs",
        ] {
            assert_eq!(count(&format!("SELECT COUNT(*) FROM {t}")), 0, "{t}");
        }
        let left: Vec<String> = {
            let c = db.c();
            let mut st = c.prepare("SELECT msg_id FROM envelopes").unwrap();
            let rows = st.query_map([], |r| r.get(0)).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        assert_eq!(left, vec![keep], "그 leave 봉투만");
    }

    #[test]
    fn immediate_tx_waits_for_another_writer_instead_of_busy() {
        // #537: 읽은 뒤 쓰는 트랜잭션 사이에 다른 연결(bootstrap 등)이 커밋하면 deferred 는 기다리지 않고 BUSY(internal)였다.
        // immediate 는 시작 때 쓰기 잠금을 잡아, 다른 연결이 busy_timeout 으로 기다린다.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let open = || {
            let c = Connection::open(&path).unwrap();
            c.pragma_update(None, "journal_mode", "WAL").unwrap();
            c.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
            c
        };
        open()
            .execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (0);")
            .unwrap();
        let race = |imm: bool| -> rusqlite::Result<()> {
            let mut c1 = open();
            let tx = if imm {
                immediate(&mut c1)?
            } else {
                c1.transaction()?
            };
            let _: i64 = tx.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;
            let p = path.clone();
            let other = std::thread::spawn(move || {
                let c2 = Connection::open(p).unwrap();
                c2.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
                c2.execute("INSERT INTO t VALUES (2)", []).unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(200));
            let r = tx.execute("INSERT INTO t VALUES (1)", []).map(|_| ());
            let r = r.and_then(|()| tx.commit());
            other.join().unwrap();
            r
        };
        assert!(race(false).is_err(), "deferred 는 BUSY");
        race(true).unwrap();
    }

    /// 휴대폰 여러 계정: 옛 DB 의 `push_tokens UNIQUE(platform, token)` 은 열 때 풀리고 행·더한 열은 그대로.
    #[test]
    fn 옛_푸시_토큰_표의_유일_제약을_푼다() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        {
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE push_tokens (
                   device_id  TEXT PRIMARY KEY,
                   platform   TEXT NOT NULL,
                   token      TEXT NOT NULL,
                   env        TEXT NOT NULL,
                   app_id     TEXT NOT NULL,
                   salt       BLOB NOT NULL,
                   key        BLOB NOT NULL,
                   updated_ms INTEGER NOT NULL,
                   UNIQUE (platform, token)
                 );
                 ALTER TABLE push_tokens ADD COLUMN off TEXT;
                 INSERT INTO push_tokens VALUES ('d1', 'apns', 'tok', 'prod', 'app', x'00', x'01', 5, 'chat');",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let sql: String = db
            .c()
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'push_tokens'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!sql.contains("UNIQUE"), "{sql}");
        let off: String = db
            .c()
            .query_row(
                "SELECT off FROM push_tokens WHERE device_id = 'd1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(off, "chat");
        // 같은 토큰을 다른 기기가 쥘 수 있다.
        db.c()
            .execute(
                "INSERT INTO push_tokens(device_id, platform, token, env, app_id, salt, key, updated_ms)
                 VALUES ('d2', 'apns', 'tok', 'prod', 'app', x'00', x'01', 6)",
                [],
            )
            .unwrap();
        assert_eq!(db.push_token_devices("apns", "tok").unwrap(), 2);
        // 다시 열어도 그대로(한 번만 옮김).
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.push_token_devices("apns", "tok").unwrap(), 2);
        assert!(db.push_token_drop_if("d9", "tok").unwrap());
        assert_eq!(db.push_token_devices("apns", "tok").unwrap(), 0);
    }

    /// #896: 90일 넘게 안 붙은 기기 — 마지막 수단이 만료됐으면 '있음'으로 세지 않는다(보통 것과 같은 규칙). 세면 접속 때
    /// '마지막 수단 없음' low 가 안 가고, 보통 것만 올리는 순간 만료 행이 지워져 마지막 수단 없는 기기가 된다.
    #[test]
    fn 만료된_마지막_수단은_있음으로_세지_않는다() {
        let db = Db::memory().unwrap();
        let now_s = now_wall_ms() / 1000;
        let kp = |r: u8, not_after: i64| crate::mls::CheckedKeyPackage {
            kp_ref: vec![r],
            data: vec![r, r],
            not_after,
        };
        // 살아 있는 마지막 수단 — 있음.
        assert!(db
            .kp_publish("d1", &[], Some(&kp(1, now_s + 3600)), 100, false)
            .unwrap());
        assert_eq!(db.kp_state("d1").unwrap(), (0, true));
        // 만료된 마지막 수단만 남은 기기(90일 넘게 안 붙음) — 없음.
        assert!(db
            .kp_publish("d2", &[], Some(&kp(2, now_s - 60)), 100, false)
            .unwrap());
        assert_eq!(db.kp_state("d2").unwrap(), (0, false));
        // 판 16 아래 연결의 low 판정은 만료된 것도 '올린 적 있음'으로 본다(예전 그대로).
        assert!(db.kp_had_last("d2").unwrap() && !db.kp_had_last("d3").unwrap());
    }
}
