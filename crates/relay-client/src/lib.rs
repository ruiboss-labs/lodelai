//! lodelai-relay-client — 코어 ↔ 중계 서버 클라이언트 (U5, #57).
//!
//! 설계: protocol §3·§7, ADR 0006, #132(기기 공개키 배포). 경계(2026-10-23 합의):
//! - **lodelai-core 에 의존하지 않는다.** core(또는 앱)가 이 크레이트를 감싸 엔진의 `Relay` 를 구현한다.
//! - **나가는 쪽**: [`RelayClient::enqueue`] 가 [`Outgoing`] 을 받자마자 SQLite 영속 큐에 **동기로** 넣는다(실패는 `Err` 로 돌려준다).
//!   보낼 메시지는 넣는 순간 기기 키로 서명해 그 바이트를 그대로 재전송한다. 중복 제거 키:
//!   `Send`·`Rejected` = (종류, msg_id), `SenderStatus` = (종류, msg_id, state), `ChatRead`·`ChatAcknowledged` = msg_id 당 하나, `PresenceSet` = 마지막 값, `Publish`·`Unpublish` = slug 당 마지막 값.
//! - **들어오는 쪽**: `deliver` 를 재검증(서명·`device_id` 지문·`from` 주소 = 서명 기기의 사용자·`reply_to` 가 내가 보낸 것)한 뒤
//!   [`Inbound::Deliver`] 로 내준다. `delivered_ack` 는 core 가 저장한 뒤 [`AckHandle::ack`] 를 불러야 나간다(저장 전 ack = 크래시 때 유실).
//! - 기기 공개키는 `directory` 의 `devices` 로 받아 사용자별 TOFU 로 고정한다([`keys`]).
//! - 로컬 relay 자식 프로세스([`spawn`])와 기기 등록·기기 연결 코드([`register`])도 여기서 한다.

pub mod blobio;
pub mod conn;
pub mod files;
pub mod group_io;
pub mod groups;
pub mod keys;
pub mod mls;
pub mod mls_blob;
pub mod mls_conn;
pub mod mls_rules;
pub mod mls_store;
pub mod outbox;
pub mod register;
pub mod spawn;
pub mod tls;

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use lodelai_crypto::DeviceKeys;
use lodelai_effects::{Clock, Rng};
use lodelai_protocol::states::{AbortReason, SenderViewState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot, watch, Notify};

pub use outbox::{Peer, Store, Trust};

/// 조직 만들기 코드 거절 이유([`Error::SetupCodeRefused`], relay `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupCodeRefusal {
    /// `setup_code_other_email` — 다른 이메일로 가입할 때만 쓸 수 있는 코드.
    OtherEmail,
    /// `setup_code_expired` — 기한이 지난 코드.
    Expired,
}

/// 이 크레이트의 오류.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("메시지 형식: {0}")]
    Message(String),
    #[error("서명: {0}")]
    Crypto(#[from] lodelai_crypto::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("relay: {0}")]
    Relay(String),
    /// 서명된 `send` 프레임이 relay 프레임 상한(`WS_MAX_FRAME_BYTES`)을 넘는다(#315). 큐에 넣지 않았다 — 보내면 서버가
    /// 연결을 끊고 재접속 때 같은 바이트를 다시 보내 큐 맨 앞이 막힌다. 다시 시도해도 같으므로 호출자는 버린다.
    #[error("프레임 {bytes}바이트 > 상한 {max}")]
    FrameTooLarge { bytes: usize, max: usize },
    #[error("봉투: {0}")]
    Envelope(#[from] lodelai_crypto::EnvelopeError),
    /// MLS 저장(묶음 22 §8). 열쇠가 바뀜([`mls_store::MlsStoreError::KeyMismatch`] — Keychain 항목을 잃음)도 여기.
    #[error("MLS 저장: {0}")]
    MlsStore(#[from] mls_store::MlsStoreError),
    /// 기기 등록: 다른 기기로 이미 있는 사용자(아이디 충돌).
    #[error("이미 있는 사용자")]
    UserExists,
    /// hosted 가입: 이 기기가 그 서버에 다른 아이디로(또는 폐기된 채) 등록돼 있다 — 409 `device_taken`(#389).
    /// 가입 토큰은 쓰이지 않았다(다른 이메일로 다시 할 수 있다).
    #[error("이 기기는 그 서버에 다른 아이디로 등록돼 있다")]
    DeviceTaken,
    /// 기기 등록: 그 아이디의 기기가 relay 상한(기본 4대)에 닿았다 — 409 `too_many_devices`(묶음 16 §3a). 쓰지 않는 기기를
    /// 끊고 다시.
    #[error("기기 수 상한")]
    DeviceLimit,
    /// 그룹 보내기: 수신 기기(로컬 멤버 × 신뢰 기기)가 64 를 넘는다 — `too_many{devices}`(묶음 16 §3).
    #[error("그룹 수신 기기 {0}대 > 상한")]
    TooManyDevices(usize),
    /// 그룹 보내기: 빈 seq 를 다시 받지 못해 멤버 상태를 믿을 수 없다 — '그룹 정보를 다시 받아야 해요'(묶음 16 §3).
    #[error("그룹 상태를 다시 받아야 한다")]
    GroupStale,
    /// 그룹 보내기: 다음 멤버 변경이 확인 전 기기의 서명이라 적용을 멈춰 두었다 — 그 기기를 확인하면 풀린다(묶음 16 §3).
    #[error("확인 전 기기의 그룹 변경을 기다린다")]
    GroupWaitingTrust,
    /// 그룹 보내기: 모르는 그룹이거나 내가 지금 멤버가 아니다(묶음 16 §3).
    #[error("그룹 멤버가 아니다")]
    NotGroupMember,
    /// 그룹이 꺼져 있다(묶음 16 §3b — `GROUPS_ENABLED`·[`Config::groups`]). 그룹 주소·헤더 group·kind group 은 보내지 않는다.
    #[error("그룹 꺼짐")]
    GroupsOff,
    /// relay 에 닿지 않았거나 응답 없이 끊겼다(기기 폐기, #325). 폐기됐을 수도 있다 — 호출자는 사람에게 묻고 정한다.
    #[error("relay 에 닿지 않음")]
    Unreachable,
    /// [`RelayClient::trust_device`]: 모르는 기기(또는 그 사용자의 기기가 아님).
    #[error("모르는 기기")]
    UnknownDevice,
    /// hosted 가입: 코드가 틀렸거나 만료·폐기, 또는 가입 토큰이 없거나 만료·사용됨(#339).
    #[error("가입 코드·토큰이 맞지 않는다")]
    InvalidCode,
    /// [`RelayClient::revoke_other_device`]: 나중 기기가 먼저 기기를 등록 24시간 전에 지우려 했다(#339).
    #[error("아직 폐기할 수 없다(등록 24시간 전)")]
    TooEarly,
    /// 조직 관리자 동작을 relay 가 거절했다(관리자 아님·모르는 id·이름 규칙 밖·이름 겹침, #355).
    #[error("relay 가 거절")]
    Refused,
    /// 상한에 걸렸다 — 초대 발급 상한(#355) 또는 relay 의 IP 상한(429, #364). 잠시 뒤 다시.
    #[error("요청이 너무 잦음")]
    RateLimited,
    /// 팀 이름이 그 조직의 다른 팀과 겹친다(#355).
    #[error("같은 이름의 팀이 있다")]
    NameTaken,
    /// hosted 가입: 초대 토큰이 없거나 만료·사용됨·이메일 불일치(#355 — 사유를 가르지 않는다).
    #[error("초대 토큰이 맞지 않는다")]
    InvalidInvite,
    /// hosted 가입: 맞는 조직 만들기 코드인데 쓸 수 없다(relay 0.1.2 — 422 `{reason, email?, message}`). `email` 은 다른 이메일
    /// 전용일 때 relay 가 가린 꼴(`a***@d…`) 그대로 — 화면 문구에만 넣는다. 이유가 없거나 모르는 값이면 [`Error::InvalidInvite`].
    #[error("조직 만들기 코드를 쓸 수 없다({reason:?})")]
    SetupCodeRefused {
        reason: SetupCodeRefusal,
        email: Option<String>,
    },
    /// [`RelayClient::revoke_other_device`]: 이 기기 자신 — 로그아웃 경로로(#339).
    #[error("이 기기 자신")]
    ThisDevice,
    /// [`RelayClient::trust_device`]: 그 기기가 `pending` 이 아니다(지금 상태 동반).
    #[error("확인할 수 없는 상태: {0:?}")]
    NotPending(Trust),
    /// hosted 가입: 이 이메일은 이미 계정이 있다 — 조직을 만들거나 다른 초대로 들어갈 수 없고 그 계정에 기기 추가로만(묶음 18
    /// §1, 409 `account_exists`). 가입 토큰은 남아 있다.
    /// 그 계정(relay 409 본문 `account`) — 앱은 친 아이디가 아니라 이것으로 기기 추가 화면을 채운다.
    #[error("이미 계정이 있는 이메일")]
    AccountExists(register::ExistingAccount),
    /// hosted 가입: 코드 없는 조직 만들기 속도 상한(묶음 18 §3, 429 `org_rate_limited`). 잠시 뒤 다시.
    #[error("조직 만들기가 너무 잦음")]
    OrgRateLimited,
    /// hosted 가입: relay 가 지금 새 조직을 받지 않는다(묶음 18 §3, 403 `org_create_closed`) — 초대로는 들어올 수 있다.
    #[error("새 조직을 받지 않음")]
    OrgCreateClosed,
    /// 원격 relay 설정 코드 등록(#364): 코드가 틀렸거나 끝났거나 5번 틀려 폐기됐다(relay 가 가르지 않는다, 401).
    #[error("설정 코드가 맞지 않음")]
    InvalidSetupCode,
    /// 원격 relay 설정 코드 등록(#364): 아이디가 `lodelai-relay bootstrap --admin` 과 다르다(400). 묶음 5 에서 없어진다.
    #[error("설정 코드의 관리자 아이디와 다름")]
    HandleMismatch,
    /// [`RelayClient::device_register`]: 그 아이디를 다른 사람이 쓴다(`error{handle_taken}`).
    #[error("이미 쓰는 아이디")]
    HandleTaken,
    /// 가입 메일: 처리방침 동의 판이 없거나 relay 의 지금 판과 다르다(422, 묶음 5) — 판을 다시 받아 다시 묻는다.
    #[error("처리방침 동의가 필요하다")]
    PrivacyRequired,
    /// 가입 메일: 이메일 형식(400, 묶음 5).
    #[error("이메일 형식")]
    InvalidEmail,
    /// 가입 메일: 메일 서비스 실패(503, 묶음 5).
    #[error("메일을 보내지 못함")]
    EmailUnavailable,
    /// 관리자가 0명이 된다(`error{last_admin}`, 묶음 5) — 다른 관리자를 먼저 세운다.
    #[error("마지막 관리자")]
    LastAdmin,
    /// 확인 안 된(잎 자격 없는) 기기라 관리자 동작을 못 한다(`error{device_unconfirmed}`, #737) — 기존 기기에서 이 기기를
    /// 확인하면 된다.
    #[error("확인 안 된 기기")]
    DeviceUnconfirmed,
    /// 메일 확인 끊기(#577 §3) 요청을 relay 가 거절했다(`error{recover_refused, reason, until?}` — 연결은 그대로). `reason` 은
    /// relay 값 그대로(trusted·no_older·cooldown·exhausted·not_scheduled·not_target·ended), `until` 은 cooldown·exhausted 만.
    #[error("메일 확인 끊기 거절: {reason}")]
    RecoverRefused {
        reason: String,
        until: Option<String>,
    },
}

/// 메일 확인 끊기 요청(#577 §4, [`RelayClient::recover`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recover {
    /// 걸기(pending 인 이 기기가 먼저 등록된 내 기기 전부를).
    Start,
    /// 건 쪽 취소.
    Cancel,
    /// 대상 쪽 막기.
    Block,
}

/// 누가 이 기기를 끊었나(`error{device_revoked, by}`, 묶음 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovedBy {
    /// 본인 다른 기기(또는 모름 — 묶음 5 전 relay).
    Device,
    /// 조직 관리자(남 기기 끊기·내보내기).
    Admin,
    /// 내가(이 기기든 내 다른 기기든) 조직을 나갔다(`member.leave`).
    Left,
    /// 내 새 기기가 메일 확인으로 이 기기를 끊었다(#577 §4 — 걸기 `at` 실행). 앱은 자동으로 지우지 않는다(진짜 주인일 수 있음).
    Recovery,
    /// 조직 관리자가 기기 바꾸는 중인 내 옛 기기(이 기기)만 끊었다(#737 `member.revoke_device` — 내보내기 아님). Recovery 와
    /// 같이 다룬다(자동 지움 없음).
    AdminDevice,
}

pub type Result<T> = std::result::Result<T, Error>;

/// `session.publish.project`(묶음 23 §5): `id` = 22자 base64url, `name` = 구분 이름(`회사/api`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishProject {
    pub id: String,
    pub name: String,
}

/// core → 서버로 나가는 것(와이어로 가는 것만). core 의 트랜잭셔널 아웃박스에 JSON 으로 저장된다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outgoing {
    /// 서명 전 메시지(§3). `from.device_id` 는 이 크레이트가 자기 기기로 채우고 서명한다.
    Send {
        message: Value,
    },
    /// 첨부가 있는 메시지(묶음 15 §3, kind `chat`·`request`·`reply`). 파일마다 예약 → 암호화(새 FK·prefix) → PUT 을 마친 뒤
    /// 헤더 `blobs`·본문 `pt=json1`(`{text, files[]}`)로 봉투·서명·`send`. 실패는 [`Inbound::Nack`] — relay `quota` 면 `upload_quota`(F6), `storage_full` 이면 `upload_storage`(F7), 그 밖은 `upload_failed`(F8 등).
    /// 다시 보내기는 같은 값으로 다시 넣는다(새 예약·새 FK). `path` 는 올리는 동안 바뀌지 않아야 한다(바뀌면 실패).
    SendFiles {
        message: Value,
        attachments: Vec<OutFile>,
    },
    /// 그룹 멤버 변경(묶음 16 §3, kind `group`). 코어는 헤더(`to` = 그룹 주소·`group_op`·`subject?`·msg_id 등)와
    /// `body.text = {op, subject?, name?}`(name 은 create·rename)까지만 — `members`·`admins`·`base_seq` 와 수신 기기는 로컬 상태로
    /// 이 크레이트가 채운다. create 뒤 멤버마다 add 를 하나씩 넣는 것은 코어.
    GroupChange {
        message: Value,
    },
    /// 수신자가 발신자에게 알리는 상태(`status` 프레임).
    SenderStatus {
        msg_id: String,
        state: SenderViewState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abort_reason: Option<AbortReason>,
        /// `state == failed` 일 때의 코드(#134, `bad_signature`·`unknown_delivery`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fail_reason: Option<String>,
    },
    /// 받은 chat 을 사람이 읽었다(`status read`, #308). 받는 쪽만 보낸다 — relay 가 발신자에게 중계만 한다.
    ChatRead {
        msg_id: String,
    },
    /// 받은 chat 에 '확인함'(`status acknowledged`, 묶음 14 B3). 받는 쪽만, msg_id 당 한 번.
    ChatAcknowledged {
        msg_id: String,
    },
    /// 접속 표시를 같은 조직에 보일지(`presence.set`, 묶음 14 B1). 마지막 값만 나간다.
    PresenceSet {
        share: bool,
    },
    /// 거절 상태(`status rejected`). 거절 **메시지**(kind=rejected)는 core 가 만들어 `Send` 로 넘긴다.
    Rejected {
        msg_id: String,
    },
    Publish {
        slug: String,
        grade: String,
        liveness: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display: Option<String>,
        /// 세션 이름·폴더 이름(m1-spec §2) — 각각 normalize(폴더는 normalize_folder)를 통과한 값만. relay 가 같은 검사로
        /// 어긋나면 프레임 전체를 거부한다.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        folder: Option<String>,
        /// 턴 처리 중(A15, protocol `session.publish` `busy?`) — 참일 때만 싣고 쉼이면 뺀다.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        busy: bool,
        /// 공개 범위(묶음 20, PROTOCOL 6). `None` = 조직 전체(`audience` 를 싣지 않음 — relay 는 없음 = org), `Some` = 그
        /// 아이디들(1~256명, 같은 조직, 나 아님 — 어기면 relay 가 프레임 전체를 error{protocol}). publish 는 통째로 덮어쓰니
        /// 다시 보낼 때(재접속·liveness·busy) 늘 지금 범위를 싣는다.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<Vec<String>>,
        /// 그 세션의 프로젝트(묶음 23 §5, PROTOCOL 7) — 동료 쪽 묶음 키·구분 이름. 이름은 `normalize_project_name` 을 통과한
        /// 값만(어기면 relay 가 프레임 전체를 거부). 없으면 싣지 않는다.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<PublishProject>,
        /// 그 세션의 에이전트 종류(Codex C2, PROTOCOL 13, 꼴 `^[a-z][a-z0-9_]{0,23}$`) — 동료 쪽 이름 앞 마크. claude_code 는
        /// 싣지 않는다(없음 = claude_code, 그 세션의 프레임은 전과 같다).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        /// 주인 코어의 같은 이름 번호(관문 Y2, PROTOCOL 13, 1..=999) — 동료 쪽 이름 뒤 `#N`·list_sessions `no`. 표시용
        /// 주장일 뿐이다. 없으면 싣지 않는다(번호 없음·첫 질문 제목 세션).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        no: Option<u16>,
    },
    Unpublish {
        slug: String,
    },
    /// 내 표시 이름·팀 변경(`profile.update`, #326·#355). 없는 필드는 안 바꾼다. 큐 키는 필드마다(`profile.display`·
    /// `profile.teams`) — 한쪽이 다른 쪽의 마지막 값을 지우지 않게.
    ProfileUpdate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        teams: Option<Vec<String>>,
    },
}

/// 재검증 실패 사유. core 는 `failed(fail_reason)` 으로 기록하고 발신자에게 알린다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// 서명·지문·발신 주소 불일치, 또는 디렉터리를 새로 고쳐도 모르는 기기.
    BadSignature,
    /// `reply_to` 가 내가 보낸 메시지가 아니다.
    UnknownDelivery,
    /// 서명은 맞는데 봉투를 열 수 없다(형식 위반·인증 실패·모르는 `alg`·UTF-8 아님·kind 별 box/plain 위반, e2e-envelope §5).
    BadEnvelope,
    /// 그룹 글인데 보낸 사람(또는 나)이 로컬 멤버 상태의 지금 멤버가 아니다(묶음 16 §3 — 서버가 끼워 넣은 사람의 글은 버린다).
    NotGroupMember,
}

impl RejectReason {
    /// `FailReason` 코드(#134).
    pub fn code(self) -> &'static str {
        match self {
            Self::BadSignature => "bad_signature",
            Self::UnknownDelivery => "unknown_delivery",
            Self::BadEnvelope => "bad_envelope",
            Self::NotGroupMember => "not_group_member",
        }
    }
}

/// 보낼 첨부 하나(묶음 15). `name` 1~255 바이트, 평문 크기 ≤ `FILE_MAX_BYTES`, 메시지당 1~`FILES_PER_MESSAGE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutFile {
    pub path: std::path::PathBuf,
    pub name: String,
    /// 보낸 쪽 추정(참고만).
    pub mime: String,
    /// `full_text` = 긴 글 자동 파일(ADR 0009 §7a).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// 코어가 검사한 사본의 평문 SHA-256(소문자 hex). 있으면 암호화하며 다시 재서 다르면 그 보내기를 멈춘다(`upload_failed`)
    /// — 코어의 재해시와 여기서 다시 읽기 사이의 틈을 닫는다(묶음 15 QA 🟢).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// 그림의 보이는 방향 크기(#612) — 봉투 `files[].w·h` 로 싣는다(봉투 안 참고 칸, 판 안 올림). 그림이 아니면 없음.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_px: Option<(u32, u32)>,
}

/// 그룹 로컬 상태(묶음 16 §3) — core 표시용.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    pub name: String,
    /// 지금 멤버(사람 주소, 들어온 순).
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub seq: u64,
    pub stale: bool,
    /// 확인 대기 기기 서명으로 멈춘 변경의 서명자 주소(`GroupWaitingTrust`, 화면 '{이름}님의 새 기기를 확인해야 계속돼요').
    pub waiting_trust: Option<String>,
    /// held 기기 서명이라 건너뛴 변경 수(§3a ⑤, 화면 '확인 안 된 변경 n건').
    pub unconfirmed_changes: u32,
    /// 이 기기의 그룹 상태가 시작된 seq(만들기·나를 더한 add·snapshot) — 그 앞 대화는 없다('이전 대화는 보이지 않아요').
    pub joined_seq: u64,
}

/// 받은 첨부 하나의 결과(묶음 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentOutcome {
    /// 풀어서 `path`(relay-client 의 `blobs-in/`, 코어 `files/` 와 같은 볼륨)에 두었다. 코어가 옮긴다(rename) — relay-client 는
    /// 넘긴 뒤 이 파일을 지우지 않는다.
    Received { path: std::path::PathBuf, size: u64 },
    /// 받을 수 없다. 다시 시도하지 않는다.
    Failed(AttachmentFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentFailure {
    /// relay 에 없다(만료·거둠·인가 없음 — relay 가 가르지 않는다).
    Unavailable,
    /// 받은 바이트의 해시·AEAD 가 틀림(F9 — 발신자에게 알리지 않음).
    BadFile,
}

/// relay 가 판이 맞지 않아 hello 를 거절했다(`error{version_unsupported, min, max}`, 묶음 26 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionMismatch {
    /// 내 판 < min, 또는 min·max 가 없거나 숫자가 아님 — 이 앱을 업데이트해야 한다. 이 프로세스에서는 다시 붙지 않는다.
    AppOutdated,
    /// 내 판 > max — relay 가 옛 판이다. [`Config::version_retry`] 마다 한 번 다시 붙어 본다.
    ServerOutdated,
}

/// 서버 → core.
#[derive(Debug)]
pub enum Inbound {
    /// 판이 맞지 않아 relay 가 받지 않는다(묶음 26 §6). 다음 [`Inbound::Ready`] 까지 그 상태다.
    /// 둘째 값은 relay 가 받는 가장 높은 판(`error{version_unsupported}` 의 `max`, 판 범위 헤더 없는 relay 의 서명 실패면
    /// 7 — 29 §3 판 기록). 모르면 `None`.
    VersionUnsupported(VersionMismatch, Option<u32>),
    /// 인증 끝. `pending` 은 서버가 쌓아 둔 수(참고값). `admin` 은 원격 relay 에서 내가 조직 관리자인가(묶음 5 — 화면
    /// 가르기용, 권한은 relay 가 따로 본다). 로컬 relay 는 언제나 `false`(관리자는 relay 를 띄운 주인 앱).
    /// `groups` 는 이 relay 가 그룹을 쓰나(22 §12-30 `Lodelai-Features`) — 줄이 없으면 모름 `None`.
    Ready {
        server: String,
        pending: u64,
        admin: bool,
        groups: Option<bool>,
        /// 이 relay 가 받는 가장 높은 판(29 §3) — 101 의 판 범위 헤더, 없으면 healthz 의 것. 둘 다 없으면 `None`.
        protocol_max: Option<u32>,
    },
    /// 헤더로는 몰랐는데(`Ready.groups = None`) relay 가 그룹 시작을 `unroutable` 로 거절했다 — 이 relay 는 그룹을 쓰지 않는다
    /// (22 §12-30). 다음 [`Inbound::Ready`] 의 `groups` 가 다시 정한다.
    GroupsOff,
    /// 재검증을 통과하고 봉투를 연 메시지. `body` 는 `{enc: plain, text}` 로 바꿔 넘긴다(코어는 평문만 본다, e2e-envelope §5).
    /// 첨부가 있으면(묶음 15 `pt=json1`) `body.files = [{idx, blob_id, name, mime, size, role?}]` 를 더한다(키·해시는 relay-client
    /// 안에만). 파일은 뒤에서 받아 [`Inbound::Attachment`] 로 하나씩 온다(이 Deliver 뒤). core 가 저장한 뒤 `ack.ack()`.
    Deliver { message: Value, ack: AckHandle },
    /// 그룹 변경을 적용했다(묶음 16 §3) — 순서대로 하나씩. `state` 는 적용 뒤 상태.
    GroupUpdate {
        gid: String,
        seq: u64,
        op: String,
        actor: String,
        subject: Option<String>,
        state: GroupState,
    },
    /// 빈 seq 를 다시 받지 못했다 — 그 그룹 보내기를 막는다('그룹 정보를 다시 받아야 해요').
    GroupStale { gid: String },
    /// 내 프로필 사진 올리기를 relay 가 거절했다(묶음 15 B9 — [`RelayClient::set_avatar`]). `reason` 은 relay `error.code`
    /// (`rate_limited`·`storage_full`·`protocol` 등) 또는 PUT 상태(`put_400`). 그 행은 큐에서 뺐다. 성공은 directory.update 의
    /// 내 `people[].avatar` 로 안다.
    AvatarFailed {
        reason: String,
        /// 조직 사진(#554 — [`RelayClient::set_org_avatar`]). 관리자가 아니게 된 거절은 예약 `protocol`·PUT `put_403`.
        org: bool,
    },
    /// 받은 메시지의 첨부 하나(묶음 15). 같은 (msg_id, idx) 는 한 번만.
    Attachment {
        msg_id: String,
        idx: u32,
        blob_id: String,
        outcome: AttachmentOutcome,
    },
    /// 서명·봉투는 맞지만 확인하지 않은(`pending`·`revoked`) 기기에서 왔다(#313 결정 c). 본문은 평문으로 열어 넘기지만 core 는
    /// 보류(`held`)로 저장하고 세션에 넣지 않는다. 그 기기를 확인하면 평소 흐름으로.
    Held { message: Value, ack: AckHandle },
    /// 봉투에 이 기기 앞 항목이 없다. `body` 는 `{enc: plain, text: ""}`, 헤더는 그대로. core 는 `unreadable` 로 저장하고 ack 한다.
    Unreadable { message: Value, ack: AckHandle },
    /// 재검증 실패. UI 에 올리지 않는다. core 가 기록한 뒤 `ack.ack()`(안 하면 서버가 다시 보낸다).
    Rejected {
        msg_id: String,
        reason: RejectReason,
        message: Value,
        ack: AckHandle,
    },
    /// 상대 당사자의 상태 보고.
    Status {
        msg_id: String,
        state: String,
        abort_reason: Option<String>,
        fail_reason: Option<String>,
        at: String,
        /// 그룹 글에서 보낸 멤버 주소(묶음 16 §4, relay 가 채움 — 코어가 멤버 대조). 1:1 이면 없음.
        by: Option<String>,
    },
    /// 내 `send` 가 서버에 저장됐다(`server_ack`).
    Ack { msg_id: String },
    /// 서버가 거부했다(`server_nack`). 다시 보내지 않는다.
    Nack { msg_id: String, reason: String },
    /// 디렉터리 전체(캐시도 갱신됨).
    Directory(Value),
    /// 이미 아는 사람에게 새 기기가 나타났다 — `pending`(사람 확인 전, 감싸지 않음). 같은 변화가 [`Inbound::DeviceTrust`] 로도 온다.
    NewDevice { user: String, device_id: String },
    /// 상대 기기의 신뢰 상태가 생기거나 바뀌었다(첫 대화 trusted·새 기기 pending·사라짐 revoked). 사람 확인은
    /// [`RelayClient::trust_device`] 가 돌려준다(이 이벤트로 오지 않는다).
    DeviceTrust(Peer),
    /// 디렉터리 항목의 공개키가 `device_id` 지문과 맞지 않아 버렸다(반신뢰 서버의 키 끼워 넣기).
    KeyMismatch { user: String, device_id: String },
    /// 그 사람의 뿌리 기기가 바뀌었다(묶음 22 §2c — 사슬이 끊김). 멈추지 않고, 그 사람 대화마다 조용한 기록 줄 하나.
    /// `root` = 새 뿌리 device_id(지문은 [`register::fingerprint_of`]).
    RootChanged { user: String, root: String },
    /// MLS 대화가 막혔거나(`Some`) 풀렸다(`None`)(묶음 22 §9 — 코어가 `EvConversationSync` 로). `conversation` = 상대 사람 주소
    /// (pair) 또는 내 주소(self). 접속 때 막힌 대화는 다시 온다.
    ConversationSync {
        conversation: String,
        state: Option<mls_store::GroupState>,
        /// 막힌 동안 열지 못하고 버린 응용 메시지가 처음 온 때(ms, §12-23 ③). 풀림(`None`)에도 실린다 — 화면 '이때부터 받지 못한
        /// 글' 줄.
        lost_since: Option<i64>,
    },
    /// relay 가 알린 그룹 관리자 줄(§12-20 `group_alert` — 서명 없는 서버 주장). 상태를 바꾸지 않고 코어가 기록 줄로 남긴다.
    GroupAlert(lodelai_protocol::generated::ws::GroupAlert),
    /// 내가 보낸 사람 op 그룹 변경의 확정 기다림(§12-27 ⓒ). `change_id` = 그 변경을 처음 보낸 group 메시지의 msg_id(다시
    /// 봉인해도 그대로). 봉인할 때 `Waiting`, 무효면 `Retry`, 확정이면 `Final`(seq 있음 — 같은 확정의 `GroupUpdate` 보다 먼저).
    GroupChangePending {
        change_id: String,
        pending: ChangePending,
        seq: Option<u64>,
    },
    /// 연결이 끊겼다. 클라이언트가 다시 붙는다.
    Disconnected,
    /// 동료가 그 대화 입력칸에 쓰는 중·멈춤(S→C `typing`, 묶음 36 #613). `from` 은 relay 가 채운 사람 주소, `group` 이 있으면
    /// 그 그룹 대화(없으면 `from` 과의 1:1). 저장하지 않는다 — 6초 만료는 코어가 쥔다.
    Typing {
        from: String,
        group: Option<String>,
        on: bool,
    },
    /// 다른 내 기기가 이 기기를 계정에서 끊었다(`error{device_revoked}`, #339). 연결 루프는 끝났고 다시 접속하지 않는다.
    /// 앱은 #325 로그아웃의 로컬 지움을 그대로 한다.
    /// `at` = relay 가 끊은 시각(RFC 3339, 실렸을 때만 — 관문 🟡-10).
    RemovedFromAccount { by: RemovedBy, at: Option<String> },
    /// 이 기기를 끊으려는 메일 확인 끊기가 걸려 있다(#577 §4 `device.recover_against` — 걸린 동안 인증 직후마다 다시 온다).
    /// `requester` = 건 새 기기의 device_id, `at` = 이 기기가 끊길 시각.
    RecoverAgainst { at: String, requester: String },
    /// 그 걸기가 끝났다(`device.recover_against_ended{reason}` — blocked·canceled·certified).
    RecoverAgainstEnded { reason: String },
}

/// [`Inbound::GroupChangePending`] 의 단계(§12-27 ⓒ — 화면 `EvGroupChange.pending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePending {
    /// 다른 동료가 받기를 기다림.
    Waiting,
    /// 무효 — 기기가 다시 보낸다.
    Retry,
    /// 확정.
    Final,
}

/// `delivered_ack` 를 보낼 권리. core 가 메시지를 저장한 **뒤** 부른다. 부르지 않고 버리면 서버가 다음 접속 때 다시 보낸다.
#[derive(Debug)]
pub struct AckHandle {
    msg_id: String,
    tx: mpsc::UnboundedSender<String>,
}

impl AckHandle {
    pub fn msg_id(&self) -> &str {
        &self.msg_id
    }

    pub fn ack(self) {
        let _ = self.tx.send(self.msg_id);
    }
}

/// [`RelayClient::device_register`] 의 결과(`device.registered`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRegistered {
    pub user: String,
    pub device_id: String,
}

/// 기기 등록 요청 하나: 연결 코드와 응답 자리.
pub(crate) type RegisterRequest = (String, oneshot::Sender<Result<DeviceRegistered>>);

/// 연결 설정.
#[derive(Clone)]
pub struct Config {
    /// `ws://127.0.0.1:<port>/v1/ws`(같은 맥 로컬 relay) 또는 `wss://<도메인>/v1/ws`(원격 relay, #364). `ws://` 는 로컬만
    /// 받는다([`tls::target`]).
    pub ws_url: String,
    /// challenge 서명에 들어가는 서버 이름(주소의 `@<server>`).
    pub server_name: String,
    pub user: String,
    pub keys: DeviceKeys,
    /// 30초(`WS_PING_INTERVAL_S`).
    pub ping_interval: Duration,
    /// 이만큼 서버에서 아무 프레임도 안 오면 끊고 다시 접속한다(서버도 30초마다 `ping`).
    pub idle_timeout: Duration,
    /// 내 `ping` 뒤 이만큼 아무 프레임도 안 오면 끊고 다시 접속한다(서버는 `ping` 에 곧바로 `pong`). 멈춘 relay 를
    /// `idle_timeout`(60~120초)보다 빨리 — 최악 `ping_interval` + 이것(40초) — 알아챈다.
    pub pong_timeout: Duration,
    /// 큐에서 꺼내 보내는 최소 간격. relay rate limit(20/s, 넘으면 연결을 끊음)보다 충분히 느리게.
    pub send_interval: Duration,
    /// 재접속 백오프 상한.
    pub backoff_max: Duration,
    /// relay 가 옛 판이라 hello 를 거절했을 때(`version_unsupported`, 내 판 > max) 다시 붙어 보는 간격(묶음 26 §6 — 15분).
    pub version_retry: Duration,
    /// 모르는 기기에서 온 `deliver` 를 디렉터리 새로고침까지 기다리는 시간.
    pub unknown_device_wait: Duration,
    /// 첨부 임시 폴더(묶음 15): `out/`(올릴 암호문)·`in/`(받아 푼 파일 — [`AttachmentOutcome::Received`] 의 경로, 코어가 옮긴다).
    /// 코어 `files/` 와 같은 볼륨이어야 옮기기가 rename 이 된다. 제품은 앱 데이터 폴더 아래를 넘긴다 — 없으면
    /// [`RelayClient::start`] 가 큐 DB 옆 `blobs/`(앱 데이터 폴더), `start_with_store`(시험)만 임시 폴더. 폴더 0700·파일 0600.
    pub files_dir: Option<std::path::PathBuf>,
    /// 그룹 변경 빈 칸을 이만큼 기다리면 `groups.replay`, 또 이만큼이면 stale(묶음 16 §3 — 30초).
    pub group_gap_wait: Duration,
    /// 보낸 `send` 에 ack·nack·ref 있는 error 가 이만큼 안 오면 끊고 다시 접속해 같은 msg_id 를 다시 보낸다(#537 — 30초,
    /// relay 는 같은 발신자의 같은 msg_id 를 멱등 ack). 연달아면 재접속 백오프를 탄다.
    pub send_ack_wait: Duration,
    /// 그룹(묶음 16 §3b — 기본 `GROUPS_ENABLED`, 시험만 켬). 꺼지면 그룹으로 보내기 전에 막고([`Error::GroupsOff`]), 받은
    /// kind group·그룹 맥락 메시지는 저장하지 않고 버린다(감사 한 줄 — 꺼진 relay 는 보내지 않지만 반신뢰).
    pub groups: bool,
    /// MLS 저장(`mls_*`) 값 열쇠 32 B(묶음 22 §8 — Keychain 의 그 프로필 슬롯). [`RelayClient::start`] 가 큐 DB 와 같은 파일에
    /// [`mls_store::MlsStore`] 를 연다.
    pub mls_store_key: zeroize::Zeroizing<[u8; 32]>,
    /// 보통 KeyPackage 를 이만큼까지 둔다(§3 — 기본 [`mls_conn::KP_TARGET`] 100). 시험은 작게.
    pub key_package_target: usize,
    /// 주기 Update(§7): 내 응용 메시지 이만큼마다(기본 100). 시험은 작게.
    pub update_every_msgs: u64,
    /// 주기 Update 때를 보는 간격(기본 10분). 시험은 짧게.
    pub update_check: Duration,
    /// 새 기기(§7): 잎 자격을 얻은 뒤 이만큼(기본 30분 — duty 최악 지연) 지나도 들지 못한 그룹이 있으면 스스로 external commit
    /// 으로 들어간다(내 다른 기기가 모두 꺼졌거나 없을 때). 시계는 `clock`.
    pub orphan_wait: Duration,
    /// 이 크기(메시지 JSON 바이트)를 넘는 group Handshake 는 큰 칸부터 blob 으로(§5c — 기본 `MLS_INLINE_MAX_BYTES`). 시험은 작게.
    pub mls_inline_max: usize,
    /// 프로필 사진 PUT 이 일시 실패했을 때 첫 재시도까지(#530 — 5초). 실패가 이어지면 두 배씩 [`Self::avatar_retry_max`]
    /// 까지 늘린다. 그동안 큐는 멈춘다(뒤의 지우기가 PUT 보다 먼저 가지 않게).
    pub avatar_retry_first: Duration,
    /// 그 물러서기의 상한(30초).
    pub avatar_retry_max: Duration,
    /// 프로필 사진 올리기가 이만큼(기본 10초) 답이 없으면 화면에 '네트워크 기다림'을 한 번 — relay 가 멈춰 연결은 열린 채
    /// 답이 없을 때 끊김으로 알기까지 2분 동안 줄 없이 머리글자만 보였다(관문 acct ⑤). 올리기는 그대로 기다린다.
    pub avatar_slow_notice: Duration,
    /// 이 기기의 이름(맥 컴퓨터 이름)을 얻는 함수(#490 28 §4). 연결의 첫 디렉터리에서 부르고, 다듬은 값이 내
    /// `DirectoryDevice.name` 과 다를 때만 `device.name` 으로 보낸다. `None` 이면 보내지 않는다.
    pub device_name: Option<DeviceNameFn>,
    /// 이 기기가 붙는 판(`hello.v`)이자 받아 여는 메시지 `v` 의 상한. 제품은 늘 `PROTOCOL_VERSION` — 시험만 낮춰 옛 판
    /// 기기를 흉내 낸다(#598 ② 판이 섞여 돎).
    pub protocol: u32,
}

/// [`Config::device_name`] — 부를 때마다 지금 이름을 돌려준다(못 얻으면 `None`).
pub type DeviceNameFn = std::sync::Arc<dyn Fn() -> Option<String> + Send + Sync>;

impl Config {
    pub fn new(
        ws_url: impl Into<String>,
        server_name: impl Into<String>,
        user: impl Into<String>,
        keys: DeviceKeys,
        mls_store_key: zeroize::Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            ws_url: ws_url.into(),
            server_name: server_name.into(),
            user: user.into(),
            keys,
            ping_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(90),
            pong_timeout: Duration::from_secs(10),
            send_interval: Duration::from_millis(100),
            backoff_max: Duration::from_secs(30),
            version_retry: Duration::from_secs(15 * 60),
            unknown_device_wait: Duration::from_secs(5),
            files_dir: None,
            group_gap_wait: Duration::from_secs(30),
            send_ack_wait: Duration::from_secs(30),
            groups: lodelai_protocol::constants::GROUPS_ENABLED,
            mls_store_key,
            key_package_target: mls_conn::KP_TARGET,
            update_every_msgs: 100,
            update_check: Duration::from_secs(600),
            orphan_wait: Duration::from_secs(1800),
            mls_inline_max: usize::try_from(lodelai_protocol::constants::MLS_INLINE_MAX_BYTES)
                .unwrap_or(49_152),
            avatar_retry_first: Duration::from_secs(5),
            avatar_retry_max: Duration::from_secs(30),
            avatar_slow_notice: Duration::from_secs(10),
            device_name: None,
            protocol: lodelai_protocol::PROTOCOL_VERSION,
        }
    }
}

/// 그룹 메시지인가(묶음 16 — kind group, 그룹 주소, 헤더 group).
#[must_use]
pub fn is_group_message(message: &Value) -> bool {
    message.get("kind").and_then(Value::as_str) == Some("group")
        || group_io::group_context(message).is_some()
}

/// 수신 채널 용량. core 가 느리면 WS 읽기가 멈춘다(메모리가 커지지 않게).
pub const INBOUND_CAPACITY: usize = 256;

/// 조직 관리자 동작(#355, [`RelayClient::org_admin`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgAdmin {
    RenameOrg(String),
    CreateTeam(String),
    RenameTeam { id: String, name: String },
    DeleteTeam(String),
}

/// 이 기기의 신원: 사람 주소(`user@server`)와 기기 지문. core 가 보낼 메시지의 `from` 을 찍을 때 쓴다(protocol §1 ④).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Me {
    /// `user@server` — 사람 주소.
    pub address: String,
    pub device_id: String,
}

/// 클라이언트 핸들. 연결 루프는 tokio 태스크로 돈다.
pub struct RelayClient {
    store: Arc<Store>,
    /// MLS 상태(묶음 22) — 그룹 화면 상태를 여기서. 메모리 큐 시험만 없음.
    mls_state: Option<Arc<conn::Mls>>,
    keys: DeviceKeys,
    me: Me,
    clock: Arc<dyn Clock>,
    wake: Arc<Notify>,
    directory: Arc<RwLock<Value>>,
    /// '다시 받기'(묶음 22 §9 `CmdConversationRejoin`) 로 다시 들어갈 그룹(헤더 값) — 연결 루프가 꺼내 간다.
    rejoin_asks: Arc<std::sync::Mutex<Vec<String>>>,
    /// [`Self::hold_group_deliveries`].
    holding: Arc<std::sync::atomic::AtomicBool>,
    unheld: Arc<std::sync::atomic::AtomicBool>,
    shutdown: watch::Sender<bool>,
    revoke: mpsc::UnboundedSender<(bool, oneshot::Sender<Result<()>>)>,
    control: mpsc::UnboundedSender<(conn::Control, oneshot::Sender<conn::ControlAnswer>)>,
    typing: mpsc::UnboundedSender<Value>,
    register: mpsc::UnboundedSender<RegisterRequest>,
    avatar_get: mpsc::UnboundedSender<files::AvatarFetch>,
    /// [`Config::groups`].
    groups: bool,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RelayClient {
    /// 큐(SQLite)를 열고 연결 루프를 띄운다. 큐에 남아 있던 것은 접속 뒤 이어서 보낸다. `rng` 는 봉투 난수(제품 = OS 난수,
    /// 시험 = 시드 난수, #313 결정 a).
    ///
    /// # Errors
    /// 큐를 못 열면.
    pub fn start(
        mut config: Config,
        db_path: &Path,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<(Self, mpsc::Receiver<Inbound>)> {
        let store = Arc::new(Store::open(db_path)?);
        if config.files_dir.is_none() {
            config.files_dir = db_path.parent().map(|p| p.join("blobs"));
        }
        // MLS 저장은 같은 DB 파일에 자기 연결(outbox 쓰기와 트랜잭션이 섞이지 않게 — mls_store).
        let mls = Some(Arc::new(conn::Mls {
            provider: mls::Provider::new(mls_store::MlsStore::open(
                db_path,
                &config.mls_store_key,
                rng.clone(),
            )?),
            signer: mls::DeviceSigner::new(config.keys.signing.clone()),
        }));
        Ok(Self::start_with(config, store, mls, clock, rng))
    }

    pub fn start_with_store(
        config: Config,
        store: Arc<Store>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> (Self, mpsc::Receiver<Inbound>) {
        Self::start_with(config, store, None, clock, rng)
    }

    fn start_with(
        config: Config,
        store: Arc<Store>,
        mls: Option<Arc<conn::Mls>>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> (Self, mpsc::Receiver<Inbound>) {
        let (tx, rx) = mpsc::channel(INBOUND_CAPACITY);
        let wake = Arc::new(Notify::new());
        let directory = Arc::new(RwLock::new(Value::Null));
        let rejoin_asks: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let holding: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let unheld: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (revoke, revoke_rx) = mpsc::unbounded_channel();
        let (control, control_rx) = mpsc::unbounded_channel();
        let (register, register_rx) = mpsc::unbounded_channel();
        let (avatar_get, avatar_get_rx) = mpsc::unbounded_channel();
        let (typing, typing_rx) = mpsc::unbounded_channel();
        let keys = config.keys.clone();
        let groups = config.groups;
        let me = Me {
            address: format!("{}@{}", config.user, config.server_name),
            device_id: keys.device_id().as_str().to_owned(),
        };
        let mls_state = mls.clone();
        let task = tokio::spawn(conn::run(conn::Shared {
            config,
            clock: clock.clone(),
            store: store.clone(),
            mls,
            me_address: me.address.clone(),
            out_frames: std::sync::Mutex::default(),
            create_retried: std::sync::Mutex::default(),
            commit_tries: std::sync::Mutex::default(),
            latest_change: std::sync::Mutex::default(),
            row_wait: std::sync::Mutex::default(),
            duty_wait: std::sync::Mutex::default(),
            row_kps: std::sync::Mutex::default(),
            update_checked: std::sync::Mutex::default(),
            rejoining: std::sync::Mutex::default(),
            groups: std::sync::Mutex::default(),
            failed_commits: std::sync::Mutex::default(),
            rejoin_now: std::sync::Mutex::default(),
            external_joiners: std::sync::Mutex::default(),
            self_updates: std::sync::Mutex::default(),
            dir_pulls: std::sync::Mutex::default(),
            known_groups: std::sync::Mutex::default(),
            rejoined: std::sync::Mutex::default(),
            orphan_tried: std::sync::Mutex::default(),
            rejoin_fails: std::sync::Mutex::default(),
            blob_jobs: std::sync::Mutex::default(),
            rejoin_asks: rejoin_asks.clone(),
            holding: holding.clone(),
            unheld: unheld.clone(),
            wake: wake.clone(),
            directory: directory.clone(),
            inbound: tx,
            shutdown: shutdown_rx,
            revoke: revoke_rx,
            control: control_rx,
            register: register_rx,
            avatar_get: avatar_get_rx,
            typing: typing_rx,
            rng: rng.clone(),
        }));
        (
            Self {
                store,
                mls_state,
                keys,
                me,
                clock,
                wake,
                directory,
                rejoin_asks,
                holding,
                unheld,
                shutdown,
                revoke,
                control,
                typing,
                register,
                avatar_get,
                groups,
                task: Some(task),
            },
            rx,
        )
    }

    /// 영속 큐에 넣는다(동기). 성공하면 연결 루프가 접속 중일 때 보낸다.
    ///
    /// # Errors
    /// 메시지 형식이 틀렸거나 서명·저장에 실패하면.
    pub fn enqueue(&self, out: &Outgoing) -> Result<()> {
        if !self.groups {
            let grouped = match out {
                Outgoing::Send { message } | Outgoing::SendFiles { message, .. } => {
                    is_group_message(message)
                }
                Outgoing::GroupChange { .. } => true,
                _ => false,
            };
            if grouped {
                return Err(Error::GroupsOff);
            }
        }
        outbox::enqueue(&self.store, &self.keys, self.clock.as_ref(), out)?;
        self.wake.notify_one();
        Ok(())
    }

    /// 마지막으로 받은 디렉터리(동기). 아직 없으면 `Null`.
    pub fn directory(&self) -> Value {
        self.directory
            .read()
            .map(|d| d.clone())
            .unwrap_or(Value::Null)
    }

    /// 큐에 남아 아직 relay 에 나가지 못한 보낸 메시지 수(로그아웃 미리보기, #325).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unsent_count(&self) -> Result<u64> {
        Ok(u64::try_from(self.store.unsent_sends()?).unwrap_or(u64::MAX))
    }

    /// 확인 안 한 기기에서 온(held) 메시지의 첨부 받기를 시작한다 — 코어가 그 기기를 믿었을 때(`release_held`, 묶음 15 §4a).
    /// 그 메시지의 '믿음 기다림' 첨부 수를 돌려준다. relay 보관 7일이 지났으면 받기는 `Failed(Unavailable)` 로 끝난다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn release_downloads(&self, msg_id: &str) -> Result<usize> {
        let n = self.store.release_downloads(msg_id)?;
        if n > 0 {
            self.wake.notify_one();
        }
        Ok(n)
    }

    /// 그 메시지의 받을 첨부를 대기열에서 지운다(기기 거부·폐기, 메시지 만료·거두기 — 코어가 행을 `failed` 로 둔다). 이미
    /// 받는 중인 것은 이번 연결이 끝날 때까지 이어질 수 있다. 지운 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_downloads(&self, msg_id: &str) -> Result<usize> {
        self.store.drop_downloads(msg_id)
    }

    /// 아직 relay 에 나가지 못한 보낸 메시지를 큐에서 버리고 그 msg_id 를 돌려준다(로그아웃, #325). 코어가 [`Self::revoke_device`]
    /// 전에 불러 그 메시지들을 `failed` 로 기록한다 — 사람에게 "버린다"고 확인받은 것이 폐기 전에 나가지 않게.
    /// 응답을 기다리는 중이던 `send` 하나는 이미 나갔을 수 있다(그 `ack` 는 큐에 행이 없어도 `Inbound::Ack` 로 온다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn discard_unsent(&self) -> Result<Vec<String>> {
        self.store.discard_sends()
    }

    /// 이 기기를 relay 에서 폐기한다(`device.revoke`, #325). 큐에 이미 들어 있는 것(중단 status·공개 내림 등)이 **다 나간 뒤**
    /// 보낸다. `device.revoked` 를 받으면 `Ok` 이고, 연결 루프는 그 뒤 다시 접속하지 않는다.
    ///
    /// # Errors
    /// 조직의 유일한 관리자의 마지막 기기 [`Error::LastAdmin`](묶음 5 — 다른 관리자를 먼저 세운다, 연결은 그대로),
    /// `timeout` 안에 응답이 없거나(오프라인·큐가 안 비움) 응답 전에 연결이 끊기면 [`Error::Unreachable`] — 폐기됐을 수도 있다.
    pub async fn revoke_device(&self, timeout: Duration) -> Result<()> {
        self.revoke_self(false, timeout).await
    }

    /// 조직을 나간다(`member.leave`, 묶음 5 — 서버 relay 만): 내 기기 전부가 폐기되고 내 다른 기기도
    /// [`Inbound::RemovedFromAccount`]`{by: Left}` 를 받는다. [`Self::revoke_device`] 처럼 큐가 다 나간 뒤 보낸다.
    ///
    /// # Errors
    /// 유일한 관리자(조직에 나 말고 사람이 있을 때) [`Error::LastAdmin`], 로컬 relay [`Error::Unreachable`](relay 가 거절하고
    /// 응답이 없다 — 화면이 서버 relay 에서만 부른다), 시간 초과·끊김 [`Error::Unreachable`].
    pub async fn leave_org(&self, timeout: Duration) -> Result<()> {
        self.revoke_self(true, timeout).await
    }

    async fn revoke_self(&self, leave: bool, timeout: Duration) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.revoke
            .send((leave, tx))
            .map_err(|_| Error::Unreachable)?;
        self.wake.notify_one();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(Error::Unreachable),
        }
    }

    /// 내 다른 기기(#339), 또는 조직 관리자면 같은 조직 사람의 기기(#355)를 relay 에서 끊는다(`device.revoke {device_id}`).
    /// 신뢰 상태와 무관하게 아는 기기면 보내고, 받을지는 relay 가 정한다.
    /// 큐를 기다리지 않고 접속 중이면 바로 보낸다. 한 번에 하나만 나간다(응답에 상관 필드가 없다). 결과의 `revoked` 표시는
    /// 뒤따르는 `directory.update` 로 온다.
    ///
    /// # Errors
    /// 이 기기 자신 [`Error::ThisDevice`], 모르는 기기·끊을 수 없는 기기(남의 기기인데 관리자 아님 — relay 도 같은 답) [`Error::UnknownDevice`],
    /// 등록 24시간 전의 나중 기기 [`Error::TooEarly`], 응답 전 끊김·시간 초과 [`Error::Unreachable`](결과를 모른다 — 다음
    /// 디렉터리로 판단).
    pub async fn revoke_other_device(&self, device_id: &str, timeout: Duration) -> Result<()> {
        if device_id == self.me.device_id {
            return Err(Error::ThisDevice);
        }
        // 아는 기기만 보낸다. 내 기기가 아니면 조직 관리자일 때만 relay 가 받는다(#355) — 판정은 relay 몫.
        let peer = self.store.peer(device_id)?.ok_or(Error::UnknownDevice)?;
        // 내 기기면 폐기 증명을 싣는다(묶음 22 §12-11 ⓐ) — 남의 기기(관리자)는 증명 없음.
        let proof = self
            .me
            .address
            .split_once('@')
            .filter(|(me, _)| *me == peer.user)
            .map(|(_, server)| keys::revoke_proof(&self.keys, server, device_id, self.clock.now()));
        match self
            .control(
                conn::Control::RevokeDevice {
                    device_id: device_id.to_owned(),
                    proof,
                },
                timeout,
            )
            .await?
        {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::TooEarly => Err(Error::TooEarly),
            conn::ControlAnswer::LastAdmin => Err(Error::LastAdmin),
            _ => Err(Error::UnknownDevice),
        }
    }

    /// 메일 확인 끊기(#577 §4): 걸기(`device.recover` → `device.recover_scheduled`), 건 쪽 취소(`device.recover_cancel` →
    /// `device.recover_canceled`), 대상 쪽 막기(`device.recover_block` → 이 기기에 `device.recover_against_ended`). 상태는 뒤따르는
    /// 디렉터리의 내 항목 `recovery` 로 온다. 이미 걸려 있으면 다시 걸기는 relay 가 멱등으로 답한다.
    ///
    /// # Errors
    /// relay 거절 [`Error::RecoverRefused`](이유 그대로), 형식 밖 [`Error::Refused`], 응답 전 끊김·시간 초과 [`Error::Unreachable`].
    pub async fn recover(&self, act: Recover, timeout: Duration) -> Result<()> {
        let c = match act {
            Recover::Start => conn::Control::Recover,
            Recover::Cancel => conn::Control::RecoverCancel,
            Recover::Block => conn::Control::RecoverBlock,
        };
        match self.control(c, timeout).await? {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::RecoverRefused { reason, until } => {
                Err(Error::RecoverRefused { reason, until })
            }
            _ => Err(Error::Refused),
        }
    }

    /// 조직 관리자 동작(#355): 조직 이름·팀 만들기·이름 바꾸기·빼기. 결과는 뒤따르는 디렉터리.
    ///
    /// # Errors
    /// 관리자 아님·모르는 id·이름 규칙 밖 [`Error::Refused`], 팀 이름 겹침 [`Error::NameTaken`], 응답 전 끊김·시간 초과
    /// [`Error::Unreachable`].
    pub async fn org_admin(&self, act: OrgAdmin, timeout: Duration) -> Result<()> {
        let c = match act {
            OrgAdmin::RenameOrg(n) => conn::Control::OrgRename(n),
            OrgAdmin::CreateTeam(n) => conn::Control::TeamCreate(n),
            OrgAdmin::RenameTeam { id, name } => conn::Control::TeamRename { id, name },
            OrgAdmin::DeleteTeam(id) => conn::Control::TeamDelete(id),
        };
        match self.control(c, timeout).await? {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::NameTaken => Err(Error::NameTaken),
            conn::ControlAnswer::DeviceUnconfirmed => Err(Error::DeviceUnconfirmed),
            _ => Err(Error::Refused),
        }
    }

    /// 초대 코드 발급(#355, 조직 관리자만 — 묶음 5 는 이메일에 묶지 않는다). `(token, expires_at)`.
    ///
    /// # Errors
    /// 관리자 아님 [`Error::Refused`], 발급 상한 [`Error::RateLimited`], 끊김·시간 초과 [`Error::Unreachable`].
    pub async fn create_invite(&self, timeout: Duration) -> Result<(String, String)> {
        match self
            .control(conn::Control::InviteCreate(None), timeout)
            .await?
        {
            conn::ControlAnswer::Invite { token, expires_at } => Ok((token, expires_at)),
            conn::ControlAnswer::RateLimited => Err(Error::RateLimited),
            // 확인 전 관리자 기기(#737)는 relay 가 막는다 — 엉뚱한 '이미 처리됨' 대신 맞는 문구로(#748).
            conn::ControlAnswer::DeviceUnconfirmed => Err(Error::DeviceUnconfirmed),
            _ => Err(Error::Refused),
        }
    }

    /// 같은 조직 사람을 내보낸다(`member.remove`, 묶음 5, 관리자만). 결과는 뒤따르는 디렉터리(그 사람이 빠진다).
    ///
    /// # Errors
    /// 관리자 아님·자기 자신·조직 밖·대상이 관리자(먼저 [`Self::set_admin`] 으로 뺀다)·이미 내보낸 사람 [`Error::Refused`],
    /// 끊김·시간 초과 [`Error::Unreachable`].
    pub async fn member_remove(&self, user: &str, timeout: Duration) -> Result<()> {
        match self
            .control(conn::Control::MemberRemove(user.to_owned()), timeout)
            .await?
        {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::DeviceUnconfirmed => Err(Error::DeviceUnconfirmed),
            _ => Err(Error::Refused),
        }
    }

    /// 관리자 폐기(`member.revoke_device`, #737): 같은 조직 다른 사람이 건 메일 확인 끊기의 대상(옛) 기기를 지금 끊는다.
    /// 결과는 뒤따르는 디렉터리(그 사람의 `recovery` 가 끝나고 그 기기가 빠진다).
    ///
    /// # Errors
    /// 확인 안 된 이 기기 [`Error::DeviceUnconfirmed`], 관리자 아님·자기 자신·조직 밖·걸기 없음·대상 아님 [`Error::Refused`],
    /// 끊김·시간 초과 [`Error::Unreachable`].
    pub async fn member_revoke_device(
        &self,
        user: &str,
        device_id: &str,
        timeout: Duration,
    ) -> Result<()> {
        match self
            .control(
                conn::Control::MemberRevokeDevice {
                    user: user.to_owned(),
                    device_id: device_id.to_owned(),
                },
                timeout,
            )
            .await?
        {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::DeviceUnconfirmed => Err(Error::DeviceUnconfirmed),
            _ => Err(Error::Refused),
        }
    }

    /// 관리자 주기·빼기(`org.admin {user, admin}`, 묶음 5, 관리자만 — 자기 자신도 뺄 수 있다). 지금 디렉터리에서 이미 그
    /// 상태면 보내지 않고 `Ok`(relay 도 멱등이라 방송이 없다).
    ///
    /// # Errors
    /// 관리자 아님·조직 밖·내보낸 사람 [`Error::Refused`], 관리자가 0명이 됨 [`Error::LastAdmin`], 끊김·시간 초과
    /// [`Error::Unreachable`].
    pub async fn set_admin(&self, user: &str, admin: bool, timeout: Duration) -> Result<()> {
        let now = self
            .directory()
            .get("org")
            .and_then(|o| o.get("admins"))
            .and_then(Value::as_array)
            .map(|a| a.iter().any(|u| u.as_str() == Some(user)));
        if now == Some(admin) {
            return Ok(());
        }
        match self
            .control(
                conn::Control::SetAdmin {
                    user: user.to_owned(),
                    admin,
                },
                timeout,
            )
            .await?
        {
            conn::ControlAnswer::Done => Ok(()),
            conn::ControlAnswer::LastAdmin => Err(Error::LastAdmin),
            conn::ControlAnswer::DeviceUnconfirmed => Err(Error::DeviceUnconfirmed),
            _ => Err(Error::Refused),
        }
    }

    /// 서버 상태(`server.status`, 묶음 5, 원격 relay 의 관리자만). 집계 숫자·시각만.
    ///
    /// # Errors
    /// 관리자 아님·로컬 relay [`Error::Refused`], 응답 형식 `Error::Relay`, 끊김·시간 초과 [`Error::Unreachable`].
    pub async fn server_status(
        &self,
        timeout: Duration,
    ) -> Result<lodelai_protocol::generated::ws::ServerStatus> {
        match self.control(conn::Control::ServerStatus, timeout).await? {
            conn::ControlAnswer::Status(v) => serde_json::from_value(*v)
                .map_err(|e| Error::Relay(format!("server.status 형식: {e}"))),
            _ => Err(Error::Refused),
        }
    }

    /// 내 프로필 사진을 바꾼다(묶음 15 B9, ADR 0009 §8). 코어가 정사각 256 PNG 로 다시 인코딩한 바이트를 넘긴다. 큐에 넣기만
    /// 한다 — 지우기와 같은 큐 키(`profile.avatar`)라 마지막 의도만 남고 차례대로 간다(계약 856eb04c). 성공은 directory.update
    /// 의 내 `people[].avatar`, relay 거절은 [`Inbound::AvatarFailed`], 끊기면 다음 연결에서 다시.
    ///
    /// # Errors
    /// PNG 시그니처가 아니거나 비었거나 `AVATAR_MAX_BYTES` 를 넘으면 [`Error::Message`](넣지 않음), sqlite 오류.
    pub fn set_avatar(&self, png: &[u8]) -> Result<()> {
        Self::check_avatar_png(png)?;
        self.store
            .push_avatar(&lodelai_crypto::encoding::encode(png))?;
        self.wake.notify_one();
        Ok(())
    }

    /// 내 프로필 사진을 지운다(`profile.update{avatar: null}`, 묶음 15 §2). [`Self::set_avatar`] 와 같은 큐 키 — 올리던 사진이
    /// 있으면 그 PUT 이 끝난 뒤 간다. 성공 응답은 없고 directory.update 에서 내 `avatar` 가 빠진다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn clear_avatar(&self) -> Result<()> {
        let f = serde_json::json!({"t": "profile.update", "avatar": null});
        self.store.push(
            outbox::AVATAR_KEY,
            "profile",
            None,
            None,
            &f.to_string(),
            true,
        )?;
        self.wake.notify_one();
        Ok(())
    }

    /// 조직 사진을 바꾼다(#554 — 관리자만). [`Self::set_avatar`] 와 같은 검사·큐 규칙, 큐 키는 `org.avatar`. 성공은
    /// directory.update 의 `org.avatar`, relay 거절은 [`Inbound::AvatarFailed`]`{org: true}`.
    ///
    /// # Errors
    /// PNG 시그니처가 아니거나 비었거나 `AVATAR_MAX_BYTES` 를 넘으면 [`Error::Message`](넣지 않음), sqlite 오류.
    pub fn set_org_avatar(&self, png: &[u8]) -> Result<()> {
        Self::check_avatar_png(png)?;
        self.store
            .push_org_avatar(&lodelai_crypto::encoding::encode(png))?;
        self.wake.notify_one();
        Ok(())
    }

    /// 조직 사진을 지운다(`org.update{avatar: null}`, #554). [`Self::set_org_avatar`] 와 같은 큐 키.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn clear_org_avatar(&self) -> Result<()> {
        let f = serde_json::json!({"t": "org.update", "avatar": null});
        self.store.push(
            outbox::ORG_AVATAR_KEY,
            "org",
            None,
            None,
            &f.to_string(),
            true,
        )?;
        self.wake.notify_one();
        Ok(())
    }

    fn check_avatar_png(png: &[u8]) -> Result<()> {
        const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let max = lodelai_protocol::constants::AVATAR_MAX_BYTES;
        if !png.starts_with(&PNG_SIG) || png.len() as u64 > max {
            return Err(Error::Message(format!(
                "프로필 사진은 PNG {max}바이트 이하"
            )));
        }
        Ok(())
    }

    /// 같은 조직 사람의 프로필 사진(디렉터리 `people[].avatar` 의 blob_id)을 받는다. 받은 평문 바이트 그대로
    /// (`AVATAR_MAX_BYTES` 이하) — 디코딩·검사는 호출자.
    ///
    /// # Errors
    /// 연결 없음·끊김·시간 초과 [`Error::Unreachable`], relay 거절(다른 조직·없는 사진) [`Error::Relay`].
    pub async fn fetch_avatar(&self, blob_id: &str, timeout: Duration) -> Result<Vec<u8>> {
        // 디렉터리(relay)가 준 값이 HTTP 요청 줄에 들어간다(리뷰 ③).
        if !files::is_blob_id(blob_id) {
            return Err(Error::Relay("protocol".into()));
        }
        let (done, rx) = oneshot::channel();
        self.avatar_get
            .send(files::AvatarFetch {
                blob_id: blob_id.to_owned(),
                done,
            })
            .map_err(|_| Error::Unreachable)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(Error::Unreachable),
        }
    }

    /// 제어 요청 하나를 보내고 응답을 기다린다(한 번에 하나 — 연결 루프가 직렬화한다).
    /// 입력 중 표시(`typing{to, on}`, 묶음 36 #613). 큐에 넣지 않는다 — 연결 중이면 바로, 끊겨 있으면 다음 접속 때 버린다.
    /// `to` = 사람 또는 그룹 주소. 갱신 주기(3초)·멈춤(5초)은 부르는 쪽(코어)이 정한다. relay 가 범위 밖·판 11 아래 상대를 거른다.
    pub fn typing(&self, to: &str, on: bool) {
        let _ = self
            .typing
            .send(serde_json::json!({"t": "typing", "to": to, "on": on}));
    }

    async fn control(&self, c: conn::Control, timeout: Duration) -> Result<conn::ControlAnswer> {
        let (tx, rx) = oneshot::channel();
        self.control.send((c, tx)).map_err(|_| Error::Unreachable)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(a)) => Ok(a),
            _ => Err(Error::Unreachable),
        }
    }

    /// 사람이 지문을 대조해 방금 승인한 **내** 다른 기기(M1 주인 앱의 기기 추가, #339 설계 4)를 미리 `trusted` 로 심는다 —
    /// 그 등록이 부르는 directory.update 에서 "새 기기 추가됨" 카드가 다시 뜨지 않게. 등록 **전에** 부른다(디렉터리가 응답보다
    /// 먼저 올 수 있다). 이미 아는 기기면 그대로 두고 `false`. 새로 심었는데 등록이 실패하면 [`Self::forget_planted_device`].
    ///
    /// # Errors
    /// 내 사용자가 아님 [`Error::UnknownDevice`], sqlite 오류.
    pub fn plant_own_device(&self, info: &register::DeviceInfo) -> Result<bool> {
        if self.me.address.split('@').next() != Some(info.user.as_str()) {
            return Err(Error::UnknownDevice);
        }
        // 주인이 연결 코드로 승인(human). `planted` = 아직 디렉터리에 나온 적 없음 — 그 전에 오는 디렉터리가 '목록에 없으면
        // 폐기'로 덮지 않게(keys::learn). 처음 목록에 나오면 지운다. 행과 근거를 한 문장에 넣는다 — 따로 쓰면 그 사이 늦게 온
        // 디렉터리가 근거 없는 행을 revoked 로 바꿔 forget 이 못 지운다(시험 흔들림, 10-27).
        self.store.insert_peer_with_basis(
            &Peer {
                device_id: info.device_id.clone(),
                user: info.user.clone(),
                ed25519: info.ed25519.clone(),
                x25519: info.x25519.clone(),
                trust: Trust::Trusted,
                first_contact: false,
            },
            &[keys::planted_basis(keys::wall_ms()), "human".to_owned()],
        )
    }

    /// 그룹에 보내기 전 검사(묶음 16 §24.5·§24.7 — 화면이 글을 입력칸에 남긴 채 이유를 보이게). `enqueue` 가 그룹 맥락
    /// 메시지에 쓰는 판정과 같고, 아무것도 넣지 않는다. 돌려주는 값: 감쌀 수신 기기 수(나 포함 지금 멤버의 신뢰 기기).
    ///
    /// # Errors
    /// 모르는 그룹·내가 멤버 아님 [`Error::NotGroupMember`], [`Error::GroupStale`], 믿음 기다림 [`Error::GroupWaitingTrust`],
    /// 64 초과 [`Error::TooManyDevices`], sqlite 오류.
    pub fn group_send_check(&self, gid: &str) -> Result<usize> {
        // 묶음 22: MLS 그룹이면 그 잎 수(받을 기기는 relay 가 잎으로 정한다).
        if let Some(m) = &self.mls_state {
            if let Some(g) = mls_conn::load(m, gid.as_bytes()) {
                return Ok(g.members().count().saturating_sub(1));
            }
        }
        Err(Error::NotGroupMember)
    }

    /// '지금 끊기'(#577 §3) 동안 그룹 응용 글을 받지 않는다(`true`) / 다시 받는다(`false`, 끊기 실패). 받지 않은 글은 ack 하지
    /// 않아 relay 큐에 남는다 — 폐기 때 relay 가 보낸 쪽에 `recipient_device_changed` 를 주고, 보낸 쪽은 새 기기가 든 뒤 다시
    /// 보낸다(눌렀는데 폐기 전 틈에 옛 기기가 받아 끝나 버리는 조용한 유실을 막음). 다시 접속해도 유지된다. Handshake 는 그대로.
    /// 풀면 바로 다시 접속해 그동안 받지 않은 글을 받는다.
    pub fn hold_group_deliveries(&self, hold: bool) {
        use std::sync::atomic::Ordering;
        if self.holding.swap(hold, Ordering::SeqCst) && !hold {
            // 연결이 살아 있는 채 풀면(LastAdmin 등) 받지 않은 글이 다음 재접속까지 묶인다 — 지금 다시 접속한다.
            self.unheld.store(true, Ordering::SeqCst);
            self.wake.notify_one();
        }
    }

    /// 이 기기가 든 MLS 그룹 중 `device` 가 아직 잎이 아닌 것의 수(#577 '지금 끊기' — 옛 기기는 새 기기를 다 넣을 때까지
    /// 기다렸다 끊는다). MLS 가 아니면 0.
    #[must_use]
    pub fn groups_missing_leaf(&self, device: &str) -> usize {
        let Some(m) = &self.mls_state else {
            return 0;
        };
        mls_conn::groups_missing_leaf(m, device)
    }

    /// 그룹 로컬 상태(묶음 16 §3). 모르는 그룹이면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group(&self, gid: &str) -> Result<Option<GroupState>> {
        // 묶음 22: MLS 그룹이 있으면 그것에서(잎·0xF0A1·확정 seq).
        if let Some(m) = &self.mls_state {
            let dir = keys::DirView::new(
                &self
                    .directory
                    .read()
                    .map(|d| d.clone())
                    .unwrap_or(Value::Null),
                self.me.address.split_once('@').map_or("", |(_, s)| s),
            )
            .with_former(&self.store);
            let server = self.me.address.split_once('@').map_or("", |(_, s)| s);
            return Ok(mls_conn::group_state(m, &dir, gid, server));
        }
        Ok(None)
    }

    /// [`Self::plant_own_device`] 로 심었지만 등록하지 못한 기기를 지운다(디렉터리에 나타나지 않았을 때만 — 이미 배웠으면 둔다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn forget_planted_device(&self, device_id: &str) -> Result<()> {
        self.store.remove_trusted_peer(device_id)
    }

    /// 원격 relay 관리자가 동료·자기 다른 맥을 등록한다(ws `device.register {code}`, #364 — 묶음 4 에서만). `code` 는 새 기기의
    /// 연결 코드([`register::connection_code`]). 큐에 이미 들어 있는 것이 다 나간 뒤 보내고, 한 번에 하나씩이다.
    ///
    /// # Errors
    /// 다른 사람이 쓰는 아이디 [`Error::HandleTaken`], 관리자 아님·코드 형식·지문 불일치 `Error::Relay("protocol")`,
    /// `timeout` 안에 응답이 없거나 응답 전에 끊기면 [`Error::Unreachable`] — 등록됐을 수도 있다(같은 코드로 다시 부르면 멱등).
    pub async fn device_register(&self, code: &str, timeout: Duration) -> Result<DeviceRegistered> {
        let (tx, rx) = oneshot::channel();
        self.register
            .send((code.to_owned(), tx))
            .map_err(|_| Error::Unreachable)?;
        self.wake.notify_one();
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            _ => Err(Error::Unreachable),
        }
    }

    /// 상대의 `pending` 기기를 사람이 확인했다(`CmdTrustDevice`, #313 결정 b) → `trusted`. 바뀐 피어를 돌려준다.
    /// 그 기기에서 와서 보류 중인 메시지를 풀어 주는 것은 core 몫이다.
    ///
    /// # Errors
    /// 모르는 기기·그 사용자의 기기가 아님 [`Error::UnknownDevice`], `pending` 이 아님 [`Error::NotPending`], sqlite 오류.
    /// '다시 받기'(묶음 22 §9·§12-19 — `CmdConversationRejoin`): 그 대화의 그룹에 최신 GroupInfo 로 다시 들어간다(external
    /// commit). 그동안 대화는 `syncing`, 들어가면 `ok`(멈춘 동안 버린 글이 있으면 `lost_since`). `conversation` = 상대 사람 주소
    /// (pair)·내 주소(self)·그룹 주소(`+gid@…`).
    ///
    /// # Errors
    /// MLS 가 없거나 대화 주소 꼴이 아니면 `Message`.
    pub fn rejoin_conversation(&self, conversation: &str) -> Result<()> {
        if self.mls_state.is_none() {
            return Err(Error::Message("MLS 없음".into()));
        }
        let (user, server) = conversation
            .split('/')
            .next()
            .and_then(|a| a.split_once('@'))
            .ok_or_else(|| Error::Message("대화 주소 꼴".into()))?;
        let header = if let Some(gid) = user.strip_prefix('+') {
            gid.to_owned()
        } else {
            let me = self.me.address.split('@').next().unwrap_or_default();
            if server.is_empty() || user.is_empty() {
                return Err(Error::Message("대화 주소 꼴".into()));
            }
            mls_conn::header_of(&mls_conn::conv(me, user).gid)
        };
        if let Ok(mut a) = self.rejoin_asks.lock() {
            a.push(header);
        }
        self.wake.notify_one();
        Ok(())
    }

    pub fn trust_device(&self, user: &str, device_id: &str) -> Result<Peer> {
        let mut p = self
            .store
            .peer(device_id)?
            .filter(|p| p.user == user)
            .ok_or(Error::UnknownDevice)?;
        if p.trust != Trust::Pending {
            return Err(Error::NotPending(p.trust));
        }
        self.store.set_trust(device_id, Trust::Trusted)?;
        self.store.add_basis(device_id, "human")?;
        self.store.set_pending_since(device_id, None)?;
        p.trust = Trust::Trusted;
        // 내 다른 기기를 확인했다 — 그 확인이 곧 서명이다(#393 §7a-1). 동료들은 이 서명으로 그 기기를 믿는다.
        if let Some((me, server)) = self.me.address.split_once('@') {
            if me == user {
                keys::queue_certify(&self.store, &self.keys, server, me, device_id, &p.x25519)?;
                self.wake.notify_one();
            }
        }
        Ok(p)
    }

    /// 아는 상대 기기 전부(사용자·device_id 순) — sync 재발행용.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn peers(&self) -> Result<Vec<Peer>> {
        self.store.peers()
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// 이 기기의 사람 주소·기기 지문.
    pub fn me(&self) -> &Me {
        &self.me
    }

    /// 연결 루프를 멈추고 끝날 때까지 기다린다.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
