//! 연결 루프: 접속 → 인증 → (큐 내보내기 · 수신 처리 · ping) → 끊기면 백오프 뒤 다시.
//!
//! - 큐의 `send` 는 하나씩 보내고 서버의 `ack`/`nack` 를 기다린다(순서 보존). `ack` 면 큐에서 빼고 `sent` 에 기록, `nack` 면 빼고
//!   [`Inbound::Nack`](crate::Inbound::Nack) — 다시 보내지 않는다. 응답 전에 끊기면 남아 있다가 재접속 뒤 같은 바이트로 다시 간다
//!   (relay 는 같은 발신자의 같은 `msg_id` 에 멱등 `ack`).
//! - `status`·`session.*` 는 쓰면 끝(서버 응답 없음).
//! - 보내는 간격은 `send_interval` 로 늦춘다 — relay rate limit 에 걸리면 연결이 끊긴다. `error rate_limited` 를 받으면 길게 쉰다.
//! - 서버 `ping` 에는 `pong`. 서버에서 `idle_timeout` 동안 아무 프레임도 안 오면 끊고 다시 접속한다(조용히 죽은 서버).
//!   내 `ping` 뒤 `pong_timeout` 안에 아무 프레임도 없어도 끊는다(멈춘 relay 를 빨리 알아챔).
//! - `deliver` 는 [`keys::verify`](crate::keys::verify) → 봉투 열기(서명이 맞을 때만, e2e-envelope §4). 모르는 기기면
//!   `directory.list` 를 한 번 보내고 기다렸다 다시 본다. 코어에는 평문(`{enc: plain, text}`)만 넘긴다.
//! - 받는 기기 목록은 MLS 그룹이 정한다(묶음 22 — 옛 봉투 `recipients`·`stale_devices` 재암호화 #313 은 없다, #503). 새·폐기 기기는
//!   그룹 Commit 으로 반영되고, epoch 가 어긋난 행은 `nack stale_epoch` 를 받아 새 epoch 로 다시 봉인해 같은 `msg_id` 로 보낸다.
//! - 기기 폐기(#325): 요청을 받아 두었다가 큐가 비고 응답 대기 중인 `send` 도 없을 때 `device.revoke` 를 보낸다. `device.revoked` 를
//!   받으면 요청자에게 알리고 루프를 끝낸다(다시 접속하지 않음). 응답 전에 연결이 끊기면 요청을 버린다 — 요청자는 `Unreachable`.
//! - 기기 등록(#364, 원격 relay 관리자): 폐기와 같이 큐가 빈 뒤 `device.register` 를 보내고 `device.registered` 나 ref 없는
//!   `error{handle_taken|protocol}` 을 그 요청의 답으로 본다(한 번에 하나라 짝이 맞는다). 끊기면 요청자는 `Unreachable`.
//! - `wss://` 는 rustls(ring, webpki 루트)로, `ws://` 는 로컬만([`tls::target`](crate::tls::target)).

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::sign_challenge;
use openmls_traits::OpenMlsProvider as _;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;

use lodelai_crypto::EnvelopeError;
use lodelai_effects::Rng;

use crate::keys::{self, Learned, Verdict};
use crate::outbox::{self, Store};
use crate::{AckHandle, Config, DeviceRegistered, Error, Inbound, RegisterRequest, RejectReason};

/// group Commit 하나를 가리키는 (gid, epoch, commit_hash).
pub type CommitKey = (String, u64, [u8; 32]);

pub struct Shared {
    pub config: Config,
    /// MLS 저장·서명(묶음 22). 메모리 큐로 띄운 시험([`crate::RelayClient::start_with_store`])만 `None`.
    pub mls: Option<Arc<Mls>>,
    /// 내 주소 `user@server`(Handshake 의 from).
    pub me_address: String,
    /// 메시지를 처리하며 relay 에 보낼 서명 없는 프레임(`commit_ack`·`commit_fail`) — 연결 루프가 프레임마다 비워 보낸다.
    pub out_frames: std::sync::Mutex<Vec<String>>,
    /// 거절돼 한 번 다시 낸 create Commit 행(§12-25 리뷰 ③ — 두 번째 거절이면 그룹을 지우고 실패).
    pub create_retried: std::sync::Mutex<std::collections::HashSet<i64>>,
    /// 확정을 기다리는 내 사람 op Commit: (gid, epoch) → (앞서 무효된 횟수, 처음 행의 msg_id) — 같은 변경 3번 무효면 멈춤(§12-26 ⑤).
    /// 메모리에만 둔다(다시 켜면 다시 셈).
    pub commit_tries: std::sync::Mutex<std::collections::HashMap<(String, u64), (u32, String)>>,
    /// 사람 op Commit 의 같은 대상 마지막 변경(§12-27 ⓒ): (gid, op, subject) → change_id. 무효 뒤 다시 봉인할 때 더 나중 변경이
    /// 봉인됐으면 앞의 것은 보내지 않는다. 메모리에만.
    pub latest_change:
        std::sync::Mutex<std::collections::HashMap<(String, String, String), String>>,
    /// `stale_epoch` 로 돌아온 MLS 행: seq → (연달아 돌아온 횟수, 이때까지 다시 봉인하지 않음). 남의 Commit 이 relay 에서 확정을
    /// 기다리는 동안(최대 1시간) 같은 epoch 로 곧바로 relay 를 다시 두드리지 않게(§4-7). 메모리에만.
    pub row_wait: std::sync::Mutex<std::collections::HashMap<i64, (u32, Instant)>>,
    /// rank k>0 로 받은 duty(§7): 이때가 되어도 아직 할 일이면 한다. 메모리에만 — 다시 접속하면 relay 가 같은 rank 로 다시 준다.
    pub duty_wait: std::sync::Mutex<Vec<(Instant, Value)>>,
    /// group Add 행이 가져온 KeyPackage: seq → 그것들. `stale_epoch` 로 다시 봉인할 때 다시 claim 하지 않는다(버린 Commit 의
    /// Welcome 은 relay 가 받지 않아 아무도 쓰지 않았다 — claim 상한·KeyPackage 를 아낌). 행이 끝나면 지운다. 메모리에만.
    pub row_kps:
        std::sync::Mutex<std::collections::HashMap<i64, Vec<openmls::prelude::KeyPackage>>>,
    /// 주기 Update 때를 마지막으로 본 때(`Config::update_check` 마다 본다).
    pub update_checked: std::sync::Mutex<Option<Instant>>,
    /// external commit 으로 다시 들어가는 중인 group: gid → (epoch, commit_hash). openmls 가 보낼 때 이미 merge 하므로 무효·거절이면
    /// 그 상태를 버리고 다시 들어간다. 메모리에만 — 다시 켜면 relay 가 접속 때 `rejoin_needed` 를 다시 준다.
    pub rejoining: std::sync::Mutex<std::collections::HashMap<String, (u64, [u8; 32])>>,
    /// 이 relay 가 그룹을 쓰나(22 §12-30): 연결마다 101 의 [`crate::blobio::FEATURES_HEADER`] 로 다시 정한다. 줄이 없으면 모름
    /// `None`(그룹 시작을 해 보고, `unroutable` 이면 `false`).
    pub groups: std::sync::Mutex<Option<bool>>,
    /// 처리하지 못해 `commit_fail` 한 group Commit (gid, epoch, hash) — 그것이 확정되면 내 몫이 깨진 것이라 external commit 으로
    /// 다시 들어간다(§4-7). 메모리에만.
    pub failed_commits: std::sync::Mutex<std::collections::HashSet<(String, u64, [u8; 32])>>,
    /// 그룹 다시 들기 신호가 왔을 때 이미 큐에 있던 다시 들기 행의 gid — 물러섬을 풀고 지금 다시 한다(#599 ②). 메모리에만.
    pub rejoin_now: std::sync::Mutex<std::collections::HashSet<String>>,
    /// 받은 group external commit (gid, epoch, hash) → 스스로 든 기기 — 확정되면 그 기기에 그룹 이름을 다시 보낼지 본다(#577).
    /// 메모리에만(확정은 보통 몇 분 안).
    pub external_joiners: std::sync::Mutex<std::collections::HashMap<CommitKey, String>>,
    /// 내 group 주기 Update Commit 의 해시 — 그것이 확정될 때만 Update 셈을 다시 한다(Add 만 든 Commit 은 내 잎 키를 바꾸지
    /// 않는다). 메모리에만 — 다시 켜면 셈은 한 시간 뒤 다시 낸다.
    pub self_updates: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    /// 그룹별 디렉터리 때문의 Commit 다시(Retry) 수와 마지막으로 `directory.list` 를 당긴 때(ms) — [`retry_pull`](#725).
    pub dir_pulls: std::sync::Mutex<std::collections::HashMap<String, (u32, i64)>>,
    /// relay `groups` 가 알려 준 내 group 들(헤더 값 — §7 새 기기가 스스로 들어갈 후보). 메모리에만.
    pub known_groups: std::sync::Mutex<Option<std::collections::BTreeSet<String>>>,
    /// 다시 들어가기가 끝난 대화(그룹 id 바이트) → 끝난 시각(ms). 그보다 먼저 넣은 다시 들어가기 행은 겹친 것이라 뺀다(#577).
    /// 메모리에만.
    pub rejoined: std::sync::Mutex<std::collections::HashMap<Vec<u8>, i64>>,
    /// 새 기기 스스로 들어가기(§7)로 이번 실행에 이미 행을 넣은 group.
    pub orphan_tried: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// 다시 들어가기(external commit)를 만들지 못한 횟수, 행 seq 별(#577 §9 — 끊긴 옛 잎이 아직 트리에 있으면 남이 빼 줄 때까지
    /// 짧게 다시 본다). 메모리에만.
    pub rejoin_fails: std::sync::Mutex<std::collections::HashMap<i64, u32>>,
    /// blob 칸이 있어 받아 채운 뒤 처리할 것(§5c). 연결 루프가 하나씩 받는다. 메모리에만 — ack 하지 않았으니 다시 접속하면
    /// relay 가 다시 준다.
    pub blob_jobs: std::sync::Mutex<VecDeque<BlobJob>>,
    /// '다시 받기'로 다시 들어갈 그룹(헤더 값, [`crate::RelayClient::rejoin_conversation`]).
    pub rejoin_asks: Arc<std::sync::Mutex<Vec<String>>>,
    /// '지금 끊기'로 이 기기를 끊는 중([`crate::RelayClient::hold_group_deliveries`], #577) — 그룹 응용 글은 받지도 ack 하지도
    /// 않는다. relay 큐에 남아 폐기 때 보낸 쪽에 `recipient_device_changed` 가 가고, 새 기기가 든 뒤 다시 온다.
    pub holding: Arc<std::sync::atomic::AtomicBool>,
    /// 받지 않기를 풀었다(끊기 실패) — 연결 루프가 다시 접속해 그동안 ack 하지 않은 글을 relay 에서 다시 받는다(relay 는 접속 때만
    /// 다시 준다).
    pub unheld: Arc<std::sync::atomic::AtomicBool>,
    pub store: Arc<Store>,
    /// 폐기 증명 `at`(relay 와 같은 시계 — 시험은 가짜 시계).
    pub clock: Arc<dyn lodelai_effects::Clock>,
    pub wake: Arc<Notify>,
    pub directory: Arc<RwLock<Value>>,
    pub inbound: mpsc::Sender<Inbound>,
    pub shutdown: watch::Receiver<bool>,
    /// 기기 폐기 요청(#325) — `true` 면 조직 나가기(`member.leave`, 묶음 5). 응답 `device.revoked` 면 `Ok`,
    /// `error{last_admin}`(묶음 5)이면 [`crate::Error::LastAdmin`].
    pub revoke: mpsc::UnboundedReceiver<(bool, oneshot::Sender<crate::Result<()>>)>,
    /// 응답이 ref 없이 오는 제어 요청(#339 내 다른 기기 끊기, #355 조직 관리자 동작). 한 번에 하나 — 응답에 상관 필드가 없다.
    pub control: mpsc::UnboundedReceiver<(Control, oneshot::Sender<ControlAnswer>)>,
    /// 기기 등록 요청(#364). 응답 `device.registered`·`error` 를 받으면 보낸다.
    pub register: mpsc::UnboundedReceiver<RegisterRequest>,
    /// 프로필 사진 받기(묶음 15 B9). 연결 중일 때 하나씩 작업으로.
    pub avatar_get: mpsc::UnboundedReceiver<crate::files::AvatarFetch>,
    /// 입력 중 표시(`typing`, 묶음 36 #613) — 큐에 넣지 않는다. 연결 중이면 바로 보내고, 끊긴 사이 온 것은 다음 접속 때 버린다.
    pub typing: mpsc::UnboundedReceiver<Value>,
    /// 난수(새 `msg_id`·MLS).
    pub rng: Arc<dyn Rng>,
}

/// 이 기기의 MLS 상태: openmls provider(같은 DB 파일의 `mls_*`)와 기기 키 Signer.
pub struct Mls {
    pub provider: crate::mls::Provider,
    pub signer: crate::mls::DeviceSigner,
}

/// 제어 요청의 응답을 기다리며 큐를 멈추는 최대 시간(#339). 지나면 대기를 비우고 큐를 다시 보낸다.
const CONTROL_WAIT: Duration = Duration::from_secs(10);
/// `device.name` 의 답(내 디렉터리 갱신 또는 ref 없는 오류)을 기다리는 상한. 그동안 관리 요청을 꺼내지 않는다 — 상한 뒤
/// 늦게 온 ref 없는 오류가 관리 요청의 답으로 읽히지 않게 [`CONTROL_WAIT`] 보다 길게(계약 8cd7072c).
const NAME_WAIT: Duration = Duration::from_secs(15);

/// 응답이 ref 없이 오는 제어 요청(#339·#355). 보내는 동안은 큐를 멈추고 하나씩만 보낸다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// 같은 사용자의 다른 기기 끊기(`proof` 를 실음 — 묶음 22 §12-11 ⓐ), 또는 조직 관리자가 같은 조직 사람의 기기 끊기
    /// (증명 없음 — relay 는 서명자가 같은 사용자일 때만 받는다).
    RevokeDevice {
        device_id: String,
        proof: Option<Value>,
    },
    OrgRename(String),
    TeamCreate(String),
    TeamRename {
        id: String,
        name: String,
    },
    TeamDelete(String),
    InviteCreate(Option<String>),
    /// 관리자 주기·빼기(묶음 5).
    SetAdmin {
        user: String,
        admin: bool,
    },
    /// 내보내기(묶음 5).
    MemberRemove(String),
    /// 관리자 폐기(#737): 같은 조직 다른 사람의 메일 확인 끊기 대상 기기.
    MemberRevokeDevice {
        user: String,
        device_id: String,
    },
    /// 서버 상태 조회(묶음 5).
    ServerStatus,
    /// 메일 확인 끊기 걸기·취소·막기(#577 §4).
    Recover,
    RecoverCancel,
    RecoverBlock,
}

impl Control {
    fn frame(&self) -> Value {
        match self {
            Self::RevokeDevice { device_id, proof } => match proof {
                Some(p) => json!({"t": "device.revoke", "device_id": device_id, "proof": p}),
                None => json!({"t": "device.revoke", "device_id": device_id}),
            },
            Self::OrgRename(name) => json!({"t": "org.update", "name": name}),
            Self::TeamCreate(name) => json!({"t": "team.create", "name": name}),
            Self::TeamRename { id, name } => json!({"t": "team.update", "id": id, "name": name}),
            Self::TeamDelete(id) => json!({"t": "team.delete", "id": id}),
            Self::InviteCreate(email) => match email {
                Some(e) => json!({"t": "invite.create", "email": e}),
                None => json!({"t": "invite.create"}),
            },
            Self::SetAdmin { user, admin } => {
                json!({"t": "org.admin", "user": user, "admin": admin})
            }
            Self::MemberRemove(user) => json!({"t": "member.remove", "user": user}),
            Self::MemberRevokeDevice { user, device_id } => {
                json!({"t": "member.revoke_device", "user": user, "device_id": device_id})
            }
            Self::ServerStatus => json!({"t": "server.status"}),
            Self::Recover => json!({"t": "device.recover"}),
            Self::RecoverCancel => json!({"t": "device.recover_cancel"}),
            Self::RecoverBlock => json!({"t": "device.recover_block"}),
        }
    }
}

/// 제어 요청의 relay 응답.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAnswer {
    /// 끊었다(`device.revoked{device_id}`) 또는 관리자 동작이 반영됐다(뒤따른 `directory.update`).
    Done,
    /// 초대 토큰(`invite.created`).
    Invite { token: String, expires_at: String },
    /// 나중 기기가 먼저 기기를 등록 24시간 전에 끊으려 했다(`error{too_early}`).
    TooEarly,
    /// 거절(`error{protocol}` — 남의 기기·모르는 id·관리자 아님·이름 규칙 밖).
    Refused,
    /// 초대 발급 상한(`error{rate_limited}`, 연결은 유지).
    RateLimited,
    /// 팀 이름이 겹친다(`error{name_taken}`, #355).
    NameTaken,
    /// 관리자가 0명이 된다(`error{last_admin}`, 묶음 5).
    LastAdmin,
    /// 확인 안 된(잎 자격 없는) 기기의 관리자 동작(`error{device_unconfirmed}`, #737).
    DeviceUnconfirmed,
    /// `server.status` 응답(묶음 5) — 모양 검사는 호출자.
    Status(Box<Value>),
    /// 메일 확인 끊기 거절(#577 `error{recover_refused, reason, until?}`).
    RecoverRefused {
        reason: String,
        until: Option<String>,
    },
}

/// 한 번의 연결이 끝난 이유.
#[derive(Debug)]
/// blob 칸을 받아 채운 뒤 할 일(§5c).
pub enum BlobJob {
    /// 받은 group Handshake — 채워서 평소 deliver 로.
    Deliver {
        message: Value,
        held: bool,
        group_seq: Option<u64>,
    },
    /// 다시 들어가기의 `group_info` 프레임 — 채워서 external commit.
    GroupInfo { seq: i64, frame: Value },
}

enum End {
    Shutdown,
    /// 인증 성공 뒤 끊김 → 백오프를 처음부터.
    AfterReady,
    /// 인증 전 실패.
    BeforeReady,
    RateLimited,
    /// 이 기기가 폐기됐다 — 다시 접속하지 않는다.
    Revoked,
    /// 판이 맞지 않는다(묶음 26 §6).
    Version(crate::VersionMismatch),
    /// 보낸 `send` 에 답이 없거나 relay 가 internal 로 답했다(#537) — 다시 접속해 같은 msg_id 를 다시 보낸다. 백오프는 인증 전
    /// 실패처럼 두 배씩(연달아도 빠른 끊김을 되풀이하지 않게).
    Unanswered,
}

pub async fn run(mut s: Shared) {
    let mut backoff = Duration::from_millis(250);
    loop {
        let end = connect_once(&mut s).await;
        if matches!(
            end,
            End::Shutdown | End::Revoked | End::Version(crate::VersionMismatch::AppOutdated)
        ) || *s.shutdown.borrow()
        {
            return;
        }
        let _ = s.inbound.send(Inbound::Disconnected).await;
        let wait = match end {
            End::AfterReady => {
                backoff = Duration::from_millis(250);
                backoff
            }
            End::RateLimited => s.config.backoff_max,
            End::Version(_) => s.config.version_retry,
            _ => {
                let w = backoff;
                backoff = (backoff * 2).min(s.config.backoff_max);
                w
            }
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = s.shutdown.changed() => return,
        }
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn recv_json(ws: &mut Ws) -> Option<Value> {
    loop {
        match ws.next().await? {
            Ok(Message::Text(t)) => return serde_json::from_str(t.as_str()).ok(),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => {}
            Ok(Message::Binary(_)) => return None,
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

async fn send_text(ws: &mut Ws, text: String) -> bool {
    ws.send(Message::Text(text.into())).await.is_ok()
}

/// 접속·인증 결과.
enum Handshake {
    Ready(Value),
    /// 이 기기가 계정에서 끊겼다(`error{device_revoked, by?}`, #339·묶음 5).
    Revoked(crate::RemovedBy, Option<String>),
    /// 판이 맞지 않는다(`error{version_unsupported}`, 묶음 26 §6).
    Version(crate::VersionMismatch, Option<u32>),
    /// hello·auth 를 거절(`error{protocol|auth}`) — 8 전 relay 의 판 불일치일 수 있다(묶음 22 §12-28 ②). 8 전 relay 는
    /// 스키마가 hello `v` 를 자기 판 하나로 묶어, 판이 다른 hello 를 challenge 대신 이 오류로 끊는다(#552).
    AuthFailed,
}

/// `error{version_unsupported, min, max}` 이면 내 판과 견준 결과. min·max 가 없거나 숫자가 아니면 앱 쪽 업데이트로 푼다.
/// 내 판이 그 사이면(relay 가 모순) 판 문제로 보지 않는다 — 보통 재접속으로.
fn version_mismatch(frame: &Value) -> Option<(crate::VersionMismatch, Option<u32>)> {
    use crate::VersionMismatch as M;
    if frame.get("t").and_then(Value::as_str) != Some("error")
        || frame.get("code").and_then(Value::as_str) != Some("version_unsupported")
    {
        return None;
    }
    let v = u64::from(lodelai_protocol::PROTOCOL_VERSION);
    let max = frame.get("max").and_then(Value::as_u64);
    let m = match (frame.get("min").and_then(Value::as_u64), max) {
        (Some(min), Some(_)) if v < min => M::AppOutdated,
        (Some(_), Some(max)) if v > max => M::ServerOutdated,
        (Some(_), Some(_)) => return None,
        _ => M::AppOutdated,
    };
    Some((m, max.and_then(|m| u32::try_from(m).ok())))
}

/// 접속·인증. 성공하면 `ready` 프레임, 폐기된 기기면 [`Handshake::Revoked`].
async fn handshake(c: &Config, ws: &mut Ws) -> Option<Handshake> {
    let device_id = c.keys.device_id();
    let hello =
        json!({"t": "hello", "v": c.protocol, "device_id": device_id.as_str(), "user": c.user});
    if !send_text(ws, hello.to_string()).await {
        return None;
    }
    let ch = recv_json(ws).await?;
    if let Some((m, max)) = version_mismatch(&ch) {
        return Some(Handshake::Version(m, max));
    }
    if rejected(&ch) {
        return Some(Handshake::AuthFailed);
    }
    let nonce = ch.get("nonce").and_then(Value::as_str)?;
    let sig = sign_challenge(&c.keys.signing, &c.server_name, device_id.as_str(), nonce).ok()?;
    if !send_text(ws, json!({"t": "auth", "sig": sig}).to_string()).await {
        return None;
    }
    let ready = recv_json(ws).await?;
    if let Some((m, max)) = version_mismatch(&ready) {
        return Some(Handshake::Version(m, max));
    }
    if ready.get("t").and_then(Value::as_str) == Some("error")
        && ready.get("code").and_then(Value::as_str) == Some("device_revoked")
    {
        return Some(Handshake::Revoked(removed_by(&ready), removed_at(&ready)));
    }
    if rejected(&ready) {
        return Some(Handshake::AuthFailed);
    }
    (ready.get("t").and_then(Value::as_str) == Some("ready")).then_some(Handshake::Ready(ready))
}

/// 폐기 대기 키로 한 번 붙어 자기 폐기(계정 흐름 11-02 — 끊긴 채 이 기기에서만 뺀 기기를 서버에서도 끊는다). 메시지·디렉터리는
/// 다루지 않는다: hello·auth → `device.revoke`(자기 폐기 증명) → `device.revoked` 를 받으면 끝. 이미 끊긴 기기면(`error{device_revoked}`)
/// 성공으로 본다. 전체 `timeout` 안에.
///
/// # Errors
/// 주소 규칙 밖·닿지 않음·시간 초과·판 불일치 [`Error::Unreachable`](다시 해 볼 것), hello·auth 거절(서버가 모르는 기기·사용자 —
/// 다시 해도 같다) [`Error::UnknownDevice`], 마지막 관리자 [`Error::LastAdmin`].
pub async fn revoke_with_key(
    ws_url: &str,
    server_name: &str,
    user: &str,
    keys: &lodelai_crypto::DeviceKeys,
    now: lodelai_effects::UnixMillis,
    timeout: Duration,
) -> crate::Result<()> {
    tokio::time::timeout(
        timeout,
        revoke_with_key_once(ws_url, server_name, user, keys, now),
    )
    .await
    .unwrap_or(Err(Error::Unreachable))
}

async fn revoke_with_key_once(
    ws_url: &str,
    server_name: &str,
    user: &str,
    keys: &lodelai_crypto::DeviceKeys,
    now: lodelai_effects::UnixMillis,
) -> crate::Result<()> {
    let target = crate::tls::target(ws_url).map_err(|_| Error::Unreachable)?;
    let connector = target
        .tls
        .then(|| tokio_tungstenite::Connector::Rustls(crate::tls::client_config()));
    let (mut ws, _) =
        tokio_tungstenite::connect_async_tls_with_config(ws_url, None, false, connector)
            .await
            .map_err(|_| Error::Unreachable)?;
    let device_id = keys.device_id();
    let hello = json!({"t": "hello", "v": lodelai_protocol::PROTOCOL_VERSION, "device_id": device_id.as_str(), "user": user});
    if !send_text(&mut ws, hello.to_string()).await {
        return Err(Error::Unreachable);
    }
    let ch = recv_json(&mut ws).await.ok_or(Error::Unreachable)?;
    if rejected(&ch) {
        return Err(Error::UnknownDevice);
    }
    let nonce = ch
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(Error::Unreachable)?;
    let sig = sign_challenge(&keys.signing, server_name, device_id.as_str(), nonce)
        .map_err(|_| Error::Unreachable)?;
    if !send_text(&mut ws, json!({"t": "auth", "sig": sig}).to_string()).await {
        return Err(Error::Unreachable);
    }
    let ready = recv_json(&mut ws).await.ok_or(Error::Unreachable)?;
    let code = |f: &Value| f.get("code").and_then(Value::as_str).map(str::to_owned);
    match ready.get("t").and_then(Value::as_str) {
        Some("ready") => {}
        Some("error") if code(&ready).as_deref() == Some("device_revoked") => return Ok(()),
        _ if rejected(&ready) => return Err(Error::UnknownDevice),
        _ => return Err(Error::Unreachable),
    }
    let proof = keys::revoke_proof(keys, server_name, device_id.as_str(), now);
    if !send_text(
        &mut ws,
        json!({"t": "device.revoke", "proof": proof}).to_string(),
    )
    .await
    {
        return Err(Error::Unreachable);
    }
    loop {
        let f = recv_json(&mut ws).await.ok_or(Error::Unreachable)?;
        match f.get("t").and_then(Value::as_str) {
            Some("device.revoked") => {
                let _ = ws.close(None).await;
                return Ok(());
            }
            Some("error") => {
                return match code(&f).as_deref() {
                    Some("device_revoked") => Ok(()),
                    Some("last_admin") => Err(Error::LastAdmin),
                    _ => Err(Error::Unreachable),
                };
            }
            _ => {}
        }
    }
}

/// 옛·지금 relay 모두 hello·서명 실패를 `error{protocol, handshake}` 로 보낸다. message 는 보지 않는다(9978ab1a).
fn rejected(frame: &Value) -> bool {
    frame.get("t").and_then(Value::as_str) == Some("error")
        && matches!(
            frame.get("code").and_then(Value::as_str),
            Some("protocol" | "auth")
        )
}

/// relay 주소 → `/v1/healthz` 에 판 범위 헤더가 있었나(§12-28 ②). 프로세스 동안 기억하고 그 relay 의 `ready` 에 지운다 —
/// 30초·15분 다시 붙기마다 GET 이 붙지 않게.
fn healthz_seen() -> &'static std::sync::Mutex<std::collections::HashMap<String, bool>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// 101 에 판 범위 헤더가 없는 relay 가 hello·서명을 거절했을 때: 8 전 relay 인가(§12-28 ②). healthz 에 헤더가 있으면 터널이 101
/// 헤더만 지운 것 — 지금의 auth 처리. healthz 를 못 읽으면 모른다 — 지금의 auth 처리, 기억하지 않는다(다음 시도에 다시 본다).
async fn relay_outdated(url: &str, t: &crate::tls::Target) -> bool {
    let seen = |m: &std::sync::Mutex<std::collections::HashMap<String, bool>>| {
        m.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(url)
            .copied()
    };
    if let Some(has) = seen(healthz_seen()) {
        return !has;
    }
    match crate::blobio::healthz_has_protocol(t).await {
        Ok(has) => {
            healthz_seen()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(url.to_owned(), has);
            !has
        }
        Err(e) => {
            tracing::debug!(error = %e, "healthz 를 읽지 못했다 — 지금의 auth 처리");
            false
        }
    }
}

/// 디렉터리(`directory`·`directory.update`)에서 내 기기(`device_id`)의 이름(#490 28 §4 — 내 항목에만 실린다).
fn my_device_name(dir: &Value, me: &str) -> Option<String> {
    dir.get("people")?
        .as_array()?
        .iter()
        .filter_map(|p| p.get("devices").and_then(Value::as_array))
        .flatten()
        .find(|d| d.get("device_id").and_then(Value::as_str) == Some(me))?
        .get("name")?
        .as_str()
        .map(str::to_owned)
}

/// 보낼 기기 이름: relay 가 `device.name` 을 알고(`ok`), 지금 이름을 다듬은 값이 디렉터리의 내 이름과 다를 때만.
fn wanted_name(s: &Shared, ok: bool, dir: &Value, me: &str) -> Option<String> {
    if !ok {
        return None;
    }
    let wanted = s
        .config
        .device_name
        .as_ref()
        .and_then(|f| f())
        .and_then(|n| lodelai_protocol::display_name::device_name_to_send(&n))?;
    (my_device_name(dir, me).as_deref() != Some(wanted.as_str())).then_some(wanted)
}

/// 101 에 판 범위 헤더가 없는 relay(터널이 지움)의 healthz 판 max(29 §3) — relay 주소마다 기억해 `ready` 마다 GET 이 붙지
/// 않게 한다(#557, [`healthz_seen`] 과 같은 셈). relay 가 올라가면 max 가 바뀌므로 [`HEALTHZ_MAX_TTL`] 이 지나면 다시 본다.
/// 못 읽으면 기억하지 않는다.
fn healthz_max(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>> {
    static M: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
    > = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// [`healthz_max`] 를 믿는 시간.
const HEALTHZ_MAX_TTL: Duration = Duration::from_secs(3600);

/// 기억한 healthz 판 max(아직 [`HEALTHZ_MAX_TTL`] 안이면).
fn remembered_max(
    m: &std::collections::HashMap<String, (std::time::Instant, u32)>,
    url: &str,
    now: std::time::Instant,
) -> Option<u32> {
    m.get(url)
        .filter(|(at, _)| now.saturating_duration_since(*at) < HEALTHZ_MAX_TTL)
        .map(|(_, max)| *max)
}

async fn tunneled_relay_max(url: &str, t: &crate::tls::Target) -> Option<u32> {
    let now = std::time::Instant::now();
    let lock = || {
        healthz_max()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    if let Some(max) = remembered_max(&lock(), url, now) {
        return Some(max);
    }
    let max = crate::blobio::healthz_headers(t)
        .await
        .ok()
        .and_then(|h| h.protocol_range())
        .map(|(_, max)| max)?;
    lock().insert(url.to_owned(), (now, max));
    Some(max)
}

/// `device.revoked`·`error{device_revoked}` 의 `by`(묶음 5). 없으면(묶음 5 전 relay) 본인 기기.
fn removed_by(frame: &Value) -> crate::RemovedBy {
    match frame.get("by").and_then(Value::as_str) {
        Some("admin") => crate::RemovedBy::Admin,
        Some("left") => crate::RemovedBy::Left,
        Some("recovery") => crate::RemovedBy::Recovery,
        Some("admin_device") => crate::RemovedBy::AdminDevice,
        _ => crate::RemovedBy::Device,
    }
}

/// 끊긴 시각(`device.revoked`·`error{device_revoked}` 의 선택 칸 `at`, #577 관문 🟡-10). 형식이 틀리면 없음.
fn removed_at(frame: &Value) -> Option<String> {
    let at = frame.get("at").and_then(Value::as_str)?;
    lodelai_effects::UnixMillis::parse_rfc3339(at)
        .ok()
        .and_then(|t| t.to_rfc3339().ok())
}

/// 서버 응답을 기다리는 `send`.
struct Inflight {
    seq: i64,
    msg_id: String,
    to_user: String,
    /// 그 frame 을 쓴 때(#537 상한 [`crate::Config::send_ack_wait`] 의 시작).
    sent: Instant,
}

/// 디렉터리 새로고침을 기다리는 `deliver`.
struct Waiting {
    message: Value,
    /// 그룹 변경의 relay 순서(묶음 16).
    group_seq: Option<u64>,
    since: Instant,
}

async fn connect_once(s: &mut Shared) -> End {
    let mut sd = s.shutdown.clone();
    let target = match crate::tls::target(&s.config.ws_url) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "서버 주소를 쓸 수 없다");
            return End::BeforeReady;
        }
    };
    let connector = target
        .tls
        .then(|| tokio_tungstenite::Connector::Rustls(crate::tls::client_config()));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        s.config.ws_url.as_str(),
        None,
        false,
        connector,
    );
    // §12-28 ②: 101 의 판 범위 헤더 — 없으면 8 전 relay 이거나 터널이 지운 것.
    let (mut ws, upgrade_protocol, name_ok) = tokio::select! {
        r = tokio::time::timeout(Duration::from_secs(10), connect) => match r {
            Ok(Ok((ws, resp))) => {
                // §12-30: 켠 기능 — 운영자가 끄고 켤 수 있어 연결마다.
                let features = resp
                    .headers()
                    .get(crate::blobio::FEATURES_HEADER)
                    .and_then(|v| v.to_str().ok());
                if let Ok(mut g) = s.groups.lock() {
                    *g = crate::blobio::groups_of(features);
                }
                let name_ok = crate::blobio::device_name_of(features);
                let protocol = resp
                    .headers()
                    .get(crate::blobio::PROTOCOL_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                (ws, protocol, name_ok)
            }
            _ => return End::BeforeReady,
        },
        _ = sd.changed() => return End::Shutdown,
    };
    let ready = tokio::select! {
        r = tokio::time::timeout(Duration::from_secs(10), handshake(&s.config, &mut ws)) => match r {
            Ok(Some(Handshake::Ready(r))) => r,
            Ok(Some(Handshake::Revoked(by, at))) => {
                // 다른 내 기기가 이 기기를 끊었다 — 다시 접속하지 않고 알린다(앱이 #325 로컬 지움을 한다).
                tracing::info!("이 기기는 계정에서 끊겼다 — 다시 접속하지 않는다");
                let _ = s.inbound.send(crate::Inbound::RemovedFromAccount { by, at }).await;
                return End::Revoked;
            }
            Ok(Some(Handshake::Version(m, max))) => {
                tracing::warn!(?m, ?max, "relay 와 판이 맞지 않는다(version_unsupported)");
                let _ = s.inbound.send(crate::Inbound::VersionUnsupported(m, max)).await;
                return End::Version(m);
            }
            Ok(Some(Handshake::AuthFailed))
                if upgrade_protocol.is_none() && relay_outdated(&s.config.ws_url, &target).await =>
            {
                // 8 전 relay 는 판이 다른 hello 를 challenge 전에 끊는다(#552) — 26 §6 의 relay 옛 판과 같이(15분마다 한 번).
                tracing::warn!("판 범위 헤더 없는 relay 의 거절 — 8 전 relay 로 본다");
                let m = crate::VersionMismatch::ServerOutdated;
                // 8 전 relay — 받는 가장 높은 판은 7(29 §3).
                let _ = s.inbound.send(crate::Inbound::VersionUnsupported(m, Some(7))).await;
                return End::Version(m);
            }
            _ => return End::BeforeReady,
        },
        _ = sd.changed() => return End::Shutdown,
    };
    healthz_seen()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&s.config.ws_url);
    let server = ready
        .get("server")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let pending = ready.get("pending").and_then(Value::as_u64).unwrap_or(0);
    let admin = ready.get("admin").and_then(Value::as_bool).unwrap_or(false);
    let groups = s.groups.lock().ok().and_then(|g| *g);
    // 29 §3: 이 relay 가 받는 가장 높은 판 — 101 헤더, 터널이 지웠으면 healthz(주소마다 기억, 못 읽어도 Ready 는 그대로).
    let protocol_max = match upgrade_protocol.as_deref() {
        Some(v) => crate::blobio::protocol_range(v).map(|(_, max)| max),
        None => tunneled_relay_max(&s.config.ws_url, &target).await,
    };
    if s.inbound
        .send(crate::Inbound::Ready {
            server,
            pending,
            admin,
            groups,
            protocol_max,
        })
        .await
        .is_err()
    {
        return End::Shutdown;
    }
    // 묶음 22 §7: 큐 맨 앞 send 행의 MLS 그룹 준비(KeyPackage 가져오기 → 시작 → Add Commit).
    let mut boot: Option<Boot> = None;
    // 묶음 22 §3: 첫 KeyPackage 묶음은 디렉터리 요청 앞에 — 디렉터리 답이 오면 relay 가 그것을 처리한 것이다.
    let mut kp_unconfirmed = false;
    if let Some(f) = s
        .mls
        .as_deref()
        .and_then(|m| crate::mls_conn::first_publish(m, s.config.key_package_target))
    {
        if !send_text(&mut ws, f).await {
            return End::AfterReady;
        }
        kp_unconfirmed = true;
    }
    if !send_text(&mut ws, json!({"t": "directory.list"}).to_string()).await {
        return End::AfterReady;
    }
    // 묶음 22 §9: 막힌 대화는 접속마다 다시 알린다(코어는 저장하지 않는다).
    if let Some(m) = s.mls.as_deref() {
        for (conversation, state, lost_since) in crate::mls_conn::blocked_conversations(m) {
            if s.inbound
                .send(crate::Inbound::ConversationSync {
                    conversation,
                    state: Some(state),
                    lost_since,
                })
                .await
                .is_err()
            {
                return End::Shutdown;
            }
        }
    }

    let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<String>();
    // 첨부 작업(묶음 15): 작업이 보낼 프레임·relay 응답 대기표·작업 손잡이(연결이 끝나면 멈춘다).
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<String>();
    let waiters = Arc::new(crate::files::Waiters::default());
    let mut tasks = crate::files::Tasks::default();
    let files_ctx = crate::files::Ctx {
        store: s.store.clone(),
        keys: s.config.keys.clone(),
        rng: s.rng.clone(),
        target: target.clone(),
        dir: s
            .config
            .files_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("lodelai-client-blobs")),
        frames: frame_tx,
        waiters: waiters.clone(),
        inbound: s.inbound.clone(),
        avatar_retry: (s.config.avatar_retry_first, s.config.avatar_retry_max),
        avatar_slow_notice: s.config.avatar_slow_notice,
        avatar_fails: Arc::default(),
        avatar_waiting_shown: Arc::default(),
    };
    // §5c: 큰 group Handshake 를 blob 으로 올리는 작업(맨 앞 `mls_blob` 행)·blob 칸 받기 작업·올리기 실패 횟수.
    let mut mls_up: Option<(i64, tokio::task::JoinHandle<bool>)> = None;
    let mut blob_get: Option<(BlobJob, tokio::task::JoinHandle<Option<Value>>)> = None;
    let mut blob_fails: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
    // 응답을 기다리는 send: (seq, msg_id)
    let mut inflight: Option<Inflight> = None;
    let mut waiting: VecDeque<Waiting> = VecDeque::new();
    let mut directory_requested = true;
    // 기기 폐기 요청과, `device.revoke` 를 이미 보냈는지.
    let mut revoke: Option<(bool, oneshot::Sender<crate::Result<()>>)> = None;
    let mut revoke_sent = false;
    // 보낸 대상 지정 폐기(대상 device_id, 응답 받을 곳). 연결이 끊기면 버려져 요청자는 `Unreachable`.
    // 보낸 시각도 둔다 — 요청자가 포기했거나(시간 초과) 서버가 답하지 않으면 큐를 계속 멈추지 않게 비운다.
    let mut other: Option<(Control, oneshot::Sender<ControlAnswer>, Instant)> = None;
    let my_device = s.config.keys.device_id().as_str().to_owned();
    // #490 ⑦(28 §4): 기기 이름. 첫 디렉터리에서 한 번 견주고(`name_checked`), 보낼 것(`name_due`)은 관리 요청이 없을 때
    // 보낸다. 보낸 뒤(`name_sent`)엔 그 답을 받거나 NAME_WAIT 이 지날 때까지 관리 요청을 꺼내지 않는다(계약 8cd7072c).
    let mut name_checked = false;
    let mut name_due: Option<String> = None;
    let mut name_sent: Option<(String, Instant)> = None;
    // 기기 등록 요청 하나와, `device.register` 를 이미 보냈는지.
    let mut register: Option<RegisterRequest> = None;
    let mut register_sent = false;
    let mut pace = tokio::time::interval(s.config.send_interval);
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ping = tokio::time::interval(s.config.ping_interval);
    ping.tick().await; // 첫 틱은 즉시 — 버린다
    let mut sweep = tokio::time::interval(Duration::from_millis(250));
    let mut last_rx = tokio::time::Instant::now();
    // 내 ping 뒤 이때까지 아무 프레임도 안 오면 끊는다. 무엇이든 받으면 지운다.
    let mut pong_due: Option<tokio::time::Instant> = None;
    // 이 연결에서 시도한 첨부 받기: (시도 수, 다음에 다시 받아도 되는 때). 일시 실패는 행이 남으므로 그때 다시 받는다
    // (30초·2분·10분 물러섬, 계약 617858e4) — 받은 요청은 첨부가 다 끝나야 세션에 들어가므로 다음 연결까지 미루지 않는다.
    let mut tried: std::collections::HashMap<(String, u32), (u32, Instant)> =
        std::collections::HashMap::new();

    // 끊긴 사이 쌓인 입력 중 표시는 이미 낡았다(#613 — 받는 쪽은 6초면 끈다) — 버린다.
    while s.typing.try_recv().is_ok() {}
    loop {
        tokio::select! {
            _ = sd.changed() => {
                let _ = ws.close(None).await;
                return End::Shutdown;
            }
            frame = recv_json_or_end(&mut ws) => {
                let Some(frame) = frame else { return End::AfterReady };
                last_rx = tokio::time::Instant::now();
                pong_due = None;
                // 첨부 요청의 답(ref 있는 error 포함) — 연결을 끊는 rate_limited 처리보다 먼저.
                if waiters.answer(&frame) {
                    continue;
                }
                let t = frame.get("t").and_then(Value::as_str);
                // 첫 묶음이 처리됐다(뒤에 보낸 요청의 답) — 또는 relay 가 이미 상한만큼 가졌다(표시 전에 꺼져 다시 올린 경우). 어느
                // 쪽이든 다음 접속부터 다시 올리지 않는다.
                let kp_full = t == Some("error")
                    && frame.get("code").and_then(Value::as_str) == Some("protocol")
                    && frame.get("message").and_then(Value::as_str) == Some("key_packages.publish 상한");
                if kp_unconfirmed && (t == Some("directory") || kp_full) {
                    kp_unconfirmed = false;
                    if let Some(m) = s.mls.as_deref() {
                        crate::mls_conn::mark_published(m, s.clock.now().0);
                    }
                }
                if kp_full {
                    continue;
                }
                if let Some(m) = s.mls.as_deref() {
                    match boot_frame(s, &mut ws, m, &mut boot, t, &frame).await {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return e,
                    }
                }
                // 입력 중 표시(#613) — 저장하지 않고 그대로 코어에.
                if t == Some("typing") {
                    match serde_json::from_value::<lodelai_protocol::generated::ws::TypingNotice>(frame.clone()) {
                        Ok(n) => {
                            let i = Inbound::Typing {
                                from: n.from.to_string(),
                                group: n.group.map(|g| g.to_string()),
                                on: n.on,
                            };
                            if s.inbound.send(i).await.is_err() {
                                return End::Shutdown;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "typing 꼴 틀림 — 버림"),
                    }
                    continue;
                }
                if t == Some("group_alert") {
                    match serde_json::from_value::<lodelai_protocol::generated::ws::GroupAlert>(
                        frame.clone(),
                    ) {
                        Ok(a) => {
                            if s.inbound.send(Inbound::GroupAlert(a)).await.is_err() {
                                return End::Shutdown;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "group_alert 꼴 틀림 — 버림"),
                    }
                    continue;
                }
                if matches!(t, Some("commit_final" | "commit_void")) {
                    if let Some(m) = s.mls.as_deref() {
                        if let Err(e) = group_result(s, m, &frame).await {
                            return e;
                        }
                    }
                    continue;
                }
                if t == Some("rejoin_needed") {
                    if let Some(m) = s.mls.as_deref() {
                        for g in frame.get("groups").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                            note_rejoin_lost(s, m, g);
                            enqueue_rejoin(s, m, g);
                        }
                    }
                    continue;
                }
                if t == Some("duty") {
                    if let Some(m) = s.mls.as_deref() {
                        take_duty(s, m, &frame);
                    }
                    continue;
                }
                if t == Some("key_packages.low") {
                    if let Some(f) = s.mls.as_deref().and_then(|m| crate::mls_conn::refill(m, &frame, s.config.key_package_target)) {
                        if !send_text(&mut ws, f).await {
                            return End::AfterReady;
                        }
                    }
                    continue;
                }
                let target = frame.get("device_id").and_then(Value::as_str).filter(|d| *d != my_device);
                if t == Some("device.revoked") && target.is_some() {
                    // 다른 기기 끊기의 응답 — 이 연결은 그대로.
                    if other.as_ref().is_some_and(|(c, _, _)| matches!(c, Control::RevokeDevice { device_id: want, .. } if Some(want.as_str()) == target)) {
                        if let Some((_, r, _)) = other.take() {
                            let _ = r.send(ControlAnswer::Done);
                        }
                    }
                    continue;
                }
                // 메일 확인 끊기(#577 §4): 걸기·취소의 답, 이 기기가 대상이면 막기 카드 재료.
                if matches!(t, Some("device.recover_scheduled" | "device.recover_canceled")) {
                    let want = if t == Some("device.recover_scheduled") { Control::Recover } else { Control::RecoverCancel };
                    if other.as_ref().is_some_and(|(c, _, _)| *c == want) {
                        if let Some((_, r, _)) = other.take() {
                            let _ = r.send(ControlAnswer::Done);
                        }
                    }
                    continue;
                }
                if t == Some("device.recover_against") {
                    let g = |k: &str| frame.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
                    let requester = frame
                        .pointer("/requester/device_id")
                        .or_else(|| frame.get("requester"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let _ = s.inbound.send(crate::Inbound::RecoverAgainst { at: g("at"), requester }).await;
                    continue;
                }
                if t == Some("device.recover_against_ended") {
                    if other.as_ref().is_some_and(|(c, _, _)| *c == Control::RecoverBlock) {
                        if let Some((_, r, _)) = other.take() {
                            let _ = r.send(ControlAnswer::Done);
                        }
                    }
                    let reason = frame.get("reason").and_then(Value::as_str).unwrap_or_default().to_owned();
                    let _ = s.inbound.send(crate::Inbound::RecoverAgainstEnded { reason }).await;
                    continue;
                }
                if t == Some("error")
                    && frame.get("code").and_then(Value::as_str) == Some("recover_refused")
                {
                    if other.as_ref().is_some_and(|(c, _, _)| matches!(c, Control::Recover | Control::RecoverCancel | Control::RecoverBlock)) {
                        if let Some((_, r, _)) = other.take() {
                            let g = |k: &str| frame.get(k).and_then(Value::as_str).map(str::to_owned);
                            let _ = r.send(ControlAnswer::RecoverRefused { reason: g("reason").unwrap_or_default(), until: g("until") });
                        }
                    }
                    continue;
                }
                if t == Some("server.status") {
                    if other.as_ref().is_some_and(|(c, _, _)| matches!(c, Control::ServerStatus)) {
                        if let Some((_, r, _)) = other.take() {
                            let _ = r.send(ControlAnswer::Status(Box::new(frame)));
                        }
                    }
                    continue;
                }
                if t == Some("invite.created") {
                    if other.as_ref().is_some_and(|(c, _, _)| matches!(c, Control::InviteCreate(_))) {
                        if let Some((_, r, _)) = other.take() {
                            let g = |k: &str| frame.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
                            let _ = r.send(ControlAnswer::Invite { token: g("token"), expires_at: g("expires_at") });
                        }
                    }
                    continue;
                }
                // #490 ⑦: 첫 디렉터리에서 내 이름과 견주고, 보낸 이름의 답(내 기기에 그 이름이 실린 디렉터리)을 받는다.
                if matches!(t, Some("directory" | "directory.update")) {
                    if !name_checked && t == Some("directory") {
                        name_checked = true;
                        name_due = wanted_name(s, name_ok, &frame, &my_device);
                    }
                    if name_sent.as_ref().is_some_and(|(n, _)| my_device_name(&frame, &my_device).as_deref() == Some(n.as_str())) {
                        name_sent = None;
                    }
                }
                // 보낸 이름을 relay 가 받지 않았다(형식·시간당 상한) — 이 답은 여기서 끝낸다. 연결을 끊는 rate_limited 로 가지 않게.
                if name_sent.is_some()
                    && t == Some("error")
                    && frame.get("ref").is_none()
                    && matches!(frame.get("code").and_then(Value::as_str), Some("protocol" | "rate_limited"))
                {
                    tracing::info!(code = ?frame.get("code"), "기기 이름을 relay 가 받지 않았다");
                    name_sent = None;
                    continue;
                }
                // 관리자 동작(조직·팀)은 성공 응답이 따로 없다 — 큐를 멈춘 동안 온 다음 디렉터리가 그 결과다.
                if matches!(t, Some("directory" | "directory.update"))
                    && other.as_ref().is_some_and(|(c, _, _)| {
                        matches!(
                            c,
                            Control::OrgRename(_)
                                | Control::TeamCreate(_)
                                | Control::TeamRename { .. }
                                | Control::TeamDelete(_)
                                | Control::SetAdmin { .. }
                                | Control::MemberRemove(_)
                                | Control::MemberRevokeDevice { .. }
                        )
                    })
                {
                    if let Some((_, r, _)) = other.take() {
                        let _ = r.send(ControlAnswer::Done);
                    }
                }
                if t == Some("error") && frame.get("ref").is_none() {
                    let code = frame.get("code").and_then(Value::as_str);
                    // 자기 폐기가 마지막 관리자의 마지막 기기라 거절됐다(묶음 5) — 연결은 그대로.
                    if code == Some("last_admin") && revoke_sent && other.is_none() {
                        if let Some((_, r)) = revoke.take() {
                            let _ = r.send(Err(crate::Error::LastAdmin));
                        }
                        revoke_sent = false;
                        continue;
                    }
                    let answer = match code {
                        Some("too_early") => Some(ControlAnswer::TooEarly),
                        Some("protocol") => Some(ControlAnswer::Refused),
                        Some("name_taken") => Some(ControlAnswer::NameTaken),
                        Some("last_admin") => Some(ControlAnswer::LastAdmin),
                        Some("device_unconfirmed") => Some(ControlAnswer::DeviceUnconfirmed),
                        Some("rate_limited")
                            if other.as_ref().is_some_and(|(c, _, _)| matches!(c, Control::InviteCreate(_))) =>
                        {
                            Some(ControlAnswer::RateLimited)
                        }
                        _ => None,
                    };
                    if let Some(a) = answer {
                        if let Some((_, r, _)) = other.take() {
                            let rate = a == ControlAnswer::RateLimited;
                            let _ = r.send(a);
                            // 초대 발급 상한은 이 요청만의 거절이다 — 연결을 끊는 rate_limited 로 처리하지 않는다.
                            if rate {
                                continue;
                            }
                        }
                    }
                }
                if t == Some("device.revoked") {
                    if let Some((_, r)) = revoke.take() {
                        let _ = r.send(Ok(()));
                    } else {
                        // 요청하지 않은 폐기 — 관리자가 끊었거나 내 다른 기기에서 조직을 나갔다(묶음 5). 로컬 지움으로.
                        let _ = s.inbound.send(crate::Inbound::RemovedFromAccount { by: removed_by(&frame), at: removed_at(&frame) }).await;
                    }
                    tracing::info!("기기 폐기됨 — 다시 접속하지 않는다");
                    let _ = ws.close(None).await;
                    return End::Revoked;
                }
                if register_sent {
                    if let Some(answer) = register_answer(&frame) {
                        if let Some((_, tx)) = register.take() {
                            let _ = tx.send(answer);
                        }
                        register_sent = false;
                        continue;
                    }
                }
                match handle_frame(s, &mut ws, frame, &mut inflight, &mut waiting, &mut directory_requested, &ack_tx).await {
                    Ok(()) => {}
                    Err(end) => return end,
                }
                let out: Vec<String> = s.out_frames.lock().map(|mut v| std::mem::take(&mut *v)).unwrap_or_default();
                for f in out {
                    if !send_text(&mut ws, f).await {
                        return End::AfterReady;
                    }
                }
            }
            Some(f) = frame_rx.recv() => {
                if !send_text(&mut ws, f).await {
                    return End::AfterReady;
                }
            }
            Some(id) = ack_rx.recv() => {
                if !send_text(&mut ws, json!({"t": "delivered_ack", "msg_id": id}).to_string()).await {
                    return End::AfterReady;
                }
                // 남겨 둔 MLS 평문은 ack 를 보낸 뒤 지운다. 7일(배달 보관)보다 오래된 것도 같이.
                if let Some(m) = s.mls.as_deref() {
                    use openmls_traits::OpenMlsProvider as _;
                    let old = s.clock.now().0 - 7 * 86_400_000;
                    if let Err(e) = m.provider.storage().drop_opened(&id, Some(old)) {
                        tracing::warn!(error = %e, "연 평문 지우기 실패");
                    }
                    m.provider.scrub();
                }
            }
            Some((c, r)) = s.control.recv(), if other.is_none() && name_sent.is_none() => {
                // 요청자가 이미 포기했으면 보내지 않는다. 큐를 기다리지 않는다(연결이 살아 있으면 바로).
                if !r.is_closed() {
                    if !send_text(&mut ws, c.frame().to_string()).await {
                        return End::AfterReady;
                    }
                    other = Some((c, r, Instant::now()));
                }
            }
            Some(f) = s.typing.recv() => {
                if !send_text(&mut ws, f.to_string()).await {
                    return End::AfterReady;
                }
            }
            Some(f) = s.avatar_get.recv() => {
                if !f.done.is_closed() {
                    tasks.avatar_gets.push(tokio::spawn(crate::files::avatar_fetch(files_ctx.clone(), f)));
                }
            }
            Some(r) = s.register.recv(), if register.is_none() => {
                if !r.1.is_closed() {
                    register = Some(r);
                }
            }
            Some(r) = s.revoke.recv(), if revoke.is_none() => {
                // 요청자가 이미 포기했으면(시간 초과) 보내지 않는다.
                if !r.1.is_closed() {
                    revoke = Some(r);
                }
            }
            _ = pace.tick() => {
                // #537: 보낸 send 에 답이 없다(잃은 응답·ref 없는 오류) — 연결이 살아 있어도 큐가 영원히 멈추지 않게.
                if let Some(f) = inflight.as_ref().filter(|f| f.sent.elapsed() >= s.config.send_ack_wait) {
                    tracing::warn!(msg_id = f.msg_id, "send inflight timeout — 다시 접속해 다시 보낸다");
                    let _ = ws.close(None).await;
                    return End::Unanswered;
                }
                // 대상 지정 폐기를 기다리는 동안은 큐를 멈춘다 — 응답이 ref 없는 error 로 오는 다른 프레임과 섞이지 않게(#339).
                tasks.reap();
                // §5c: 큰 Handshake 올리기가 끝났다 — 실패면 쥔 Commit 을 버리고 다시 봉인(세 번이면 그 행을 실패로).
                if mls_up.as_ref().is_some_and(|(_, h)| h.is_finished()) {
                    if let (Some((bseq, h)), Some(m)) = (mls_up.take(), s.mls.as_deref()) {
                        if !h.await.unwrap_or(false) {
                            if let Err(e) = blob_up_failed(s, m, bseq, &mut blob_fails).await {
                                return e;
                            }
                        }
                    }
                }
                // §5c: blob 칸을 받아 채웠다 — 평소 길로(받지 못했으면 버리고, group Commit 이면 commit_fail).
                if blob_get.as_ref().is_some_and(|(_, h)| h.is_finished()) {
                    if let Some((job, h)) = blob_get.take() {
                        let filled = h.await.ok().flatten();
                        let r = match (job, filled, s.mls.as_deref()) {
                            (BlobJob::Deliver { held, group_seq, .. }, Some(f), _) => {
                                deliver(s, &ack_tx, f, held, group_seq).await
                            }
                            (BlobJob::Deliver { message, .. }, None, _) => {
                                blob_get_failed(&mut ws, &ack_tx, &message).await
                            }
                            (BlobJob::GroupInfo { seq, .. }, Some(f), Some(m)) => {
                                rejoin_with(s, &mut ws, m, &mut boot, seq, &f).await
                            }
                            (BlobJob::GroupInfo { seq, .. }, _, _) => {
                                let _ = s.store.remove(seq);
                                boot = None;
                                Ok(())
                            }
                        };
                        if let Err(e) = r {
                            return e;
                        }
                    }
                }
                if blob_get.is_none() {
                    if let Some(job) = s.blob_jobs.lock().ok().and_then(|mut j| j.pop_front()) {
                        let (v, root) = match &job {
                            BlobJob::Deliver { message, .. } => (message.clone(), "/body"),
                            BlobJob::GroupInfo { frame, .. } => (frame.clone(), ""),
                        };
                        let h = tokio::spawn(crate::mls_blob::fill(files_ctx.clone(), v, root));
                        blob_get = Some((job, h));
                    }
                }
                if let Ok(Some(i)) = s.store.peek() {
                    if i.kind == "mls_blob" {
                        if mls_up.is_none() {
                            let h = tokio::spawn(crate::mls_blob::upload(files_ctx.clone(), i.seq, s.config.mls_inline_max));
                            mls_up = Some((i.seq, h));
                        }
                        continue;
                    }
                }
                // 큐 맨 앞이 첨부 올리기면 그것을 먼저(순서 유지) — 다 올리면 같은 행이 send 로 바뀐다.
                // 프로필 사진(묶음 15 §2)도 같다 — 올리는 동안은 아무것도 보내지 않는다(뒤의 지우기가 PUT 보다 먼저 가지 않게).
                let head = match s.store.peek() {
                    Ok(Some(i)) if matches!(i.kind.as_str(), "upload" | "avatar" | "org_avatar") => {
                        Some((i.seq, i.kind != "upload", i.kind == "org_avatar"))
                    }
                    _ => None,
                };
                if tasks.avatar_put.is_some() {
                    // 사진 PUT 이 끝날 때까지 큐를 멈춘다.
                } else if let Some((seq, true, org)) = head {
                    tasks.avatar_put = Some(tokio::spawn(crate::files::avatar_upload(files_ctx.clone(), seq, org)));
                } else if let Some((seq, false, _)) = head {
                    if tasks.upload.is_none() {
                        let h = tokio::spawn(crate::files::upload(files_ctx.clone(), seq));
                        tasks.upload = Some((seq, h));
                    }
                } else if inflight.is_none() && other.is_none() {
                    if s.unheld.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        tracing::info!("받지 않기를 풂 — 다시 접속해 그동안 받지 않은 글을 받는다");
                        return End::AfterReady;
                    }
                    if let Some(m) = s.mls.as_deref() {
                        if let Err(e) = rejoin_asked(s, m).await {
                            return e;
                        }
                        due_duties(s, m);
                        if due_updates(s, m) {
                            match redrive_stalled(s, m).await {
                                Ok(false) => {}
                                // 풀렸다 — 멈춘 동안 ack 하지 않은 Handshake 를 relay 에서 다시 받는다.
                                Ok(true) => return End::AfterReady,
                                Err(e) => return e,
                            }
                        }
                    }
                    match mls_head(s, &mut ws, &mut boot).await {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(()) => return End::AfterReady,
                    }
                    match flush_one(s, &mut ws).await {
                        Ok(Some(f)) => inflight = Some(f),
                        Ok(None) => {
                            // 큐가 비었으면(앞서 넣은 것이 다 나갔다) 그때 폐기를 보낸다. flush_one 은 응답 없는 프레임을
                            // 보낸 뒤에도 None 이라 큐 길이를 따로 본다.
                            if !revoke_sent
                                && revoke.as_ref().is_some_and(|r| !r.1.is_closed())
                                && s.store.len().is_ok_and(|n| n == 0)
                            {
                                let leave = revoke.as_ref().is_some_and(|r| r.0);
                                // 자기 폐기는 이 기기 자신이 서명한 증명을 싣는다(§12-11 ⓐ — 옛 뿌리 자신의 증명 길). 나가기는
                                // 내 기기 전부라 증명 없음.
                                let frame = if leave {
                                    json!({"t": "member.leave"})
                                } else {
                                    let me = s.config.keys.device_id();
                                    json!({"t": "device.revoke", "proof": crate::keys::revoke_proof(
                                        &s.config.keys,
                                        &s.config.server_name,
                                        me.as_str(),
                                        s.clock.now(),
                                    )})
                                };
                                if !send_text(&mut ws, frame.to_string()).await {
                                    return End::AfterReady;
                                }
                                revoke_sent = true;
                            }
                            if !register_sent
                                && register.as_ref().is_some_and(|r| !r.1.is_closed())
                                && s.store.len().is_ok_and(|n| n == 0)
                            {
                                let code = register.as_ref().map(|r| r.0.clone()).unwrap_or_default();
                                if !send_text(&mut ws, json!({"t": "device.register", "code": code}).to_string()).await {
                                    return End::AfterReady;
                                }
                                register_sent = true;
                            }
                        }
                        Err(()) => return End::AfterReady,
                    }
                }
            }
            () = s.wake.notified() => {
                // 큐가 생겼다 — 다음 pace 틱에 보낸다(간격 유지).
            }
            _ = ping.tick() => {
                if last_rx.elapsed() >= s.config.idle_timeout {
                    tracing::info!("서버 응답 없음 — 다시 접속");
                    let _ = ws.close(None).await;
                    return End::AfterReady;
                }
                if !send_text(&mut ws, json!({"t": "ping"}).to_string()).await {
                    return End::AfterReady;
                }
                pong_due.get_or_insert_with(|| tokio::time::Instant::now() + s.config.pong_timeout);
            }
            _ = sweep.tick() => {
                if pong_due.is_some_and(|d| tokio::time::Instant::now() >= d) {
                    tracing::info!("ping 에 답 없음 — 다시 접속");
                    let _ = ws.close(None).await;
                    return End::AfterReady;
                }
                if other
                    .as_ref()
                    .is_some_and(|(_, r, at)| r.is_closed() || at.elapsed() >= CONTROL_WAIT)
                {
                    // 결과를 모른다 — 요청자는 Unreachable(보낸 쪽이 닫혔거나, 여기서 버려 닫힘), 다음 디렉터리가 알려 준다.
                    other = None;
                }
                if name_sent.as_ref().is_some_and(|(_, at)| at.elapsed() >= NAME_WAIT) {
                    name_sent = None;
                }
                // #490 ⑦: 관리 요청·기기 등록·폐기가 없을 때만 보낸다 — 그들의 ref 없는 답과 섞이지 않게.
                if other.is_none() && name_sent.is_none() && revoke.is_none() && register.is_none() {
                    if let Some(n) = name_due.take() {
                        if !send_text(&mut ws, json!({"t": "device.name", "name": n}).to_string()).await {
                            return End::AfterReady;
                        }
                        name_sent = Some((n, Instant::now()));
                    }
                }
                // 받을 첨부(동시 DOWNLOADS_AT_ONCE 개).
                tasks.reap();
                if tasks.downloads.len() < crate::files::DOWNLOADS_AT_ONCE {
                    if let Ok(all) = s.store.downloads() {
                        for d in all {
                            if tasks.downloads.len() >= crate::files::DOWNLOADS_AT_ONCE {
                                break;
                            }
                            let key = (d.msg_id.clone(), d.idx);
                            let now = Instant::now();
                            if tasks.downloads.iter().any(|(k, _)| *k == key)
                                || tried.get(&key).is_some_and(|(_, at)| now < *at)
                            {
                                continue;
                            }
                            let n = tried.get(&key).map_or(0, |(n, _)| *n) + 1;
                            tried.insert(key.clone(), (n, now + crate::files::download_backoff(n)));
                            let h = tokio::spawn(crate::files::download(files_ctx.clone(), d));
                            tasks.downloads.push((key, h));
                        }
                    }
                }
                // 디렉터리를 기다려도 모르는 기기면 거부.
                while let Some(w) = waiting.front() {
                    if w.since.elapsed() < s.config.unknown_device_wait {
                        break;
                    }
                    let w = waiting.pop_front().expect("front 있음");
                    if reject(s, &ack_tx, w.message, RejectReason::BadSignature).await.is_err() {
                        return End::Shutdown;
                    }
                }
            }
        }
    }
}

/// `device.register` 를 보낸 뒤 그 답인 프레임이면 결과. `error` 는 ref 없는 `handle_taken`·`protocol` 만 답으로 본다.
fn register_answer(frame: &Value) -> Option<crate::Result<DeviceRegistered>> {
    let str_of = |k: &str| frame.get(k).and_then(Value::as_str);
    match str_of("t")? {
        "device.registered" => Some(Ok(DeviceRegistered {
            user: str_of("user")?.to_owned(),
            device_id: str_of("device_id")?.to_owned(),
        })),
        "error" if str_of("ref").is_none() => match str_of("code")? {
            "handle_taken" => Some(Err(Error::HandleTaken)),
            "protocol" => Some(Err(Error::Relay("protocol".into()))),
            _ => None,
        },
        _ => None,
    }
}

async fn recv_json_or_end(ws: &mut Ws) -> Option<Value> {
    recv_json(ws).await
}

/// 큐 맨 앞을 하나 보낸다. `send` 면 응답을 기다릴 (seq, msg_id) 를 돌려준다.
fn now_secs(s: &Shared) -> u64 {
    u64::try_from(s.clock.now().0 / 1000).unwrap_or(0)
}

/// 지금 디렉터리의 잎 자격 보기.
fn dir_view(s: &Shared) -> crate::keys::DirView {
    let d = s.directory.read().map(|d| d.clone()).unwrap_or(Value::Null);
    crate::keys::DirView::new(&d, &s.config.server_name).with_former(&s.store)
}

/// 큐 맨 앞 send 행의 MLS 그룹 준비 단계(묶음 22 §7 '처음 보내기'). 한 번에 하나 — 그 행이 나가야 다음 행.
enum Boot {
    /// `key_packages.claim` 을 보냈다. `add_only` 면 그룹은 있고(시작은 됨) Add 만 남았다.
    Claiming {
        seq: i64,
        since: Instant,
        add_only: bool,
        /// 빈 답으로 다시 가져온 횟수(물러섬 길이).
        tries: u32,
    },
    /// `start` 를 보냈다 — ack 면 Add Commit.
    Starting {
        seq: i64,
        msg_id: String,
        gid: Vec<u8>,
        kps: Vec<openmls::prelude::KeyPackage>,
    },
    /// Add Commit 을 보냈다 — ack 면 merge.
    Committing {
        seq: i64,
        msg_id: String,
        gid: Vec<u8>,
    },
    /// group 변경 행(만들기·add)의 KeyPackage 를 가져오는 중.
    GClaiming {
        seq: i64,
        since: Instant,
        tries: u32,
    },
    /// group 만들기 `start` 를 보냈다 — ack 면 처음 멤버를 넣는 create Commit(§12-22).
    GStarting {
        seq: i64,
        msg_id: String,
        gid: String,
        kps: Vec<openmls::prelude::KeyPackage>,
    },
    /// 상대가 먼저 시작했다(`epoch_taken`) — Welcome 을 기다린다. external commit 으로 들어가는 길은 조각 h.
    Welcome { seq: i64, until: Instant },
    /// `group_info.get` 을 보냈다 — 답이 오면 external commit 으로 다시 들어간다(§5a·§5b).
    Rejoin { seq: i64, since: Instant },
    /// 실패 — 이때까지 다시 하지 않는다(claim 하루 상한을 아끼려고). `tries` 는 빈 KeyPackage 답 횟수.
    Backoff {
        seq: i64,
        until: Instant,
        tries: u32,
    },
}

impl Boot {
    fn seq(&self) -> i64 {
        match self {
            Self::Claiming { seq, .. }
            | Self::GClaiming { seq, .. }
            | Self::GStarting { seq, .. }
            | Self::Starting { seq, .. }
            | Self::Committing { seq, .. }
            | Self::Welcome { seq, .. }
            | Self::Rejoin { seq, .. }
            | Self::Backoff { seq, .. } => *seq,
        }
    }
    fn msg_id(&self) -> Option<&str> {
        match self {
            Self::Starting { msg_id, .. }
            | Self::Committing { msg_id, .. }
            | Self::GStarting { msg_id, .. } => Some(msg_id),
            _ => None,
        }
    }
}

const BOOT_BACKOFF: Duration = Duration::from_secs(60);
/// 다시 들어가기를 만들지 못했을 때 첫 기다림([`rejoin_with`] — 두 배씩 [`BOOT_BACKOFF`] 까지).
const REJOIN_RETRY_FIRST: Duration = Duration::from_secs(2);
const CLAIM_WAIT: Duration = Duration::from_secs(30);
const WELCOME_WAIT: Duration = Duration::from_secs(60);

/// Handshake 머리(보내는 나 → 그 행의 받는 주소).
fn boot_head<'a>(s: &'a Shared, to: &'a str, msg_id: &'a str) -> crate::mls_conn::Head<'a> {
    crate::mls_conn::Head {
        keys: &s.config.keys,
        from: s.me_address.as_str(),
        to,
        msg_id,
        now: s.clock.now(),
    }
}

/// 그 행의 평문과 받는 **사람** 주소(Handshake 는 사람 단위 — 세션 slug 를 뗀다, relay §6).
fn head_plain(s: &Shared, seq: i64) -> Option<(Value, String)> {
    let Ok(Some(Some(p))) = s.store.plain_of(seq) else {
        return None;
    };
    let v: Value = serde_json::from_str(&p).ok()?;
    let to = v.pointer("/to/address")?.as_str()?;
    let person = to.split_once('/').map_or(to, |(p, _)| p).to_owned();
    Some((v, person))
}

fn new_msg_id(s: &Shared) -> Option<String> {
    use lodelai_effects::IdGen as _;
    lodelai_effects::UlidGen::new(s.clock.clone(), s.rng.clone())
        .try_next_ulid()
        .ok()
}

/// 큐 맨 앞이 MLS 로 봉인할 send 행이면 그룹을 준비해 봉인한다. `true` 면 flush_one 이 그대로 보낸다, `false` 면 이번엔 보내지 않음.
async fn mls_head(s: &Shared, ws: &mut Ws, boot: &mut Option<Boot>) -> Result<bool, ()> {
    let Some(m) = s.mls.as_deref() else {
        return Ok(true);
    };
    let Ok(Some(item)) = s.store.peek() else {
        return Ok(true);
    };
    // 빈 frame = 아직 봉인 안 함, box = 옛 행(§7 다시 봉인).
    if item.kind != "send" || !(item.frame.is_empty() || item.frame.contains(r#""enc":"box""#)) {
        return Ok(true);
    }
    if boot.as_ref().is_some_and(|b| b.seq() != item.seq) {
        *boot = None;
    }
    // 물러서 있던 다시 들기 행에 그 그룹의 다시 들기 신호가 왔다 — 기다리지 않고 지금(#599 ②).
    if matches!(boot, Some(Boot::Backoff { .. })) {
        if let Some(gid) = rejoin_row_gid(s, item.seq) {
            if s.rejoin_now.lock().is_ok_and(|mut n| n.remove(&gid)) {
                *boot = None;
            }
        }
    }
    if s.row_wait.lock().is_ok_and(|w| {
        w.get(&item.seq)
            .is_some_and(|(_, until)| Instant::now() < *until)
    }) {
        return Ok(false);
    }
    // 잎 자격은 디렉터리로 본다 — 첫 디렉터리 전엔 준비하지 않는다(받을 기기가 없다고 잘못 실패시키지 않게).
    if s.directory.read().map_or(true, |d| d.is_null()) {
        return Ok(false);
    }
    let Some((plain, to)) = head_plain(s, item.seq) else {
        return Ok(true);
    };
    // pair·self 의 기기 단위 일(duty·주기 Update — 이 크레이트가 넣은 행).
    if plain.get("kind").and_then(Value::as_str) == Some(TASK_KIND) {
        return task_head(s, ws, m, boot, &item, &plain).await;
    }
    // 그룹(묶음 16·22 h): 응용 메시지·만들기·add.
    if crate::is_group_message(&plain) {
        return group_head(s, ws, m, boot, &item, &plain).await;
    }
    let to_user = to.split('@').next().unwrap_or_default().to_owned();
    let c = crate::mls_conn::conv(&s.config.user, &to_user);
    let group = crate::mls_conn::load(m, &c.gid);
    // 시작은 됐는데 Add 가 안 된 pair(Commit 이 거절됐거나 아직 확정 전) — Add 만 다시. 내 기기 그룹(self)도 잎이 나 하나인데
    // 들일 내 다른 기기가 있으면 같다(#490 — 그대로 봉인하면 받을 잎 없이 나가 내 다른 맥의 세션 앞 요청이 사라진다).
    let add_only = group.as_ref().is_some_and(|g| {
        g.members().count() < 2
            && match c.kind {
                crate::mls::Kind::Pair => true,
                crate::mls::Kind::SelfDevices => !crate::mls_conn::claim_targets(
                    &dir_view(s),
                    &c,
                    s.config.keys.device_id().as_str(),
                )
                .is_empty(),
                crate::mls::Kind::Group => false,
            }
    });
    if let (Some(mut g), false) = (group, add_only) {
        *boot = None;
        match crate::mls_conn::seal_app(m, &s.config.keys, &mut g, &plain) {
            Ok(frame) => {
                if let Err(e) = s.store.reseal(item.seq, &frame) {
                    tracing::warn!(error = %e, "봉인 저장 실패");
                    return Ok(false);
                }
                count_sent(s, m, &c.gid);
                return Ok(true);
            }
            // 프레임 상한을 넘는다 — 다시 해도 같다(#315). 그 행을 실패로.
            Err(crate::mls::Error::Rejected("frame_too_large")) => {
                let msg_id = item.msg_id.clone().unwrap_or_default();
                let _ = s.store.remove(item.seq);
                let _ = s
                    .inbound
                    .send(Inbound::Nack {
                        msg_id,
                        reason: "too_large".into(),
                    })
                    .await;
                return Ok(false);
            }
            Err(e) => {
                tracing::warn!(error = %e, "MLS 봉인 실패 — 잠시 뒤 다시");
                *boot = Some(Boot::Backoff {
                    seq: item.seq,
                    until: Instant::now() + BOOT_BACKOFF,
                    tries: 0,
                });
                return Ok(false);
            }
        }
    }
    match boot {
        Some(Boot::Backoff { until, .. } | Boot::Welcome { until, .. })
            if Instant::now() < *until =>
        {
            return Ok(false)
        }
        Some(Boot::Claiming { since, .. }) if since.elapsed() < CLAIM_WAIT => return Ok(false),
        Some(Boot::Starting { .. } | Boot::Committing { .. }) => return Ok(false),
        _ => {}
    }
    let targets =
        crate::mls_conn::claim_targets(&dir_view(s), &c, s.config.keys.device_id().as_str());
    if targets.is_empty() {
        if c.kind == crate::mls::Kind::Pair {
            // 상대에게 잎 자격 있는 기기가 없다(모르는 사람 포함) — relay 의 unroutable 과 같은 실패로 알린다.
            tracing::warn!("받을 기기가 없다 — 실패 처리");
            let msg_id = item.msg_id.clone().unwrap_or_default();
            let _ = s.store.remove(item.seq);
            let _ = s
                .inbound
                .send(Inbound::Nack {
                    msg_id,
                    reason: "unroutable".into(),
                })
                .await;
            return Ok(false);
        }
        // 내 기기가 이것 하나 — 혼자 시작.
        return start_boot(s, ws, m, boot, item.seq, &to, Vec::new())
            .await
            .map(|()| false);
    }
    if !send_text(
        ws,
        json!({"t": "key_packages.claim", "device_ids": targets}).to_string(),
    )
    .await
    {
        return Err(());
    }
    let tries = match boot {
        Some(Boot::Backoff { tries, .. }) => *tries,
        _ => 0,
    };
    *boot = Some(Boot::Claiming {
        seq: item.seq,
        since: Instant::now(),
        add_only,
        tries,
    });
    Ok(false)
}

/// 시작(epoch 0)을 보낸다.
async fn start_boot(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    seq: i64,
    to: &str,
    kps: Vec<openmls::prelude::KeyPackage>,
) -> Result<(), ()> {
    let to_user = to.split('@').next().unwrap_or_default();
    let c = crate::mls_conn::conv(&s.config.user, to_user);
    let backoff = Boot::Backoff {
        seq,
        until: Instant::now() + BOOT_BACKOFF,
        tries: 0,
    };
    let Some(msg_id) = new_msg_id(s) else {
        *boot = Some(backoff);
        return Ok(());
    };
    let Some((_, frame)) = crate::mls_conn::start(m, &boot_head(s, to, &msg_id), &c) else {
        tracing::warn!("MLS 그룹 시작 실패");
        *boot = Some(backoff);
        return Ok(());
    };
    if !send_text(ws, frame).await {
        return Err(());
    }
    *boot = Some(Boot::Starting {
        seq,
        msg_id,
        gid: c.gid,
        kps,
    });
    Ok(())
}

/// Add Commit 을 보낸다(시작 뒤, 또는 Add 만 다시).
async fn commit_boot(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    seq: i64,
    gid: Vec<u8>,
    kps: &[openmls::prelude::KeyPackage],
) -> Result<(), ()> {
    let backoff = Boot::Backoff {
        seq,
        until: Instant::now() + BOOT_BACKOFF,
        tries: 0,
    };
    let to = head_plain(s, seq).map(|(_, to)| to);
    let (Some(to), Some(mut g), Some(msg_id)) = (to, crate::mls_conn::load(m, &gid), new_msg_id(s))
    else {
        *boot = Some(backoff);
        return Ok(());
    };
    let Some(frame) = crate::mls_conn::add_commit(m, &boot_head(s, &to, &msg_id), &mut g, kps)
    else {
        tracing::warn!("MLS Add Commit 실패");
        *boot = Some(backoff);
        return Ok(());
    };
    if !send_text(ws, frame).await {
        return Err(());
    }
    *boot = Some(Boot::Committing { seq, msg_id, gid });
    Ok(())
}

/// 그룹 준비에 걸린 프레임이면 처리하고 `true`(연결 루프는 다음 프레임으로).
async fn boot_frame(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    t: Option<&str>,
    frame: &Value,
) -> Result<bool, End> {
    let Some(b) = boot.as_ref() else {
        return Ok(false);
    };
    let seq = b.seq();
    let backoff = |d: Duration| {
        Some(Boot::Backoff {
            seq,
            until: Instant::now() + d,
            tries: 0,
        })
    };
    match (t, b) {
        // 다시 들어가기(§5a): 받은 GroupInfo 로 external commit.
        (Some("group_info"), Boot::Rejoin { .. }) => {
            *boot = None;
            rejoin_with(s, ws, m, boot, seq, frame).await?;
            Ok(true)
        }
        // group 만들기·add(묶음 22 h1): 가져온 KeyPackage 로 — 만들기면 start 먼저, 아니면 바로 Commit.
        (Some("key_packages"), Boot::GClaiming { tries, .. }) => {
            let tries = *tries;
            let Some((plain, _)) = head_plain(s, seq) else {
                *boot = None;
                return Ok(true);
            };
            let gid = crate::group_io::group_context(&plain).unwrap_or_default();
            let create = plain.get("group_op").and_then(Value::as_str) == Some("create");
            // 넣을 사람(만들기 = 처음 멤버, add = 그 사람). 내 다른 기기는 고르는 것이라 빼고 본다.
            let need: Vec<String> = if create {
                plain
                    .get("subjects")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(user_part)
                    .collect()
            } else {
                plain
                    .get("subject")
                    .and_then(Value::as_str)
                    .map(user_part)
                    .into_iter()
                    .collect()
            };
            let need: Vec<String> = need.into_iter().filter(|u| *u != s.config.user).collect();
            let (kps, covered, no_device) = {
                let dir = dir_view(s);
                // 디렉터리에 기기가 하나도 없는 사람(조직에서 빠짐 등)은 기다려도 들 수 없다.
                let no_device = {
                    use crate::mls_rules::Directory as _;
                    need.iter().any(|u| dir.devices(u).is_empty())
                };
                let c = crate::mls_conn::group_conv(&dir, &gid);
                let ctx = crate::mls_rules::RuleCtx {
                    dir: &dir,
                    members: &c.members,
                    expect_sender: None,
                    keep_as: None,
                    group: None,
                };
                let kps = crate::mls_conn::key_packages(frame, &ctx);
                let covered = crate::mls_conn::kps_cover(&dir, &kps, &need);
                (kps, covered, no_device)
            };
            // #605: 한 사람 몫이라도 없으면(아직 올리지 않았거나 디렉터리가 늦어 뺌) 빈 답처럼 물러섰다 다시 가져온다 — 그대로
            // 봉인하면 relay 가 invalid_commit 으로 거절하고, 같은 KeyPackage 로 다시 해도 같아 만들기가 실패(internal)했다.
            // 기다려도 안 될 때(기기 없는 사람은 두 번 뒤·상한)는 실패로 보인다 — '그룹에 넣을 기기가 없다'와 같은 unroutable.
            let wait = kp_wait(!kps.is_empty() && covered, no_device, tries);
            if wait == KpWait::Fail {
                tracing::warn!(
                    tries,
                    no_device,
                    "넣을 사람의 KeyPackage 가 끝내 없다 — 실패 처리"
                );
                *boot = None;
                let msg_id = plain
                    .get("msg_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let _ = s.store.remove(seq);
                if let Ok(mut k) = s.row_kps.lock() {
                    k.remove(&seq);
                }
                if create {
                    crate::mls_conn::drop_group(m, gid.as_bytes());
                }
                emit(
                    s,
                    Inbound::Nack {
                        msg_id,
                        reason: "unroutable".into(),
                    },
                )
                .await?;
                return Ok(true);
            }
            if wait == KpWait::Again {
                let d =
                    Duration::from_secs(2u64.saturating_mul(1 << tries.min(5))).min(BOOT_BACKOFF);
                *boot = Some(Boot::Backoff {
                    seq,
                    until: Instant::now() + d,
                    tries: tries + 1,
                });
                return Ok(true);
            }
            if create && crate::mls_conn::load(m, gid.as_bytes()).is_none() {
                let Some(msg_id) = new_msg_id(s) else {
                    *boot = backoff(BOOT_BACKOFF);
                    return Ok(true);
                };
                let to = plain
                    .pointer("/to/address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let Some(f) = crate::mls_conn::group_start(m, &boot_head(s, &to, &msg_id), &gid)
                else {
                    *boot = backoff(BOOT_BACKOFF);
                    return Ok(true);
                };
                // 처음 이름은 이 기기에 두고, 멤버에게는 create 확정 뒤 rename 으로(§12-23).
                if let Some(name) = plain
                    .pointer("/body/text")
                    .and_then(Value::as_str)
                    .and_then(|t| serde_json::from_str::<Value>(t).ok())
                    .and_then(|b| b.get("name").and_then(Value::as_str).map(str::to_owned))
                {
                    let _ = openmls_traits::OpenMlsProvider::storage(&m.provider).set_group_meta(
                        gid.as_bytes(),
                        Some(&name),
                        None,
                        None,
                    );
                }
                if !send_text(ws, f).await {
                    return Err(End::AfterReady);
                }
                *boot = Some(Boot::GStarting {
                    seq,
                    msg_id,
                    gid,
                    kps,
                });
            } else {
                *boot = if seal_group_commit(s, m, seq, &kps) {
                    None
                } else {
                    backoff(BOOT_BACKOFF)
                };
            }
            Ok(true)
        }
        (
            Some("key_packages"),
            Boot::Claiming {
                add_only, tries, ..
            },
        ) => {
            let add_only = *add_only;
            let tries = *tries;
            let kps = {
                let to = head_plain(s, seq).map(|(_, to)| to).unwrap_or_default();
                let c =
                    crate::mls_conn::conv(&s.config.user, to.split('@').next().unwrap_or_default());
                let dir = dir_view(s);
                let ctx = crate::mls_rules::RuleCtx {
                    dir: &dir,
                    members: &c.members,
                    expect_sender: None,
                    keep_as: None,
                    group: None,
                };
                crate::mls_conn::key_packages(frame, &ctx)
            };
            if kps.is_empty() {
                // 상대가 아직 한 번도 접속하지 않아 올린 것이 없을 수 있다(등록하면 디렉터리엔 바로 나온다) — 짧게 시작해 늘린다
                // (2·4·8…60초, (요청자, 대상) 하루 claim 상한 안).
                let d =
                    Duration::from_secs(2u64.saturating_mul(1 << tries.min(5))).min(BOOT_BACKOFF);
                tracing::info!(
                    tries,
                    "가져온 KeyPackage 가 없다 — {}초 뒤 다시",
                    d.as_secs()
                );
                *boot = Some(Boot::Backoff {
                    seq,
                    until: Instant::now() + d,
                    tries: tries + 1,
                });
                return Ok(true);
            }
            let r = if add_only {
                let to = head_plain(s, seq).map(|(_, to)| to).unwrap_or_default();
                let c =
                    crate::mls_conn::conv(&s.config.user, to.split('@').next().unwrap_or_default());
                commit_boot(s, ws, m, boot, seq, c.gid, &kps).await
            } else {
                let to = head_plain(s, seq).map(|(_, to)| to).unwrap_or_default();
                start_boot(s, ws, m, boot, seq, &to, kps).await
            };
            r.map_err(|()| End::AfterReady)?;
            Ok(true)
        }
        // claim 의 rate_limited 는 ref 가 없다(§12-1) — 연결을 끊는 처리로 가지 않게.
        (Some("error"), Boot::Claiming { .. } | Boot::GClaiming { .. })
            if frame.get("ref").is_none()
                && frame.get("code").and_then(Value::as_str) == Some("rate_limited") =>
        {
            *boot = backoff(Duration::from_secs(600));
            Ok(true)
        }
        (Some("ack" | "nack"), _) if frame.get("msg_id").and_then(Value::as_str) == b.msg_id() => {
            let ok = t == Some("ack");
            let reason = frame
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match boot.take() {
                // group start 가 받아들여졌다 — 처음 멤버를 넣는 create Commit 을 행에(§12-22).
                Some(Boot::GStarting { gid, kps, .. }) => {
                    if ok {
                        if !seal_group_commit(s, m, seq, &kps) {
                            *boot = backoff(BOOT_BACKOFF);
                        }
                    } else if reason == "unroutable" {
                        // 그룹을 끈 relay(22 §12-30 (a)) — 다시 해도 같다. 행을 실패로 빼고 이 연결은 groups=false.
                        tracing::warn!(
                            "그룹 시작 unroutable — 그룹을 끈 relay 로 보고 만들기 실패"
                        );
                        crate::mls_conn::drop_group(m, gid.as_bytes());
                        groups_off(s).await;
                        if let Ok(Some(item)) = s.store.peek() {
                            if item.seq == seq {
                                fail_row(s, &item, "unroutable").await;
                            }
                        }
                    } else {
                        tracing::warn!(reason, "그룹 시작 거절");
                        crate::mls_conn::drop_group(m, gid.as_bytes());
                        *boot = backoff(BOOT_BACKOFF);
                    }
                }
                Some(Boot::Starting { gid, kps, .. }) => {
                    if !ok {
                        // 그 사이 상대 Welcome 으로 들어갔으면(잎 둘 이상) 그 그룹은 둔다.
                        if crate::mls_conn::load(m, &gid).is_some_and(|g| g.members().count() == 1)
                        {
                            crate::mls_conn::drop_group(m, &gid);
                        }
                        *boot = if reason == "epoch_taken" {
                            Some(Boot::Welcome {
                                seq,
                                until: Instant::now() + WELCOME_WAIT,
                            })
                        } else {
                            tracing::warn!(reason, "MLS 시작 거절");
                            backoff(BOOT_BACKOFF)
                        };
                    } else if !kps.is_empty() {
                        commit_boot(s, ws, m, boot, seq, gid, &kps)
                            .await
                            .map_err(|()| End::AfterReady)?;
                    }
                }
                Some(Boot::Committing { gid, .. }) => {
                    let task = head_plain(s, seq)
                        .filter(|(p, _)| p.get("kind").and_then(Value::as_str) == Some(TASK_KIND))
                        .map(|(p, _)| {
                            p.get("task")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        });
                    let update = task.as_deref() == Some("self_update");
                    let rejoin = task.as_deref() == Some("rejoin");
                    let task = task.is_some();
                    if rejoin {
                        // external commit 은 보낼 때 이미 merge 했다 — 거절이면 그 상태를 버린다.
                        if ok {
                            let _ = s.store.remove(seq);
                            on_rejoined(s, m, &gid).await?;
                        } else {
                            tracing::warn!(reason, "external commit 거절");
                            crate::mls_conn::drop_group(m, &gid);
                            if reason == "stale_epoch" {
                                *boot = backoff(Duration::from_secs(2));
                            } else {
                                let _ = s.store.remove(seq);
                            }
                        }
                    } else if ok {
                        if !crate::mls_conn::merge(m, &gid) {
                            tracing::warn!("MLS Commit merge 실패");
                        } else if update {
                            let _ = m
                                .provider
                                .storage()
                                .update_reset(&gid, Some(s.clock.now().0));
                        }
                        // 기기 단위 일은 이것으로 끝.
                        if task {
                            let _ = s.store.remove(seq);
                        }
                    } else {
                        tracing::warn!(reason, "MLS Commit 거절");
                        crate::mls_conn::clear_pending(m, &gid);
                        if task && reason != "stale_epoch" {
                            // 다시 해도 같다 — 일은 relay 가 다음 접속 때 다시 준다.
                            let _ = s.store.remove(seq);
                        } else {
                            *boot = backoff(BOOT_BACKOFF);
                        }
                    }
                }
                other => *boot = other,
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// 이 relay 는 그룹을 쓰지 않는다(헤더로 몰랐는데 그룹 시작이 `unroutable`, 22 §12-30) — 다음 연결의 헤더까지 `false`.
/// 코어에 먼저 알린다(이어 오는 만들기 실패 nack 의 화면 문구가 이것을 본다).
async fn groups_off(s: &Shared) {
    if let Ok(mut g) = s.groups.lock() {
        *g = Some(false);
    }
    let _ = s.inbound.send(Inbound::GroupsOff).await;
}

/// 큐 맨 앞 행을 실패로 빼고 코어에 nack 으로 알린다.
async fn fail_row(s: &Shared, item: &outbox::Item, reason: &str) {
    let msg_id = item.msg_id.clone().unwrap_or_default();
    let _ = s.store.remove(item.seq);
    let _ = s
        .inbound
        .send(Inbound::Nack {
            msg_id,
            reason: reason.into(),
        })
        .await;
}

/// 사람 주소의 서버.
fn server_of(a: &str) -> &str {
    a.split_once('@').map_or("", |(_, x)| x)
}

/// 사람 주소의 아이디.
fn user_part(a: &str) -> String {
    a.split('@').next().unwrap_or_default().to_owned()
}

/// group 대화의 큐 맨 앞(묶음 22 h1): 응용 메시지는 그 그룹으로 봉인, 만들기·add 는 KeyPackage 를 가져와 Commit 으로. 같은 그룹의
/// 내 Commit 이 확정을 기다리면 다음 Commit 은 기다린다(relay 가 pending 중엔 stale_epoch, §12-21).
async fn group_head(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    item: &outbox::Item,
    plain: &Value,
) -> Result<bool, ()> {
    let Some(gid) = crate::group_io::group_context(plain) else {
        fail_row(s, item, "unroutable").await;
        return Ok(false);
    };
    let op = (plain.get("kind").and_then(Value::as_str) == Some("group"))
        .then(|| plain.get("group_op").and_then(Value::as_str))
        .flatten()
        .map(str::to_owned);
    let group = crate::mls_conn::load(m, gid.as_bytes());
    match op.as_deref() {
        None => {
            let Some(mut g) = group else {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            };
            match crate::mls_conn::seal_app(m, &s.config.keys, &mut g, plain) {
                Ok(frame) => {
                    count_sent(s, m, gid.as_bytes());
                    Ok(s.store.reseal(item.seq, &frame).is_ok())
                }
                Err(crate::mls::Error::Rejected("frame_too_large")) => {
                    fail_row(s, item, "too_large").await;
                    Ok(false)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "MLS 그룹 봉인 실패 — 잠시 뒤 다시");
                    *boot = Some(Boot::Backoff {
                        seq: item.seq,
                        until: Instant::now() + BOOT_BACKOFF,
                        tries: 0,
                    });
                    Ok(false)
                }
            }
        }
        Some(op @ ("create" | "add")) => {
            if group.as_ref().is_some_and(|g| g.pending_commit().is_some()) {
                return Ok(false);
            }
            if op == "add" && group.is_none() {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            }
            // 그룹을 끈 relay(22 §12-30) — 시작 프레임을 보내지 않고 만들기 실패.
            if op == "create" && group.is_none() && s.groups.lock().is_ok_and(|g| *g == Some(false))
            {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            }
            match boot {
                Some(Boot::Backoff { until, .. }) if Instant::now() < *until => return Ok(false),
                Some(Boot::GClaiming { since, .. }) if since.elapsed() < CLAIM_WAIT => {
                    return Ok(false)
                }
                Some(Boot::GStarting { .. }) => return Ok(false),
                _ => {}
            }
            if group.is_some() && reseal_with_kps(s, m, item.seq) {
                return Ok(true);
            }
            let dir = dir_view(s);
            let my_device = s.config.keys.device_id().as_str().to_owned();
            let mut users: Vec<String> = if op == "create" {
                plain
                    .get("subjects")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(user_part)
                    .collect()
            } else {
                plain
                    .get("subject")
                    .and_then(Value::as_str)
                    .map(user_part)
                    .into_iter()
                    .collect()
            };
            if op == "create" {
                users.push(s.config.user.clone());
            }
            let targets = crate::mls_conn::claim_users(&dir, &users, &my_device);
            if targets.is_empty() {
                tracing::warn!(op, "그룹에 넣을 기기가 없다 — 실패 처리");
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            }
            if !send_text(
                ws,
                json!({"t": "key_packages.claim", "device_ids": targets}).to_string(),
            )
            .await
            {
                return Err(());
            }
            let tries = match boot {
                Some(Boot::Backoff { tries, .. }) => *tries,
                _ => 0,
            };
            *boot = Some(Boot::GClaiming {
                seq: item.seq,
                since: Instant::now(),
                tries,
            });
            Ok(false)
        }
        Some(op)
            if matches!(op, "remove" | "admin" | "org_left")
                || (op == "leave"
                    && plain
                        .get("subject")
                        .and_then(Value::as_str)
                        .is_some_and(|x| x != s.me_address)) =>
        {
            let Some(g) = group else {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            };
            if g.pending_commit().is_some() {
                return Ok(false);
            }
            if matches!(boot, Some(Boot::Backoff { until, .. }) if Instant::now() < *until) {
                return Ok(false);
            }
            let Some(subject) = plain.get("subject").and_then(Value::as_str).map(user_part) else {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            };
            if requeued_change_check(s, m, item, &gid, op, plain).await {
                return Ok(false);
            }
            let change = if op == "admin" {
                // 16 의 admin 은 그 사람의 관리자 표시를 뒤집는다.
                let a = format!("{subject}@{}", server_of(&s.me_address));
                let dir = dir_view(s);
                let users = { dir.users() };
                let mut admins = crate::mls::effective_admins(&g, server_of(&s.me_address), |d| {
                    use crate::mls_rules::Directory as _;
                    users
                        .iter()
                        .find(|u| dir.devices(u).iter().any(|x| x.device_id == d))
                        .cloned()
                        .or_else(|| dir.former_user(d))
                });
                if let Some(i) = admins.iter().position(|x| *x == a) {
                    admins.remove(i);
                } else {
                    admins.push(a);
                }
                crate::mls_conn::Change::Admins(admins)
            } else {
                crate::mls_conn::Change::Remove(crate::mls_conn::leaves_of(
                    &dir_view(s),
                    &s.store,
                    &g,
                    &subject,
                ))
            };
            if seal_group_change(s, m, item.seq, &change) {
                Ok(true)
            } else {
                tracing::warn!(op, "그룹 Commit 을 만들 수 없음 — 실패 처리");
                fail_row(s, item, "unroutable").await;
                Ok(false)
            }
        }
        // 사람 op 가 아닌 Commit(§12-15): 새 기기 Add·폐기 기기 Remove·주기 Update. 이미 된 일이면 조용히 뺀다.
        Some("update") => {
            let rejoin = plain
                .pointer("/body/text")
                .and_then(Value::as_str)
                .and_then(|t| serde_json::from_str::<Value>(t).ok())
                .is_some_and(|a| a.get("task").and_then(Value::as_str) == Some("rejoin"));
            if rejoin {
                match boot {
                    Some(Boot::Backoff { until, .. }) if Instant::now() < *until => {
                        return Ok(false)
                    }
                    Some(Boot::Rejoin { since, .. }) if since.elapsed() < CLAIM_WAIT => {
                        return Ok(false)
                    }
                    _ => {}
                }
                return ask_group_info(ws, boot, item.seq, &gid).await;
            }
            let Some(g) = group else {
                let _ = s.store.remove(item.seq);
                return Ok(false);
            };
            if g.pending_commit().is_some() {
                return Ok(false);
            }
            let tries = match boot {
                Some(Boot::Backoff { until, .. }) if Instant::now() < *until => return Ok(false),
                Some(Boot::GClaiming { since, .. }) if since.elapsed() < CLAIM_WAIT => {
                    return Ok(false)
                }
                Some(Boot::Backoff { tries, .. }) => *tries,
                _ => 0,
            };
            let asked: Value = plain
                .pointer("/body/text")
                .and_then(Value::as_str)
                .and_then(|t| serde_json::from_str(t).ok())
                .unwrap_or_default();
            let device = asked.get("device").and_then(Value::as_str);
            let change = match asked.get("task").and_then(Value::as_str) {
                Some("add_device") => {
                    let Some(d) = device.filter(|d| crate::mls_conn::leaf_of(&g, d).is_none())
                    else {
                        let _ = s.store.remove(item.seq);
                        return Ok(false);
                    };
                    if reseal_with_kps(s, m, item.seq) {
                        return Ok(true);
                    }
                    if tries > TASK_TRIES {
                        tracing::warn!("새 기기 KeyPackage 가 없다 — 그만둠");
                        let _ = s.store.remove(item.seq);
                        *boot = None;
                        return Ok(false);
                    }
                    if !send_text(
                        ws,
                        json!({"t": "key_packages.claim", "device_ids": [d]}).to_string(),
                    )
                    .await
                    {
                        return Err(());
                    }
                    *boot = Some(Boot::GClaiming {
                        seq: item.seq,
                        since: Instant::now(),
                        tries,
                    });
                    return Ok(false);
                }
                Some("remove_device") => {
                    match device.and_then(|d| crate::mls_conn::leaf_of(&g, d)) {
                        Some(i) => crate::mls_conn::Change::Remove(vec![i]),
                        None => {
                            let _ = s.store.remove(item.seq);
                            return Ok(false);
                        }
                    }
                }
                Some("self_update") => crate::mls_conn::Change::Update,
                _ => {
                    let _ = s.store.remove(item.seq);
                    return Ok(false);
                }
            };
            let self_update = matches!(change, crate::mls_conn::Change::Update);
            if seal_group_change(s, m, item.seq, &change) {
                if self_update {
                    let hash = s
                        .store
                        .peek()
                        .ok()
                        .flatten()
                        .and_then(|i| crate::mls_conn::frame_commit_hash(&i.frame));
                    if let (Some(h), Ok(mut u)) = (hash, s.self_updates.lock()) {
                        u.insert(h);
                    }
                }
                Ok(true)
            } else {
                tracing::warn!("update Commit 을 만들 수 없음 — 그만둠");
                let _ = s.store.remove(item.seq);
                Ok(false)
            }
        }
        Some("rename") => {
            let Some(mut g) = group else {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            };
            match crate::mls_conn::seal_app(m, &s.config.keys, &mut g, plain) {
                Ok(frame) => Ok(s.store.reseal(item.seq, &frame).is_ok()),
                Err(e) => {
                    tracing::warn!(error = %e, "이름 바꾸기 봉인 실패 — 실패 처리");
                    fail_row(s, item, "internal").await;
                    Ok(false)
                }
            }
        }
        Some("leave") => {
            // 나가는 사람은 자기 잎을 자기 Commit 으로 못 뺀다 — wire app 으로 알리면 relay 가 표에서 빼고 남은 기기에
            // remove_user duty 를 준다(§12-13 ②).
            let Some(mut g) = group else {
                fail_row(s, item, "unroutable").await;
                return Ok(false);
            };
            let mut msg = plain.clone();
            msg["subject"] = Value::String(s.me_address.clone());
            match crate::mls_conn::seal_app(m, &s.config.keys, &mut g, &msg) {
                Ok(frame) => Ok(s.store.reseal(item.seq, &frame).is_ok()),
                Err(e) => {
                    tracing::warn!(error = %e, "나가기 봉인 실패 — 실패 처리");
                    fail_row(s, item, "internal").await;
                    Ok(false)
                }
            }
        }
        Some(other) => {
            tracing::warn!(op = other, "아직 MLS 로 못 하는 그룹 변경 — 실패 처리");
            fail_row(s, item, "internal").await;
            Ok(false)
        }
    }
}

/// group 변경 행을 KeyPackage 로 Commit 으로 봉인해 행에 둔다(다음 틱에 flush_one 이 보냄). 헤더를 확정 때 쓰려고 남긴다.
fn seal_group_commit(s: &Shared, m: &Mls, seq: i64, kps: &[openmls::prelude::KeyPackage]) -> bool {
    if let Ok(mut k) = s.row_kps.lock() {
        k.insert(seq, kps.to_vec());
    }
    seal_group_change(s, m, seq, &crate::mls_conn::Change::Add(kps))
}

/// 이 행이 앞서 가져온 KeyPackage 로 다시 봉인했으면 `true`(그룹이 이미 있을 때만 — 만들기의 start 는 다시 하지 않는다).
fn reseal_with_kps(s: &Shared, m: &Mls, seq: i64) -> bool {
    let kps = s.row_kps.lock().ok().and_then(|k| k.get(&seq).cloned());
    kps.is_some_and(|kps| seal_group_change(s, m, seq, &crate::mls_conn::Change::Add(&kps)))
}

/// group 변경 행을 그 [`crate::mls_conn::Change`] 의 Commit 으로 봉인해 행에 둔다(다음 틱에 flush_one 이 보냄). 헤더를 확정 때 쓰려고 남긴다.
fn seal_group_change(s: &Shared, m: &Mls, seq: i64, change: &crate::mls_conn::Change<'_>) -> bool {
    let Some((plain, _)) = head_plain(s, seq) else {
        return false;
    };
    let Some(gid) = crate::group_io::group_context(&plain) else {
        return false;
    };
    let Some(mut g) = crate::mls_conn::load(m, gid.as_bytes()) else {
        return false;
    };
    let op = plain
        .get("group_op")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut msg = plain.clone();
    if op == "create" {
        // §12-22: start 뒤 첫 Commit — subjects, base_seq 1.
        msg["base_seq"] = json!(1);
    }
    let epoch = g.epoch().as_u64();
    let Some(frame) = crate::mls_conn::group_commit(m, &s.config.keys, &mut g, &msg, change) else {
        tracing::warn!(op, "그룹 Commit 만들기 실패");
        return false;
    };
    if matches!(op.as_str(), "create" | "add" | "remove" | "admin") {
        let asked = plain
            .pointer("/body/text")
            .and_then(Value::as_str)
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .unwrap_or(Value::Null);
        let tries = asked
            .get("tries")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        let orig = asked
            .get("orig")
            .and_then(Value::as_str)
            .or_else(|| plain.get("msg_id").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned();
        if let Ok(mut t) = s.commit_tries.lock() {
            t.insert((gid.clone(), epoch), (tries, orig));
        }
    }
    if let Some(hash) = crate::mls_conn::frame_commit_hash(&frame) {
        // create 는 처음 멤버(subjects)를 줄바꿈으로 이어 남긴다 — 무효면 같은 create 를 다시 낸다.
        let subjects = plain.get("subjects").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        });
        let subject = plain
            .get("subject")
            .and_then(Value::as_str)
            .or(subjects.as_deref());
        let _ = crate::mls_conn::put_commit_meta(
            m,
            gid.as_bytes(),
            epoch,
            &hash,
            &op,
            &s.me_address,
            subject,
        );
    }
    // 사람 op 면 변경 줄 키를 이 epoch 에 남기고 화면에 '기다림'(§12-27 ⓒ). 키는 처음 보낸 msg_id — 다시 봉인한 행(orig)도 같다.
    // 이 함수는 동기라 try_send — 채널이 차서 빠져도 코어는 처음 보낼 때 이미 기다림으로 그렸다.
    if op != "update" {
        let change_id = plain
            .pointer("/body/text")
            .and_then(Value::as_str)
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .and_then(|a| a.get("orig").and_then(Value::as_str).map(str::to_owned))
            .or_else(|| {
                plain
                    .get("msg_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        if let Some(change_id) = change_id {
            let _ = m
                .provider
                .storage()
                .put_change(gid.as_bytes(), epoch, &change_id);
            if let (true, Some(x)) = (
                matches!(op.as_str(), "remove" | "admin"),
                plain.get("subject").and_then(Value::as_str),
            ) {
                if let Ok(mut l) = s.latest_change.lock() {
                    l.insert((gid.clone(), op.clone(), x.to_owned()), change_id.clone());
                }
            }
            let _ = s.inbound.try_send(Inbound::GroupChangePending {
                change_id,
                pending: crate::ChangePending::Waiting,
                seq: None,
            });
        }
    }
    seal_or_blob(s, seq, &frame)
}

/// 큰 Handshake 올리기 실패(§5c): 쥔 Commit 을 버리고(external commit 이면 그룹 상태도) 행을 빈 send 로 — 다음 틱에 다시
/// 봉인한다. 같은 행이 세 번 실패하면 그 행을 실패로.
async fn blob_up_failed(
    s: &Shared,
    m: &Mls,
    seq: i64,
    fails: &mut std::collections::HashMap<i64, u32>,
) -> Result<(), End> {
    let n = fails.entry(seq).or_insert(0);
    *n += 1;
    let plain = head_plain(s, seq).map(|(p, _)| p);
    if let Some(gid) = plain.as_ref().and_then(crate::group_io::group_context) {
        if rejoin_row_gid(s, seq).is_some() {
            if let Ok(mut r) = s.rejoining.lock() {
                r.remove(&gid);
            }
            crate::mls_conn::drop_group(m, gid.as_bytes());
        } else {
            crate::mls_conn::clear_pending(m, gid.as_bytes());
        }
    }
    if *n < 3 {
        tracing::info!(seq, "Handshake blob 올리기 실패 — 다시 봉인");
        let _ = s.store.promote_mls_blob(seq, "");
        return Ok(());
    }
    fails.remove(&seq);
    tracing::warn!(seq, "Handshake blob 올리기 세 번 실패 — 그 행을 실패로");
    let _ = s.store.remove(seq);
    let msg_id = plain
        .as_ref()
        .and_then(|p| p.get("msg_id").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();
    emit(
        s,
        Inbound::Nack {
            msg_id,
            reason: "internal".into(),
        },
    )
    .await
}

/// blob 칸을 받지 못했다(§5c — 없음·해시 어긋남): 받았다고 하고 버린다. group Commit 이면 처리하지 못한 것이니 commit_fail.
async fn blob_get_failed(
    ws: &mut Ws,
    ack_tx: &mpsc::UnboundedSender<String>,
    message: &Value,
) -> Result<(), End> {
    if message.pointer("/body/wire").and_then(Value::as_str) == Some("commit") {
        if let (Some(gid), Some(epoch), Some(hash)) = (
            crate::group_io::group_context(message),
            message.get("epoch").and_then(Value::as_u64),
            message
                .pointer("/body/payload/blob/sha256")
                .and_then(Value::as_str),
        ) {
            let f = json!({"t": "commit_fail", "group": gid, "epoch": epoch, "commit_hash": hash});
            if !send_text(ws, f.to_string()).await {
                return Err(End::AfterReady);
            }
        }
    }
    if let Some(id) = message.get("msg_id").and_then(Value::as_str) {
        let _ = ack_tx.send(id.to_owned());
    }
    Ok(())
}

/// 봉인한 group Handshake 프레임을 행에 둔다 — 메시지가 상한을 넘으면 blob 으로 올릴 행(`mls_blob`)으로(§5c).
fn seal_or_blob(s: &Shared, seq: i64, frame: &str) -> bool {
    match crate::mls_blob::unsigned_if_oversize(frame, s.config.mls_inline_max) {
        Some(m) => s.store.demote_to_mls_blob(seq, &m).unwrap_or(false),
        None => s.store.reseal(seq, frame).is_ok(),
    }
}

/// 그 행이 group `create` 의 Commit(start 는 끝나 그룹이 있음)이면 gid.
fn create_row_gid(s: &Shared, seq: i64) -> Option<String> {
    let plain: Value =
        serde_json::from_str(&s.store.plain_of(seq).ok().flatten().flatten()?).ok()?;
    if plain.get("kind").and_then(Value::as_str) != Some("group")
        || plain.get("group_op").and_then(Value::as_str) != Some("create")
    {
        return None;
    }
    let gid = crate::group_io::group_context(&plain)?;
    let m = s.mls.as_deref()?;
    crate::mls_conn::load(m, gid.as_bytes()).map(|_| gid)
}

/// 거절된 행이 group Commit(app 으로 가는 rename·내 leave 말고)이면 그 그룹의 pending Commit 과 확정용 헤더를 버린다.
fn clear_own_commit(s: &Shared, m: &Mls, seq: i64) {
    let Some(plain) = s
        .store
        .plain_of(seq)
        .ok()
        .flatten()
        .flatten()
        .and_then(|p| serde_json::from_str::<Value>(&p).ok())
    else {
        return;
    };
    if plain.get("kind").and_then(Value::as_str) != Some("group") {
        return;
    }
    let op = plain
        .get("group_op")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // 내 leave(app)는 subject 없이 큐에 들어온다(봉인 때 붙임) — 없음 또는 나.
    let mine = plain
        .get("subject")
        .and_then(Value::as_str)
        .is_none_or(|x| x == s.me_address);
    if op == "rename" || (op == "leave" && mine) {
        return;
    }
    if let Some(gid) = crate::group_io::group_context(&plain) {
        if crate::mls_conn::load(m, gid.as_bytes()).is_some_and(|g| g.pending_commit().is_some()) {
            crate::mls_conn::clear_pending(m, gid.as_bytes());
        }
    }
}

/// duty 줄 한 칸(§7 — rank k 는 k × 2분 뒤, rank 15 이상은 30분).
const DUTY_STEP: Duration = Duration::from_secs(120);
/// 기기 단위 일 행이 빈 KeyPackage 답으로 물러서는 최대 횟수(2·4…64초) — 넘으면 그만둔다(relay 가 다음 접속 때 다시 준다).
const TASK_TRIES: u32 = 6;
/// 가져온 KeyPackage 로 무엇을 할지(#605).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KpWait {
    /// 넣을 사람 모두의 몫이 있다 — 봉인.
    Go,
    /// 아직 없다 — 물러섰다 다시 가져온다.
    Again,
    /// 기다려도 안 된다(기기 없는 사람·상한) — 실패로 보인다.
    Fail,
}

/// `all` = 넣을 사람 모두의 KeyPackage 가 왔다, `no_device` = 디렉터리 기기가 없는 사람이 있다, `tries` = 앞서 물러선 횟수.
fn kp_wait(all: bool, no_device: bool, tries: u32) -> KpWait {
    if all {
        KpWait::Go
    } else if (no_device && tries >= NO_DEVICE_TRIES) || tries + 1 >= GROUP_KP_TRIES {
        KpWait::Fail
    } else {
        KpWait::Again
    }
}

/// 그룹 만들기·add 가 넣을 사람 모두의 KeyPackage 를 기다리는 횟수(#605 — 물러섬 2·4·8·16·32·60·60초, 약 3분). 넘으면
/// 실패로 보인다(조용히 '만드는 중'에 남지 않게).
const GROUP_KP_TRIES: u32 = 8;
/// 디렉터리에 기기가 없는 사람이 있어도 처음 이만큼은 기다린다(#605 리뷰 🟡 — 디렉터리가 늦게 오는 것과 갈라, 약 6초).
const NO_DEVICE_TRIES: u32 = 2;
/// pair·self 의 기기 단위 일 행의 `kind`(이 크레이트 안에서만 — 보내지 않는다).
const TASK_KIND: &str = "mls_task";

/// relay 의 `duty`(§7·§12-13 ②). rank 0 은 바로, k 는 k × 2분 뒤에도 아직 할 일이면.
fn take_duty(s: &Shared, m: &Mls, frame: &Value) {
    let rank = frame.get("rank").and_then(Value::as_u64).unwrap_or(0);
    if rank == 0 {
        run_duty(s, m, frame);
        return;
    }
    let key = |f: &Value| {
        ["group", "task", "subject"].map(|k| f.get(k).and_then(Value::as_str).map(str::to_owned))
    };
    if let Ok(mut w) = s.duty_wait.lock() {
        if !w.iter().any(|(_, f)| key(f) == key(frame)) {
            let wait = DUTY_STEP * u32::try_from(rank.min(15)).unwrap_or(15);
            w.push((Instant::now() + wait, frame.clone()));
        }
    }
}

/// 때가 된 rank k>0 duty 를 한다.
fn due_duties(s: &Shared, m: &Mls) {
    let now = Instant::now();
    let due: Vec<Value> = match s.duty_wait.lock() {
        Ok(mut w) => {
            let (due, keep): (Vec<_>, Vec<_>) = w.drain(..).partition(|(at, _)| *at <= now);
            *w = keep;
            due.into_iter().map(|(_, f)| f).collect()
        }
        Err(_) => return,
    };
    for f in &due {
        run_duty(s, m, f);
    }
}

/// '다시 받기'로 부탁받은 그룹마다(§9): 멈춤·다시 볼 행을 걷고 `syncing` 으로 막아 둔 채(다시 들어가기 전 epoch 로 보내지 않게)
/// external commit 으로 다시 들어간다. 들어가면 [`on_rejoined`] 가 `ok` 로.
async fn rejoin_asked(s: &Shared, m: &Mls) -> Result<(), End> {
    let asks: Vec<String> = s
        .rejoin_asks
        .lock()
        .map(|mut a| std::mem::take(&mut *a))
        .unwrap_or_default();
    for header in asks {
        let Some(gid) = crate::mls_conn::gid_of_header(&header) else {
            continue;
        };
        let st = m.provider.storage();
        let _ = st.drop_stalled(&gid);
        let _ = st.clear_state(&gid);
        let _ = st.set_state(
            &gid,
            crate::mls_store::GroupState::Syncing,
            "rejoin",
            s.clock.now().0,
        );
        if let Ok(Some(conversation)) = st.conv(&gid) {
            emit(
                s,
                Inbound::ConversationSync {
                    conversation,
                    state: Some(crate::mls_store::GroupState::Syncing),
                    lost_since: st.lost(&gid).ok().flatten(),
                },
            )
            .await?;
        }
        enqueue_rejoin(s, m, &header);
    }
    Ok(())
}

/// 다시 들어갔다(external commit 이 받아들여짐) — 막혀 있었으면 풀고 코어에 `ok`(멈춘 동안 버린 글의 때와 함께) 뒤 다시 접속해
/// 막힌 동안 ack 하지 않은 Handshake 를 relay 에서 다시 받는다(`Err(AfterReady)`).
/// 든 뒤(Welcome·external) 트리에 남은 폐기 잎을 duty 를 기다리지 않고 스스로 뺀다(#577 설계 결정 — 들 때 그 잎을 통과로
/// 봤으니 내가 빼기 경쟁에 낀다). group 만. 이미 빠졌거나 다른 멤버가 먼저 빼면 행이 저절로 빠진다(run_duty·Commit 만들 때 잎 없음).
fn remove_revoked_leaves(s: &Shared, m: &Mls, gid: &str) {
    let Some(g) = crate::mls_conn::load(m, gid.as_bytes()) else {
        return;
    };
    let dir = dir_view(s);
    let members = crate::mls_conn::group_conv(&dir, gid).members;
    let ctx = crate::mls_rules::RuleCtx {
        dir: &dir,
        members: &members,
        expect_sender: None,
        keep_as: None,
        group: None,
    };
    let revoked: Vec<String> = crate::mls_conn::leaf_devices(&g)
        .into_iter()
        .map(|(_, d)| d)
        .filter(|d| ctx.is_revoked_leaf(d))
        .collect();
    for dev in revoked {
        tracing::info!(gid, dev, "든 트리에 폐기 잎 — 스스로 뺀다");
        run_duty(
            s,
            m,
            &json!({"group": gid, "task": "remove_device", "subject": dev}),
        );
    }
}

async fn on_rejoined(s: &Shared, m: &Mls, gid: &[u8]) -> Result<(), End> {
    if let Ok(mut r) = s.rejoined.lock() {
        r.insert(gid.to_vec(), s.clock.now().0);
    }
    let st = m.provider.storage();
    if crate::mls_conn::blocked(m, gid).is_none() {
        // rejoin_needed 로 다시 들어간 것(막힘 없음)은 잃은 글 표시만 실어 알린다(§12-27 ⓐ) — 다시 접속할 것은 없다.
        if let (Ok(Some(since)), Ok(Some(conversation))) = (st.take_lost(gid), st.conv(gid)) {
            emit(
                s,
                Inbound::ConversationSync {
                    conversation,
                    state: None,
                    lost_since: Some(since),
                },
            )
            .await?;
        }
        return Ok(());
    }
    let _ = st.clear_state(gid);
    let _ = st.drop_stalled(gid);
    let lost_since = st.take_lost(gid).ok().flatten();
    if let Ok(Some(conversation)) = st.conv(gid) {
        emit(
            s,
            Inbound::ConversationSync {
                conversation,
                state: None,
                lost_since,
            },
        )
        .await?;
    }
    Err(End::AfterReady)
}

/// 멈춘 대화를 스스로 다시 보는 기간(§12-19): 처음 멈춘 뒤 30일 — 그 뒤엔 멈춘 채로 두고 '다시 받기'·'나가기'만.
const STALL_RETRY_MS: i64 = 30 * 86_400_000;

/// 멈춘 대화 스스로 풀기(§12-19): 멈추게 한 Handshake 를 지금 디렉터리로 같은 길(pair·self 는 Handshake, group 은 확정된
/// Commit)로 다시 처리한다. epoch 가 올라가면(들어감) 행을 지우고 코어에 풀림을 알린다 — 기록 줄 없음. 아니면 원래 멈춤(상태·이유·
/// 처음 멈춘 때)을 그대로 되돌린다(디렉터리가 아직 늦어 Retry 여도 열린 채 두지 않는다 — 열리면 뒤처진 epoch 로 보낸다).
/// 하나라도 풀리면 `true` — 호출자가 다시 접속해 멈춘 동안 ack 하지 않은 것을 relay 에서 다시 받는다.
async fn redrive_stalled(s: &Shared, m: &Mls) -> Result<bool, End> {
    let st = m.provider.storage();
    let Ok(rows) = st.stalled() else {
        return Ok(false);
    };
    let now_ms = s.clock.now().0;
    let mut freed = false;
    for row in rows {
        let gid = row.group.as_slice();
        if now_ms.saturating_sub(row.since) > STALL_RETRY_MS {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&row.message) else {
            let _ = st.drop_stalled(gid);
            continue;
        };
        let group = message.get("kind").and_then(Value::as_str) == Some("group");
        // 쥔 채 멈춘 group Commit 은 확정(commit_final 이 seq 를 채움)된 것만 다시 본다 — 무효면 이미 지웠다.
        if group && row.group_seq.is_none() {
            continue;
        }
        let Some(snap) = crate::mls_conn::stall_open(m, gid) else {
            continue;
        };
        let handled = if group {
            group_commit_in(s, m, &message, row.group_seq).await?;
            crate::mls_conn::Handled::Done
        } else {
            crate::mls_conn::handle_handshake(m, &dir_view(s), &message, now_secs(s))
        };
        match crate::mls_conn::stall_close(m, gid, snap, &handled) {
            crate::mls_conn::Retried::Still => continue,
            crate::mls_conn::Retried::Rejoin(h) => enqueue_rejoin(s, m, &h),
            crate::mls_conn::Retried::Freed => tracing::info!("멈춘 대화가 풀림"),
        }
        let lost_since = st.take_lost(gid).ok().flatten();
        if let Ok(Some(conversation)) = st.conv(gid) {
            emit(
                s,
                Inbound::ConversationSync {
                    conversation,
                    state: None,
                    lost_since,
                },
            )
            .await?;
        }
        freed = true;
    }
    Ok(freed)
}

/// 한 그룹에 내 응용 메시지가 이만큼 쌓이면 주기 Update 를 간격(`Config::update_check`) 기다리지 않고 다음 틱에 본다(#626 §5 —
/// 옛 판 기기는 relay 가 뺀 반응만큼 보낸 기기의 sender ratchet 을 건너뛰고, 우리 설정의 건너뛰기 상한은 1000).
const UPDATE_BURST: u64 = 500;

/// 내 응용 메시지 하나를 셈에 넣고, [`UPDATE_BURST`] 를 넘었으면 다음 틱에 주기 Update 를 보게 한다.
fn count_sent(s: &Shared, m: &Mls, gid: &[u8]) {
    let n = m
        .provider
        .storage()
        .update_sent(gid, s.clock.now().0)
        .unwrap_or(0);
    if n >= UPDATE_BURST {
        if let Ok(mut at) = s.update_checked.lock() {
            *at = None;
        }
    }
}

/// 주기 Update 의 때(§7): 마지막 내 Update(또는 처음 본) 뒤 7일.
const UPDATE_EVERY_MS: i64 = 7 * 86_400_000;
/// 주기 Update 를 냈는데 확정 소식이 없으면(무효·꺼짐) 이만큼 뒤 다시.
const UPDATE_RETRY_MS: i64 = 3_600_000;

/// 때가 된 그룹마다 내 잎 Update 행을 넣는다(§7 — 7일 또는 내 응용 메시지 `update_every_msgs` 개). group 은 `update` Commit,
/// pair·self 는 기기 단위 일. 확정되면 셈을 다시 하고, 소식이 없으면 한 시간 뒤 다시 낸다. '다른 멤버가 접속해 있을 때 먼저'는
/// 접속 신호가 없어 하지 않는다 — 무효면 그 한 시간 뒤 다시(때 + 24시간 안). 간격이 차서 봤으면 `true`(멈춘 대화도 그때 다시 본다).
fn due_updates(s: &Shared, m: &Mls) -> bool {
    {
        let Ok(mut at) = s.update_checked.lock() else {
            return false;
        };
        if at.is_some_and(|t| t.elapsed() < s.config.update_check) {
            return false;
        }
        *at = Some(Instant::now());
    }
    // 새 기기 스스로 들어가기(§7)도 같은 간격으로 본다(틱마다 디렉터리를 보지 않게).
    due_orphan(s, m);
    let now = s.clock.now().0;
    let st = m.provider.storage();
    let Ok(due) = st.update_due(now, UPDATE_EVERY_MS, s.config.update_every_msgs) else {
        return true;
    };
    let me = s.config.keys.device_id().as_str().to_owned();
    for gid in due {
        let Some(g) = crate::mls_conn::load(m, &gid).filter(openmls::prelude::MlsGroup::is_active)
        else {
            let _ = st.update_reset(&gid, None);
            continue;
        };
        let _ = st.update_reset(&gid, Some(now - UPDATE_EVERY_MS + UPDATE_RETRY_MS));
        let header = crate::mls_conn::header_of(&gid);
        if header.as_bytes() == gid.as_slice() {
            enqueue_group_row(
                s,
                m,
                &header,
                "update",
                json!({}),
                json!({"op": "update", "task": "self_update"}),
            );
        } else {
            enqueue_task_row(s, &dir_view(s), &g, &header, "self_update", &me);
        }
    }
    true
}

/// 이 기기가 처음 잎 자격(§2b — devcert 사슬이 뿌리에 닿음)을 얻은 때 — mls_flags.
const LEAF_SINCE: &str = "leaf_since";
/// 새 기기 스스로 들어가기의 self·pair 쪽을 한 번 했다 — mls_flags. group 쪽은 relay `groups` 를 받은 뒤 실행마다 본다.
const ORPHAN_DONE: &str = "orphan_done";

/// [`due_updates`] 의 간격과 디렉터리를 받을 때마다 본다. 새 기기(§7): 잎 자격을 얻고 `orphan_wait`(30분) 뒤에도 들지 못한 내 그룹이
/// 있으면 한 번 external commit 으로 들어간다 — 내 다른 기기가 모두 꺼졌거나 잃어서 duty Add 를 낼 기기가 없을 때. 후보: self,
/// 디렉터리의 사람마다 pair, relay `groups` 의 group. 없는 그룹은 GroupInfo 가 오지 않아 행이 그냥 빠진다.
/// 내 다른 폐기 안 된 기기가 없고 끊긴 내 기기가 있으면(메일 확인 끊기·직접 끊기 뒤 이 기기 혼자, #577 §9 ①) Add 를 낼 기기가 없으니
/// 기다리지 않는다.
fn due_orphan(s: &Shared, m: &Mls) {
    let st = m.provider.storage();
    let dir = dir_view(s);
    let me = s.config.keys.device_id().as_str().to_owned();
    // 잎 자격은 relay 와 같은 판정(§2b 사슬) — 확인 전 기기의 external commit 은 거절된다(§4-5 ⓐ).
    let members = vec![s.config.user.clone()];
    let ctx = crate::mls_rules::RuleCtx {
        dir: &dir,
        members: &members,
        expect_sender: None,
        keep_as: None,
        group: None,
    };
    let key = m.signer.credential().signature_key;
    if !matches!(
        ctx.leaf_verdict(&me, key.as_slice()),
        crate::mls_rules::Verdict::Ok
    ) {
        return;
    }
    let now = s.clock.now().0;
    // 처음부터 기기가 하나뿐인 사용자는 들 대화가 없다 — 내 기기가 끊긴 적이 있을 때만(끊기 완료 뒤 혼자).
    let alone = crate::mls_rules::Directory::devices(&dir, &s.config.user)
        .iter()
        .all(|d| d.device_id == me)
        && (!crate::mls_rules::Directory::revocations(&dir, &s.config.user).is_empty()
            || s.store
                .peers_of(&s.config.user)
                .is_ok_and(|p| p.iter().any(|p| p.trust == crate::outbox::Trust::Revoked)));
    let wait = if alone {
        0
    } else {
        i64::try_from(s.config.orphan_wait.as_millis()).unwrap_or(i64::MAX)
    };
    let since = match st.flag_at(LEAF_SINCE) {
        Ok(Some(t)) => t,
        Ok(None) => {
            let _ = st.set_flag(LEAF_SINCE, now);
            now
        }
        Err(_) => return,
    };
    if now.saturating_sub(since) < wait {
        return;
    }
    if !st.flag(ORPHAN_DONE).unwrap_or(true) {
        let _ = st.set_flag(ORPHAN_DONE, now);
        let mut users = dir.users();
        users.retain(|u| *u != s.config.user);
        users.insert(0, s.config.user.clone());
        for u in users {
            let c = crate::mls_conn::conv(&s.config.user, &u);
            if crate::mls_conn::load(m, &c.gid).is_none() {
                push_task_row(s, &crate::mls_conn::header_of(&c.gid), &u, "rejoin", &me);
            }
        }
    }
    // group: relay `groups` 를 받은 뒤에만(그 전엔 후보를 모름) — 내 사용자는 멤버인데 이 기기에 없는 group, 이번 실행에 한 번.
    if !s.config.groups {
        return;
    }
    let groups: Vec<String> = s
        .known_groups
        .lock()
        .ok()
        .and_then(|k| k.as_ref().map(|k| k.iter().cloned().collect()))
        .unwrap_or_default();
    for g in groups {
        let fresh = s.orphan_tried.lock().is_ok_and(|mut t| t.insert(g.clone()));
        if fresh && crate::mls_conn::load(m, g.as_bytes()).is_none() {
            enqueue_rejoin(s, m, &g);
        }
    }
}

/// `rejoin_needed` 의 대화에 잃은 글 표시(§12-27 ⓐ): 그 대화에서 마지막으로 연 글의 시각, 없으면 지금. 다시 들어간 뒤
/// `ConversationSync{state: None, lost_since}` 로 실린다(이미 있으면 더 이른 쪽이 남는다).
fn note_rejoin_lost(s: &Shared, m: &Mls, gid: &str) {
    let Some(gid_b) = crate::mls_conn::gid_of_header(gid) else {
        return;
    };
    let st = m.provider.storage();
    let at = st.recv_at(&gid_b).ok().flatten().unwrap_or(s.clock.now().0);
    let _ = st.put_lost(&gid_b, at);
}

/// `rejoin_needed`(§5a)의 그룹 하나를 다시 들어가는 행으로: group 은 `update` 행(task rejoin), pair·self 는 기기 단위 일
/// (받는 주소 = 이 기기의 그 그룹 상대 — 옛 그룹이나 남겨 둔 대화 주소로). 같은 그룹이 이미 다시 들어가는 중이면 그대로.
fn enqueue_rejoin(s: &Shared, m: &Mls, gid: &str) {
    let Some(gid_b) = crate::mls_conn::gid_of_header(gid) else {
        return;
    };
    if gid_b == gid.as_bytes() {
        if s.rejoining.lock().is_ok_and(|r| r.contains_key(gid)) {
            return;
        }
        // 같은 그룹의 스스로 다시 들기 행이 이미 큐에 있다(물러서 기다리는 중일 수 있음) — 새 행을 더하지 않고 그 행을 지금
        // 다시 하게 당긴다(#599 ② — 두 external commit 이 나가지 않게, 물러섬만큼 늦지 않게).
        let queued = s.store.items().is_ok_and(|items| {
            items
                .iter()
                .any(|i| rejoin_row_gid(s, i.seq).as_deref() == Some(gid))
        });
        if queued {
            if let Ok(mut n) = s.rejoin_now.lock() {
                n.insert(gid.to_owned());
            }
            s.wake.notify_one();
            return;
        }
        enqueue_group_row(
            s,
            m,
            gid,
            "update",
            json!({}),
            json!({"op": "update", "task": "rejoin"}),
        );
        return;
    }
    let peer = match crate::mls_conn::load(m, &gid_b) {
        Some(g) => Some(task_peer(s, &dir_view(s), &g)),
        None => m
            .provider
            .storage()
            .conv(&gid_b)
            .ok()
            .flatten()
            .map(|a| user_part(&a)),
    };
    let Some(peer) = peer.filter(|p| crate::mls_conn::conv(&s.config.user, p).gid == gid_b) else {
        tracing::info!(gid, "다시 들어갈 대화를 모른다 — 건너뜀");
        return;
    };
    push_task_row(s, gid, &peer, "rejoin", s.config.keys.device_id().as_str());
}

/// 그 행이 group 다시 들어가기(`update` task rejoin)면 그 gid.
fn rejoin_row_gid(s: &Shared, seq: i64) -> Option<String> {
    let (p, _) = head_plain(s, seq)?;
    let task = p
        .pointer("/body/text")
        .and_then(Value::as_str)
        .and_then(|t| serde_json::from_str::<Value>(t).ok())?;
    (p.get("group_op").and_then(Value::as_str) == Some("update")
        && task.get("task").and_then(Value::as_str) == Some("rejoin"))
    .then(|| crate::group_io::group_context(&p))
    .flatten()
}

/// `group_info.get` 을 보내고 답을 기다린다.
async fn ask_group_info(
    ws: &mut Ws,
    boot: &mut Option<Boot>,
    seq: i64,
    gid: &str,
) -> Result<bool, ()> {
    if !send_text(ws, json!({"t": "group_info.get", "group": gid}).to_string()).await {
        return Err(());
    }
    *boot = Some(Boot::Rejoin {
        seq,
        since: Instant::now(),
    });
    Ok(false)
}

/// `group_info` 답으로 external commit(§4-5·§5b): pair·self 는 Handshake 를 바로 보내고 ack 를 기다리고, group 은 행을 그
/// Commit 으로 봉인한다(2단계 확정은 [`group_result`]). GroupInfo 가 없으면(멤버 아님·그룹 없음) 그 행을 뺀다.
async fn rejoin_with(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    seq: i64,
    frame: &Value,
) -> Result<(), End> {
    let Some((plain, to)) = head_plain(s, seq) else {
        return Ok(());
    };
    // external commit 을 만들지 못했다 — 받은 GroupInfo 의 트리에 끊긴 잎(내 옛 기기 등)이 남아 잎 검사가 Retry 인 경우가 보통이고,
    // 남은 멤버가 곧 빼 준다(#577 §9 ③ — external commit 에는 남의 잎 Remove 를 실을 수 없다). 2초부터 두 배씩, 60초까지.
    let backoff = |boot: &mut Option<Boot>| {
        let n = s.rejoin_fails.lock().map_or(0, |mut f| {
            let n = f.entry(seq).or_insert(0);
            *n += 1;
            *n
        });
        let wait = REJOIN_RETRY_FIRST
            .saturating_mul(1 << n.saturating_sub(1).min(5))
            .min(BOOT_BACKOFF);
        *boot = Some(Boot::Backoff {
            seq,
            until: Instant::now() + wait,
            tries: 0,
        });
    };
    // 큰 GroupInfo(§5c) — 받아 채운 뒤 다시 여기로. 그동안 Rejoin 을 새로 둬 다시 묻지 않게.
    if frame.pointer("/group_info/blob").is_some() {
        if let Ok(mut j) = s.blob_jobs.lock() {
            j.push_back(BlobJob::GroupInfo {
                seq,
                frame: frame.clone(),
            });
        }
        *boot = Some(Boot::Rejoin {
            seq,
            since: Instant::now(),
        });
        return Ok(());
    }
    let gi = frame
        .pointer("/group_info/data")
        .and_then(Value::as_str)
        .and_then(|d| lodelai_crypto::encoding::decode(d, "group_info").ok());
    let Some(gi) = gi else {
        tracing::info!("다시 들어갈 GroupInfo 가 없다(멤버 아님·그룹 없음) — 그만둠");
        let _ = s.store.remove(seq);
        return Ok(());
    };
    let dir = dir_view(s);
    // 겹친 다시 들어가기(#577 — rejoin_needed·주기 검사·거절 뒤 재시도가 같은 대화에 행을 둘 넣음): 이 행을 넣은 뒤 같은 대화의
    // 다시 들어가기가 이미 끝났으면 이 행은 뺀다. 두 번째 external commit 은 맞는 상태를 먼저 지우고, 거절되면 그 대화를 잃었다.
    let made = plain
        .get("created_at")
        .and_then(Value::as_str)
        .and_then(|t| lodelai_effects::UnixMillis::parse_rfc3339(t).ok())
        .map(|t| t.0);
    let done_after = |gid: &[u8]| {
        s.rejoined
            .lock()
            .ok()
            .and_then(|r| r.get(gid).copied())
            .zip(made)
            .is_some_and(|(done, made)| done >= made)
    };
    if plain.get("kind").and_then(Value::as_str) == Some(TASK_KIND) {
        let c = crate::mls_conn::conv(&s.config.user, &user_part(&to));
        if done_after(&c.gid) {
            tracing::info!("겹친 다시 들어가기 — 뺌");
            let _ = s.store.remove(seq);
            return Ok(());
        }
        let Some(msg_id) = new_msg_id(s) else {
            backoff(boot);
            return Ok(());
        };
        let Some(f) = crate::mls_conn::rejoin_pair(m, &boot_head(s, &to, &msg_id), &dir, &gi, &c)
        else {
            backoff(boot);
            return Ok(());
        };
        if !send_text(ws, f).await {
            return Err(End::AfterReady);
        }
        *boot = Some(Boot::Committing {
            seq,
            msg_id,
            gid: c.gid,
        });
        return Ok(());
    }
    let Some(gid) = crate::group_io::group_context(&plain) else {
        let _ = s.store.remove(seq);
        return Ok(());
    };
    // 같은 그룹의 external commit 이 이미 나가 있어도 겹친 것이다(그 결과를 기다린다).
    if s.rejoining.lock().is_ok_and(|r| r.contains_key(&gid)) || done_after(gid.as_bytes()) {
        tracing::info!(gid, "겹친 다시 들어가기 — 뺌");
        let _ = s.store.remove(seq);
        return Ok(());
    }
    let Some((f, epoch, hash)) =
        crate::mls_conn::rejoin_group(m, &s.config.keys, &dir, &gi, &gid, &plain)
    else {
        backoff(boot);
        return Ok(());
    };
    let _ = crate::mls_conn::put_commit_meta(
        m,
        gid.as_bytes(),
        epoch,
        &hash,
        "update",
        &s.me_address,
        None,
    );
    if let Ok(mut r) = s.rejoining.lock() {
        r.insert(gid.clone(), (epoch, hash));
    }
    if !seal_or_blob(s, seq, &f) {
        tracing::warn!("external commit 봉인 저장 실패");
    }
    Ok(())
}

/// duty 를 행으로 — 이미 된 일(대상이 잎임·이미 빠짐·그 사람 잎 없음)이면 아무것도 하지 않는다. `remove_user` 는 그 사람 잎을 모두
/// 빼는 Commit(디렉터리에 남아 있으면 `leave`, 빠졌으면 `org_left`), `add_device`·`remove_device` 는 group 이면 `update` Commit,
/// pair·self 면 기기 단위 일 행([`task_head`]).
fn run_duty(s: &Shared, m: &Mls, frame: &Value) {
    use crate::mls_rules::Directory as _;
    let (Some(gid), Some(task), Some(subject)) = (
        frame.get("group").and_then(Value::as_str),
        frame.get("task").and_then(Value::as_str),
        frame.get("subject").and_then(Value::as_str),
    ) else {
        return;
    };
    let Some(gid_b) = crate::mls_conn::gid_of_header(gid) else {
        return;
    };
    let Some(g) = crate::mls_conn::load(m, &gid_b) else {
        return;
    };
    let group_kind = gid_b == gid.as_bytes();
    let dir = dir_view(s);
    match task {
        "remove_user" if group_kind => {
            let user = user_part(subject);
            if crate::mls_conn::leaves_of(&dir, &s.store, &g, &user).is_empty() {
                return;
            }
            let op = if dir.devices(&user).is_empty() {
                "org_left"
            } else {
                "leave"
            };
            enqueue_group_row(
                s,
                m,
                gid,
                op,
                json!({"subject": subject}),
                json!({"op": op, "subject": subject}),
            );
        }
        "add_device" | "remove_device" => {
            let leaf = crate::mls_conn::leaf_of(&g, subject).is_some();
            if leaf == (task == "add_device") {
                return;
            }
            if group_kind {
                enqueue_group_row(
                    s,
                    m,
                    gid,
                    "update",
                    json!({}),
                    json!({"op": "update", "task": task, "device": subject}),
                );
            } else {
                enqueue_task_row(s, &dir, &g, gid, task, subject);
            }
        }
        _ => tracing::info!(task, "모르는 duty"),
    }
}

/// pair·self 그룹의 기기 단위 일 행을 큐에(받는 주소 = 그 대화의 상대, self 는 나). 같은 일이 이미 큐에 있으면 그대로.
fn enqueue_task_row(
    s: &Shared,
    dir: &crate::keys::DirView,
    g: &openmls::prelude::MlsGroup,
    gid: &str,
    task: &str,
    subject: &str,
) {
    let peer = task_peer(s, dir, g);
    if crate::mls_conn::conv(&s.config.user, &peer).gid != g.group_id().as_slice() {
        return;
    }
    push_task_row(s, gid, &peer, task, subject);
}

/// pair·self 그룹의 상대 사용자(잎 기기의 사용자 중 내가 아닌 사람, 없으면 나 — self).
fn task_peer(s: &Shared, dir: &crate::keys::DirView, g: &openmls::prelude::MlsGroup) -> String {
    use crate::mls_rules::Directory as _;
    let users = dir.users();
    g.members()
        .filter_map(|mem| crate::mls_rules::device_of(&mem.credential))
        .filter_map(|d| {
            users
                .iter()
                .find(|u| dir.devices(u).iter().any(|x| x.device_id == d))
                .cloned()
                .or_else(|| s.store.peer(&d).ok().flatten().map(|p| p.user))
        })
        .find(|u| *u != s.config.user)
        .unwrap_or_else(|| s.config.user.clone())
}

/// 기기 단위 일 행을 큐에(같은 일이 이미 큐에 있으면 그대로).
fn push_task_row(s: &Shared, gid: &str, peer: &str, task: &str, subject: &str) {
    let Some(id) = new_msg_id(s) else {
        return;
    };
    let to = format!("{peer}@{}", server_of(&s.me_address));
    let plain = json!({"kind": TASK_KIND, "msg_id": id, "to": {"address": to}, "task": task, "subject": subject});
    if let Err(e) = s.store.push_with_plain(
        &format!("{TASK_KIND}:{gid}:{task}:{subject}"),
        "send",
        Some(&id),
        Some(peer),
        "",
        Some(&plain.to_string()),
        false,
    ) {
        tracing::warn!(error = %e, task, "기기 단위 일 행 큐 실패");
    }
    s.wake.notify_one();
}

/// 큐 맨 앞의 pair·self 기기 단위 일(§7·§12-15): `add_device` 는 그 기기 KeyPackage 를 가져와 Add, `remove_device` 는 그 잎 Remove,
/// `self_update` 는 내 잎 Update. 확정은 ack 때 merge(2단계 없음). 이미 된 일이면 행을 뺀다.
async fn task_head(
    s: &Shared,
    ws: &mut Ws,
    m: &Mls,
    boot: &mut Option<Boot>,
    item: &outbox::Item,
    plain: &Value,
) -> Result<bool, ()> {
    let task = plain
        .get("task")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let subject = plain
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to = plain
        .pointer("/to/address")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let c = crate::mls_conn::conv(&s.config.user, &user_part(to));
    let tries = match boot {
        Some(Boot::Backoff { until, .. }) if Instant::now() < *until => return Ok(false),
        Some(Boot::Claiming { since, .. }) if since.elapsed() < CLAIM_WAIT => return Ok(false),
        Some(Boot::Committing { .. }) => return Ok(false),
        Some(Boot::Backoff { tries, .. }) => *tries,
        _ => 0,
    };
    let done = |boot: &mut Option<Boot>| {
        let _ = s.store.remove(item.seq);
        *boot = None;
        Ok(false)
    };
    if task == "rejoin" {
        if matches!(boot, Some(Boot::Rejoin { since, .. }) if since.elapsed() < CLAIM_WAIT) {
            return Ok(false);
        }
        if tries > TASK_TRIES {
            return done(boot);
        }
        return ask_group_info(ws, boot, item.seq, &crate::mls_conn::header_of(&c.gid)).await;
    }
    let Some(mut g) = crate::mls_conn::load(m, &c.gid) else {
        return done(boot);
    };
    // 보낸 Commit 의 답을 기다리는 중이 아니다 — 남은 pending(꺼지기 전 것)은 버린다.
    if g.pending_commit().is_some() {
        crate::mls_conn::clear_pending(m, &c.gid);
        let Some(g2) = crate::mls_conn::load(m, &c.gid) else {
            return done(boot);
        };
        g = g2;
    }
    let change = match task {
        "add_device" => {
            if crate::mls_conn::leaf_of(&g, subject).is_some() || tries > TASK_TRIES {
                return done(boot);
            }
            if !send_text(
                ws,
                json!({"t": "key_packages.claim", "device_ids": [subject]}).to_string(),
            )
            .await
            {
                return Err(());
            }
            *boot = Some(Boot::Claiming {
                seq: item.seq,
                since: Instant::now(),
                add_only: true,
                tries,
            });
            return Ok(false);
        }
        "remove_device" => match crate::mls_conn::leaf_of(&g, subject) {
            Some(i) => crate::mls_conn::Change::Remove(vec![i]),
            None => return done(boot),
        },
        "self_update" => crate::mls_conn::Change::Update,
        _ => return done(boot),
    };
    let Some(msg_id) = new_msg_id(s) else {
        return Ok(false);
    };
    let Some(frame) = crate::mls_conn::pair_commit(m, &boot_head(s, to, &msg_id), &mut g, &change)
    else {
        tracing::warn!(task, "기기 단위 Commit 을 만들 수 없음 — 그만둠");
        return done(boot);
    };
    if !send_text(ws, frame).await {
        return Err(());
    }
    *boot = Some(Boot::Committing {
        seq: item.seq,
        msg_id,
        gid: c.gid,
    });
    Ok(false)
}

/// 무효 뒤 다시 낸 빼기·관리자 행을 봉인하기 전에 지금 그룹 상태로 다시 본다(§12-27 ⓒ d4c07549). 보내지 않을 것이면 행을
/// 지우고 `true`: 할 수 없게 됐으면(내가 관리자·멤버가 아님) 실패 길(Nack commit_void — 줄 키로), 이미 이뤄졌거나(빼려는 사람이
/// 없음·관리자 상태가 이미 그 값) 같은 대상의 더 나중 변경이 봉인됐으면 실패 아님(Final, seq 없음 — 코어가 기다림만 지움).
async fn requeued_change_check(
    s: &Shared,
    m: &Mls,
    item: &outbox::Item,
    gid: &str,
    op: &str,
    plain: &Value,
) -> bool {
    let asked = plain
        .pointer("/body/text")
        .and_then(Value::as_str)
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .unwrap_or(Value::Null);
    let (Some(orig), Some(full), true) = (
        asked.get("orig").and_then(Value::as_str),
        plain.get("subject").and_then(Value::as_str),
        asked.get("tries").is_some() && matches!(op, "remove" | "admin"),
    ) else {
        return false;
    };
    let st = crate::mls_conn::group_state(m, &dir_view(s), gid, server_of(&s.me_address));
    let latest = s.latest_change.lock().ok().and_then(|l| {
        l.get(&(gid.to_owned(), op.to_owned(), full.to_owned()))
            .cloned()
    });
    let i = match requeued_verdict(
        op,
        &asked,
        full,
        &s.me_address,
        st.as_ref(),
        latest.as_deref(),
        orig,
    ) {
        Requeued::Send => return false,
        Requeued::Skip => {
            tracing::info!(
                gid,
                op,
                "다시 낼 변경이 이미 됐거나 더 나중 변경이 있다 — 보내지 않음"
            );
            Inbound::GroupChangePending {
                change_id: orig.to_owned(),
                pending: crate::ChangePending::Final,
                seq: None,
            }
        }
        Requeued::Fail => {
            tracing::warn!(gid, op, "다시 낼 변경을 할 수 없게 됐다 — 실패");
            Inbound::Nack {
                msg_id: orig.to_owned(),
                reason: "commit_void".into(),
            }
        }
    };
    let _ = s.store.remove(item.seq);
    let _ = s.inbound.send(i).await;
    true
}

/// [`requeued_change_check`] 의 판정.
#[derive(Debug, PartialEq, Eq)]
enum Requeued {
    /// 그대로 할 수 있다 — 보낸다.
    Send,
    /// 이미 이뤄졌거나 같은 대상의 더 나중 변경이 있다 — 보내지 않음, 실패 아님.
    Skip,
    /// 할 수 없게 됐다(내가 관리자·멤버가 아님) — 실패.
    Fail,
}

/// 다시 낸 remove·admin 의 판정(§12-27 ⓒ). `full` = 대상 사람 주소, `st` = 지금 그룹 상태, `latest` = 같은 (그룹, op, 대상)의
/// 마지막으로 봉인한 변경 줄 키, `orig` = 이 변경의 줄 키. admin 의 목표값은 `asked.admin`.
fn requeued_verdict(
    op: &str,
    asked: &Value,
    full: &str,
    me: &str,
    st: Option<&crate::GroupState>,
    latest: Option<&str>,
    orig: &str,
) -> Requeued {
    let able = st
        .is_some_and(|st| st.members.iter().any(|a| a == me) && st.admins.iter().any(|a| a == me));
    if !able {
        return Requeued::Fail;
    }
    let done = latest.is_some_and(|l| l != orig)
        || st.is_some_and(|st| match op {
            "remove" => !st.members.iter().any(|a| a == full),
            _ => {
                asked.get("admin").and_then(Value::as_bool)
                    == Some(st.admins.iter().any(|a| a == full))
            }
        });
    if done {
        Requeued::Skip
    } else {
        Requeued::Send
    }
}

/// 무효가 된 내 사람 op Commit(create·add·remove·admin)을 같은 변경 행으로 다시 큐에(§12-21). create 의 subject 는 처음 멤버를 줄바꿈으로 이은 값.
/// 같은 사람 op 변경이 무효가 되어도 다시 내는 최대 횟수(§12-26 ⑤).
const VOID_MAX: u32 = 3;

fn requeue_change(
    s: &Shared,
    m: &Mls,
    gid: &str,
    op: &str,
    subject: Option<&str>,
    tries: u32,
    orig: &str,
) {
    match (op, subject) {
        ("add", Some(x)) => {
            tracing::info!(gid, "add Commit 무효 — 다시 냄");
            enqueue_group_row(
                s,
                m,
                gid,
                op,
                json!({"subject": x}),
                json!({"op": op, "subject": x, "tries": tries, "orig": orig}),
            );
        }
        // §12-27 ⓒ: 빼기·관리자도 다시 낸다 — 다시 봉인할 때 지금 상태로 다시 본다([`requeued_change_check`]). 관리자는
        // 뒤집기라 지금(무효 전과 같은 epoch)의 반대를 목표로 남긴다.
        ("remove", Some(x)) => {
            tracing::info!(gid, "remove Commit 무효 — 다시 냄");
            enqueue_group_row(
                s,
                m,
                gid,
                op,
                json!({"subject": x}),
                json!({"op": op, "subject": x, "tries": tries, "orig": orig}),
            );
        }
        ("admin", Some(x)) => {
            tracing::info!(gid, "admin Commit 무효 — 다시 냄");
            let target =
                !crate::mls_conn::group_state(m, &dir_view(s), gid, server_of(&s.me_address))
                    .is_some_and(|st| st.admins.iter().any(|a| a == x));
            enqueue_group_row(
                s,
                m,
                gid,
                op,
                json!({"subject": x}),
                json!({"op": op, "subject": x, "admin": target, "tries": tries, "orig": orig}),
            );
        }
        ("create", Some(x)) => {
            tracing::info!(gid, "create Commit 무효 — 다시 냄");
            let subjects: Vec<&str> = x.split('\n').collect();
            enqueue_group_row(
                s,
                m,
                gid,
                op,
                json!({"subjects": subjects}),
                json!({"op": op, "tries": tries, "orig": orig}),
            );
        }
        _ => {}
    }
}

/// relay-client 가 스스로 내는 group 변경 행(코어 group_change_out 과 같은 꼴, 연결 루프가 봉인).
fn enqueue_group_row(s: &Shared, m: &Mls, gid: &str, op: &str, headers: Value, asked: Value) {
    let Some(id) = new_msg_id(s) else {
        return;
    };
    let now = s.clock.now();
    let (Ok(created), Ok(expires)) = (
        now.to_rfc3339(),
        lodelai_effects::UnixMillis(now.0 + 30 * 86_400_000).to_rfc3339(),
    ) else {
        return;
    };
    let mut message = json!({
        "v": lodelai_protocol::PROTOCOL_MIN, "msg_id": id, "thread_id": id, "kind": "group",
        "from": {"address": s.me_address, "author": "human"},
        "to": {"address": format!("+{gid}@{}", server_of(&s.me_address))},
        "group_op": op,
        "base_seq": crate::mls_conn::group_seq_of(m, gid.as_bytes()),
        "body": {"enc": "plain", "text": asked.to_string()},
        "created_at": created,
        "expires_at": expires,
    });
    if let (Some(o), Some(h)) = (message.as_object_mut(), headers.as_object()) {
        for (k, v) in h {
            o.insert(k.clone(), v.clone());
        }
    }
    if let Err(e) = crate::outbox::enqueue(
        &s.store,
        &s.config.keys,
        s.clock.as_ref(),
        &crate::Outgoing::GroupChange { message },
    ) {
        tracing::warn!(error = %e, op, "그룹 행 큐 실패");
    }
    s.wake.notify_one();
}

/// 확정 뒤 그룹에 새로 든 기기 잎이 생겼고(`before` 에 없던 기기, 또는 external commit 으로 스스로 든 `joiner` — 옛 잎을 갈아
/// 끼운 같은 기기도), 그 기기가 아닌 `before` 의 잎 중 번호가 가장 작은 것이 이 기기인가.
fn first_old_leaf_saw_new(
    s: &Shared,
    m: &Mls,
    gid: &str,
    before: &[String],
    joiner: Option<&str>,
) -> bool {
    let Some(g) = crate::mls_conn::load(m, gid.as_bytes()) else {
        return false;
    };
    let after = crate::mls_conn::leaf_devices(&g);
    let me = s.config.keys.device_id();
    let me = me.as_str();
    // 폐기됐는데 아직 안 빠진 잎(#577 '지금 끊기' — 끊긴 옛 기기)은 다시 보낼 수 없다 — 그다음 잎이 맡는다.
    let dir = dir_view(s);
    let members = crate::mls_conn::group_conv(&dir, gid).members;
    let ctx = crate::mls_rules::RuleCtx {
        dir: &dir,
        members: &members,
        expect_sender: None,
        keep_as: None,
        group: None,
    };
    let joined = joiner.is_some_and(|j| after.iter().any(|(_, d)| d == j));
    (joined || after.iter().any(|(_, d)| !before.contains(d)))
        && after
            .iter()
            .find(|(_, d)| {
                before.contains(d) && Some(d.as_str()) != joiner && !ctx.is_revoked_leaf(d)
            })
            .is_some_and(|(_, d)| d == me)
}

/// 지금 이름으로 `rename` 행을 큐에 넣는다(코어 group_change_out 과 같은 꼴, 연결 루프가 봉인).
fn resend_name(s: &Shared, m: &Mls, gid: &str) {
    let Some(name) = openmls_traits::OpenMlsProvider::storage(&m.provider)
        .group_meta(gid.as_bytes())
        .ok()
        .flatten()
        .map(|(n, _, _)| n)
        .filter(|n| !n.is_empty())
    else {
        return;
    };
    enqueue_group_row(
        s,
        m,
        gid,
        "rename",
        json!({}),
        json!({"op": "rename", "name": name}),
    );
}

/// MLS 그룹의 app op(내가 보낸 것의 ack 포함): `rename` 은 평문 머리 `meta.name` 으로 이름을 바꾸고(같으면 줄 없음, §12-23),
/// `leave` 는 그 사람을 화면 상태에서 뺀다 — 잎은 남은 기기의 leave Commit 으로 빠진다(§12-13 ②). 나간 사람이 나면 그룹을 지운다.
async fn group_app_in(
    s: &Shared,
    m: &Mls,
    message: &Value,
    text: &str,
    group_seq: Option<u64>,
) -> Result<(), End> {
    let Some(gid) = crate::group_io::group_context(message) else {
        return Ok(());
    };
    let op = message
        .get("group_op")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let actor = message
        .pointer("/from/address")
        .and_then(Value::as_str)
        .map(|a| a.split_once('/').map_or(a, |(p, _)| p).to_owned())
        .unwrap_or_default();
    let seq = group_seq.unwrap_or_else(|| crate::mls_conn::group_seq_of(m, gid.as_bytes()));
    // 이름 바꾸기·내 나가기는 Commit 이 아니라 app 이라 commit_final 이 없다 — relay 가 받은 것(ack)이 확정이다(§12-27 ⓒ). 그 줄
    // 키(이 msg_id)에 seq 를 실어 GroupUpdate 보다 먼저. 내 다른 기기가 보낸 것이면 코어가 모르는 키라 그냥 지나간다.
    if actor == s.me_address && matches!(op.as_str(), "rename" | "leave") {
        if let Some(change_id) = message.get("msg_id").and_then(Value::as_str) {
            emit(
                s,
                Inbound::GroupChangePending {
                    change_id: change_id.to_owned(),
                    pending: crate::ChangePending::Final,
                    seq: Some(seq),
                },
            )
            .await?;
        }
    }
    match op.as_str() {
        "rename" => {
            let name = text
                .split_once('\n')
                .and_then(|(h, _)| serde_json::from_str::<Value>(h).ok())
                .and_then(|h| {
                    h.pointer("/meta/name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .map(|n| n.trim().to_owned())
                .filter(|n| (1..=crate::groups::NAME_MAX_CHARS).contains(&n.chars().count()));
            let Some(name) = name else {
                tracing::warn!("그룹 이름이 틀림 — 무시");
                return Ok(());
            };
            let st = openmls_traits::OpenMlsProvider::storage(&m.provider);
            let same = st
                .group_meta(gid.as_bytes())
                .ok()
                .flatten()
                .is_some_and(|(n, _, _)| n == name);
            let _ = st.set_group_meta(gid.as_bytes(), Some(&name), group_seq, None);
            if !same {
                emit_group_update(s, m, &gid, seq, op, actor, None).await?;
            }
        }
        "leave" => {
            let subject = message
                .get("subject")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| actor.clone());
            if let Some(q) = group_seq {
                crate::mls_conn::note_group_seq(m, gid.as_bytes(), q, false);
            }
            emit_group_update(s, m, &gid, seq, op, actor, Some(subject.clone())).await?;
            if subject == s.me_address {
                crate::mls_conn::drop_group(m, gid.as_bytes());
            }
        }
        other => tracing::warn!(op = other, "모르는 그룹 app op — 무시"),
    }
    Ok(())
}

/// 확정된 group 변경을 코어에 `GroupUpdate` 로(묶음 16 API 그대로, 상태는 MLS 에서).
async fn emit_group_update(
    s: &Shared,
    m: &Mls,
    gid: &str,
    seq: u64,
    op: String,
    actor: String,
    subject: Option<String>,
) -> Result<(), End> {
    let dir = dir_view(s);
    let server = s
        .me_address
        .split_once('@')
        .map_or("", |(_, x)| x)
        .to_owned();
    // 남은 기기가 낸 leave Commit(§12-13 ②)은 나간 사람의 leave(app) 때 이미 줄을 냈다 — 확정 때는 줄 없이 상태만(`update`,
    // §12-25 ⓐ: 잎이 빠져 유효 관리자가 이때 바뀐다).
    let (op, subject) = if op == "leave" && subject.as_deref().is_some_and(|x| x != actor) {
        ("update".to_owned(), None)
    } else {
        (op, subject)
    };
    let Some(mut state) = crate::mls_conn::group_state(m, &dir, gid, &server) else {
        return Ok(());
    };
    // 사람이 빠지는 op: leave(app)는 잎이 아직 있고, 빠진 기기는 확정 뒤 그룹이 없다 — 화면 상태에서 그 사람을 뺀다.
    if matches!(op.as_str(), "leave" | "remove" | "org_left") {
        if let Some(x) = subject.as_deref() {
            state.members.retain(|a| a != x);
            state.admins.retain(|a| a != x);
        }
    }
    // 내 create 의 확정용 헤더는 처음 멤버를 이어 둔 값 — 화면에는 subject 없음(16 그대로).
    let subject = if op == "create" { None } else { subject };
    // 16 의 꼴 그대로: leave 는 subject 없음(나간 사람 = actor), org_left 는 보낸 사람 없음(서버 사실).
    let (actor, subject) = match op.as_str() {
        "leave" => (subject.unwrap_or(actor), None),
        "org_left" => (String::new(), subject),
        _ => (actor, subject),
    };
    emit(
        s,
        Inbound::GroupUpdate {
            gid: gid.to_owned(),
            seq,
            op,
            actor,
            subject,
            state,
        },
    )
    .await
}

/// 다시 들기(내 external commit)를 기다리는 그룹에 온 결과를 가른다.
#[derive(Debug, PartialEq, Eq)]
enum RejoinResult {
    /// 기다림 없음·앞 epoch 의 결과(부하로 늦게 닿은 남의 확정 등) — 기다림을 그대로 둔다. 지우면 정작 내 확정이 왔을 때 그룹
    /// 상태를 알리지 않고 지나갔다(#645).
    Keep,
    /// 기다리던 내 Commit 의 결과 — 꺼냈다.
    Mine,
    /// 같은·높은 epoch 의 다른 Commit 이 확정됐다 — 내 것은 확정될 수 없다(무효를 끊긴 채 놓쳤을 수 있음). 기다림을 지웠다 — 다시
    /// 든다(#645 설계 리뷰 🟡, 남겨 두면 enqueue_rejoin 이 늘 물러서 그 그룹에 영영 못 든다).
    Superseded((u64, [u8; 32])),
}

fn take_rejoin(
    r: &mut std::collections::HashMap<String, (u64, [u8; 32])>,
    gid: &str,
    epoch: u64,
    hash: &[u8; 32],
    final_: bool,
) -> RejoinResult {
    match r.get(gid) {
        Some(&(e, h)) if (e, h) == (epoch, *hash) => {
            r.remove(gid);
            RejoinResult::Mine
        }
        // 남의 Commit 의 무효는 내 것을 막지 않는다 — 확정일 때만.
        Some(&(e, h)) if final_ && epoch >= e => {
            r.remove(gid);
            RejoinResult::Superseded((e, h))
        }
        _ => RejoinResult::Keep,
    }
}

/// `commit_final`·`commit_void`(§4-7·§12-14·§12-16): 내 Commit 이면 merge_pending_commit·clear, 남의 것이면 같은 해시로 쥔 것을
/// merge·버림. 확정이면 화면 seq 를 남기고 GroupUpdate.
async fn group_result(s: &Shared, m: &Mls, frame: &Value) -> Result<(), End> {
    let final_ = frame.get("t").and_then(Value::as_str) == Some("commit_final");
    let (Some(gid), Some(epoch), Some(hash)) = (
        frame.get("group").and_then(Value::as_str),
        frame.get("epoch").and_then(Value::as_u64),
        frame
            .get("commit_hash")
            .and_then(Value::as_str)
            .and_then(|h| lodelai_crypto::encoding::decode_array::<32>(h, "commit_hash").ok()),
    ) else {
        return Ok(());
    };
    let group_seq = frame.get("group_seq").and_then(Value::as_u64);
    // 내 external commit(다시 들어가기)의 결과: 확정이면 상태 갱신, 무효면 버리고 다시 들어간다(보낼 때 이미 merge 함).
    let rejoined = s.rejoining.lock().map_or(RejoinResult::Keep, |mut r| {
        take_rejoin(&mut r, gid, epoch, &hash, final_)
    });
    let failed = s
        .failed_commits
        .lock()
        .is_ok_and(|mut f| f.remove(&(gid.to_owned(), epoch, hash)));
    if failed && final_ {
        tracing::warn!(gid, "처리하지 못한 Commit 이 확정됨 — 다시 들어감");
        enqueue_rejoin(s, m, gid);
        return Ok(());
    }
    if let RejoinResult::Superseded((e, h)) = rejoined {
        tracing::info!(
            gid,
            "다른 Commit 이 끝나 내 다시 들기는 확정될 수 없음 — 다시 듦"
        );
        let _ = crate::mls_conn::take_commit_meta(m, gid.as_bytes(), e, &h);
        crate::mls_conn::drop_group(m, gid.as_bytes());
        wake_stale(s);
        enqueue_rejoin(s, m, gid);
        return Ok(());
    }
    if rejoined == RejoinResult::Mine {
        let _ = crate::mls_conn::take_commit_meta(m, gid.as_bytes(), epoch, &hash);
        wake_stale(s);
        if final_ {
            let seq = crate::mls_conn::group_seq_of(m, gid.as_bytes());
            emit_group_update(s, m, gid, seq, "update".into(), s.me_address.clone(), None).await?;
            remove_revoked_leaves(s, m, gid);
            return on_rejoined(s, m, gid.as_bytes()).await;
        }
        crate::mls_conn::drop_group(m, gid.as_bytes());
        enqueue_rejoin(s, m, gid);
        return Ok(());
    }
    // 이 기기를 멈추게 한 Commit 의 결과(§12-19): 확정이면 다시 볼 seq 를 채우고(디렉터리가 바뀌면 같은 길로), 무효면 그 변경은
    // 없던 일이라 epoch N 그대로 연다.
    if openmls_traits::OpenMlsProvider::storage(&m.provider)
        .is_stalled_by(gid.as_bytes(), epoch, &hash)
        .unwrap_or(false)
    {
        let st = openmls_traits::OpenMlsProvider::storage(&m.provider);
        if final_ {
            let seq = group_seq.unwrap_or_else(|| crate::mls_conn::group_seq_of(m, gid.as_bytes()));
            let _ = st.stalled_final(gid.as_bytes(), epoch, &hash, seq);
        } else {
            let _ = st.drop_stalled(gid.as_bytes());
            let _ = st.clear_state(gid.as_bytes());
            let _ = crate::mls::discard(&m.provider, gid.as_bytes(), epoch);
            let lost_since = st.take_lost(gid.as_bytes()).ok().flatten();
            if let Ok(Some(conversation)) = st.conv(gid.as_bytes()) {
                emit(
                    s,
                    Inbound::ConversationSync {
                        conversation,
                        state: None,
                        lost_since,
                    },
                )
                .await?;
            }
        }
        return Ok(());
    }
    // 받은 external commit 의 든 기기 — 확정·무효 어느 쪽이든 결과가 왔으면 지운다(설계 리뷰 🟡).
    let joiner = s
        .external_joiners
        .lock()
        .ok()
        .and_then(|mut x| x.remove(&(gid.to_owned(), epoch, hash)));
    let Some(mut g) = crate::mls_conn::load(m, gid.as_bytes()) else {
        // #599: 다시 들 그룹(로컬 상태 없음)의 확정 전 Commit 이 끝났다 — relay 가 mls_rejoin 표시 기기에도 결과를 보낸다.
        // stale_epoch 로 물러선 external commit 을 곧바로 다시 낸다(횟수는 그대로).
        wake_stale(s);
        return Ok(());
    };
    // 지난 epoch 의 결과(접속 때 relay 가 마지막 결과를 다시 보냄 — §12-14 ②)는 이미 처리했다. 지금 쥔 pending 을 '다른 Commit
    // 확정'으로 잘못 버리지 않게 지금 epoch 의 결과만 본다(앞선 epoch 면 쌓인 것에서 group_seq 붙은 Commit 이 온다).
    if epoch != g.epoch().as_u64() {
        // #599: 옛 로컬 그룹이 남은 다시 들 기기도 결과를 받으면 물러선 다시 들기를 깨운다(위 None 갈래와 같은 까닭).
        wake_stale(s);
        return Ok(());
    }
    // 이 Commit 전의 잎 기기 — 확정 뒤 새로 생긴 잎이 있으면 이름을 다시 보낼지 본다(#577).
    let leaves_before: Vec<String> = crate::mls_conn::leaf_devices(&g)
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    // relay 의 확정 전 Commit 이 끝났다 — stale_epoch 로 물러선 행을 곧바로 다시 낸다.
    wake_stale(s);
    let own = g.pending_commit().is_some();
    let mine = own
        .then(|| {
            openmls_traits::OpenMlsProvider::storage(&m.provider)
                .own_commit_meta(gid.as_bytes(), epoch, &s.me_address)
                .ok()
                .flatten()
        })
        .flatten();
    // 확정된 것이 쥔 남의 Commit 인가(내 것과 같은 epoch 로 겹쳐 relay 가 그쪽을 받았다) — 해시로 가른다. 내 다른 기기의 것도
    // 같은 actor 라 meta 로는 못 가른다.
    let held = openmls_traits::OpenMlsProvider::storage(&m.provider)
        .pending(gid.as_bytes(), epoch, &hash)
        .ok()
        .flatten()
        .is_some();
    let meta = crate::mls_conn::take_commit_meta(m, gid.as_bytes(), epoch, &hash);
    // 이 epoch 에 낸 내 사람 op 변경의 줄 키(§12-27 ⓒ) — 확정이면 final, 아니면 retry 로 코어에.
    let change = own
        .then(|| {
            openmls_traits::OpenMlsProvider::storage(&m.provider)
                .take_change(gid.as_bytes(), epoch)
                .ok()
                .flatten()
        })
        .flatten();
    let mut mine_merged = false;
    let merged = if own {
        if final_ && !held && meta.is_some() {
            mine_merged = crate::mls_conn::merge(m, gid.as_bytes());
            mine_merged
        } else {
            // 세 번째 무효는 아래 Nack(commit_void) 이 줄을 맡는다 — 그 전엔 '접속하면 반영돼요'(retry).
            let last = s
                .commit_tries
                .lock()
                .ok()
                .and_then(|t| t.get(&(gid.to_owned(), epoch)).map(|(n, _)| *n))
                .is_some_and(|n| n + 1 >= VOID_MAX);
            if let (Some(change_id), false) = (change.clone(), last) {
                emit(
                    s,
                    Inbound::GroupChangePending {
                        change_id,
                        pending: crate::ChangePending::Retry,
                        seq: None,
                    },
                )
                .await?;
            }
            // 무효이거나 다른 Commit 이 확정됐다 — 내 것을 버리고(행은 이미 ack 로 빠짐) 쌓인 것을 기다린다. 사람 op
            // (create·add)는 같은 변경을 다시 큐에 넣어 다음 epoch 로 낸다(§12-21, 사람 확인 없음). duty 는 relay 가 다시 준다.
            crate::mls_conn::clear_pending(m, gid.as_bytes());
            let tried = s
                .commit_tries
                .lock()
                .ok()
                .and_then(|mut t| t.remove(&(gid.to_owned(), epoch)));
            // 내 Commit 행이 아직 응답 전(맨 앞에 봉인된 채)이면 다시 넣지 않는다 — 그 행은 곧 올 stale_epoch nack 으로 다음
            // epoch 에 다시 나간다(넣으면 같은 변경이 둘).
            let unanswered = s.store.peek().ok().flatten().is_some_and(|i| {
                crate::mls_conn::frame_commit_hash(&i.frame).is_some()
                    && head_plain(s, i.seq)
                        .and_then(|(p, _)| crate::group_io::group_context(&p))
                        .is_some_and(|g| g == gid)
            });
            if let (Some((op, subject)), false) = (&mine, unanswered) {
                let (tries, orig) = tried.unwrap_or_default();
                if tries + 1 >= VOID_MAX {
                    // 같은 변경이 3번 무효 — 멈추고 처음 행을 실패로(공모 fail·망가진 KeyPackage 로 KP 를 끝없이 태우지 않게).
                    tracing::warn!(gid, op, "같은 변경이 {VOID_MAX}번 무효 — 멈춤");
                    if op == "create" {
                        crate::mls_conn::drop_group(m, gid.as_bytes());
                    }
                    if !orig.is_empty() {
                        emit(
                            s,
                            Inbound::Nack {
                                msg_id: orig,
                                reason: "commit_void".into(),
                            },
                        )
                        .await?;
                    }
                } else {
                    requeue_change(s, m, gid, op, subject.as_deref(), tries + 1, &orig);
                }
            }
            // 쥔 남의 Commit 이 확정됐다 — 내 것을 버린 그룹에서 merge(안 하면 이 epoch 에 멈춘다).
            match (final_ && held)
                .then(|| crate::mls_conn::load(m, gid.as_bytes()))
                .flatten()
            {
                Some(mut g) => {
                    crate::mls::finalize(&m.provider, &mut g, epoch, &hash).unwrap_or(false)
                }
                None => false,
            }
        }
    } else if final_ {
        crate::mls::finalize(&m.provider, &mut g, epoch, &hash).unwrap_or(false)
    } else {
        let _ = crate::mls::discard(&m.provider, gid.as_bytes(), epoch);
        false
    };
    m.provider.scrub();
    if merged {
        if let Some(seq) = group_seq {
            crate::mls_conn::note_group_seq(m, gid.as_bytes(), seq, false);
        }
        if let Some((op, actor, subject)) = meta {
            let seq = group_seq.unwrap_or_else(|| crate::mls_conn::group_seq_of(m, gid.as_bytes()));
            // 확정 — 같은 줄 키에 seq 를 실어 GroupUpdate 보다 먼저(코어가 기다린 줄에 seq 를 채워 같은 줄을 두 번 넣지 않게).
            if let (true, Some(change_id)) = (mine_merged, change) {
                emit(
                    s,
                    Inbound::GroupChangePending {
                        change_id,
                        pending: crate::ChangePending::Final,
                        seq: Some(seq),
                    },
                )
                .await?;
            }
            let named = matches!(op.as_str(), "create" | "add");
            let added = mine_merged && named;
            if mine_merged && s.self_updates.lock().is_ok_and(|mut u| u.remove(&hash)) {
                let _ = m
                    .provider
                    .storage()
                    .update_reset(gid.as_bytes(), Some(s.clock.now().0));
            }
            emit_group_update(s, m, gid, seq, op, actor, subject).await?;
            // Add Commit 을 낸 기기가 확정 뒤 지금 이름을 다시 보낸다 — 새 멤버는 이것으로 이름을 안다(§12-23).
            if added {
                resend_name(s, m, gid);
            } else if !named && first_old_leaf_saw_new(s, m, gid, &leaves_before, joiner.as_deref())
            {
                // 그 밖의 Commit(내 다른 기기 duty Add·새 기기의 external commit)으로 잎이 새로 생겼다 — 이름은 MLS 안 rename
                // 글에만 있어 새 기기는 모른다(#577 실기 확인: 사이드바 '?'). 그 전부터 있던 잎 중 번호가 가장 작은 기기 하나가
                // 다시 보낸다(한 번만 — 같은 이름은 다른 멤버에게 줄을 만들지 않는다).
                resend_name(s, m, gid);
            }
        }
        crate::mls_conn::drop_if_removed(m, gid.as_bytes());
    }
    Ok(())
}

/// 받은 group Commit(kind group, wire commit — §4-7). 그룹이 없으면 welcome 으로 들어가고, 있으면 쥐고 commit_ack(group_seq 가
/// 붙었으면 이미 확정 — 바로 merge, §12-14 ①). 처리 실패면 commit_fail. ack 할 것이면 `true`(멈춘 그룹에 온 것은 `false`).
async fn group_commit_in(
    s: &Shared,
    m: &Mls,
    message: &Value,
    group_seq: Option<u64>,
) -> Result<bool, End> {
    let header = |k: &str| message.get(k).and_then(Value::as_str).map(str::to_owned);
    let (Some(gid), Some(epoch)) = (
        header("mls_group"),
        message.get("epoch").and_then(Value::as_u64),
    ) else {
        return Ok(true);
    };
    if group_seq.is_some() {
        // 이미 확정된 Commit — 그 epoch 의 relay pending 은 끝났다.
        wake_stale(s);
    }
    let op = header("group_op").unwrap_or_default();
    let actor = message
        .pointer("/from/address")
        .and_then(Value::as_str)
        .map(|a| a.split_once('/').map_or(a, |(p, _)| p).to_owned())
        .unwrap_or_default();
    let subject = header("subject");
    // MLS 일은 동기로 끝내고(RuleCtx 를 .await 너머로 쥐지 않음) 결과만 들고 나온다.
    let mut ack = true;
    let emit_seq = group_commit_sync(
        s,
        m,
        message,
        &gid,
        epoch,
        group_seq,
        &op,
        &actor,
        subject.as_deref(),
        &mut ack,
    );
    if let Some(seq) = emit_seq {
        emit_group_update(s, m, &gid, seq, op, actor, subject).await?;
        crate::mls_conn::drop_if_removed(m, gid.as_bytes());
    }
    Ok(ack)
}

/// Handshake 의 [`crate::mls_conn::Handled::RetryDir`] 열쇠와 같은 꼴(`mls:` + `mls_group` 헤더) — 수를 되돌릴 때.
fn handshake_key(message: &Value) -> Option<String> {
    message
        .get("mls_group")
        .and_then(Value::as_str)
        .map(|g| format!("mls:{g}"))
}

/// 그룹 하나에서 디렉터리를 당겨 올 사이(ms) (#725).
const DIR_PULL_GAP_MS: i64 = 10_000;

/// #725: 그룹 `gid` 의 Commit 이 디렉터리 때문에 다시(Retry, `no_chain`·`device_unknown`)가 됐다 — 그 그룹에서 두 번째부터
/// (앞 Commit 이 무효가 된 뒤 다시 온 것)이고 그 그룹에서 마지막으로 당긴 지 [`DIR_PULL_GAP_MS`] 가 지났으면 참(당긴 때를 적는다).
/// Retry 가 아닌 처리를 하면 부르는 쪽이 수를 0 으로 되돌린다.
fn retry_pull(
    pulls: &mut std::collections::HashMap<String, (u32, i64)>,
    gid: &str,
    now_ms: i64,
) -> bool {
    let e = pulls.entry(gid.to_owned()).or_insert((0, i64::MIN));
    e.0 = e.0.saturating_add(1);
    if e.0 >= 2 && now_ms.saturating_sub(e.1) >= DIR_PULL_GAP_MS {
        e.1 = now_ms;
        true
    } else {
        false
    }
}

/// [`group_commit_in`] 의 동기 몫. 화면에 GroupUpdate 를 낼 seq(들어감·바로 확정)면 `Some`.
#[allow(clippy::too_many_arguments)]
fn group_commit_sync(
    s: &Shared,
    m: &Mls,
    message: &Value,
    gid: &str,
    epoch: u64,
    group_seq: Option<u64>,
    op: &str,
    actor: &str,
    subject: Option<&str>,
    ack: &mut bool,
) -> Option<u64> {
    let dir = dir_view(s);
    let body = message.get("body").cloned().unwrap_or(Value::Null);
    let decode = |f: &str| {
        body.get(f)
            .and_then(|v| v.get("data"))
            .and_then(Value::as_str)
            .and_then(|d| lodelai_crypto::encoding::decode(d, "mls").ok())
    };
    let ctx_members = crate::mls_conn::group_conv(&dir, gid).members;
    let rule_subject = subject.map(user_part);
    let rule_subjects: Vec<String> = message
        .get("subjects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(user_part)
        .collect();
    let ctx = crate::mls_rules::RuleCtx {
        dir: &dir,
        members: &ctx_members,
        expect_sender: message.pointer("/from/device_id").and_then(Value::as_str),
        keep_as: None,
        group: Some(crate::mls_rules::GroupRule {
            op,
            subject: rule_subject.as_deref(),
            subjects: &rule_subjects,
        }),
    };
    let Some(mut g) = crate::mls_conn::load(m, gid.as_bytes()) else {
        // 새 잎 — Welcome 으로(그룹은 commit_final 뒤에만 새 잎에 온다 — 이미 확정).
        let w = decode("welcome")?;
        let joined = crate::mls::join_welcome(
            &m.provider,
            &w,
            crate::mls::Kind::Group,
            gid.as_bytes(),
            &ctx,
        );
        m.provider.scrub();
        return match joined {
            Ok(_) => {
                let seq = group_seq.unwrap_or(0);
                crate::mls_conn::note_group_seq(m, gid.as_bytes(), seq, true);
                crate::mls_conn::remember_conv(
                    m,
                    gid.as_bytes(),
                    message
                        .pointer("/to/address")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
                remove_revoked_leaves(s, m, gid);
                Some(seq)
            }
            Err(e) => {
                tracing::warn!(error = %e, "그룹 Welcome 으로 들어가지 않음");
                None
            }
        };
    };
    let bytes = decode("payload")?;
    let hash = crate::mls::commit_hash(&bytes);
    let r = crate::mls::receive(
        &m.provider,
        &mut g,
        crate::mls::Kind::Group,
        &bytes,
        now_secs(s),
        &ctx,
    );
    m.provider.scrub();
    let vote = |t: &str| {
        json!({"t": t, "group": gid, "epoch": epoch, "commit_hash": lodelai_crypto::encoding::encode(&hash)}).to_string()
    };
    let push = |f: String| {
        if let Ok(mut v) = s.out_frames.lock() {
            v.push(f);
        }
    };
    // #725: 디렉터리 때문의 Retry 가 아니면 그 그룹의 Retry 수를 0 으로(디렉터리가 따라잡았다).
    if !matches!(r, Err(crate::mls::Error::Retry(_))) {
        if let Ok(mut p) = s.dir_pulls.lock() {
            if let Some(e) = p.get_mut(gid) {
                e.0 = 0;
            }
        }
    }
    match r {
        Ok(crate::mls::Received::Staged { joiner, .. }) => {
            if let (Some(j), Ok(mut x)) = (joiner, s.external_joiners.lock()) {
                x.insert((gid.to_owned(), epoch, hash), j);
            }
            let _ = crate::mls_conn::put_commit_meta(
                m,
                gid.as_bytes(),
                epoch,
                &hash,
                op,
                actor,
                subject,
            );
            let Some(seq) = group_seq else {
                push(vote("commit_ack"));
                return None;
            };
            // 이미 확정된 것(쌓인 것에서 처음 받음) — 바로 merge.
            let merged = crate::mls::finalize(&m.provider, &mut g, epoch, &hash).unwrap_or(false);
            m.provider.scrub();
            let _ = crate::mls_conn::take_commit_meta(m, gid.as_bytes(), epoch, &hash);
            merged.then(|| {
                crate::mls_conn::note_group_seq(m, gid.as_bytes(), seq, false);
                seq
            })
        }
        Ok(_) => None,
        Err(crate::mls::Error::Retry(why)) => {
            tracing::info!(why, "그룹 Commit — 디렉터리 갱신 뒤 다시");
            // #725: 같은 그룹에서 또 Retry 면(앞 Commit 이 무효가 되어 다시 온 것) 디렉터리 갱신 하나를 놓쳤을 수 있다 — relay
            // 결함(#702)이 다시 생겨도 스스로 풀리게 directory.list 를 당긴다(그룹당 10초에 한 번).
            let pull = s
                .dir_pulls
                .lock()
                .is_ok_and(|mut p| retry_pull(&mut p, gid, s.clock.now().0));
            if pull {
                tracing::info!(why, "디렉터리를 당겨 온다(#725)");
                push(json!({"t": "directory.list"}).to_string());
            }
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "그룹 Commit 처리 실패 — commit_fail");
            match e {
                // 멈춘 동안 온 것은 ack 하지 않는다 — 풀린 뒤 다시 접속하면 relay 가 다시 준다(§12-19).
                crate::mls::Error::Blocked(_) => *ack = false,
                crate::mls::Error::Stalled(_) => crate::mls_conn::keep_stalled(
                    m,
                    gid.as_bytes(),
                    epoch,
                    &bytes,
                    message,
                    group_seq,
                    now_secs(s),
                ),
                _ => {}
            }
            // 처리 실패(규칙 밖·막힘이 아님): 확정되면 내 몫이 깨진 것 — 다시 들어간다(§4-7).
            let broken = matches!(e, crate::mls::Error::Mls(_));
            if group_seq.is_none() {
                push(vote("commit_fail"));
                if broken {
                    if let Ok(mut f) = s.failed_commits.lock() {
                        f.insert((gid.to_owned(), epoch, hash));
                    }
                }
            } else if broken {
                enqueue_rejoin(s, m, gid);
            }
            None
        }
    }
}

async fn flush_one(s: &Shared, ws: &mut Ws) -> Result<Option<Inflight>, ()> {
    let item = match s.store.peek() {
        Ok(Some(i)) => i,
        Ok(None) => return Ok(None),
        Err(e) => {
            tracing::warn!(error = %e, "큐 읽기 실패");
            return Ok(None);
        }
    };
    // blob 으로 올리는 중인 큰 Handshake(§5c) — 다 올리면 send 로 바뀐다. 첨부·프로필 사진 행은 frame 이 아니라 올리기 작업이
    // 맡는다(연결 루프가 맨 앞을 보고 띄움). 루프가 맨 앞을 본 뒤 여기 오기 전에 그 행이 새로 들어올 수 있다 — 그대로 보내면
    // 빈 frame 이 relay 에 가 protocol 오류가 나고, 행은 빠져 사진·첨부가 조용히 사라졌다(#536). 다음 차례에 맡긴다.
    if matches!(
        item.kind.as_str(),
        "mls_blob" | "upload" | "avatar" | "org_avatar"
    ) {
        return Ok(None);
    }
    // 같은 까닭으로 아직 봉인 안 한 send 행([`mls_head`] 가 맡는 것 — 빈 frame·옛 box)도 보내지 않는다. 보내면 빈 frame 이 가고
    // ack 가 오지 않아 큐가 그 행에서 멈췄다(#536).
    if s.mls.is_some()
        && item.kind == "send"
        && (item.frame.is_empty() || item.frame.contains(r#""enc":"box""#))
    {
        return Ok(None);
    }
    if !send_text(ws, item.frame.clone()).await {
        return Err(());
    }
    if item.kind == "send" {
        Ok(Some(Inflight {
            sent: Instant::now(),
            seq: item.seq,
            msg_id: item.msg_id.unwrap_or_default(),
            to_user: item.peer.unwrap_or_default(),
        }))
    } else {
        if let Err(e) = s.store.remove(item.seq) {
            tracing::warn!(error = %e, "큐 삭제 실패");
        }
        Ok(None)
    }
}

async fn emit(s: &Shared, i: Inbound) -> Result<(), End> {
    s.inbound.send(i).await.map_err(|_| End::Shutdown)
}

async fn reject(
    s: &Shared,
    ack_tx: &mpsc::UnboundedSender<String>,
    message: Value,
    reason: RejectReason,
) -> Result<(), End> {
    let msg_id = message
        .get("msg_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    tracing::warn!(msg_id, reason = reason.code(), "수신 재검증 실패");
    let ack = AckHandle {
        msg_id: msg_id.clone(),
        tx: ack_tx.clone(),
    };
    emit(
        s,
        Inbound::Rejected {
            msg_id,
            reason,
            message,
            ack,
        },
    )
    .await
}

/// 내 다른 기기가 상대에게 보낸 것의 사본: Handshake(Commit)는 처리해 epoch 를 따라가고, 응용 메시지는 열어 코어에 '보낸 글'로
/// 넘긴다(§7 10-27 결정 — chat·reply·rejected·request·reaction(#626), system 은 거두기만). 그 밖은 받았다고만 한다.
async fn own_copy(
    s: &Shared,
    ack_tx: &mpsc::UnboundedSender<String>,
    message: Value,
    group_seq: Option<u64>,
) -> Result<(), End> {
    let shown = match message.get("kind").and_then(Value::as_str) {
        Some("mls" | "chat" | "reply" | "rejected" | "request" | "reaction") => true,
        Some("system") => message.get("reason").and_then(Value::as_str) == Some("withdrawn"),
        _ => false,
    };
    if shown {
        return deliver(s, ack_tx, message, false, group_seq).await;
    }
    if let Some(id) = message.get("msg_id").and_then(Value::as_str) {
        let _ = ack_tx.send(id.to_owned());
    }
    Ok(())
}

/// 재검증을 통과한(또는 보류할) 메시지의 봉투를 열어 core 에 넘긴다(e2e-envelope §3.4·§5).
/// `system` 은 빈 평문이어야 하고, 그 밖은 봉투를 열어 `body` 를 평문으로 바꾼다. 이 기기 앞 항목이 없으면 `Unreadable`.
async fn deliver(
    s: &Shared,
    ack_tx: &mpsc::UnboundedSender<String>,
    message: Value,
    held: bool,
    group_seq: Option<u64>,
) -> Result<(), End> {
    let msg_id = message
        .get("msg_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let kind = message
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if kind != "mls"
        && message.get("mls_group").is_some()
        && s.holding.load(std::sync::atomic::Ordering::SeqCst)
    {
        tracing::info!(
            msg_id,
            "끊는 중 — 그룹 글을 받지 않음(폐기 뒤 새 기기로 다시 온다)"
        );
        return Ok(());
    }
    // 받는 판 범위 밖(v0 평문 등)은 열지 않는다 — relay 도 거부하지만 서버는 반신뢰다(다운그레이드 방지, e2e-envelope §8).
    // 판이 섞여 돈다(#598 — 메시지 v 는 쓰는 칸의 판): [PROTOCOL_MIN, min(내 판, MESSAGE_V_MAX)](#613 — 판 11 은 연결 판).
    let version_ok = message.get("v").and_then(Value::as_u64).is_some_and(|v| {
        (u64::from(lodelai_protocol::PROTOCOL_MIN)
            ..=u64::from(s.config.protocol.min(lodelai_protocol::MESSAGE_V_MAX)))
            .contains(&v)
    });
    // 묶음 22 §9: 이 MLS 메시지의 그룹 막힘 상태가 바뀌면 코어에 알린다(처리 뒤 견줌).
    let conv = s.mls.as_deref().filter(|_| version_ok).and_then(|m| {
        let mls_msg =
            kind == "mls" || message.pointer("/body/enc").and_then(Value::as_str) == Some("mls");
        let (gid, conversation) =
            crate::mls_conn::conversation_of(&dir_view(s), &message, &s.config.user, &s.me_address)
                .filter(|_| mls_msg)?;
        crate::mls_conn::remember_conv(m, &gid, &conversation);
        let _ = m.provider.storage().update_seen(&gid, s.clock.now().0);
        let lost = |gid: &[u8]| m.provider.storage().lost(gid).ok().flatten();
        let before = (crate::mls_conn::blocked(m, &gid), lost(&gid));
        let new = crate::mls_conn::load(m, &gid).is_none();
        Some((m, gid, conversation, before, new))
    });
    let r = deliver_in(
        s, ack_tx, message, held, group_seq, kind, version_ok, msg_id,
    )
    .await;
    if let Some((m, gid, conversation, before, new)) = conv {
        // 방금 들어갔다 — 마지막 수단 KeyPackage 로 들어왔으면 그 그룹이 Update 때다(§7). 그 뒤 쓰는 글보다 먼저 나가게 지금 본다.
        if new && crate::mls_conn::load(m, &gid).is_some() {
            // Welcome 으로 든 것도 '들기 끝'이다(#616) — 그 전에 넣어 물러서 있던 다시 들기 행(혼자 남은 새 기기의 §9 ① 바로 들기 등)이
            // 뒤늦게 external commit 을 한 번 더 내면, 그 확정 전 틈에 온 글을 이 기기가 읽지 못한다. 겹친 행으로 빼게 적는다.
            if let Ok(mut r) = s.rejoined.lock() {
                r.insert(gid.clone(), s.clock.now().0);
            }
            if let Ok(mut at) = s.update_checked.lock() {
                *at = None;
            }
            due_updates(s, m);
        }
        // 막힘이 바뀌었거나 막힌 동안 처음 글을 버렸다(lost_since).
        let st = m.provider.storage();
        let state = crate::mls_conn::blocked(m, &gid);
        let mut lost_since = st.lost(&gid).ok().flatten();
        // 막힘 없이 잃은 글 표시가 있으면(풀림·§12-27 ⓐ rejoin_needed) 지우고 반드시 알린다 — 지우기만 하고 앞과 같다고 건너뛰면
        // 표시가 사라진다.
        let released = state.is_none() && lost_since.is_some();
        if released {
            lost_since = st.take_lost(&gid).ok().flatten();
        }
        if released || (state, lost_since) != before {
            emit(
                s,
                Inbound::ConversationSync {
                    conversation,
                    state,
                    lost_since,
                },
            )
            .await?;
        }
    }
    r
}

#[allow(clippy::too_many_arguments)]
async fn deliver_in(
    s: &Shared,
    ack_tx: &mpsc::UnboundedSender<String>,
    mut message: Value,
    held: bool,
    group_seq: Option<u64>,
    kind: String,
    version_ok: bool,
    msg_id: String,
) -> Result<(), End> {
    let kind = kind.as_str();
    // 묶음 22: Handshake(kind mls)는 코어에 가지 않는다 — 처리하고 ack(디렉터리가 늦으면 ack 하지 않아 다시 받는다).
    if kind == "mls" {
        let handled = match s.mls.as_deref() {
            Some(m) if version_ok => {
                let dir = dir_view(s);
                crate::mls_conn::handle_handshake(m, &dir, &message, now_secs(s))
            }
            _ => crate::mls_conn::Handled::Done,
        };
        if let crate::mls_conn::Handled::Rejoin(gid) = &handled {
            if let Some(m) = s.mls.as_deref() {
                enqueue_rejoin(s, m, gid);
            }
        }
        // #725: 1:1 Handshake 도 디렉터리 때문에 또 다시면 당겨 온다 — 그룹 Commit 과 같은 규칙.
        if let crate::mls_conn::Handled::RetryDir(key) = &handled {
            if s.dir_pulls
                .lock()
                .is_ok_and(|mut p| retry_pull(&mut p, key, s.clock.now().0))
            {
                tracing::info!("디렉터리를 당겨 온다(#725, Handshake)");
                if let Ok(mut v) = s.out_frames.lock() {
                    v.push(json!({"t": "directory.list"}).to_string());
                }
            }
        } else if let Some(key) = handshake_key(&message) {
            // 디렉터리 Retry 가 아니게 처리했다 — 그 대화의 수를 0 으로.
            if let Ok(mut p) = s.dir_pulls.lock() {
                if let Some(e) = p.get_mut(&key) {
                    e.0 = 0;
                }
            }
        }
        if !matches!(
            handled,
            crate::mls_conn::Handled::Retry | crate::mls_conn::Handled::RetryDir(_)
        ) {
            let _ = ack_tx.send(msg_id);
        }
        return Ok(());
    }
    let mls_body = message.pointer("/body/enc").and_then(Value::as_str) == Some("mls");
    // 그룹 변경 Commit(묶음 22 h1) — 코어에는 확정 때 GroupUpdate 로만.
    if kind == "group"
        && mls_body
        && message.pointer("/body/wire").and_then(Value::as_str) == Some("commit")
    {
        let ack = match (s.mls.as_deref(), version_ok) {
            (Some(m), true) => group_commit_in(s, m, &message, group_seq).await?,
            _ => true,
        };
        if ack {
            let _ = ack_tx.send(msg_id);
        }
        return Ok(());
    }
    let opened = if !version_ok {
        Err(EnvelopeError::BadEnvelope("v"))
    } else if mls_body {
        match s.mls.as_deref() {
            Some(m) => crate::mls_conn::open_app(m, &dir_view(s), &message, now_secs(s)),
            None => Err(EnvelopeError::Unreadable),
        }
    } else if kind == "system" {
        let empty_plain = message.pointer("/body/enc").and_then(Value::as_str) == Some("plain")
            && message.pointer("/body/text").and_then(Value::as_str) == Some("");
        if empty_plain {
            Ok(String::new())
        } else {
            Err(EnvelopeError::BadEnvelope("system 은 빈 평문"))
        }
    } else {
        // box 봉투(묶음 22 전)는 relay 가 받지 않는다 — MLS·빈 system 밖은 꼴 오류.
        Err(EnvelopeError::BadEnvelope("enc"))
    };
    let ack = AckHandle {
        msg_id,
        tx: ack_tx.clone(),
    };
    // 그룹 변경 app op(MLS)는 core 로 넘기지 않고 여기서 처리한다(ack 도 여기서). MLS 아닌 kind group 은 꼴 오류.
    if message.get("kind").and_then(Value::as_str) == Some("group") && mls_body {
        // MLS 그룹의 app op(§12-13 ②·§12-23): leave·rename. 못 열면 버린다(그룹 밖이거나 지난 epoch).
        ack.ack();
        if let (Ok(text), Some(m)) = (opened, s.mls.as_deref()) {
            group_app_in(s, m, &message, &text, group_seq).await?;
        }
        return Ok(());
    }
    if message.get("kind").and_then(Value::as_str) == Some("group") {
        return reject(s, ack_tx, message, RejectReason::BadEnvelope).await;
    }
    // MLS 응용 메시지 평문(§12-17): 머리 한 줄 + 본문 원 바이트. 첨부면 묶음 15 json1 으로 다시 엮어 아래 펼치기로.
    let mut mls_files = false;
    let mut origin = serde_json::Map::new();
    // 처음 출처 칸은 내가 보낸 것(내 다른 기기 → 서명 확인이 OwnCopy 로 가른 것)만 믿는다(#490 28 §2).
    let from_me = message
        .pointer("/from/address")
        .and_then(Value::as_str)
        .and_then(|a| a.split('@').next())
        == Some(s.config.user.as_str());
    let opened = match opened {
        Ok(t) if mls_body => match crate::mls_conn::split_plaintext(&t) {
            Some((_, Some(json1), o)) => {
                mls_files = true;
                origin = o;
                Ok(json1)
            }
            Some((body, None, o)) => {
                origin = o;
                Ok(body)
            }
            None => Err(EnvelopeError::BadEnvelope("mls_plaintext")),
        },
        other => other,
    };
    let pt_json1 =
        message.pointer("/body/pt").and_then(Value::as_str) == Some("json1") || mls_files;
    let has_blobs = message.get("blobs").is_some();
    match opened {
        // 첨부(묶음 15): pt=json1 이면 펼치고 받을 것을 적는다. 모양이 틀리거나 헤더 blobs 와 어긋나면 bad_envelope.
        Ok(text) if pt_json1 || has_blobs => {
            let unpacked = if pt_json1 && has_blobs {
                crate::files::unpack(&message, &text)
            } else {
                None
            };
            let Some((body, jobs)) = unpacked else {
                tracing::warn!(msg_id = ack.msg_id, "첨부 본문이 헤더와 맞지 않음");
                return reject(s, ack_tx, message, RejectReason::BadEnvelope).await;
            };
            // held 면 믿을 때까지 받지 않는다(§4a — 확인 안 한 기기가 디스크를 채우지 못하게). 코어가 release·drop 한다.
            for d in &jobs {
                if let Err(e) = s.store.add_download(d, held) {
                    tracing::warn!(error = %e, "받을 첨부 기록 실패");
                }
            }
            message["body"] = body;
            crate::mls_conn::origin_into(&mut message["body"], origin, from_me);
            if held {
                emit(s, Inbound::Held { message, ack }).await
            } else {
                emit(s, Inbound::Deliver { message, ack }).await
            }
        }
        Ok(text) => {
            message["body"] = json!({"enc": "plain", "text": text});
            crate::mls_conn::origin_into(&mut message["body"], origin, from_me);
            if held {
                emit(s, Inbound::Held { message, ack }).await
            } else {
                emit(s, Inbound::Deliver { message, ack }).await
            }
        }
        Err(EnvelopeError::Unreadable) => {
            message["body"] = json!({"enc": "plain", "text": ""});
            emit(s, Inbound::Unreadable { message, ack }).await
        }
        Err(e) => {
            tracing::warn!(msg_id = ack.msg_id, error = %e, "봉투를 열 수 없음");
            reject(s, ack_tx, message, RejectReason::BadEnvelope).await
        }
    }
}

/// `stale_epoch` 물러섬 상한: 2초부터 두 배씩 60초까지, 이 횟수(1시간 남짓 — relay 의 확정 전 Commit 수명)를 넘으면 실패.
const STALE_MAX: u32 = 70;

/// `stale_epoch` 로 돌아온 행을 물러서게 하고 `true`. 상한을 넘었으면 기록을 지우고 `false`(그 행은 nack 으로 실패).
fn stale_backoff(s: &Shared, seq: i64) -> bool {
    let Ok(mut w) = s.row_wait.lock() else {
        return true;
    };
    let tries = w.get(&seq).map_or(0, |(t, _)| *t) + 1;
    if tries > STALE_MAX {
        tracing::warn!(seq, "stale_epoch 가 {STALE_MAX}번 — 실패 처리");
        w.remove(&seq);
        return false;
    }
    let wait = Duration::from_secs(1u64 << tries.min(6)).min(BOOT_BACKOFF);
    w.insert(seq, (tries, Instant::now() + wait));
    true
}

/// 그룹 epoch 가 움직였다(확정·무효) — 물러선 행의 기다림만 풀고 횟수는 둔다(상한은 그대로 센다).
fn wake_stale(s: &Shared) {
    if let Ok(mut w) = s.row_wait.lock() {
        let now = Instant::now();
        for (_, until) in w.values_mut() {
            *until = now;
        }
    }
    s.wake.notify_one();
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame(
    s: &Shared,
    ws: &mut Ws,
    frame: Value,
    inflight: &mut Option<Inflight>,
    waiting: &mut VecDeque<Waiting>,
    directory_requested: &mut bool,
    ack_tx: &mpsc::UnboundedSender<String>,
) -> Result<(), End> {
    let t = frame.get("t").and_then(Value::as_str).unwrap_or_default();
    let msg_id = || {
        frame
            .get("msg_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    match t {
        "ack" | "nack" => {
            let id = msg_id();
            if inflight.as_ref().is_none_or(|f| f.msg_id != id) {
                // ack 로 행을 뺀 뒤 쥔 N+1 응용 메시지가 무효됐다(§12-13④·§12-14③). 이 기기는 pending 중에도 epoch N 으로
                // 봉인해(§12-21) 이 길로 올 일이 없고 평문도 남기지 않는다 — 다시 보낼 수 없으니 보내기 실패로 알린다.
                if t == "nack" && frame.get("reason").and_then(Value::as_str) == Some("commit_void")
                {
                    tracing::warn!(msg_id = id, "쥔 응용 메시지 무효 — 보내기 실패");
                    emit(
                        s,
                        Inbound::Nack {
                            msg_id: id,
                            reason: "commit_void".into(),
                        },
                    )
                    .await?;
                }
                return Ok(());
            }
            let Some(f) = inflight.take() else {
                return Ok(());
            };
            let seq = f.seq;
            // 내 group Commit 이 거절됐다(stale_epoch·invalid_commit·unroutable…) — 쥔 pending Commit 을 버린다. 안 버리면 그
            // 그룹의 다음 행이 영영 기다린다. stale_epoch 면 아래에서 지금 epoch 로 다시 만든다.
            let mut create_failed = false;
            if t == "nack" {
                if let Some(m) = s.mls.as_deref() {
                    clear_own_commit(s, m, seq);
                    // 거절된 external commit(보낼 때 이미 merge 함) — 그 상태를 버린다(stale_epoch 면 행이 다시 GroupInfo 부터).
                    if let Some(gid) = rejoin_row_gid(s, seq) {
                        if s.rejoining
                            .lock()
                            .ok()
                            .and_then(|mut r| r.remove(&gid))
                            .is_some()
                        {
                            crate::mls_conn::drop_group(m, gid.as_bytes());
                        }
                        // 거절된 다시 들어가기(#577 실기 확인 ❌-1 — relay 가 거절하면 행이 빠져 이번 실행엔 다시 보지 않았다):
                        // 다음 디렉터리·주기 검사 때 다시 든다.
                        if let Ok(mut t) = s.orphan_tried.lock() {
                            t.remove(&gid);
                        }
                    }
                    // create Commit 이 stale 말고 거절됐다(KeyPackage 문제 등) — 새 KeyPackage 로 한 번 다시, 또 거절이면
                    // 혼자 남은 그룹을 지우고 만들기 실패(internal).
                    let reason = frame.get("reason").and_then(Value::as_str);
                    if reason != Some("stale_epoch") {
                        if let Some(gid) = create_row_gid(s, seq) {
                            let first = s
                                .create_retried
                                .lock()
                                .map(|mut r| r.insert(seq))
                                .unwrap_or(false);
                            if first {
                                tracing::warn!(?reason, "create Commit 거절 — 한 번 다시");
                                // 새 KeyPackage 로(#605) — 앞서 가져온 것으로 다시 봉인하면 같은 거절이 온다.
                                if let Ok(mut k) = s.row_kps.lock() {
                                    k.remove(&seq);
                                }
                                let _ = s.store.reseal(seq, "");
                                return Ok(());
                            }
                            if let Ok(mut r) = s.create_retried.lock() {
                                r.remove(&seq);
                            }
                            crate::mls_conn::drop_group(m, gid.as_bytes());
                            create_failed = true;
                        }
                    }
                }
            }
            // MLS 메시지의 epoch 가 맞지 않다(§12-11 ⓑ·남의 Commit 이 확정 전 — §4-7) — 물러섰다가 평문에서 지금 epoch 로
            // 다시 봉인한다(행은 맨 앞에 둔다). 1시간을 넘게 계속이면 그 행을 실패로.
            if t == "nack"
                && s.mls.is_some()
                && frame.get("reason").and_then(Value::as_str) == Some("stale_epoch")
                && stale_backoff(s, seq)
            {
                if let Err(e) = s.store.reseal(seq, "") {
                    tracing::warn!(error = %e, "다시 봉인 표시 실패");
                }
                return Ok(());
            }
            // 첨부를 묶지 못했다(F8) — 한 번은 새 예약으로 다시 올리고, 그다음은 upload_failed.
            let mut upload_failed = false;
            if t == "nack"
                && frame.get("reason").and_then(Value::as_str) == Some("blob_unavailable")
            {
                let spec = s
                    .store
                    .upload_spec(seq)
                    .ok()
                    .flatten()
                    .and_then(|x| serde_json::from_str::<crate::outbox::UploadSpec>(&x).ok());
                if let Some(mut spec) = spec {
                    if spec.attempts < 1 {
                        spec.attempts += 1;
                        let again = serde_json::to_string(&spec).unwrap_or_default();
                        if s.store.demote_to_upload(seq, &again).unwrap_or(false) {
                            return Ok(());
                        }
                    }
                    upload_failed = true;
                }
            }
            // app 으로 가는 내 op(rename·내 leave)만 — duty 로 낸 남의 leave Commit(subject 가 남)을 내 나가기로 보고 그룹을
            // 지우지 않게(#499).
            let own_group_app = (t == "ack")
                .then(|| s.store.plain_of(seq).ok().flatten())
                .flatten()
                .flatten()
                .and_then(|p| serde_json::from_str::<Value>(&p).ok())
                .filter(|p| {
                    p.get("kind").and_then(Value::as_str) == Some("group")
                        && match p.get("group_op").and_then(Value::as_str) {
                            Some("rename") => true,
                            Some("leave") => p
                                .get("subject")
                                .and_then(Value::as_str)
                                .is_none_or(|x| x == s.me_address),
                            _ => false,
                        }
                });
            if let Err(e) = s.store.remove(seq) {
                tracing::warn!(error = %e, "큐 삭제 실패");
            }
            if let Ok(mut w) = s.row_wait.lock() {
                w.remove(&seq);
            }
            if let Ok(mut k) = s.row_kps.lock() {
                k.remove(&seq);
            }
            if let (Some(p), Some(m)) = (own_group_app, s.mls.as_deref()) {
                let group_seq = frame.get("group_seq").and_then(Value::as_u64);
                let mut p = p;
                if p.get("group_op").and_then(Value::as_str) == Some("leave") {
                    p["subject"] = Value::String(s.me_address.clone());
                }
                let text = p
                    .pointer("/body/text")
                    .and_then(Value::as_str)
                    .and_then(|t| serde_json::from_str::<Value>(t).ok())
                    .and_then(|b| b.get("name").cloned())
                    .map(|n| format!("{}\n", json!({"v": 1, "meta": {"name": n}})))
                    .unwrap_or_else(|| "{\"v\":1}\n".to_owned());
                group_app_in(s, m, &p, &text, group_seq).await?;
            }
            if t == "ack" {
                if let Err(e) = s.store.mark_sent(&id, &f.to_user) {
                    tracing::warn!(error = %e, "보낸 기록 실패");
                }
                emit(s, Inbound::Ack { msg_id: id }).await?;
            } else {
                let reason = if upload_failed {
                    "upload_failed".to_owned()
                } else {
                    frame
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                let reason = if create_failed {
                    "internal".to_owned()
                } else {
                    reason
                };
                emit(s, Inbound::Nack { msg_id: id, reason }).await?;
            }
        }
        "deliver" => {
            let Some(message) = frame.get("message").cloned() else {
                return Ok(());
            };
            let group_seq = frame.get("group_seq").and_then(Value::as_u64);
            // 그룹 끔(묶음 16 §3b): 꺼진 relay 는 보내지 않지만 반신뢰 — 저장·전달 없이 받았다고만 한다.
            if !s.config.groups && crate::is_group_message(&message) {
                let msg_id = message
                    .get("msg_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                tracing::warn!(msg_id, "그룹 꺼짐 — 그룹 메시지를 버림");
                let _ = ack_tx.send(msg_id);
                return Ok(());
            }
            let verdict = keys::verify(&s.store, &message, &s.config.user, &s.config.server_name);
            // blob 칸이 있는 group Handshake(§5c) — 서명은 지금 본 그대로, 받아 채운 뒤 처리(ack 는 그때).
            if s.mls.is_some()
                && crate::mls_blob::has_blobs(&message)
                && matches!(verdict, Ok(Verdict::Ok | Verdict::Held | Verdict::OwnCopy))
            {
                let held = matches!(verdict, Ok(Verdict::Held));
                if let Ok(mut j) = s.blob_jobs.lock() {
                    let id = message.get("msg_id").cloned();
                    let dup = j.iter().any(|x| {
                        matches!(x, BlobJob::Deliver { message: m, .. } if m.get("msg_id") == id.as_ref())
                    });
                    if !dup {
                        j.push_back(BlobJob::Deliver {
                            message,
                            held,
                            group_seq,
                        });
                    }
                }
                return Ok(());
            }
            match verdict {
                Ok(Verdict::Ok) => deliver(s, ack_tx, message, false, group_seq).await?,
                Ok(Verdict::Held) => deliver(s, ack_tx, message, true, group_seq).await?,
                Ok(Verdict::OwnCopy) => {
                    // 접속 때 다시 받은 사본이면 relay 가 지금 보낸 쪽 상태를 싣는다(§7) — 서명 검사 뒤에 붙인다.
                    let mut message = message;
                    if let Some(v) = frame.get("sender_view").and_then(Value::as_str) {
                        message["sender_view"] = Value::String(v.to_owned());
                    }
                    own_copy(s, ack_tx, message, group_seq).await?;
                }
                Ok(Verdict::Reject(r)) => reject(s, ack_tx, message, r).await?,
                Ok(Verdict::UnknownDevice(_)) => {
                    if !*directory_requested
                        && !send_text(ws, json!({"t": "directory.list"}).to_string()).await
                    {
                        return Err(End::AfterReady);
                    }
                    *directory_requested = true;
                    waiting.push_back(Waiting {
                        message,
                        group_seq,
                        since: Instant::now(),
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "재검증 중 저장 오류 — ack 하지 않음(다시 온다)")
                }
            }
        }
        "status" => {
            let g = |k: &str| frame.get(k).and_then(Value::as_str).map(str::to_owned);
            emit(
                s,
                Inbound::Status {
                    msg_id: msg_id(),
                    state: g("state").unwrap_or_default(),
                    abort_reason: g("abort_reason"),
                    fail_reason: g("fail_reason"),
                    at: g("at").unwrap_or_default(),
                    by: g("by"),
                },
            )
            .await?;
        }
        // 그룹 끔(§3b)이면 꺼진 relay 는 보내지 않지만 반신뢰 — 조직 빠짐 힌트도 쓰지 않는다(QA 🟢 #480).
        "groups" if !s.config.groups => {
            tracing::warn!("그룹 꺼짐 — groups 프레임을 버림");
        }
        // relay 가 알린 그룹 목록 — 새 기기 스스로 들어가기(§7)의 group 후보로만 쓴다. 조직 빠짐은 relay 의 org_left Commit(§12-13).
        "groups" => {
            if let Ok(mut k) = s.known_groups.lock() {
                let k = k.get_or_insert_with(Default::default);
                for it in frame
                    .get("items")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(g) = it
                        .get("group")
                        .and_then(Value::as_str)
                        .and_then(crate::group_io::gid_of)
                    {
                        k.insert(g.to_owned());
                    }
                }
            }
        }
        "directory" | "directory.update" => {
            *directory_requested = false;
            let now_ms = keys::wall_ms();
            match keys::learn_directory(
                &s.store,
                &frame,
                &s.config.user,
                s.config.keys.device_id().as_str(),
                &s.config.server_name,
                now_ms,
            ) {
                Ok(learned) => {
                    for l in learned {
                        match l {
                            Learned::CertTrusted(p) | Learned::CertLost(p) => {
                                emit(s, Inbound::DeviceTrust(p)).await?;
                            }
                            Learned::NewDevice(p) => {
                                emit(
                                    s,
                                    Inbound::NewDevice {
                                        user: p.user.clone(),
                                        device_id: p.device_id.clone(),
                                    },
                                )
                                .await?;
                                emit(s, Inbound::DeviceTrust(p)).await?;
                            }
                            Learned::FirstContact(p) | Learned::Revoked(p) => {
                                emit(s, Inbound::DeviceTrust(p)).await?;
                            }
                            Learned::Mismatch { user, device_id } => {
                                emit(s, Inbound::KeyMismatch { user, device_id }).await?;
                            }
                            Learned::RootChanged { user, root } => {
                                emit(s, Inbound::RootChanged { user, root }).await?;
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "디렉터리 키 저장 실패"),
            }
            // 내가 믿는 내 다른 기기 중 내 서명이 없는 것에 서명(§7a-1 자동 재서명). relay 가 같은 쌍·같은 서명은 저장·방송을
            // 건너뛰고, 방송된 디렉터리에 내 서명이 보이면 여기서 더 보내지 않는다.
            match keys::to_certify(
                &s.store,
                &frame,
                &s.config.user,
                s.config.keys.device_id().as_str(),
            ) {
                Ok(want) => {
                    for (device_id, x) in want {
                        if let Err(e) = keys::queue_certify(
                            &s.store,
                            &s.config.keys,
                            &s.config.server_name,
                            &s.config.user,
                            &device_id,
                            &x,
                        ) {
                            tracing::warn!(error = %e, device_id, "내 기기 서명 큐 실패");
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "서명할 내 기기 찾기 실패"),
            }
            if let Ok(mut d) = s.directory.write() {
                *d = frame.clone();
            }
            emit(s, Inbound::Directory(frame)).await?;
            // 기다리던 deliver 를 다시 본다.
            let pending: Vec<Waiting> = waiting.drain(..).collect();
            for w in pending {
                match keys::verify(&s.store, &w.message, &s.config.user, &s.config.server_name) {
                    Ok(Verdict::Ok) => deliver(s, ack_tx, w.message, false, w.group_seq).await?,
                    Ok(Verdict::Held) => deliver(s, ack_tx, w.message, true, w.group_seq).await?,
                    Ok(Verdict::OwnCopy) => own_copy(s, ack_tx, w.message, w.group_seq).await?,
                    Ok(Verdict::Reject(r)) => reject(s, ack_tx, w.message, r).await?,
                    Ok(Verdict::UnknownDevice(_)) => {
                        reject(s, ack_tx, w.message, RejectReason::BadSignature).await?
                    }
                    Err(e) => tracing::warn!(error = %e, "재검증 중 저장 오류"),
                }
            }
            // 멈춘 대화를 새 디렉터리로 다시 본다(§12-19) — 풀리면 다시 접속해 멈춘 동안 받지 않은 것을 받는다.
            if let Some(m) = s.mls.as_deref() {
                if redrive_stalled(s, m).await? {
                    return Err(End::AfterReady);
                }
                // 끊기가 끝나 잎 자격을 얻었으면 바로 든다(#577 §9 ① — update_check 간격을 기다리지 않는다). 폐기·recovered 뒤에도
                // relay 가 directory.update 를 보내므로 여기 한 곳이면 된다.
                due_orphan(s, m);
            }
        }
        "ping" => {
            if !send_text(ws, json!({"t": "pong"}).to_string()).await {
                return Err(End::AfterReady);
            }
        }
        "error" => {
            let code = frame
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            tracing::warn!(code, message = ?frame.get("message"), "relay 오류");
            if code == "rate_limited" {
                return Err(End::RateLimited);
            }
            // 내 send 가 형식 오류로 거부됐다(ref = msg_id) → nack 와 같다. 다시 보내도 같은 결과라 큐에서 뺀다.
            let r = frame.get("ref").and_then(Value::as_str);
            if let (Some(r), Some(f)) = (r, inflight.as_ref()) {
                // #537: relay 가 이 send 를 처리하지 못했다(DB 등) — 형식 오류가 아니니 빼지 않고 다시 접속해 다시 보낸다.
                if r == f.msg_id && code == "internal" {
                    return Err(End::Unanswered);
                }
                if r == f.msg_id {
                    let (seq, id) = (f.seq, f.msg_id.clone());
                    *inflight = None;
                    if let Err(e) = s.store.remove(seq) {
                        tracing::warn!(error = %e, "큐 삭제 실패");
                    }
                    emit(
                        s,
                        Inbound::Nack {
                            msg_id: id,
                            reason: "protocol".into(),
                        },
                    )
                    .await?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod requeued_tests {
    use super::{requeued_verdict, Requeued};
    use serde_json::json;

    fn st(members: &[&str], admins: &[&str]) -> crate::GroupState {
        crate::GroupState {
            name: "팀".into(),
            members: members.iter().map(|m| (*m).to_owned()).collect(),
            admins: admins.iter().map(|m| (*m).to_owned()).collect(),
            seq: 3,
            stale: false,
            waiting_trust: None,
            unconfirmed_changes: 0,
            joined_seq: 1,
        }
    }

    const A: &str = "alice@local";
    const B: &str = "bob@local";
    const C: &str = "carol@local";

    /// §12-27 ⓒ 네 갈래(설계 aa571abc): 이미 빠짐 → 안 보냄 / 관리자 해제 → 실패 / 같은 키의 더 나중 변경 → 안 보냄 /
    /// 그대로 할 수 있음 → 보냄. admin 은 목표값(asked.admin)이 이미 그 값이면 안 보냄.
    #[test]
    fn 다시_낸_변경은_지금_상태로_다시_본다() {
        let rm = json!({"op": "remove", "subject": C, "tries": 1, "orig": "X"});
        let v = |op, asked: &serde_json::Value, st: &crate::GroupState, latest| {
            requeued_verdict(op, asked, C, A, Some(st), latest, "X")
        };
        // 이미 빠짐.
        assert_eq!(
            v("remove", &rm, &st(&[A, B], &[A, B]), None),
            Requeued::Skip
        );
        // 내가 관리자가 아님·그룹에서 빠짐.
        assert_eq!(
            v("remove", &rm, &st(&[A, B, C], &[B]), None),
            Requeued::Fail
        );
        assert_eq!(v("remove", &rm, &st(&[B, C], &[B]), None), Requeued::Fail);
        assert_eq!(
            requeued_verdict("remove", &rm, C, A, None, None, "X"),
            Requeued::Fail
        );
        // 같은 키의 더 나중 변경.
        assert_eq!(
            v("remove", &rm, &st(&[A, B, C], &[A]), Some("Y")),
            Requeued::Skip
        );
        // 그대로 할 수 있음(마지막 변경이 자기 자신이어도).
        assert_eq!(
            v("remove", &rm, &st(&[A, B, C], &[A]), None),
            Requeued::Send
        );
        assert_eq!(
            v("remove", &rm, &st(&[A, B, C], &[A]), Some("X")),
            Requeued::Send
        );
        // admin: 목표값이 이미 그 값이면 안 보냄, 아니면 보냄.
        let make = json!({"op": "admin", "subject": C, "admin": true, "tries": 1, "orig": "X"});
        assert_eq!(
            v("admin", &make, &st(&[A, C], &[A, C]), None),
            Requeued::Skip
        );
        assert_eq!(v("admin", &make, &st(&[A, C], &[A]), None), Requeued::Send);
        let drop = json!({"op": "admin", "subject": C, "admin": false, "tries": 1, "orig": "X"});
        assert_eq!(v("admin", &drop, &st(&[A, C], &[A]), None), Requeued::Skip);
        assert_eq!(
            v("admin", &drop, &st(&[A, C], &[A, C]), None),
            Requeued::Send
        );
        assert_eq!(v("admin", &drop, &st(&[A, C], &[C]), None), Requeued::Fail);
    }
}

#[cfg(test)]
mod take_rejoin_tests {
    use super::{take_rejoin, RejoinResult};

    /// #645 재현: 새 기기가 external commit(epoch 2)을 보낸 뒤 다른 기기의 epoch 1 확정이 늦게 닿는다(결과 순서 뒤집힘). 그
    /// 결과는 기다림을 지우지 않고, 뒤에 온 내 epoch 2 확정이 그것을 꺼낸다.
    #[test]
    fn 늦게_닿은_앞_epoch_결과는_다시_들기_기다림을_지우지_않는다() {
        let mut r = std::collections::HashMap::new();
        r.insert("g".to_owned(), (2, [2u8; 32]));
        assert_eq!(
            take_rejoin(&mut r, "g", 1, &[1u8; 32], true),
            RejoinResult::Keep
        );
        assert_eq!(
            take_rejoin(&mut r, "x", 2, &[2u8; 32], true),
            RejoinResult::Keep,
            "다른 그룹"
        );
        assert!(r.contains_key("g"));
        assert_eq!(
            take_rejoin(&mut r, "g", 2, &[2u8; 32], true),
            RejoinResult::Mine
        );
        assert!(r.is_empty());
    }

    /// #645 설계 리뷰 🟡: 같은·높은 epoch 의 남의 확정이 오면(내 무효를 끊긴 채 놓침) 기다림을 지우고 다시 든다.
    #[test]
    fn 높은_epoch_남의_확정이면_기다림을_지우고_다시_든다() {
        for epoch in [2, 3] {
            let mut r = std::collections::HashMap::new();
            r.insert("g".to_owned(), (2, [2u8; 32]));
            assert_eq!(
                take_rejoin(&mut r, "g", epoch, &[9u8; 32], true),
                RejoinResult::Superseded((2, [2u8; 32])),
                "epoch {epoch}"
            );
            assert!(r.is_empty());
        }
        // 남의 Commit 의 무효는 내 것을 막지 않는다 — 기다림 그대로.
        let mut r = std::collections::HashMap::new();
        r.insert("g".to_owned(), (2, [2u8; 32]));
        assert_eq!(
            take_rejoin(&mut r, "g", 2, &[9u8; 32], false),
            RejoinResult::Keep
        );
        assert!(r.contains_key("g"));
    }
}

#[cfg(test)]
mod healthz_max_tests {
    use super::{remembered_max, HEALTHZ_MAX_TTL};

    /// #557: 터널 뒤 relay 의 healthz 판 max 는 주소마다 한 시간 기억한다(그 뒤 다시 본다).
    #[test]
    fn remembered_healthz_max_expires_after_ttl() {
        let t0 = std::time::Instant::now();
        let mut m = std::collections::HashMap::new();
        m.insert("wss://a.example/v1/ws".to_owned(), (t0, 8u32));
        assert_eq!(remembered_max(&m, "wss://a.example/v1/ws", t0), Some(8));
        assert_eq!(remembered_max(&m, "wss://b.example/v1/ws", t0), None);
        assert_eq!(
            remembered_max(&m, "wss://a.example/v1/ws", t0 + HEALTHZ_MAX_TTL),
            None
        );
    }
}

#[cfg(test)]
mod kp_wait_tests {
    use super::{kp_wait, KpWait, BOOT_BACKOFF, GROUP_KP_TRIES, NO_DEVICE_TRIES};
    use std::time::Duration;

    /// #605 리뷰 🔴: KeyPackage 를 끝내 못 올리는 멤버가 있으면 상한(약 3분) 뒤 실패로 끝나 outbox 맨 앞 줄을 푼다.
    #[test]
    fn 끝내_오지_않는_keypackage_는_상한_뒤_실패() {
        let mut waited = Duration::ZERO;
        let mut tries = 0;
        while kp_wait(false, false, tries) == KpWait::Again {
            // 연결 루프의 물러섬과 같은 꼴(2·4·8…60초).
            waited += Duration::from_secs(2u64.saturating_mul(1 << tries.min(5))).min(BOOT_BACKOFF);
            tries += 1;
        }
        assert_eq!(kp_wait(false, false, tries), KpWait::Fail);
        assert_eq!(tries + 1, GROUP_KP_TRIES);
        assert!(
            (Duration::from_secs(150)..=Duration::from_secs(300)).contains(&waited),
            "{waited:?}"
        );
    }

    #[test]
    fn 기기_없는_사람은_두_번_기다린_뒤_실패_모두_오면_봉인() {
        // 디렉터리가 늦게 오는 것과 가르려고 처음 두 번은 기다린다(#605 리뷰 🟡).
        assert_eq!(kp_wait(false, true, 0), KpWait::Again);
        assert_eq!(kp_wait(false, true, NO_DEVICE_TRIES - 1), KpWait::Again);
        assert_eq!(kp_wait(false, true, NO_DEVICE_TRIES), KpWait::Fail);
        assert_eq!(kp_wait(true, false, 0), KpWait::Go);
        assert_eq!(kp_wait(true, false, GROUP_KP_TRIES), KpWait::Go);
    }
}

#[cfg(test)]
mod dir_pull_tests {
    use super::{retry_pull, DIR_PULL_GAP_MS};
    use std::collections::HashMap;

    /// #725: 같은 그룹의 두 번째 Retry 부터 당기고, 그룹당 10초에 한 번. 그룹마다 따로, 수가 0 으로 되돌면
    /// 다시 두 번째부터.
    #[test]
    fn 두_번째_retry_부터_그룹당_10초에_한_번_당긴다() {
        let mut p = HashMap::new();
        assert!(!retry_pull(&mut p, "g1", 1_000), "첫 Retry 는 기다린다");
        assert!(
            retry_pull(&mut p, "g1", 7_000),
            "앞 Commit 이 무효가 된 뒤 또 Retry"
        );
        assert!(
            !retry_pull(&mut p, "g1", 8_000),
            "10초 안엔 다시 당기지 않는다"
        );
        assert!(retry_pull(&mut p, "g1", 7_000 + DIR_PULL_GAP_MS));
        // 다른 그룹은 따로 센다.
        assert!(!retry_pull(&mut p, "g2", 8_000));
        assert!(retry_pull(&mut p, "g2", 9_000));
        // Retry 아닌 처리 뒤(수 0)에는 다시 두 번째부터 — 당긴 때는 남아 10초 사이는 지킨다.
        p.get_mut("g1").unwrap().0 = 0;
        assert!(!retry_pull(&mut p, "g1", 40_000));
        assert!(retry_pull(&mut p, "g1", 41_000));
    }

    /// #725 🟡: Handshake 의 RetryDir 열쇠와 받은 메시지 헤더로 만든 열쇠가 같다(수를 되돌릴 때 같은 칸을 본다) — 26자 대화 id·
    /// 그 밖(인코딩) 둘 다.
    #[test]
    fn handshake_열쇠는_retrydir_과_같다() {
        for gid in [
            b"01JB0000000000000000000001".to_vec(),
            vec![0xff, 0x00, 0x10],
        ] {
            let m = serde_json::json!({"mls_group": crate::mls_conn::header_of(&gid)});
            assert_eq!(
                super::handshake_key(&m),
                Some(crate::mls_conn::gid_key(&gid))
            );
        }
        assert_eq!(super::handshake_key(&serde_json::json!({})), None);
    }
}
