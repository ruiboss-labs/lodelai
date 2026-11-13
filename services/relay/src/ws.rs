//! WebSocket: 핸드셰이크(protocol §7.1)와 프레임 루프(§7.2).
//!
//! `hello → challenge → auth → ready`. 모르는 기기·사용자 불일치·서명 실패는 모두 같은 `error protocol` 한 줄 뒤 끊는다.
//! challenge 는 기기가 있든 없든 항상 보낸다(기기 존재 열거 방지).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::{encoding, verify_challenge, DeviceId, VerifyingKey};
use tokio::sync::{mpsc, Notify};

use crate::db::{
    AdminAct, AdminOutcome, MemberOutcome, OrgLeaveOut, PublicSession, RevokeOutcome, SelfRevoke,
};
use crate::frames::{
    ClientFrame, DeviceCert, DevicePubkeys, DirectoryBody, DirectoryDevice, DirectoryOrg,
    DirectoryPerson, DirectoryRevocation, DirectorySession, DirectoryTeam, ErrorCode, RevokedBy,
    ServerFrame,
};
use crate::rules::{self, Authed};
use crate::{blocking, App, Relay};

/// 핸드셰이크 전체 시간 상한.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 초대 토큰 유효 시간(#355, security §6 — 7일, 1회용).
pub const INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 관리자당 초대 발급 상한(#355 설계): 1시간에 20개.
pub const INVITE_WINDOW_MS: i64 = 60 * 60 * 1000;
pub const INVITE_MAX: i64 = 20;
/// 인증 전(hello·auth) 텍스트 프레임 상한(#320). 둘 다 수백 바이트다. 업그레이드 때 정한 상한(`max_frame_bytes`)은 연결
/// 도중 못 바꾸므로 받은 길이를 직접 보고 끊는다 — 인증 없는 연결이 큰 프레임으로 비용을 쓰지 못하게.
pub const HANDSHAKE_MAX_FRAME_BYTES: usize = 4096;
/// 나중 기기가 먼저 기기를 폐기하기 전 대기(#339 2026-10-24 결정 — 24시간). 기준은 요청 기기의 등록 시각.
pub const DEVICE_REVOKE_WAIT_MS: i64 = 24 * 60 * 60 * 1000;

/// 연결의 쓰기 줄. 값은 `Utf8Bytes`(참조 셈) — 여러 연결에 같은 프레임을 보낼 때 한 벌을 나눠 쓴다(묶음 22 §5d, 잎 200 에
/// 같은 암호문을 연결마다 복제하지 않게). 연결 하나에 보내는 곳은 `String` 을 그대로 넘긴다.
#[derive(Clone)]
struct Tx(mpsc::UnboundedSender<Utf8Bytes>);

impl Tx {
    fn send(&self, text: impl Into<Utf8Bytes>) -> Result<(), ()> {
        self.0.send(text.into()).map_err(|_| ())
    }
}

struct Conn {
    id: u64,
    device_id: String,
    /// 모바일 검증: hello.no_duty — duty 후보에서 뺀다.
    no_duty: bool,
    /// hello.own — own_stream(#870)을 넘길 연결.
    own: bool,
    /// #845 hello.contacts — account_suspended 같은 새 코드를 아는 연결.
    contacts: bool,
    /// #846: 이 기기가 잎 자격이 있나(승인됨). 아니면 쓰기 고리가 디렉터리를 내 항목만으로 줄인다([`for_unapproved`]).
    /// 그 사용자의 잎 자격이 바뀌면 [`reapprove`] 가 다시 센다.
    approved: Arc<std::sync::atomic::AtomicBool>,
    tx: Tx,
    /// 기기가 폐기되면 그 기기의 다른 연결도 닫는다(#325).
    kill: Arc<Notify>,
    /// #888 승인 닫기 — 폐기와 달리 이미 받은 프레임(접속 직후의 key_packages.publish 등)을 다 처리한 뒤 닫는다.
    close_soft: Arc<Notify>,
}

/// 사용자별 접속 중인 연결.
#[derive(Default)]
pub struct Connections {
    inner: Mutex<HashMap<String, Vec<Conn>>>,
    next: AtomicU64,
    /// #888 새로 승인된 (사용자, 기기, 넣은 때) — 진행 중인 처리가 다 끝난 뒤 [`flush_approved`] 가 error{approved} 를 보내고
    /// 닫는다.
    approve_pending: Mutex<Vec<(String, String, std::time::Instant)>>,
    /// #888 지금 진행 중인 처리(읽기 고리 한 바퀴·주기 틱) 수 — [`Busy`].
    busy: AtomicU64,
}

impl Connections {
    #[cfg(test)]
    fn add(&self, who: &Authed, tx: Tx) -> (u64, Arc<Notify>) {
        let (id, kill, _, _) = self.add_approved(who, tx, true);
        (id, kill)
    }

    /// [`Self::add`] + 승인 여부(#846). 쓰기 고리가 읽을 승인 표시를 돌려준다.
    fn add_approved(
        &self,
        who: &Authed,
        tx: Tx,
        approved: bool,
    ) -> (
        u64,
        Arc<Notify>,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<Notify>,
    ) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let kill = Arc::new(Notify::new());
        let close_soft = Arc::new(Notify::new());
        let approved = Arc::new(std::sync::atomic::AtomicBool::new(approved));
        self.lock().entry(who.user.clone()).or_default().push(Conn {
            id,
            device_id: who.device_id.clone(),
            no_duty: who.no_duty,
            own: who.own,
            contacts: who.contacts,
            approved: approved.clone(),
            tx,
            kill: kill.clone(),
            close_soft: close_soft.clone(),
        });
        (id, kill, approved, close_soft)
    }

    /// #846: 그 사용자 연결의 승인 여부를 `eligible` 로 다시 정한다. 새로 승인된 연결의 기기들.
    fn reapprove(&self, user: &str, eligible: &[String]) -> Vec<String> {
        let mut newly = Vec::new();
        if let Some(v) = self.lock().get(user) {
            for c in v {
                let now = eligible.contains(&c.device_id);
                let was = c.approved.swap(now, Ordering::Relaxed);
                if now && !was && !newly.contains(&c.device_id) {
                    newly.push(c.device_id.clone());
                }
            }
        }
        newly
    }

    /// #888 그 기기의 연결을 이미 받은 프레임을 다 처리한 뒤 닫게 한다(승인 닫기).
    fn close_device_soft(&self, user: &str, device_id: &str) {
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.device_id == device_id) {
                c.close_soft.notify_one();
            }
        }
    }

    /// 그 기기의 연결을 모두 닫게 한다(폐기, #325). `notify_one` 이라 아직 기다리지 않는 연결도 다음 대기에서 깬다.
    pub(crate) fn close_device(&self, user: &str, device_id: &str) {
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.device_id == device_id) {
                c.kill.notify_one();
            }
        }
    }

    /// 그 사용자의 모든 연결을 닫게 한다(내보내기·나가기, 묶음 5, #845 ⑤ 멈춤 틱).
    pub(crate) fn close_user(&self, user: &str) {
        if let Some(v) = self.lock().get(user) {
            for c in v {
                c.kill.notify_one();
            }
        }
    }

    /// 그 기기의 연결에만 보낸다(관리자가 기기 하나를 끊을 때 — 같은 사람의 다른 기기가 자기 폐기로 읽지 않게, 묶음 5).
    fn send_device(&self, user: &str, device_id: &str, frame: &ServerFrame) {
        let text = Utf8Bytes::from(frame.to_json());
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.device_id == device_id) {
                let _ = c.tx.send(text.clone());
            }
        }
    }

    fn remove(&self, user: &str, id: u64) {
        let mut m = self.lock();
        if let Some(v) = m.get_mut(user) {
            v.retain(|c| c.id != id);
            if v.is_empty() {
                m.remove(user);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Conn>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 그 기기들의 연결에만 보낸다(기기별 보관의 실시간 `deliver`, protocol §7.2-6).
    pub fn send_devices(&self, user: &str, device_ids: &[String], frame: &ServerFrame) {
        let text = Utf8Bytes::from(frame.to_json());
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| device_ids.contains(&c.device_id)) {
                let _ = c.tx.send(text.clone());
            }
        }
    }

    /// 그 기기의 hello.own 연결에만 보낸다(#870 own_stream). 보낸 연결 수.
    pub fn send_device_own(&self, user: &str, device_id: &str, frame: &ServerFrame) -> usize {
        let text = Utf8Bytes::from(frame.to_json());
        self.lock().get(user).map_or(0, |v| {
            v.iter()
                .filter(|c| c.device_id == device_id && c.own)
                .filter(|c| c.tx.send(text.clone()).is_ok())
                .count()
        })
    }

    /// 그 기기들의 연결에 보낸다 — 사용자를 가리지 않고(그룹 메시지는 여러 사람의 기기로 간다, 묶음 16).
    pub fn send_any_devices(&self, device_ids: &[String], frame: &ServerFrame) {
        let text = frame.to_json();
        for c in self
            .lock()
            .values()
            .flatten()
            .filter(|c| device_ids.contains(&c.device_id))
        {
            let _ = c.tx.send(text.clone());
        }
    }

    /// 그 사용자의 모든 연결에 보낸다. 보낸 연결 수.
    pub fn send_user(&self, user: &str, frame: &ServerFrame) -> usize {
        let text = Utf8Bytes::from(frame.to_json());
        self.lock().get(user).map_or(0, |v| {
            v.iter().filter(|c| c.tx.send(text.clone()).is_ok()).count()
        })
    }

    /// #845 ⑤ 그 사람의 contacts 연결에만 보낸다(옛 앱은 모르는 코드).
    pub(crate) fn send_contacts(&self, user: &str, frame: &ServerFrame) {
        let text = Utf8Bytes::from(frame.to_json());
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.contacts) {
                let _ = c.tx.send(text.clone());
            }
        }
    }

    /// 모든 연결을 닫게 한다(relay 정리, #328).
    pub fn close_all(&self) {
        for c in self.lock().values().flatten() {
            c.kill.notify_one();
        }
    }

    pub fn users(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// 그 사용자의 열린 연결 수(`server.status.devices.connected` — 조직 사람별로 더한다).
    pub fn connections_of(&self, user: &str) -> usize {
        self.lock().get(user).map_or(0, Vec::len)
    }

    /// 그 사용자의 접속한 기기(§7 duty 후보).
    pub fn online_devices(&self, user: &str) -> Vec<String> {
        self.lock()
            .get(user)
            .map(|v| v.iter().map(|c| c.device_id.clone()).collect())
            .unwrap_or_default()
    }

    /// 그 기기의 연결이 하나라도 있나(사용자를 모를 때 — 모바일 검증 푸시).
    pub fn device_online(&self, device_id: &str) -> bool {
        self.lock()
            .values()
            .flatten()
            .any(|c| c.device_id == device_id)
    }

    /// duty 후보가 될 접속 기기 — `no_duty` 가 아닌 연결이 하나라도 있는 기기(모바일 검증 S3).
    pub fn duty_devices(&self, user: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| !c.no_duty) {
                if !out.contains(&c.device_id) {
                    out.push(c.device_id.clone());
                }
            }
        }
        out
    }

    pub fn is_online(&self, user: &str) -> bool {
        self.lock().contains_key(user)
    }
}

pub async fn upgrade(
    State(app): State<App>,
    ip: Option<axum::Extension<crate::http::ClientIp>>,
    ws: WebSocketUpgrade,
) -> Response {
    // 인증 전 시도의 IP 상한(#364) — 원격 relay 만. 로컬은 모든 연결이 127.0.0.1 이라 재접속이 서로 막힌다.
    // 연결에도 실어 둔다(#845 ③ 없는 아이디 찾기 상한의 IP 쪽).
    let client_ip = ip
        .filter(|_| app.config.remote)
        .and_then(|axum::Extension(crate::http::ClientIp(ip))| ip);
    if let Some(ip) = &client_ip {
        if !app.ip_limiter.allow(ip, app.effects.clock.now()) {
            return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    let max = app.config.max_frame_bytes;
    let server = server_header_value(&app.config.server_name);
    let features = features_header_value(&app.config, app.db.has_email_key());
    let mut resp = ws
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| run(app, socket, client_ip));
    // §12-28 ①: 받는 판 범위. 옛 relay(헤더 없음)는 판이 다른 hello 를 auth 로 끊어서, 앱이 이것으로 진짜 인증 실패와 가른다.
    resp.headers_mut()
        .insert(PROTOCOL_HEADER, protocol_header_value());
    // §12-29 ①: 서명을 검사할 서버 이름 — 앱이 접속 호스트와 견줘 어긋남을 가입 전에 알린다.
    if let Some(v) = server {
        resp.headers_mut().insert(SERVER_HEADER, v);
    }
    // §12-30 ②: 켜진 기능 — 앱이 연결마다 읽어 꺼진 기능(그룹)의 입구를 닫는다.
    resp.headers_mut().insert(FEATURES_HEADER, features);
    resp
}

/// 101 응답과 `/v1/healthz` 응답의 판 범위 헤더(§12-28 ①, `<MIN>-<VERSION>`). 101 헤더는 프록시가 지울 수 있어 healthz 에도 싣는다.
/// 사용자 단위 프레임 상한(규칙 0).
fn rate_ok(app: &Relay, who: &Authed) -> bool {
    app.limiter.allow(&who.user, app.effects.clock.now())
}

pub const PROTOCOL_HEADER: &str = "lodelai-protocol";

/// [`PROTOCOL_HEADER`] 의 값 `<MIN>-<VERSION>`.
pub fn protocol_header_value() -> axum::http::HeaderValue {
    axum::http::HeaderValue::from_str(&format!(
        "{}-{}",
        lodelai_protocol::PROTOCOL_MIN,
        lodelai_protocol::PROTOCOL_VERSION
    ))
    .expect("숫자와 '-' 뿐")
}

/// 101 응답과 `/v1/healthz` 응답의 서버 이름 헤더(§12-29 ①, #534) — challenge 서명을 검사할 `server_name`. 앱은 이 값으로
/// 서명하지 않고(되쓰기 막기) 접속 호스트와 견주기만 한다.
pub const SERVER_HEADER: &str = "lodelai-server";

/// [`SERVER_HEADER`] 의 값. 헤더에 못 싣는 이름이면 `None`(싣지 않음 — 앱은 견주지 않는다).
pub fn server_header_value(server_name: &str) -> Option<axum::http::HeaderValue> {
    axum::http::HeaderValue::from_str(server_name).ok()
}

/// 101 응답과 `/v1/healthz` 응답의 켜진 기능 헤더(§12-30 ②, #535) — 쉼표 목록: `groups`(설정), `device_name`(늘 — #490 묶음
/// 28 §4 `device.name` 을 아는 relay. PROTOCOL 판을 올리지 않아 앱은 이것으로만 보내도 되는지 안다 — 모르는 relay 는 ref 없는
/// error{protocol} 을 돌려줘 앱이 다른 관리 요청의 거절로 읽는다). **늘 싣는다**: 줄이 없으면 앱은 '모름'(옛 relay·터널이
/// 지움)으로 보니, 켜진 것이 없으면 값 `none`(빈 헤더는 프록시가 지울 수 있다).
pub const FEATURES_HEADER: &str = "lodelai-features";

/// [`FEATURES_HEADER`] 의 값 — 켜진 기능 쉼표 목록, 없으면 `none`. `email_key` = DB 가 이메일 HMAC 키를 쥠(contacts 의 조건).
pub fn features_header_value(config: &crate::Config, email_key: bool) -> axum::http::HeaderValue {
    let on: Vec<&str> = [
        ("groups", config.groups),
        ("device_name", true),
        // 판 15: device.name.os 를 아는 relay — 앱은 이것이 있을 때만 os 칸을 싣는다.
        ("device_os", true),
        ("kp_reset", true),
        // 0.2.6 #809: delivered_ack.unreadable 을 아는 relay — 앱은 이것이 있을 때만 싣는다.
        ("unreadable_ack", true),
        // 모바일 검증(시험 relay 만): push.register·hello.no_duty 를 아는 relay.
        ("push", config.mobile_push),
        // #845 §7-55: push.register.off(알림 갈래 끄기)를 아는 relay.
        ("push_prefs", config.mobile_push),
        // 휴대폰 여러 계정: 한 OS 토큰에 기기(계정) 여럿을 둔다 — 없으면(옛 relay) 앱은 고른 계정으로만 다시 등록한다.
        ("push_multi", config.mobile_push),
        // hello.no_duty 를 아는 relay — 푸시와 무관하게 늘(서버 고르기 §3). 푸시 없는 자체 서버에서도 휴대폰이 그룹 일감
        // 후보에서 빠져야 앱이 뒤로 가도 일이 밀리지 않는다. relay 는 이 칸을 판·설정과 상관없이 늘 읽어 왔다.
        ("no_duty", true),
        // #882 own_live·own_live.want·push.live 를 아는 relay — 휴대폰 현황 푸시를 낼 수 있을 때만(ADR 0014).
        ("own_live", config.mobile_push),
        // #870·#872: own_* 글·own_stream·own_alert·내 공개 안 한 세션 앞 request 를 아는 relay(판 OWN_CONTROL_PROTOCOL).
        ("own_control", true),
        // #890 own_alert.kind(card·usage)를 아는 relay — 앱은 이것이 있을 때만 kind 를 싣고, 없으면 usage 알림을 보내지 않는다.
        ("own_alert_kinds", true),
        // #881 blob.reserve.for_device(지난 대화 옮기기 조각)를 아는 relay.
        ("history_transfer", true),
        // #877 org.leave(조직에서 나가 개인 공간으로)를 아는 relay — 없으면 앱은 '나가기'를 그리지 않는다(계정 지우기만).
        // #905: 개인 공간 가입이 닫힌 relay 는 알리지 않는다(나가는 길은 계정 지우기 — member.leave).
        ("org_leave", config.personal_signup),
        // 관문 A6 link.unblock(막은 사람 풀기)을 아는 relay — 없으면 앱은 '차단 풀기'를 그리지 않고 보내지 않는다.
        ("link_unblock", true),
        // #923 §11 link.block(같은 조직 사람 막기)·디렉터리 blocked(hello.blocks)를 아는 relay.
        ("link_block", true),
        // #923 report(신고)를 받는 relay — 받는 주소(LODELAI_REPORT_EMAIL)가 있을 때만. 없으면 앱은 '신고'를 그리지 않는다.
        ("report", config.report_email.is_some()),
        // 조직 고유색(org.update.color·디렉터리 org.color·초대 카드 org_color)을 아는 relay — 없으면 앱은 색 고르기를 그리지 않는다.
        ("org_color", true),
        // #845 둘째: list.put·list.delete·디렉터리 lists·audience.lists(친구 목록)를 아는 relay — 없으면 앱은 목록 화면을 그리지 않는다.
        ("lists", true),
        // #845 둘째 ②: org.update.external·DirectoryOrg.external(조직 밖 연락 막기)를 아는 relay.
        ("org_external", true),
        // #845 둘째 ③: org.external.preview(켜기 전 조직 전체 셈)를 아는 relay — 없으면 앱은 숫자 없이 묻는다.
        ("org_external_preview", true),
        // #874: profile.update.look·디렉터리 사람 항목 look·hello.look 을 아는 relay.
        ("look", true),
        // #845: link.*·hello.contacts·디렉터리 links·link_requests 를 아는 relay. 알리면 contact_link 는 늘 된다 — 키가 없어
        // 못 하는 relay 는 알리지 않는다(앱은 not_supported 로 본다, internal_error 로 새지 않게).
        ("contacts", email_key),
        // §7-46 가입한 개인 공간 사람의 조직 만들기·코드로 들기(org.code.check·org.join·org.create).
        ("org_move", true),
        // §7-56 계정 단위 대화 음소거(mute.set·디렉터리 mutes·푸시 거름).
        ("mutes", true),
        // #880 계정 단위 대화 고정(pin.set·디렉터리 pins).
        ("pins", true),
        // #870 맥 잠듦: 디렉터리 내 기기 항목 away(닫는 이유 sleep·quit, 그 밖 lost)·hello.away 를 아는 relay.
        ("away", true),
        // #961: 세션 liveness live:next_turn(다음 차례에 받는 바깥 세션)·hello.next_turn 을 아는 relay.
        ("next_turn", true),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect();
    let v = if on.is_empty() {
        "none".to_owned()
    } else {
        on.join(",")
    };
    axum::http::HeaderValue::from_str(&v).expect("영문 소문자와 쉼표뿐")
}

/// 요청 프레임의 식별자(#537 (d)) — `send` 는 그 메시지의 `msg_id`, 그 밖은 `req`. 오류 답의 `ref` 로 쓴다.
fn request_ref(frame: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(frame).ok()?;
    let id = if v["t"] == "send" {
        v.pointer("/message/msg_id")
    } else {
        v.get("req")
    };
    id.and_then(serde_json::Value::as_str).map(str::to_owned)
}

/// 핸드셰이크 실패 이유 — hello 의 판이 범위 밖.
const VERSION_UNSUPPORTED: &str = "version_unsupported";

/// 프레임에 싣는 시각(RFC3339).
fn at_of(ms: i64) -> Option<String> {
    lodelai_effects::UnixMillis(ms).to_rfc3339().ok()
}

fn error_frame(code: ErrorCode, message: &str) -> String {
    ServerFrame::Error {
        code,
        message: message.to_owned(),
        r#ref: None,
    }
    .to_json()
}

async fn recv_frame(socket: &mut WebSocket) -> Option<Result<ClientFrame, ()>> {
    loop {
        match socket.next().await? {
            Ok(Message::Text(t)) if t.len() > HANDSHAKE_MAX_FRAME_BYTES => return Some(Err(())),
            Ok(Message::Text(t)) => return Some(ClientFrame::parse(t.as_str()).ok_or(())),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Binary(_)) => return Some(Err(())),
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// 핸드셰이크. 성공하면 인증된 주체, 폐기된 기기가 자기 키로 맞게 서명했으면 안쪽 `Err((누가, 언제 끊었나))`.
async fn handshake(
    app: &App,
    socket: &mut WebSocket,
) -> Result<Result<Authed, (Option<RevokedBy>, Option<i64>)>, &'static str> {
    let Some(Ok(ClientFrame::Hello {
        v,
        device_id,
        user,
        no_duty,
        look,
        own,
        contacts,
        mutes,
        pins,
        blocks,
        away,
        next_turn,
    })) = recv_frame(socket).await
    else {
        return Err("hello 가 아니다");
    };
    // 판이 범위 밖이면 서명을 보기 전에 명시 오류로 닫는다(묶음 22 §12-24 — auth 실패와 구별, 판 번호는 비밀이 아님).
    if !(lodelai_protocol::PROTOCOL_MIN..=lodelai_protocol::PROTOCOL_VERSION).contains(&v) {
        return Err(VERSION_UNSUPPORTED);
    }
    let mut nonce = [0u8; 32];
    app.effects
        .rng
        .try_fill(&mut nonce)
        .map_err(|_| "internal")?;
    let nonce_b64 = encoding::encode(&nonce);
    socket
        .send(Message::Text(
            ServerFrame::Challenge {
                nonce: nonce_b64.clone(),
            }
            .to_json()
            .into(),
        ))
        .await
        .map_err(|_| "send")?;
    let Some(Ok(ClientFrame::Auth { sig })) = recv_frame(socket).await else {
        return Err("auth 가 아니다");
    };
    // 이 아래 실패는 모두 같은 응답이다 — 폐기된 기기가 자기 키로 맞게 서명했을 때만 빼고(#339).
    let id = device_id.clone();
    let (registered, revoked, revoked_by) = blocking(app, move |r| {
        (
            r.db.device(&id).ok().flatten(),
            r.db.revoked_device(&id).ok().flatten(),
            r.db.revoked_by(&id).ok().flatten(),
        )
    })
    .await
    .ok_or("internal")?;
    let signed_by = |row: &Option<(String, String)>| {
        // 9·10 이 함께 돈다(#598 ②) — 범위는 위에서 봤고 서명은 판을 묶지 않는다(lodelai-auth-v1 은 둘 다 같음).
        (lodelai_protocol::PROTOCOL_MIN..=lodelai_protocol::PROTOCOL_VERSION).contains(&v)
            && row.as_ref().is_some_and(|(u, pk)| {
                *u == user
                    && VerifyingKey::from_b64(pk).is_ok_and(|k| {
                        DeviceId::parse(&device_id).is_some_and(|id| id.matches(&k))
                            && verify_challenge(
                                &k,
                                &app.config.server_name,
                                &device_id,
                                &nonce_b64,
                                &sig,
                            )
                            .is_ok()
                    })
            })
    };
    if signed_by(&registered) {
        Ok(Ok(Authed {
            user,
            device_id,
            v: u64::from(v),
            no_duty,
            own,
            look,
            contacts,
            mutes,
            pins,
            blocks,
            away,
            next_turn,
            ip: None,
        }))
    } else if signed_by(&revoked) {
        Ok(Err(
            revoked_by.map_or((None, None), |(by, ms)| (by, Some(ms)))
        ))
    } else {
        Err("auth")
    }
}

async fn run(app: App, mut socket: WebSocket, ip: Option<String>) {
    let who = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&app, &mut socket)).await {
        Ok(Ok(Ok(who))) => Authed { ip, ..who },
        Ok(outcome) => {
            let frame = match outcome {
                Ok(Err((by, ms))) => {
                    tracing::debug!("핸드셰이크 — 폐기된 기기");
                    ServerFrame::Revoked {
                        by,
                        at: ms.and_then(at_of),
                    }
                    .to_json()
                }
                Err("internal") => error_frame(ErrorCode::Internal, "handshake"),
                Err(VERSION_UNSUPPORTED) => {
                    tracing::debug!("핸드셰이크 — 판이 맞지 않음");
                    ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::Error(
                        lodelai_protocol::ws::Error {
                            at: None,
                            by: None,
                            code: lodelai_protocol::ws::ErrorCode::VersionUnsupported,
                            max: Some(u64::from(lodelai_protocol::PROTOCOL_VERSION)),
                            until: None,
                            reason: None,
                            message: "handshake".into(),
                            min: Some(u64::from(lodelai_protocol::PROTOCOL_MIN)),
                            ref_: None,
                            t: lodelai_protocol::ws::ErrorT::Error,
                        },
                    )))
                    .to_json()
                }
                Err(why) => {
                    tracing::debug!(why, "핸드셰이크 실패");
                    error_frame(ErrorCode::Protocol, "handshake")
                }
                Ok(Ok(_)) => unreachable!(),
            };
            let _ = socket.send(Message::Text(frame.into())).await;
            let _ = socket.close().await;
            return;
        }
        Err(_) => {
            let _ = socket.close().await;
            return;
        }
    };

    // #845 ⑤ 운영 멈춤: 서명 확인 뒤에만 가른다. contacts 연결엔 account_suspended(+풀리는 때), 옛 앱은 지금처럼 일반 실패.
    let (u, now) = (who.user.clone(), app.effects.clock.now().0);
    if let Some(until) = blocking(&app, move |r| r.db.suspended(&u, now).ok().flatten())
        .await
        .flatten()
    {
        tracing::info!(user = %who.user, device = %who.device_id, "멈춘 계정 접속");
        let frame = if who.contacts {
            account_suspended_frame(until).to_json()
        } else {
            error_frame(ErrorCode::Protocol, "handshake")
        };
        let _ = socket.send(Message::Text(frame.into())).await;
        let _ = socket.close().await;
        return;
    }

    let (mut sink, mut stream) = socket.split();
    let (raw_tx, mut rx) = mpsc::unbounded_channel::<Utf8Bytes>();
    let tx = Tx(raw_tx);

    // 순서: ready 를 먼저 큐에 넣고 → 연결 등록 → 그다음 쌓인 것을 쏟는다. 등록과 조회 사이에 도착한 메시지는
    // 실시간 deliver 와 pending 양쪽으로 두 번 갈 수 있지만(수신 코어가 msg_id 로 거른다) 빠지지는 않는다.
    // ready.pending 은 등록 직전 기준이라 실제 deliver 수보다 적을 수 있다.
    if who.no_duty {
        tracing::info!(device = %who.device_id, "no_duty 연결(duty 후보 아님)");
    }
    let (user, device) = (who.user.clone(), who.device_id.clone());
    let hello_v = who.v;
    let own = who.own;
    let Some((pending_before, admin, seen_before)) = blocking(&app, move |r| {
        // #846: 전에 붙은 적 있는 기기인가(hello_v 가 이미 적혀 있음) — 처음 붙는 기기는 스스로 첫 KeyPackage 묶음을 올린다.
        let seen_before =
            r.db.device_hello_v(std::slice::from_ref(&device))
                .is_ok_and(|m| m.contains_key(&device));
        // 이 기기가 붙은 판(#598 ② — 디렉터리 `v`). 실패해도 접속은 잇는다(모르면 9 로 보임).
        let _ = r.db.set_device_hello_v(&device, hello_v);
        let _ = r.db.set_device_own(&device, own);
        (
            r.db.pending_for(&user, &device)
                .map(|v| v.len())
                .unwrap_or(0),
            // 원격 relay 만 "내가 관리자인가"를 알린다(묶음 5 — 화면 가르기용, 권한은 relay 가 따로 본다).
            r.config.remote.then(|| {
                r.db.is_org_admin(&user).unwrap_or(false)
                    || r.db.admin().ok().flatten().as_deref() == Some(user.as_str())
            }),
            seen_before,
        )
    })
    .await
    else {
        return;
    };
    let now = app.effects.clock.now().to_rfc3339().unwrap_or_default();
    let _ = tx.send(
        ServerFrame::Ready {
            server: app.config.server_name.clone(),
            now,
            pending: pending_before as u64,
            admin,
        }
        .to_json(),
    );
    let was_online = crate::presence::connecting(&app, &who.user);
    // 연결 등록 → 쌓인 것 쏟기를 그룹 순서 잠금 안에서(묶음 16 §3a ④): 그룹이 있으면 directory·groups(조직 빠짐 힌트)를 먼저
    // 보내, 떨어져 있던 동안의 조직 빠짐을 쌓인 변경보다 먼저 알게 한다. 잠근 동안 실시간 그룹 변경이 이 연결 큐에 먼저 끼지 못한다.
    let (w, q) = (who.clone(), tx.clone());
    let Some((conn_id, kill, approved, close_soft)) = blocking(&app, move |r| {
        let _order = r
            .group_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // #846: 승인 전(잎 자격 없음) 기기는 디렉터리를 내 항목만 받는다 — 이메일 코드만 통과한 기기가 조직 명단·접속을 보지 않게.
        let ok = crate::mls::eligible_devices(r, &w.user).contains(&w.device_id);
        let added = r.conns.add_approved(&w, q.clone(), ok);
        // 센 뒤 add 전에 서명이 끼면 reapprove 가 이 연결을 못 봤다 — add 뒤 한 번 더 센다(그 뒤 서명은 reapprove 가 본다).
        if !ok && crate::mls::eligible_devices(r, &w.user).contains(&w.device_id) {
            added.2.store(true, Ordering::Relaxed);
        }
        // 그룹이 있으면 directory → groups(조직 빠짐 힌트) → 쌓인 것(§3a ④ 접속 때 순서, 8b85eddb) — 쌓인 그룹 변경이 없어도.
        // 디렉터리가 힌트보다 먼저여야 클라이언트가 지난 접속의 목록으로 힌트를 미루지 않는다.
        if let Some(f) = groups_frame_if_any(r, &w.user) {
            with_directory_order(r, || {
                let _ = q.send(ServerFrame::Directory(directory(r, &w.user)).to_json());
            });
            let _ = q.send(f.to_json());
        }
        // 묶음 22 §12-14: 저장한 nack commit_void → 그룹마다 마지막 결과 → 쌓인 것.
        for f in crate::mls_group::on_connect_frames(r, &w.device_id) {
            let _ = q.send(f);
        }
        // 0.2.6 #809: 꺼져 있던 동안 알릴 때가 된 못 엶 보고(이 연결은 이미 등록됨).
        crate::rules::notify_unreadable(r);
        let pending = r.db.pending_for(&w.user, &w.device_id).unwrap_or_default();
        for (m, group_seq) in pending {
            let Ok(message) = serde_json::from_str::<serde_json::Value>(&m) else {
                continue;
            };
            // 내 다른 기기가 보낸 것의 사본(묶음 22 §7) — 꺼져 있던 동안 바뀐 보낸 쪽 상태를 싣는다.
            let view = message
                .get("msg_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| r.db.header(id).ok().flatten())
                .filter(|h| h.from_user == w.user && h.to_user != w.user)
                .map(|h| h.sender_view);
            let mut f = serde_json::json!({"t": "deliver", "message": message});
            if let Some(s) = group_seq {
                f["group_seq"] = serde_json::json!(s);
            }
            if let Some(v) = view {
                f["sender_view"] = serde_json::Value::String(v);
            }
            let _ = q.send(Utf8Bytes::from(f.to_string()));
        }
        // #598 ②: 꺼져 있던 동안 못 알린 recipient_outdated(보낸 코어가 v9 로 다시 보내게).
        for f in crate::rules::outdated_notices(r, &w) {
            let _ = q.send(f.to_json());
        }
        // #882: 확인된 hello.own 연결에 현황을 받는 휴대폰이 있는지(맥은 on 일 때만 own_live 를 보낸다).
        if w.own && ok {
            if let Some(f) = crate::live::want_on_connect(r, &w.user) {
                let _ = q.send(f.to_json());
            }
        }
        added
    })
    .await
    else {
        crate::presence::disconnected(&app, &who.user);
        return;
    };
    // 묶음 22 §3: KeyPackage 가 모자라면 채우라고 알린다.
    {
        let (app, who) = (app.clone(), who.clone());
        let _ = blocking(&app, move |r| {
            crate::mls::on_ready(r, &who, seen_before);
            // #577: 마지막 접속 시각·걸린 걸기의 대상이면 막기 카드 재료.
            crate::recovery::on_auth(r, &who);
        })
        .await;
    }
    if !was_online {
        crate::presence::announce(&app, &who.user);
    }
    // 묶음 22 §12-27 ⓑ: 이 기기가 접속한 날(UTC 0시)을 남기고, 날짜가 바뀌었을 때만 내 다른 기기들에 directory.update(하루 한 번).
    // 그 밖에 이 기기가 막 붙었으면(첫 연결) 승인 전 내 기기에만 바로 — 가입 화면의 '맥 꺼짐'이 바로 풀리게. 승인된 내 기기(휴대폰
    // '내 에이전트'의 맥 붙음, #870)는 합쳐서([`crate::presence::my_device_changed`]).
    // 내 항목에만 실리므로 동료에게는 보내지 않는다.
    {
        let w = who.clone();
        let first_conn = blocking(&app, move |r| {
            let who = w;
            let now = r.effects.clock.now().0;
            let day = now - now.rem_euclid(24 * 60 * 60 * 1000);
            let new_day = r.db.touch_device_day(&who.device_id, day).unwrap_or(false);
            // #870: 붙은 동안은 'lost' — 닫는 이유를 못 보고 끝나면(relay 재시작·망 끊김) 그대로 남는다.
            let _ = r.db.set_away(&who.device_id, "lost");
            let online = r.conns.online_devices(&who.user);
            let first_conn = online.iter().filter(|d| **d == who.device_id).count() == 1;
            // 접속한 이 기기는 곧 directory.list 로 받는다 — 내 다른 기기에만(접속 직후 프레임 순서를 바꾸지 않게).
            let others = other_devices(online, &who.device_id);
            let targets = if new_day {
                others
            } else if first_conn {
                unapproved_of(r, &who.user, others)
            } else {
                Vec::new()
            };
            send_my_directory(r, &who.user, &targets);
            !new_day && first_conn
        })
        .await;
        if first_conn == Some(true) {
            crate::presence::my_device_changed(&app, &who.user, Some(&who.device_id));
        }
    }

    let conn_v = who.v;
    let conn_look = who.look;
    let conn_contacts = who.contacts;
    let conn_mutes = who.mutes;
    let conn_pins = who.pins;
    let conn_blocks = who.blocks;
    let conn_away = who.away;
    let conn_next_turn = who.next_turn;
    let my_addr = format!("{}@{}", who.user, app.config.server_name);
    // #888: 읽기 고리도 승인 여부를 본다(쓰기 고리가 가져가는 것과 같은 값).
    let approved_rx = approved.clone();
    let writer = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            let Some(text) = for_version(text, conn_v) else {
                continue;
            };
            let text = if approved.load(Ordering::Relaxed) {
                text
            } else {
                let Some(t) = for_unapproved(text, &my_addr) else {
                    continue;
                };
                t
            };
            let text = if conn_look { text } else { without_look(text) };
            let text = if conn_contacts {
                text
            } else {
                without_links(text)
            };
            let text = if conn_mutes {
                text
            } else {
                without_mutes(text)
            };
            let text = if conn_pins { text } else { without_pins(text) };
            let text = if conn_blocks {
                text
            } else {
                without_blocked(text)
            };
            // #845 둘째: 판 16 아래 앱의 Directory 는 모르는 최상위 칸을 거절한다 — 친구 목록 칸을 뺀다.
            let text = if conn_v >= LISTS_FROM {
                text
            } else {
                without_lists(text)
            };
            let text = if conn_away { text } else { without_away(text) };
            let text = if conn_next_turn {
                text
            } else {
                without_next_turn(text)
            };
            if sink.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // 서버 ping(protocol §7.2). 생존 판정은 앱 텍스트 프레임만 본다 — WebSocket 제어 프레임은 세지 않는다.
    let mut ping = tokio::time::interval(app.config.ping_interval);
    ping.tick().await; // 첫 틱은 즉시 — 버린다
    let mut last_rx = tokio::time::Instant::now();
    let mut typing_gate = crate::presence::TypingGate::default();
    // #888 감사: 승인 전 막은 프레임은 연결당 처음 몇 번만 로그.
    let mut gate_logged = 0u32;
    // #870: 이 연결이 어떻게 끝났나 — 앱이 close reason 으로 알린 sleep·quit, 그 밖은 lost.
    let mut away = "lost";
    loop {
        // 순서 고정(biased): 폐기 닫기 → 받은 프레임 → 승인 닫기(#888 — 접속 직후 이미 보낸 key_packages.publish 를 처리하기 전에
        // 닫으면 앱은 접속 때 디렉터리를 보고 '올렸음'으로 적어 KeyPackage 를 영영 안 올린다) → ping.
        let frame = tokio::select! {
            biased;
            () = kill.notified() => {
                tracing::info!(user = %who.user, device = %who.device_id, "연결 강제 종료");
                break;
            }
            next = stream.next() => match next {
                Some(Ok(Message::Text(t))) => t,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(cf))) => {
                    away = close_away(cf.as_ref().map(|c| c.reason.as_str()));
                    tracing::info!(user = %who.user, device = %who.device_id, away, "앱이 연결을 닫음");
                    break;
                }
                // 끊김 원인 추적용(주소·내용 없이 사용자·기기만).
                _ => {
                    tracing::info!(user = %who.user, device = %who.device_id, "앱이 연결을 닫음");
                    break;
                }
            },
            () = close_soft.notified() => {
                tracing::info!(user = %who.user, device = %who.device_id, "승인됨 — 받은 프레임 처리 뒤 닫음");
                break;
            }
            _ = ping.tick() => {
                if last_rx.elapsed() >= app.config.idle_timeout {
                    tracing::info!(user = %who.user, device = %who.device_id, "유휴 연결 종료");
                    break;
                }
                let _ = tx.send(ServerFrame::Ping.to_json());
                continue;
            }
        };
        last_rx = tokio::time::Instant::now();
        // #888: 이 프레임 처리로 승인된 기기가 있으면 진행 중인 처리가 다 끝난 뒤 닫는다.
        let _busy = Busy::new(&app);
        // 0. rate limit — 파싱 직후, 다른 검사 전. own_stream(#870)은 기기 짝 상한([`crate::own::StreamGate`])이 따로 센다 — 화면
        //    4fps 가 사용자 상한을 먹어 맥 연결이 끊기지 않게. 표식만 보고 건너뛴 프레임이 own_stream 이 아니면 파싱 뒤에 센다.
        let maybe_stream = frame.as_str().contains("\"own_stream\"");
        if !maybe_stream && !rate_ok(&app, &who) {
            let _ = tx.send(error_frame(ErrorCode::RateLimited, "rate limited"));
            tracing::info!(user = %who.user, device = %who.device_id, "rate limit 으로 연결 종료");
            break;
        }
        let parsed = ClientFrame::parse(frame.as_str());
        if maybe_stream
            && !matches!(parsed, Some(ClientFrame::OwnStream { .. }))
            && !rate_ok(&app, &who)
        {
            let _ = tx.send(error_frame(ErrorCode::RateLimited, "rate limited"));
            tracing::info!(user = %who.user, device = %who.device_id, "rate limit 으로 연결 종료");
            break;
        }
        let Some(parsed) = parsed else {
            // send 의 메시지가 스키마에 맞지 않으면 ref = msg_id 로 알려 보낸 쪽이 큐에서 뺄 수 있게 한다.
            let raw: Option<serde_json::Value> = serde_json::from_str(frame.as_str()).ok();
            // 입력 중 표시(#613)·내 기기 흘림(#870)은 어긋나도(세션 주소 등) 조용히 버린다 — 오류를 내면 대상이 있는지 드러난다.
            if raw.as_ref().is_some_and(|v| {
                v["t"] == "typing" || v["t"] == "own_stream" || v["t"] == "own_alert"
            }) {
                continue;
            }
            let reply = match raw
                .as_ref()
                .filter(|v| v["t"] == "send")
                .and_then(|v| v.get("message"))
            {
                Some(m) => rules::send_format_error(m),
                None => rules::protocol_error("프레임 형식"),
            };
            let _ = tx.send(reply.to_json());
            continue;
        };
        // #888: 승인 전(잎 자격 밖) 연결은 허용 목록 밖 프레임을 막는다 — 특수 갈래(typing·own·revoke)보다 먼저.
        if !approved_rx.load(Ordering::Relaxed) {
            let gate = unapproved_gate(&parsed, &who);
            if !matches!(gate, Gate::Allow) {
                if gate_logged < GATE_LOG_MAX {
                    gate_logged += 1;
                    tracing::info!(user = %who.user, device = %who.device_id, t = frame_t(frame.as_str()),
                        "승인 전 기기의 프레임 막음");
                }
                if let Gate::Refuse = gate {
                    // ref 가 없는 거절은 #737 관리자 동작에만 답한다 — 그 밖은 앱이 걸어 둔 다른 요청(push.register 등)의
                    // 답으로 잘못 붙는다. 그래서 조용히 버린다(감사 줄은 위에).
                    let r#ref = refused_ref(&parsed, frame.as_str());
                    if r#ref.is_some() || ref_less_refusal(frame.as_str()) {
                        let reply = ServerFrame::Error {
                            code: ErrorCode::DeviceUnconfirmed,
                            message: "not approved".into(),
                            r#ref,
                        };
                        let _ = tx.send(reply.to_json());
                    }
                }
                continue;
            }
        }
        // 입력 중 표시(#613): 응답 없음. 판 11 아래 연결이 보낸 것·연결마다 to·값마다 초당 1 을 넘은 것은 버린다.
        if let ClientFrame::Typing { to, on } = parsed {
            if who.v >= crate::presence::TYPING_FROM
                && typing_gate.allow(&to, on, tokio::time::Instant::now())
            {
                let w = who.clone();
                if blocking(&app, move |r| crate::presence::typing(r, &w, &to, on))
                    .await
                    .is_none()
                {
                    break;
                }
            }
            continue;
        }
        // 내 기기끼리(#870): 응답 없음. 어긋나면 조용히 버린다([`crate::own`]).
        if let ClientFrame::OwnStream {
            to_device,
            epoch,
            seq,
            data,
        } = parsed
        {
            let w = who.clone();
            if blocking(&app, move |r| {
                crate::own::stream(r, &w, &to_device, epoch, seq, &data);
            })
            .await
            .is_none()
            {
                break;
            }
            continue;
        }
        // #882 맥의 현황 숫자: 응답 없음, 어긋나면 조용히 버린다([`crate::live`]).
        if let ClientFrame::OwnLive {
            busy,
            approval,
            question,
            oldest_ms,
        } = parsed
        {
            let w = who.clone();
            let v = crate::live::Vals {
                busy,
                approval,
                question,
                oldest_ms,
            };
            if blocking(&app, move |r| {
                crate::live::on_frame(r, &w, v);
            })
            .await
            .is_none()
            {
                break;
            }
            continue;
        }
        if let ClientFrame::OwnAlert { usage } = parsed {
            let w = who.clone();
            if blocking(&app, move |r| {
                crate::own::alert(r, &w, usage);
            })
            .await
            .is_none()
            {
                break;
            }
            continue;
        }
        // 기기 폐기(#325·#339): 순서 고정 — 폐기 커밋 → device.revoked → 같은 조직에 directory.update → 폐기된 기기의 연결 닫음.
        if let ClientFrame::DeviceRevoke { device_id, proof } = &parsed {
            let target = device_id.clone().filter(|d| *d != who.device_id);
            // 묶음 22 devrevoke: 증명이 있으면 먼저 검사 — 틀리면 error{protocol}, 폐기하지 않는다.
            let proof = match proof {
                Some((at, sig)) => {
                    let (w, t, at, sig) = (
                        who.clone(),
                        target.clone().unwrap_or_else(|| who.device_id.clone()),
                        at.clone(),
                        sig.clone(),
                    );
                    let Some(checked) =
                        blocking(&app, move |r| crate::mls::revoke_proof(r, &w, &t, at, sig)).await
                    else {
                        break;
                    };
                    let Some(p) = checked else {
                        let _ = tx.send(error_frame(ErrorCode::Protocol, "device.revoke"));
                        continue;
                    };
                    Some(p)
                }
                None => None,
            };
            let Some(target) = target else {
                // 자기 폐기(#325) — 이 연결도 닫는다.
                let w = who.clone();
                let now = app.effects.clock.now().0;
                let p = proof.clone();
                let Some(done) = blocking(&app, move |r| {
                    r.db.revoke_device(&w.device_id, now, p.as_ref())
                })
                .await
                else {
                    break;
                };
                match done {
                    Ok(SelfRevoke::Revoked) => {}
                    // 유일한 관리자의 마지막 기기(묶음 5) — 연결은 그대로 둔다.
                    Ok(SelfRevoke::LastAdmin) => {
                        let _ = tx.send(error_frame(ErrorCode::LastAdmin, "device.revoke"));
                        continue;
                    }
                    Ok(SelfRevoke::Gone) | Err(_) => {
                        let _ = tx.send(error_frame(ErrorCode::Internal, "device.revoke"));
                        continue;
                    }
                }
                tracing::info!(user = %who.user, device = %who.device_id, "기기 폐기");
                // 묶음 22 §7: 그 기기의 잎을 남은 잎이 빼게(remove_device), 뿌리가 바뀌어 자격이 생긴 기기는 들이게.
                {
                    let u = who.user.clone();
                    let _ = blocking(&app, move |r| {
                        crate::mls_group::void_revoked_senders(r);
                        crate::mls::refresh_add_duties(r, &u);
                        crate::mls::rejoin_orphaned(r, &u);
                    })
                    .await;
                }
                // #577: 지금 끊기(자기 폐기)·요청 기기 폐기 — 걸기를 다시 본다.
                {
                    let u = who.user.clone();
                    let _ = blocking(&app, move |r| crate::recovery::on_trust_change(r, &u)).await;
                }
                let _ = tx.send(
                    ServerFrame::DeviceRevoked {
                        device_id: device_id.clone(),
                        by: Some(RevokedBy::Device),
                        at: at_of(now),
                    }
                    .to_json(),
                );
                let w = who.clone();
                let _ = blocking(&app, move |r| broadcast_directory(r, &w)).await;
                app.conns.close_device(&who.user, &who.device_id);
                linger_until_closed(&mut stream).await;
                break;
            };
            // 같은 사용자의 다른 기기(#339) — 요청한 연결은 유지한다.
            let (w, t) = (who.clone(), target.clone());
            let now = app.effects.clock.now().0;
            let Some(outcome) = blocking(&app, move |r| {
                let trusted = crate::mls::eligible_devices(r, &w.user).contains(&w.device_id);
                r.db.revoke_other(
                    &w.device_id,
                    &t,
                    now,
                    DEVICE_REVOKE_WAIT_MS,
                    proof.as_ref(),
                    trusted,
                )
            })
            .await
            else {
                break;
            };
            match outcome {
                Ok(RevokeOutcome::Revoked { user: owner }) => {
                    tracing::info!(user = %who.user, by = %who.device_id, device = %target, "다른 기기 폐기");
                    {
                        let u = owner.clone();
                        let _ = blocking(&app, move |r| {
                            crate::mls_group::void_revoked_senders(r);
                            crate::mls::refresh_add_duties(r, &u);
                            crate::mls::rejoin_orphaned(r, &u);
                            crate::recovery::on_trust_change(r, &u);
                        })
                        .await;
                    }
                    let _ = tx.send(
                        ServerFrame::DeviceRevoked {
                            device_id: Some(target.clone()),
                            by: Some(if owner == who.user {
                                RevokedBy::Device
                            } else {
                                RevokedBy::Admin
                            }),
                            at: at_of(now),
                        }
                        .to_json(),
                    );
                    let w = who.clone();
                    let _ = blocking(&app, move |r| broadcast_directory(r, &w)).await;
                    // 대상 기기의 주인(관리자가 남의 기기를 끊으면 요청자와 다르다, #355). 남의 기기면 끊기기 전에
                    // 그 기기에만 알린다(묶음 5 — 꺼져 있었으면 재접속 때 error{device_revoked, by}).
                    if owner != who.user {
                        app.conns.send_device(
                            &owner,
                            &target,
                            &ServerFrame::DeviceRevoked {
                                device_id: None,
                                by: Some(RevokedBy::Admin),
                                at: at_of(now),
                            },
                        );
                    }
                    app.conns.close_device(&owner, &target);
                }
                Ok(RevokeOutcome::AlreadyRevoked) => {
                    let _ = tx.send(
                        ServerFrame::DeviceRevoked {
                            device_id: Some(target),
                            by: None,
                            at: None,
                        }
                        .to_json(),
                    );
                }
                Ok(RevokeOutcome::TooEarly) => {
                    let _ = tx.send(error_frame(ErrorCode::TooEarly, "device.revoke"));
                }
                // 남의 기기·모르는 id 는 같은 바이트(열거 방지).
                Ok(RevokeOutcome::Unknown) => {
                    let _ = tx.send(error_frame(ErrorCode::Protocol, "device.revoke"));
                }
                Err(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Internal, "device.revoke"));
                }
            }
            continue;
        }
        // #877 조직에서 나가 개인 공간으로: 한 트랜잭션 → 옛 조직 동료에게 directory.update·groups → 내 모든 연결에
        // error{org_changed} 뒤 닫음(기기는 그대로 — 앱은 바로 다시 붙는다).
        if matches!(parsed, ClientFrame::OrgLeave) {
            // #905: 개인 공간 가입이 닫힌 relay — 기능 표시(org_leave)를 내지 않으니 새 앱은 보내지 않는다. 온 것은 거절.
            if !app.config.personal_signup {
                let _ = tx.send(error_frame(ErrorCode::Protocol, "org.leave"));
                continue;
            }
            let w = who.clone();
            let now = app.effects.clock.now().0;
            let Some(outcome) = blocking(&app, move |r| {
                let _order = r
                    .group_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let personal = r.effects.ids.next_ulid();
                let out = r.db.org_leave(&w.user, &personal, now);
                if let Ok(OrgLeaveOut::Moved { old_org }) = &out {
                    announce_org_left(r, &w.user, old_org);
                    r.conns.send_user(
                        &w.user,
                        &ServerFrame::Error {
                            code: ErrorCode::OrgChanged,
                            message: "org.leave".into(),
                            r#ref: None,
                        },
                    );
                }
                out
            })
            .await
            else {
                break;
            };
            match outcome {
                Ok(OrgLeaveOut::Moved { .. }) => {
                    tracing::info!(user = %who.user, "조직 나감 → 개인 공간");
                    app.conns.close_user(&who.user);
                    linger_until_closed(&mut stream).await;
                    break;
                }
                Ok(OrgLeaveOut::LastAdmin) => {
                    let _ = tx.send(error_frame(ErrorCode::LastAdmin, "org.leave"));
                }
                Ok(OrgLeaveOut::NotOrg) => {
                    let _ = tx.send(error_frame(ErrorCode::Protocol, "org.leave"));
                }
                Err(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Internal, "org.leave"));
                }
            }
            continue;
        }
        // 조직 나가기(묶음 5): 폐기 커밋 → 내 모든 연결에 device.revoked{by:left} → 같은 조직에 directory.update → 내 연결 모두 닫음.
        if matches!(parsed, ClientFrame::MemberLeave) {
            let w = who.clone();
            let now = app.effects.clock.now().0;
            // 폐기 커밋 → directory.update 사이에 그룹 변경 전달이 끼지 않게(묶음 16 §3a ④) — 한 블록 안에서 잠근 채로.
            let Some(outcome) = blocking(&app, move |r| {
                let _order = r
                    .group_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let out = r.db.member_leave(&w.user, now);
                if matches!(out, Ok(MemberOutcome::Done { .. })) {
                    r.conns.send_user(
                        &w.user,
                        &ServerFrame::DeviceRevoked {
                            device_id: None,
                            by: Some(RevokedBy::Left),
                            at: at_of(now),
                        },
                    );
                    announce_org_removal(r, &w.user);
                }
                out
            })
            .await
            else {
                break;
            };
            match outcome {
                Ok(MemberOutcome::Done { .. }) => {
                    tracing::info!(user = %who.user, "조직 나감");
                    // #599: 폐기된 내 기기들이 보낸 확정 전 Commit — group_order 를 놓은 뒤.
                    let _ = blocking(&app, crate::mls_group::void_revoked_senders).await;
                    app.conns.close_user(&who.user);
                    // #622 후속(설계 리뷰 6515564969): 요청한 연결은 자기 폐기와 같이 앱이 읽고 닫을 때까지 둔다.
                    linger_until_closed(&mut stream).await;
                    break;
                }
                Ok(MemberOutcome::LastAdmin) => {
                    let _ = tx.send(error_frame(ErrorCode::LastAdmin, "member.leave"));
                }
                Ok(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Protocol, "member.leave"));
                }
                Err(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Internal, "member.leave"));
                }
            }
            continue;
        }
        // #702: directory.list 의 답도 만들기와 큐 넣기를 같은 잠금 안에서 — dispatch 가 돌려준 뒤 넣으면 그 사이 방송이 먼저 들어가
        // 이 낡은 답이 새 모습을 덮는다.
        if matches!(parsed, ClientFrame::DirectoryList) {
            let (w, q) = (who.clone(), tx.clone());
            if blocking(&app, move |r| {
                with_directory_order(r, || {
                    let _ = q.send(ServerFrame::Directory(directory(r, &w.user)).to_json());
                });
            })
            .await
            .is_none()
            {
                break;
            }
            continue;
        }
        // 시험 전용(#839 claim 보류, 기본 None): 이 연결의 읽기만 멈춘다 — 보내기 큐(tx)는 따로 돌아 Welcome 등은 그대로 간다.
        if let (ClientFrame::KeyPackagesClaim { .. }, Some(h)) =
            (&parsed, app.config.claim_hold.as_ref())
        {
            if h.take(&who.device_id) {
                h.reached.notify_one();
                h.release.notified().await;
            }
        }
        // 앞 프레임의 처리를 기다린 뒤 다음을 읽는다 — 한 연결 안의 순서를 지킨다(병렬 dispatch 금지).
        let w = who.clone();
        let rid = request_ref(frame.as_str());
        // send 의 답(ack) 뒤에 알리는 것들: #598 ② recipient_outdated, #577 §9 ② 기기 바뀜 실패(같은 연결 큐 순서).
        let sent = matches!(parsed, ClientFrame::Send { .. });
        let Some(reply) = blocking(&app, move |r| dispatch(r, &w, parsed)).await else {
            break;
        };
        if let Some(mut reply) = reply {
            // #537 (d): 요청에 대한 오류는 internal 이라도 ref 를 단다 — 보낸 쪽이 어느 행·요청의 오류인지 알아 기다림을 푼다.
            // 생성 타입으로 만든 error(until 실은 rate_limited 등, #845 §7-10)도 같다.
            match (&mut reply, rid) {
                (
                    ServerFrame::Error {
                        r#ref: r @ None, ..
                    },
                    Some(id),
                ) => *r = Some(id),
                (ServerFrame::Ws(f), Some(id)) => {
                    if let lodelai_protocol::ws::Frame::Error(e) = f.as_mut() {
                        if e.ref_.is_none() {
                            e.ref_ = Some(id);
                        }
                    }
                }
                _ => {}
            }
            let _ = tx.send(reply.to_json());
        }
        // #598 ②: send 의 답(ack) 뒤에 recipient_outdated — 보낸 기기에만, ack 보다 먼저 가지 않게.
        if sent {
            let w = who.clone();
            if let Some(fs) = blocking(&app, move |r| crate::rules::outdated_notices(r, &w)).await {
                for f in fs {
                    let _ = tx.send(f.to_json());
                }
            }
        }
        if sent {
            let _ = blocking(&app, crate::recovery::notify_device_changed).await;
        }
    }

    app.conns.remove(&who.user, conn_id);
    {
        let (u, d) = (who.user.clone(), who.device_id.clone());
        let last = blocking(&app, move |r| {
            crate::recovery::on_disconnect(r, &u, &d);
            // 이 기기의 마지막 연결이 끊겼으면 승인 전 내 기기에 바뀐 마지막 접속 시각을(가입 화면의 '맥 꺼짐'). 승인된 내 기기
            // (휴대폰 '내 에이전트'의 맥 잠듦·꺼짐, #870)는 아래에서 합쳐서.
            let online = r.conns.online_devices(&u);
            let last = !online.contains(&d);
            if last {
                crate::live::on_mac_gone(r, &u, &d);
                let _ = r.db.set_away(&d, away);
                let targets = unapproved_of(r, &u, other_devices(online, &d));
                send_my_directory(r, &u, &targets);
            }
            last
        })
        .await;
        if last == Some(true) {
            crate::presence::my_device_changed(&app, &who.user, None);
        }
    }
    crate::presence::disconnected(&app, &who.user);
    crate::presence::device_disconnected(&app, &who.user, &who.device_id);
    drop(tx);
    let _ = writer.await;
}

/// 붙어 있는 내 기기 중 `me` 를 뺀 것(같은 기기의 연결 여럿은 하나로).
fn other_devices(mut online: Vec<String>, me: &str) -> Vec<String> {
    online.retain(|d| d != me);
    online.sort();
    online.dedup();
    online
}

/// `devices` 중 폐기되지 않았고 아직 잎 자격이 없는(승인 전) 기기. 폐기된 기기는 폐기 통지 뒤에 아무것도 받지 않는다.
fn unapproved_of(app: &Relay, user: &str, mut devices: Vec<String>) -> Vec<String> {
    if devices.is_empty() {
        return devices;
    }
    let live: Vec<String> = app
        .db
        .devices_of(user)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.device_id)
        .collect();
    let eligible = crate::mls::eligible_devices(app, user);
    devices.retain(|d| live.contains(d) && !eligible.contains(d));
    devices
}

/// #870: 내 붙은 승인된(잎 자격 있는) 기기 중 `except` 를 뺀 것에 내 디렉터리(내 기기 하나의 online·away·마지막 접속 시각이
/// 바뀜). 승인 전 기기는 붙음·끊김 때 [`unapproved_of`] 길로 이미 바로 받았다. 합치기는 [`crate::presence::my_device_changed`].
pub(crate) fn send_my_devices(app: &Relay, user: &str, except: Option<&str>) {
    let mut targets = other_devices(app.conns.online_devices(user), except.unwrap_or(""));
    if targets.is_empty() {
        return;
    }
    let eligible = crate::mls::eligible_devices(app, user);
    targets.retain(|d| eligible.contains(d));
    send_my_directory(app, user, &targets);
}

/// 내 기기 `targets` 에 내 디렉터리(`directory.update`).
fn send_my_directory(app: &Relay, user: &str, targets: &[String]) {
    if targets.is_empty() {
        return;
    }
    with_directory_order(app, || {
        app.conns.send_devices(
            user,
            targets,
            &ServerFrame::DirectoryUpdate(directory(app, user)),
        );
    });
}

/// 조직 관리자 동작 적용(#355): 관리자 판정·적용 → 같은 조직에 directory.update. 실패는 모두 같은 `error{protocol}`(ref 없음).
fn admin(app: &Relay, who: &Authed, act: &AdminAct<'_>) -> Option<ServerFrame> {
    match app.db.admin_act(&who.user, act) {
        Ok(AdminOutcome::Done) => {
            broadcast_directory(app, who);
            None
        }
        Ok(AdminOutcome::NameTaken) => Some(ServerFrame::Error {
            code: ErrorCode::NameTaken,
            message: "team 이름".into(),
            r#ref: None,
        }),
        _ => Some(rules::protocol_error("org·team")),
    }
}

/// 내 기기 서명 검사(#393, protocol §7.2 `device.certify`): 서명자 = 이 연결의 기기(폐기 안 됨), 대상 = 같은 사용자의
/// 폐기 안 된 다른 기기, `lodelai-devcert-v1` 서명이 서명자 키로 맞음.
fn certify_ok(app: &Relay, who: &Authed, target: &str, sig: &str) -> bool {
    if target == who.device_id {
        return false;
    }
    let Ok(devices) = app.db.devices_of(&who.user) else {
        return false;
    };
    let (Some(signer), Some(t)) = (
        devices.iter().find(|d| d.device_id == who.device_id),
        devices.iter().find(|d| d.device_id == target),
    ) else {
        return false;
    };
    let (Ok(vk), Ok(x25519)) = (
        lodelai_crypto::VerifyingKey::from_b64(&signer.ed25519),
        lodelai_crypto::encoding::decode_array::<32>(&t.x25519, "x25519"),
    ) else {
        return false;
    };
    let cert = lodelai_crypto::devcert::Cert {
        server: &app.config.server_name,
        user: &who.user,
        device_id: target,
        x25519: &x25519,
        signer: &who.device_id,
    };
    lodelai_crypto::devcert::verify(&vk, &cert, sig)
}

/// 조직·팀 이름 규칙(표시 이름과 같다).
fn org_name(name: &str) -> Option<String> {
    lodelai_protocol::display_name::normalize(name).ok()
}

/// #737: 확인되지 않은(잎 자격 없는) 기기의 관리자 동작은 막는다 — 관리자 이메일을 뺏은 사람이 새 기기를 붙여 확인 전에
/// 조직을 바꾸지 못하게. 관리자가 아니면 여기서 거르지 않는다(원래 갈래가 protocol 로 거절).
fn unconfirmed_admin(app: &Relay, who: &Authed, what: &str) -> Option<ServerFrame> {
    if !app.db.is_org_admin(&who.user).unwrap_or(false) {
        return None;
    }
    if crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) {
        return None;
    }
    Some(ServerFrame::Error {
        code: ErrorCode::DeviceUnconfirmed,
        message: what.into(),
        r#ref: None,
    })
}

/// #737 관리자 폐기: 같은 조직 다른 사람의 메일 확인 끊기 대상 기기를 지금 끊는다. 순서는 `member.remove` 와 같게 — 폐기
/// 커밋 → 그 기기에 device.revoked{by: admin} → MLS duty → 걸기 다시 보기 → directory.update → 연결 닫음 → 메일.
fn member_revoke_device(
    app: &Relay,
    who: &Authed,
    user: &str,
    device_id: &str,
) -> Option<ServerFrame> {
    if let Some(e) = unconfirmed_admin(app, who, "member.revoke_device") {
        return Some(e);
    }
    let now = app.effects.clock.now().0;
    {
        let _order = app
            .group_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match app.db.admin_revoke_device(&who.user, user, device_id, now) {
            Ok(true) => {}
            Ok(false) => return Some(rules::protocol_error("member.revoke_device")),
            Err(_) => return Some(rules::internal_error()),
        }
        tracing::info!(by = %who.user, user = %user, device = %device_id, "관리자가 예전 기기 끊음");
        app.conns.send_devices(
            user,
            &[device_id.to_owned()],
            &ServerFrame::DeviceRevoked {
                device_id: None,
                by: Some(RevokedBy::AdminDevice),
                at: at_of(now),
            },
        );
    }
    crate::mls_group::void_revoked_senders(app);
    crate::mls::refresh_add_duties(app, user);
    crate::mls::rejoin_orphaned(app, user);
    crate::recovery::on_admin_cut(app, user, now);
    broadcast_directory_of(app, user);
    app.conns.close_device(user, device_id);
    crate::recovery::mail_admin_cut(app, user, now);
    None
}

fn dispatch(app: &Relay, who: &Authed, frame: ClientFrame) -> Option<ServerFrame> {
    let admin_act = match &frame {
        ClientFrame::OrgAdmin { .. } => Some("org.admin"),
        ClientFrame::MemberRemove { .. } => Some("member.remove"),
        ClientFrame::OrgUpdate { .. } => Some("org.update"),
        ClientFrame::TeamCreate { .. } => Some("team.create"),
        ClientFrame::TeamUpdate { .. } => Some("team.update"),
        ClientFrame::TeamDelete { .. } => Some("team.delete"),
        // 확인 전 기기가 남(또는 자기 다른 계정)을 초대하면 이 기기를 끊어도 그 계정이 조직에 남는다.
        ClientFrame::InviteCreate { .. } => Some("invite.create"),
        _ => None,
    };
    if let Some(e) = admin_act.and_then(|w| unconfirmed_admin(app, who, w)) {
        return Some(e);
    }
    match frame {
        ClientFrame::Send { message } => Some(rules::handle_send(app, who, message)),
        ClientFrame::DeliveredAck { msg_id, unreadable } => {
            rules::handle_delivered_ack(app, who, &msg_id, unreadable);
            None
        }
        ClientFrame::Status {
            msg_id,
            state,
            abort_reason,
            fail_reason,
            at,
        } => rules::handle_status(
            app,
            who,
            &msg_id,
            &state,
            abort_reason.as_deref(),
            fail_reason.as_deref(),
            &at,
        ),
        ClientFrame::SessionPublish {
            slug,
            grade,
            liveness,
            display,
            title,
            folder,
            project,
            capabilities: _,
            busy,
            audience,
            agent,
            no,
        } => {
            // 세션 표시 이름·제목·폴더도 사람 표시 이름과 같은 규칙(#348, m1-spec §2) — 동료 세션의
            // list_sessions·화면으로 들어간다. 하나라도 어긋나면 프레임 전체를 거부한다.
            // 폴더는 cwd 마지막 성분만 — 경로 구분자도 거부한다(normalize_folder, 코어도 같은 함수로 거른다).
            let (Ok(display), Ok(title), Ok(folder)) = (
                optional(
                    display.as_deref(),
                    lodelai_protocol::display_name::normalize,
                ),
                optional(title.as_deref(), lodelai_protocol::display_name::normalize),
                optional(
                    folder.as_deref(),
                    lodelai_protocol::display_name::normalize_folder,
                ),
            ) else {
                return Some(rules::protocol_error("session.publish 형식"));
            };
            // 프로젝트(묶음 23 §5): 구분 이름은 성분마다 폴더 규칙 + 전체 64자 — 전체 경로가 새지 않게. id 꼴은 스키마가 봄.
            let project = match project {
                None => None,
                Some((id, name)) => {
                    match lodelai_protocol::display_name::normalize_project_name(&name) {
                        Ok(n) => Some((id, n)),
                        Err(_) => return Some(rules::protocol_error("session.publish 형식")),
                    }
                }
            };
            if !valid_slug(&slug)
                || !matches!(grade.as_str(), "question" | "task")
                || !matches!(
                    liveness.as_str(),
                    "live:channel" | "live:pty" | "live:next_turn" | "dead"
                )
            {
                return Some(rules::protocol_error("session.publish 형식"));
            }
            let Some(audience) = checked_audience(app, &who.user, audience) else {
                return Some(rules::protocol_error("session.publish audience"));
            };
            let (audience, audience_lists) = match audience {
                Some((u, l)) => (Some(u), l),
                None => (None, Vec::new()),
            };
            let s = PublicSession {
                user: who.user.clone(),
                slug,
                grade,
                liveness,
                display,
                title,
                folder,
                project,
                busy,
                audience,
                audience_lists,
                listed: Vec::new(),
                agent,
                no,
                offline: false,
            };
            if app.db.publish_session(&s, Some(&who.device_id)).is_err() {
                return Some(rules::protocol_error("session.publish"));
            }
            broadcast_directory(app, who);
            None
        }
        ClientFrame::SessionUnpublish { slug } => {
            let _ = app.db.unpublish_session(&who.user, &slug);
            broadcast_directory(app, who);
            None
        }
        // 연결의 읽기 고리는 directory.list 를 여기 오기 전에 잠금 안에서 답한다(#702). 여기는 그 밖의 부르는 곳(시험)용.
        ClientFrame::DirectoryList => Some(ServerFrame::Directory(directory(app, &who.user))),
        ClientFrame::ProfileUpdate {
            display_name,
            teams,
            clear_avatar,
            look,
        } => {
            // 없는 필드는 안 바꾼다(#355). 둘 다 검사한 뒤에 바꾼다 — 하나만 바뀌고 오류가 나지 않게.
            let display = match display_name
                .as_deref()
                .map(lodelai_protocol::display_name::normalize)
            {
                None => None,
                Some(Ok(d)) => Some(d),
                Some(Err(_)) => return Some(rules::protocol_error("profile.update 형식")),
            };
            if let Some(ts) = &teams {
                if !matches!(app.db.set_user_teams(&who.user, ts), Ok(true)) {
                    return Some(rules::protocol_error("profile.update teams"));
                }
            }
            if let Some(d) = &display {
                if app.db.set_display(&who.user, d).is_err() {
                    return Some(rules::protocol_error("profile.update"));
                }
            }
            // 사진 지우기(묶음 15 §2): 이미 없고 다른 필드도 없으면 방송하지 않는다.
            let mut cleared = false;
            if clear_avatar {
                match app.db.clear_avatar(&who.user) {
                    Ok(old) => {
                        cleared = old.is_some();
                        crate::blob::remove_files(app, &old.into_iter().collect::<Vec<_>>());
                    }
                    Err(_) => return Some(rules::protocol_error("profile.update")),
                }
            }
            // #874: 고르면 사진도 같이 지운다(한 트랜잭션 — 둘이 어긋난 모습이 방송되지 않게). 같은 값이면 바뀜 없음.
            let mut looked = false;
            if let Some(l) = &look {
                match app.db.set_look(&who.user, l.as_deref()) {
                    Ok((changed, old_avatar)) => {
                        looked = changed;
                        crate::blob::remove_files(app, &old_avatar.into_iter().collect::<Vec<_>>());
                    }
                    Err(_) => return Some(rules::protocol_error("profile.update")),
                }
            }
            if cleared || looked || display.is_some() || teams.is_some() {
                broadcast_directory(app, who);
            }
            None
        }
        ClientFrame::OrgUpdate {
            name,
            clear_avatar,
            color,
            external,
        } => {
            // 둘 다 없으면 형식 오류. 이름 규칙·관리자는 바꾸기 전에 모두 본다(하나만 바뀌지 않게).
            let name = match name.as_deref().map(org_name) {
                None => None,
                Some(Some(n)) => Some(n),
                Some(None) => return Some(rules::protocol_error("org·team 이름 형식")),
            };
            if name.is_none() && !clear_avatar && color.is_none() && external.is_none() {
                return Some(rules::protocol_error("org.update"));
            }
            // 조직 색·밖 연락 막기는 관리자·조직(개인 공간 아님)만 — 다른 것을 바꾸기 전에 본다.
            if (color.is_some() || external.is_some())
                && !matches!(app.db.org_admin_of(&who.user), Ok(Some(o)) if app.db.org_kind(&o).ok().flatten().as_deref() == Some("org"))
            {
                return Some(rules::protocol_error("org.update color"));
            }
            let org = if clear_avatar {
                match app.db.org_admin_of(&who.user) {
                    Ok(Some(org)) => Some(org),
                    _ => return Some(rules::protocol_error("org·team")),
                }
            } else {
                None
            };
            // 조직 사진 지우기(#554) 먼저 — 이름도 바꾸면 그 방송에 지운 결과가 실린다. 이미 없으면 방송하지 않는다.
            let mut cleared = false;
            if let Some(org) = org {
                match app.db.clear_org_avatar(&org) {
                    Ok(old) => {
                        cleared = old.is_some();
                        crate::blob::remove_files(app, &old.into_iter().collect::<Vec<_>>());
                    }
                    Err(_) => return Some(rules::protocol_error("org.update")),
                }
            }
            let mut colored = false;
            if let Some(c) = &color {
                match app.db.set_org_color(&who.user, c.as_deref()) {
                    Ok(crate::db::OrgColorOut::Changed { org }) => {
                        tracing::info!(org = %org, "조직 색 바꿈");
                        colored = true;
                    }
                    Ok(crate::db::OrgColorOut::Same) => {}
                    _ => return Some(rules::protocol_error("org.update color")),
                }
            }
            // #845 둘째 ②: 막거나 풀면 조직 멤버와 그 조직 밖 연락처·걸렸던 요청 상대 모두 디렉터리를 다시 받는다.
            let mut outsiders: Option<Vec<String>> = None;
            if let Some(closed) = external {
                match app.db.set_org_external(&who.user, closed) {
                    Ok(crate::db::OrgExternalOut::Changed { org, outsiders: o }) => {
                        tracing::info!(org = %org, closed, "조직 밖 연락 막기 바꿈");
                        outsiders = Some(o);
                    }
                    Ok(crate::db::OrgExternalOut::Same) => {}
                    _ => return Some(rules::protocol_error("org.update external")),
                }
            }
            if let Some(n) = &name {
                let r = admin(app, who, &AdminAct::OrgRename { name: n });
                if let Some(o) = outsiders.filter(|o| !o.is_empty()) {
                    send_directory_to(app, &o);
                }
                return r;
            }
            if cleared || colored || outsiders.is_some() {
                broadcast_directory(app, who);
            }
            if let Some(o) = outsiders.filter(|o| !o.is_empty()) {
                send_directory_to(app, &o);
            }
            None
        }
        ClientFrame::TeamCreate { name } => match org_name(&name) {
            Some(n) => {
                let id = app.effects.ids.next_ulid();
                admin(app, who, &AdminAct::TeamCreate { id: &id, name: &n })
            }
            None => Some(rules::protocol_error("org·team 이름 형식")),
        },
        ClientFrame::TeamUpdate { id, name } => match org_name(&name) {
            Some(n) => admin(app, who, &AdminAct::TeamRename { id: &id, name: &n }),
            None => Some(rules::protocol_error("org·team 이름 형식")),
        },
        ClientFrame::TeamDelete { id } => admin(app, who, &AdminAct::TeamDelete { id: &id }),
        ClientFrame::InviteCreate { email } => {
            let email = match email.as_deref().map(crate::http::normalize_email) {
                None => None,
                Some(Some(e)) => Some(e),
                Some(None) => return Some(rules::protocol_error("invite.create 형식")),
            };
            let mut raw = [0u8; 32];
            if app.effects.rng.try_fill(&mut raw).is_err() {
                return Some(ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "invite.create".into(),
                    r#ref: None,
                });
            }
            let token = encoding::encode(&raw);
            let now = app.effects.clock.now().0;
            let expires = now + INVITE_TTL_MS;
            let hash = crate::http::invite_hash(&token);
            match app.db.admin_act(
                &who.user,
                &AdminAct::Invite {
                    token_hash: &hash,
                    email: email.as_deref(),
                    now_ms: now,
                    expires_ms: expires,
                    window_ms: INVITE_WINDOW_MS,
                    max: INVITE_MAX,
                },
            ) {
                Ok(AdminOutcome::Done) => Some(ServerFrame::InviteCreated {
                    token,
                    expires_at: lodelai_effects::UnixMillis(expires)
                        .to_rfc3339()
                        .unwrap_or_default(),
                }),
                // 발급 상한은 연결을 끊는 rate_limited 가 아니라 이 요청만 거절한다 — protocol 과 구분해 알린다.
                Ok(AdminOutcome::RateLimited) => Some(ServerFrame::Error {
                    code: ErrorCode::RateLimited,
                    message: "invite.create".into(),
                    r#ref: None,
                }),
                _ => Some(rules::protocol_error("invite.create")),
            }
        }
        // run() 이 dispatch 전에 처리한다(응답·방송·닫기 순서 때문에).
        ClientFrame::DeviceRevoke { .. } => None,
        ClientFrame::BlobReserve {
            req,
            ct_len,
            avatar,
            for_org,
            for_device,
        } => Some(crate::blob::reserve(
            app,
            who,
            &req,
            ct_len,
            avatar,
            for_org,
            for_device.as_deref(),
        )),
        ClientFrame::BlobGet { req, blob_id } => {
            Some(crate::blob::get_ticket(app, who, &req, &blob_id))
        }
        ClientFrame::BlobFetched { blob_id } => {
            crate::blob::fetched(app, who, &blob_id);
            None
        }
        ClientFrame::GroupsList => match groups_frame(app, &who.user) {
            Ok(f) => Some(f),
            Err(_) => Some(ServerFrame::Error {
                code: ErrorCode::Internal,
                message: "groups.list".into(),
                r#ref: None,
            }),
        },
        ClientFrame::GroupsReplay { group, from_seq } => {
            // 그룹 끔(묶음 16 §3b)이면 모르는 그룹과 같다.
            let gid = crate::frames::Address::parse(&group)
                .filter(|a| app.config.groups && a.server == app.config.server_name)
                .and_then(|a| a.gid().map(str::to_owned));
            let found = gid.map(|g| app.db.group_replay(&g, &who.user, &who.device_id, from_seq));
            match found {
                Some(Ok(Some(items))) => {
                    for (m, seq) in items {
                        if let Ok(message) = serde_json::from_str(&m) {
                            app.conns.send_device(
                                &who.user,
                                &who.device_id,
                                &ServerFrame::Deliver {
                                    message,
                                    group_seq: Some(seq),
                                },
                            );
                        }
                    }
                    None
                }
                _ => Some(rules::protocol_error("groups.replay")),
            }
        }
        // 연결 루프가 먼저 받는다(연결마다 상한) — 여기 오지 않는다.
        ClientFrame::Typing { .. }
        | ClientFrame::OwnStream { .. }
        | ClientFrame::OwnAlert { .. }
        | ClientFrame::OwnLive { .. } => None,
        ClientFrame::LinkRequest { req, to } => link_request(app, who, req, &to),
        ClientFrame::LinkAnswer { id, answer } => {
            let answer = match answer {
                crate::frames::LinkAnswerKind::Accept => crate::db::LinkAnswer::Accept,
                crate::frames::LinkAnswerKind::Decline => crate::db::LinkAnswer::Decline,
                crate::frames::LinkAnswerKind::Block => crate::db::LinkAnswer::Block,
            };
            let now = app.effects.clock.now().0;
            match app.db.link_answer(&who.user, &id, answer, now) {
                // 모르는·만료된·이미 답한 id 는 조용히(설계 §7-7 5).
                Ok(None) => None,
                Ok(Some(from)) => {
                    tracing::info!(user = %who.user, ?answer, "연락 요청 답");
                    send_directory_to(app, &[who.user.clone(), from]);
                    None
                }
                Err(_) => Some(rules::internal_error()),
            }
        }
        ClientFrame::LinkRemove { peer, block } => match link_peer(app, &peer) {
            Some(p) if p == who.user => None,
            Some(p) => match app
                .db
                .link_remove(&who.user, &p, block, app.effects.clock.now().0)
            {
                Ok(true) => {
                    tracing::info!(user = %who.user, "연락처 빼기");
                    send_directory_to(app, &[who.user.clone(), p]);
                    None
                }
                Ok(false) => None,
                Err(_) => Some(rules::internal_error()),
            },
            None => None,
        },
        ClientFrame::LinkUpdate { peer, task_ok } => match link_peer(app, &peer) {
            Some(p) => match app.db.link_update(&who.user, &p, task_ok) {
                Ok(true) => {
                    send_directory_to(app, &[who.user.clone(), p]);
                    None
                }
                Ok(false) => None,
                Err(_) => Some(rules::internal_error()),
            },
            None => None,
        },
        ClientFrame::ContactLink { req, rotate } => {
            let nonce = app.effects.ids.next_ulid();
            match app
                .db
                .contact_link(&who.user, &nonce, rotate, app.effects.clock.now().0)
            {
                Ok(token) => {
                    if rotate {
                        tracing::info!(user = %who.user, "초대 링크 다시 만듦");
                    }
                    let mut v = serde_json::json!({"t": "contact_link", "token": token});
                    if let Some(r) = req {
                        v["req"] = r.into();
                    }
                    match serde_json::from_value::<lodelai_protocol::ws::Frame>(v) {
                        Ok(f) => Some(ServerFrame::Ws(Box::new(f))),
                        Err(_) => Some(rules::internal_error()),
                    }
                }
                Err(_) => Some(rules::internal_error()),
            }
        }
        // 답은 늘 link.sent(모르는·끝난 토큰·막힌 사이도 같은 바이트).
        ClientFrame::LinkJoin { req, token } => {
            match app
                .db
                .link_join(&who.user, &token, app.effects.clock.now().0)
            {
                Ok(Some(owner)) => {
                    tracing::info!(user = %who.user, "초대 링크로 연락처");
                    send_directory_to(app, &[who.user.clone(), owner]);
                }
                Ok(None) => {}
                Err(_) => return Some(rules::internal_error()),
            }
            Some(link_sent(req, false))
        }
        ClientFrame::ContactLinkPreview { req, token } => {
            contact_link_preview(app, who, req, &token)
        }
        ClientFrame::OrgInvite { req, email } => org_invite(app, who, req, &email),
        ClientFrame::GroupInvite { req, group, to } => group_invite(app, who, req, &group, &to),
        // §7-26: 답 프레임 없음 — 결과는 디렉터리. 받는 쪽엔 알리지 않는다(카드가 다음 디렉터리에서 빠질 뿐).
        ClientFrame::OrgInviteWithdraw { id } => {
            match app
                .db
                .org_invite_withdraw(&who.user, &id, app.effects.clock.now().0)
            {
                Ok(Some((org, card))) => {
                    tracing::info!(by = %who.user, "조직 초대 거두기");
                    let mut to = app.db.org_admins_of(&org).unwrap_or_default();
                    to.extend(card);
                    send_directory_to(app, &to);
                    None
                }
                Ok(None) => None,
                Err(_) => Some(rules::internal_error()),
            }
        }
        ClientFrame::GroupInviteWithdraw { id } => {
            match app.db.group_invite_withdraw(&who.user, &id) {
                Ok(Some((gid, card))) => {
                    tracing::info!(by = %who.user, "그룹 초대 거두기");
                    let mut to = vec![who.user.clone()];
                    to.extend(card);
                    send_directory_to(app, &to);
                    send_directory_to_invitees(app, &gid, &to);
                    None
                }
                Ok(None) => None,
                Err(_) => Some(rules::internal_error()),
            }
        }
        ClientFrame::GroupInviteAnswer { id, accept } => {
            match app
                .db
                .group_invite_answer(&who.user, &id, accept, app.effects.clock.now().0)
            {
                Ok(Some((gid, by, true))) => {
                    tracing::info!(user = %who.user, "그룹 초대 수락");
                    send_directory_to(app, &[who.user.clone(), by]);
                    send_groups_to_members(app, &gid);
                    None
                }
                Ok(Some((gid, _, false))) => {
                    send_directory_to(app, std::slice::from_ref(&who.user));
                    send_directory_to_invitees(app, &gid, &[]);
                    None
                }
                Ok(None) => None,
                Err(_) => Some(rules::internal_error()),
            }
        }
        ClientFrame::MuteSet {
            req,
            conv,
            until,
            clear,
        } => mute_set(app, who, req, &conv, until.as_deref(), clear),
        ClientFrame::PinSet { req, conv, index } => pin_set(app, who, req, &conv, index),
        ClientFrame::ListPut {
            req,
            list_id,
            name,
            users,
        } => list_put(app, who, req, &list_id, &name, users),
        ClientFrame::ListDelete { req, list_id } => list_delete(app, who, req, &list_id),
        ClientFrame::OrgCodeCheck { req, code } => org_code_check(app, who, req, &code),
        ClientFrame::OrgExternalPreview { req } => org_external_preview(app, who, req),
        ClientFrame::OrgJoin { req, code, teams } => org_join(app, who, req, &code, &teams),
        ClientFrame::OrgCreate {
            req,
            name,
            setup_code,
        } => org_create(app, who, req, &name, setup_code.as_deref()),
        ClientFrame::OrgInviteAnswer { id, accept } => {
            match app
                .db
                .org_invite_answer(&who.user, &id, accept, app.effects.clock.now().0)
            {
                Ok(Some((_old, _new))) => {
                    tracing::info!(user = %who.user, "조직 초대 수락 — 조직 옮김");
                    // 새 조직 동료에게 새 사람, 그 뒤 내 연결은 org_changed 를 받고 닫힌다(앱은 바로 다시 붙는다).
                    broadcast_directory_of(app, &who.user);
                    app.conns.send_user(
                        &who.user,
                        &ServerFrame::Error {
                            code: ErrorCode::OrgChanged,
                            message: "org.invite.answer".into(),
                            r#ref: None,
                        },
                    );
                    app.conns.close_user(&who.user);
                    None
                }
                Ok(None) => {
                    if !accept {
                        send_directory_to(app, std::slice::from_ref(&who.user));
                    }
                    None
                }
                Err(_) => Some(rules::internal_error()),
            }
        }
        // §7-9: 상대에게 알림은 없다. 다만 상대 디렉터리도 한 번 보내 받은 요청 줄을 바로 뺀다(관문 A4 —
        // 남은 줄을 수락하면 조용히 사라졌다). 기다림·거절당함 어느 쪽이든 늘 보내므로 가를 것이 없다
        // (거절한 쪽엔 원래 줄이 없어 바뀌는 게 없음).
        ClientFrame::LinkWithdraw { id } => match app.db.link_withdraw(&who.user, &id) {
            Ok(Some(peer)) => {
                tracing::info!(user = %who.user, "보낸 연락 요청 거두기");
                let mut to = vec![who.user.clone()];
                to.extend(peer);
                send_directory_to(app, &to);
                None
            }
            Ok(None) => None,
            Err(_) => Some(rules::internal_error()),
        },
        // 관문 A6: 막음 줄만 지운다. 막은 적 없음·모름·나 자신도 같은 답(아이디가 있는지 새지 않게, 되풀이해도 같음).
        // 상대에겐 아무것도 안 간다 — 막기는 상대 쪽에서 '연락처 빠짐'으로만 보였고 풀어도 바뀌는 것이 없다.
        ClientFrame::LinkUnblock { req, peer } => {
            let r = match link_peer(app, &peer) {
                Some(p) if p != who.user => app.db.unblock(&who.user, &p),
                _ => Ok(false),
            };
            match r {
                Ok(changed) => {
                    if changed {
                        tracing::info!(user = %who.user, "막음 풀기");
                        send_directory_to(app, std::slice::from_ref(&who.user));
                    }
                    Some(link_sent(req, false))
                }
                Err(_) => Some(ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "internal".to_owned(),
                    r#ref: req,
                }),
            }
        }
        // #923 §11: 내가 이미 아는 사람에게만 막음 줄(db link_block). 모르는·없는 사람·나 자신·이미 막음도 같은 답, 상대엔 0.
        ClientFrame::LinkBlock { req, peer } => {
            let r = match link_peer(app, &peer) {
                Some(p) => app.db.link_block(&who.user, &p, app.effects.clock.now().0),
                None => Ok(false),
            };
            match r {
                Ok(changed) => {
                    if changed {
                        tracing::info!(user = %who.user, "사람 막기");
                        send_directory_to(app, std::slice::from_ref(&who.user));
                    }
                    Some(link_sent(req, false))
                }
                Err(_) => Some(ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "internal".to_owned(),
                    r#ref: req,
                }),
            }
        }
        ClientFrame::Report(r) => report(app, who, *r),
        ClientFrame::PresenceSet { share } => match app.db.set_share_presence(&who.user, share) {
            Ok(true) => {
                tracing::info!(user = %who.user, share, "접속 표시 설정");
                broadcast_directory(app, who);
                None
            }
            Ok(false) => None,
            Err(_) => Some(ServerFrame::Error {
                code: ErrorCode::Internal,
                message: "presence.set".into(),
                r#ref: None,
            }),
        },
        ClientFrame::DeviceCertify { device_id, sig } => {
            if !certify_ok(app, who, &device_id, &sig) {
                return Some(rules::protocol_error("device.certify"));
            }
            let now = app.effects.clock.now().0;
            match app
                .db
                .put_device_cert(&who.device_id, &device_id, &sig, now)
            {
                Ok(true) => {}
                // 같은 쌍·같은 sig — 바뀐 것이 없으니 방송하지 않는다(설계 리뷰 eb674083).
                Ok(false) => return None,
                Err(_) => {
                    return Some(ServerFrame::Error {
                        code: ErrorCode::Internal,
                        message: "device.certify".into(),
                        r#ref: None,
                    })
                }
            }
            tracing::info!(user = %who.user, by = %who.device_id, device = %device_id, "내 기기 서명");
            broadcast_directory(app, who);
            // 묶음 22 §7: 새로 잎 자격을 얻은 기기를 내 다른 기기가 들이게.
            crate::mls::refresh_add_duties(app, &who.user);
            // #577: 요청 기기가 잎 자격을 얻었으면 메일 확인 끊기는 끝난다.
            crate::recovery::on_trust_change(app, &who.user);
            None
        }
        ClientFrame::DeviceRecover => crate::recovery::start(app, who),
        ClientFrame::DeviceRecoverCancel => crate::recovery::cancel(app, who),
        ClientFrame::DeviceRecoverBlock => crate::recovery::block(app, who),
        // 묶음 4 의 연결 코드 등록은 묶음 5 에서 없앴다 — 서버 relay 는 이메일 가입·초대로만 사람·기기를 들인다(m1-spec §17.3).
        ClientFrame::DeviceRegister { .. } => Some(rules::protocol_error("device.register")),
        ClientFrame::MemberRevokeDevice { user, device_id } => {
            member_revoke_device(app, who, &user, &device_id)
        }
        ClientFrame::OrgAdmin { user, admin } => match app.db.set_admin(&who.user, &user, admin) {
            Ok(MemberOutcome::Done { .. }) => {
                tracing::info!(by = %who.user, user = %user, admin, "관리자 바꿈");
                broadcast_directory(app, who);
                None
            }
            Ok(MemberOutcome::Unchanged) => None,
            Ok(MemberOutcome::LastAdmin) => Some(ServerFrame::Error {
                code: ErrorCode::LastAdmin,
                message: "org.admin".into(),
                r#ref: None,
            }),
            _ => Some(rules::protocol_error("org.admin")),
        },
        ClientFrame::MemberRemove { user } => {
            let now = app.effects.clock.now().0;
            let (reply, removed) = {
                // 폐기 커밋 → directory.update 사이에 그룹 변경 전달이 끼지 않게(묶음 16 §3a ④).
                let _order = app
                    .group_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                member_remove(app, who, &user, now)
            };
            // #599: 내보낸 사람의 폐기된 기기가 보낸 확정 전 Commit — group_order 를 놓은 뒤.
            if removed {
                crate::mls_group::void_revoked_senders(app);
            }
            reply
        }
        // run() 이 dispatch 전에 처리한다(나간 뒤 이 연결을 닫아야 해서).
        ClientFrame::MemberLeave | ClientFrame::OrgLeave => None,
        ClientFrame::DeviceName { name, os } => device_name(app, who, &name, os.as_deref()),
        // #882: 현황 받기·Live Activity 토큰. 푸시 자격이 없는 relay 는 기능 표시도 없다 — protocol.
        ClientFrame::PushLive {
            req,
            on,
            start_token,
            activity,
        } => Some(if app.push.get().is_some() {
            crate::live::on_push_live(app, who, req, on, start_token, activity)
        } else {
            ServerFrame::Error {
                code: ErrorCode::Protocol,
                message: "push.live".into(),
                r#ref: Some(req),
            }
        }),
        ClientFrame::PushRegister {
            req,
            apns,
            token,
            sandbox,
            app_id,
            off,
        } => Some(push_register(
            app, who, req, apns, token, sandbox, app_id, &off,
        )),
        ClientFrame::PushUnregister { req } => Some(if app.config.mobile_push {
            let _ = app.db.push_token_drop(&who.device_id);
            push_ok(req, None)
        } else {
            push_error(req)
        }),
        // 원격 relay 의 관리자 누구나(묶음 5). 응답은 로그에 남기지 않는다.
        ClientFrame::ServerStatus => {
            let org = app
                .config
                .remote
                .then(|| app.db.user_org(&who.user).ok().flatten())
                .flatten()
                .filter(|_| app.db.is_org_admin(&who.user).unwrap_or(false));
            let Some(org) = org else {
                return Some(rules::protocol_error("server.status"));
            };
            Some(match crate::status::server_status(app, &org) {
                Some(s) => ServerFrame::ServerStatus(Box::new(s)),
                None => ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "server.status".into(),
                    r#ref: None,
                },
            })
        }
        ClientFrame::Ping => Some(ServerFrame::Pong),
        ClientFrame::KeyPackagesPublish {
            items,
            last_resort,
            reset,
        } => crate::mls::publish(app, who, &items, last_resort.as_deref(), reset),
        ClientFrame::KeyPackagesClaim { device_ids } => crate::mls::claim(app, who, &device_ids),
        ClientFrame::GroupInfoGet { group } => Some(crate::mls::group_info_get(app, who, &group)),
        ClientFrame::CommitVote {
            group,
            epoch,
            commit_hash,
            ack,
        } => {
            crate::mls_group::vote(app, who, &group, epoch, &commit_hash, ack);
            None
        }
        ClientFrame::Pong => None,
        ClientFrame::Hello { .. } | ClientFrame::Auth { .. } => {
            Some(rules::protocol_error("이미 인증됨"))
        }
    }
}

/// 선택 이름 필드 검사 — 없으면 `Ok(None)`, 있으면 `check` 를 통과한 값.
fn optional<E>(
    raw: Option<&str>,
    check: fn(&str) -> Result<String, E>,
) -> Result<Option<String>, E> {
    raw.map(check).transpose()
}

fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `session.publish.audience` 검사(묶음 20 §2): 없거나 `org` 면 `Some(None)`(조직 전체). `people` 은 1~256명, 중복 없음,
/// 나 자신 없음 — 어기면 `None`(error{protocol}). 지금 내 조직에 없는 아이디는 빼고 저장한다(내보낸·나간 사람 행은 같은 조직이라
/// 남는다 — 라우팅에서 범위 밖으로 친다).
#[allow(clippy::type_complexity)]
fn checked_audience(
    app: &Relay,
    me: &str,
    a: Option<lodelai_protocol::ws::Audience>,
) -> Option<Option<(Vec<String>, Vec<String>)>> {
    use lodelai_protocol::ws::AudienceKind;
    let Some(a) = a else { return Some(None) };
    match a.kind {
        AudienceKind::Org => (a.users.is_empty() && a.lists.is_empty()).then_some(None),
        AudienceKind::People => {
            let org = app.db.user_org(me).ok().flatten()?;
            let mut seen = std::collections::HashSet::new();
            let mut seen_lists = std::collections::HashSet::new();
            let lists: Vec<String> = a.lists.into_iter().map(String::from).collect();
            // #845 둘째: users+lists 합쳐 1개 이상, lists 0~16·중복 없음. 없는 목록 id 는 거절하지 않는다(빈 목록으로 봄).
            let shape_ok = !(a.users.is_empty() && lists.is_empty())
                && a.users.len() <= AUDIENCE_MAX
                && lists.len() <= crate::db::AUDIENCE_LISTS_MAX
                && lists.iter().all(|l| seen_lists.insert(l.as_str()))
                && a.users
                    .iter()
                    .all(|u| u.as_str() != me && seen.insert(u.as_str()));
            if !shape_ok {
                return None;
            }
            // 지금 내 조직에 없는 아이디(모름·다른 조직으로 옮김)는 거절하지 않고 뺀다(d3284b3c) — 주인 코어가 쥔 옛 범위로 다시
            // publish 할 때마다 거절되지 않게. 좁히는 쪽으로만 틀린다. 다 빠지면 빈 목록(주인만).
            Some(Some((
                a.users
                    .into_iter()
                    .map(String::from)
                    .filter(|u| {
                        app.db.user_org(u).ok().flatten().as_deref() == Some(org.as_str())
                            || app.db.linked(me, u).unwrap_or(false)
                    })
                    .collect(),
                lists,
            )))
        }
    }
}

/// 옛 판 연결로 나갈 프레임을 그 판 꼴로 낮춘다(#598 ② 계약 4절 — 판이 섞여 도는 동안의 안전망). 판 15 이상은 그대로.
/// - typing(#613): 판 11 아래엔 보내지 않는다(`None`).
/// - 전체 directory: 판 13 아래엔 세션 항목의 agent·no, 사람 항목 recovery 의 postponed(#737)를 뺀다(12 앱은
///   additionalProperties false).
/// - error `device_unconfirmed`(#737): 판 13 아래엔 `protocol` 로.
/// - `device.revoked`·`error{device_revoked}` 의 `by: admin_device`(#737): 판 13 아래엔 `admin` 으로.
/// - directory·directory.update: `DirectoryDevice.v` 를 뺀다(9 앱의 DirectoryDevice 는 additionalProperties false).
/// - status `done`: `aborted{abort_reason: turn_ended}` 로(9 앱은 done 을 모른다 — 지금과 같은 '중단' 표시).
/// - directory·directory.update: 판 15 아래엔 기기 항목의 `online`(모바일 가입 '맥 꺼짐')·`os` 를 뺀다.
///
/// 문자열에 그 표식이 없으면 파싱하지 않는다(대부분의 프레임).
pub fn for_version(text: Utf8Bytes, v: u64) -> Option<Utf8Bytes> {
    if v >= DEVICE_ONLINE_FROM {
        return Some(text);
    }
    let s = text.as_str();
    // 판 15 아래 앱의 DirectoryDevice 는 모르는 칸을 거절한다 — 내 기기 항목의 online·os 를 뺀다.
    let dir_online =
        s.contains("\"t\":\"directory") && (s.contains("\"online\"") || s.contains("\"os\""));
    if v >= SESSION_FIELDS_FROM {
        return if dir_online {
            Some(without_device_online(s).unwrap_or(text))
        } else {
            Some(text)
        };
    }
    // 판 11 아래 앱은 typing 을 모른다(#613 계약 §5) — 보내지 않는다.
    if v < crate::presence::TYPING_FROM && s.contains("\"t\":\"typing\"") {
        return None;
    }
    // 판 13 아래 앱의 전체 `directory`(접속·directory.list 답)는 세션 항목이 모르는 칸을 거절한다(additionalProperties
    // false·deny_unknown_fields) — 13 칸 agent·no 를 뺀다(백엔드 리뷰 Y2). directory.update 는 모르는 칸을 받으니 그대로.
    let full_dir = s.contains("\"t\":\"directory\"");
    let old = v < 10;
    let dir_v = old && s.contains("\"t\":\"directory");
    let done = old && s.contains("\"t\":\"status\"") && s.contains("\"state\":\"done\"");
    let unconfirmed = s.contains("\"device_unconfirmed\"");
    let admin_device = s.contains("\"admin_device\"");
    if !full_dir && !dir_v && !done && !unconfirmed && !admin_device && !dir_online {
        return Some(text);
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return Some(text);
    };
    if full_dir && f["t"] == "directory" {
        for x in f["sessions"].as_array_mut().into_iter().flatten() {
            if let Some(o) = x.as_object_mut() {
                o.remove("agent");
                o.remove("no");
                o.remove("offline");
            }
        }
        // #737: 12 앱의 DirectoryRecovery 도 additionalProperties false.
        for p in f["people"].as_array_mut().into_iter().flatten() {
            if let Some(o) = p["recovery"].as_object_mut() {
                o.remove("postponed");
            }
        }
    }
    // #737: 12 앱의 error.code 는 닫힌 enum — 모르는 device_unconfirmed 는 protocol 로(전과 같은 거절).
    if unconfirmed && f["t"] == "error" && f["code"] == "device_unconfirmed" {
        f["code"] = serde_json::Value::String("protocol".into());
    }
    // #737: 12 앱의 by 도 닫힌 enum — 관리자의 옛 기기 끊기는 admin 으로(전과 같은 문구).
    if admin_device
        && (f["t"] == "device.revoked" || f["t"] == "error")
        && f["by"] == "admin_device"
    {
        f["by"] = serde_json::Value::String("admin".into());
    }
    if dir_v || dir_online {
        for p in f["people"].as_array_mut().into_iter().flatten() {
            for d in p["devices"].as_array_mut().into_iter().flatten() {
                if let Some(o) = d.as_object_mut() {
                    if dir_v {
                        o.remove("v");
                    }
                    o.remove("online");
                    o.remove("os");
                }
            }
        }
    }
    if done && f["t"] == "status" && f["state"] == "done" {
        f["state"] = serde_json::Value::String("aborted".into());
        f["abort_reason"] = serde_json::Value::String("turn_ended".into());
    }
    Some(Utf8Bytes::from(f.to_string()))
}

/// 판 13·14 연결로 가는 directory·directory.update 에서 기기 항목의 판 15 칸(`online`·`os`)만 뺀다(사람 항목의 online 은 그대로).
/// #874: hello.look 없이 붙은 연결(옛 앱 — 디렉터리 사람 항목이 모르는 칸을 거절)엔 사람 항목의 `look` 을 뺀다. 표식이 없으면
/// 파싱하지 않는다.
pub fn without_look(text: Utf8Bytes) -> Utf8Bytes {
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory") && s.contains("\"look\"")) {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    // #845: links·group_members 도 사람 항목 꼴이다.
    for k in ["people", "links", "group_members"] {
        for p in f[k].as_array_mut().into_iter().flatten() {
            if let Some(o) = p.as_object_mut() {
                o.remove("look");
            }
        }
    }
    Utf8Bytes::from(f.to_string())
}

/// #845: hello.contacts 없이 붙은 연결(옛 앱 — 디렉터리 최상위의 모르는 칸을 거절)엔 `links`·`link_requests`·`org_invites`·`group_invites`·`group_members`, groups 의 `joining` 을 뺀다.
/// 표식이 없으면 파싱하지 않는다.
pub fn without_links(text: Utf8Bytes) -> Utf8Bytes {
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory")
        && (s.contains("\"links\"")
            || s.contains("\"link_requests\"")
            || s.contains("\"org_invites\"")
            || s.contains("\"group_invites\"")
            || s.contains("\"group_members\"")
            || s.contains("_invites_sent\"")))
        && !(s.contains("\"t\":\"groups\"") && s.contains("\"joining\""))
    {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    if let Some(o) = f.as_object_mut() {
        o.remove("links");
        o.remove("link_requests");
        o.remove("org_invites");
        o.remove("group_invites");
        o.remove("group_members");
        o.remove("org_invites_sent");
        o.remove("group_invites_sent");
    }
    // #845 ④ groups.items[].joining 도 옛 앱은 모른다.
    if f["t"] == "groups" {
        for it in f["items"].as_array_mut().into_iter().flatten() {
            if let Some(o) = it.as_object_mut() {
                o.remove("joining");
            }
        }
    }
    Utf8Bytes::from(f.to_string())
}

/// #845 §7-56: hello.mutes 없이 붙은 연결(옛 앱)엔 디렉터리 `mutes` 를 뺀다. 표식이 없으면 파싱하지 않는다.
pub fn without_mutes(text: Utf8Bytes) -> Utf8Bytes {
    without_directory_field(text, "mutes")
}

/// #880: hello.pins 없이 붙은 연결(옛 앱)엔 디렉터리 `pins` 를 뺀다.
/// #845 둘째: 판 16([`LISTS_FROM`]) 아래 연결엔 디렉터리 `lists`(친구 목록)를 뺀다 — 옛 앱의 Directory 는 모르는 최상위 칸을
/// 거절한다. 주인 세션 항목의 `audience`(저장된 공개 범위)도 뺀다(옛 앱의 세션 항목도 모르는 칸을 거절).
pub fn without_lists(text: Utf8Bytes) -> Utf8Bytes {
    let text = without_directory_field(text, "lists");
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory") && s.contains("\"audience\"")) {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    for x in f["sessions"].as_array_mut().into_iter().flatten() {
        if let Some(o) = x.as_object_mut() {
            o.remove("audience");
        }
    }
    Utf8Bytes::from(f.to_string())
}

pub fn without_pins(text: Utf8Bytes) -> Utf8Bytes {
    without_directory_field(text, "pins")
}

/// #923 §11: hello.blocks 없이 붙은 연결(옛 앱)엔 디렉터리 `blocked` 를 뺀다.
pub fn without_blocked(text: Utf8Bytes) -> Utf8Bytes {
    without_directory_field(text, "blocked")
}

/// 디렉터리(`directory`·`directory.update`)의 최상위 칸 하나를 뺀다. 그 칸 이름이 글에 없으면 파싱하지 않는다.
fn without_directory_field(text: Utf8Bytes, key: &str) -> Utf8Bytes {
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory") && s.contains(&format!("\"{key}\""))) {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    if let Some(o) = f.as_object_mut() {
        o.remove(key);
    }
    Utf8Bytes::from(f.to_string())
}

fn without_device_online(s: &str) -> Option<Utf8Bytes> {
    let mut f = serde_json::from_str::<serde_json::Value>(s).ok()?;
    for p in f["people"].as_array_mut().into_iter().flatten() {
        for d in p["devices"].as_array_mut().into_iter().flatten() {
            if let Some(o) = d.as_object_mut() {
                o.remove("online");
                o.remove("os");
                o.remove("away");
            }
        }
    }
    Some(Utf8Bytes::from(f.to_string()))
}

/// #870: hello.away 없이 붙은 연결(옛 앱 — DirectoryDevice 가 모르는 칸을 거절)엔 내 기기 항목의 `away` 를 뺀다.
pub fn without_away(text: Utf8Bytes) -> Utf8Bytes {
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory") && s.contains("\"away\"")) {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    for p in f["people"].as_array_mut().into_iter().flatten() {
        for d in p["devices"].as_array_mut().into_iter().flatten() {
            if let Some(o) = d.as_object_mut() {
                o.remove("away");
            }
        }
    }
    Utf8Bytes::from(f.to_string())
}

/// #961: hello.next_turn 없이 붙은 연결(옛 앱 — 세션 liveness 가 닫힌 enum 이라 모르는 값을 거절)엔 디렉터리 sessions 에서
/// liveness `live:next_turn` 인 항목을 뺀다(안 보임 = 공개 전과 같음). directory.update 도 전체 목록이라 같은 길.
pub fn without_next_turn(text: Utf8Bytes) -> Utf8Bytes {
    let s = text.as_str();
    if !(s.contains("\"t\":\"directory") && s.contains("\"live:next_turn\"")) {
        return text;
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return text;
    };
    if let Some(a) = f["sessions"].as_array_mut() {
        a.retain(|x| x["liveness"] != "live:next_turn");
    }
    Utf8Bytes::from(f.to_string())
}

/// #846 승인 전 연결에 쓰기 직전: 디렉터리(`directory`·`directory.update`)는 people 에 내 항목(`my_addr`)만 두고 sessions 를
/// 비우고 남의 것을 싣는 칸(팀·연락처·요청·초대 카드·보낸 초대·그룹 동료·음소거·고정)을 뺀다. 내 항목은 그대로(기기·certs·
/// online·away·revocations·recovery). 동료 `typing`·그룹 목록 `groups`·내 기기끼리 흘림 `own_stream` 은 보내지 않는다(None).
/// 그 밖 프레임은 그대로.
pub fn for_unapproved(text: Utf8Bytes, my_addr: &str) -> Option<Utf8Bytes> {
    let s = text.as_str();
    if ["typing", "groups", "own_stream"]
        .iter()
        .any(|t| s.contains(&format!("\"t\":\"{t}\"")))
    {
        return None;
    }
    if !s.contains("\"t\":\"directory") {
        return Some(text);
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return Some(text);
    };
    if !matches!(f["t"].as_str(), Some("directory" | "directory.update")) {
        return Some(text);
    }
    if let Some(o) = f.as_object_mut() {
        if let Some(p) = o
            .get_mut("people")
            .and_then(serde_json::Value::as_array_mut)
        {
            p.retain(|x| x["address"].as_str() == Some(my_addr));
        }
        if o.contains_key("sessions") {
            o.insert("sessions".into(), serde_json::Value::Array(Vec::new()));
        }
        for k in [
            "teams",
            "links",
            "link_requests",
            "org_invites",
            "group_invites",
            "org_invites_sent",
            "group_invites_sent",
            "group_members",
            "mutes",
            "pins",
            // 친구 목록(#845 둘째) — 이름·아이디가 든다.
            "lists",
            // #923 내가 막은 사람.
            "blocked",
        ] {
            o.remove(k);
        }
    }
    Some(Utf8Bytes::from(f.to_string()))
}

/// #846·#888: 그 사용자의 잎 자격이 바뀌었을 수 있을 때(기기 서명·폐기·되찾기·확정, 저장 commit 뒤) — 연결마다 승인 여부를
/// 다시 정하고, 새로 승인된 기기의 연결엔 `error{approved}` 를 보내고 닫는다(org_changed 와 같은 길 — 앱은 바로 다시 붙어
/// 승인 전 막혔던 접속 때 일·전체 디렉터리를 확인된 연결로 다시 받는다, 조용한 대기 금지). 승인됨 → 밖은 표시만 바꾼다.
pub(crate) fn reapprove(app: &Relay, user: &str, eligible: &[String]) {
    let newly = app.conns.reapprove(user, eligible);
    if newly.is_empty() {
        return;
    }
    // 표시는 이미 바뀌었다 — 같은 처리 안에서 그 기기로 가는 프레임(device.recovered·다시 들기 신호 등)은 그대로 실린다.
    // 닫기는 처리가 끝난 뒤(읽기 고리 한 바퀴 끝·주기 틱 끝)에 — 먼저 닫으면 그 프레임들이 사라진다.
    let mut p = app
        .conns
        .approve_pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = std::time::Instant::now();
    for d in newly {
        p.push((user.to_owned(), d, now));
    }
}

/// 대기 목록이 이만큼 밀리면 진행 중인 처리가 있어도 닫는다(바쁜 relay 에서 끝없이 미뤄지지 않게).
const APPROVE_FLUSH_MAX: std::time::Duration = std::time::Duration::from_secs(2);

/// #888 [`reapprove`] 가 모은 새로 승인된 기기의 연결에 `error{approved}` 를 보내고 닫는다(앱은 바로 다시 붙는다). `all` 이
/// 아니면 [`APPROVE_FLUSH_MAX`] 넘게 밀린 것만.
fn flush_approved(app: &Relay, all: bool) {
    let pending: Vec<(String, String, std::time::Instant)> = {
        let mut p = app
            .conns
            .approve_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if all {
            std::mem::take(&mut *p)
        } else {
            let (old, keep) = std::mem::take(&mut *p)
                .into_iter()
                .partition(|(_, _, at)| at.elapsed() >= APPROVE_FLUSH_MAX);
            *p = keep;
            old
        }
    };
    for (user, d, _) in pending {
        app.conns.send_devices(
            &user,
            std::slice::from_ref(&d),
            &ServerFrame::Error {
                code: ErrorCode::Approved,
                message: "approved".into(),
                r#ref: None,
            },
        );
        app.conns.close_device_soft(&user, &d);
    }
}

/// #888 처리 하나(읽기 고리 한 바퀴 — `continue`·`break` 포함, 주기 틱)가 도는 동안. 끝날 때 진행 중인 처리가 더 없으면 승인 닫기
/// 대기 목록을 비운다 — 다른 연결의 한 바퀴가 끝났다고 아직 도는 처리(되찾기 틱 등)가 그 기기에 보낼 알림보다 먼저 닫지 않게.
pub(crate) struct Busy<'a>(&'a Relay);

impl<'a> Busy<'a> {
    pub(crate) fn new(app: &'a Relay) -> Self {
        app.conns.busy.fetch_add(1, Ordering::SeqCst);
        Self(app)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let left = self.0.conns.busy.fetch_sub(1, Ordering::SeqCst) - 1;
        flush_approved(self.0, left == 0);
    }
}

/// #888 승인 전 연결이 보낸 프레임의 처리.
enum Gate {
    /// 그대로 처리.
    Allow,
    /// 답 없이 버림(성공 때도 답 프레임이 없는 것 — 모르는 오류가 옛 앱에 뜨지 않게).
    Drop,
    /// `error{device_unconfirmed}`(send 면 ref = msg_id, req 있는 요청이면 ref = req).
    Refuse,
}

/// #888 감사 로그를 연결당 이만큼만.
const GATE_LOG_MAX: u32 = 5;

/// #888 허용 목록(기본 막음): 연결 유지·내 것 읽기·이 기기 꾸리기·되찾기·이 기기 로그아웃·받은 글 답. 성공 답이 없는 것
/// (typing·own_*·session.publish/unpublish·presence.set·profile.update)은 조용히 버리고, 그 밖은 거절한다.
/// 서버 상태(`server.status`)는 허용하지 않는다(#909) — 승인 전 기기는 내 항목 말고는 아무것도 받지 않는다(#846). req 가 없는
/// 프레임이지만 앱이 답을 기다리므로 ref 없는 `device_unconfirmed` 로 바로 거절한다(`UNCONFIRMED_REF_LESS_FRAMES` — 답 없이
/// 버리면 관리자 화면의 조회가 시간 초과까지 조용히 기다린다).
fn unapproved_gate(f: &ClientFrame, who: &Authed) -> Gate {
    match f {
        ClientFrame::Hello { .. }
        | ClientFrame::Auth { .. }
        | ClientFrame::Ping
        | ClientFrame::Pong
        | ClientFrame::DirectoryList
        | ClientFrame::BlobGet { .. }
        | ClientFrame::BlobFetched { .. }
        | ClientFrame::DeviceName { .. }
        | ClientFrame::PushRegister { .. }
        | ClientFrame::PushUnregister { .. }
        | ClientFrame::KeyPackagesPublish { .. }
        | ClientFrame::DeviceRecover
        | ClientFrame::DeviceRecoverCancel
        | ClientFrame::DeviceRecoverBlock
        | ClientFrame::DeliveredAck { .. }
        | ClientFrame::Status { .. } => Gate::Allow,
        // 로그아웃: 이 기기만(남의 기기 끊기는 막음).
        ClientFrame::DeviceRevoke { device_id, .. } => {
            if device_id.as_ref().is_none_or(|d| *d == who.device_id) {
                Gate::Allow
            } else {
                Gate::Refuse
            }
        }
        ClientFrame::Typing { .. }
        | ClientFrame::OwnStream { .. }
        | ClientFrame::OwnAlert { .. }
        | ClientFrame::OwnLive { .. }
        | ClientFrame::SessionPublish { .. }
        | ClientFrame::SessionUnpublish { .. }
        | ClientFrame::PresenceSet { .. }
        | ClientFrame::ProfileUpdate { .. } => Gate::Drop,
        _ => Gate::Refuse,
    }
}

/// #888 승인 전 기기가 보내면 ref 없는 `device_unconfirmed` 로 답할 프레임인가 — 앱이 그 답을 기다리는 것(#737 관리자 동작·§7-46 조직
/// 옮기기·남의 기기 끊기). 목록은 relay·relay-client 가 같이 읽는 선 상수 `UNCONFIRMED_REF_LESS_FRAMES`.
fn ref_less_refusal(raw: &str) -> bool {
    lodelai_protocol::constants::UNCONFIRMED_REF_LESS_FRAMES.contains(&frame_t(raw).as_str())
}

/// #888 거절의 ref: send 면 message.msg_id, 그 밖엔 프레임의 req(있으면).
fn refused_ref(f: &ClientFrame, raw: &str) -> Option<String> {
    if let ClientFrame::Send { message } = f {
        return message["msg_id"].as_str().map(str::to_owned);
    }
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    v["req"].as_str().map(str::to_owned)
}

/// 감사 로그용 프레임 종류(내용 없이).
fn frame_t(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| v["t"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// #870: 앱이 보낸 close frame 의 reason → 디렉터리 `away`. 글자 그대로 `sleep`·`quit` 만, 그 밖·없음은 `lost`.
fn close_away(reason: Option<&str>) -> &'static str {
    match reason {
        Some("sleep") => "sleep",
        Some("quit") => "quit",
        _ => "lost",
    }
}

/// 디렉터리 내 기기 항목에 online(모바일 가입 '맥 꺼짐')을 싣는 판 — 그 아래 연결엔 [`for_version`] 이 뺀다.
const DEVICE_ONLINE_FROM: u64 = 15;

/// 전체 `directory` 세션 항목에 agent(Codex C2)·no(관문 Y2) 를 싣는 판 — 그 아래 연결엔 [`for_version`] 이 뺀다.
const SESSION_FIELDS_FROM: u64 = 13;

/// 관리자 내보내기(`member.remove`, 묶음 5) — 호출자가 `group_order` 를 쥔 채. 응답과 내보냈는지.
fn member_remove(app: &Relay, who: &Authed, user: &str, now: i64) -> (Option<ServerFrame>, bool) {
    match app.db.member_remove(&who.user, user, now) {
        // 순서: 폐기 커밋 → 그 사람의 연결에 device.revoked{by:admin} → 같은 조직에 directory.update → 그 사람 연결 닫음.
        Ok(MemberOutcome::Done { .. }) => {
            tracing::info!(by = %who.user, user = %user, "내보냄");
            app.conns.send_user(
                user,
                &ServerFrame::DeviceRevoked {
                    device_id: None,
                    by: Some(RevokedBy::Admin),
                    at: at_of(now),
                },
            );
            announce_org_removal(app, &who.user);
            app.conns.close_user(user);
            (None, true)
        }
        _ => (Some(rules::protocol_error("member.remove")), false),
    }
}

/// 자기 폐기·조직 나가기 응답 뒤 앱이 읽고 닫기를 기다리는 상한(#622). 앱은 받자마자 닫으므로 보통 바로 끝난다.
pub const REVOKED_LINGER: std::time::Duration = std::time::Duration::from_secs(2);

/// #622: 요청한 연결은 앱이 `device.revoked` 를 읽고 스스로 닫을 때까지(최대 [`REVOKED_LINGER`]) 열어 둔다. 바로 닫으면 앱이 앞서
/// 받은 프레임(duty·directory 등)에 답해 쓰다가 끊긴 연결에 막혀, 버퍼에 와 있던 응답을 읽기 전에 연결을 버리고 요청을
/// 실패(Unreachable)로 끝낸다 — 폐기·나가기는 됐는데 사람에게 오류가 뜬다. 그동안 받은 프레임은 버린다.
async fn linger_until_closed<S, E>(stream: &mut S)
where
    S: futures_util::Stream<Item = Result<Message, E>> + Unpin,
{
    let _ = tokio::time::timeout(REVOKED_LINGER, async {
        while let Some(Ok(m)) = stream.next().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}

/// `people` 범위 상한(묶음 20 §1).
pub const AUDIENCE_MAX: usize = 256;

/// #845 둘째 친구 목록(디렉터리 `lists`·`audience.lists`·`list.*`)을 아는 판.
pub const LISTS_FROM: u64 = 16;

/// 같은 조직의 사람·공개 세션(+ hosted 면 조직·팀·이메일, #355). 조직 밖은 빈 결과.
pub fn directory(app: &Relay, user: &str) -> DirectoryBody {
    let Ok(Some(org)) = app.db.user_org(user) else {
        return DirectoryBody::default();
    };
    // M1 `local` 은 orgs 행이 없다 — 조직·팀·이메일을 싣지 않는다.
    let org_info = app.db.org_info(&org).ok().flatten();
    let hosted = org_info.is_some();
    let server = &app.config.server_name;
    // 이 받는 사람이 초대한 사람(M1 결함 ①) — 받는 사람마다 다르다(누가 누구를 초대했는지는 퍼지지 않는다).
    // 받는 사람을 초대한 사람(§17.3 `invited_me`) — 본인은 가입 때 이미 봤으니 새로 드러나는 것은 없다.
    let (invited, inviter) = if hosted {
        (
            app.db.invited_by(user).unwrap_or_default(),
            app.db.inviter_of(user).ok().flatten(),
        )
    } else {
        (std::collections::HashSet::new(), None)
    };
    // 접속 표시(묶음 14 B1): 숨긴 사람의 것은 싣지 않고, 받는 사람이 숨겼으면 아무의 것도 싣지 않는다(맞교환).
    let mut hidden = app.db.presence_hidden_in_org(&org).unwrap_or_default();
    let mut avatars = app.db.avatars_in_org(&org).unwrap_or_default();
    let mut looks = app.db.looks_in_org(&org).unwrap_or_default();
    // #845: 수락된 연락처. #898: 같은 조직 사람도 싣는다(수락 직후 대화 목록 줄 — linked_at) — 세션 덧붙임(link_peers)만
    // 조직 밖으로(같은 조직 세션은 sessions_in_org 에 이미 있다). 사진·기본 이미지·접속 숨김을 같은 표에 더한다.
    let now = app.effects.clock.now().0;
    let mut outside_links: std::collections::HashSet<String> = std::collections::HashSet::new();
    let link_rows: Vec<_> = app
        .db
        .links_of(user)
        .unwrap_or_default()
        .into_iter()
        .inspect(|(p, ..)| {
            if app.db.user_org(p).ok().flatten().as_deref() != Some(org.as_str()) {
                outside_links.insert(p.clone());
            }
        })
        .map(|(p, mine, theirs, linked, via_link)| {
            let (display, avatar, look, hide) = app.db.person_bits(&p).unwrap_or_default();
            if let Some(a) = avatar {
                avatars.insert(p.clone(), a);
            }
            if let Some(l) = look {
                looks.insert(p.clone(), l);
            }
            if hide {
                hidden.insert(p.clone());
            }
            (p, display, mine, theirs, linked, via_link)
        })
        .collect();
    // #845 ⑦: 연락처 아닌 그룹 동료의 얼굴(look·아바타)도 같은 표에 — 접속은 싣지 않는다.
    let stranger_rows: Vec<(String, Option<String>)> = app
        .db
        .group_strangers(user)
        .unwrap_or_default()
        .into_iter()
        .map(|(p, display)| {
            let (_, avatar, look, _) = app.db.person_bits(&p).unwrap_or_default();
            if let Some(a) = avatar {
                avatars.insert(p.clone(), a);
            }
            if let Some(l) = look {
                looks.insert(p.clone(), l);
            }
            (p, display)
        })
        .collect();
    let sees_presence = !hidden.contains(user);
    // #737: 관리자는 기기 바꾸는 중인 사람의 옛 기기(걸기 대상)의 마지막 접속(일 단위)을 본다 — '옛 기기 끊기' 판단 재료.
    let viewer_admin = app.db.is_org_admin(user).unwrap_or(false);
    let now_ms = app.effects.clock.now().0;
    let person = |(u, display): (String, Option<String>)| {
        let (email, teams) = if hosted {
            let (e, t) = app.db.user_meta(&u).unwrap_or_default();
            (e, Some(t))
        } else {
            (None, None)
        };
        let certs = app.db.device_certs_of(&u).unwrap_or_default();
        let my_online = if u == user {
            app.conns.online_devices(&u)
        } else {
            Vec::new()
        };
        let switching_targets: Vec<String> = if viewer_admin && u != user {
            app.db
                .recovery(&u)
                .ok()
                .flatten()
                .filter(|r| r.state == crate::db::RecoveryState::Scheduled)
                .map(|r| r.targets)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let online = (sees_presence && !hidden.contains(&u)).then(|| app.presence.online(app, &u));
        DirectoryPerson {
            online,
            avatar: avatars.get(&u).cloned(),
            look: looks.get(&u).and_then(|l| serde_json::from_str(l).ok()),
            invited_by_me: invited.contains(&u).then_some(true),
            invited_me: (inviter.as_deref() == Some(u.as_str())).then_some(true),
            address: format!("{u}@{server}"),
            display,
            email,
            teams,
            devices: app
                .db
                .devices_of(&u)
                .unwrap_or_default()
                .into_iter()
                .map(|d| DirectoryDevice {
                    certs: certs
                        .iter()
                        .filter(|(t, ..)| *t == d.device_id)
                        .map(|(_, signer, sig)| DeviceCert {
                            signer: signer.clone(),
                            sig: sig.clone(),
                        })
                        .collect(),
                    // 내 기기에만(§12-27 ⓑ) — 동료의 접속 시각은 새지 않는다. 예외(#737): 관리자에게 기기 바꾸는 중인
                    // 사람의 옛 기기(걸기 대상)만.
                    last_seen_at: d
                        .last_seen_day
                        .filter(|_| u == user || switching_targets.contains(&d.device_id))
                        .and_then(|t| lodelai_effects::UnixMillis(t).to_rfc3339().ok()),
                    // #577: 같은 규칙 — 내 기기에만(마지막으로 붙어 있던 시각, ms). 지금 붙어 있으면 이 디렉터리를 만든
                    // 시각(코어 seen_since_me — 새 기기 추가 전부터 끊김 없이 붙어 있던 옛 기기도 '봤다'로).
                    last_auth_at: d
                        .last_auth_ms
                        .filter(|_| u == user)
                        .map(|t| {
                            if my_online.contains(&d.device_id) {
                                now_ms
                            } else {
                                t
                            }
                        })
                        .and_then(|t| lodelai_effects::UnixMillis(t).to_rfc3339().ok()),
                    // 모바일 가입 '맥 꺼짐'(판 15): 같은 규칙 — 내 기기에만, 지금 붙어 있나. 시각 비교로는 끊김 직후를 못 가른다
                    // (끊긴 시각과 이 디렉터리를 만든 시각이 같은 ms 일 수 있다).
                    online: (u == user).then(|| my_online.contains(&d.device_id)),
                    // #870: 같은 규칙 + 지금 안 붙은 기기에만 — 마지막 연결이 어떻게 끝났나.
                    away: d
                        .away
                        .clone()
                        .filter(|_| u == user && !my_online.contains(&d.device_id)),
                    // 판 15: 기기가 알린 OS — 이름과 같은 규칙(내 항목에만).
                    os: if u == user { d.os.clone() } else { None },
                    device_id: d.device_id,
                    device_pubkeys: DevicePubkeys {
                        ed25519: d.ed25519,
                        x25519: d.x25519,
                        x25519_sig: d.x25519_sig,
                    },
                    added_at: lodelai_effects::UnixMillis(d.created_ms).to_rfc3339().ok(),
                    // 기기 이름은 요청한 사람 자신의 항목에만(#490 — 실명이 들어가기 쉬움).
                    name: if u == user { d.name } else { None },
                    // 앱 판(#598 ②) — 모두에게(보내는 코어가 10 전용 칸을 실을지 가른다). 9 연결엔 쓰기 직전에 뺀다.
                    v: d.hello_v.and_then(|v| u64::try_from(v).ok()),
                })
                .collect(),
            revocations: crate::mls::needed_revocations(app, &u)
                .into_iter()
                .map(|r| DirectoryRevocation {
                    certs: certs
                        .iter()
                        .filter(|(t, ..)| *t == r.device_id)
                        .map(|(_, signer, sig)| DeviceCert {
                            signer: signer.clone(),
                            sig: sig.clone(),
                        })
                        .collect(),
                    added_at: lodelai_effects::UnixMillis(r.created_ms)
                        .to_rfc3339()
                        .unwrap_or_default(),
                    device_id: r.device_id,
                    ed25519: r.ed25519,
                    x25519: r.x25519,
                    at: r.proof.at,
                    signer: r.proof.signer,
                    sig: r.proof.sig,
                })
                .collect(),
            recovery: crate::recovery::directory_view(app, user, &u),
            task_ok: None,
            task_ok_for_me: None,
            linked_at: None,
            joined_my_link: None,
        }
    };
    let people = app
        .db
        .people_in_org(&org)
        .unwrap_or_default()
        .into_iter()
        .map(person)
        .collect();
    // links 항목: 사람 항목과 같은 꼴에서 팀·초대 관계·기기 바꾸기를 빼고 task_ok 두 칸을 더한다. 이메일은 수락한 상대에게 보인다.
    let link_peers: Vec<String> = link_rows
        .iter()
        .map(|(p, ..)| p.clone())
        .filter(|p| outside_links.contains(p))
        .collect();
    let links: Vec<DirectoryPerson> = link_rows
        .into_iter()
        .map(|(p, display, mine, theirs, linked, via_link)| {
            let email = app.db.user_meta(&p).ok().and_then(|(e, _)| e);
            let mut d = person((p, display));
            d.teams = None;
            d.invited_by_me = None;
            d.invited_me = None;
            d.recovery = None;
            d.email = email;
            d.task_ok = mine.then_some(true);
            d.task_ok_for_me = theirs.then_some(true);
            // 880 3 덧: 연결(수락) 시각 — 대화 없는 연락처를 맥·휴대폰이 같은 순서로 놓는다.
            d.linked_at = linked.and_then(at_of);
            // #886 ⑧: 내 초대 링크로 들어와 맺어진 연락처(내 줄에서만 — 들어온 쪽·요청 수락엔 없음).
            d.joined_my_link = via_link.then_some(true);
            d
        })
        .collect();
    // #845 ④(§7-14): 연락처 아닌 그룹 동료 — 앱이 그 사람의 그룹 잎을 검증하도록 기기 키·certs·revocations 는 싣고, 이메일·
    // 접속·팀·초대 관계·기기 이름·os 는 뺀다. ⑦(§8-1): 얼굴(look·아바타)은 싣는다 — 아바타 blob.get 은 지금 같은 그룹 멤버까지.
    let group_members: Vec<DirectoryPerson> = stranger_rows
        .into_iter()
        .map(|(u, display)| {
            let mut d = person((u, display));
            d.email = None;
            d.teams = None;
            d.invited_by_me = None;
            d.invited_me = None;
            d.online = None;
            d.recovery = None;
            d.task_ok = None;
            d.task_ok_for_me = None;
            for dev in &mut d.devices {
                dev.name = None;
                dev.os = None;
                dev.online = None;
                dev.away = None;
                dev.last_seen_at = None;
                dev.last_auth_at = None;
            }
            d
        })
        .collect();
    let link_requests = crate::frames::LinkRequestsView {
        incoming: app
            .db
            .link_incoming(user, now)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, from, display, email, at)| {
                Some(crate::frames::LinkIncoming {
                    id,
                    address: format!("{from}@{server}"),
                    display,
                    email,
                    at: lodelai_effects::UnixMillis(at).to_rfc3339().ok()?,
                })
            })
            .collect(),
        outgoing: app
            .db
            .link_outgoing(user, now)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, to, at)| {
                Some(crate::frames::LinkOutgoing {
                    id,
                    to,
                    at: lodelai_effects::UnixMillis(at).to_rfc3339().ok()?,
                })
            })
            .collect(),
    };
    let sessions = app
        .db
        .sessions_in_org(&org)
        .unwrap_or_default()
        .into_iter()
        // 묶음 20: 받는 사람이 주인이거나 범위 안인 세션만 — 범위 목록 자체는 싣지 않는다.
        .filter(|s| s.reaches(user))
        // #845 결정 A: 연락처의 세션은 나를 고른 사람에 넣은 것만(범위 없음 = 그 사람 조직만).
        .chain(
            link_peers
                .iter()
                .flat_map(|p| app.db.sessions_of(p).unwrap_or_default())
                .filter(|s| s.picks(user)),
        )
        .map(|s| DirectorySession {
            // #845 둘째: 주인에게만 저장된 범위 그대로(빼고 받은 뒤 값, 얼린 사람 포함) — 코어가 정본으로 받는다.
            audience: if s.user == user {
                s.audience
                    .clone()
                    .map(|users| crate::frames::SessionAudience {
                        kind: "people".to_owned(),
                        users,
                        lists: s.audience_lists.clone(),
                    })
            } else {
                None
            },
            offline: (s.offline && s.liveness_is_dead()).then_some(true),
            address: format!("{}@{server}/{}", s.user, s.slug),
            grade: s.grade,
            liveness: s.liveness,
            display: s.display,
            title: s.title,
            folder: s.folder,
            project: s
                .project
                .map(|(id, name)| crate::frames::ProjectRef { id, name }),
            busy: s.busy.then_some(true),
            agent: s.agent,
            no: s.no,
        })
        .collect();
    let teams = hosted.then(|| {
        app.db
            .teams_of_org(&org)
            .unwrap_or_default()
            .into_iter()
            .map(|(id, name)| DirectoryTeam { id, name })
            .collect()
    });
    DirectoryBody {
        people,
        sessions,
        org: org_info.map(|(name, admins)| DirectoryOrg {
            avatar: app.db.org_avatar(&org).ok().flatten(),
            color: app.db.org_color(&org).ok().flatten(),
            external_closed: app.db.org_external_closed(&org).unwrap_or(false),
            kind: app.db.org_kind(&org).ok().flatten().map(|k| {
                if k == "personal" {
                    k
                } else {
                    "org".to_owned()
                }
            }),
            id: org.clone(),
            name,
            admins,
        }),
        teams,
        links: Some(links),
        link_requests: Some(link_requests),
        org_invites: Some(
            app.db
                .org_invites_of(user, now)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|c| {
                    Some(crate::frames::OrgInviteView {
                        id: c.id,
                        org_name: c.org_name,
                        by_display: c.by_display,
                        at: lodelai_effects::UnixMillis(c.at_ms).to_rfc3339().ok()?,
                        blocked: c.other_org.then(|| "other_org".to_owned()),
                        org_color: c.org_color,
                    })
                })
                .collect(),
        ),
        group_invites: Some(
            app.db
                .group_invites_of(user, now)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|c| {
                    Some(crate::frames::GroupInviteView {
                        id: c.id,
                        group: format!("+{}@{server}", c.gid),
                        by: format!("{}@{server}", c.by),
                        by_display: c.by_display,
                        at: lodelai_effects::UnixMillis(c.at_ms).to_rfc3339().ok()?,
                        members: u64::try_from(c.members).unwrap_or(0),
                        joining: c.joining.then_some(true),
                    })
                })
                .collect(),
        ),
        group_members: Some(group_members),
        mutes: Some(
            app.db
                .mutes_of(user, now)
                .unwrap_or_default()
                .into_iter()
                .map(|(conv, until)| crate::frames::MuteView {
                    conv,
                    until: until.and_then(|u| lodelai_effects::UnixMillis(u).to_rfc3339().ok()),
                })
                .collect(),
        ),
        pins: Some(app.db.pins_of(user).unwrap_or_default()),
        blocked: Some(
            app.db
                .blocked_of(user)
                .unwrap_or_default()
                .into_iter()
                .map(|u| format!("{u}@{}", app.config.server_name))
                .collect(),
        ),
        lists: Some(app.db.lists_of(user).unwrap_or_default()),
        org_invites_sent: Some(
            app.db
                .org_invites_sent_of(user, now)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(id, shown, at)| {
                    Some(crate::frames::SentInviteView {
                        id,
                        group: None,
                        shown,
                        at: lodelai_effects::UnixMillis(at).to_rfc3339().ok()?,
                    })
                })
                .collect(),
        ),
        group_invites_sent: Some(
            app.db
                .group_invites_sent_of(user, now)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(id, gid, shown, at)| {
                    Some(crate::frames::SentInviteView {
                        id,
                        group: Some(format!("+{gid}@{server}")),
                        shown,
                        at: lodelai_effects::UnixMillis(at).to_rfc3339().ok()?,
                    })
                })
                .collect(),
        ),
    }
}

/// #845 ⑤ `error{account_suspended, until?}`(인증 뒤, contacts 연결에만).
pub(crate) fn account_suspended_frame(until: Option<i64>) -> ServerFrame {
    ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::Error(
        lodelai_protocol::ws::Error {
            at: None,
            by: None,
            code: lodelai_protocol::ws::ErrorCode::AccountSuspended,
            max: None,
            until: until.and_then(|t| {
                lodelai_effects::UnixMillis(t)
                    .to_rfc3339()
                    .ok()
                    .and_then(|s| s.try_into().ok())
            }),
            reason: None,
            message: "auth".into(),
            min: None,
            ref_: None,
            t: lodelai_protocol::ws::ErrorT::Error,
        },
    )))
}

/// 그 사용자의 `groups`(묶음 16): 지금 멤버인 그룹·마지막 seq·조직 빠짐으로 나간 멤버(§3a ④).
fn groups_frame(app: &Relay, user: &str) -> Result<ServerFrame, crate::db::DbError> {
    // 그룹 끔(묶음 16 §3b): 빈 목록 — 접속 때 프레임·조직 빠짐 힌트도 이 빈 목록으로 나가지 않는다.
    if !app.config.groups {
        return Ok(ServerFrame::Groups(Vec::new()));
    }
    let server = &app.config.server_name;
    Ok(ServerFrame::Groups(
        app.db
            .groups_of(user)?
            .into_iter()
            .map(|g| {
                // §7-57: 디렉터리 밖일 수 있는 사람(다른 조직)의 이름 — relay 가 가진 가입 이름, 지운 계정·이름 없음은 뺀다.
                let names = app
                    .db
                    .display_names(&g.joining)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(u, n)| (format!("{u}@{server}"), n))
                    .collect();
                (
                    format!("+{}@{server}", g.gid),
                    g.seq,
                    g.org_left
                        .into_iter()
                        .map(|(u, s)| (format!("{u}@{server}"), s))
                        .collect(),
                    g.joining
                        .into_iter()
                        .map(|u| format!("{u}@{server}"))
                        .collect(),
                    names,
                )
            })
            .collect(),
    ))
}

/// 그룹이 하나라도 있을 때만 [`groups_frame`](읽기 오류면 없음).
fn groups_frame_if_any(app: &Relay, user: &str) -> Option<ServerFrame> {
    match groups_frame(app, user) {
        Ok(ServerFrame::Groups(items)) if !items.is_empty() => Some(ServerFrame::Groups(items)),
        _ => None,
    }
}

/// #877 `org.leave` 커밋 뒤 알림: 옛 조직 동료에게 `directory.update`(그 사람 빠짐)·`groups`(org_left 힌트), 그 사람을 새로 쥐게 된
/// 사람(연락처·다른 조직이 된 섞인 그룹 동료)에게 그 사람 모습, 남은 기기에 잎 빼기 일. 부르는 쪽이 `group_order` 를 잡는다.
fn announce_org_left(app: &Relay, user: &str, old_org: &str) {
    with_directory_order(app, || {
        for u in app.conns.users() {
            if u == user
                || app.db.user_org(&u).ok().flatten().as_deref() != Some(old_org)
                || app.db.is_removed(&u).unwrap_or(true)
            {
                continue;
            }
            app.conns
                .send_user(&u, &ServerFrame::DirectoryUpdate(directory(app, &u)));
        }
        broadcast_directory_locked(app, user, false);
    });
    crate::mls::dispatch_duties(app, None);
    for u in app.conns.users() {
        if u == user
            || app.db.user_org(&u).ok().flatten().as_deref() != Some(old_org)
            || app.db.is_removed(&u).unwrap_or(true)
        {
            continue;
        }
        if let Some(f) = groups_frame_if_any(app, &u) {
            app.conns.send_user(&u, &f);
        }
    }
}

/// 조직 빠짐(내보내기·나가기) 커밋 뒤 알림(묶음 16 §3a ④): 같은 조직에 `directory.update`, 그다음 그룹이 있는 사람에게 `groups`
/// (조직 빠짐 힌트). 부르는 쪽이 `group_order` 를 잡고 커밋부터 여기까지 한 줄로 세운다 — 그 뒤 어떤 group 메시지보다 먼저 간다.
pub fn announce_org_removal(app: &Relay, user: &str) {
    broadcast_directory_of(app, user);
    // 묶음 22: 그 사람의 잎을 빼는 org_left Commit 일(remove_user)을 남은 접속 기기에.
    crate::mls::dispatch_duties(app, None);
    let org = app.db.user_org(user).ok().flatten();
    for u in app.conns.users() {
        if app.db.user_org(&u).ok().flatten() != org || app.db.is_removed(&u).unwrap_or(true) {
            continue;
        }
        if let Some(f) = groups_frame_if_any(app, &u) {
            app.conns.send_user(&u, &f);
        }
    }
}

/// 같은 조직의 접속 중인 사용자들에게 `directory.update`(전체 목록).
/// `device.name`(#490 묶음 28 §4): NFC·규칙 검사 → 같은 값이면 아무것도 안 함 → 기기당 시간당 상한 → 저장 → 본인 연결들에만
/// directory.update(이름은 본인 항목에만 실리므로 동료에게는 바뀐 것이 없다). 이름은 로그에 싣지 않는다.
fn device_name(app: &Relay, who: &Authed, raw: &str, os: Option<&str>) -> Option<ServerFrame> {
    let Ok(name) = lodelai_protocol::display_name::normalize_device_name(raw) else {
        return Some(rules::protocol_error("device.name 형식"));
    };
    let name_changed = match app.db.device_name(&who.device_id) {
        Ok(Some(cur)) => cur != name,
        Ok(None) | Err(_) => return Some(rules::protocol_error("device.name")),
    };
    // 판 15: os 는 없으면(옛 앱) 남긴 값 그대로. 바뀜은 이름과 같은 상한을 센다 — 번갈아 보내도 디렉터리를 끝없이 만들지 않게.
    let os_changed = os.is_some_and(|o| {
        app.db
            .device_os(&who.device_id)
            .is_ok_and(|cur| cur.as_deref() != Some(o))
    });
    if !name_changed && !os_changed {
        return None;
    }
    if !app
        .device_name_limiter
        .allow(&who.device_id, app.effects.clock.now())
    {
        return Some(ServerFrame::Error {
            code: ErrorCode::RateLimited,
            message: "device.name".into(),
            r#ref: None,
        });
    }
    let mut changed = false;
    if name_changed {
        match app.db.set_device_name(&who.device_id, name.as_deref()) {
            Ok(c) => changed |= c,
            Err(_) => return Some(rules::protocol_error("device.name")),
        }
    }
    if let Some(o) = os.filter(|_| os_changed) {
        match app.db.set_device_os(&who.device_id, o) {
            Ok(c) => changed |= c,
            Err(_) => return Some(rules::protocol_error("device.name")),
        }
    }
    if changed {
        with_directory_order(app, || {
            let frame = ServerFrame::DirectoryUpdate(directory(app, &who.user));
            app.conns.send_user(&who.user, &frame);
        });
    }
    None
}

/// 모바일 검증: 토큰 꼴(APNs 는 URL 경로에 들어간다 — 16진 64~200자, FCM 은 `[A-Za-z0-9_:-]`).
fn push_token_ok(apns: bool, token: &str) -> bool {
    if apns {
        (64..=200).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        token.len() <= 4096
            && !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
    }
}

fn push_error(req: String) -> ServerFrame {
    ServerFrame::Error {
        code: ErrorCode::Protocol,
        message: "push".into(),
        r#ref: Some(req),
    }
}

fn push_ok(req: String, salt_key: Option<(&[u8], &[u8])>) -> ServerFrame {
    let b64 = |b: &[u8]| encoding::encode(b);
    let frame = (|| {
        Some(lodelai_protocol::ws::Frame::PushOk(
            lodelai_protocol::ws::PushOk {
                req: req.clone().try_into().ok()?,
                salt: match salt_key {
                    Some((s, _)) => Some(b64(s).try_into().ok()?),
                    None => None,
                },
                key: match salt_key {
                    Some((_, k)) => Some(b64(k).try_into().ok()?),
                    None => None,
                },
                t: lodelai_protocol::ws::PushOkT::PushOk,
            },
        ))
    })();
    frame.map_or_else(|| push_error(req), |f| ServerFrame::Ws(Box::new(f)))
}

/// `push.register`(모바일 검증, `--mobile-push` 일 때만): 꼴을 보고 기기당 한 행으로 넣거나 바꾼다. salt·push 키는 늘 새로.
#[allow(clippy::too_many_arguments)]
fn push_register(
    app: &Relay,
    who: &Authed,
    req: String,
    apns: bool,
    token: String,
    sandbox: bool,
    app_id: String,
    off: &[String],
) -> ServerFrame {
    if !app.config.mobile_push
        || !push_token_ok(apns, &token)
        || (!apns && sandbox)
        || !app.config.push_app_ids.contains(&app_id)
    {
        return push_error(req);
    }
    let mut salt = [0u8; 16];
    let mut key = [0u8; 32];
    if app.effects.rng.try_fill(&mut salt).is_err() || app.effects.rng.try_fill(&mut key).is_err() {
        return rules::internal_error();
    }
    let row = crate::db::PushToken {
        platform: if apns { "apns" } else { "fcm" }.into(),
        token,
        env: if sandbox { "sandbox" } else { "prod" }.into(),
        app_id,
        salt: salt.to_vec(),
        key: key.to_vec(),
        off: off.join(","),
    };
    match app
        .db
        .push_token_put(&who.device_id, &row, app.effects.clock.now().0)
    {
        Ok(true) => push_ok(req, Some((&salt, &key))),
        Ok(false) => push_error(req),
        Err(_) => rules::internal_error(),
    }
}

pub fn broadcast_directory(app: &Relay, who: &Authed) {
    broadcast_directory_of(app, &who.user);
}

/// [`broadcast_directory`] 를 사용자 이름으로(연결 밖에서).
pub fn broadcast_directory_of(app: &Relay, user: &str) {
    broadcast_directory_to(app, user, false);
}

/// 접속 변화(묶음 14 B1): 그 사용자 본인에게는 보내지 않는다 — 자기 접속은 새 소식이 아니고, 등록 전에 심어 둔 내 기기를
/// 디렉터리가 덮는 창(relay-client 의 '목록에 없으면 폐기')을 늘리지 않는다.
pub fn broadcast_presence_of(app: &Relay, user: &str) {
    broadcast_directory_to(app, user, true);
}

/// 디렉터리 모습을 만들고 큐에 넣는 일을 [`crate::Relay::directory_order`] 안에서(#702). 만든 순서 = 큐에 들어간 순서라서
/// 받는 쪽은 늘 마지막에 만든 모습을 마지막에 받는다(연결이 여럿이어도, 다시 붙어도 — 접속 때 모습도 이 안에서 만든다).
pub fn with_directory_order<T>(app: &Relay, f: impl FnOnce() -> T) -> T {
    let _order = app
        .directory_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

fn broadcast_directory_to(app: &Relay, user: &str, skip_self: bool) {
    with_directory_order(app, || broadcast_directory_locked(app, user, skip_self));
}

fn broadcast_directory_locked(app: &Relay, user: &str, skip_self: bool) {
    let org = app.db.user_org(user).ok().flatten();
    // #845: 연락처와 걸린 요청의 상대도 이 사람의 모습(이름·사진·기기·접속)을 디렉터리에 쥔다.
    let mut watchers = app
        .db
        .link_watchers(user, app.effects.clock.now().0)
        .unwrap_or_default();
    // #877: 연락처 아닌 다른 조직의 그룹 동료도 이 사람을 디렉터리 group_members 로 쥔다(이름·얼굴·기기 키) — 바뀜을 바로.
    // group_strangers 는 맞쪽 관계(같은 그룹·다른 조직·연락처 아님)라 이 사람의 것이 곧 이 사람을 쥔 사람들이다. 접속 변화는
    // group_members 에 싣지 않으므로 뺀다.
    if !skip_self {
        watchers.extend(
            app.db
                .group_strangers(user)
                .unwrap_or_default()
                .into_iter()
                .map(|(u, _)| u),
        );
    }
    for u in app.conns.users() {
        if skip_self && u == user {
            continue;
        }
        // 내보낸 사람·나간 사람(연결이 닫히기 전)에게는 보내지 않는다 — 이미 조직 밖이다.
        if (app.db.user_org(&u).ok().flatten() == org || watchers.contains(&u))
            && !app.db.is_removed(&u).unwrap_or(true)
        {
            app.conns
                .send_user(&u, &ServerFrame::DirectoryUpdate(directory(app, &u)));
        }
    }
}

/// #845: 그 사람들에게만 디렉터리 갱신(연락처 바뀜 — 조직 전체에 보내지 않는다).
pub fn send_directory_to(app: &Relay, users: &[String]) {
    with_directory_order(app, || {
        for u in users {
            if !app.db.is_removed(u).unwrap_or(true) {
                app.conns
                    .send_user(u, &ServerFrame::DirectoryUpdate(directory(app, u)));
            }
        }
    });
}

/// #845 `link.*` 의 상대 주소 → 이 서버 사람 아이디. 다른 서버·세션 주소면 `None`(조용히 무시).
fn link_peer(app: &Relay, peer: &str) -> Option<String> {
    let a = crate::frames::Address::parse(peer)?;
    (a.server == app.config.server_name && a.slug.is_none() && !a.is_group()).then_some(a.user)
}

/// #845 `link.request`: 답은 늘 `link.sent`(이메일은 계정 있음·없음·막힘·이미 연락처가 같은 바이트 — 설계 §3·§7-7).
/// 메일은 여기서 보내지 않는다(일 대기열 — 답 시각으로 갈리지 않게).
fn link_request(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    to: &crate::frames::LinkTo,
) -> Option<ServerFrame> {
    use crate::frames::LinkTo;
    let (target, shown, normalized);
    match to {
        LinkTo::Email(e) => {
            let Some(n) = lodelai_protocol::email::normalize(e) else {
                return Some(rules::protocol_error("link.request email"));
            };
            normalized = n;
            target = crate::db::LinkTarget::Email(&normalized);
            shown = e.trim();
        }
        LinkTo::User(u) => {
            target = crate::db::LinkTarget::User(u);
            shown = u.as_str();
        }
    }
    let id = app.effects.ids.next_ulid();
    let out = match app.db.link_request(&crate::db::LinkRequestIn {
        me: &who.user,
        to: target,
        shown,
        id: &id,
        now_ms: app.effects.clock.now().0,
    }) {
        Ok(o) => o,
        Err(_) => return Some(rules::internal_error()),
    };
    if let Some(until) = out.limited_until {
        return Some(rules::rate_limited("link.request", until));
    }
    // 있는 아이디는 이 통을 쓰지 않는다(§7-1).
    if out.unknown {
        if let Err(until) = unknown_id_spend(app, who) {
            return Some(rules::rate_limited("link.request", until));
        }
    }
    if !out.notify.is_empty() {
        send_directory_to(app, &out.notify);
    }
    if let Some(t) = &out.card {
        crate::push::on_invite(app, t, crate::push::InviteSub::Contact, &id);
    }
    Some(link_sent(req, out.unknown))
}

/// #845 §7-23 `contact_link.preview`: 살아 있는 링크 주인의 이름·look(아바타 없음)·제 색 번호(tone), 내 링크면 mine, 끝난 링크면 gone. 막힌 사이도
/// 같은 답. 사람 찾기 통(없는 아이디 — 사용자·IP)에 센다.
fn contact_link_preview(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    token: &str,
) -> Option<ServerFrame> {
    if let Err(until) = unknown_id_spend(app, who) {
        return Some(rules::rate_limited("contact_link.preview", until));
    }
    let owner = match app.db.contact_link_owner(token) {
        Ok(o) => o,
        Err(_) => return Some(rules::internal_error()),
    };
    let mut ans = lodelai_protocol::ws::ContactLinkPreviewAnswer {
        gone: None,
        look: serde_json::Map::new(),
        mine: None,
        name: None,
        req: req.and_then(|r| r.try_into().ok()),
        t: lodelai_protocol::ws::ContactLinkPreviewAnswerT::ContactLinkPreview,
        tone: None,
    };
    match owner {
        None => ans.gone = Some(true),
        Some(o) if o == who.user => ans.mine = Some(true),
        Some(o) => {
            let (display, _, look, _) = app.db.person_bits(&o).unwrap_or_default();
            ans.tone =
                std::num::NonZeroU64::new(person_tone(&format!("{o}@{}", app.config.server_name)));
            ans.name = Some(display.unwrap_or_else(|| o.clone()));
            if let Some(serde_json::Value::Object(m)) =
                look.and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
            {
                ans.look = m;
            }
        }
    }
    Some(ServerFrame::Ws(Box::new(
        lodelai_protocol::ws::Frame::ContactLinkPreviewAnswer(ans),
    )))
}

/// #845 §7-23 사람 제 색 번호 1..6 — 앱 `orgTile` 과 같은 식(주소의 UTF-16 코드 합 % 6 + 1). look 없는 사람의 미리보기 얼굴 색.
#[must_use]
pub fn person_tone(address: &str) -> u64 {
    address
        .encode_utf16()
        .fold(0u64, |n, c| (n + u64::from(c)) % 6)
        + 1
}

/// #845 둘째 목록 id 꼴 `^[A-Za-z0-9_-]{8,64}$`(앱이 만든다).
fn list_id_ok(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// #845 둘째 목록 이름: 조직 이름과 같은 규칙(앞뒤 공백 떼기·제어·서식 문자 없음)에 상한만 40 글자.
fn list_name(name: &str) -> Option<String> {
    lodelai_protocol::display_name::normalize(name)
        .ok()
        .filter(|n| n.chars().count() <= LIST_NAME_MAX)
}

/// 목록 이름 상한(유니코드 글자 수).
pub const LIST_NAME_MAX: usize = 40;

/// #845 둘째 `list.put`: 통째 덮어쓰기. 답 프레임 없음 — 내 연결 모두와 들고 난 사람에게 directory.update.
fn list_put(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    list_id: &str,
    name: &str,
    users: Vec<String>,
) -> Option<ServerFrame> {
    let err = |code: ErrorCode| ServerFrame::Error {
        code,
        message: "list.put".into(),
        r#ref: req.clone(),
    };
    let Some(name) = list_name(name) else {
        return Some(err(ErrorCode::Protocol));
    };
    if !list_id_ok(list_id) || users.len() > crate::db::LIST_USERS_MAX {
        return Some(err(ErrorCode::Protocol));
    }
    match app
        .db
        .list_put(&who.user, list_id, &name, &users, app.effects.clock.now().0)
    {
        Ok(crate::db::ListPutOut::Done(changed)) => {
            send_directory_to(app, std::slice::from_ref(&who.user));
            if !changed.is_empty() {
                send_directory_to(app, &changed);
            }
            None
        }
        Ok(crate::db::ListPutOut::Refused) => Some(err(ErrorCode::Protocol)),
        Ok(crate::db::ListPutOut::Quota) => Some(err(ErrorCode::Quota)),
        Err(_) => Some(rules::internal_error()),
    }
}

/// #845 둘째 `list.delete`: 없는 id 는 조용히 끝. 지웠으면 내 연결 모두와 그 목록에 있던 사람에게 directory.update.
fn list_delete(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    list_id: &str,
) -> Option<ServerFrame> {
    if !list_id_ok(list_id) {
        return Some(ServerFrame::Error {
            code: ErrorCode::Protocol,
            message: "list.delete".into(),
            r#ref: req,
        });
    }
    match app.db.list_delete(&who.user, list_id) {
        Ok(Some(was)) => {
            send_directory_to(app, std::slice::from_ref(&who.user));
            if !was.is_empty() {
                send_directory_to(app, &was);
            }
            None
        }
        Ok(None) => None,
        Err(_) => Some(rules::internal_error()),
    }
}

/// #845 §7-56 계정당 음소거 대화 상한.
pub const MUTES_MAX: i64 = 500;

/// #845 §7-56 `mute.set`: 계정 단위 대화 음소거(내 모든 기기가 같이). `until` 없음 = 계속, 시각 = 그때까지, `clear`(null)·지난
/// 시각 = 풂. 바뀌면 내 연결 모두에 directory.update(답 프레임 없음). 주소 꼴이 아니면 protocol, 새 대화가 상한을 넘으면 quota
/// (둘 다 ref = req).
fn mute_set(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    conv: &str,
    until: Option<&str>,
    clear: bool,
) -> Option<ServerFrame> {
    let err = |code: ErrorCode| ServerFrame::Error {
        code,
        message: "mute.set".into(),
        r#ref: req.clone(),
    };
    let Some(addr) = crate::frames::Address::parse(conv) else {
        return Some(err(ErrorCode::Protocol));
    };
    if addr.is_group() && addr.gid().is_none() {
        return Some(err(ErrorCode::Protocol));
    }
    let now = app.effects.clock.now().0;
    let until_ms = match until {
        None => None,
        Some(t) => match lodelai_effects::UnixMillis::parse_rfc3339(t) {
            Ok(u) => Some(u.0),
            Err(_) => return Some(err(ErrorCode::Protocol)),
        },
    };
    // null·지난 시각 = 풂.
    let off = clear || until_ms.is_some_and(|u| u <= now);
    // 저장은 받은 글 그대로가 아니라 푸시 비교(`Category::mute_conv`)와 같은 꼴로.
    match app.db.mute_set(
        &who.user,
        &addr.conv_key(),
        (!off).then_some(until_ms),
        now,
        MUTES_MAX,
    ) {
        Ok(Some(true)) => {
            send_directory_to(app, std::slice::from_ref(&who.user));
            None
        }
        Ok(Some(false)) => None,
        Ok(None) => Some(err(ErrorCode::Quota)),
        Err(_) => Some(rules::internal_error()),
    }
}

/// #880 `pin.set`: 계정 단위 대화 고정 한 동작(내 모든 기기가 같이). `index` = 그 자리에 넣기(있으면 옮기기), `None` = 풂.
/// 바뀌면 내 연결 모두에 directory.update(답 프레임 없음). 세션 주소·내 주소·꼴 틀림은 protocol, 찬 뒤 새 대화는 quota
/// (둘 다 ref = req).
fn pin_set(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    conv: &str,
    index: Option<i64>,
) -> Option<ServerFrame> {
    let err = |code: ErrorCode| ServerFrame::Error {
        code,
        message: "pin.set".into(),
        r#ref: req.clone(),
    };
    let max = i64::try_from(lodelai_protocol::constants::PINS_MAX).unwrap_or(9);
    let Some(addr) = crate::frames::Address::parse(conv) else {
        return Some(err(ErrorCode::Protocol));
    };
    // 고정은 화면의 대화 단위 — 그룹이나 사람(세션 주소는 사람 대화 안에 든다). 나와의 대화도 없다.
    let mine = addr.user.eq_ignore_ascii_case(&who.user)
        && addr.server.eq_ignore_ascii_case(&app.config.server_name);
    if addr.slug.is_some()
        || mine
        || (addr.is_group() && addr.gid().is_none())
        || index.is_some_and(|i| !(0..max).contains(&i))
    {
        return Some(err(ErrorCode::Protocol));
    }
    // 그룹은 지금 멤버일 때만 넣는다(나간 그룹은 relay 가 목록에서 뺀다). 풀기는 늘 된다.
    if index.is_some() {
        if let Some(gid) = addr.gid() {
            let member = app
                .db
                .group_view(gid)
                .ok()
                .flatten()
                .is_some_and(|g| g.members.contains(&who.user));
            if !member {
                return Some(err(ErrorCode::Protocol));
            }
        }
    }
    let res = app.db.pin_set(
        &who.user,
        &addr.conv_key(),
        index.and_then(|i| usize::try_from(i).ok()),
        usize::try_from(max).unwrap_or(9),
    );
    // 고정 수가 줄었을 때 누가·언제 바꿨는지 가리려고(11-10 실기 다섯→둘).
    let outcome = match &res {
        Ok(Some(true)) => "바뀜",
        Ok(Some(false)) => "그대로",
        Ok(None) => "상한",
        Err(_) => "오류",
    };
    tracing::info!(user = %who.user, device = %who.device_id, conv = %addr.conv_key(), ?index, outcome, "pin.set");
    match res {
        Ok(Some(true)) => {
            send_directory_to(app, std::slice::from_ref(&who.user));
            None
        }
        Ok(Some(false)) => None,
        Ok(None) => Some(err(ErrorCode::Quota)),
        Err(_) => Some(rules::internal_error()),
    }
}

/// §7-46 틀린 조직 초대 코드 상한(사용자당 1시간 10번 — 가입의 `invites/check` 확인 실패 상한과 같은 수).
pub const ORG_CODE_FAILS_PER_HOUR: u32 = 10;
/// #845 둘째 ③ `org.external.preview` 조직당 1시간 상한(넘으면 1시간 `rate_limited`, 창은 [`ORG_CODE_THROTTLE_MS`]).
pub const ORG_EXTERNAL_PREVIEW_PER_HOUR: u32 = 10;
/// §7-46 틀린 코드 상한의 창·막는 시간.
pub const ORG_CODE_THROTTLE_MS: i64 = 60 * 60 * 1000;

/// §7-46 확인되지 않은(잎 자격 없는) 기기는 계정을 옮기지 못한다 — 관리자 동작과 같은 문턱(#737).
fn unconfirmed_device(app: &Relay, who: &Authed, what: &str) -> Option<ServerFrame> {
    if crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) {
        return None;
    }
    Some(ServerFrame::Error {
        code: ErrorCode::DeviceUnconfirmed,
        message: what.into(),
        r#ref: None,
    })
}

/// §7-46 늦춤 — `error{rate_limited, ref: req, until}`.
fn rate_limited_req(what: &str, req: Option<&str>, until_ms: i64) -> ServerFrame {
    let mut v = serde_json::json!({
        "t": "error", "code": "rate_limited", "message": what,
        "until": lodelai_effects::UnixMillis(until_ms).to_rfc3339().unwrap_or_default(),
    });
    if let Some(r) = req {
        v["ref"] = serde_json::json!(r);
    }
    match serde_json::from_value::<lodelai_protocol::ws::Frame>(v) {
        Ok(f) => ServerFrame::Ws(Box::new(f)),
        Err(_) => rules::rate_limited(what, until_ms),
    }
}

/// #845 둘째 ③ `org.external.preview`: 조직 밖 막기를 켜기 전 조직 전체 셈 — 읽기만. 관리자·조직만(아니면
/// error{protocol, ref: req} — org.update external 과 같은 검사). 조직당 1시간 10번 상한(넘으면 rate_limited, ref).
/// 밀어 주지 않는다(요청/답만), 로그엔 조직 id 만.
fn org_external_preview(app: &Relay, who: &Authed, req: Option<String>) -> Option<ServerFrame> {
    let now = app.effects.clock.now();
    let key = match app.db.user_org(&who.user) {
        Ok(Some(org)) => org,
        Ok(None) => String::new(),
        Err(_) => return Some(rules::internal_error()),
    };
    if let Some(ms) = app.org_external_preview.blocked(&key, now) {
        return Some(rate_limited_req(
            "org.external.preview",
            req.as_deref(),
            now.0 + ms,
        ));
    }
    let p = match app.db.org_external_preview(&who.user, now.0) {
        Ok(Some(p)) => {
            if app.org_external_preview.hit(&key, now) {
                tracing::info!(org = %key, "조직 밖 막기 셈 상한 — 1시간 막음");
            }
            p
        }
        Ok(None) => {
            return Some(ServerFrame::Error {
                code: ErrorCode::Protocol,
                message: "org.external.preview".into(),
                r#ref: req,
            });
        }
        Err(_) => return Some(rules::internal_error()),
    };
    Some(ServerFrame::Ws(Box::new(
        lodelai_protocol::ws::Frame::OrgExternalPreviewAnswer(
            lodelai_protocol::ws::OrgExternalPreviewAnswer {
                frozen: p.frozen,
                invites: p.invites,
                pending: p.pending,
                req: req.and_then(|r| r.try_into().ok()),
                t: lodelai_protocol::ws::OrgExternalPreviewAnswerT::OrgExternalPreview,
            },
        ),
    )))
}

/// §7-46 틀린 코드 셈의 열쇠(사용자).
fn org_code_key(who: &Authed) -> String {
    format!("u:{}", who.user)
}

/// §7-46 `org.code.check`: 초대 카드(가입의 `invites/check` 와 같은 칸) — 읽기만. 다른 이메일 것이면 가린 이메일(실패로
/// 세지 않음), 없음·끝남이면 gone(틀린 코드로 센다). 막혀 있으면 rate_limited.
fn org_code_check(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    code: &str,
) -> Option<ServerFrame> {
    let now = app.effects.clock.now();
    let key = org_code_key(who);
    if let Some(ms) = app.org_code_fails.blocked(&key, now) {
        return Some(rate_limited_req(
            "org.code.check",
            req.as_deref(),
            now.0 + ms,
        ));
    }
    let out = match app
        .db
        .org_code_check(&who.user, &crate::http::invite_hash(code.trim()), now.0)
    {
        Ok(o) => o,
        Err(_) => return Some(rules::internal_error()),
    };
    let mut ans = lodelai_protocol::ws::OrgCodeCheckAnswer {
        gone: None,
        inviter: None,
        org_avatar: None,
        org_color: None,
        org_id: None,
        org_name: None,
        other_email: None,
        req: req.and_then(|r| r.try_into().ok()),
        t: lodelai_protocol::ws::OrgCodeCheckAnswerT::OrgCodeCheck,
        teams: Vec::new(),
    };
    match out {
        crate::db::InviteCheckOut::Ok(i) => {
            ans.org_avatar = i
                .org_avatar
                .as_deref()
                .and_then(|id| crate::blob::read_avatar(app, id))
                .map(|png| encoding::encode(&png));
            ans.org_color = i.org_color.as_deref().and_then(|c| c.parse().ok());
            ans.inviter = Some(lodelai_protocol::ws::OrgCodeCheckAnswerInviter {
                user: i.inviter,
                display_name: i.inviter_display,
            });
            ans.teams = i
                .teams
                .into_iter()
                .map(|(id, name)| lodelai_protocol::ws::DirectoryTeam { id, name })
                .collect();
            ans.org_name = Some(i.org_name);
            ans.org_id = Some(i.org_id);
        }
        crate::db::InviteCheckOut::OtherEmail(e) => {
            ans.other_email = Some(crate::http::mask_email(&e));
        }
        crate::db::InviteCheckOut::NotFound => {
            app.org_code_fails.hit(&key, now);
            ans.gone = Some(true);
        }
    }
    Some(ServerFrame::Ws(Box::new(
        lodelai_protocol::ws::Frame::OrgCodeCheckAnswer(ans),
    )))
}

/// §7-46 옮긴 뒤 — 성공 답을 먼저, 그다음 새 조직 동료에게 새 사람, 내 연결 모두에 org_changed 를 보내고 닫는다
/// (org.invite.answer 수락과 같음 — 앱은 바로 다시 붙는다).
fn org_moved(app: &Relay, who: &Authed, what: &str, answer: lodelai_protocol::ws::Frame) {
    app.conns.send_devices(
        &who.user,
        std::slice::from_ref(&who.device_id),
        &ServerFrame::Ws(Box::new(answer)),
    );
    broadcast_directory_of(app, &who.user);
    app.conns.send_user(
        &who.user,
        &ServerFrame::Error {
            code: ErrorCode::OrgChanged,
            message: what.into(),
            r#ref: None,
        },
    );
    app.conns.close_user(&who.user);
}

/// §7-46 `org.join`: 개인 공간 → 초대 코드로 그 조직에.
fn org_join(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    code: &str,
    teams: &[String],
) -> Option<ServerFrame> {
    use lodelai_protocol::ws::{OrgJoinAnswer, OrgJoinAnswerRefused as R, OrgJoinAnswerT};
    if let Some(e) = unconfirmed_device(app, who, "org.join") {
        return Some(e);
    }
    let now = app.effects.clock.now();
    let key = org_code_key(who);
    if let Some(ms) = app.org_code_fails.blocked(&key, now) {
        return Some(rate_limited_req("org.join", req.as_deref(), now.0 + ms));
    }
    let answer = |refused: Option<R>, email: Option<String>| OrgJoinAnswer {
        email,
        refused,
        req: req.clone().and_then(|r| r.try_into().ok()),
        t: OrgJoinAnswerT::OrgJoin,
    };
    let refused = |r: R, email: Option<String>| {
        Some(ServerFrame::Ws(Box::new(
            lodelai_protocol::ws::Frame::OrgJoinAnswer(answer(Some(r), email)),
        )))
    };
    match app.db.org_join(
        &who.user,
        &crate::http::invite_hash(code.trim()),
        teams,
        now.0,
    ) {
        Ok(crate::db::OrgMoveOut::Moved(..)) => {
            tracing::info!(user = %who.user, "초대 코드로 조직 들기 — 조직 옮김");
            org_moved(
                app,
                who,
                "org.join",
                lodelai_protocol::ws::Frame::OrgJoinAnswer(answer(None, None)),
            );
            None
        }
        Ok(crate::db::OrgMoveOut::NotPersonal) => refused(R::NotPersonal, None),
        Ok(crate::db::OrgMoveOut::OtherEmail(e)) => {
            refused(R::InviteOtherEmail, Some(crate::http::mask_email(&e)))
        }
        Ok(crate::db::OrgMoveOut::BadCode) => {
            app.org_code_fails.hit(&key, now);
            refused(R::InvalidInvite, None)
        }
        Err(crate::db::DbError::BadOrg) => Some(rules::protocol_error("org.join teams")),
        Err(_) => Some(rules::internal_error()),
    }
}

/// §7-46 `org.create`: 개인 공간 → 조직 만들기. 가입의 조직 만들기(http `register` 의 `OrgRequest::Create`)와 같은 거절
/// 순서·이유 — 코드를 줬으면 코드 검사(맞으면 상한 밖, 늦춤은 전체·사용자·이메일), 코드 없이 `code` 모드면 승인된 이메일만,
/// `open` 이면 상한(사용자 키가 IP 자리). hosted(`remote`)가 아니면 상한·코드 없이 만든다.
#[allow(clippy::too_many_lines)]
fn org_create(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    name: &str,
    setup_code: Option<&str>,
) -> Option<ServerFrame> {
    use lodelai_protocol::ws::{OrgCreateAnswer, OrgCreateAnswerRefused as R, OrgCreateAnswerT};
    if let Some(e) = unconfirmed_device(app, who, "org.create") {
        return Some(e);
    }
    let Some(name) = org_name(name) else {
        return Some(rules::protocol_error("org.create name"));
    };
    let answer = |refused: Option<R>, email: Option<String>| OrgCreateAnswer {
        email,
        refused,
        req: req.clone().and_then(|r| r.try_into().ok()),
        t: OrgCreateAnswerT::OrgCreate,
    };
    let refused = |r: R, email: Option<String>| {
        Some(ServerFrame::Ws(Box::new(
            lodelai_protocol::ws::Frame::OrgCreateAnswer(answer(Some(r), email)),
        )))
    };
    let clock = app.effects.clock.now();
    let now = clock.0;
    let user_key = org_code_key(who);
    let email = match app.db.user_email(&who.user) {
        Ok(e) => e,
        Err(_) => return Some(rules::internal_error()),
    };
    let (hash, quota, allowed) = if app.config.remote {
        match setup_code {
            Some(code) => {
                // 가입과 같은 늦춤: 전체·사용자(IP 자리)는 모든 시도, 이메일(없으면 사용자)은 틀린 코드만 센다.
                let fail_key = email.clone().unwrap_or_else(|| user_key.clone());
                let blocked = [
                    app.setup_code_all.blocked("all", clock),
                    app.setup_code_ip.blocked(&user_key, clock),
                    app.setup_code_email_fails.blocked(&fail_key, clock),
                ]
                .into_iter()
                .flatten()
                .max();
                if let Some(ms) = blocked {
                    return Some(rate_limited_req("org.create", req.as_deref(), now + ms));
                }
                if app.setup_code_all.hit("all", clock) {
                    tracing::warn!(
                        "조직 만들기 코드 시도가 relay 전체 상한에 닿았다 — 1시간 받지 않는다"
                    );
                }
                app.setup_code_ip.hit(&user_key, clock);
                let h = crate::http::setup_code_hash(code);
                match app.db.check_setup_code(&h, email.as_deref(), now) {
                    Ok(crate::db::SetupCheck::Ok) => {}
                    Ok(crate::db::SetupCheck::Expired) => {
                        return refused(R::SetupCodeExpired, None)
                    }
                    Ok(crate::db::SetupCheck::OtherEmail(mask)) => {
                        return refused(
                            R::SetupCodeOtherEmail,
                            Some(mask).filter(|m| !m.is_empty()),
                        );
                    }
                    Ok(crate::db::SetupCheck::Wrong) => {
                        app.setup_code_email_fails.hit(&fail_key, clock);
                        return refused(R::InvalidInvite, None);
                    }
                    Err(_) => return Some(rules::internal_error()),
                }
                (Some(h), None, false)
            }
            None if !app.config.org_create_open => {
                match email.as_deref().map(|e| app.db.org_create_allowed(e, now)) {
                    Some(Ok(true)) => (None, None, true),
                    Some(Ok(false)) | None => return refused(R::InvalidInvite, None),
                    Some(Err(_)) => return Some(rules::internal_error()),
                }
            }
            None => {
                let l = app.config.org_create_limits;
                let over = !app.org_create_ip_limiter.would_allow(&user_key, clock);
                (
                    None,
                    Some(crate::db::OrgQuota {
                        per_email_30d: l.per_email_30d,
                        per_day: l.per_day,
                        max_orgs: l.max_orgs,
                        ip_over: over,
                    }),
                    false,
                )
            }
        }
    } else {
        (None, None, false)
    };
    let id = app.effects.ids.next_ulid();
    match app
        .db
        .org_create_move(&who.user, &id, &name, hash.as_deref(), quota, allowed, now)
    {
        Ok(crate::db::OrgMoveOut::Moved(..)) => {
            if quota.is_some() {
                app.org_create_ip_limiter.allow(&user_key, clock);
            }
            tracing::info!(org = %id, user = %who.user, "조직 만들기 — 개인 공간에서 옮김");
            org_moved(
                app,
                who,
                "org.create",
                lodelai_protocol::ws::Frame::OrgCreateAnswer(answer(None, None)),
            );
            None
        }
        Ok(crate::db::OrgMoveOut::NotPersonal) => refused(R::NotPersonal, None),
        Ok(crate::db::OrgMoveOut::BadCode | crate::db::OrgMoveOut::OtherEmail(_)) => {
            refused(R::InvalidInvite, None)
        }
        Err(crate::db::DbError::OrgClosed) => refused(R::OrgCreateClosed, None),
        Err(crate::db::DbError::OrgRateLimited) => refused(R::OrgRateLimited, None),
        Err(_) => Some(rules::internal_error()),
    }
}

/// #845 ④ `org.invite`: 관리자만, 답은 늘 `org.invite.sent`(받는 사람의 사정을 드러내지 않는다). 메일은 ⑤.
fn org_invite(app: &Relay, who: &Authed, req: Option<String>, raw: &str) -> Option<ServerFrame> {
    let Some(email) = crate::http::normalize_email(raw) else {
        return Some(rules::protocol_error("org.invite 형식"));
    };
    let mut token = [0u8; 32];
    if app.effects.rng.try_fill(&mut token).is_err() {
        return Some(rules::internal_error());
    }
    let hash = crate::http::invite_hash(&encoding::encode(&token));
    let id = app.effects.ids.next_ulid();
    match app.db.org_invite(
        &who.user,
        &email,
        raw.trim(),
        &id,
        &hash,
        app.effects.clock.now().0,
        INVITE_WINDOW_MS,
        INVITE_MAX,
    ) {
        Ok(crate::db::OrgInviteOut::Sent { notify, org }) => {
            tracing::info!(by = %who.user, "조직 초대");
            // §7-26: 보낸 기록은 그 조직 관리자 전원에게.
            let mut to = app.db.org_admins_of(&org).unwrap_or_default();
            if let Some(u) = &notify {
                crate::push::on_invite(app, u, crate::push::InviteSub::Org, &id);
            }
            to.extend(notify);
            send_directory_to(app, &to);
            let sent = lodelai_protocol::ws::OrgInviteSent {
                req: req.and_then(|r| r.try_into().ok()),
                t: lodelai_protocol::ws::OrgInviteSentT::OrgInviteSent,
            };
            Some(ServerFrame::Ws(Box::new(
                lodelai_protocol::ws::Frame::OrgInviteSent(sent),
            )))
        }
        Ok(crate::db::OrgInviteOut::RateLimited { until_ms }) => {
            Some(rules::rate_limited("org.invite", until_ms))
        }
        Ok(crate::db::OrgInviteOut::Refused) => Some(rules::protocol_error("org.invite")),
        Err(_) => Some(rules::internal_error()),
    }
}

/// #845 ④ `group.invite`: 그룹의 지금 멤버만, 답은 늘 `group.invite.sent`. 메일은 ⑤.
fn group_invite(
    app: &Relay,
    who: &Authed,
    req: Option<String>,
    group: &str,
    to: &crate::frames::LinkTo,
) -> Option<ServerFrame> {
    let gid = crate::frames::Address::parse(group)
        .filter(|a| a.server == app.config.server_name)
        .and_then(|a| a.gid().map(str::to_owned));
    let Some(gid) = gid else {
        return Some(rules::protocol_error("group.invite 형식"));
    };
    let shown = match to {
        crate::frames::LinkTo::Email(e) | crate::frames::LinkTo::User(e) => e.trim().to_owned(),
    };
    let email;
    let target = match to {
        crate::frames::LinkTo::Email(e) => {
            let Some(e) = crate::http::normalize_email(e) else {
                return Some(rules::protocol_error("group.invite 형식"));
            };
            email = e;
            crate::db::LinkTarget::Email(&email)
        }
        crate::frames::LinkTo::User(u) => crate::db::LinkTarget::User(u),
    };
    // QA 시험 전용(`--test-invite-fail`): 앞부분이 fail 인 대상은 상한에 걸린 것처럼 — 앱 '초대 안 됨'. 다시 시도 시각
    // (`--test-invite-fail-retry-secs`, 기본 1시간)이 지난 같은 대상의 두 번째 시도는 통과(앱 '다시 초대').
    if app.config.test_invite_fail && shown.to_ascii_lowercase().starts_with("fail") {
        let now = app.effects.clock.now().0;
        let key = format!("{}\n{gid}\n{}", who.user, shown.to_ascii_lowercase());
        let mut seen = app
            .test_invite_fail_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retry_ms = i64::try_from(app.config.test_invite_fail_retry_secs)
            .unwrap_or(i64::MAX / 1000)
            .saturating_mul(1000);
        match seen.get(&key).copied() {
            Some(until) if now >= until => {}
            Some(until) => return Some(rules::rate_limited("group.invite", until)),
            None => {
                let until = now.saturating_add(retry_ms);
                seen.insert(key, until);
                return Some(rules::rate_limited("group.invite", until));
            }
        }
    }
    let id = app.effects.ids.next_ulid();
    match app.db.group_invite(
        &who.user,
        &gid,
        target,
        &shown,
        &id,
        app.effects.clock.now().0,
    ) {
        Ok(crate::db::GroupInviteOut::Sent { card, joining }) => {
            tracing::info!(by = %who.user, "그룹 초대");
            // §7-26: 보낸 기록은 나에게(모든 기기).
            let mut to = vec![who.user.clone()];
            if let Some(u) = &card {
                crate::push::on_invite(app, u, crate::push::InviteSub::Group, &id);
            }
            to.extend(card);
            send_directory_to(app, &to);
            send_directory_to_invitees(app, &gid, &to);
            if joining {
                send_groups_to_members(app, &gid);
            }
            let sent = lodelai_protocol::ws::GroupInviteSent {
                req: req.and_then(|r| r.try_into().ok()),
                t: lodelai_protocol::ws::GroupInviteSentT::GroupInviteSent,
            };
            Some(ServerFrame::Ws(Box::new(
                lodelai_protocol::ws::Frame::GroupInviteSent(sent),
            )))
        }
        Ok(crate::db::GroupInviteOut::RateLimited { until_ms }) => {
            Some(rules::rate_limited("group.invite", until_ms))
        }
        Ok(crate::db::GroupInviteOut::Refused) => Some(rules::protocol_error("group.invite")),
        Err(_) => Some(rules::internal_error()),
    }
}

/// #845 §7-44 ② 그 그룹의 대기 초대를 받은 사람에게 디렉터리 다시(카드의 멤버 수가 바뀜). `except` 는 이미 보낸 사람.
pub fn send_directory_to_invitees(app: &Relay, gid: &str, except: &[String]) {
    let now = app.effects.clock.now().0;
    let to: Vec<String> = app
        .db
        .group_invitees_pending(gid, now)
        .unwrap_or_default()
        .into_iter()
        .filter(|u| !except.contains(u))
        .collect();
    if !to.is_empty() {
        send_directory_to(app, &to);
    }
}

/// #845 ④ 그룹의 지금 멤버 연결에 `groups`(joining 이 바뀜 — 멤버 기기가 add 한다).
pub fn send_groups_to_members(app: &Relay, gid: &str) {
    // §7-25: 대리 add 하는 기기가 Commit 을 만들기 전에 모두가 새 잎·기존 잎의 키를 갖게 — 디렉터리를 먼저.
    if let Ok(circle) = app.db.group_circle(gid) {
        send_directory_to(app, &circle);
    }
    for u in app.db.group_members_now(gid).unwrap_or_default() {
        if let Some(f) = groups_frame_if_any(app, &u) {
            app.conns.send_user(&u, &f);
        }
    }
}

/// #923 신고 글 개수·길이 상한(스키마에 겹친 상한을 두지 않고 여기서 본다).
pub const REPORT_MESSAGES_MAX: usize = 20;
pub const REPORT_TEXT_MAX_CHARS: usize = 4000;
pub const REPORT_NOTE_MAX_CHARS: usize = 1000;

/// #923 `report`: 상한 셈 → (대상이 있고 나 자신이 아니면) 그 자리에서 메일 → 줄 넣기. 본문·설명은 메일에만 싣고 DB·로그
/// 어디에도 남기지 않는다(줄은 신고자·대상·사유·시각만). 대상 유무와 무관하게 같은 답·같은 셈(없는·나 자신도 줄을 남김,
/// 메일만 안 감). 메일 실패면 줄을 남기지 않고 internal(앱이 다시 시도). 대상에겐 아무것도 안 간다.
fn report(app: &Relay, who: &Authed, r: lodelai_protocol::ws::Report) -> Option<ServerFrame> {
    let req = r.req.to_string();
    let err = |code: ErrorCode| ServerFrame::Error {
        code,
        message: "report".into(),
        r#ref: Some(req.clone()),
    };
    let (Some(to), Some(mailer)) = (app.config.report_email.as_deref(), app.mailer.as_ref()) else {
        return Some(err(ErrorCode::Protocol));
    };
    if r.messages.len() > REPORT_MESSAGES_MAX
        || r.messages
            .iter()
            .any(|m| m.text.chars().count() > REPORT_TEXT_MAX_CHARS)
        || r.note
            .as_ref()
            .is_some_and(|n| n.chars().count() > REPORT_NOTE_MAX_CHARS)
    {
        return Some(err(ErrorCode::Protocol));
    }
    let now = app.effects.clock.now().0;
    // 주소 꼴은 스키마가 봤다 — 다른 서버 주소면 대상 없음과 같다(아이디만 셈에 남김).
    let peer = r.peer.to_string();
    let target = link_peer(app, &peer);
    let reported = target.clone().unwrap_or(peer);
    match app.db.report_limited(&who.user, &reported, now) {
        Ok(Some(until)) => return Some(rate_limited_req("report", Some(&req), until)),
        Ok(None) => {}
        Err(_) => return Some(err(ErrorCode::Internal)),
    }
    let reason = r.reason.to_string();
    let gid = r.group.as_ref().and_then(|g| {
        crate::frames::Address::parse(g.as_str()).and_then(|a| a.gid().map(str::to_owned))
    });
    let facts = match target.as_deref().filter(|t| *t != who.user) {
        Some(t) => match app.db.report_facts(&who.user, t, gid.as_deref(), now) {
            Ok(f) => f,
            Err(_) => return Some(err(ErrorCode::Internal)),
        },
        None => None,
    };
    if let Some(facts) = facts {
        let ts = |ms: i64| {
            lodelai_effects::UnixMillis(ms)
                .to_rfc3339()
                .unwrap_or_default()
        };
        let at = ts(now);
        let until = facts.suspended.flatten().map(ts);
        let (subject, text) = crate::mail::report_mail(&crate::mail::ReportMail {
            server: &app.config.server_name,
            at: &at,
            reporter: &who.user,
            reported: &reported,
            reason: &reason,
            facts: &facts,
            suspended_until: until.as_deref(),
            group: r.group.as_ref().map(|g| g.as_str()),
            note: r.note.as_deref(),
            messages: &r.messages,
        });
        if let Err(e) = mailer.send_text(to, &subject, &text) {
            tracing::warn!(user = %who.user, error = %e, "신고 메일 실패");
            return Some(err(ErrorCode::Internal));
        }
    }
    if app
        .db
        .report_insert(&who.user, &reported, &reason, now)
        .is_err()
    {
        return Some(err(ErrorCode::Internal));
    }
    tracing::info!(reporter = %who.user, reported = %reported, reason = %reason, "신고 받음");
    Some(report_sent(req))
}

fn report_sent(req: String) -> ServerFrame {
    // req 는 받은 프레임의 같은 꼴(64자 이하)이라 바뀌지 않을 수 없다.
    let Ok(req) = req.try_into() else {
        return rules::internal_error();
    };
    let sent = lodelai_protocol::ws::ReportSent {
        req,
        t: lodelai_protocol::ws::ReportSentT::ReportSent,
    };
    ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::ReportSent(sent)))
}

fn link_sent(req: Option<String>, unknown: bool) -> ServerFrame {
    let sent = lodelai_protocol::ws::LinkSent {
        req: req.and_then(|r| r.try_into().ok()),
        t: lodelai_protocol::ws::LinkSentT::LinkSent,
        unknown: unknown.then_some(true),
    };
    ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::LinkSent(sent)))
}

/// 없는 아이디 찾기 통(사용자·IP, 분·하루)에서 하나씩 꺼낸다. 하나라도 비었으면 아무것도 꺼내지 않고 다시 될 시각.
fn unknown_id_spend(app: &Relay, who: &Authed) -> Result<(), i64> {
    let now = app.effects.clock.now();
    let mut keys = vec![format!("u:{}", who.user)];
    if let Some(ip) = &who.ip {
        keys.push(format!("ip:{ip}"));
    }
    crate::limiter::spend_all(&[&app.unknown_id_minute, &app.unknown_id_day], &keys, now)
}

#[cfg(test)]
mod tests {

    #[test]
    fn 판_16_아래엔_친구_목록_칸을_뺀다() {
        let text = Utf8Bytes::from(
            serde_json::json!({"t": "directory", "people": [], "sessions": [],
                "lists": [{"list_id": "friends01", "name": "친구", "users": []}]})
            .to_string(),
        );
        let v: serde_json::Value =
            serde_json::from_str(without_lists(text.clone()).as_str()).unwrap();
        assert!(v.get("lists").is_none(), "{v}");
        // 주인 세션 항목의 저장된 범위도 뺀다.
        let text = Utf8Bytes::from(
            serde_json::json!({"t": "directory.update", "people": [], "sessions": [
                {"address": "a@l/x", "grade": "task", "liveness": "dead",
                 "audience": {"kind": "people", "users": ["b"]}}]})
            .to_string(),
        );
        let v: serde_json::Value = serde_json::from_str(without_lists(text).as_str()).unwrap();
        assert!(v["sessions"][0].get("audience").is_none(), "{v}");
        // 디렉터리가 아니면 손대지 않는다.
        let other = Utf8Bytes::from(r#"{"t":"chat","lists":1}"#);
        assert_eq!(without_lists(other.clone()), other);
        assert_eq!(LISTS_FROM, 16);
    }
    use super::*;

    /// #846: 승인 전 연결 — 디렉터리는 내 항목만·sessions 빔·남의 칸 뺌, typing·groups·own_stream 버림, 그 밖 그대로.
    #[test]
    fn for_unapproved_keeps_only_my_entry_and_drops_peer_frames() {
        let me = "ann@local";
        let d = serde_json::json!({"t": "directory.update",
            "people": [{"address": me, "devices": [{"device_id": "d1"}]}, {"address": "bob@local"}],
            "sessions": [{"address": "bob@local/web"}], "links": [{"user": "bob"}], "teams": [], "pins": ["bob@local"],
            "mutes": [], "group_members": [], "link_requests": [], "revocations": [{"device_id": "x"}],
            "lists": [{"id": "l1", "name": "친구", "members": ["bob"]}]});
        let out = for_unapproved(Utf8Bytes::from(d.to_string()), me).unwrap();
        let v: serde_json::Value = serde_json::from_str(out.as_str()).unwrap();
        assert_eq!(
            v["people"],
            serde_json::json!([{"address": me, "devices": [{"device_id": "d1"}]}])
        );
        assert_eq!(v["sessions"], serde_json::json!([]));
        for k in [
            "links",
            "teams",
            "pins",
            "mutes",
            "group_members",
            "link_requests",
            "lists",
        ] {
            assert!(v.get(k).is_none(), "{k}: {v}");
        }
        assert_eq!(v["revocations"], d["revocations"]);
        for t in ["typing", "groups", "own_stream"] {
            let f = serde_json::json!({"t": t}).to_string();
            assert!(for_unapproved(Utf8Bytes::from(f), me).is_none(), "{t}");
        }
        let ack = r#"{"t":"ack","msg_id":"m"}"#;
        assert_eq!(
            for_unapproved(Utf8Bytes::from(ack), me).unwrap().as_str(),
            ack
        );
    }

    /// #702: 여러 스레드가 거의 같은 때 사람을 더하고 방송해도, 받는 연결의 디렉터리 모습은 뒤로 가지 않는다(사람 수가 줄지
    /// 않음) — 만든 순서 = 큐 순서. 잠금이 없으면 부하에서 낡은 모습이 새 모습 뒤에 들어간다.
    #[test]
    fn no_duty_connection_is_online_but_not_a_duty_candidate() {
        let conns = Connections::default();
        let who = |d: &str, no_duty: bool| Authed {
            user: "bob".into(),
            device_id: d.into(),
            v: 14,
            no_duty,
            own: false,
            look: false,
            contacts: false,
            mutes: false,
            pins: false,
            blocks: false,
            away: false,
            next_turn: false,
            ip: None,
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        conns.add(&who("phone", true), Tx(tx.clone()));
        conns.add(&who("mac", false), Tx(tx.clone()));
        assert_eq!(conns.online_devices("bob"), ["phone", "mac"]);
        assert_eq!(
            conns.duty_devices("bob"),
            ["mac"],
            "휴대폰 연결은 duty 후보가 아니다"
        );
        // 같은 기기가 no_duty 없는 연결도 하나 쥐면 후보다.
        conns.add(&who("phone", false), Tx(tx));
        assert_eq!(conns.duty_devices("bob"), ["mac", "phone"]);
        assert!(conns.duty_devices("nobody").is_empty());
    }

    #[test]
    fn 거의_같은_때의_방송도_낡은_디렉터리가_새_것을_덮지_않는다() {
        const THREADS: usize = 8;
        const EACH: usize = 25;
        let app = crate::Relay::new(
            crate::Config::local("local"),
            crate::Effects::system(),
            crate::db::Db::memory().unwrap(),
        );
        app.db
            .register_device("bob", None, "b1", "e", "x", "s", 0, false)
            .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let bob = Authed {
            user: "bob".into(),
            device_id: "b1".into(),
            v: 12,
            no_duty: false,
            own: false,
            look: false,
            contacts: false,
            mutes: false,
            pins: false,
            blocks: false,
            away: false,
            next_turn: false,
            ip: None,
        };
        app.conns.add(&bob, Tx(tx));
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let app = &app;
                s.spawn(move || {
                    for i in 0..EACH {
                        let u = format!("u{t}x{i}");
                        app.db
                            .register_device(
                                &u,
                                None,
                                &format!("d{t}x{i}"),
                                "e",
                                "x",
                                "s",
                                0,
                                false,
                            )
                            .unwrap();
                        broadcast_directory_of(app, &u);
                    }
                });
            }
        });
        let mut seen = Vec::new();
        while let Ok(f) = rx.try_recv() {
            let v: serde_json::Value = serde_json::from_str(f.as_str()).unwrap();
            assert_eq!(v["t"], "directory.update");
            seen.push(v["people"].as_array().unwrap().len());
        }
        assert_eq!(seen.len(), THREADS * EACH);
        assert!(
            seen.windows(2).all(|w| w[0] <= w[1]),
            "디렉터리가 뒤로 갔다: {seen:?}"
        );
        assert_eq!(seen.last(), Some(&(THREADS * EACH + 1)));
    }

    /// 묶음 22 §5d·⑦: 같은 프레임을 200 연결에 보내도 한 벌을 나눠 쓴다(연결마다 복제하지 않음).
    /// #598 ②: 판 9 연결엔 DirectoryDevice.v 를 빼고 status done 을 aborted{turn_ended} 로, 10 은 그대로.
    /// #961: hello.next_turn 없는 연결엔 sessions 의 live:next_turn 항목만 빠진다. 다른 항목·다른 프레임은 그대로.
    #[test]
    fn 옛_앱엔_다음_차례_세션_줄을_뺀다() {
        let dir = r#"{"t":"directory.update","people":[],"sessions":[{"address":"a@x/p","grade":"question","liveness":"live:pty"},{"address":"a@x/n","grade":"question","liveness":"live:next_turn"},{"address":"a@x/d","grade":"task","liveness":"dead"}]}"#;
        let out: serde_json::Value =
            serde_json::from_str(without_next_turn(Utf8Bytes::from(dir)).as_str()).unwrap();
        let left: Vec<_> = out["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["address"].as_str().unwrap())
            .collect();
        assert_eq!(left, ["a@x/p", "a@x/d"]);
        let plain = r#"{"t":"directory","people":[],"sessions":[{"address":"a@x/p","grade":"task","liveness":"live:pty"}]}"#;
        assert_eq!(
            without_next_turn(Utf8Bytes::from(plain)).as_str(),
            plain,
            "값 없으면 손대지 않음"
        );
        let msg = r#"{"t":"deliver","note":"live:next_turn"}"#;
        assert_eq!(
            without_next_turn(Utf8Bytes::from(msg)).as_str(),
            msg,
            "디렉터리 밖은 그대로"
        );
    }

    #[test]
    fn 판_9_연결엔_10_전용_칸과_상태를_낮춘다() {
        let dir = r#"{"t":"directory.update","people":[{"address":"a@x","devices":[{"device_id":"d1","v":10}]}]}"#;
        let st = r#"{"t":"status","msg_id":"m","state":"done","at":"2026-10-30T00:00:00Z"}"#;
        let other = r#"{"t":"status","msg_id":"m","state":"replied","at":"2026-10-30T00:00:00Z"}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        assert_eq!(v(dir, 9)["people"][0]["devices"][0].get("v"), None);
        assert_eq!(v(dir, 10)["people"][0]["devices"][0]["v"], 10);
        assert_eq!(v(st, 9)["state"], "aborted");
        assert_eq!(v(st, 9)["abort_reason"], "turn_ended");
        assert_eq!(v(st, 10)["state"], "done");
        assert_eq!(
            for_version(Utf8Bytes::from(other), 9).unwrap().as_str(),
            other,
            "표식 없으면 손대지 않음"
        );
        // #613: typing 은 판 11 아래 연결엔 보내지 않는다.
        let ty = r#"{"t":"typing","from":"a@x","on":true}"#;
        assert!(for_version(Utf8Bytes::from(ty), 10).is_none());
        assert!(for_version(Utf8Bytes::from(ty), 9).is_none());
        assert_eq!(for_version(Utf8Bytes::from(ty), 11).unwrap().as_str(), ty);
        assert_eq!(v(st, 11)["state"], "done");
    }

    /// 모바일 가입 '맥 꺼짐': 기기 항목의 online 은 판 15 이상 연결에만. 사람 항목의 online(접속 표시)과 다른 칸은 그대로.
    #[test]
    fn 판_15_아래_연결엔_기기_online_을_뺀다() {
        let dir = r#"{"t":"directory","people":[{"address":"a@x","online":true,"devices":[{"device_id":"d1","v":15,"online":false}]}],"sessions":[{"address":"a@x/s","agent":"codex"}]}"#;
        let upd = r#"{"t":"directory.update","people":[{"address":"a@x","online":true,"devices":[{"device_id":"d1","v":15,"online":true,"os":"android"}]}]}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        assert_eq!(for_version(Utf8Bytes::from(dir), 15).unwrap().as_str(), dir);
        assert_eq!(for_version(Utf8Bytes::from(upd), 15).unwrap().as_str(), upd);
        for n in [9, 10, 12, 13, 14] {
            for f in [dir, upd] {
                let out = v(f, n);
                let d = &out["people"][0]["devices"][0];
                assert_eq!(d.get("online"), None, "{n} {out}");
                assert_eq!(d.get("os"), None, "{n} {out}");
                assert_eq!(out["people"][0]["online"], true, "{n} {out}");
                assert_eq!(d.get("v").is_some(), n >= 10, "{n} {out}");
            }
        }
        // 판 13·14 는 세션 항목 agent 를 그대로 둔다(13 칸).
        assert_eq!(v(dir, 14)["sessions"][0]["agent"], "codex");
        assert_eq!(v(dir, 13)["sessions"][0]["agent"], "codex");
    }

    /// 백엔드 리뷰 Y2: 판 13 아래 연결의 전체 directory 에선 세션 항목의 agent·no 를 뺀다(12 앱은 모르는 칸이 든 directory 를
    /// 통째로 못 읽는다). directory.update 는 모르는 칸을 받으니 그대로, 13 은 그대로. 판 9 의 기기 v 빼기도 같이 된다.
    #[test]
    fn 판_13_아래_전체_directory_엔_세션_agent_no_를_뺀다() {
        let full = r#"{"t":"directory","people":[{"address":"a@x","devices":[{"device_id":"d1","v":10}]}],"sessions":[{"address":"a@x/s","grade":"task","liveness":"dead","agent":"codex","no":6,"offline":true}]}"#;
        let upd = r#"{"t":"directory.update","people":[],"sessions":[{"address":"a@x/s","grade":"task","liveness":"dead","agent":"codex","no":6}]}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        for n in [9, 10, 11, 12] {
            let s = &v(full, n)["sessions"][0];
            assert!(
                s.get("agent").is_none() && s.get("no").is_none() && s.get("offline").is_none(),
                "{n}: {s}"
            );
            assert_eq!(s["address"], "a@x/s");
            assert_eq!(v(upd, n)["sessions"][0]["no"], 6, "{n}: update 는 그대로");
        }
        assert_eq!(v(full, 9)["people"][0]["devices"][0].get("v"), None);
        assert_eq!(v(full, 12)["people"][0]["devices"][0]["v"], 10);
        assert_eq!(
            for_version(Utf8Bytes::from(full), 13).unwrap().as_str(),
            full
        );
    }

    /// #737: 판 13 아래엔 전체 directory 의 recovery.postponed 를 빼고, error device_unconfirmed 는 protocol 로.
    #[test]
    fn 판_13_아래엔_postponed_를_빼고_device_unconfirmed_는_protocol() {
        let full = r#"{"t":"directory","people":[{"address":"a@x","devices":[],"recovery":{"state":"scheduled","at":"2026-11-03T00:00:00.000Z","postponed":true}}],"sessions":[]}"#;
        let err = r#"{"t":"error","code":"device_unconfirmed","message":"org.admin"}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        for n in [9, 12] {
            let r = &v(full, n)["people"][0]["recovery"];
            assert!(r.get("postponed").is_none(), "{n}: {r}");
            assert_eq!(r["state"], "scheduled");
            assert_eq!(v(err, n)["code"], "protocol");
        }
        assert_eq!(v(full, 13)["people"][0]["recovery"]["postponed"], true);
        assert_eq!(v(err, 13)["code"], "device_unconfirmed");
        let rv = r#"{"t":"device.revoked","by":"admin_device","at":"2026-11-03T00:00:00.000Z"}"#;
        let er = r#"{"t":"error","code":"device_revoked","by":"admin_device","message":"auth"}"#;
        assert_eq!(v(rv, 12)["by"], "admin");
        assert_eq!(v(er, 12)["by"], "admin");
        assert_eq!(v(rv, 13)["by"], "admin_device");
    }

    #[test]
    fn send_devices_shares_one_copy() {
        let conns = Connections::default();
        let mut rxs = Vec::new();
        let mut ids = Vec::new();
        for i in 0..200 {
            let (t, r) = mpsc::unbounded_channel::<Utf8Bytes>();
            let who = Authed {
                user: "alice".into(),
                device_id: format!("d{i}"),
                v: u64::from(lodelai_protocol::PROTOCOL_VERSION),
                no_duty: false,
                own: false,
                look: false,
                contacts: false,
                mutes: false,
                pins: false,
                blocks: false,
                away: false,
                next_turn: false,
                ip: None,
            };
            conns.add(&who, Tx(t));
            ids.push(who.device_id);
            rxs.push(r);
        }
        let frame = ServerFrame::Deliver {
            message: serde_json::json!({"body": "x".repeat(40_000)}),
            group_seq: None,
        };
        conns.send_devices("alice", &ids, &frame);
        let got: Vec<Utf8Bytes> = rxs.iter_mut().map(|r| r.try_recv().unwrap()).collect();
        let first = got[0].as_str().as_ptr();
        assert!(got.iter().all(|t| t.as_str().as_ptr() == first));
        assert!(got[0].len() > 40_000);
    }
}
