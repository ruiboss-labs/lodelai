//! protocol §7.2 서버 규칙. 순서대로 검사하고 처음 실패에서 답한다.
//!
//! - 규칙 0, rate limit: [`crate::ws`] 가 프레임 파싱 직후에 본다.
//! - 규칙 1, 발신자 신원(`from.device_id`·`from.address` user·`sig`) + 크기 상한: `nack auth` / `too_large`.
//! - 규칙 2~5, 수신자 관계·등급·`reply_to` 대조·`chat` 은 사람 주소만: **모두 [`unroutable_nack`]** (존재 열거 방지).
//!   [`route`] 는 어느 경우든 같은 네 조회(사용자·조직·차단·세션)와 헤더 조회를 끝까지 한 뒤 판정한다.
//! - 규칙 6, 수신자가 오프라인이면 `expires_at` 까지 보관하고 접속하면 쏟는다.
//! - 규칙 7, 서버는 봉투 상태를 `stored → device_received` 로만 바꾸고 나머지는 당사자의 `status` 를 중계한다.

use lodelai_crypto::{verify_message, VerifyingKey};
use lodelai_effects::{is_ulid, UnixMillis};
use lodelai_statechart::request_recipient::AbortReason;
use lodelai_statechart::{envelope_server, request_sender_view, Step};
use serde_json::Value;

use crate::db::{GroupView, StoredHeader};
use crate::frames::{Address, ErrorCode, Header, Kind, NackReason, ServerFrame};
use crate::Relay;

/// 인증된 연결의 주체.
#[derive(Debug, Clone)]
pub struct Authed {
    pub user: String,
    pub device_id: String,
    /// 이 연결의 hello.v(#598 ② — 9 인 연결엔 10 전용 칸·상태를 낮춰 보낸다, [`crate::ws::for_version`]).
    pub v: u64,
}

/// 수신 메시지 보관 상한(chat 기본 7일). 발신자가 더 긴 `expires_at` 을 써도 서버는 이만큼만 보관한다.
pub const MAX_RETENTION_MS: i64 = 7 * 24 * 3600 * 1000;

/// `unroutable` 은 이 함수에서만 만든다. 사유 외 필드가 없고 경우와 무관하게 바이트가 같다(QA S-TENANT).
pub fn unroutable_nack(msg_id: &str) -> ServerFrame {
    ServerFrame::Nack {
        msg_id: msg_id.to_owned(),
        reason: NackReason::Unroutable,
    }
}

pub(crate) fn nack(msg_id: &str, reason: NackReason) -> ServerFrame {
    ServerFrame::Nack {
        msg_id: msg_id.to_owned(),
        reason,
    }
}

/// `send` 의 형식 오류. 보낸 쪽이 큐에서 그 메시지를 빼도록 `ref` 에 `msg_id` 를 싣는다(있을 때).
pub fn send_format_error(message: &Value) -> ServerFrame {
    let msg_id = message
        .get("msg_id")
        .and_then(Value::as_str)
        .filter(|id| is_ulid(id));
    ServerFrame::Error {
        code: ErrorCode::Protocol,
        message: "메시지 형식".to_owned(),
        r#ref: msg_id.map(str::to_owned),
    }
}

pub fn protocol_error(message: &str) -> ServerFrame {
    ServerFrame::Error {
        code: ErrorCode::Protocol,
        message: message.to_owned(),
        r#ref: None,
    }
}

pub(crate) fn internal_error() -> ServerFrame {
    ServerFrame::Error {
        code: ErrorCode::Internal,
        message: "internal".to_owned(),
        r#ref: None,
    }
}

fn grade_rank(g: &str) -> Option<u8> {
    match g {
        "question" => Some(1),
        "task" => Some(2),
        _ => None,
    }
}

/// `envelope_server.reply_accept_rule` (machines/wire.yaml): `kind=reply` 만 적용.
pub fn reply_accepted(h: &StoredHeader) -> bool {
    use request_sender_view::State as S;
    match S::from_name(&h.sender_view) {
        // done(#598 ②) — 답이 필요 없다 했어도 늦은 답은 받는다.
        Some(S::Pending | S::Accepted | S::Consumed | S::Replied | S::Done) => true,
        // needs_task 는 turn_ended 의 갈래(묶음 26 §5) — 늦은 회신을 받는다.
        Some(S::Aborted) => matches!(
            h.abort_reason.as_deref(),
            Some(r) if r == AbortReason::TurnEnded.as_str() || r == AbortReason::NeedsTask.as_str()
        ),
        _ => false,
    }
}

/// 거두기(묶음 14 #403): `system{reason: withdrawn}`.
pub fn is_withdraw(h: &Header) -> bool {
    h.kind == Kind::System && h.reason.as_deref() == Some("withdrawn")
}

/// 규칙 2·3·4·5. 통과하면 `Ok`, 아니면 `Err(())` — 호출자는 [`unroutable_nack`] 만 돌려준다.
///
/// 지연이 경우별로 다르지 않도록 일곱 조회를 **항상** 끝까지 한다.
pub(crate) fn route(
    app: &Relay,
    who: &Authed,
    h: &Header,
    to_raw: &str,
    group: Option<&GroupView>,
) -> Result<(), ()> {
    let db = &app.db;
    // 일곱 조회는 결과와 무관하게 모두 수행한다. 오류는 거부로 접는다.
    let to_org = db.user_org(&h.to.user).ok().flatten();
    let from_org = db.user_org(&who.user).ok().flatten();
    let blocked = db.is_blocked(&h.to.user, &who.user).unwrap_or(true);
    let session_grade = db
        .session_grade(&h.to.user, h.to.slug.as_deref().unwrap_or(""))
        .ok()
        .flatten();
    let original = db
        .header(h.reply_to.as_deref().unwrap_or(""))
        .ok()
        .flatten();
    // 고치기(묶음 14 #404)의 원 메시지.
    let edited = db.header(h.edits.as_deref().unwrap_or("")).ok().flatten();
    // 받을 기기(폐기 안 된)가 없는 사람 = 로그아웃한 사람(#325) — 본문을 쌓아 둘 이유가 없다(새 기기용 봉투가 아님).
    let has_device = db.devices_of(&h.to.user).is_ok_and(|d| !d.is_empty());

    // 그룹(묶음 16): 그룹 주소로 가면 사람 조회 대신 '그 그룹의 조직 = 내 조직 이고 내가 지금 멤버'. 헤더 group 이 붙은
    // 그룹 안 request·reply·rejected·system 은 사람 규칙에 더해 보내는 사람과 받는 사람(세션 주인·요청자) 둘 다 지금 멤버.
    let member = |u: &str| {
        group.is_some_and(|g| {
            from_org.as_deref() == Some(g.org.as_str()) && g.members.iter().any(|m| m == u)
        })
    };
    let peer_ok = if h.to.is_group() {
        h.to.server == app.config.server_name && member(&who.user)
    } else {
        h.to.server == app.config.server_name
            && to_org.is_some()
            && to_org == from_org
            && !blocked
            && has_device
            && (h.group.is_none() || (member(&who.user) && member(&h.to.user)))
    };

    let kind_ok = match h.kind {
        // 묶음 22 Handshake 는 crate::mls 가 따로 본다(§6 — pair·self 사람 관계는 거기서).
        Kind::Mls => false,
        // 멤버 변경은 [`handle_group_op`] 이 따로 본다.
        Kind::Group => false,
        // 5. chat 은 같은 조직 사람 주소로만. reply_to(인용, 묶음 14 B2)는 보지 않는다. edits 는 내가 같은 사람에게 보낸
        //    chat 이어야 한다(남의 메시지를 고치는 길 없음).
        Kind::Chat => {
            h.to.slug.is_none()
                && match (&h.edits, &edited) {
                    (None, _) => true,
                    (Some(_), Some(e)) => {
                        e.kind == "chat" && e.from_user == who.user && e.to_address == to_raw
                    }
                    (Some(_), None) => false,
                }
        }
        // 반응(#626)은 chat 처럼 사람·그룹 주소로만 — 세션 주소는 unroutable. 인용·고치기·등급 칸은 없다.
        Kind::Reaction => {
            h.to.slug.is_none() && h.reply_to.is_none() && h.edits.is_none() && h.grade.is_none()
        }
        // 3. request 는 공개된 세션 주소로, 공개 등급 이하만.
        Kind::Request => match (
            h.grade.as_deref().and_then(grade_rank),
            session_grade.as_ref().and_then(|(g, _)| grade_rank(g)),
        ) {
            // 묶음 20: 보낸 사용자가 주인이거나 범위 안(그룹 안 request 도 같다 — 그룹은 범위를 넓히지 않는다).
            (Some(asked), Some(published)) => {
                h.to.slug.is_some()
                    && h.reply_to.is_none()
                    && asked <= published
                    && (who.user == h.to.user
                        || session_grade
                            .as_ref()
                            .is_some_and(|(_, a)| a.as_ref().is_none_or(|a| a.contains(&who.user))))
            }
            _ => false,
        },
        // 거두기(묶음 14 #403): 원 메시지(request·chat)를 **보낸** 사용자가 그 메시지의 받는 주소로만.
        Kind::System if is_withdraw(h) => original.as_ref().is_some_and(|o| {
            matches!(o.kind.as_str(), "request" | "chat")
                && o.from_user == who.user
                && o.to_address == to_raw
        }),
        // 4. reply·rejected·system 은 보관 중인 원 메시지와 대조. 비공개 세션도 이 조건이면 보낼 수 있다.
        Kind::Reply | Kind::Rejected | Kind::System => match &original {
            Some(o) => {
                o.to_user == who.user
                    && o.from_address == to_raw
                    && (h.kind != Kind::Reply || reply_accepted(o))
            }
            None => false,
        },
    };

    if peer_ok && kind_ok {
        Ok(())
    } else {
        Err(())
    }
}

/// `send` 처리. 돌려준 프레임(`ack`/`nack`/`error`)을 발신 연결에 보낸다. 통과하면 수신자에게 `deliver` 한다.
/// 그룹 첨부 합계(묶음 22 §5d, 16 에서 옮김): 그룹 메시지(to 가 그룹 또는 헤더 group)의 첨부 `ct_len` 합이
/// `blob_ct_len(GROUP_FILES_MAX_BYTES) + 16 × 파일 수` 를 넘으면 `nack too_large`. 1:1 은 보지 않는다.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
pub(crate) fn group_files_ok(app: &Relay, who: &Authed, h: &Header) -> Result<(), ServerFrame> {
    if h.blobs.is_empty() || !(h.to.is_group() || h.group.is_some()) {
        return Ok(());
    }
    let max = lodelai_crypto::blob::blob_ct_len(lodelai_protocol::constants::GROUP_FILES_MAX_BYTES)
        + 16 * h.blobs.len() as u64;
    match app.db.blobs_ct_sum(&who.user, &h.blobs) {
        Ok(n) if n > max => Err(nack(&h.msg_id, NackReason::TooLarge)),
        Ok(_) => Ok(()),
        Err(_) => Err(internal_error()),
    }
}

pub fn handle_send(app: &Relay, who: &Authed, mut message: Value) -> ServerFrame {
    let Some(h) = Header::from_value(&message) else {
        return send_format_error(&message);
    };
    if !is_ulid(&h.msg_id)
        || !is_ulid(&h.thread_id)
        || h.reply_to.as_deref().is_some_and(|r| !is_ulid(r))
        || h.edits.as_deref().is_some_and(|r| !is_ulid(r))
    {
        return send_format_error(&message);
    }
    let (Ok(created), Ok(expires)) = (
        UnixMillis::parse_rfc3339(&h.created_at),
        UnixMillis::parse_rfc3339(&h.expires_at),
    ) else {
        return send_format_error(&message);
    };
    let _ = created;

    // 1. 크기 → 신원 → 서명
    if h.body_bytes > h.body_max_bytes() {
        return nack(&h.msg_id, NackReason::TooLarge);
    }
    if h.from_device_id != who.device_id
        || h.from.user != who.user
        || h.from.server != app.config.server_name
    {
        return nack(&h.msg_id, NackReason::Auth);
    }
    let key = match app.db.device(&who.device_id) {
        Ok(Some((_, pk))) => match VerifyingKey::from_b64(&pk) {
            Ok(k) => k,
            Err(_) => return internal_error(),
        },
        Ok(None) => return nack(&h.msg_id, NackReason::Auth),
        Err(_) => return internal_error(),
    };
    if verify_message(&message, &key).is_err() {
        return nack(&h.msg_id, NackReason::Auth);
    }

    // 그룹 끔(묶음 16 §3b): 그룹 주소·헤더 group·kind group 은 모두 같은 unroutable — 그룹이 있는지 드러나지 않는다.
    if !app.config.groups && (h.kind == Kind::Group || h.to.is_group() || h.group.is_some()) {
        return unroutable_nack(&h.msg_id);
    }

    // #577 §9 ②: 받는 기기가 바뀌어 실패를 알린 글을 같은 msg_id 로 다시 보내면 재생 ack 대신 다시 받는다(옛 봉투는 저장
    // 직전에 지운다 — mls::handle_send).
    let resend = app
        .db
        .device_changed_has(&h.msg_id, &who.user)
        .unwrap_or(false);
    // 재생(S-FORGE-8): 같은 발신자의 같은 msg_id 는 멱등 ack(다시 저장·전달하지 않음), 다른 발신자면 unroutable.
    match app.db.header(&h.msg_id) {
        // #598 ②: recipient_outdated 뒤 같은 msg_id 를 v9 로 다시 보냈다 — 표시된 판 9 기기에만(원래 봉투는 그대로).
        Ok(Some(existing))
            if existing.from_user == who.user
                && h.v < OUTDATED_FROM
                && h.mls
                    .as_ref()
                    .is_some_and(|m| m.wire == crate::frames::MlsWire::App)
                && app
                    .db
                    .outdated_waiting(&h.msg_id, &who.user)
                    .unwrap_or(false) =>
        {
            return outdated_resend(app, who, &h, message);
        }
        // 0.2.6 #809 §1-3: 못 엶을 알린 글을 같은 msg_id 로 다시 보냈다 — 보고한 기기에만(원래 봉투는 그대로).
        Ok(Some(existing))
            if existing.from_user == who.user
                && h.mls
                    .as_ref()
                    .is_some_and(|m| m.wire == crate::frames::MlsWire::App)
                && app
                    .db
                    .unreadable_waiting(&h.msg_id, &who.user)
                    .unwrap_or(false) =>
        {
            return unreadable_resend(app, &who.user, &h, message);
        }
        Ok(Some(_)) if resend => {}
        Ok(Some(existing)) => {
            return if existing.from_user == who.user {
                let group_seq = app.db.group_seq_of(&h.msg_id).ok().flatten();
                ServerFrame::Ack {
                    msg_id: h.msg_id,
                    group_seq,
                }
            } else {
                unroutable_nack(&h.msg_id)
            };
        }
        Ok(None) => {}
        Err(_) => return internal_error(),
    }

    let to_raw = message["to"]["address"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let from_raw = message["from"]["address"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // 묶음 22: MLS 본문은 전달 서비스가 맡는다(그룹 상태·잎 배달 — 봉투 recipients 6a 없음).
    if h.mls.is_some() {
        return crate::mls::handle_send(app, who, &h, message, to_raw, from_raw, expires.0);
    }
    // 여기부터는 평문 system 빈 본문뿐이다(frames: 평문은 system 빈 본문만, box 는 형식 오류 — #503). 첨부·고치기는 없고
    // 받을 기기는 받는 사용자(그룹 맥락이면 멤버, 거두기면 원 메시지의 수신 기기)의 폐기 안 된 기기.
    // 그룹 맥락(묶음 16)은 결과와 무관하게 한 번 읽는다.
    let group = match h.group.as_ref().and_then(Address::gid) {
        Some(gid) => match app.db.group_view(gid) {
            Ok(v) => v,
            Err(_) => return internal_error(),
        },
        None => None,
    };
    if route(app, who, &h, &to_raw, group.as_ref()).is_err() {
        return unroutable_nack(&h.msg_id);
    }
    let pool: Option<Vec<String>> = group.as_ref().map(|g| g.devices.clone());

    // 거두기·고치기(묶음 14): 원 메시지의 아직 받지 않은 기기 몫을 지운다(그 기기에 옛 글이 늦게 가지 않게).
    // 거두기는 원래 수신 기기 전부(이미 받은 기기 포함 — 지우도록)에만 전달한다.
    let withdraw_targets = match (is_withdraw(&h), h.reply_to.as_deref(), h.edits.as_deref()) {
        (true, Some(x), _) => match withdraw_original(app, x) {
            Ok(t) => Some(t),
            Err(()) => return internal_error(),
        },
        (false, _, Some(x)) => match withdraw_original(app, x) {
            Ok(_) => None,
            Err(()) => return internal_error(),
        },
        _ => None,
    };

    // 6. 저장 후 전달. 보관 기한은 min(expires_at, now + 7일).
    let now = app.effects.clock.now();
    let expires_ms = expires.0.min(now.0.saturating_add(MAX_RETENTION_MS));
    if let Some(obj) = message.as_object_mut() {
        obj.insert("state".into(), Value::String("stored".into()));
    }
    let header = StoredHeader {
        msg_id: h.msg_id.clone(),
        kind: h.kind.as_str().to_owned(),
        from_user: who.user.clone(),
        from_address: from_raw,
        to_user: h.to.user.clone(),
        to_address: to_raw,
        expires_ms,
        env_state: envelope_server::INITIAL.as_str().to_owned(),
        sender_view: request_sender_view::State::Stored.as_str().to_owned(),
        abort_reason: None,
    };
    let text = message.to_string();
    // 거두기는 원 메시지의 수신 기기 전부(그룹이면 여러 사람 — 그 뒤 들어온 멤버는 아님), 그룹 맥락은 멤버 기기가 후보.
    let pool = match &withdraw_targets {
        Some(Some(orig)) => Some(orig.as_slice()),
        _ => pool.as_deref(),
    };
    let targets = match app.db.store_envelope(
        &header,
        &text,
        &h.blobs,
        pool,
        h.group.as_ref().and_then(Address::gid),
    ) {
        Ok(t) => t,
        // 첨부(묶음 15): 남의 것·이미 묶임·안 올림·없음 — 모두 같은 사유.
        Err(crate::db::DbError::BlobUnavailable) => {
            return nack(&h.msg_id, NackReason::BlobUnavailable)
        }
        // 거둔 메시지의 수신 기기가 그 뒤 모두 폐기됨 — 지울 기기가 없다.
        Err(crate::db::DbError::NoTargets) if withdraw_targets.is_some() => {
            return ServerFrame::Ack {
                msg_id: h.msg_id,
                group_seq: None,
            }
        }
        Err(crate::db::DbError::Conflict) => return unroutable_nack(&h.msg_id),
        // 그룹 맥락인데 멤버 기기가 모두 폐기됨 — 옛 6a 와 같은 답(프로토콜 그대로).
        Err(crate::db::DbError::NoTargets) => return nack(&h.msg_id, NackReason::StaleDevices),
        Err(_) => return internal_error(),
    };
    // 실시간 deliver 는 전달 대상 기기의 연결에만(protocol §7.2-6) — 그룹이면 여러 사람의 기기.
    app.conns.send_any_devices(
        &targets,
        &ServerFrame::Deliver {
            message,
            group_seq: None,
        },
    );
    ServerFrame::Ack {
        msg_id: h.msg_id,
        group_seq: None,
    }
}

/// 이 판부터의 글은 판 9 기기에 전하지 않는다(#598 ② — 메시지 v 는 쓰는 칸의 판, 판 10 칸은 no_reply).
pub(crate) const OUTDATED_FROM: u64 = 10;

/// #598 ② recipient_outdated(#626 에서 일반화): 받을 기기를 (전할 기기, 글 판보다 낮은 hello.v 라 뺄 기기)로 가른다. 마지막으로
/// 붙은 hello.v 를 모르는 기기는 `PROTOCOL_MIN` 으로 본다. 그 판 이하 글은 그대로.
pub(crate) fn split_outdated<T: Clone>(
    app: &Relay,
    h: &Header,
    targets: Vec<T>,
    device: impl Fn(&T) -> &str,
) -> (Vec<T>, Vec<String>) {
    if h.v <= u64::from(lodelai_protocol::PROTOCOL_MIN) || targets.is_empty() {
        return (targets, Vec::new());
    }
    let ids: Vec<String> = targets.iter().map(|t| device(t).to_owned()).collect();
    let vs = app.db.device_hello_v(&ids).unwrap_or_default();
    let (keep, old): (Vec<T>, Vec<T>) = targets
        .into_iter()
        .partition(|t| vs.get(device(t)).is_some_and(|v| *v >= h.v));
    (keep, old.iter().map(|t| device(t).to_owned()).collect())
}

/// 옛 판 기기를 뺐으면 표시해 둔다(보낸 기기에는 ack 뒤에 [`outdated_notices`] 가 알린다).
pub(crate) fn mark_outdated(
    app: &Relay,
    who: &Authed,
    h: &Header,
    old: &[String],
    expires_ms: i64,
) {
    // 반응(#626)이 옛 판에 안 보이는 것은 실패가 아니라 그 판이 모르는 기능 — 보낸 쪽에 알리지 않는다.
    if old.is_empty() || h.kind == Kind::Reaction {
        return;
    }
    tracing::info!(msg_id = %h.msg_id, n = old.len(), "판 9 기기에 전하지 않음(recipient_outdated)");
    if let Err(e) = app
        .db
        .outdated_mark(&h.msg_id, &who.user, &who.device_id, old, expires_ms)
    {
        tracing::warn!(msg_id = %h.msg_id, error = %e, "recipient_outdated 표시 실패");
    }
}

/// 그 보낸 기기에 아직 알리지 않은 recipient_outdated — `status{failed, recipient_outdated}` 프레임들. 연결 루프가 send 의 답
/// 뒤와 접속 때 보낸다(ack 보다 먼저 가지 않게, 끊겨도 다음 접속에).
pub fn outdated_notices(app: &Relay, who: &Authed) -> Vec<ServerFrame> {
    let ids = app
        .db
        .outdated_take_notices(&who.device_id)
        .unwrap_or_default();
    if ids.is_empty() {
        return Vec::new();
    }
    let at = app.effects.clock.now().to_rfc3339().unwrap_or_default();
    ids.into_iter()
        .map(|msg_id| ServerFrame::Status {
            msg_id,
            state: "failed".into(),
            abort_reason: None,
            fail_reason: Some("recipient_outdated".into()),
            at: at.clone(),
            by: None,
        })
        .collect()
}

/// recipient_outdated 뒤 같은 msg_id 의 v9 다시 보내기 — 표시된 판 9 기기(폐기 안 됨)에만 전한다. 원래 봉투(판 10 기기 몫)는
/// 그대로라 그 기기들에는 다시 가지 않는다. 같은 보낸 사람·msg_id 만 여기로 온다(호출자가 봄).
fn outdated_resend(app: &Relay, who: &Authed, h: &Header, mut message: Value) -> ServerFrame {
    if let Some(obj) = message.as_object_mut() {
        obj.insert("state".into(), Value::String("stored".into()));
    }
    let group_seq = app.db.group_seq_of(&h.msg_id).ok().flatten();
    let devices = match app
        .db
        .outdated_fill(&h.msg_id, &who.user, &message.to_string(), group_seq)
    {
        Ok(d) => d,
        Err(_) => return internal_error(),
    };
    tracing::info!(msg_id = %h.msg_id, n = devices.len(), "판 9 기기 몫 다시 받음(recipient_outdated)");
    app.conns
        .send_any_devices(&devices, &ServerFrame::Deliver { message, group_seq });
    ServerFrame::Ack {
        msg_id: h.msg_id.clone(),
        group_seq,
    }
}

/// 0.2.6 #809 §1-3: 다시 보낸 본문을 보고한 기기(그 대화의 지금 잎) 몫으로 두고 붙어 있으면 바로 전한다.
fn unreadable_resend(app: &Relay, from_user: &str, h: &Header, mut message: Value) -> ServerFrame {
    let Some(group) = h.mls.as_ref().map(|m| m.group.clone()) else {
        return internal_error();
    };
    if let Some(obj) = message.as_object_mut() {
        obj.insert("state".into(), Value::String("stored".into()));
    }
    let group_seq = app.db.group_seq_of(&h.msg_id).ok().flatten();
    let devices = match app.db.unreadable_fill(
        &h.msg_id,
        from_user,
        &group,
        &message.to_string(),
        group_seq,
    ) {
        Ok(d) => d,
        Err(_) => return internal_error(),
    };
    tracing::info!(msg_id = %h.msg_id, n = devices.len(), "못 연 기기 몫 다시 받음(recipient_unreadable)");
    app.conns
        .send_any_devices(&devices, &ServerFrame::Deliver { message, group_seq });
    ServerFrame::Ack {
        msg_id: h.msg_id.clone(),
        group_seq,
    }
}

/// 거두기·고치기가 가리킨 원 메시지에 `envelope_server` 의 `withdraw` 를 적용한다. 돌려주는 값: 원래 수신 기기
/// (`None` = 대상 행이 없는 옛 봉투 — 받는 사용자의 기기 전부). 이미 만료된 봉투는 route() 에서 걸러진다.
/// MLS 응용 메시지(묶음 22 §12-18)의 거두기·고치기: 첨부를 묶을 수 있는지 먼저 보고(묶음 15 리뷰 ⑥), 원 메시지의 아직 받지
/// 않은 몫을 지운다. 받을 기기는 MLS 잎 그대로(원래 수신 기기로 좁히지 않음). 보낸 사람 = 원 발신자는 route() 가 본다.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
pub(crate) fn mls_withdraw(app: &Relay, who: &Authed, h: &Header) -> Result<(), ServerFrame> {
    let original = if is_withdraw(h) {
        h.reply_to.as_deref()
    } else {
        h.edits.as_deref()
    };
    let Some(x) = original else {
        return Ok(());
    };
    if !h.blobs.is_empty() {
        match app.db.blobs_bindable(&who.user, &h.blobs) {
            Ok(true) => {}
            Ok(false) => return Err(nack(&h.msg_id, NackReason::BlobUnavailable)),
            Err(_) => return Err(internal_error()),
        }
    }
    withdraw_original(app, x)
        .map(|_| ())
        .map_err(|()| internal_error())
}

fn withdraw_original(app: &Relay, msg_id: &str) -> Result<Option<Vec<String>>, ()> {
    let Ok(Some(h)) = app.db.header(msg_id) else {
        return Err(());
    };
    let Some(env) = envelope_server::State::from_name(&h.env_state) else {
        tracing::warn!(msg_id, env = %h.env_state, "모르는 봉투 상태 — 거두기 무시");
        return Ok(None);
    };
    let drop = matches!(
        envelope_server::step(env, envelope_server::Event::Withdraw, &envelope_server::Guards::default()),
        Ok(Step::Transition { actions, .. }) if actions.contains(&envelope_server::Action::DropUnackedDevices)
    );
    if !drop {
        return Ok(None);
    }
    // 묶인 첨부는 받음 여부와 상관없이 바로 지운다(ADR 0009 §11).
    match app.db.take_blobs_of(msg_id) {
        Ok(ids) => crate::blob::remove_files(app, &ids),
        Err(e) => tracing::warn!(msg_id, error = %e, "거둔 메시지 첨부 지우기 실패"),
    }
    app.db.withdraw_envelope(msg_id).map_err(|e| {
        tracing::warn!(msg_id, error = %e, "거두기 실패");
    })
}

/// CAS 재시도 상한. 같은 msg_id 에 동시에 오는 갱신은 많아야 기기 수만큼이다.
const CAS_ATTEMPTS: usize = 8;

/// 헤더를 읽고 `compute` 로 새 (봉투 상태, 발신자 뷰, abort_reason) 를 정해 **조건부로** 쓴다.
/// 읽은 뒤 다른 갱신이 끼어들면 다시 읽고 다시 계산한다(#110). 바꿀 것이 없으면(`None`) 쓰지 않는다.
/// 돌려주는 값: 실제로 쓴 경우 (읽은 헤더, 새 봉투 상태, 새 발신자 뷰).
///
/// 저장된 상태 이름을 모르면 초기 상태로 되돌리지 않고 무시하고 기록한다(fail-closed).
fn transition<F>(
    app: &Relay,
    msg_id: &str,
    compute: F,
) -> Option<(
    StoredHeader,
    envelope_server::State,
    request_sender_view::State,
)>
where
    F: Fn(
        &StoredHeader,
        envelope_server::State,
        request_sender_view::State,
    ) -> Option<(
        envelope_server::State,
        request_sender_view::State,
        Option<String>,
    )>,
{
    for _ in 0..CAS_ATTEMPTS {
        let h = match app.db.header(msg_id) {
            Ok(Some(h)) => h,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(msg_id, error = %e, "헤더 읽기 실패");
                return None;
            }
        };
        let (Some(env), Some(view)) = (
            envelope_server::State::from_name(&h.env_state),
            request_sender_view::State::from_name(&h.sender_view),
        ) else {
            tracing::warn!(msg_id, env = %h.env_state, view = %h.sender_view, "모르는 저장 상태 — 무시");
            return None;
        };
        let (new_env, new_view, abort) = compute(&h, env, view)?;
        if new_env == env && new_view == view && abort == h.abort_reason {
            return None;
        }
        match app
            .db
            .update_states_if(&h, new_env.as_str(), new_view.as_str(), abort.as_deref())
        {
            Ok(true) => return Some((h, new_env, new_view)),
            Ok(false) => {} // 경합: 다시 읽는다
            Err(e) => {
                tracing::warn!(msg_id, error = %e, "상태 갱신 실패");
                return None;
            }
        }
    }
    tracing::warn!(msg_id, "상태 갱신 경합이 계속됨 — 포기");
    None
}

/// `request_sender_view::step` 이 전이를 주면 그 상태, 아니면(무시·가드 오류) `None`.
fn view_step(
    view: request_sender_view::State,
    event: request_sender_view::Event,
) -> Option<request_sender_view::State> {
    match request_sender_view::step(view, event, &request_sender_view::Guards::default()) {
        Ok(Step::Transition { to, .. }) => Some(to),
        Ok(Step::Ignored) => None,
        Err(e) => {
            tracing::warn!(error = %e, "request_sender_view step 오류");
            None
        }
    }
}

/// 0.2.6 #809: 기기마다 시간당 받는 못 엶 보고 수. 넘으면 보통 ack 로 다룬다(계약 §1-2 남용 상한).
pub const UNREADABLE_PER_HOUR: i64 = 100;
/// 0.2.6 #809 §1-9 (나): 보고 뒤 이만큼 지나야 알린다 — 못 엶 ack 직후 스스로 다시 들기를 시작하는 사이를 덮는다.
pub const UNREADABLE_SETTLE_MS: i64 = 30 * 1000;
/// `recipient_unreadable*` status 를 받는 연결의 가장 낮은 hello.v(판 14).
pub const UNREADABLE_FROM_V: u64 = 14;

/// `delivered_ack`: 수신자 기기만. 그 기기를 받음으로 표시하고(`mark_device_acked`) 대상이 모두 받았으면 본문을
/// 지운다(`drop_body_when_all_acked`, protocol §7.2-6). 첫 ack 만 `stored → device_received` 와 발신자 `status received`.
///
/// `unreadable`(0.2.6 #809): 그 기기가 열지 못했다 — 받은 것으로 적되 발신자 `received` 는 보내지 않고 보고 표에 둔다(알리기는
/// [`notify_unreadable`] 가 때를 보고). 받아들이지 않는 보고(만료·상한·셀 것 없음)는 보통 ack 로, 대상 아닌 기기 것은 무시한다.
pub fn handle_delivered_ack(app: &Relay, who: &Authed, msg_id: &str, unreadable: bool) {
    let now_ms = app.effects.clock.now().0;
    // #809 §1-3: 못 엶 보고 뒤 다시 보낸 글(곁 배달)을 받았다 — 곁 배달만 멈추고, ack 자체는 아래 본 처리로 흐른다.
    let _ = app.db.unreadable_side_acked(msg_id, &who.device_id, now_ms);
    // #598 ②: 판 9 라 따로 받은 다시 보내기 — 그 몫만 기록한다(원래 봉투의 상태는 판 10 기기 ack 가 움직인다).
    if app
        .db
        .outdated_ack(msg_id, &who.device_id, app.effects.clock.now().0)
        .unwrap_or(false)
    {
        return;
    }
    let Ok(Some(h)) = app.db.header(msg_id) else {
        return;
    };
    // 그룹(묶음 16)은 여러 사용자의 기기가 받는다 — 받는 사용자가 아니어도 그 기기의 대상 행이 있으면 된다.
    let addressee = h.to_user == who.user;
    if !addressee
        && !app
            .db
            .is_target_device(msg_id, &who.device_id)
            .unwrap_or(false)
    {
        return;
    }
    // #809: 못 엶 보고. Handshake 는 보고 대상이 아니다(열지 못한 Commit 은 다시 들기 길).
    let reported = if unreadable && h.kind != "mls" {
        match app
            .db
            .unreadable_report(msg_id, &who.device_id, now_ms, UNREADABLE_PER_HOUR)
        {
            Ok(crate::db::UnreadableReport::Recorded) => true,
            Ok(crate::db::UnreadableReport::NotTarget) => return,
            Ok(crate::db::UnreadableReport::Limited) => {
                tracing::warn!(device = %who.device_id, "못 엶 보고 시간당 상한 — 보통 ack 로");
                false
            }
            Ok(crate::db::UnreadableReport::Plain) => false,
            Err(e) => {
                tracing::warn!(msg_id, error = %e, "못 엶 보고 기록 실패");
                false
            }
        }
    } else {
        if !unreadable {
            // 열었다 — 같은 사람의 보고가 있으면 final 을 내지 않는다.
            let _ = app.db.unreadable_opened(msg_id, &who.device_id, now_ms);
        }
        false
    };
    // 발신자 received 는 받는 사람(그룹이면 아무 멤버) 기기의 첫 ack 로. 그룹 안 request 의 다른 멤버는 본문 정리만.
    // Handshake(kind mls, 묶음 22)는 보낸 사람 화면에 상태가 없다 — status 를 보내지 않는다(#519: 보낸 쪽이 그 received 를
    // 다른 메시지 것으로 셈). 못 엶 보고는 received 가 아니다(#809).
    let moves_view = (addressee || h.to_user.starts_with('+')) && h.kind != "mls" && !reported;
    let Some(env) = envelope_server::State::from_name(&h.env_state) else {
        tracing::warn!(msg_id, env = %h.env_state, "모르는 봉투 상태 — ack 무시");
        return;
    };
    let actions = match envelope_server::step(
        env,
        envelope_server::Event::DeviceAck,
        &envelope_server::Guards::default(),
    ) {
        Ok(Step::Transition { actions, .. }) => actions,
        _ => return,
    };
    let mut drop_body = false;
    for a in actions.iter() {
        match a {
            envelope_server::Action::MarkDeviceAcked => {
                let now = app.effects.clock.now();
                match app.db.ack_device(msg_id, &who.device_id, now.0) {
                    Ok(Some(all)) => drop_body = all,
                    // 대상이 아닌 기기: 전이·발신자 received·본문 삭제 모두 없다.
                    Ok(None) => return,
                    Err(e) => tracing::warn!(msg_id, error = %e, "기기 ack 기록 실패"),
                }
            }
            envelope_server::Action::DropBodyWhenAllAcked if drop_body => {
                if let Err(e) = app.db.drop_body(msg_id) {
                    tracing::warn!(msg_id, error = %e, "본문 삭제 실패");
                }
            }
            _ => {}
        }
    }
    if !moves_view {
        return;
    }
    let applied = transition(app, msg_id, |h, env, view| {
        if h.to_user != who.user && !h.to_user.starts_with('+') {
            return None;
        }
        let new_env = match envelope_server::step(
            env,
            envelope_server::Event::DeviceAck,
            &envelope_server::Guards::default(),
        ) {
            Ok(Step::Transition { to, .. }) if to != env => to,
            _ => return None, // 이미 받음: log_ignored
        };
        let new_view =
            view_step(view, request_sender_view::Event::ServerDeviceReceived).unwrap_or(view);
        Some((new_env, new_view, h.abort_reason.clone()))
    });
    let Some((h, _, new_view)) = applied else {
        return;
    };
    if new_view.as_str() != h.sender_view {
        let at = app.effects.clock.now().to_rfc3339().unwrap_or_default();
        app.conns.send_user(
            &h.from_user,
            &ServerFrame::Status {
                msg_id: msg_id.to_owned(),
                state: new_view.as_str().to_owned(),
                abort_reason: None,
                fail_reason: None,
                at,
                by: None,
            },
        );
    }
}

/// 0.2.6 #809 §1-2: 알릴 때가 된 못 엶 보고마다 보낸 사람의 판 14 이상 연결에 `status{failed, recipient_unreadable(_final),
/// by}`. 보낸 사람이 꺼져 있거나 옛 앱만 붙어 있으면 남겨 두고 다음(tick·접속)에 다시 본다. final 인데 그 사람의 다른 기기가
/// 열었으면 보내지 않고 닫는다.
pub fn notify_unreadable(app: &Relay) {
    let now = app.effects.clock.now();
    let Ok(due) = app.db.unreadable_due(now.0, UNREADABLE_SETTLE_MS) else {
        return;
    };
    let at = now.to_rfc3339().unwrap_or_default();
    for d in due {
        if d.final_ && d.opened {
            let _ = app.db.unreadable_notified(&d.msg_id, &d.device_id, false);
            continue;
        }
        let online = app.conns.online_devices(&d.from_user);
        let vs = app.db.device_hello_v(&online).unwrap_or_default();
        let devices: Vec<String> = online
            .into_iter()
            .filter(|x| vs.get(x).is_some_and(|v| *v >= UNREADABLE_FROM_V))
            .collect();
        if devices.is_empty() {
            continue;
        }
        let reason = if d.final_ {
            "recipient_unreadable_final"
        } else {
            "recipient_unreadable"
        };
        app.conns.send_devices(
            &d.from_user,
            &devices,
            &ServerFrame::Status {
                msg_id: d.msg_id.clone(),
                state: "failed".into(),
                abort_reason: None,
                fail_reason: Some(reason.into()),
                at: at.clone(),
                by: Some(format!("{}@{}", d.to_user, app.config.server_name)),
            },
        );
        tracing::info!(msg_id = %d.msg_id, device = %d.device_id, reason, "못 엶 보고 알림");
        let _ = app.db.unreadable_notified(&d.msg_id, &d.device_id, true);
    }
}

/// `status`: 메시지의 발신·수신 당사자만(S-FORGE-9). 수신자가 보낸 것은 rank 규칙으로 발신자 뷰에 반영하고,
/// 어느 쪽이든 상대 당사자에게 그대로 중계한다(상대가 오프라인이면 버린다 — M1).
///
/// 거부는 `None` 이 아니라 같은 `error protocol` 하나 — 헤더가 없을 때와 당사자가 아닐 때가 구분되지 않는다.
pub fn handle_status(
    app: &Relay,
    who: &Authed,
    msg_id: &str,
    state: &str,
    abort_reason: Option<&str>,
    fail_reason: Option<&str>,
    at: &str,
) -> Option<ServerFrame> {
    let refused = || Some(protocol_error("status 거부"));
    let Ok(Some(h)) = app.db.header(msg_id) else {
        return refused();
    };
    let is_sender = h.from_user == who.user;
    // 그룹 주소로 간 메시지(묶음 16)는 그 기기가 수신 기기면 받는 쪽 — 상태는 보낸 사람에게만 간다(chat 경로).
    let is_recipient = h.to_user == who.user
        || (h.to_user.starts_with('+')
            && app
                .db
                .is_target_device(msg_id, &who.device_id)
                .unwrap_or(false));
    if !is_sender && !is_recipient {
        return refused();
    }
    // 그룹 글이면 누가 보냈는지를 relay 가 인증한 사용자로 싣는다(묶음 16 §4). 1:1·내 다른 기기면 없음.
    let by = (h.to_user.starts_with('+') && !is_sender)
        .then(|| format!("{}@{}", who.user, app.config.server_name));
    // 허용은 보관한 헤더의 kind 로 가른다(protocol §7.2-7, #308). chat 은 수신자의 read·acknowledged(묶음 14 B3) 만 — 서버 뷰는 바꾸지 않고
    // 발신자에게 중계만 한다(오프라인이면 버린다). reply·rejected·system 에는 status 가 없다(읽음은 chat 만, §5.3).
    match h.kind.as_str() {
        "request" => {}
        "chat" => {
            if !is_recipient
                || !matches!(state, "read" | "acknowledged")
                || abort_reason.is_some()
                || fail_reason.is_some()
                || UnixMillis::parse_rfc3339(at).is_err()
            {
                return refused();
            }
            app.conns.send_user(
                &h.from_user,
                &ServerFrame::Status {
                    msg_id: msg_id.to_owned(),
                    state: state.to_owned(),
                    abort_reason: None,
                    fail_reason: None,
                    at: at.to_owned(),
                    by,
                },
            );
            return None;
        }
        _ => return refused(),
    }
    let Some(new_state) = request_sender_view::State::from_name(state) else {
        return refused();
    };
    let abort = match abort_reason {
        Some(a) => match AbortReason::from_name(a) {
            Some(r) => Some(r),
            None => return refused(),
        },
        None => None,
    };
    if UnixMillis::parse_rfc3339(at).is_err() {
        return refused();
    }

    if is_recipient {
        if let Some(event) =
            request_sender_view::Event::from_name(&format!("status_{}", new_state.as_str()))
        {
            transition(app, msg_id, |h, env, view| {
                let wants_update = matches!(
                    envelope_server::step(env, envelope_server::Event::StatusFrame, &envelope_server::Guards::default()),
                    Ok(Step::Transition { actions, .. }) if actions.contains(&envelope_server::Action::UpdateSenderViewStateByRank)
                );
                if !wants_update {
                    return None;
                }
                let to = view_step(view, event)?;
                let reason = if to == request_sender_view::State::Aborted {
                    abort.map(|a| a.as_str().to_owned())
                } else {
                    h.abort_reason.clone()
                };
                Some((env, to, reason))
            });
        }
    }

    // abort_reason 은 aborted 일 때만, fail_reason 은 failed 일 때만 붙인다(#134).
    let abort = abort.filter(|_| new_state == request_sender_view::State::Aborted);
    let fail = fail_reason.filter(|_| new_state == request_sender_view::State::Failed);
    let other = if is_sender { &h.to_user } else { &h.from_user };
    app.conns.send_user(
        other,
        &ServerFrame::Status {
            msg_id: msg_id.to_owned(),
            state: new_state.as_str().to_owned(),
            abort_reason: abort.map(|a| a.as_str().to_owned()),
            fail_reason: fail.map(str::to_owned),
            at: at.to_owned(),
            by,
        },
    );
    None
}

/// 만료 스캔(`clock_expired`): 헤더 삭제 + 발신자 뷰가 종료가 아니면 `status expired` 통지. 처리한 수를 돌려준다.
pub fn expire_tick(app: &Relay) -> usize {
    let now = app.effects.clock.now();
    // Handshake 는 7일 작업 밖(§5a — 30일·rejoin_needed).
    let mut n = crate::mls::expire_handshakes(app);
    // §7: 다른 길(관리자 내보내기·나가기 등)로 생긴 일도 30초 안에 나눠 준다.
    // 묶음 22 §4-7: 60초 창·1시간 — 확정·무효.
    crate::mls_group::tick(app);
    crate::mls::dispatch_duties(app, None);
    // #819: 멈췄던 일이 끝났으면 관리자에게 done.
    crate::mls_group::duty_stuck_sweep(app);
    // g025f A: 할 기기가 접속해 있지 않은 add_device 는 새 기기가 스스로 들게.
    crate::mls::rejoin_unserved_adds(app);
    let _ = app.db.outdated_sweep(now.0);
    let Ok(expired) = app.db.expired(now.0) else {
        return n;
    };
    for h in expired {
        // 보관 기한이 지났으면 상태와 무관하게 지운다. 저장 상태를 모르면 통지 없이 지우고 기록한다.
        let Some(env) = envelope_server::State::from_name(&h.env_state) else {
            tracing::warn!(msg_id = %h.msg_id, env = %h.env_state, "모르는 봉투 상태 — 통지 없이 만료 삭제");
            let _ = app.db.delete_envelope(&h.msg_id);
            n += 1;
            continue;
        };
        let Ok(Step::Transition { actions, .. }) = envelope_server::step(
            env,
            envelope_server::Event::ClockExpired,
            &envelope_server::Guards::default(),
        ) else {
            continue;
        };
        // 발신자 뷰를 모르면 종료 상태로 보고 통지하지 않는다.
        let view_open =
            request_sender_view::State::from_name(&h.sender_view).is_some_and(|v| !v.is_terminal());
        for a in actions {
            match a {
                envelope_server::Action::DeleteHeader => {
                    let _ = app.db.delete_envelope(&h.msg_id);
                }
                envelope_server::Action::NotifySenderStatusExpired if view_open => {
                    app.conns.send_user(
                        &h.from_user,
                        &ServerFrame::Status {
                            msg_id: h.msg_id.clone(),
                            state: request_sender_view::State::Expired.as_str().to_owned(),
                            abort_reason: None,
                            fail_reason: None,
                            at: now.to_rfc3339().unwrap_or_default(),
                            by: None,
                        },
                    );
                }
                _ => {}
            }
        }
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unroutable_has_only_reason() {
        assert_eq!(
            unroutable_nack("01JB0000000000000000000001").to_json(),
            r#"{"msg_id":"01JB0000000000000000000001","reason":"unroutable","t":"nack"}"#
        );
    }

    #[test]
    fn reply_accept_rule_matches_yaml() {
        // yaml envelope_server.reply_accept_rule 와 같은지 문자열로 고정한다(yaml 이 바뀌면 여기도 바뀌어야 한다).
        let yaml = include_str!("../../../crates/statechart/machines/wire.yaml");
        assert!(yaml
            .contains("accept_when_sender_view_in: [pending, accepted, consumed, replied, done]"));
        assert!(yaml.contains("accept_when_aborted_reason_in: [turn_ended, needs_task]"));

        let mk = |view: &str, reason: Option<&str>| StoredHeader {
            msg_id: String::new(),
            kind: "request".into(),
            from_user: String::new(),
            from_address: String::new(),
            to_user: String::new(),
            to_address: String::new(),
            expires_ms: 0,
            env_state: "stored".into(),
            sender_view: view.into(),
            abort_reason: reason.map(str::to_owned),
        };
        for v in ["pending", "accepted", "consumed", "replied"] {
            assert!(reply_accepted(&mk(v, None)), "{v}");
        }
        for v in [
            "sent", "stored", "received", "failed", "rejected", "expired",
        ] {
            assert!(!reply_accepted(&mk(v, None)), "{v}");
        }
        assert!(reply_accepted(&mk("aborted", Some("turn_ended"))));
        assert!(reply_accepted(&mk("aborted", Some("needs_task"))));
        for r in [
            "owner_aborted",
            "session_exited",
            "mode_escalated",
            "draft_discarded",
        ] {
            assert!(!reply_accepted(&mk("aborted", Some(r))), "{r}");
        }
    }

    fn app_with_request(view: &str) -> (crate::App, String) {
        let fx = lodelai_testkit::effects::TestEffects::new(1_792_728_776_000, 1);
        let effects = crate::Effects {
            clock: fx.clock.clone(),
            ids: fx.ids.clone(),
            rng: fx.rng.clone(),
        };
        let app = crate::Relay::new(
            crate::Config::local("local"),
            effects,
            crate::db::Db::memory().unwrap(),
        );
        let msg_id = "01JB0000000000000000000001".to_owned();
        let h = StoredHeader {
            msg_id: msg_id.clone(),
            kind: "request".into(),
            from_user: "alice".into(),
            from_address: "alice@local".into(),
            to_user: "bob".into(),
            to_address: "bob@local/be".into(),
            expires_ms: i64::MAX,
            env_state: "stored".into(),
            sender_view: view.into(),
            abort_reason: None,
        };
        app.db.store_envelope(&h, "{}", &[], None, None).unwrap();
        (app, msg_id)
    }

    #[test]
    fn interleaved_update_cannot_roll_rank_back() {
        // #110: consumed 를 계산하는 사이에 replied 가 먼저 쓰이면, consumed 는 다시 읽고 rank 규칙으로 무시돼야 한다.
        let (app, id) = app_with_request("accepted");
        let calls = std::cell::Cell::new(0);
        let applied = transition(&app, &id, |h, env, view| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                // 다른 연결의 replied 가 끼어든다
                assert!(app
                    .db
                    .update_states_if(h, &h.env_state, "replied", None)
                    .unwrap());
            }
            let to = view_step(view, request_sender_view::Event::StatusConsumed)?;
            Some((env, to, None))
        });
        assert!(
            applied.is_none(),
            "consumed 는 replied 위에 적용되지 않는다"
        );
        assert_eq!(calls.get(), 2, "경합 뒤 다시 읽어 다시 계산했다");
        assert_eq!(app.db.header(&id).unwrap().unwrap().sender_view, "replied");
    }

    #[test]
    fn stale_cas_returns_false() {
        let (app, id) = app_with_request("accepted");
        let stale = app.db.header(&id).unwrap().unwrap();
        assert!(app
            .db
            .update_states_if(&stale, "stored", "consumed", None)
            .unwrap());
        assert!(
            !app.db
                .update_states_if(&stale, "stored", "pending", None)
                .unwrap(),
            "읽은 뒤 바뀌었으면 0행"
        );
        assert_eq!(app.db.header(&id).unwrap().unwrap().sender_view, "consumed");
    }

    #[test]
    fn unknown_stored_state_is_ignored_not_reset() {
        let (app, id) = app_with_request("bogus_state");
        let applied = transition(&app, &id, |_, env, view| {
            Some((
                env,
                view_step(view, request_sender_view::Event::StatusReplied)?,
                None,
            ))
        });
        assert!(applied.is_none());
        assert_eq!(
            app.db.header(&id).unwrap().unwrap().sender_view,
            "bogus_state",
            "초기 상태로 되돌리지 않는다"
        );
    }
}
