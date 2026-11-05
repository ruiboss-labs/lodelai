//! 메일 확인 끊기(#577, 계약 6490433889 v4.2 §4): 잎 자격 없는(pending) 새 기기가 먼저 등록된 내 기기를 `recovery_wait`
//! 뒤 끊도록 건다. 대상 기기는 막을 수 있고(막기 카드), 요청 기기가 잎 자격을 얻으면(certify·폐기) 걸기는 끝난다.
//!
//! 모두 동기(`blocking` 안에서 부른다). 프레임은 `serde_json::json!` → `ws::Frame` → `ServerFrame::Ws`, 메일은 따로 스레드.

use lodelai_effects::UnixMillis;
use lodelai_protocol::ws;

use crate::db::{RecoveryRow, RecoveryState};
use crate::frames::{DirectoryRecoveryBlocker, DirectoryRecoveryView, ServerFrame};
use crate::rules::Authed;
use crate::ws::broadcast_directory_of;
use crate::Relay;

/// 막기 몇 번이면 `exhausted` 인가(계약 §4 — 30일에 3번).
const BLOCKS_MAX: usize = 3;

fn ms(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn ts(at_ms: i64) -> String {
    UnixMillis(at_ms).to_rfc3339().unwrap_or_default()
}

/// 스키마에 맞는 S→C 프레임. 형식이 틀리면(코드 잘못) `None` — 보내지 않는다.
fn frame(v: serde_json::Value) -> Option<ServerFrame> {
    match serde_json::from_value::<ws::Frame>(v) {
        Ok(f) => Some(ServerFrame::Ws(Box::new(f))),
        Err(e) => {
            tracing::error!(error = %e, "recovery 프레임 형식");
            None
        }
    }
}

fn send(app: &Relay, user: &str, devices: &[String], v: serde_json::Value) {
    if let Some(f) = frame(v) {
        app.conns.send_devices(user, devices, &f);
    }
}

/// `error{recover_refused, reason, until?}` — 연결은 그대로.
fn refused(reason: &str, until_ms: Option<i64>) -> Option<ServerFrame> {
    let mut v = serde_json::json!({
        "t": "error", "code": "recover_refused", "reason": reason, "message": "device.recover",
    });
    if let Some(u) = until_ms {
        v["until"] = serde_json::Value::String(ts(u));
    }
    frame(v)
}

/// 막기 30일 상한이 풀리는 시각(지금 상한 안이면 `None`).
fn exhausted_until(app: &Relay, user: &str, now: i64) -> Option<i64> {
    let window = ms(app.config.recovery_block_window);
    let blocks = app
        .db
        .recovery_blocks_since(user, now - window)
        .unwrap_or_default();
    (blocks.len() >= BLOCKS_MAX).then(|| blocks[blocks.len() - BLOCKS_MAX] + window)
}

/// 막힘·취소 뒤 다시 걸 수 있는 시각(쿨다운 안이면).
fn cooldown_until(app: &Relay, row: &RecoveryRow, now: i64) -> Option<i64> {
    if !matches!(row.state, RecoveryState::Blocked | RecoveryState::Canceled) {
        return None;
    }
    let end = row.ended_ms? + ms(app.config.recovery_cooldown);
    (end > now).then_some(end)
}

/// 다시 걸 수 있는 시각 — 쿨다운 끝과 30일 상한이 풀리는 시각 중 늦은 것.
fn retry_at(app: &Relay, user: &str, row: &RecoveryRow, now: i64) -> Option<i64> {
    let c = cooldown_until(app, row, now);
    let x = exhausted_until(app, user, now);
    c.max(x)
}

fn email_of(app: &Relay, user: &str) -> Option<String> {
    app.db.user_meta(user).ok().and_then(|(e, _)| e)
}

/// 계정 메일(텍스트만, 링크 없음). 문구 확정은 디자인 몫 — 화면·메일 모두 '끊기'.
fn mail(app: &Relay, user: &str, kind: &str, at_ms: i64) {
    let (Some(mailer), Some(email)) = (app.mailer.clone(), email_of(app, user)) else {
        return;
    };
    let at = ts(at_ms);
    let (subject, text) = match kind {
        "scheduled" => (
            "lodelai: 예전 기기를 끊으려는 요청이 있어요",
            format!(
                "새 기기에서 메일 확인으로 예전 기기를 끊으려 해요. {at} 에 예전 기기가 계정에서 끊겨요.\n\
                 내가 한 일이 아니면 예전 기기에서 '막기'를 누르세요.\n\n\
                 A new device asked to disconnect your earlier devices by email verification. They will be \
                 disconnected at {at}. If this wasn't you, press 'Block' on an earlier device."
            ),
        ),
        "blocked" => (
            "lodelai: 예전 기기에서 끊기를 막았어요",
            format!(
                "예전 기기에서 끊기를 막았어요({at}). 기기 바꾸기가 멈췄어요.\n\n\
                 An earlier device blocked the disconnect ({at}). The device change has stopped."
            ),
        ),
        "canceled" => (
            "lodelai: 예전 기기 끊기를 취소했어요",
            format!(
                "새 기기에서 예전 기기 끊기를 취소했어요({at}).\n\n\
                 The new device canceled disconnecting your earlier devices ({at})."
            ),
        ),
        "admin_cut" => (
            "lodelai: 관리자가 예전 기기를 끊었어요",
            format!(
                "조직 관리자가 기기 바꾸기를 끝내려고 예전 기기를 계정에서 끊었어요({at}).\n\
                 내가 한 일이 아니면 메일 계정을 지키고 관리자에게 알리세요.\n\n\
                 Your organization admin disconnected your earlier device to finish the device change ({at}). \
                 If this wasn't you, secure your email account and tell your admin."
            ),
        ),
        _ => (
            "lodelai: 메일 확인으로 예전 기기를 끊었어요",
            format!(
                "메일 확인으로 예전 기기를 계정에서 끊었어요({at}).\n\
                 내가 한 일이 아니면 메일 계정을 지키고 동료·관리자에게 알리세요.\n\n\
                 Your earlier devices were disconnected by email verification ({at}). If this wasn't you, \
                 secure your email account and tell your teammates or admin."
            ),
        ),
    };
    let send = move || {
        if let Err(e) = mailer.send_text(&email, subject, &text) {
            tracing::warn!(error = %e, "recovery 알림 메일 실패");
        }
    };
    // #762: Resend 는 런타임 핸들로 요청을 끝까지 기다린다 — 런타임 밖 스레드(std::thread)면 'no reactor running' 으로
    // 모두 실패했다. 런타임의 막는 작업 스레드에서 보낸다(가입 코드 메일과 같은 길). 런타임 밖(동기 호출)이면 그 자리에서.
    match tokio::runtime::Handle::try_current() {
        Ok(rt) => {
            rt.spawn_blocking(send);
        }
        Err(_) => send(),
    }
}

/// #737 관리자가 걸기 대상 기기를 끊은 뒤: 그 사람 이메일로 알림(진짜 주인이 모르는 사이 끊기지 않게).
pub fn mail_admin_cut(app: &Relay, user: &str, at_ms: i64) {
    mail(app, user, "admin_cut", at_ms);
}

/// #737 관리자가 걸기 대상 기기를 끊은 직후(폐기 커밋 뒤, directory.update 앞): 대상이 모두 빠졌으면 걸기는 실행 완료(done)와
/// 같다 — 요청 기기에 `device.recovered`(계약 member.revoke_device 의 서버 순서). 요청 기기가 홀로 남아 잎 자격을 얻었어도
/// certified 로 끝내지 않는다: 옛 기기가 확인한 게 아니라 관리자가 끊었다(디렉터리에서 걸기가 그냥 사라지면 동료 코어가
/// '옛 기기에서 확인' 줄을 냈다). 메일·연결 닫기·디렉터리는 부르는 쪽이. 대상이 남으면 [`on_trust_change`] 그대로.
pub fn on_admin_cut(app: &Relay, user: &str, now: i64) {
    let row = app
        .db
        .recovery(user)
        .ok()
        .flatten()
        .filter(|r| r.state == RecoveryState::Scheduled);
    let live = live(app, user);
    let all_cut = row.as_ref().is_some_and(|r| {
        live.contains(&r.requester) && r.targets.iter().all(|t| !live.contains(t))
    });
    if !all_cut {
        on_trust_change(app, user);
        return;
    }
    let Ok(Some(row)) = app
        .db
        .recovery_end(user, Some(RecoveryState::Done), now, None)
    else {
        return;
    };
    tracing::info!(user = %user, "관리자가 대상을 다 끊어 메일 확인 끊기 끝");
    notify_device_changed(app);
    send(
        app,
        user,
        std::slice::from_ref(&row.requester),
        serde_json::json!({"t": "device.recovered", "at": ts(now), "targets": []}),
    );
}

/// 그 사용자의 요청 기기보다 먼저 등록된 폐기 안 된 기기.
fn older_devices(app: &Relay, user: &str, requester: &str) -> Vec<String> {
    app.db
        .older_live_devices(user, requester)
        .unwrap_or_default()
}

fn live(app: &Relay, user: &str) -> Vec<String> {
    app.db
        .devices_of(user)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.device_id)
        .collect()
}

// ---------------------------------------------------------------- C→S

/// `device.recover`.
pub fn start(app: &Relay, who: &Authed) -> Option<ServerFrame> {
    let now = app.effects.clock.now().0;
    let user = &who.user;
    if crate::mls::eligible_devices(app, user).contains(&who.device_id) {
        return refused("trusted", None);
    }
    let row = app.db.recovery(user).ok().flatten();
    if let Some(r) = row.as_ref().filter(|r| r.state == RecoveryState::Scheduled) {
        if r.requester != who.device_id {
            return Some(crate::rules::protocol_error("device.recover"));
        }
        // 같은 요청 기기의 재요청 — 멱등.
        return frame(serde_json::json!({
            "t": "device.recover_scheduled", "at": ts(r.at_ms), "targets": r.targets,
        }));
    }
    let targets = older_devices(app, user, &who.device_id);
    if targets.is_empty() {
        return refused("no_older", None);
    }
    if let Some(u) = exhausted_until(app, user, now) {
        return refused("exhausted", Some(u));
    }
    if let Some(u) = row.as_ref().and_then(|r| cooldown_until(app, r, now)) {
        return refused("cooldown", Some(u));
    }
    let at = now + ms(app.config.recovery_wait);
    if app
        .db
        .recovery_schedule(user, &who.device_id, now, at, &targets)
        .is_err()
    {
        return Some(crate::rules::internal_error());
    }
    tracing::info!(user = %user, device = %who.device_id, "메일 확인 끊기 걸림");
    // #737: 걸 때 이미 붙어 있는 옛 기기도 '붙음'이다(그 기기는 지금 막기 카드를 받는다).
    let online = app.conns.online_devices(user);
    for t in targets.iter().filter(|t| online.contains(t)) {
        let _ = app.db.recovery_mark_seen(user, t);
    }
    send(
        app,
        user,
        std::slice::from_ref(&who.device_id),
        serde_json::json!({"t": "device.recover_scheduled", "at": ts(at), "targets": targets}),
    );
    send(
        app,
        user,
        &targets,
        serde_json::json!({"t": "device.recover_against", "at": ts(at), "requester": who.device_id}),
    );
    broadcast_directory_of(app, user);
    mail(app, user, "scheduled", at);
    None
}

/// `device.recover_cancel` — 건 요청 기기만.
pub fn cancel(app: &Relay, who: &Authed) -> Option<ServerFrame> {
    let now = app.effects.clock.now().0;
    let user = &who.user;
    let mine = app
        .db
        .recovery(user)
        .ok()
        .flatten()
        .is_some_and(|r| r.state == RecoveryState::Scheduled && r.requester == who.device_id);
    if !mine {
        return refused("not_scheduled", None);
    }
    let Ok(Some(row)) = app
        .db
        .recovery_end(user, Some(RecoveryState::Canceled), now, None)
    else {
        return refused("not_scheduled", None);
    };
    tracing::info!(user = %user, device = %who.device_id, "메일 확인 끊기 취소");
    let ended = app.db.recovery(user).ok().flatten();
    let retry = ended.and_then(|r| retry_at(app, user, &r, now));
    let mut v = serde_json::json!({"t": "device.recover_canceled", "reason": "requester"});
    if let Some(r) = retry {
        v["retry_at"] = serde_json::Value::String(ts(r));
    }
    send(app, user, std::slice::from_ref(&row.requester), v);
    send(
        app,
        user,
        &row.targets,
        serde_json::json!({"t": "device.recover_against_ended", "reason": "canceled"}),
    );
    broadcast_directory_of(app, user);
    mail(app, user, "canceled", now);
    None
}

/// `device.recover_block` — 그 걸기의 대상 기기만.
pub fn block(app: &Relay, who: &Authed) -> Option<ServerFrame> {
    let now = app.effects.clock.now().0;
    let user = &who.user;
    let Some(row) = app
        .db
        .recovery(user)
        .ok()
        .flatten()
        .filter(|r| r.state == RecoveryState::Scheduled)
    else {
        return refused("ended", None);
    };
    if !row.targets.contains(&who.device_id) {
        return refused("not_target", None);
    }
    // 실행과 한 IMMEDIATE 트랜잭션 순서(A7) — 실행이 먼저 이겼으면 끝난 걸기.
    let Ok(Some(row)) = app.db.recovery_end(
        user,
        Some(RecoveryState::Blocked),
        now,
        Some(&who.device_id),
    ) else {
        return refused("ended", None);
    };
    tracing::info!(user = %user, device = %who.device_id, "메일 확인 끊기 막음");
    let ended = app.db.recovery(user).ok().flatten();
    let retry = ended.and_then(|r| retry_at(app, user, &r, now));
    let mut v = serde_json::json!({
        "t": "device.recover_canceled", "reason": "blocked", "by": who.device_id, "at": ts(now),
    });
    if let Some(r) = retry {
        v["retry_at"] = serde_json::Value::String(ts(r));
    }
    send(app, user, std::slice::from_ref(&row.requester), v);
    send(
        app,
        user,
        &row.targets,
        serde_json::json!({"t": "device.recover_against_ended", "reason": "blocked"}),
    );
    broadcast_directory_of(app, user);
    mail(app, user, "blocked", now);
    None
}

// ---------------------------------------------------------------- 사건

/// 그 사용자의 기기 신뢰가 바뀌었다(certify·폐기 — 지금 끊기의 자기 폐기 포함). 요청 기기가 사라졌으면 걸기를 지우고,
/// 잎 자격을 얻었으면 끝내고(`certified`), 아니면 폐기된 대상을 빼고(모두 빠지면 실행 완료와 같다).
pub fn on_trust_change(app: &Relay, user: &str) {
    notify_device_changed(app);
    let Some(row) = app
        .db
        .recovery(user)
        .ok()
        .flatten()
        .filter(|r| r.state == RecoveryState::Scheduled)
    else {
        return;
    };
    let now = app.effects.clock.now().0;
    let live = live(app, user);
    if !live.contains(&row.requester) {
        if let Ok(Some(row)) = app.db.recovery_end(user, None, now, None) {
            tracing::info!(user = %user, "요청 기기가 사라져 메일 확인 끊기 지움");
            send(
                app,
                user,
                &row.targets,
                serde_json::json!({"t": "device.recover_against_ended", "reason": "canceled"}),
            );
            broadcast_directory_of(app, user);
        }
        return;
    }
    if crate::mls::eligible_devices(app, user).contains(&row.requester) {
        if let Ok(Some(row)) = app.db.recovery_end(user, None, now, None) {
            tracing::info!(user = %user, "요청 기기가 잎 자격을 얻어 메일 확인 끊기 끝");
            send(
                app,
                user,
                std::slice::from_ref(&row.requester),
                serde_json::json!({"t": "device.recover_canceled", "reason": "certified"}),
            );
            send(
                app,
                user,
                &row.targets,
                serde_json::json!({"t": "device.recover_against_ended", "reason": "certified"}),
            );
            broadcast_directory_of(app, user);
        }
        return;
    }
    let left: Vec<String> = row
        .targets
        .iter()
        .filter(|t| live.contains(t))
        .cloned()
        .collect();
    if left.len() == row.targets.len() {
        return;
    }
    if left.is_empty() {
        // 대상이 모두 빠짐 — 그 순간 실행 완료와 같다.
        if let Ok(Some(row)) = app
            .db
            .recovery_end(user, Some(RecoveryState::Done), now, None)
        {
            finish(app, user, &row.requester, &[], now);
        }
        return;
    }
    let _ = app.db.recovery_set_targets(user, &left);
    broadcast_directory_of(app, user);
}

/// 인증 직후(연결 등록 뒤): 마지막 접속 시각을 쓰고, 걸린 걸기의 대상이면 막기 카드 재료를 보낸다.
pub fn on_auth(app: &Relay, who: &Authed) {
    let now = app.effects.clock.now().0;
    let _ = app.db.touch_last_auth(&who.device_id, now);
    notify_device_changed(app);
    if let Some(row) = app
        .db
        .recovery(&who.user)
        .ok()
        .flatten()
        .filter(|r| r.state == RecoveryState::Scheduled && r.targets.contains(&who.device_id))
    {
        // #737: 걸기 뒤 옛 기기가 붙었다 — 살아 있는 기기일 수 있으니 시각에 바로 끊지 않고 한 번 미룬다(tick).
        if app
            .db
            .recovery_mark_seen(&who.user, &who.device_id)
            .unwrap_or(false)
        {
            tracing::info!(user = %who.user, device = %who.device_id, "메일 확인 끊기 대상이 붙음");
        }
        send(
            app,
            &who.user,
            std::slice::from_ref(&who.device_id),
            serde_json::json!({
                "t": "device.recover_against", "at": ts(row.at_ms), "requester": row.requester,
            }),
        );
    }
}

/// 연결 하나가 끝났다 — 그 기기의 마지막 연결이면 마지막으로 붙어 있던 시각을 쓴다.
pub fn on_disconnect(app: &Relay, user: &str, device_id: &str) {
    if app
        .conns
        .online_devices(user)
        .iter()
        .any(|d| d == device_id)
    {
        return;
    }
    let _ = app.db.touch_last_auth(device_id, app.effects.clock.now().0);
}

/// `at` 이 지난 걸기를 실행한다(relay 타이머·재시작 뒤 — 시험이 직접 부른다). 실행한 수.
pub fn tick(app: &Relay) -> usize {
    let now = app.effects.clock.now().0;
    let _ = app
        .db
        .recovery_prune(now - ms(app.config.recovery_block_window));
    let mut n = 0;
    for user in app.db.recoveries_due(now).unwrap_or_default() {
        // 요청 기기가 사라졌거나 이미 자격을 얻었으면 여기서 끝난다.
        on_trust_change(app, &user);
        // #737: 그동안 옛 기기가 붙었으면 이번엔 실행하지 않고 한 번만 미룬다 — 양쪽에 새 시각을 다시 알린다.
        if let Ok(Some(row)) = app
            .db
            .recovery_defer(&user, now, now + ms(app.config.recovery_wait))
        {
            tracing::info!(user = %user, "메일 확인 끊기 미룸(대상이 붙었음)");
            send(
                app,
                &user,
                std::slice::from_ref(&row.requester),
                serde_json::json!({
                    "t": "device.recover_scheduled", "at": ts(row.at_ms), "targets": row.targets,
                }),
            );
            send(
                app,
                &user,
                &row.targets,
                serde_json::json!({
                    "t": "device.recover_against", "at": ts(row.at_ms), "requester": row.requester,
                }),
            );
            broadcast_directory_of(app, &user);
            continue;
        }
        let Ok(Some((requester, cut))) = app.db.recovery_execute(&user, now) else {
            continue;
        };
        n += 1;
        tracing::info!(user = %user, cut = cut.len(), "메일 확인 끊기 실행");
        finish(app, &user, &requester, &cut, now);
    }
    let _ = app.db.device_changed_sweep(now);
    notify_device_changed(app);
    n
}

/// 실행 완료(at 실행·대상이 모두 빠짐): 잎 duty → 요청 기기 `device.recovered` → 끊긴 대상에 `device.revoked{by:
/// recovery}` → 같은 조직에 directory.update → 끊긴 대상 연결 닫음 → 메일.
fn finish(app: &Relay, user: &str, requester: &str, cut: &[String], now: i64) {
    // #599: 끊긴 기기가 보낸 확정 전 Commit 은 확정될 길이 없다 — 바로 무효로(다시 들기를 막지 않게).
    if !cut.is_empty() {
        crate::mls_group::void_revoked_senders(app);
    }
    crate::mls::refresh_add_duties(app, user);
    notify_device_changed(app);
    send(
        app,
        user,
        &[requester.to_owned()],
        serde_json::json!({"t": "device.recovered", "at": ts(now), "targets": cut}),
    );
    // #599 ①: 끊김 알림(device.recovered) 뒤에 — 산 잎이 안 남은 그룹에 다시 들기 신호.
    crate::mls::rejoin_orphaned(app, user);
    app.conns.send_devices(
        user,
        cut,
        &ServerFrame::DeviceRevoked {
            device_id: None,
            by: Some(crate::frames::RevokedBy::Recovery),
            at: Some(ts(now)),
        },
    );
    broadcast_directory_of(app, user);
    for d in cut {
        app.conns.close_device(user, d);
    }
    mail(app, user, "done", now);
}

/// §9 ②: 폐기된 기기 큐에만 있던 글마다 보낸 사람에게 `status{failed, recipient_device_changed}`. 보낸 사람이 꺼져 있으면
/// 남겨 두고 다음에(tick·폐기·접속) 다시 본다.
pub fn notify_device_changed(app: &Relay) {
    let at = ts(app.effects.clock.now().0);
    for (msg_id, from) in app.db.device_changed_pending().unwrap_or_default() {
        let sent = app.conns.send_user(
            &from,
            &ServerFrame::Status {
                msg_id: msg_id.clone(),
                state: "failed".into(),
                abort_reason: None,
                fail_reason: Some("recipient_device_changed".into()),
                at: at.clone(),
                by: None,
            },
        );
        if sent > 0 {
            let _ = app.db.device_changed_notified(&msg_id);
        }
    }
}

// ---------------------------------------------------------------- 디렉터리

/// 디렉터리 사람 항목의 `recovery`(`viewer` 가 받는다). 동료는 state·at·requester 만, 본인은 전부(exhausted 포함).
pub fn directory_view(app: &Relay, viewer: &str, user: &str) -> Option<DirectoryRecoveryView> {
    let now = app.effects.clock.now().0;
    let mine = viewer == user;
    // #737: 같은 조직 관리자도 대상(옛 기기)을 본다 — 관리자 '옛 기기 끊기'(member.revoke_device)의 재료. 디렉터리는 같은
    // 조직에만 가므로 관리자 여부만 본다.
    let show_targets = mine || app.db.is_org_admin(viewer).unwrap_or(false);
    let row = app.db.recovery(user).ok().flatten();
    let exhausted = mine.then(|| exhausted_until(app, user, now)).flatten();
    let view = |state: &str, at: i64, row: &RecoveryRow| DirectoryRecoveryView {
        state: state.to_owned(),
        at: Some(ts(at)),
        requester: Some(row.requester.clone()),
        targets: if show_targets {
            row.targets.clone()
        } else {
            Vec::new()
        },
        postponed: row.state == RecoveryState::Scheduled && row.deferred,
        blocked_by: if mine && row.state == RecoveryState::Blocked {
            row.blocked_by
                .clone()
                .zip(row.ended_ms.map(ts))
                .map(|(device_id, at)| DirectoryRecoveryBlocker { device_id, at })
        } else {
            None
        },
    };
    match row {
        Some(r) if r.state == RecoveryState::Scheduled => Some(view("scheduled", r.at_ms, &r)),
        Some(r) if cooldown_until(app, &r, now).is_some() => {
            let at = retry_at(app, user, &r, now).unwrap_or(now);
            let state = if exhausted.is_some() {
                "exhausted"
            } else if r.state == RecoveryState::Blocked {
                "blocked"
            } else {
                "canceled"
            };
            Some(view(state, at, &r))
        }
        Some(r)
            if r.state == RecoveryState::Done
                && r.ended_ms
                    .is_some_and(|e| e + ms(app.config.recovery_cooldown) > now) =>
        {
            Some(view("done", r.ended_ms.unwrap_or(now), &r))
        }
        r => exhausted.map(|until| DirectoryRecoveryView {
            state: "exhausted".into(),
            at: Some(ts(until)),
            requester: r.map(|r| r.requester),
            targets: Vec::new(),
            blocked_by: None,
            postponed: false,
        }),
    }
}
