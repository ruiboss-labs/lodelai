//! 묶음 22 group 종류(§12-13·14·15, `docs/design/bundle-22-mls.md`): 그룹 표(16)와 MLS 를 한 길로. 그룹 맥락은 `enc: mls` 만
//! 받는다. 사람 op 는 Commit 으로 오고 **2단계로 확정**한다(§4-7) — relay 는 비밀이 없어 Commit 안쪽을 못 보므로, 받은
//! 다른 멤버의 ack 로 확정하고 60초 창 뒤 ack 0 + fail 사용자 둘, 또는 1시간이면 무효로 한다.
//!
//! - create = wire start(만든 사람 혼자의 epoch 0) — 표 만들기와 같은 메시지, seq 1.
//! - add·remove·admin·org_left·update = wire commit. leave 는 나가는 사람의 wire app(표에서 바로 빼고 seq·remove_user duty)
//!   또는 남은 기기의 commit.
//! - 확정 전 Commit 의 N+1 응용 메시지는 쥐었다가 확정 때 배달, 무효면 보낸 기기에 `nack commit_void`.

use lodelai_crypto::encoding;
use lodelai_protocol::ws;
use openmls::prelude::{Extension, ExtensionType};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::db::{GiPin, GroupOp, PendingCommit, StoredHeader};
use crate::frames::{Address, Header, Kind, MlsBytes, MlsWire, NackReason, ServerFrame};
use crate::mls::{self, APP_PAST_EPOCHS, HANDSHAKE_RETENTION_MS};
use crate::rules::{internal_error, nack, route, unroutable_nack, Authed, MAX_RETENTION_MS};
use crate::Relay;

/// 확정 전 창(§4-7): 이 안에서는 확정하지 않는다.
pub const VOTE_WINDOW_MS: i64 = 60 * 1000;
/// 이만큼 확정되지 않으면 무효(§4-7).
pub const PENDING_MAX_MS: i64 = 60 * 60 * 1000;
/// 관리자 목록 GroupContext 확장(ADR 0012 — `admins`).
const EXT_ADMINS: u16 = 0xF0A1;

/// group 맥락의 `send`(그룹 주소·헤더 group·kind group). 호출자(`mls::handle_send`)가 서명·크기를 이미 봤다.
#[allow(clippy::too_many_arguments)]
pub fn handle_send(
    app: &Relay,
    who: &Authed,
    h: &Header,
    message: Value,
    to_raw: String,
    from_raw: String,
    expires_ms: i64,
) -> ServerFrame {
    let Some(m) = h.mls.as_ref() else {
        return internal_error();
    };
    let gid = match h
        .group
        .as_ref()
        .and_then(Address::gid)
        .or_else(|| h.to.gid())
    {
        Some(g) => g.to_owned(),
        None => return unroutable_nack(&h.msg_id),
    };
    let server_ok = h.to.server == app.config.server_name
        && h.subject
            .as_ref()
            .is_none_or(|s| s.server == app.config.server_name);
    if m.group != gid || !server_ok {
        return unroutable_nack(&h.msg_id);
    }
    // 같은 그룹의 Handshake 는 한 줄(§4), 표 변경은 조직 빠짐 directory.update 와 같은 줄(16 §3a ④).
    let _order = app
        .mls_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _group = app
        .group_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (hr, attach, gi_pin) = match mls::resolve_blobs(app, who, h) {
        Ok(r) => r,
        Err(f) => return f,
    };
    let h = &hr;
    let wire = m.wire;
    match (h.kind, wire) {
        (Kind::Group, MlsWire::Start) => create(app, who, h, &gid, gi_pin.as_ref()),
        (Kind::Group, MlsWire::Commit) => commit(
            app, who, h, message, &to_raw, from_raw, &gid, gi_pin, &attach,
        ),
        (Kind::Group, MlsWire::App) if h.group_op.as_deref() == Some("rename") => {
            rename(app, who, h, message, to_raw, from_raw, &gid)
        }
        (Kind::Group, MlsWire::App) => leave(app, who, h, message, to_raw, from_raw, &gid),
        (_, MlsWire::App) => app_message(app, who, h, message, to_raw, from_raw, expires_ms, &gid),
        _ => unroutable_nack(&h.msg_id),
    }
}

fn stored_header(
    who: &Authed,
    h: &Header,
    to_raw: String,
    from_raw: String,
    expires_ms: i64,
) -> StoredHeader {
    StoredHeader {
        msg_id: h.msg_id.clone(),
        kind: h.kind.as_str().to_owned(),
        from_user: who.user.clone(),
        from_address: from_raw,
        to_user: h.to.user.clone(),
        to_address: to_raw,
        expires_ms,
        env_state: lodelai_statechart::envelope_server::INITIAL
            .as_str()
            .to_owned(),
        sender_view: lodelai_statechart::request_sender_view::State::Stored
            .as_str()
            .to_owned(),
        abort_reason: None,
    }
}

fn stored_state(mut message: Value) -> String {
    if let Some(obj) = message.as_object_mut() {
        obj.insert("state".into(), Value::String("stored".into()));
    }
    message.to_string()
}

fn ack(msg_id: &str, group_seq: Option<u64>) -> ServerFrame {
    ServerFrame::Ack {
        msg_id: msg_id.to_owned(),
        group_seq,
    }
}

/// create(§12-13 ①): 만든 사람 혼자의 epoch 0 GroupInfo — 표 만들기와 같은 트랜잭션, seq 1. 거절은 모두 같은 unroutable(16).
fn create(app: &Relay, who: &Authed, h: &Header, gid: &str, gi_pin: Option<&GiPin>) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    let users = [who.user.clone()];
    let Some((storage, gi)) = mls::verify_start(app, who, m, gid.as_bytes(), &users) else {
        return nack(&h.msg_id, NackReason::InvalidCommit);
    };
    match app.db.group_create_mls(
        gid,
        &who.user,
        &storage,
        &gi,
        gi_pin.map(|p| (p, h.msg_id.as_str())),
        &who.device_id,
        &h.msg_id,
        app.effects.clock.now().0,
    ) {
        Ok(Some((seq, removed))) => {
            if !removed.is_empty() {
                crate::blob::remove_files(app, &removed);
            }
            tracing::info!(gid, "그룹 만들기(MLS)");
            ack(&h.msg_id, Some(seq))
        }
        Ok(None) | Err(crate::db::DbError::Conflict) => unroutable_nack(&h.msg_id),
        Err(crate::db::DbError::BlobUnavailable) => nack(&h.msg_id, NackReason::BlobUnavailable),
        Err(_) => internal_error(),
    }
}

/// 기기의 사용자(폐기된 기기도).
fn owner(app: &Relay, device: &str) -> Option<String> {
    app.db.device_user(device).ok().flatten()
}

/// 사람 op·update 의 Commit(§4 1~6 + §4-3·4·§12-13·15): 검사를 지나면 확정 전(pending)으로 두고 지금 잎(보낸 기기·새 잎 빼고)에
/// 배달한다. ack 에 seq 는 없다(확정 때 commit_final 에).
#[allow(clippy::too_many_arguments)]
fn commit(
    app: &Relay,
    who: &Authed,
    h: &Header,
    message: Value,
    to_raw: &str,
    from_raw: String,
    gid: &str,
    gi_pin: Option<GiPin>,
    attach: &[String],
) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    let invalid = || nack(&h.msg_id, NackReason::InvalidCommit);
    let (Some(op), mut subject) = (
        h.group_op.as_deref(),
        h.subject.as_ref().map(|s| s.user.clone()),
    ) else {
        return unroutable_nack(&h.msg_id);
    };
    // 만들기 Commit(§12-22): 처음 멤버 subjects — 표·권한에는 줄바꿈으로 이은 아이디로 넘긴다.
    let first: Vec<String> = h
        .subjects
        .as_ref()
        .map(|v| v.iter().map(|a| a.user.clone()).collect())
        .unwrap_or_default();
    if h.subjects
        .as_ref()
        .is_some_and(|v| v.iter().any(|a| a.server != app.config.server_name))
    {
        return unroutable_nack(&h.msg_id);
    }
    let creating = op == "create";
    if creating {
        subject = Some(first.join("\n"));
    }
    // remove·admin 은 '보낸 사람이 지금 관리자'를 MLS 그룹에서 계산한 유효 관리자로 본다(§12-25 — 받는 기기와 같은 계산).
    // 아니면 다른 권한 거절과 같은 unroutable(그룹이 있는지 드러내지 않게 — 거절 꼴은 하나).
    let admin = matches!(op, "remove" | "admin").then(|| {
        mls::load(app, gid.as_bytes())
            .is_some_and(|(pg, _, _)| effective_admins(app, &pg).contains(&who.user))
    });
    let g = GroupOp {
        gid,
        op,
        sender: &who.user,
        subject: subject.as_deref(),
        admin,
    };
    let view = match (app.db.group_op_allowed(&g), app.db.group_view(gid)) {
        (Ok(true), Ok(Some(v))) => v,
        (Ok(_), Ok(_)) => return unroutable_nack(&h.msg_id),
        _ => return internal_error(),
    };
    // 하나씩(§4-7): 확정 전 Commit 이 있으면 그 epoch 의 새 Commit 은 stale_epoch.
    if matches!(app.db.mls_pending(gid), Ok(Some(_))) {
        return nack(&h.msg_id, NackReason::StaleEpoch);
    }
    let mut users = view.members.clone();
    if op == "add" {
        users.extend(subject.clone());
    }
    if creating {
        users.extend(first.iter().cloned());
    }
    let c = match mls::check_commit(app, who, h, gid.as_bytes(), &users) {
        Ok(c) => c,
        Err(f) => return f,
    };
    let joining_users: Vec<Option<String>> = c.joining.iter().map(|d| owner(app, d)).collect();
    let before_users: Vec<Option<String>> = c.before.iter().map(|(_, d)| owner(app, d)).collect();
    // Add: add 는 그 사람의 기기만, update 는 지금 멤버의 기기만, 그 밖의 op 는 없음.
    let adds_ok = match op {
        "add" => joining_users.iter().all(|u| *u == subject),
        // 만들기: epoch 0 → 1, Add 로 드는 사용자 ⊆ subjects ∪ {만든 사람}(만든 사람의 다른 기기는 선택), subjects 는 모두
        // 든다(사람마다 기기 하나 이상), Remove 없음(§12-22).
        "create" => {
            c.epoch == 0
                && c.removed.is_empty()
                && joining_users.iter().all(|u| {
                    u.as_ref()
                        .is_some_and(|u| first.contains(u) || *u == who.user)
                })
                && first
                    .iter()
                    .all(|f| joining_users.iter().any(|u| u.as_deref() == Some(f)))
        }
        "update" => joining_users
            .iter()
            .all(|u| u.as_ref().is_some_and(|u| view.members.contains(u))),
        _ => c.joining.is_empty(),
    };
    // Remove: 폐기된 기기의 잎·external 의 옛 자기 잎은 언제나, 사용자 단위 op 는 그 사람의 잎.
    let user_op = matches!(op, "remove" | "leave" | "org_left");
    let removes_ok = c.removed.iter().all(|d| {
        let revoked = app.db.device(d).ok().flatten().is_none();
        let own_old = c.external && *d == who.device_id;
        revoked || own_old || (user_op && owner(app, d) == subject)
    });
    // 사용자 단위 op 뒤 그 사람의 잎은 0(§4-4).
    let gone = !user_op
        || c.new_leaves
            .iter()
            .all(|(_, d)| owner(app, d).as_ref() != subject.as_ref());
    // GCE 는 admin 만, 관리자 목록 말고는 그대로(§12-13 ①).
    let gce_ok = match (&c.gce, op) {
        (Some(new), "admin") => only_admins_changed(&c.old_extensions, new),
        (None, "admin") => false,
        (Some(_), _) => false,
        (None, _) => true,
    };
    // external commit 은 update(복구)뿐, 그 사용자는 직전 epoch 에 잎이 있었어야(§4-5 ⓑ). #577: 또는 지금 멤버(그룹 표) —
    // 메일 확인 끊기로 옛 기기 잎이 먼저 빠진 뒤 같은 사람의 새 기기가 스스로 드는 길(잎 자격은 check_commit 이 users 로 봄).
    let external_ok = !c.external
        || (op == "update"
            && (before_users.iter().any(|u| u.as_deref() == Some(&who.user))
                || view.members.contains(&who.user)));
    if !(adds_ok && removes_ok && gone && gce_ok && external_ok) {
        return invalid();
    }
    let Some(payload) = m.payload.as_ref().and_then(MlsBytes::data) else {
        return invalid();
    };
    let commit_hash = encoding::encode(&Sha256::digest(payload));
    let mut excluded = vec![who.user.clone()];
    if user_op {
        excluded.extend(subject.clone());
    }
    let now = app.effects.clock.now().0;
    let text = stored_state(message);
    let expires = now.saturating_add(HANDSHAKE_RETENTION_MS);
    let p = PendingCommit {
        group_id: gid.to_owned(),
        epoch: c.epoch,
        msg_id: h.msg_id.clone(),
        commit_hash,
        sender_user: who.user.clone(),
        sender_device: who.device_id.clone(),
        op: op.to_owned(),
        subject: subject.clone(),
        storage: c.storage,
        group_info: c.gi,
        gi_pin,
        leaves: c.new_leaves.iter().map(|(_, d)| d.clone()).collect(),
        joining: c.joining.clone(),
        excluded,
        delivered_ms: now,
        message: text.clone(),
        from_address: from_raw.clone(),
        to_address: to_raw.to_owned(),
        expires_ms: expires,
    };
    match app.db.mls_pending_put(&p, c.recovery) {
        Ok(true) => {}
        Ok(false) => return nack(&h.msg_id, NackReason::StaleEpoch),
        Err(_) => return internal_error(),
    }
    // pending 배달: 지금 잎(보낸 기기·폐기 기기 빼고). 새 잎은 확정 뒤(§5d).
    let targets: Vec<(String, String)> = mls::deliverable(app, &c.before, &who.device_id);
    let header = stored_header(who, h, to_raw.to_owned(), from_raw, expires);
    let stored = app.db.store_handshake(
        &header,
        &text,
        gid,
        &targets,
        &[],
        attach,
        app.config.handshake_cap,
        now,
    );
    let s = match stored {
        Ok(s) => s,
        Err(e) => {
            let _ = app.db.mls_pending_drop(gid, &h.msg_id);
            return match e {
                crate::db::DbError::Conflict => unroutable_nack(&h.msg_id),
                crate::db::DbError::BlobUnavailable => nack(&h.msg_id, NackReason::BlobUnavailable),
                _ => internal_error(),
            };
        }
    };
    crate::blob::remove_files(app, &s.removed_blobs);
    let _ = app.db.set_envelope_gid(&h.msg_id, gid);
    for (u, d) in &s.marked {
        mls::send_rejoin(app, u, d);
    }
    deliver_stored(app, &h.msg_id, &s.targets, None);
    tracing::info!(gid, op, epoch = p.epoch, "그룹 Commit 확정 전");
    // 응답할 자격 있는 사람(지금 잎의 사용자 중 보낸 사람·Remove 대상이 아닌 지금 멤버)이 없으면 기다릴 것이 없다 — 바로 확정
    // (혼자 만든 그룹의 첫 add·내 기기만 남은 그룹). 망가뜨려 해칠 다른 사람도 없다. #577: 폐기된 잎·이 Commit 이 빼는 잎은
    // 응답할 수 없으니 세지 않는다(두 명 그룹에서 끊긴 옛 기기를 빼는 Commit 이 그 기기의 ack 를 기다리다 void 되던 것).
    let voters = c.before.iter().any(|(_, d)| {
        *d != who.device_id
            && !c.removed.contains(d)
            && app
                .db
                .device(d)
                .ok()
                .flatten()
                .is_some_and(|(u, _)| !p.excluded.contains(&u) && view.members.contains(&u))
    });
    if !voters {
        finalize(app, &p);
    }
    ack(&h.msg_id, None)
}

/// 저장된 메시지를 대상 기기에 보낸다.
fn deliver_stored(app: &Relay, msg_id: &str, targets: &[(String, String)], group_seq: Option<u64>) {
    let Ok(Some(text)) = app.db.envelope_message(msg_id) else {
        return;
    };
    let Ok(message) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let devices: Vec<String> = targets.iter().map(|(_, d)| d.clone()).collect();
    app.conns
        .send_any_devices(&devices, &ServerFrame::Deliver { message, group_seq });
}

/// 유효 관리자(§12-25): 0xF0A1 `admins`(사람 주소) ∩ 지금 잎 사용자, 비면 가장 작은 잎 번호의 사용자 한 명. `admins` 는 나간·빠진
/// 사람을 품을 수 있어 잎으로 거른다. 코어 `mls_rules` 와 같은 계산.
fn effective_admins(app: &Relay, pg: &openmls::prelude::PublicGroup) -> Vec<String> {
    let mut leaves = mls::leaves(pg);
    leaves.sort_by_key(|(i, _)| i.u32());
    let users: Vec<String> = leaves.iter().filter_map(|(_, d)| owner(app, d)).collect();
    let admins: Vec<String> = pg
        .group_context()
        .extensions()
        .iter()
        .find_map(|x| match x {
            Extension::Unknown(EXT_ADMINS, u) => serde_json::from_slice::<Value>(&u.0).ok(),
            _ => None,
        })
        .and_then(|v| v.get("admins").cloned())
        .and_then(|a| serde_json::from_value::<Vec<String>>(a).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| a.split_once('@').map(|(u, _)| u.to_owned()))
        .collect();
    pick_admins(&users, &admins)
}

/// [`effective_admins`] 의 계산 — `users` 는 잎 번호 순 잎 사용자(같은 사람 여러 번 가능), `admins` 는 아이디.
fn pick_admins(users: &[String], admins: &[String]) -> Vec<String> {
    let mut eff: Vec<String> = Vec::new();
    for u in users.iter().filter(|u| admins.contains(u)) {
        if !eff.contains(u) {
            eff.push(u.clone());
        }
    }
    if eff.is_empty() {
        eff.extend(users.first().cloned());
    }
    eff
}

/// 관리자 목록 말고는 GroupContext extensions 가 그대로인가 — 0xF0A1 `{kind, admins?}` 의 kind 도 그대로(§12-13 ①).
fn only_admins_changed(
    old: &openmls::prelude::Extensions<openmls::prelude::GroupContext>,
    new: &openmls::prelude::Extensions<openmls::prelude::GroupContext>,
) -> bool {
    type Exts = openmls::prelude::Extensions<openmls::prelude::GroupContext>;
    let rest = |e: &Exts| -> Vec<Extension> {
        e.iter()
            .filter(|x| x.extension_type() != ExtensionType::Unknown(EXT_ADMINS))
            .cloned()
            .collect()
    };
    let kind = |e: &Exts| -> Option<String> {
        e.iter().find_map(|x| match x {
            Extension::Unknown(EXT_ADMINS, u) => serde_json::from_slice::<Value>(&u.0)
                .ok()?
                .get("kind")?
                .as_str()
                .map(str::to_owned),
            _ => None,
        })
    };
    rest(old) == rest(new) && kind(old).is_some() && kind(old) == kind(new)
}

/// 나가는 사람의 leave(wire app, §12-13 ②): 지금 잎이어야 하고 epoch 는 응용 메시지 창. 받은 때 표에서 빼고 seq 를 매겨 잎에
/// 배달하고, 남은 접속 기기에 remove_user duty 를 준다.
fn leave(
    app: &Relay,
    who: &Authed,
    h: &Header,
    message: Value,
    to_raw: String,
    from_raw: String,
    gid: &str,
) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    if h.subject.as_ref().map(|s| s.user.as_str()) != Some(who.user.as_str()) {
        return unroutable_nack(&h.msg_id);
    }
    let Some((pg, _, epoch)) = mls::load(app, gid.as_bytes()) else {
        return unroutable_nack(&h.msg_id);
    };
    if m.epoch > epoch || m.epoch + APP_PAST_EPOCHS < epoch {
        return nack(&h.msg_id, NackReason::StaleEpoch);
    }
    let ls = mls::leaves(&pg);
    if !ls.iter().any(|(_, d)| *d == who.device_id) {
        return unroutable_nack(&h.msg_id);
    }
    let targets: Vec<String> = mls::deliverable(app, &ls, &who.device_id)
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    let now = app.effects.clock.now().0;
    let header = stored_header(
        who,
        h,
        to_raw,
        from_raw,
        now.saturating_add(MAX_RETENTION_MS),
    );
    let seq =
        match app
            .db
            .group_app_op_now(gid, "leave", &header, &stored_state(message), &targets, now)
        {
            Ok(Some(r)) => r,
            Ok(None) | Err(crate::db::DbError::Conflict) => return unroutable_nack(&h.msg_id),
            Err(_) => return internal_error(),
        };
    let (seq, dropped) = seq;
    let pairs: Vec<(String, String)> = targets.iter().map(|d| (String::new(), d.clone())).collect();
    deliver_stored(app, &h.msg_id, &pairs, Some(seq));
    // 남은 기기가 그 사람의 잎을 모두 빼는 Commit 을 내도록(§12-13 ②). 마지막 멤버였으면 그룹이 지워졌다(#532) — 넣으면 되살아남.
    if !dropped {
        let _ = app.db.duty_add(gid, mls::TASK_REMOVE_USER, &who.user, now);
        mls::dispatch_duties(app, None);
    }
    tracing::info!(gid, seq, dropped, "그룹 나감(MLS)");
    ack(&h.msg_id, Some(seq))
}

/// 이름 바꾸기(§12-23, wire app·subject 없음): 보낸 기기가 지금 잎이고 지금 epoch 의 PrivateMessage 여야 한다. seq 를 매겨
/// 잎 − 보낸 기기에 배달한다. 이름은 MLS 평문 머리(`meta.name`)라 relay 는 모른다 — 알림·안 읽음으로 세지 않는다.
fn rename(
    app: &Relay,
    who: &Authed,
    h: &Header,
    message: Value,
    to_raw: String,
    from_raw: String,
    gid: &str,
) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    let Some((pg, _, epoch)) = mls::load(app, gid.as_bytes()) else {
        return unroutable_nack(&h.msg_id);
    };
    if m.epoch != epoch {
        return nack(&h.msg_id, NackReason::StaleEpoch);
    }
    let ls = mls::leaves(&pg);
    if !ls.iter().any(|(_, d)| *d == who.device_id) {
        return unroutable_nack(&h.msg_id);
    }
    let targets: Vec<String> = mls::deliverable(app, &ls, &who.device_id)
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    let now = app.effects.clock.now().0;
    let header = stored_header(
        who,
        h,
        to_raw,
        from_raw,
        now.saturating_add(MAX_RETENTION_MS),
    );
    let seq = match app.db.group_app_op_now(
        gid,
        "rename",
        &header,
        &stored_state(message),
        &targets,
        now,
    ) {
        Ok(Some((seq, _))) => seq,
        Ok(None) | Err(crate::db::DbError::Conflict) => return unroutable_nack(&h.msg_id),
        Err(_) => return internal_error(),
    };
    let pairs: Vec<(String, String)> = targets.iter().map(|d| (String::new(), d.clone())).collect();
    deliver_stored(app, &h.msg_id, &pairs, Some(seq));
    tracing::info!(gid, seq, "그룹 이름 바꿈(MLS)");
    ack(&h.msg_id, Some(seq))
}

/// 그룹 응용 메시지(§5d·§12-11 ⓑ): 16 의 사람 규칙(route) + 그룹 첨부 합계 + epoch 창(지금 − 3 ~ 지금, 확정 전 Commit 이 있으면
/// 지금 + 1 은 쥠). 대상: 잎 − 보낸 기기(헤더 group 이 붙은 세션·사람 앞 글도 — 16 §5).
#[allow(clippy::too_many_arguments)]
fn app_message(
    app: &Relay,
    who: &Authed,
    h: &Header,
    message: Value,
    to_raw: String,
    from_raw: String,
    expires_ms: i64,
    gid: &str,
) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    let view = match app.db.group_view(gid) {
        Ok(v) => v,
        Err(_) => return internal_error(),
    };
    if route(app, who, h, &to_raw, view.as_ref()).is_err() {
        return unroutable_nack(&h.msg_id);
    }
    if let Err(f) = crate::rules::group_files_ok(app, who, h) {
        return f;
    }
    let Some((pg, _, epoch)) = mls::load(app, gid.as_bytes()) else {
        return unroutable_nack(&h.msg_id);
    };
    let pending = app.db.mls_pending(gid).ok().flatten();
    let hold = pending.as_ref().is_some_and(|p| p.epoch == epoch) && m.epoch == epoch + 1;
    if !hold && (m.epoch > epoch || m.epoch + APP_PAST_EPOCHS < epoch) {
        return nack(&h.msg_id, NackReason::StaleEpoch);
    }
    let ls = mls::leaves(&pg);
    if !ls.iter().any(|(_, d)| *d == who.device_id) {
        return unroutable_nack(&h.msg_id);
    }
    // 그룹 맥락의 글은 받는 사람이 세션·사람이어도(그룹 안 request·reply) 그룹 잎 모두가 본다(16 §5 — 범위는 route 가 봄).
    // #598 ②: 판 10 글(no_reply 그룹 안 request)은 판 9 기기에 전하지 않는다.
    // 0.2.5(g025f 물음): 나간 사람의 잎은 remove_user 확정 전까지 남는다 — 응용 글은 지금 멤버의 잎에만(leave·rename 은 따로).
    let mut live = mls::deliverable(app, &ls, &who.device_id);
    live.retain(|(u, _)| app.db.group_member_now(gid, u).unwrap_or(false));
    let (targets, outdated) = crate::rules::split_outdated(app, h, live, |(_, d)| d.as_str());
    let others_left = targets.iter().any(|(u, _)| *u != who.user);
    let targets: Vec<String> = targets.into_iter().map(|(_, d)| d).collect();
    // #577 §9 ②(설계 리뷰 🟡2): 기기가 바뀌는 중인 멤버(잎은 모두 끊겼고 새 기기가 아직 안 듦)의 몫은 조용히 빠지지 않게.
    let orphan =
        mls::device_changing(app, &ls, &who.user) || member_without_leaf(app, gid, &ls, &who.user);
    // 거두기·고치기(§12-18): 검사가 모두 끝난 뒤 — 원 메시지만 사라지고 새 글이 안 가는 일이 없게.
    if let Err(f) = crate::rules::mls_withdraw(app, who, h) {
        return f;
    }
    let now = app.effects.clock.now().0;
    let keep = expires_ms.min(now.saturating_add(MAX_RETENTION_MS));
    // #577: 기기 바뀜 실패를 알린 글의 다시 보내기 — 옛 봉투를 지우고 새로 저장한다(같은 msg_id, 받는 쪽이 거름).
    if app
        .db
        .device_changed_resend(&h.msg_id, &who.user)
        .unwrap_or(false)
    {
        tracing::info!(msg_id = %h.msg_id, "받는 기기가 바뀐 그룹 글 다시 받음");
    }
    // 다른 멤버 기기가 모두 판 9 면 봉투를 남기지 않는다 — 같은 msg_id 의 v9 다시 보내기가 보통 길로 모두에게 간다.
    // 반응(#626)은 v9 다시 보내기가 없으니 내 다른 기기 몫이 있으면 저장한다.
    if !outdated.is_empty() && !others_left && (h.kind != Kind::Reaction || targets.is_empty()) {
        crate::rules::mark_outdated(app, who, h, &outdated, keep);
        return ack(&h.msg_id, None);
    }
    let header = stored_header(who, h, to_raw, from_raw, keep);
    match app.db.store_group_app(
        &header,
        &stored_state(message),
        gid,
        &targets,
        &h.blobs,
        hold,
    ) {
        Ok(()) => {}
        Err(crate::db::DbError::Conflict) => return unroutable_nack(&h.msg_id),
        Err(crate::db::DbError::BlobUnavailable) => {
            return nack(&h.msg_id, NackReason::BlobUnavailable)
        }
        Err(_) => return internal_error(),
    }
    crate::rules::mark_outdated(app, who, h, &outdated, keep);
    if h.v < crate::rules::OUTDATED_FROM
        && app
            .db
            .outdated_waiting(&h.msg_id, &who.user)
            .unwrap_or(false)
    {
        let _ = app.db.outdated_clear(&h.msg_id, &who.user);
    }
    if !hold {
        let pairs: Vec<(String, String)> =
            targets.iter().map(|d| (String::new(), d.clone())).collect();
        deliver_stored(app, &h.msg_id, &pairs, None);
    }
    if orphan {
        let _ = app.db.device_changed_mark(&h.msg_id, &who.user, now, keep);
    }
    ack(&h.msg_id, None)
}

/// 그룹 멤버(그룹 표) 중 이 epoch 에 산 잎이 하나도 없고, 산 기기에 이 그룹 add_device 일이 남은 사람이 있나(#577 §9 ② — 옛 잎이
/// 이미 빠져 잎 목록에 아예 없는 경우. 10-29 실기 확인: 옛 잎 빼기 확정 뒤·새 기기가 들기 전에 다시 보낸 글이 조용히 빠졌다).
/// 일이 남은 사람만 — KeyPackage 가 없어 못 든 멤버 하나 때문에 그룹 글이 모두 실패로 뜨지 않게(설계 리뷰 🔴).
fn member_without_leaf(
    app: &Relay,
    gid: &str,
    ls: &[(openmls::prelude::LeafNodeIndex, String)],
    sender: &str,
) -> bool {
    let Ok(Some(view)) = app.db.group_view(gid) else {
        return false;
    };
    view.members.iter().any(|u| {
        u != sender
            && !ls.iter().any(|(_, d)| {
                app.db
                    .device(d)
                    .ok()
                    .flatten()
                    .is_some_and(|(o, _)| o == *u)
            })
            && app.db.add_duty_pending_for_user(gid, u).unwrap_or(false)
    })
}

/// commit_ack·commit_fail(§4-7). 확정 전이면 표 하나(지금 잎인 기기, 그 사용자가 지금 멤버, 보낸 사람·Remove 대상 아님) — 창이
/// 끝난 뒤의 ack 는 바로 확정. 확정 뒤 fail 은 관리자 줄 판정. 모르는 Commit 이면 버린다(답 없음).
pub fn vote(app: &Relay, who: &Authed, group: &str, epoch: u64, commit_hash: &str, ack: bool) {
    let _order = app
        .mls_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _group = app
        .group_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let leaf = app
        .db
        .group_leaves(group)
        .is_ok_and(|l| l.contains(&who.device_id));
    if !leaf {
        return;
    }
    match app.db.mls_pending(group) {
        Ok(Some(p)) if p.epoch == epoch && p.commit_hash == commit_hash => {
            if p.excluded.contains(&who.user) {
                return;
            }
            let _ = app.db.mls_vote(group, epoch, commit_hash, &who.user, ack);
            let now = app.effects.clock.now().0;
            if ack && (now >= p.delivered_ms + VOTE_WINDOW_MS || all_acked(app, &p)) {
                finalize(app, &p);
            }
        }
        Ok(None) if !ack => {
            let _ = app.db.mls_vote(group, epoch, commit_hash, &who.user, false);
            if let Ok(Some(u)) = app.db.mls_unprocessed(group, epoch, commit_hash) {
                notify_unprocessed(app, group, epoch, commit_hash, &u);
            }
        }
        _ => {}
    }
}

/// 창 판정(expire_tick): 60초 창이 끝났고 ack 가 있으면 확정, ack 0 + fail 사용자 둘이면 무효, 1시간이면 무효.
/// 창 안이라도 연결된 투표자가 다 ack 했으면 확정(A — ack 뒤에 다른 투표자가 끊긴 경우). 창 끝에 ack·fail 이 없고 연결된
/// 투표자도 없으면 확정(B — 다 오프라인이면 1시간 조용한 기다림이었다. 망가진 Commit 이면 돌아온 기기가 다시 든다).
pub fn tick(app: &Relay) {
    let _order = app
        .mls_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _group = app
        .group_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = app.effects.clock.now().0;
    for p in app.db.mls_pendings().unwrap_or_default() {
        // #599: 보낸 기기가 폐기됐고 ack 가 없으면 창을 기다리지 않는다.
        if revoked_unacked(app, &p) {
            void(app, &p);
            continue;
        }
        if now < p.delivered_ms + VOTE_WINDOW_MS {
            if all_acked(app, &p) {
                finalize(app, &p);
            }
            continue;
        }
        let Ok((acks, fails)) = app
            .db
            .mls_tally(&p.group_id, p.epoch, &p.commit_hash, &p.excluded)
        else {
            continue;
        };
        if !acks.is_empty() || !live_voters(app, &p) {
            // #577: 창이 끝났는데 응답할 산 잎이 없으면(그 사이 폐기됨) 기다릴 것이 없다 — 확정.
            finalize(app, &p);
        } else if fails.len() >= 2 || now >= p.delivered_ms + PENDING_MAX_MS {
            void(app, &p);
        } else if fails.is_empty() && live_voter_users(app, &p, true, true).is_empty() {
            tracing::info!(gid = %p.group_id, epoch = p.epoch, "창 끝 — 연결된 투표자 없음, 확정");
            finalize(app, &p);
        }
    }
}

/// 확정 전 Commit 에 응답할 수 있는 산 잎이 있나 — 확정 뒤 잎(N+1) 중 폐기 안 됐고, 그 사용자가 보낸 사람·Remove 대상이 아닌
/// 지금 멤버.
fn live_voters(app: &Relay, p: &PendingCommit) -> bool {
    !live_voter_users(app, p, false, false).is_empty()
}

/// [`live_voters`] 의 그 잎을 가진 사용자(표는 사람 단위). `skip_joining` 이면 이 Commit 으로 드는 잎(Welcome 은 확정 뒤에 받아
/// 응답할 수 없다)은 세지 않는다. `online_only` 면 그 **잎 기기**가 지금 연결된 것만 센다(hosted 11-04 A — 같은 사용자의 다른
/// 기기가 붙어 있어도 그 기기는 표를 낼 수 없다).
fn live_voter_users(
    app: &Relay,
    p: &PendingCommit,
    skip_joining: bool,
    online_only: bool,
) -> Vec<String> {
    let members = app
        .db
        .group_view(&p.group_id)
        .ok()
        .flatten()
        .map(|v| v.members)
        .unwrap_or_default();
    // 다시 들기 표시(`mls_rejoin`)가 있는 기기는 그룹 상태가 없어 ack·fail 을 못 낸다 — 세면 다른 투표자가 없을 때 창 끝 확정(B)이
    // 걸리지 않는다(g025 ①). 다시 들기가 확정되면 표시가 지워져 다음 Commit 부터 다시 센다.
    let rejoining = app.db.rejoin_devices(&p.group_id).unwrap_or_default();
    let mut users: Vec<String> = Vec::new();
    for d in p.leaves.iter().filter(|d| {
        **d != p.sender_device && !(skip_joining && p.joining.contains(d)) && !rejoining.contains(d)
    }) {
        if let Ok(Some((u, _))) = app.db.device(d) {
            if online_only && !app.conns.online_devices(&u).contains(d) {
                continue;
            }
            if !p.excluded.contains(&u) && members.contains(&u) && !users.contains(&u) {
                users.push(u);
            }
        }
    }
    users
}

/// #599(설계 리뷰 6519899388): 응답할 산 사용자가 모두 ack 했다 — 창 끝 판정이 'ack 하나면 확정'이라 창을 더 기다려도 결과가
/// 같다. 창(60초)과 tick 간격(30초)을 기다리지 않고 바로 확정한다.
///
/// hosted 11-04 A: 지금 **연결된 잎**을 가진 투표자만 센다 — 오프라인 투표자를 기다리느라 다른 사람이 다 ack 해도 60초를
/// 기다렸다(초대한 방이 1분 뒤에 생김). 그래도 결과는 같다(창 끝엔 ack 하나면 확정). 연결된 투표자가 0 이면 '다 ack'로
/// 보지 않는다(빈 집합 참 금지) — 창 끝의 [`tick`] 이 정한다.
fn all_acked(app: &Relay, p: &PendingCommit) -> bool {
    let voters = live_voter_users(app, p, true, true);
    let Ok((acks, _)) = app
        .db
        .mls_tally(&p.group_id, p.epoch, &p.commit_hash, &p.excluded)
    else {
        return false;
    };
    !voters.is_empty() && voters.iter().all(|u| acks.contains(u))
}

fn outcome_frame(
    group: &str,
    epoch: u64,
    commit_hash: &str,
    is_final: bool,
    seq: Option<u64>,
) -> Option<ServerFrame> {
    let group: lodelai_protocol::message::MlsGroupId = group.to_owned().try_into().ok()?;
    let f = if is_final {
        ws::Frame::CommitFinal(ws::CommitFinal {
            commit_hash: commit_hash.to_owned().try_into().ok()?,
            epoch,
            group,
            group_seq: seq.and_then(std::num::NonZeroU64::new),
            t: ws::CommitFinalT::CommitFinal,
        })
    } else {
        ws::Frame::CommitVoid(ws::CommitVoid {
            commit_hash: commit_hash.to_owned().try_into().ok()?,
            epoch,
            group,
            t: ws::CommitVoidT::CommitVoid,
        })
    };
    Some(ServerFrame::Ws(Box::new(f)))
}

/// 확정: 표·seq·epoch, 지금(옛) 잎과 빠진 잎에 commit_final, 새 잎에 그 Commit(Welcome), 쥔 N+1 풀기.
fn finalize(app: &Relay, p: &PendingCommit) {
    let old = app.db.group_leaves(&p.group_id).unwrap_or_default();
    let now = app.effects.clock.now().0;
    let Ok(Some(f)) = app.db.mls_finalize(p, now) else {
        return;
    };
    crate::blob::remove_files(app, &f.removed_blobs);
    tracing::info!(group = %p.group_id, epoch = p.epoch, seq = ?f.group_seq, "그룹 Commit 확정");
    // 빠진 기기 채우기(§12-24): create·add·update 확정 뒤 그 그룹 잎 사용자마다 add_device 를 다시 센다 — 그때 KeyPackage 가
    // 없던 기기도 나중에 들 수 있게.
    let refresh: Vec<String> = if matches!(p.op.as_str(), "create" | "add" | "update") {
        let mut users: Vec<String> = app
            .db
            .group_leaves(&p.group_id)
            .unwrap_or_default()
            .iter()
            .filter_map(|d| owner(app, d))
            .collect();
        users.sort();
        users.dedup();
        users
    } else {
        Vec::new()
    };
    if let Some(frame) = outcome_frame(&p.group_id, p.epoch, &p.commit_hash, true, f.group_seq) {
        let mut to: Vec<String> = old.into_iter().filter(|d| !p.joining.contains(d)).collect();
        // external commit 으로 처음 드는 기기(#577 — 잎이었던 적 없음, Add 도 아님)도 자기 Commit 의 결과를 받아야 그룹을 연다.
        if !to.contains(&p.sender_device) {
            to.push(p.sender_device.clone());
        }
        rejoiners(app, &p.group_id, &mut to);
        app.conns.send_any_devices(&to, &frame);
    }
    if let Some(text) = f.commit_message {
        if let Ok(message) = serde_json::from_str::<Value>(&text) {
            app.conns.send_any_devices(
                &f.welcome,
                &ServerFrame::Deliver {
                    message,
                    group_seq: f.group_seq,
                },
            );
        }
    }
    for (text, targets) in f.released {
        if let Ok(message) = serde_json::from_str::<Value>(&text) {
            app.conns.send_any_devices(
                &targets,
                &ServerFrame::Deliver {
                    message,
                    group_seq: None,
                },
            );
        }
    }
    for u in &refresh {
        mls::refresh_add_duties(app, u);
    }
    mls::dispatch_duties(app, None);
}

/// #599(설계 리뷰 6519899388 ②): 확정·무효 결과를 그 그룹에 다시 들라는 표시(`mls_rejoin`)가 있는 기기에도 보탠다 — 지금 그룹
/// 멤버이고 폐기 안 된 기기만. 잎이 아니라 결과를 못 받으면 `stale_epoch` 로 물러선 external commit 이 물러섬(최대 60초)을 다
/// 기다린다. 받은 클라이언트는 모르는 그룹의 결과여도 물러섬만 푼다.
fn rejoiners(app: &Relay, group: &str, to: &mut Vec<String>) {
    let members = app
        .db
        .group_view(group)
        .ok()
        .flatten()
        .map(|v| v.members)
        .unwrap_or_default();
    for d in app.db.rejoin_devices(group).unwrap_or_default() {
        let member = matches!(app.db.device(&d), Ok(Some((u, _))) if members.contains(&u));
        if member && !to.contains(&d) {
            to.push(d);
        }
    }
}

/// #599: 폐기된 기기가 보낸 확정 전 Commit 은 바로 무효로 한다. 다른 클라이언트가 보낸 이를 `revoked` 로 보고 실패시키므로 확정될 길이
/// 없는데, 창 판정은 fail 사용자 둘이 아니면 1시간을 기다린다 — 그동안 같은 그룹의 새 Commit(지금 끊기로 남은 새 기기의 external
/// commit)이 `stale_epoch` 로 막힌다. 기기를 폐기하는 자리(자기 폐기·다른 기기 끊기·메일 확인 끊기·조직 나가기·내보내기)가 잠금을
/// 놓은 뒤 부르고, [`tick`] 도 같은 판정을 받침으로 한다(폐기 뒤 남은 연결로 온 Commit 등). 이미 ack 를 받은 것은 창 끝 확정에
/// 맡긴다. 무효가 되면 [`void`] 가 다시 들기 신호를 본다.
pub fn void_revoked_senders(app: &Relay) {
    let _order = app
        .mls_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _group = app
        .group_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for p in app.db.mls_pendings().unwrap_or_default() {
        if revoked_unacked(app, &p) {
            void(app, &p);
        }
    }
}

/// 보낸 기기가 폐기됐고 ack 가 하나도 없다(확정될 길이 없음).
fn revoked_unacked(app: &Relay, p: &PendingCommit) -> bool {
    let revoked = matches!(app.db.device(&p.sender_device), Ok(None));
    revoked
        && app
            .db
            .mls_tally(&p.group_id, p.epoch, &p.commit_hash, &p.excluded)
            .is_ok_and(|(acks, _)| acks.is_empty())
}

/// 무효: 옛 잎에 commit_void, 쥔 N+1 은 보낸 기기에 nack commit_void(접속해 있으면 바로, 아니면 접속 때).
fn void(app: &Relay, p: &PendingCommit) {
    let leaves = app.db.group_leaves(&p.group_id).unwrap_or_default();
    let now = app.effects.clock.now().0;
    let Ok(v) = app.db.mls_void(p, now) else {
        return;
    };
    crate::blob::remove_files(app, &v.removed_blobs);
    tracing::info!(group = %p.group_id, epoch = p.epoch, "그룹 Commit 무효");
    // #577: 무효가 된 Commit 이 duty(remove_device·add_device) 였으면 그 일은 아직 남았다 — 순서를 비워 다시 나눠 준다.
    let _ = app.db.duty_ranks_reset(&p.group_id);
    if let Some(frame) = outcome_frame(&p.group_id, p.epoch, &p.commit_hash, false, None) {
        let mut to = leaves;
        // 잎이 아닌 기기의 external commit(#577)도 무효를 알아야 다시 든다.
        if !to.contains(&p.sender_device) {
            to.push(p.sender_device.clone());
        }
        rejoiners(app, &p.group_id, &mut to);
        app.conns.send_any_devices(&to, &frame);
    }
    for (device, msg_id) in v.nacks {
        let Some(user) = owner(app, &device) else {
            continue;
        };
        if app.conns.online_devices(&user).contains(&device) {
            app.conns.send_devices(
                &user,
                std::slice::from_ref(&device),
                &nack(&msg_id, NackReason::CommitVoid),
            );
            let _ = app.db.mls_void_nack_done(&device, &msg_id);
        }
    }
    // #599 ①(설계 리뷰 🟡 6513600893): 이 Commit 으로 들 기기가 있어 다시 들기 신호를 미뤘을 수 있다(rejoin_orphaned 의 확정 전
    // 건너뜀) — 무효가 됐으니 N+1 잎에 있던 사람마다 다시 본다(산 잎이 남았으면 아무것도 안 함).
    let mut users: Vec<String> = Vec::new();
    for d in &p.leaves {
        if let Some(u) = owner(app, d) {
            if !users.contains(&u) {
                users.push(u);
            }
        }
    }
    for u in users {
        crate::mls::rejoin_orphaned(app, &u);
    }
}

/// 접속 때(§12-14·20): 저장한 nack commit_void → 그 기기가 잎인 그룹마다 마지막 결과 → 저장한 group_alert. 보낸 것은 지운다.
/// 돌려주는 값: 프레임 JSON.
pub fn on_connect_frames(app: &Relay, device_id: &str) -> Vec<String> {
    let now = app.effects.clock.now().0;
    let mut out = Vec::new();
    for msg_id in app
        .db
        .mls_void_nacks_for(device_id, now)
        .unwrap_or_default()
    {
        out.push(nack(&msg_id, NackReason::CommitVoid).to_json());
        let _ = app.db.mls_void_nack_done(device_id, &msg_id);
    }
    for o in app.db.mls_outcomes_for(device_id, now).unwrap_or_default() {
        out.extend(
            outcome_frame(
                &o.group_id,
                o.epoch,
                &o.commit_hash,
                o.is_final,
                o.group_seq,
            )
            .map(|f| f.to_json()),
        );
    }
    out.extend(app.db.mls_alerts_take(device_id, now).unwrap_or_default());
    out
}

/// 확정 뒤 처리 못 함(§4-7·§12-20): 그룹 관리자 기기에 group_alert 한 번 — 접속해 있으면 바로, 아니면 저장했다 접속 때.
fn notify_unprocessed(
    app: &Relay,
    group: &str,
    epoch: u64,
    hash: &str,
    u: &crate::db::Unprocessed,
) {
    tracing::warn!(group, sender = %u.sender, failed = u.failed, "확정 뒤 처리 못 함");
    let server = &app.config.server_name;
    let addr = |user: &str| -> Option<lodelai_protocol::message::PersonAddress> {
        format!("{user}@{server}").try_into().ok()
    };
    let (Ok(g), Some(sender), Ok(commit_hash)) = (
        format!("+{group}@{server}").try_into(),
        addr(&u.sender),
        hash.to_owned().try_into(),
    ) else {
        return;
    };
    let frame = ServerFrame::Ws(Box::new(ws::Frame::GroupAlert(ws::GroupAlert {
        acked: u.acked.iter().filter_map(|a| addr(a)).collect(),
        commit_hash,
        epoch,
        group: g,
        n: i64::try_from(u.failed).unwrap_or(i64::MAX),
        reason: ws::GroupAlertReason::CommitUnprocessed,
        sender,
        t: ws::GroupAlertT::GroupAlert,
    })));
    let text = frame.to_json();
    let now = app.effects.clock.now().0;
    for admin in &u.admins {
        let online = app.conns.online_devices(admin);
        for d in app
            .db
            .devices_of(admin)
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.device_id)
        {
            if online.contains(&d) {
                app.conns
                    .send_devices(admin, std::slice::from_ref(&d), &frame);
            } else {
                let _ = app.db.mls_alert_put(&d, group, hash, &text, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pick_admins;

    fn v(x: &[&str]) -> Vec<String> {
        x.iter().map(|s| (*s).to_owned()).collect()
    }

    // §12-25 시험 줄 — 코어 mls_rules 와 같은 표.
    #[test]
    fn 유효_관리자() {
        // 관리자 A 혼자, A 가 나가 잎에 없음 → 잎 번호가 가장 작은 B 하나(C 는 아님).
        assert_eq!(pick_admins(&v(&["b", "c", "b"]), &v(&["a"])), ["b"]);
        // admins = {A, B}, A 나감 → B 만.
        assert_eq!(pick_admins(&v(&["c", "b"]), &v(&["a", "b"])), ["b"]);
        // 둘 다 잎이면 둘 다.
        assert_eq!(
            pick_admins(&v(&["a", "b", "c"]), &v(&["a", "b"])),
            ["a", "b"]
        );
        // 잎이 없으면 없음.
        assert!(pick_admins(&[], &v(&["a"])).is_empty());
    }
}
