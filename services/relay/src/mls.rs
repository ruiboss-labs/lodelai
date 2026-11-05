//! 묶음 22 MLS 전달 서비스(DS, `docs/design/bundle-22-mls.md`). relay 는 비밀을 쥐지 않는다 — KeyPackage 를 보관해 나눠 주고,
//! 그룹마다 공개 상태(openmls `PublicGroup`)로 Commit 을 검증해 순서를 준다.
//!
//! - §3 KeyPackage: 기기마다 보통 100 + 마지막 수단 1, 가져가기 소비 상한, 20 아래면 `key_packages.low`.

use lodelai_crypto::encoding;
use lodelai_protocol::ws;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{
    BasicCredential, Ciphersuite, KeyPackage, MlsMessageBodyIn, MlsMessageIn, ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;

use crate::frames::ServerFrame;
use crate::rules::{protocol_error, Authed};
use crate::Relay;

/// 프로필 ciphersuite 하나(§2 — 0x0003). 다른 것은 거절한다.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// 기기마다 보통 KeyPackage 상한(§3).
pub const KP_MAX: usize = 100;
/// 이 아래로 남으면 `key_packages.low`(§3).
pub const KP_LOW: u64 = 20;
/// KeyPackage lifetime 상한(§3 — 90일).
pub const KP_LIFETIME_MAX_S: u64 = 90 * 24 * 3600;
/// 소비 상한(§3): 가져가는 사용자 시간당, (가져가는 사용자, 대상 기기) 하루, 대상 기기 하루 합(주인 것 빼고).
pub const KP_CLAIM_PER_HOUR: i64 = 300;
/// 짝 하루 25(g025 11-04 판정 — 대상 기기 하루 50 의 절반: 한 사람이 남의 기기 하루 몫을 혼자 다 쓰지 않게).
pub const KP_CLAIM_PAIR_PER_DAY: i64 = 25;
pub const KP_CLAIM_TARGET_PER_DAY: i64 = 50;
/// 주인 예외의 그룹 몫(`GROUPS_PER_USER` — 묶음 16 상수, develop 에 들기 전까지 같은 값) + 동료 수.
pub const KP_OWNER_GROUPS: i64 = 100;
/// Handshake 본문 blob 칸 하나의 상한(§5c, 설계 ⑨ 리뷰) — 넘으면 relay 가 읽기 전에 `blob_unavailable`.
pub const MLS_BLOB_MAX_BYTES: u64 = 1 << 20;

/// 검사를 통과한 KeyPackage 하나.
pub struct CheckedKeyPackage {
    pub kp_ref: Vec<u8>,
    pub data: Vec<u8>,
    /// lifetime 끝(초).
    pub not_after: i64,
}

/// 올린 KeyPackage 검사(§3·§2): MLSMessage 의 KeyPackage, 서명 맞음(openmls validate), ciphersuite 0x0003, Credential
/// `BasicCredential(device_id)` = 이 기기, 잎 서명 키 = 디렉터리의 이 기기 ed25519, lifetime ≤ 90일·아직 유효.
pub fn check_key_package(
    app: &Relay,
    who: &Authed,
    b64: &str,
    now_s: u64,
) -> Option<CheckedKeyPackage> {
    let data = encoding::decode(b64, "key_package").ok()?;
    let msg = MlsMessageIn::tls_deserialize_exact(data.as_slice()).ok()?;
    let MlsMessageBodyIn::KeyPackage(kp_in) = msg.extract() else {
        return None;
    };
    let crypto = RustCrypto::default();
    let kp: KeyPackage = kp_in.validate(&crypto, ProtocolVersion::Mls10).ok()?;
    if kp.ciphersuite() != CIPHERSUITE {
        return None;
    }
    let leaf = kp.leaf_node();
    let cred = BasicCredential::try_from(leaf.credential().clone()).ok()?;
    if cred.identity() != who.device_id.as_bytes() {
        return None;
    }
    let (_, pk) = app.db.device(&who.device_id).ok().flatten()?;
    let pk = encoding::decode(&pk, "ed25519").ok()?;
    if leaf.signature_key().as_slice() != pk.as_slice() {
        return None;
    }
    let lt = kp.life_time();
    if lt.not_after().saturating_sub(lt.not_before()) > KP_LIFETIME_MAX_S || lt.not_after() <= now_s
    {
        return None;
    }
    let kp_ref = kp.hash_ref(&crypto).ok()?.as_slice().to_vec();
    Some(CheckedKeyPackage {
        kp_ref,
        data,
        not_after: i64::try_from(lt.not_after()).ok()?,
    })
}

/// `key_packages.publish{items, last_resort?, reset?}`(§3). 하나라도 검사를 못 지나거나 보통 것이 100 을 넘으면 `error{protocol}`
/// 이고 아무것도 저장하지 않는다. `reset`(0.2.5 g025f B)이면 이 기기의 남은 것을 같은 트랜잭션에서 지우고 바꾼다 — 로컬 MLS
/// 데이터를 잃은 기기가 옛 KeyPackage 로 Welcome 을 받아 못 여는 것을 막는다.
pub fn publish(
    app: &Relay,
    who: &Authed,
    items: &[String],
    last_resort: Option<&str>,
    reset: bool,
) -> Option<ServerFrame> {
    let now_s = u64::try_from(app.effects.clock.now().0 / 1000).unwrap_or(0);
    let mut checked = Vec::with_capacity(items.len());
    for it in items {
        match check_key_package(app, who, it, now_s) {
            Some(c) => checked.push(c),
            None => return Some(protocol_error("key_packages.publish")),
        }
    }
    let last = match last_resort.map(|l| check_key_package(app, who, l, now_s)) {
        None => None,
        Some(Some(c)) => Some(c),
        Some(None) => return Some(protocol_error("key_packages.publish")),
    };
    match app
        .db
        .kp_publish(&who.device_id, &checked, last.as_ref(), KP_MAX, reset)
    {
        Ok(true) => {
            // KeyPackage 가 생겼으니 그 사용자의 빠진 기기를 다시 센다(§12-24).
            refresh_add_duties(app, &who.user);
            if reset {
                rejoin_own_leaves(app, who);
            }
            None
        }
        Ok(false) => Some(protocol_error("key_packages.publish 상한")),
        Err(_) => Some(protocol_error("key_packages.publish")),
    }
}

/// `key_packages.claim{device_ids}`(§3): 같은 조직의 폐기 안 된 기기마다 하나(보통 것 먼저, 없으면 마지막 수단). 줄 수 없는 기기는
/// 항목이 없다(이유를 가르지 않음 — 열거 없음). 소비 상한을 넘으면 `error{rate_limited}` 이고 아무것도 가져가지 않는다.
pub fn claim(app: &Relay, who: &Authed, device_ids: &[String]) -> Option<ServerFrame> {
    let Ok(Some(org)) = app.db.user_org(&who.user) else {
        return Some(kp_answer(Vec::new()));
    };
    // 대상 기기 → 주인(같은 조직·폐기 안 됨만). 같은 기기를 두 번 적으면 한 번만.
    let mut targets: Vec<(String, String)> = Vec::new();
    for d in device_ids {
        if targets.iter().any(|(t, _)| t == d) {
            continue;
        }
        if let Ok(Some((owner, _))) = app.db.device(d) {
            if app.db.user_org(&owner).ok().flatten().as_deref() == Some(org.as_str()) {
                targets.push((d.clone(), owner));
            }
        }
    }
    let peers = app.db.people_in_org(&org).map_or(0, |p| p.len() as i64);
    let now = app.effects.clock.now().0;
    let limits = crate::db::KpClaimLimits {
        per_hour: KP_CLAIM_PER_HOUR,
        pair_per_day: KP_CLAIM_PAIR_PER_DAY,
        owner_pair_per_day: KP_OWNER_GROUPS + peers,
        target_per_day: KP_CLAIM_TARGET_PER_DAY,
    };
    match app.db.kp_claim(&who.user, &targets, now, &limits) {
        Ok(Some(got)) => {
            for (device, owner, remaining) in &got.low {
                send_low(app, owner, device, *remaining);
            }
            Some(kp_answer(got.items))
        }
        // 다시 될 시각을 `until` 로(g025 11-04) — 클라이언트가 짧으면 기다리고 길면 그 변경을 실패로 끝낸다.
        Ok(None) => {
            let until = app
                .db
                .kp_claim_free_at(&who.user, &targets, now, &limits)
                .unwrap_or(now);
            let v = serde_json::json!({
                "t": "error", "code": "rate_limited", "message": "key_packages.claim",
                "until": lodelai_effects::UnixMillis(until).to_rfc3339().unwrap_or_default(),
            });
            Some(match serde_json::from_value::<ws::Frame>(v) {
                Ok(f) => ServerFrame::Ws(Box::new(f)),
                Err(_) => ServerFrame::Error {
                    code: crate::frames::ErrorCode::RateLimited,
                    message: "key_packages.claim".into(),
                    r#ref: None,
                },
            })
        }
        Err(_) => Some(protocol_error("key_packages.claim")),
    }
}

fn kp_answer(items: Vec<(String, Vec<u8>)>) -> ServerFrame {
    ServerFrame::Ws(Box::new(ws::Frame::KeyPackages(ws::KeyPackages {
        items: items
            .into_iter()
            .filter_map(|(device_id, data)| {
                Some(ws::KeyPackagesItemsItem {
                    device_id: device_id.parse().ok()?,
                    key_package: encoding::encode(&data).parse().ok()?,
                })
            })
            .collect(),
        t: ws::KeyPackagesT::KeyPackages,
    })))
}

/// 그 기기에 `key_packages.low{remaining}`(접속해 있으면).
pub fn send_low(app: &Relay, user: &str, device_id: &str, remaining: u64) {
    let f = ServerFrame::Ws(Box::new(ws::Frame::KeyPackagesLow(ws::KeyPackagesLow {
        remaining,
        t: ws::KeyPackagesLowT::KeyPackagesLow,
    })));
    app.conns.send_devices(user, &[device_id.to_owned()], &f);
}

/// 접속 직후: 한 번이라도 올린 기기(마지막 수단이 있음)의 보통 KeyPackage 가 20 아래면 `key_packages.low`(§3). 한 번도 올리지
/// 않은 기기는 MLS 클라이언트가 첫 접속에 스스로 올린다 — 옛 클라이언트에 모르는 프레임을 보내지 않게.
pub fn on_ready(app: &Relay, who: &Authed) {
    if let Ok((n, true)) = app.db.kp_state(&who.device_id) {
        if n < KP_LOW {
            send_low(app, &who.user, &who.device_id, n);
        }
    }
    // §5a: 비운 그룹이 남아 있으면 접속마다 다시 알린다(다시 잎이 되면 지워진다).
    send_rejoin(app, &who.user, &who.device_id);
    // §7: 받았던 일은 같은 자리로 다시, 새로 후보가 된 일은 줄 끝에.
    dispatch_duties(app, Some(&who.device_id));
}

// ------------------------------------------------------------------ devrevoke(§12-11 ⓐ)

/// 폐기 증명 `at` 허용 오차(±5분).
pub const REVOKE_PROOF_SKEW_MS: i64 = 5 * 60 * 1000;

/// `device.revoke` 의 증명 검사: 서명자 = 이 연결의 기기(폐기 안 됨), 대상 = 같은 사용자의 기기, `at` 이 지금 ±5분, 서명이 맞음.
/// 맞으면 저장할 증명(`at` 은 받은 문자열 그대로 — 서명 입력과 바이트가 같게).
pub fn revoke_proof(
    app: &Relay,
    who: &Authed,
    target: &str,
    at: String,
    sig: String,
) -> Option<crate::db::RevokeProof> {
    let (_, pk) = app.db.device(&who.device_id).ok().flatten()?;
    let owner = match app.db.device(target).ok().flatten() {
        Some((u, _)) => u,
        None => app.db.revoked_device(target).ok().flatten()?.0,
    };
    if owner != who.user {
        return None;
    }
    let when = lodelai_effects::UnixMillis::parse_rfc3339(&at).ok()?.0;
    if (when - app.effects.clock.now().0).abs() > REVOKE_PROOF_SKEW_MS {
        return None;
    }
    let key = lodelai_crypto::VerifyingKey::from_b64(&pk).ok()?;
    let ok = lodelai_crypto::devrevoke::verify(
        &key,
        &lodelai_crypto::devrevoke::Revoke {
            server: &app.config.server_name,
            device_id: target,
            at: &at,
        },
        &sig,
    );
    ok.then(|| crate::db::RevokeProof {
        at,
        signer: who.device_id.clone(),
        sig,
    })
}

// ------------------------------------------------------------------ duty(§7)

const TASK_ADD: &str = "add_device";
/// group 종류에서 표에서 빠진 사람의 잎을 모두 빼는 일(§12-13 ②, subject = 사용자 아이디 — 보낼 때 사람 주소로).
pub(crate) const TASK_REMOVE_USER: &str = "remove_user";

/// 기기가 새로 잎 자격을 얻었을 수 있을 때(devcert·폐기로 뿌리 바뀜): 그 사용자의 기기가 잎인 그룹마다, 자격 있는데 잎이
/// 아닌 기기에 add_device 를 남기고 나눠 준다.
pub fn refresh_add_duties(app: &Relay, user: &str) {
    let now = app.effects.clock.now().0;
    let eligible = eligible_devices(app, user);
    for g in app.db.groups_with_user_leaves(user).unwrap_or_default() {
        // 나간 사람의 잎은 remove_user 전까지 남는다 — 그 그룹에 그 사람 기기를 더 들이지 않는다(g025f 리뷰 🟡).
        if !app.db.may_rejoin(&g, user).unwrap_or(false) {
            continue;
        }
        let leaves = app.db.group_leaves(&g).unwrap_or_default();
        for d in eligible.iter().filter(|d| !leaves.contains(d)) {
            let _ = app.db.duty_add(&g, TASK_ADD, d, now);
        }
    }
    dispatch_duties(app, None);
}

/// 끊기 완료(#599 ①, 설계 리뷰 6500088945·6512635445): 그 사람이 잎이던 그룹 중 산 잎이 하나도 안 남은 그룹(남은 잎이 모두
/// 폐기된 기기)에는 add_device 를 낼 같은 사람 잎이 없다 — 잎 자격 있는 그 사람의 기기 **하나**에 `mls_rejoin` 표시 +
/// `rejoin_needed` 를 보내 external commit 으로 들게 한다. 하나가 들면 나머지는 add_device 일로 든다(여럿이 함께 들면 external
/// commit 이 헛돌고 한도를 먹는다). 고르는 순서: 지금 연결된 것 → 등록이 이른 것 → device_id. 연결된 기기가 없으면 가장 이른
/// 기기에 표시만(다음 접속 때 받는다). 산 잎이 남은 그룹은 add_device 길 그대로. 폐기 자리에서만 부른다(KeyPackage·확정 뒤의
/// `refresh_add_duties` 에선 부르지 않는다).
pub fn rejoin_orphaned(app: &Relay, user: &str) {
    let eligible = eligible_devices(app, user);
    // devices_of 는 (created_ms, device_id) 순이다.
    let ordered: Vec<String> = app
        .db
        .devices_of(user)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.device_id)
        .filter(|d| eligible.contains(d))
        .collect();
    let online = app.conns.online_devices(user);
    let Some(pick) = ordered
        .iter()
        .find(|d| online.contains(d))
        .or_else(|| ordered.first())
    else {
        return;
    };
    let now = app.effects.clock.now().0;
    let mut fresh = false;
    let live_mine = |d: &String| {
        app.db
            .device(d)
            .ok()
            .flatten()
            .is_some_and(|(u, _)| u == user)
    };
    for g in app.db.groups_with_user_leaves(user).unwrap_or_default() {
        if !app.db.may_rejoin(&g, user).unwrap_or(false) {
            continue;
        }
        let live_leaf = app
            .db
            .group_leaves(&g)
            .unwrap_or_default()
            .iter()
            .any(live_mine);
        // 확정 전 Commit 으로 그 사람의 산 기기가 드는 중이면(지금 끊기 — 옛 기기가 새 기기를 add 한 뒤 바로 자기를 끊음) 그
        // Welcome 으로 든다. 신호를 보내면 든 뒤 한 번 더 다시 들며 그 사이 글을 잃는다(35 mls_e2e 간헐 실패).
        let joining = app
            .db
            .mls_pending(&g)
            .ok()
            .flatten()
            .is_some_and(|p| p.leaves.iter().any(live_mine));
        if !live_leaf && !joining {
            fresh |= app.db.rejoin_mark(pick, &g, now).unwrap_or(false);
        }
    }
    if fresh {
        send_rejoin(app, user, pick);
    }
}

/// g025f B②(0.2.5): `reset` 올리기 = 이 기기가 로컬 MLS 데이터를 잃었다 — 그 기기가 아직 잎인 그룹은 열 수 없고 어느 그룹인지도
/// 모른다. 그 그룹마다 다시 들기 표시를 남기고 `rejoin_needed` 로 알린다(external commit 이 같은 서명 키의 옛 잎을 갈아 끼운다).
fn rejoin_own_leaves(app: &Relay, who: &Authed) {
    let now = app.effects.clock.now().0;
    let mut fresh = false;
    for g in app
        .db
        .groups_with_user_leaves(&who.user)
        .unwrap_or_default()
    {
        if app
            .db
            .group_leaves(&g)
            .unwrap_or_default()
            .contains(&who.device_id)
            && app.db.may_rejoin(&g, &who.user).unwrap_or(false)
        {
            fresh |= app.db.rejoin_mark(&who.device_id, &g, now).unwrap_or(false);
        }
    }
    if fresh {
        send_rejoin(app, &who.user, &who.device_id);
    }
}

/// g025f A: add_device 일을 할 기기(대상과 같은 사용자의 잎)가 하나도 접속해 있지 않은 채 이만큼 지나면 대상이 스스로 든다.
pub const UNSERVED_ADD_WAIT_MS: i64 = 60_000;

/// g025f A(0.2.5): 새 기기를 확인한 옛 기기가 바로 꺼지면 있던 1:1·그룹의 add_device 를 낼 기기가 없다(상대는 후보가 아니다) —
/// 일이 [`UNSERVED_ADD_WAIT_MS`] 넘게 남았고 후보가 지금 하나도 접속해 있지 않으면, 대상 기기에 그 그룹 다시 들기 표시를 남겨
/// external commit 으로 스스로 들게 한다. 대상이 이미 잎이거나 확정 전 Commit 으로 드는 중이면 건너뛴다. 옛 기기가 돌아와 먼저
/// Add 하면 표시는 그 잎이 되며 지워지고, 새 기기가 먼저 들면 옛 기기의 Add 는 Add 없이 끝난다(#806).
pub fn rejoin_unserved_adds(app: &Relay) {
    let now = app.effects.clock.now().0;
    // (그룹, 사용자)마다 후보 기기들 — 그중 하나만 표시한다(여럿이 함께 external commit 을 내면 헛돈다, rejoin_orphaned 와 같음).
    let mut picks: Vec<(String, String, Vec<String>)> = Vec::new();
    for (g, subject, created) in app.db.duties_of(TASK_ADD).unwrap_or_default() {
        if now.saturating_sub(created) < UNSERVED_ADD_WAIT_MS {
            continue;
        }
        let Some((user, _)) = app.db.device(&subject).ok().flatten() else {
            continue;
        };
        let served = duty_candidates(app, &g, TASK_ADD, &subject)
            .iter()
            .any(|(u, d)| app.conns.online_devices(u).contains(d));
        let joining = app
            .db
            .mls_pending(&g)
            .ok()
            .flatten()
            .is_some_and(|p| p.leaves.contains(&subject));
        if served
            || joining
            || app
                .db
                .group_leaves(&g)
                .unwrap_or_default()
                .contains(&subject)
            || !eligible_devices(app, &user).contains(&subject)
            || !app.db.may_rejoin(&g, &user).unwrap_or(false)
        {
            continue;
        }
        match picks.iter_mut().find(|(pg, pu, _)| *pg == g && *pu == user) {
            Some((_, _, ds)) => ds.push(subject),
            None => picks.push((g, user, vec![subject])),
        }
    }
    let mut fresh: Vec<(String, String)> = Vec::new();
    for (g, user, ds) in picks {
        // 그 사람의 기기 하나가 이미 표시를 받았으면 그 기기가 들고 나머지는 add_device 로 든다.
        let marked = app.db.rejoin_devices(&g).unwrap_or_default();
        if marked.iter().any(|d| {
            app.db
                .device(d)
                .ok()
                .flatten()
                .is_some_and(|(u, _)| u == user)
        }) {
            continue;
        }
        // 접속한 후보에게만 — 꺼진 기기에 표시하면 뒤에 다른 후보가 붙어도 '이미 표시됨'으로 멈춘다. 없으면 다음 주기에.
        let online = app.conns.online_devices(&user);
        let Some(pick) = ds.iter().find(|d| online.contains(d)).cloned() else {
            continue;
        };
        if app.db.rejoin_mark(&pick, &g, now).unwrap_or(false)
            && !fresh.iter().any(|(_, d)| *d == pick)
        {
            fresh.push((user, pick));
        }
    }
    for (u, d) in fresh {
        send_rejoin(app, &u, &d);
    }
}

/// 그 일을 할 수 있는 기기: add_device 는 대상과 같은 사용자의 다른 잎, remove_device 는 남은 잎(폐기 안 됨). (사용자, 기기)
pub(crate) fn duty_candidates(
    app: &Relay,
    group: &str,
    task: &str,
    subject: &str,
) -> Vec<(String, String)> {
    let owner = if task == TASK_ADD {
        match app.db.device(subject) {
            Ok(Some((u, _))) => Some(u),
            _ => return Vec::new(),
        }
    } else {
        None
    };
    app.db
        .group_leaves(group)
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d != subject)
        .filter_map(|d| {
            let (u, _) = app.db.device(&d).ok().flatten()?;
            let ok = owner.as_ref().is_none_or(|o| *o == u)
                && !(task == TASK_REMOVE_USER && u == subject);
            ok.then_some((u, d))
        })
        .collect()
}

/// 끝나지 않은 일을 접속한 후보에게 나눠 준다(§7). 처음 받는 후보들은 무작위로 섞어 rank 를 주고(device_id·접속 순서로 앞자리를
/// 고를 수 없게), 나중에 붙은 후보는 rank = 지금 접속한 다른 후보 수. `resend` 기기는 이미 받은 일도 같은 rank 로 다시 받는다.
pub fn dispatch_duties(app: &Relay, resend: Option<&str>) {
    for (g, task, subject) in app.db.duties().unwrap_or_default() {
        let online: Vec<(String, String)> = duty_candidates(app, &g, &task, &subject)
            .into_iter()
            .filter(|(u, d)| app.conns.online_devices(u).contains(d))
            .collect();
        let ranks = app.db.duty_ranks(&g, &task, &subject).unwrap_or_default();
        let mut fresh: Vec<&(String, String)> = online
            .iter()
            .filter(|(_, d)| !ranks.iter().any(|(r, _)| r == d))
            .collect();
        shuffle(app, &mut fresh);
        let base = (online.len() - fresh.len()) as u64;
        for (i, (u, d)) in fresh.into_iter().enumerate() {
            let rank = base + i as u64;
            let _ = app.db.duty_rank_put(&g, &task, &subject, d, rank);
            send_duty(app, u, d, &g, &task, &subject, rank);
        }
        if let Some(me) = resend {
            if let (Some((u, _)), Some((_, rank))) = (
                online.iter().find(|(_, d)| d == me),
                ranks.iter().find(|(d, _)| d == me),
            ) {
                send_duty(app, u, me, &g, &task, &subject, *rank);
            }
        }
    }
}

fn shuffle<T>(app: &Relay, v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        app.effects.rng.fill(&mut b);
        let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_duty(
    app: &Relay,
    user: &str,
    device: &str,
    group: &str,
    task: &str,
    subject: &str,
    rank: u64,
) {
    let (task, subject) = match task {
        TASK_ADD => (ws::DutyTask::AddDevice, subject.to_owned()),
        TASK_REMOVE_USER => (
            ws::DutyTask::RemoveUser,
            format!("{subject}@{}", app.config.server_name),
        ),
        _ => (ws::DutyTask::RemoveDevice, subject.to_owned()),
    };
    let Ok(group) = group.to_owned().try_into() else {
        return;
    };
    let f = ServerFrame::Ws(Box::new(ws::Frame::Duty(ws::Duty {
        group,
        rank,
        subject,
        t: ws::DutyT::Duty,
        task,
    })));
    app.conns.send_devices(user, &[device.to_owned()], &f);
}

/// 그 기기에 `rejoin_needed{groups}`(rejoin 표시가 있고 접속해 있으면, §5a). 그 사람이 나간 그룹은 빼고 보낸다(#816 ① — 표시는
/// 나갈 때 지우지만, 그 전 판이 남긴 표시도 다시 가지 않게).
pub fn send_rejoin(app: &Relay, user: &str, device_id: &str) {
    let groups: Vec<_> = app
        .db
        .rejoin_for(device_id)
        .unwrap_or_default()
        .into_iter()
        .filter(|g| app.db.may_rejoin(g, user).unwrap_or(false))
        .filter_map(|g| g.try_into().ok())
        .collect();
    if groups.is_empty() {
        return;
    }
    let f = ServerFrame::Ws(Box::new(ws::Frame::RejoinNeeded(ws::RejoinNeeded {
        groups,
        t: ws::RejoinNeededT::RejoinNeeded,
    })));
    app.conns.send_devices(user, &[device_id.to_owned()], &f);
}

/// `group_info.get{group}`(§5b): 그 그룹 멤버 사용자의 기기면 최신 GroupInfo, 아니거나 없는 그룹이면 `group` 만(같은 바이트 —
/// 있음·없음을 가르지 않음). 멤버 사용자 = 그룹 id 를 이루는 사용자(§2a·§6 — start 때 from·to 로 적어 둔 것).
pub fn group_info_get(app: &Relay, who: &Authed, group: &str) -> ServerFrame {
    let found = app
        .db
        .mls_group(group)
        .ok()
        .flatten()
        .and_then(|(kind, epoch, _, gi)| {
            let member = if kind == "group" {
                // group 종류(§12-13): 멤버 판정은 relay 그룹 표(16)의 지금 멤버.
                app.db
                    .group_view(group)
                    .ok()
                    .flatten()
                    .is_some_and(|v| v.members.contains(&who.user))
            } else {
                // pair·self: start 때 적은 사용자(§6 — 잎 상태와 상관없이). 옛 행(사용자 없음)은 self id 만 계산으로.
                let users = app
                    .db
                    .mls_group_users(group)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let self_id = encoding::decode(group, "group")
                    .ok()
                    .is_some_and(|b| b.as_slice() == self_group_id(&who.user));
                users.contains(&who.user) || self_id
            };
            member.then_some((epoch, gi))
        });
    let (epoch, group_info) = match found {
        // 큰 GroupInfo 는 붙잡아 둔 blob 참조로(프레임 상한, §5c). 아니면 프레임 안.
        Some((epoch, gi)) => (
            Some(epoch),
            match app.db.gi_pin(group).ok().flatten() {
                Some(p) => gi_blob_ref(&p).map(lodelai_protocol::message::MlsPayload::Blob),
                None => encoding::encode(&gi)
                    .parse()
                    .ok()
                    .map(lodelai_protocol::message::MlsPayload::Data),
            },
        ),
        None => (None, None),
    };
    let group = group.to_owned().try_into().ok();
    match group {
        Some(group) => ServerFrame::Ws(Box::new(ws::Frame::GroupInfo(ws::GroupInfo {
            epoch,
            group,
            group_info,
            t: ws::GroupInfoT::GroupInfo,
        }))),
        // 스키마 검사를 지난 프레임이라 오지 않는다.
        None => protocol_error("group_info.get"),
    }
}

fn gi_blob_ref(p: &crate::db::GiPin) -> Option<lodelai_protocol::message::MlsBlobRef> {
    Some(lodelai_protocol::message::MlsBlobRef {
        blob_id: p.blob_id.parse().ok()?,
        sha256: p.sha256.parse().ok()?,
        size: std::num::NonZeroU64::new(p.size)?,
    })
}

/// 30일 지난 Handshake(§5a): 받지 않은 기기마다 그 그룹을 비우고 rejoin 표시, 접속해 있으면 바로 알린다. 지운 기기 수.
pub fn expire_handshakes(app: &Relay) -> usize {
    let now = app.effects.clock.now().0;
    let Ok((marked, removed)) = app.db.expire_handshakes(now) else {
        return 0;
    };
    crate::blob::remove_files(app, &removed);
    for (u, d) in &marked {
        send_rejoin(app, u, d);
    }
    marked.len()
}

// ------------------------------------------------------------------ 그룹(§2a·§4·§6) — pair·self

use openmls::prelude::group_info::VerifiableGroupInfo;
use openmls::prelude::{
    Extensions, GroupContext, GroupEpoch, GroupId, LeafNodeIndex, ProcessedMessageContent,
    Proposal, ProposalStore, ProtocolMessage, PublicGroup, Sender,
};
use openmls_memory_storage::MemoryStorage;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::db::StoredHeader;
use crate::frames::{Header, Kind, MlsBytes, MlsWire, NackReason};
use crate::rules::{internal_error, nack, route, unroutable_nack};

/// §4-6 속도 상한.
pub const COMMITS_PER_HOUR: i64 = 30;
pub const COMMITS_PER_DAY: i64 = 1_000;
pub const RECOVERY_PER_HOUR: i64 = 60;
/// §12-11 ⓑ 응용 메시지 epoch 창: 지금 − 3 ~ 지금(`max_past_epochs`).
pub const APP_PAST_EPOCHS: u64 = 3;
/// Handshake 의 relay 보관은 §5a(기기마다 받지 않은 것 2 000개·64 MiB·30일) — expires_at 이 아니다.
pub const HANDSHAKE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 그룹 종류(§2a). group(묶음 16)은 16 이 develop 에 든 뒤.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Pair,
    SelfDevices,
}

impl GroupKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::SelfDevices => "self",
        }
    }
}

/// pair id(§2a): `SHA-256("lodelai-pair-v1" ‖ 0 ‖ min ‖ 0 ‖ max)`.
#[must_use]
pub fn pair_group_id(a: &str, b: &str) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(b"lodelai-pair-v1\0");
    h.update(lo.as_bytes());
    h.update(b"\0");
    h.update(hi.as_bytes());
    h.finalize().into()
}

/// self id(§2a): `SHA-256("lodelai-self-v1" ‖ 0 ‖ user)`.
#[must_use]
pub fn self_group_id(user: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lodelai-self-v1\0");
    h.update(user.as_bytes());
    h.finalize().into()
}

/// 보낸·받는 사용자로 정해지는 그룹(§6): (종류, id 바이트, 멤버 사용자).
fn expected_group(from_user: &str, to_user: &str) -> (GroupKind, [u8; 32], Vec<String>) {
    if from_user == to_user {
        (
            GroupKind::SelfDevices,
            self_group_id(from_user),
            vec![from_user.to_owned()],
        )
    } else {
        (
            GroupKind::Pair,
            pair_group_id(from_user, to_user),
            vec![from_user.to_owned(), to_user.to_owned()],
        )
    }
}

/// openmls 저장 값(공개 상태)을 한 덩어리로: (u32 키 길이, 키, u32 값 길이, 값)… 키 순.
fn save_storage(s: &MemoryStorage) -> Vec<u8> {
    let map = s
        .values
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut keys: Vec<&Vec<u8>> = map.keys().collect();
    keys.sort();
    let mut out = Vec::new();
    for k in keys {
        let v = &map[k];
        out.extend_from_slice(&(k.len() as u32).to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn load_storage(b: &[u8]) -> Option<MemoryStorage> {
    let s = MemoryStorage::default();
    {
        let mut map = s
            .values
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut i = 0;
        let take = |i: &mut usize| -> Option<Vec<u8>> {
            let n = u32::from_be_bytes(b.get(*i..*i + 4)?.try_into().ok()?) as usize;
            let v = b.get(*i + 4..*i + 4 + n)?.to_vec();
            *i += 4 + n;
            Some(v)
        };
        while i < b.len() {
            let k = take(&mut i)?;
            let v = take(&mut i)?;
            map.insert(k, v);
        }
    }
    Some(s)
}

/// 잎 기기 목록(Credential identity = device_id) — 잎 자리 순.
pub(crate) fn leaves(pg: &PublicGroup) -> Vec<(LeafNodeIndex, String)> {
    pg.members()
        .filter_map(|m| {
            let c = BasicCredential::try_from(m.credential).ok()?;
            Some((m.index, String::from_utf8(c.identity().to_vec()).ok()?))
        })
        .collect()
}

/// 잎 자격(§2b): 디렉터리의 폐기 안 된 기기, 그 사용자가 `users` 안, 잎 서명 키 = 디렉터리 ed25519, devcert 사슬이 뿌리에
/// 닿음(뿌리 = 등록이 가장 이른 devcert 없는 폐기 안 된 기기). `joining` 은 같은 Commit 으로 함께 드는 그 사용자의 기기(사슬 고리).
pub(crate) fn leaf_ok(
    app: &Relay,
    device_id: &str,
    sig_key: &[u8],
    users: &[String],
    joining: &[String],
) -> bool {
    let Ok(Some((user, pk))) = app.db.device(device_id) else {
        return false;
    };
    if !users.contains(&user) {
        return false;
    }
    if encoding::decode(&pk, "ed25519").ok().as_deref() != Some(sig_key) {
        return false;
    }
    let _ = joining;
    eligible_devices(app, &user).iter().any(|d| d == device_id)
}

/// 그 사용자의 잎 자격 있는 기기(§2b 3, c53989c0·e73b25bd): 마디 = 폐기 안 된 기기 + 증명 폐기 기기(고리), 화살표 = 보관된
/// devcert(서명자 → 대상). 뿌리 후보 = 자기·아래에 산 기기가 있는 마디(들어오는 화살표 있어도 — #489), 뿌리 = 후보 중 등록이 가장 이른 것
/// (같으면 device_id). 잎 자격 = 뿌리에서 닿는 산 기기. 서명은 저장 때 검사했으므로 relay 는 다시 보지 않는다.
pub(crate) fn eligible_devices(app: &Relay, user: &str) -> Vec<String> {
    root_graph(app, user).0
}

/// 디렉터리에 실을 증명 폐기(설계 ⑥ 권고 ②): 아래로 산 기기에 닿는 마디만 — 닿지 않는 마디는 뿌리 후보도, 경로의 고리도
/// 못 되므로 빼도 계산이 같다(끝없이 쌓이지 않게).
pub fn needed_revocations(app: &Relay, user: &str) -> Vec<crate::db::RevocationRow> {
    let keep = root_graph(app, user).1;
    app.db
        .revocations_of(user)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| keep.contains(&r.device_id))
        .collect()
}

/// (잎 자격 있는 산 기기, 아래로 산 기기에 닿는 증명 폐기 마디).
fn root_graph(app: &Relay, user: &str) -> (Vec<String>, std::collections::HashSet<String>) {
    let (Ok(live), Ok(revoked), Ok(certs)) = (
        app.db.devices_of(user),
        app.db.revocations_of(user),
        app.db.device_certs_of(user),
    ) else {
        return Default::default();
    };
    let live: Vec<(&str, i64)> = live
        .iter()
        .map(|d| (d.device_id.as_str(), d.created_ms))
        .collect();
    let revoked: Vec<(&str, i64)> = revoked
        .iter()
        .map(|r| (r.device_id.as_str(), r.created_ms))
        .collect();
    let certs: Vec<(&str, &str)> = certs
        .iter()
        .map(|(t, s, _)| (t.as_str(), s.as_str()))
        .collect();
    root_graph_of(&live, &revoked, &certs)
}

/// [`root_graph`] 의 계산(코어 `mls_rules::roots` 와 같은 규칙, 같은 시험 표). `live`·`revoked` = (기기, 등록 ms),
/// `certs` = (대상, 서명자). 뿌리 후보 = 자기·아래에 산 기기가 있는 마디 — 들어오는 화살표가 있어도(#489, 자동 재서명으로
/// 내 기기끼리 서로 서명해 순환이 보통이다).
fn root_graph_of(
    live: &[(&str, i64)],
    revoked: &[(&str, i64)],
    certs: &[(&str, &str)],
) -> (Vec<String>, std::collections::HashSet<String>) {
    use std::collections::{HashMap, HashSet};
    // id → (등록 시각, 살아 있나)
    let mut nodes: HashMap<&str, (i64, bool)> =
        live.iter().map(|&(id, at)| (id, (at, true))).collect();
    for &(id, at) in revoked {
        nodes.entry(id).or_insert((at, false));
    }
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for &(target, signer) in certs {
        if target == signer || !nodes.contains_key(target) || !nodes.contains_key(signer) {
            continue;
        }
        edges.entry(signer).or_default().push(target);
    }
    let below = |from: &str| -> HashSet<String> {
        let mut seen = HashSet::from([from.to_owned()]);
        let mut stack = vec![from.to_owned()];
        while let Some(n) = stack.pop() {
            for t in edges.get(n.as_str()).into_iter().flatten() {
                if seen.insert((*t).to_owned()) {
                    stack.push((*t).to_owned());
                }
            }
        }
        seen
    };
    let alive = |n: &String| nodes.get(n.as_str()).is_some_and(|x| x.1);
    let alive_below: HashSet<String> = revoked
        .iter()
        .map(|&(id, _)| id.to_owned())
        .filter(|id| below(id).iter().any(alive))
        .collect();
    let mut best: Option<(i64, &str, HashSet<String>)> = None;
    for (&id, &(added, _)) in &nodes {
        let reach = below(id);
        if !reach.iter().any(alive) {
            continue;
        }
        if best.as_ref().is_none_or(|(a, b, _)| (added, id) < (*a, *b)) {
            best = Some((added, id, reach));
        }
    }
    let mut out: Vec<String> = best
        .map(|(_, _, reach)| reach.into_iter().filter(alive).collect())
        .unwrap_or_default();
    out.sort();
    (out, alive_below)
}

/// MLS 본문 send(§4·§6). 신원·서명·재생 검사는 이미 지났다.
#[allow(clippy::too_many_arguments)]
pub fn handle_send(
    app: &Relay,
    who: &Authed,
    h: &Header,
    mut message: Value,
    to_raw: String,
    from_raw: String,
    expires_ms: i64,
) -> ServerFrame {
    let Some(m) = h.mls.as_ref() else {
        return internal_error();
    };
    // group 종류(§12-13): 그룹 주소·헤더 group·kind group 은 그룹 표(16)와 2단계 확정(§4-7)으로.
    if h.kind == Kind::Group || h.to.is_group() || h.group.is_some() {
        return crate::mls_group::handle_send(app, who, h, message, to_raw, from_raw, expires_ms);
    }
    // 사람 관계: 응용 메시지는 지금 규칙(조직·차단·세션·등급…) 그대로, Handshake 는 pair 면 같은 조직·차단 없음·받을 기기.
    let peer_ok = if h.kind == Kind::Mls {
        handshake_peer_ok(app, who, h)
    } else {
        route(app, who, h, &to_raw, None).is_ok()
    };
    let (kind, gid, users) = expected_group(&who.user, &h.to.user);
    if !peer_ok || m.group != encoding::encode(&gid) {
        return unroutable_nack(&h.msg_id);
    }
    // 그룹마다 한 줄(§4 — 같은 epoch 의 Commit 둘이 끼어들지 않게).
    let _order = app
        .mls_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // §5c: Handshake 의 blob 칸 — 묶을 수 있는지 보고, relay 가 쓰는 칸(payload·group_info)은 읽어 프레임 안 바이트로 바꾼다.
    let (hr, attach, gi_pin) = match resolve_blobs(app, who, h) {
        Ok(r) => r,
        Err(f) => return f,
    };
    let h = &hr;
    let mut outdated = Vec::new();
    let mut orphan_mark = false;
    let (targets, rejoined) = match m.wire {
        MlsWire::Start => return start(app, who, h, kind, &gid, &users, gi_pin.as_ref()),
        MlsWire::Commit => match commit(app, who, h, &gid, &users, gi_pin.as_ref(), &attach) {
            Ok(t) => t,
            Err(f) => return f,
        },
        MlsWire::App => match app_targets(app, who, h, &gid) {
            Ok((t, orphan)) => {
                if orphan {
                    orphan_mark = true;
                }
                // 거두기·고치기(§12-18 — 1:1 도 같은 꼴): 원 메시지의 아직 안 받은 몫을 지운다.
                if let Err(f) = crate::rules::mls_withdraw(app, who, h) {
                    return f;
                }
                // #598 ②: 판 10 글은 판 9 기기에 전하지 않는다.
                let (t, old) = crate::rules::split_outdated(app, h, t, |(_, d)| d.as_str());
                outdated = old;
                (t, Vec::new())
            }
            Err(f) => return f,
        },
    };
    // 저장 후 잎 배달. 응용 메시지는 7일, Handshake 는 §5a(30일 — expires_at 이 아님).
    let now = app.effects.clock.now().0;
    // g025g(0.2.5): pair 에 받는 사람의 새 잎이 들었다 — 그 전에 봉인돼 그 사람 어느 기기에도 아직 닿지 않은 상대의 글을 기기 바뀜
    // 실패로 알린다(보낸 쪽이 같은 msg_id 로 다시 보내면 #577 길로 옛 봉투를 지우고 새 잎에 간다). Commit 배달보다 먼저.
    if kind == GroupKind::Pair && !rejoined.is_empty() {
        mark_undelivered_before_join(app, &users, &rejoined, now);
    }
    let keep = if h.kind == Kind::Mls {
        now.saturating_add(HANDSHAKE_RETENTION_MS)
    } else {
        expires_ms.min(now.saturating_add(crate::rules::MAX_RETENTION_MS))
    };
    // #577 §9 ②: 받는 기기가 바뀌어 실패를 알린 글의 다시 보내기 — 받을 잎이 정해졌으니 옛 봉투를 지우고 새로 저장한다.
    // 아래 '모두 판 9' 이른 return 보다 앞(그룹과 같은 순서) — 뒤면 옛 봉투·표시가 남아 v9 다시 보내기가 곁 표로만 가고 같은 글이
    // 기기 바뀜 다시 보내기로 한 번 더 온다.
    if h.kind != Kind::Mls
        && app
            .db
            .device_changed_resend(&h.msg_id, &who.user)
            .unwrap_or(false)
    {
        tracing::info!(msg_id = %h.msg_id, "받는 기기가 바뀐 글 다시 받음");
    }
    // #598 ②: 받는 사람 기기가 모두 판 9 면 봉투를 남기지 않는다 — 같은 msg_id 의 v9 다시 보내기가 보통 길로 모두에게 간다.
    // 반응(#626)은 v9 다시 보내기가 없으니 내 다른 기기 몫이 있으면 저장한다.
    if !outdated.is_empty()
        && !targets.iter().any(|(u, _)| *u != who.user)
        && (h.kind != Kind::Reaction || targets.is_empty())
    {
        crate::rules::mark_outdated(app, who, h, &outdated, keep);
        return ServerFrame::Ack {
            msg_id: h.msg_id.clone(),
            group_seq: None,
        };
    }
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
        expires_ms: keep,
        env_state: lodelai_statechart::envelope_server::INITIAL
            .as_str()
            .to_owned(),
        sender_view: lodelai_statechart::request_sender_view::State::Stored
            .as_str()
            .to_owned(),
        abort_reason: None,
    };
    // Handshake 는 §5a 보관 상한 안에서(rejoin 표시가 있는 기기는 빼고, 넘친 기기는 오래된 그룹부터 비움).
    let stored = if h.kind == Kind::Mls {
        app.db
            .store_handshake(
                &header,
                &message.to_string(),
                &m.group,
                &targets,
                &rejoined,
                &attach,
                app.config.handshake_cap,
                now,
            )
            .map(|s| {
                crate::blob::remove_files(app, &s.removed_blobs);
                (s.targets, s.marked)
            })
    } else {
        app.db
            .store_envelope_to(&header, &message.to_string(), &targets, &h.blobs)
            .map(|()| (targets, Vec::new()))
    };
    let (targets, marked) = match stored {
        Ok(t) => t,
        Err(crate::db::DbError::Conflict) => return unroutable_nack(&h.msg_id),
        Err(crate::db::DbError::BlobUnavailable) => {
            return nack(&h.msg_id, NackReason::BlobUnavailable)
        }
        Err(_) => return internal_error(),
    };
    for (u, d) in &marked {
        send_rejoin(app, u, d);
    }
    // 0.2.6 #809: 다시 든 기기의 못 엶 보고를 알릴 때가 됐을 수 있다.
    if !rejoined.is_empty() {
        crate::rules::notify_unreadable(app);
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
    // #577: 기기가 바뀌는 중인 받는 사람의 몫 — 보낸 사람에게 기기 바뀜 실패(ack 뒤에 ws 가 알린다), 새 잎이 들면 다시 온다.
    if orphan_mark {
        let _ = app.db.device_changed_mark(&h.msg_id, &who.user, now, keep);
    }
    let frame = ServerFrame::Deliver {
        message,
        group_seq: None,
    };
    let mut by_user: Vec<(&str, Vec<String>)> = Vec::new();
    for (u, d) in &targets {
        match by_user.iter_mut().find(|(x, _)| x == u) {
            Some((_, v)) => v.push(d.clone()),
            None => by_user.push((u.as_str(), vec![d.clone()])),
        }
    }
    for (u, ds) in by_user {
        app.conns.send_devices(u, &ds, &frame);
    }
    ServerFrame::Ack {
        msg_id: h.msg_id.clone(),
        group_seq: None,
    }
}

/// [`handle_send`] 의 g025g 표시 — 새 잎마다 그 주인 앞 상대 글 중 아직 아무 기기에도 닿지 않은 것.
fn mark_undelivered_before_join(app: &Relay, users: &[String], rejoined: &[String], now: i64) {
    let mut any = false;
    for d in rejoined {
        let Some((owner, _)) = app.db.device(d).ok().flatten() else {
            continue;
        };
        let Some(sender) = users.iter().find(|u| **u != owner) else {
            continue;
        };
        for (msg_id, expires) in app
            .db
            .undelivered_before_join(&owner, sender, d)
            .unwrap_or_default()
        {
            if app
                .db
                .device_changed_mark(&msg_id, sender, now, expires)
                .is_ok()
            {
                tracing::info!(msg_id, "새 잎이 들기 전 글 — 기기 바뀜으로 알림");
                any = true;
            }
        }
    }
    if any {
        crate::recovery::notify_device_changed(app);
    }
}

/// §5c: Handshake 본문의 blob 칸. 묶을 수 없으면(보낸 사용자가 올린·묶이지 않은·길이 같은 것이 아님) `nack blob_unavailable`,
/// payload·group_info blob 의 길이·해시가 틀리면 `invalid_commit`. 돌려주는 값: payload·group_info 를 프레임 안 바이트로 바꾼
/// 머리, 이 Handshake 에 묶을 blob, group_info 가 blob 이면 그 참조(그룹의 지금 GroupInfo 로 붙잡음). 응용 메시지는 그대로.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
pub(crate) fn resolve_blobs(
    app: &Relay,
    who: &Authed,
    h: &Header,
) -> Result<(Header, Vec<String>, Option<crate::db::GiPin>), ServerFrame> {
    let m = h.mls.as_ref().expect("mls");
    let refs: Vec<(String, u64)> = [&m.payload, &m.group_info, &m.welcome]
        .into_iter()
        .flatten()
        .filter_map(|b| match b {
            MlsBytes::Blob { blob_id, size, .. } => Some((blob_id.clone(), *size)),
            MlsBytes::Data(_) => None,
        })
        .collect();
    if refs.is_empty() {
        return Ok((h.clone(), Vec::new(), None));
    }
    match app.db.mls_blobs_bindable(&who.user, &refs) {
        Ok(true) => {}
        Ok(false) => return Err(nack(&h.msg_id, NackReason::BlobUnavailable)),
        Err(_) => return Err(internal_error()),
    }
    let read = |b: &Option<MlsBytes>| -> Result<Option<MlsBytes>, ServerFrame> {
        match b {
            Some(MlsBytes::Blob {
                blob_id,
                size,
                sha256,
            }) => crate::blob::read_verified(app, blob_id, *size, sha256)
                .map(|d| Some(MlsBytes::Data(d)))
                .ok_or_else(|| nack(&h.msg_id, NackReason::InvalidCommit)),
            other => Ok(other.clone()),
        }
    };
    let gi_pin = match &m.group_info {
        Some(MlsBytes::Blob {
            blob_id,
            size,
            sha256,
        }) => Some(crate::db::GiPin {
            blob_id: blob_id.clone(),
            size: *size,
            sha256: sha256.clone(),
        }),
        _ => None,
    };
    let mut hr = h.clone();
    if let Some(mm) = hr.mls.as_mut() {
        mm.payload = read(&m.payload)?;
        mm.group_info = read(&m.group_info)?;
    }
    Ok((hr, refs.into_iter().map(|(b, _)| b).collect(), gi_pin))
}

/// Handshake 의 사람 관계(§6): self 는 나, pair 는 같은 조직·차단 없음·받을 기기가 있는 사람.
fn handshake_peer_ok(app: &Relay, who: &Authed, h: &Header) -> bool {
    if h.to.server != app.config.server_name || h.to.slug.is_some() {
        return false;
    }
    if h.to.user == who.user {
        return true;
    }
    let to_org = app.db.user_org(&h.to.user).ok().flatten();
    let from_org = app.db.user_org(&who.user).ok().flatten();
    to_org.is_some()
        && to_org == from_org
        && !app.db.is_blocked(&h.to.user, &who.user).unwrap_or(true)
        && app.db.devices_of(&h.to.user).is_ok_and(|d| !d.is_empty())
}

/// GroupInfo 바이트(MLSMessage) → 검증 전 GroupInfo.
pub(crate) fn group_info_in(b: &[u8]) -> Option<VerifiableGroupInfo> {
    let msg = MlsMessageIn::tls_deserialize_exact(b).ok()?;
    match msg.extract() {
        MlsMessageBodyIn::GroupInfo(g) => Some(g),
        _ => None,
    }
}

/// start(epoch 0, §4 시작·§2a): GroupInfo(트리 포함)로 공개 상태를 만든다. 잎은 보낸 기기 하나. pair·self 는 한 번만.
fn start(
    app: &Relay,
    who: &Authed,
    h: &Header,
    kind: GroupKind,
    gid: &[u8; 32],
    users: &[String],
    gi_pin: Option<&crate::db::GiPin>,
) -> ServerFrame {
    let m = h.mls.as_ref().expect("mls");
    let id = encoding::encode(gid);
    if app.db.mls_group(&id).ok().flatten().is_some() {
        return nack(&h.msg_id, NackReason::EpochTaken);
    }
    let Some((storage, gi)) = verify_start(app, who, m, gid, users) else {
        return nack(&h.msg_id, NackReason::InvalidCommit);
    };
    match app.db.mls_group_start(
        &id,
        kind.as_str(),
        users,
        &storage,
        &gi,
        gi_pin.map(|p| (p, h.msg_id.as_str(), who.user.as_str())),
        std::slice::from_ref(&who.device_id),
        app.effects.clock.now().0,
    ) {
        Ok(true) => {
            // 잎 자격이 그룹보다 먼저 생긴 내 다른 기기(devcert 를 처리할 때 이 그룹이 없어 일이 안 생겼다)도 들게 — group 종류의
            // 확정 뒤와 같다(§12-24, #490).
            for u in users {
                refresh_add_duties(app, u);
            }
            ServerFrame::Ack {
                msg_id: h.msg_id.clone(),
                group_seq: None,
            }
        }
        Ok(false) => nack(&h.msg_id, NackReason::EpochTaken),
        Err(crate::db::DbError::BlobUnavailable) => nack(&h.msg_id, NackReason::BlobUnavailable),
        Err(_) => internal_error(),
    }
}

/// 그룹 id 바이트의 저장 열쇠: pair·self(32 B)는 base64url, group 은 gid 문자열 그대로(§2a — 헤더 `mls_group` 과 같은 꼴).
pub(crate) fn group_key(gid: &[u8]) -> String {
    if gid.len() == 32 {
        encoding::encode(gid)
    } else {
        String::from_utf8_lossy(gid).into_owned()
    }
}

/// epoch 0 GroupInfo 검사(§4 시작): 그룹 id·epoch 0, 트리로 공개 상태를 만들 수 있고 ciphersuite 맞음, 잎은 보낸 기기 하나이고
/// 잎 자격(`users`). 돌려주는 값: (공개 상태 저장 값, GroupInfo 바이트).
pub(crate) fn verify_start(
    app: &Relay,
    who: &Authed,
    m: &crate::frames::MlsHead,
    gid: &[u8],
    users: &[String],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let gi_bytes = m.group_info.as_ref()?.data()?;
    let vgi = group_info_in(gi_bytes)?;
    if vgi.group_id().as_slice() != gid || vgi.epoch() != GroupEpoch::from(0) || m.epoch != 0 {
        return None;
    }
    let tree = vgi.extensions().ratchet_tree()?.ratchet_tree().clone();
    let storage = MemoryStorage::default();
    let crypto = RustCrypto::default();
    let (pg, _) =
        PublicGroup::from_external(&crypto, &storage, tree, vgi, ProposalStore::new()).ok()?;
    if pg.group_context().ciphersuite() != CIPHERSUITE {
        return None;
    }
    let members: Vec<_> = pg.members().collect();
    let [only] = members.as_slice() else {
        return None;
    };
    let c = BasicCredential::try_from(only.credential.clone()).ok()?;
    if c.identity() != who.device_id.as_bytes()
        || !leaf_ok(app, &who.device_id, &only.signature_key, users, &[])
        || !gi_matches(&pg, group_info_in(gi_bytes)?, &who.device_id)
    {
        return None;
    }
    Some((save_storage(&storage), gi_bytes.to_vec()))
}

/// GroupInfo 가 이 공개 상태의 결과인가(§12-18): `device` 잎의 키로 서명이 맞고 group context(epoch·tree_hash·
/// confirmed_transcript_hash·extensions)가 바이트로 같다. 아니면 relay 가 다시 들어오는 기기에 갈라진 상태를 내준다.
fn gi_matches(pg: &PublicGroup, vgi: VerifiableGroupInfo, device: &str) -> bool {
    use openmls::ciphersuite::signable::Verifiable as _;
    use openmls::prelude::tls_codec::Serialize as _;
    let Some(key) = pg
        .members()
        .find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .is_ok_and(|c| c.identity() == device.as_bytes())
        })
        .map(|m| m.signature_key)
    else {
        return false;
    };
    let Ok(pk) = openmls::prelude::OpenMlsSignaturePublicKey::new(
        key.into(),
        openmls::prelude::SignatureScheme::ED25519,
    ) else {
        return false;
    };
    let Ok(gi) = vgi.verify(&RustCrypto::default(), &pk) else {
        return false;
    };
    match (
        gi.group_context().tls_serialize_detached(),
        pg.group_context().tls_serialize_detached(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// 그 그룹의 공개 상태와 지금 epoch.
pub(crate) fn load(app: &Relay, gid: &[u8]) -> Option<(PublicGroup, MemoryStorage, u64)> {
    let (_, epoch, storage, _) = app.db.mls_group(&group_key(gid)).ok().flatten()?;
    let storage = load_storage(&storage)?;
    let pg = PublicGroup::load(&storage, &GroupId::from_slice(gid))
        .ok()
        .flatten()?;
    Some((pg, storage, epoch))
}

/// 배달 대상 (사용자, 기기).
type Targets = Vec<(String, String)>;

/// §4 1~6 을 지난 Commit(아직 저장 전). 사람 단위 규칙(Remove 대상·GCE)은 호출자가 본다.
pub(crate) struct Checked {
    /// 지금 epoch N(Commit 이 만들어진 epoch).
    pub epoch: u64,
    /// merge 뒤 공개 상태(저장 값).
    pub storage: Vec<u8>,
    /// epoch N+1 GroupInfo.
    pub gi: Vec<u8>,
    pub before: Vec<(LeafNodeIndex, String)>,
    pub new_leaves: Vec<(LeafNodeIndex, String)>,
    /// 이 Commit 의 Add 로 드는 기기.
    pub joining: Vec<String>,
    /// Remove 대상 기기.
    pub removed: Vec<String>,
    /// external commit(보낸 잎이 새로 듦).
    pub external: bool,
    /// external 이 자기 옛 잎을 뺌(복구 — 속도 셈이 따로).
    pub recovery: bool,
    /// GroupContextExtensions 제안의 새 extensions(있으면).
    pub gce: Option<Extensions<GroupContext>>,
    /// 지금(N) GroupContext extensions.
    pub old_extensions: Extensions<GroupContext>,
}

/// Commit 검사(§4 1~3·5·6): epoch, 보낸 잎 서명·= 인증 기기, Add 잎 자격(`users` 안), external 조건, 속도, Welcome 칸, merge 뒤
/// 새 GroupInfo. `users` = 잎이 될 수 있는 사용자.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
pub(crate) fn check_commit(
    app: &Relay,
    who: &Authed,
    h: &Header,
    gid: &[u8],
    users: &[String],
) -> Result<Checked, ServerFrame> {
    let m = h.mls.as_ref().expect("mls");
    let invalid = || nack(&h.msg_id, NackReason::InvalidCommit);
    let Some((mut pg, storage, epoch)) = load(app, gid) else {
        return Err(unroutable_nack(&h.msg_id));
    };
    // 1. epoch
    if m.epoch != epoch {
        return Err(nack(&h.msg_id, NackReason::StaleEpoch));
    }
    let crypto = RustCrypto::default();
    let Some(pm) = m
        .payload
        .as_ref()
        .and_then(MlsBytes::data)
        .and_then(|p| MlsMessageIn::tls_deserialize_exact(p).ok())
        .and_then(|msg| ProtocolMessage::try_from(msg).ok())
    else {
        return Err(invalid());
    };
    if pm.epoch() != GroupEpoch::from(epoch) {
        return Err(nack(&h.msg_id, NackReason::StaleEpoch));
    }
    let before = leaves(&pg);
    let old_extensions = pg.group_context().extensions().clone();
    // 2. 보낸 잎 서명(그룹 문맥 포함) — process_message.
    let Ok(processed) = pg.process_message(&crypto, pm) else {
        return Err(invalid());
    };
    let sender = processed.sender().clone();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(invalid());
    };
    // 보낸 잎 = 이 연결의 인증 기기(§4-2·§12-11 ⓔ). external 이면 들어오는 잎.
    let recovery = match sender {
        Sender::Member(idx) => {
            if !before.iter().any(|(i, d)| *i == idx && *d == who.device_id) {
                return Err(invalid());
            }
            false
        }
        Sender::NewMemberCommit => {
            // 5. external commit(pair·self): 들어오는 기기 = 인증 기기, 그 사용자는 id 의 사용자, 옛 잎(같은 기기)이 있으면 뺀다.
            let Some(leaf) = staged.update_path_leaf_node() else {
                return Err(invalid());
            };
            let Ok(c) = BasicCredential::try_from(leaf.credential().clone()) else {
                return Err(invalid());
            };
            if c.identity() != who.device_id.as_bytes()
                || !leaf_ok(
                    app,
                    &who.device_id,
                    leaf.signature_key().as_slice(),
                    users,
                    &[],
                )
            {
                return Err(invalid());
            }
            let old = before
                .iter()
                .find(|(_, d)| *d == who.device_id)
                .map(|(i, _)| *i);
            if let Some(old) = old {
                if !staged
                    .remove_proposals()
                    .any(|r| r.remove_proposal().removed() == old)
                {
                    return Err(invalid());
                }
            }
            old.is_some()
        }
        _ => return Err(invalid()),
    };
    // 3. Add 마다 잎 자격(§2b). 같은 Commit 으로 드는 기기 목록.
    let joining: Vec<String> = staged
        .add_proposals()
        .filter_map(|a| {
            let c = BasicCredential::try_from(
                a.add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential()
                    .clone(),
            )
            .ok()?;
            String::from_utf8(c.identity().to_vec()).ok()
        })
        .collect();
    for a in staged.add_proposals() {
        let kp = a.add_proposal().key_package();
        let leaf = kp.leaf_node();
        let Some(dev) = BasicCredential::try_from(leaf.credential().clone())
            .ok()
            .and_then(|c| String::from_utf8(c.identity().to_vec()).ok())
        else {
            return Err(invalid());
        };
        if kp.ciphersuite() != CIPHERSUITE
            || !leaf_ok(app, &dev, leaf.signature_key().as_slice(), users, &joining)
        {
            return Err(invalid());
        }
    }
    // 4. Remove 대상 기기(판단은 호출자 — pair·self 는 기기 단위, group 은 헤더 op 와 대조).
    let mut removed = Vec::new();
    for r in staged.remove_proposals() {
        let idx = r.remove_proposal().removed();
        let Some((_, dev)) = before.iter().find(|(i, _)| *i == idx) else {
            return Err(invalid());
        };
        removed.push(dev.clone());
    }
    let gce = staged.queued_proposals().find_map(|q| match q.proposal() {
        Proposal::GroupContextExtensions(p) => Some(p.extensions().clone()),
        _ => None,
    });
    // 6. 속도.
    let now = app.effects.clock.now().0;
    let gid_s = encoding::encode(gid);
    let Ok((hour, rec_hour, day)) = app.db.mls_commit_counts(&gid_s, &who.device_id, now) else {
        return Err(internal_error());
    };
    if (recovery && rec_hour >= RECOVERY_PER_HOUR)
        || (!recovery && (hour >= COMMITS_PER_HOUR || day >= COMMITS_PER_DAY))
    {
        return Err(nack(&h.msg_id, NackReason::RateLimited));
    }
    // Welcome 칸: Add 가 있으면 필수, 없으면 금지(§12).
    if joining.is_empty() != m.welcome.is_none() {
        return Err(invalid());
    }
    if pg.merge_commit(&storage, *staged).is_err() {
        return Err(invalid());
    }
    // 새 epoch 의 GroupInfo(§5b — 의무).
    let new_epoch = epoch + 1;
    let external = matches!(sender, Sender::NewMemberCommit);
    let Some(gi) = m.group_info.as_ref().and_then(MlsBytes::data) else {
        return Err(invalid());
    };
    let Some(vgi) = group_info_in(gi) else {
        return Err(invalid());
    };
    if vgi.group_id().as_slice() != gid
        || vgi.epoch() != GroupEpoch::from(new_epoch)
        || !gi_matches(&pg, vgi, &who.device_id)
    {
        return Err(invalid());
    }
    Ok(Checked {
        epoch,
        storage: save_storage(&storage),
        gi: gi.to_vec(),
        before,
        new_leaves: leaves(&pg),
        joining,
        removed,
        external,
        recovery,
        gce,
        old_extensions,
    })
}

/// commit(pair·self, §4 1~6). 통과하면 epoch 를 올리고 배달 대상(새 잎 목록 − 보낸 기기 − 폐기 기기)과 이 Commit 으로 잎이 새로
/// 된 기기(Add·external commit — §5a rejoin 표시를 지움)를 돌려준다.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
fn commit(
    app: &Relay,
    who: &Authed,
    h: &Header,
    gid: &[u8; 32],
    users: &[String],
    gi_pin: Option<&crate::db::GiPin>,
    attach: &[String],
) -> Result<(Targets, Vec<String>), ServerFrame> {
    let c = check_commit(app, who, h, gid, users)?;
    // 4(pair·self = 기기 단위): Remove 는 폐기된 기기의 잎, 또는 external 의 옛 자기 잎만. GCE 없음.
    let own_old = |d: &String| c.external && *d == who.device_id;
    if c.gce.is_some()
        || c.removed
            .iter()
            .any(|d| !own_old(d) && app.db.device(d).ok().flatten().is_some())
    {
        return Err(nack(&h.msg_id, NackReason::InvalidCommit));
    }
    let now = app.effects.clock.now().0;
    let leaf_ids: Vec<String> = c.new_leaves.iter().map(|(_, d)| d.clone()).collect();
    match app.db.mls_group_commit(
        &encoding::encode(gid),
        c.epoch,
        &c.storage,
        &c.gi,
        &who.device_id,
        c.recovery,
        (gi_pin, h.msg_id.as_str(), who.user.as_str()),
        attach,
        &leaf_ids,
        now,
    ) {
        Ok(Some(removed)) => crate::blob::remove_files(app, &removed),
        Ok(None) => return Err(nack(&h.msg_id, NackReason::StaleEpoch)),
        Err(crate::db::DbError::BlobUnavailable) => {
            return Err(nack(&h.msg_id, NackReason::BlobUnavailable))
        }
        Err(_) => return Err(internal_error()),
    }
    // 배달: 새 잎 목록(새 기기 포함 — Welcome 칸으로 들어옴)에서 보낸 기기·폐기 기기를 뺀다(§12-11 ⓒ).
    let mut rejoined = c.joining;
    if c.external {
        rejoined.push(who.device_id.clone());
    }
    Ok((deliverable(app, &c.new_leaves, &who.device_id), rejoined))
}

/// 응용 메시지(§5d·§12-11 ⓑⓒ): epoch 창 지금 − 3 ~ 지금, 보낸 기기는 지금 잎이고 폐기 안 됨. 대상 = 잎 − 보낸 기기 − 폐기.
#[allow(clippy::result_large_err)] // 거절 답 프레임을 그대로 돌려준다(한 번 쓰고 버림).
fn app_targets(
    app: &Relay,
    who: &Authed,
    h: &Header,
    gid: &[u8; 32],
) -> Result<(Vec<(String, String)>, bool), ServerFrame> {
    let m = h.mls.as_ref().expect("mls");
    let Some((pg, _, epoch)) = load(app, gid) else {
        return Err(unroutable_nack(&h.msg_id));
    };
    if m.epoch > epoch || m.epoch + APP_PAST_EPOCHS < epoch {
        return Err(nack(&h.msg_id, NackReason::StaleEpoch));
    }
    let ls = leaves(&pg);
    if !ls.iter().any(|(_, d)| *d == who.device_id) {
        return Err(unroutable_nack(&h.msg_id));
    }
    // 받을 잎이 없다(나 하나인 내 기기 그룹 등) — 받아 두면 보낸 쪽은 보냈다고 보고 글은 아무에게도 가지 않는다(#490).
    // 단 받는 사람의 기기가 바뀌는 중이면(#577 — 잎은 모두 끊겼고 새 기기가 아직 안 듦) 받아 두고 기기 바뀜 실패로 알린다.
    let targets = deliverable(app, &ls, &who.device_id);
    let orphan = device_changing(app, &ls, &who.user);
    if targets.is_empty() && !orphan {
        return Err(unroutable_nack(&h.msg_id));
    }
    Ok((targets, orphan))
}

/// #577 §9 ②(설계 리뷰 6493882795 🟡2): 이 잎 목록에 잎이 있는 (보낸 사람 말고) 사용자 중, 잎은 모두 폐기됐는데 폐기
/// 안 된 기기는 있는 사람이 있나 — 끊긴 뒤 새 기기가 아직 들지 않은 사이. 그 몫은 조용히 빠지지 않고 기기 바뀜 실패로 간다.
pub(crate) fn device_changing(app: &Relay, ls: &[(LeafNodeIndex, String)], sender: &str) -> bool {
    let mut users: Vec<(String, bool)> = Vec::new();
    for (_, d) in ls {
        let Some(u) = app.db.device_user(d).ok().flatten() else {
            continue;
        };
        if u == sender {
            continue;
        }
        let live = app.db.device(d).ok().flatten().is_some();
        match users.iter_mut().find(|(x, _)| *x == u) {
            Some((_, l)) => *l |= live,
            None => users.push((u, live)),
        }
    }
    users
        .iter()
        .any(|(u, live_leaf)| !live_leaf && app.db.devices_of(u).is_ok_and(|v| !v.is_empty()))
}

pub(crate) fn deliverable(
    app: &Relay,
    ls: &[(LeafNodeIndex, String)],
    sender: &str,
) -> Vec<(String, String)> {
    ls.iter()
        .filter(|(_, d)| d != sender)
        .filter_map(|(_, d)| app.db.device(d).ok().flatten().map(|(u, _)| (u, d.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::root_graph_of;

    fn leaves(
        live: &[(&str, i64)],
        revoked: &[(&str, i64)],
        certs: &[(&str, &str)],
    ) -> Vec<String> {
        root_graph_of(live, revoked, certs).0
    }

    // §2b 3 시험 표(#489) — 코어 mls_rules 와 같은 줄. certs = (대상, 서명자).
    #[test]
    fn 서로_서명한_순환도_뿌리가_있다() {
        assert_eq!(
            leaves(&[("a1", 1), ("a2", 2)], &[], &[("a2", "a1"), ("a1", "a2")]),
            ["a1", "a2"]
        );
    }

    #[test]
    fn 이른_기기를_늦은_기기가_확인해도_잎() {
        // A→C, C→B — B 가 C 보다 이른 등록.
        assert_eq!(
            leaves(
                &[("A", 1), ("B", 2), ("C", 3)],
                &[],
                &[("C", "A"), ("B", "C")]
            ),
            ["A", "B", "C"]
        );
    }

    #[test]
    fn 증명_폐기_뒤_devcert_없는_기기는_잎_아님() {
        let (out, keep) = root_graph_of(&[("B", 2), ("D2", 5)], &[("A", 1)], &[("B", "A")]);
        assert_eq!(out, ["B"]);
        assert!(keep.contains("A"));
    }

    #[test]
    fn 증명_없이_지운_뿌리_뒤엔_남은_이른_기기가_뿌리() {
        assert_eq!(
            leaves(&[("B", 2), ("C", 3)], &[], &[("C", "B"), ("B", "C")]),
            ["B", "C"]
        );
    }

    #[test]
    fn 늦은_기기가_뿌리를_서명해도_잎_아님() {
        assert_eq!(leaves(&[("A", 1), ("X", 9)], &[], &[("A", "X")]), ["A"]);
    }
}
