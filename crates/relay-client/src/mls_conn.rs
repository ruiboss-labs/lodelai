//! 연결 루프의 MLS 일(묶음 22 §3·§7): KeyPackage 올리기·채우기. 프레임만 만들어 돌려주고 보내기는 연결 루프가 한다 —
//! openmls·저장 잠금은 이 함수 안에서 끝난다(`.await` 너머로 쥐지 않음).

use lodelai_crypto::encoding;
use openmls::prelude::{LeafNodeParameters, MlsMessageOut};
use openmls_traits::OpenMlsProvider as _;
use serde_json::{json, Value};

use crate::conn::Mls;
use crate::mls;

/// 보통 KeyPackage 를 이만큼까지 둔다(relay 상한과 같음, §3).
pub const KP_TARGET: usize = 100;

/// 첫 KeyPackage 묶음을 relay 가 받았다는 표시(`mls_flags`).
pub const KP_PUBLISHED: &str = "kp_published";

/// 마지막 수단 KeyPackage 를 마지막으로 만든 시각(`mls_flags` 값). 없으면 [`KP_PUBLISHED`] 시각이 첫 마지막 수단 시각이다.
pub const KP_LAST_RESORT: &str = "kp_last_resort";

/// 마지막 수단을 만든 지 이만큼 넘으면 접속 때 미리 간다(#896). 수명은 90일(`mls::key_package`) — 60일 전에 붙은 기기는 남은
/// 유효가 늘 30일 넘고, 그보다 오래 비우면 relay 의 `low{last_resort:false}` 가 받는다.
pub const LAST_RESORT_ROTATE_MS: i64 = 60 * 24 * 60 * 60 * 1000;

fn kp_b64(m: &Mls, last_resort: bool) -> Option<String> {
    let b = mls::key_package(&m.provider, &m.signer, last_resort).ok()?;
    let out = MlsMessageOut::from(b.key_package().clone());
    mls::to_bytes(&out).ok().map(|v| encoding::encode(&v))
}

/// `n` 개(+ `last_resort` 면 마지막 수단 하나)를 만들어 저장하고 `key_packages.publish` 프레임을 돌려준다. 만들기·저장은
/// 트랜잭션 하나 — 실패하면 아무것도 남기지 않고 `None`. 마지막 수단을 실으면 그 시각([`KP_LAST_RESORT`])도 같은 트랜잭션에 적는다.
/// 옛 마지막 수단의 로컬 비밀은 지우지 않는다 — relay 가 바꾸기 전에 가져간 옛 것으로 만든 Welcome 이 뒤늦게 올 수 있다.
fn publish_frame(m: &Mls, n: usize, last_resort: bool, reset: bool, now_ms: i64) -> Option<String> {
    let t = m.provider.begin().ok()?;
    let items: Vec<String> = (0..n).map(|_| kp_b64(m, false)).collect::<Option<_>>()?;
    let last = if last_resort {
        let l = kp_b64(m, true)?;
        m.provider
            .storage()
            .put_flag_value(KP_LAST_RESORT, now_ms)
            .ok()?;
        Some(l)
    } else {
        None
    };
    t.commit().ok()?;
    let mut f = json!({"t": "key_packages.publish", "items": items});
    if let Some(l) = last {
        f["last_resort"] = Value::String(l);
    }
    if reset {
        f["reset"] = Value::Bool(true);
    }
    Some(f.to_string())
}

/// 접속 직후: 한 번도 올린 적 없으면(표시 없음) 보통 100 + 마지막 수단 하나. 올린 적 있으면 relay 가 모자랄 때 `low` 를 준다.
/// `reset`(relay 가 `kp_reset` 을 앎)이면 relay 에 남은 이 기기 것을 바꾸게 한다(g025f B) — 표시가 없다는 것은 이 기기가 처음이거나
/// 로컬 MLS 데이터를 잃었다는 것이다. 잃었으면 relay 에 남은 것은 이 기기가 열 수 없고, 올린 뒤 표시 전에 꺼졌으면 남은 것을
/// 지워도 이 묶음이 그 자리를 채운다.
#[must_use]
pub fn first_publish(m: &Mls, target: usize, reset: bool, now_ms: i64) -> Option<String> {
    let st = m.provider.storage();
    if st.flag(KP_PUBLISHED).unwrap_or(true) {
        return None;
    }
    // 든 그룹이 있으면 데이터를 잃은 것이 아니다(올린 뒤 표시 전에 꺼짐) — relay 가 그 그룹들에 다시 들기 표시를 남기지 않게.
    let reset = reset && st.conv_groups().is_ok_and(|g| g.is_empty());
    publish_frame(m, target, true, reset, now_ms)
}

/// 접속 직후([`first_publish`] 가 없을 때) 한 번: 마지막 수단을 만든 지 [`LAST_RESORT_ROTATE_MS`] 넘었으면 마지막 수단만 새로 올린다
/// (보통 것 0·`reset` 없음, #896). 90일 만료 전에 갈아 두어 오래 안 붙은 기기도 돌아오자마자 그룹에 넣을 수 있게. 연결 중 주기
/// 검사는 하지 않는다. 시계가 뒤로 갔으면(만든 시각이 지금보다 뒤) 갈지 않는다.
#[must_use]
pub fn rotate_last_resort(m: &Mls, now_ms: i64) -> Option<String> {
    let st = m.provider.storage();
    if !st.flag(KP_PUBLISHED).unwrap_or(false) {
        return None;
    }
    let at = match st.flag_at(KP_LAST_RESORT) {
        Ok(Some(at)) => at,
        Ok(None) => st.flag_at(KP_PUBLISHED).ok()??,
        Err(_) => return None,
    };
    (now_ms.saturating_sub(at) > LAST_RESORT_ROTATE_MS)
        .then(|| publish_frame(m, 0, true, false, now_ms))
        .flatten()
}

/// relay 가 첫 묶음을 처리했다(같은 연결에서 뒤에 보낸 요청의 답이 왔다) — 다음 접속부터 다시 올리지 않는다.
pub fn mark_published(m: &Mls, now_ms: i64) {
    if let Err(e) = m.provider.storage().set_flag(KP_PUBLISHED, now_ms) {
        tracing::warn!(error = %e, "KeyPackage 표시 실패");
    }
}

/// `key_packages.low{remaining, last_resort?}`: 보통 것을 `target` 까지 채운다. `last_resort: false` 면 relay 에 이 기기의 마지막 수단이
/// 없다 — 같은 묶음에 마지막 수단도 싣는다(#846: 첫 묶음을 처리하기 전에 연결이 끊겨 relay 에 하나도 없던 틈의 받침, 설계 리뷰).
#[must_use]
pub fn refill(m: &Mls, frame: &Value, target: usize, now_ms: i64) -> Option<String> {
    let remaining = frame.get("remaining").and_then(Value::as_u64)?;
    let n = target.saturating_sub(usize::try_from(remaining).unwrap_or(target));
    let last = frame.get("last_resort") == Some(&Value::Bool(false));
    (n > 0 || last)
        .then(|| publish_frame(m, n, last, false, now_ms))
        .flatten()
}

// ------------------------------------------------------------------ pair·self 대화(§2a·§7)

use lodelai_crypto::{sign_message, DeviceKeys, EnvelopeError};
use lodelai_effects::UnixMillis;
use openmls::prelude::{
    GroupId, KeyPackage, KeyPackageIn, MlsGroup, MlsMessageBodyIn, ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;

use crate::keys::DirView;
use crate::mls::{Kind, Received};
use crate::mls_rules::RuleCtx;

/// 대화의 MLS 그룹: 나와 상대가 같으면 내 기기 그룹(self), 아니면 pair(§2a), 그룹 주소면 group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conv {
    pub kind: Kind,
    /// pair·self 는 SHA-256 32 B, group 은 ULID 글자 26 B(§2a).
    pub gid: Vec<u8>,
    /// 그룹의 멤버 사용자(받는 쪽 재검사 `RuleCtx.members`).
    pub members: Vec<String>,
}

#[must_use]
pub fn conv(a: &str, b: &str) -> Conv {
    if a == b {
        Conv {
            kind: Kind::SelfDevices,
            gid: mls::self_group_id(a).to_vec(),
            members: vec![a.to_owned()],
        }
    } else {
        Conv {
            kind: Kind::Pair,
            gid: mls::pair_group_id(a, b).to_vec(),
            members: vec![a.to_owned(), b.to_owned()],
        }
    }
}

/// group 종류 대화(묶음 16 그룹, §2a): gid = ULID 글자. 멤버 사용자는 디렉터리의 모든 사람 — 누가 들어올 수 있는지는 그룹
/// 규칙(관리자·헤더 subject, h2)이 정하고 여기서는 잎 키·자격만 본다.
#[must_use]
pub fn group_conv(dir: &DirView, gid: &str) -> Conv {
    Conv {
        kind: Kind::Group,
        gid: gid.as_bytes().to_vec(),
        members: dir.leaf_users(),
    }
}

/// group 종류의 화면 상태(묶음 16 [`crate::GroupState`])를 MLS 그룹에서 만든다: 멤버 = 잎 기기의 사용자(디렉터리로, 사람 주소),
/// 관리자 = 0xF0A1, 이름·seq 는 `mls_group_meta`. 이 기기에 그 그룹이 없으면 `None`.
#[must_use]
pub fn group_state(m: &Mls, dir: &DirView, gid: &str, server: &str) -> Option<crate::GroupState> {
    use crate::mls_rules::Directory as _;
    let g = load(m, gid.as_bytes())?;
    let users = dir.users();
    let mut members: Vec<String> = Vec::new();
    for mem in g.members() {
        let Some(dev) = crate::mls_rules::device_of(&mem.credential) else {
            continue;
        };
        if let Some(u) = users
            .iter()
            .find(|u| dir.devices(u).iter().any(|d| d.device_id == dev))
        {
            let a = format!("{u}@{server}");
            if !members.contains(&a) {
                members.push(a);
            }
        }
    }
    let (name, seq, joined_seq) = m
        .provider
        .storage()
        .group_meta(gid.as_bytes())
        .ok()
        .flatten()
        .unwrap_or_default();
    Some(crate::GroupState {
        name,
        members,
        admins: mls::effective_admins(&g, server, |d| {
            users
                .iter()
                .find(|u| dir.devices(u).iter().any(|x| x.device_id == d))
                .cloned()
                .or_else(|| dir.former_user(d))
        }),
        seq,
        stale: false,
        waiting_trust: None,
        unconfirmed_changes: 0,
        history_hidden: history_hidden(m, gid, joined_seq),
        joined_seq,
    })
}

/// §7-47 받은 history 의 열쇠 — (그룹, 내가 든 seq) 마다 하나. 다시 들면 joined_seq 가 바뀌어 새 값을 받는다.
#[must_use]
pub fn history_key(gid: &str, joined_seq: u64) -> String {
    format!("history:{gid}:{joined_seq}")
}

/// 내가 든 뒤 처음 받은 history 값(없으면 `None`).
#[must_use]
pub fn history_hidden(m: &Mls, gid: &str, joined_seq: u64) -> Option<bool> {
    m.provider
        .storage()
        .flag_at(&history_key(gid, joined_seq))
        .ok()
        .flatten()
        .map(|v| v != 0)
}

/// §7-47 내가 낸 add 의 history(코어가 누를 때 정한 값) 열쇠 — 무효 뒤 다시 내도 같은 (그룹, 대상)이라 이어진다.
#[must_use]
pub fn add_history_key(gid: &str, subject: &str) -> String {
    format!("add_history:{gid}:{subject}")
}

/// 헤더 `mls_group` 값: group 은 ULID 글자 그대로, pair·self 는 32 B 의 base64url(§2a·§12).
#[must_use]
pub fn header_of(gid: &[u8]) -> String {
    if crate::mls_store::is_group_gid(gid) {
        String::from_utf8_lossy(gid).into_owned()
    } else {
        encoding::encode(gid)
    }
}

/// 저장된 그룹(없으면 `None`).
#[must_use]
pub fn load(m: &Mls, gid: &[u8]) -> Option<MlsGroup> {
    MlsGroup::load(m.provider.storage(), &GroupId::from_slice(gid))
        .ok()
        .flatten()
}

/// 처음 만들 때 넣을 기기: 대화 사용자(상대·나)의 잎 자격 있는 기기 중 이 기기 빼고(§7 '처음 보내기'). 디렉터리 기준이다 —
/// 옛 신뢰(held) 표시는 쓰지 않는다(설계 리뷰 ①).
#[must_use]
pub fn claim_targets(dir: &DirView, c: &Conv, my_device: &str) -> Vec<String> {
    use crate::mls_rules::Directory as _;
    let mut out = Vec::new();
    for user in &c.members {
        // 섞인 그룹으로만 아는 사람에게는 1:1 을 열지 않는다(#845 §7-14 — relay 도 can_reach 로 막음).
        if c.kind == crate::mls::Kind::Pair && dir.group_only(user) {
            continue;
        }
        for d in dir.devices(user) {
            if d.device_id != my_device
                && crate::mls_rules::leaf_ok(dir, user, &d.device_id, &d.ed25519)
                    == crate::mls_rules::Verdict::Ok
                && !out.contains(&d.device_id)
            {
                out.push(d.device_id);
            }
        }
    }
    out
}

/// `key_packages` 답 → Add 해도 되는 KeyPackage: 서명·꼴 검사를 지나고, Credential device_id 가 항목과 같고, **잎 서명 키가
/// 디렉터리의 그 기기 키이며 대화 사용자의 잎 자격이 있음**(relay 가 끼운 KeyPackage 로 MITM 막기 — 설계 리뷰 ①).
/// 어긋난 기기는 뺀다.
#[must_use]
pub fn key_packages(frame: &Value, ctx: &RuleCtx<'_>) -> Vec<KeyPackage> {
    let crypto = RustCrypto::default();
    frame
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|it| {
            let dev = it.get("device_id")?.as_str()?;
            let bytes = encoding::decode(it.get("key_package")?.as_str()?, "key_package").ok()?;
            let MlsMessageBodyIn::KeyPackage(kp) = mls::parse(&bytes).ok()?.extract() else {
                return None;
            };
            let kp: KeyPackage = KeyPackageIn::validate(kp, &crypto, ProtocolVersion::Mls10).ok()?;
            let id = openmls::prelude::BasicCredential::try_from(kp.leaf_node().credential().clone()).ok()?;
            if id.identity() != dev.as_bytes() {
                return None;
            }
            match ctx.leaf_verdict(dev, kp.leaf_node().signature_key().as_slice()) {
                crate::mls_rules::Verdict::Ok => Some(kp),
                v => {
                    tracing::warn!(device_id = dev, verdict = ?v, "디렉터리와 맞지 않는 KeyPackage — 뺌");
                    None
                }
            }
        })
        .collect()
}

/// 서명한 `send` 프레임.
fn send_frame(keys: &DeviceKeys, m: Value) -> Option<String> {
    let frame = sign_frame(keys, m)?;
    (frame.len() <= lodelai_protocol::constants::WS_MAX_FRAME_BYTES as usize).then_some(frame)
}

/// 서명한 `send` 프레임(크기 상한 없이 — group Handshake 는 크면 호출자가 blob 으로 옮긴다, §5c).
#[must_use]
pub fn sign_frame(keys: &DeviceKeys, mut m: Value) -> Option<String> {
    sign_message(&mut m, &keys.signing).ok()?;
    Some(json!({"t": "send", "message": m}).to_string())
}

fn b64(bytes: &[u8]) -> Value {
    json!({"data": encoding::encode(bytes)})
}

/// Handshake 메시지 머리: 보내는 기기·주소·msg_id·시각.
pub struct Head<'a> {
    pub keys: &'a DeviceKeys,
    pub from: &'a str,
    pub to: &'a str,
    pub msg_id: &'a str,
    pub now: UnixMillis,
}

/// Handshake 메시지(kind `mls`, §12-2): 나 → `to` 주소, 30일.
fn handshake(h: &Head<'_>, gid: &[u8], epoch: u64, body: Value) -> Option<String> {
    let Head {
        keys,
        from,
        to,
        msg_id,
        now,
    } = *h;
    let m = json!({
        "v": lodelai_protocol::PROTOCOL_MIN, // MLS Handshake 엔 10 전용 칸이 없다(#598 계약 0절)
        "msg_id": msg_id,
        "thread_id": msg_id,
        "kind": "mls",
        "from": {"address": from, "author": "human", "device_id": keys.device_id().as_str()},
        "to": {"address": to},
        "mls_group": header_of(gid),
        "epoch": epoch,
        "body": body,
        "created_at": now.to_rfc3339().ok()?,
        "expires_at": UnixMillis(now.0 + 30 * 86_400_000).to_rfc3339().ok()?,
    });
    send_frame(keys, m)
}

/// 시작(epoch 0, §4 시작): 나 혼자 그룹을 만들어 저장하고 `start{group_info}` 프레임.
#[must_use]
pub fn start(m: &Mls, h: &Head<'_>, c: &Conv) -> Option<(MlsGroup, String)> {
    let t = m.provider.begin().ok()?;
    let g = mls::create_group(&m.provider, &m.signer, c.kind, &c.gid, &[]).ok()?;
    let gi = g
        .export_group_info(m.provider.crypto(), &m.signer, true)
        .ok()?;
    let gi = mls::to_bytes(&gi).ok()?;
    t.commit().ok()?;
    m.provider.scrub();
    let f = handshake(
        h,
        &c.gid,
        0,
        json!({"enc": "mls", "wire": "start", "group_info": b64(&gi)}),
    )?;
    Some((g, f))
}

/// #1569 이 기기가 1:1·내 기기 그룹을 시작하거나 다시 든 것이 **받아들여지면** 대화 주소를 남긴다 — 받는 쪽([`conversation_of`])만
/// 남기면, 먼저 시작한 기기는 붙은 채 그 그룹 글을 한 번 받기 전까지 주소가 없어 휴대폰 알림이 이름·누름·답장 줄을 못 찾는다.
/// 보낼 때가 아니라 ack 뒤인 까닭: 대화 주소가 있으면 「전에 쓰던 대화」로 보고 시작의 epoch_taken 을 스스로 다시 들기로 넘긴다
/// (`start_taken_rejoins`) — 동시에 시작해 진 쪽은 상대 Welcome 을 기다려야 한다. `to` 는 상대 사람 주소(내 기기 그룹이면 내
/// 주소) — 받는 쪽이 남기는 값과 같은 꼴(세션 slug 없음). group 종류는 Welcome·group_start 길이 따로 남긴다.
pub fn remember_own_conv(m: &Mls, gid: &[u8], to: &str) {
    if crate::mls_store::is_group_gid(gid) {
        return;
    }
    let to = to.split_once('/').map_or(to, |(a, _)| a);
    remember_conv(m, gid, to);
}

/// 시작이 받아들여진 뒤 KeyPackage 기기들을 Add 하는 Commit(epoch 0 → 1, welcome 포함). merge 는 ack 뒤([`merge`]).
#[must_use]
pub fn add_commit(m: &Mls, h: &Head<'_>, g: &mut MlsGroup, kps: &[KeyPackage]) -> Option<String> {
    let epoch = g.epoch().as_u64();
    let t = m.provider.begin().ok()?;
    let (commit, welcome, gi) = g.add_members(&m.provider, &m.signer, kps).ok()?;
    let gi = gi?;
    let body = json!({
        "enc": "mls",
        "wire": "commit",
        "payload": b64(&mls::to_bytes(&commit).ok()?),
        "group_info": b64(&mls::to_bytes(&MlsMessageOut::from(gi)).ok()?),
        "welcome": b64(&mls::to_bytes(&welcome).ok()?),
    });
    t.commit().ok()?;
    m.provider.scrub();
    handshake(h, g.group_id().as_slice(), epoch, body)
}

/// relay 가 Commit 을 받았다 — 쥐고 있던 pending Commit 을 merge.
pub fn merge(m: &Mls, gid: &[u8]) -> bool {
    let Some(mut g) = load(m, gid) else {
        return false;
    };
    let ok = m
        .provider
        .begin()
        .ok()
        .and_then(|t| {
            crate::mls::merge_commit(&m.provider, &mut g, crate::mls::Merge::Pending).ok()?;
            t.commit().ok()
        })
        .is_some();
    m.provider.scrub();
    ok
}

/// Add Commit 이 거절됐다 — 쥐고 있던 pending Commit 을 버린다(그룹은 epoch 그대로, 다음에 Add 만 다시).
pub fn clear_pending(m: &Mls, gid: &[u8]) {
    if let Some(mut g) = load(m, gid) {
        if let Ok(t) = m.provider.begin() {
            if g.clear_pending_commit(m.provider.storage()).is_ok() {
                let _ = t.commit();
            }
        }
        m.provider.scrub();
    }
}

/// 시작·Commit 이 거절됐다 — 내 그룹을 지운다(epoch_taken 이면 상대 Welcome 으로 들어간다).
pub fn drop_group(m: &Mls, gid: &[u8]) {
    let _ = m.provider.storage().drop_stalled(gid);
    if let Some(mut g) = load(m, gid) {
        if let Ok(t) = m.provider.begin() {
            if g.delete(m.provider.storage()).is_ok() {
                let _ = t.commit();
            }
        }
        m.provider.scrub();
    }
}

/// 응용 메시지 봉인(`enc: mls, wire: app`): 평문 메시지의 `body.text` 를 그룹으로 암호화하고 헤더 `mls_group`·`epoch` 를 붙여
/// 서명한 `send` 프레임. 평문 꼴은 [`mls_plaintext`](§12-17).
///
/// # Errors
/// 막힌 그룹·openmls·서명·프레임 상한.
pub fn seal_app(
    m: &Mls,
    keys: &DeviceKeys,
    g: &mut MlsGroup,
    plain: &Value,
) -> Result<String, mls::Error> {
    mls::ensure_open(&m.provider, g)?;
    let text = plain
        .pointer("/body/text")
        .and_then(Value::as_str)
        .ok_or(mls::Error::Codec)?;
    let pt = mls_plaintext(plain, text).ok_or(mls::Error::Codec)?;
    let t = m.provider.begin()?;
    let out = g
        .create_message(&m.provider, &m.signer, &pt)
        .map_err(|e| mls::Error::Mls(e.to_string()))?;
    let bytes = mls::to_bytes(&out)?;
    t.commit()?;
    let mut msg = plain.clone();
    // BodyMls 에는 pt 칸이 없다 — 평문 머리가 꼴을 말한다(§12-17).
    msg["body"] = json!({"enc": "mls", "wire": "app", "payload": b64(&bytes)});
    msg["mls_group"] = Value::String(header_of(g.group_id().as_slice()));
    msg["epoch"] = json!(g.epoch().as_u64());
    send_frame(keys, msg).ok_or(mls::Error::Rejected("frame_too_large"))
}

/// MLS 응용 메시지 평문(§12-17): JSON 머리 한 줄 `{"v":1}`(첨부면 `{"v":1,"files":[…]}`) + `\n` + 본문 원 바이트 — 본문은
/// 다시 이스케이프하지 않는다. 첨부 메시지의 큐 평문은 묶음 15 json1 문자열(`{"text","files"}`)이라 풀어서 옮긴다.
fn mls_plaintext(plain: &Value, text: &str) -> Option<Vec<u8>> {
    let rename = plain.get("kind").and_then(Value::as_str) == Some("group")
        && plain.get("group_op").and_then(Value::as_str) == Some("rename");
    let (head, body) = if rename {
        // 이름은 평문 머리에만(§12-23), 본문 빈 값.
        let asked: Value = serde_json::from_str(text).ok()?;
        let mut meta = json!({"name": asked.get("name")?.as_str()?});
        // §7-47: add 확정 뒤 다시 보내는 이름에 얹은 history — 암호 안 평문 머리라 relay 는 모른다.
        if let Some(h) = asked.get("history").filter(|h| h.is_object()) {
            meta["history"] = h.clone();
        }
        (json!({"v": 1, "meta": meta}), String::new())
    } else if plain.pointer("/body/pt").and_then(Value::as_str) == Some("json1") {
        let inner: Value = serde_json::from_str(text).ok()?;
        (
            json!({"v": 1, "files": inner.get("files")?.clone()}),
            inner.get("text")?.as_str()?.to_owned(),
        )
    } else {
        (json!({"v": 1}), text.to_owned())
    };
    // #490 28 §2: 내 다른 기기로 넘기는 글의 처음 출처 — 큐 본문(BodyPlain)의 칸을 머리로.
    let mut head = head;
    for k in ORIGIN_KEYS {
        if let Some(v) = plain
            .pointer(&format!("/body/{k}"))
            .filter(|v| v.is_string())
        {
            head[k] = v.clone();
        }
    }
    // #627 멘션 칸 — 큐 본문의 `mentions`(주소 목록)·`of`(묶일 그룹 글)를 머리로.
    for k in MENTION_KEYS {
        if let Some(v) = plain
            .pointer(&format!("/body/{k}"))
            .filter(|v| mention_shape(k, v))
        {
            head[k] = v.clone();
        }
    }
    // #1092 보낸 에이전트 — 큐 평문의 보낸 주소가 세션(`handle@server/slug`)이면 그 slug. 알림(push_open)만 읽는다(봉투가 없어서).
    if let Some(slug) = (!rename)
        .then(|| plain.pointer("/from/address"))
        .flatten()
        .and_then(Value::as_str)
        .and_then(|a| a.split_once('/'))
        .map(|(_, s)| s)
        .filter(|s| agent_shape(s))
    {
        head[AGENT_KEY] = json!(slug);
    }
    // #1598 에이전트가 물은 요청의 답·거절 — 큐 본문의 `to_agent: true`(코어 `compose::answer` 가 요청 `from.author` 로 적는다)를
    // 머리로. 알림(push_open)만 읽는다: 푸시에는 봉투가 없어 여는 쪽이 「에이전트 앞으로 간 답」과 「사람 앞으로 온 답」을 가를 길이
    // 없었다. 받는 주소의 slug 로는 못 가른다 — 공개 전 세션이 물은 요청은 from 이 사람 주소라 답도 사람 주소로 간다(#1607 판정
    // 7055693137). 값은 참 하나(slug 아님).
    if !rename && plain.pointer("/body/to_agent") == Some(&Value::Bool(true)) {
        head[TO_AGENT_KEY] = json!(true);
    }
    // #1318 보낸 사람이 시작한 요청 — 큐 본문의 `own_start: true`(코어 `with_origin` 이 동료 앞 request 에 적는다)를 머리로.
    if !rename && plain.pointer(&format!("/body/{OWN_START_KEY}")) == Some(&Value::Bool(true)) {
        head[OWN_START_KEY] = json!(true);
    }
    // #1598 답·거절의 받는 사람이 보내는 사람과 다른가 — 「동료 사람이 물은 것에 내 에이전트가 한 답」을 내 휴대폰이
    // 조용한 줄로 가르게. 「내가 사람으로 내 에이전트에 물은 답」(받는 사람 = 나)과 가르는 값이 푸시에는 없었다(봉투가 없어서).
    // 주소가 아니라 참 하나(relay 크기 상한의 머리 몫). 알림(push_open)만 읽는다.
    if !rename && to_peer(plain) {
        head[TO_PEER_KEY] = json!(true);
    }
    // #1470 글 종류 — 바깥 머리(relay 가 보는 것)와 같은 낱말. 알림(push_open)만 읽는다: 푸시에는 암호문뿐이라 여는 쪽이
    // 반응·거두기·멤버 변경을 글과 가를 길이 없었다. 앱이 받는 길은 바깥 kind 가 기준이라 버린다([`origin_into`]).
    if let Some(k) = plain
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| kind_shape(k))
    {
        head[KIND_KEY] = json!(k);
    }
    // #1470 반응의 원글 작성자 — 큐 본문의 칸을 머리로. 알림(push_open)만 읽는다.
    if let Some(a) = plain
        .pointer(&format!("/body/{TARGET_AUTHOR_KEY}"))
        .and_then(Value::as_str)
        .filter(|a| target_author_shape(a))
    {
        head[TARGET_AUTHOR_KEY] = json!(a);
    }
    let mut out = head.to_string().into_bytes();
    out.push(b'\n');
    out.extend_from_slice(body.as_bytes());
    Some(out)
}

/// 시험용(#1546): 보낼 큐 평문 `plain` 이 푸시로 열렸을 때 알림 길이 읽는 값 — (본문, 첨부 있음, `agent`, `kind`,
/// `target_author`). 보내는 평문 만들기와 [`split_plaintext`] 를 그대로 지난다(휴대폰이 「푸시로 연 글」과 「붙어서 받은 글」의
/// 알림이 같은지 견준다).
#[doc(hidden)]
#[must_use]
pub fn pushed_parts(plain: &Value) -> Option<PushedParts> {
    let text = plain.pointer("/body/text")?.as_str()?;
    let pt = String::from_utf8(mls_plaintext(plain, text)?).ok()?;
    let (body, files, extra) = split_plaintext(&pt)?;
    let s = |k: &str| extra.get(k).and_then(Value::as_str).map(str::to_owned);
    Some(PushedParts {
        body,
        has_files: files.is_some(),
        agent: s(AGENT_KEY),
        kind: s(KIND_KEY),
        to_agent: extra.get(TO_AGENT_KEY) == Some(&Value::Bool(true)),
        to_peer: extra.get(TO_PEER_KEY) == Some(&Value::Bool(true)),
        target_author: s(TARGET_AUTHOR_KEY),
    })
}

/// [`pushed_parts`] 의 값.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedParts {
    pub body: String,
    pub has_files: bool,
    pub agent: Option<String>,
    pub kind: Option<String>,
    pub to_agent: bool,
    pub to_peer: bool,
    pub target_author: Option<String>,
}

/// 평문 머리의 처음 출처 칸(#490 28 §2, §12-17). 모르는 칸이라 옛 기기는 그냥 넘긴다.
const ORIGIN_KEYS: [&str; 2] = ["origin", "origin_msg"];

/// 평문 머리의 멘션 칸(#627) — `mentions`: 주소 문자열 목록(≤20), `of`: 그룹 글 msg_id. 옛 기기는 모르는 칸이라 넘긴다(판 그대로).
/// 출처 칸과 달리 보낸 이와 무관하게 본문으로 옮긴다 — 믿을지(보낸 이가 사람인가·지금 멤버인가)는 코어가 정한다.
const MENTION_KEYS: [&str; 2] = ["mentions", "of"];

/// 평문 머리의 보낸 에이전트 칸(#1092) — 세션 slug. 옛 기기는 모르는 칸이라 넘긴다(판 그대로). 알림 길만 읽고, 앱이 받는 길은
/// 봉투 from 이 기준이라 버린다([`origin_into`]).
pub const AGENT_KEY: &str = "agent";

/// 평문 머리의 받는 에이전트 칸(#1598) — 받는 세션 slug([`AGENT_KEY`] 와 같은 꼴). 옛 기기는 모르는 칸이라 넘긴다(판 그대로).
/// 알림 길만 읽고(에이전트끼리 오간 답·거절을 조용한 줄로), 앱이 받는 길은 봉투 to 가 기준이라 버린다([`origin_into`]).
/// 보낸 쪽이 적는 값이다 — 알림 가르기에만 쓰고 다른 판단에 쓰지 않는다.
pub const TO_AGENT_KEY: &str = "to_agent";

/// 평문 머리의 「보낸 사람이 시작한 요청」 칸(#1318) — 동료 앞 request 에, 그 글의 처음 출처가 보낸 사람 본인일 때만 `true`.
/// 옛 기기는 모르는 칸이라 넘긴다(판 그대로). [`TO_AGENT_KEY`] 처럼 보낸 이와 무관하게 본문으로 옮긴다 — 받는 코어가 「질문도
/// 작업으로 받기」를 켠 사람의 글에서만 읽고, 저장 전에 뗀다. 값은 참 하나(누구의 요청이었는지는 싣지 않는다).
pub const OWN_START_KEY: &str = "own_start";

/// 평문 머리의 「남 앞으로 간 답」 칸(#1598) — 답·거절의 받는 사람이 보내는 사람과 다르면 참 하나([`to_peer`]). 옛 기기는 모르는
/// 칸이라 넘긴다. 알림 길만 읽고(내 기기가 보낸 내 에이전트의 답을 조용한 줄로), 앱이 받는 길은 버린다([`origin_into`]).
/// 보낸 쪽이 적는 값이다 — 알림 가르기에만 쓴다.
pub const TO_PEER_KEY: &str = "to_peer";

/// #1598 답·거절(`kind` reply·rejected)의 받는 사람(`to.address` 의 사람 주소)이 보내는 사람(`from.address` 의 사람 주소)과
/// 다른가. 보내는 큐 평문(머리 [`TO_PEER_KEY`])과 붙어서 받은 봉투(휴대폰 알림 사본)가 같은 함수를 쓴다 — 둘 다 같은 꼴이다.
#[must_use]
pub fn to_peer(message: &Value) -> bool {
    let person = |p: &str| {
        message
            .pointer(p)
            .and_then(Value::as_str)
            .map(|a| a.split('/').next().unwrap_or(a))
    };
    matches!(
        message.get("kind").and_then(Value::as_str),
        Some("reply" | "rejected")
    ) && matches!((person("/from/address"), person("/to/address")), (Some(f), Some(t)) if f != t)
}

/// 평문 머리의 글 종류 칸(#1470) — 바깥 머리 `kind` 와 같은 낱말(`chat`·`reaction`·`system`·`group` …). 옛 기기는 모르는 칸이라
/// 넘긴다. 알림 길만 읽고, 앱이 받는 길은 바깥 kind 가 기준이라 버린다([`origin_into`]) — 두 값이 갈려 화면이 달라지지 않게.
pub const KIND_KEY: &str = "kind";

/// 평문 머리의 반응 원글 작성자 칸(#1470 판정 7005102612) — 사람 주소. 옛 기기는 모르는 칸이라 넘긴다. 알림 길만
/// 읽는다: 원글 행이 그 휴대폰에 아직 없을 때(내가 맥에서 보낸 글) 「내 글에 단 반응인가」를 가른다. 앱이 받는 길은 자기
/// 저장소의 원글이 기준이라 버린다([`origin_into`]).
pub const TARGET_AUTHOR_KEY: &str = "target_author";

/// 원글 작성자 칸 꼴 — `user@server` 한 줄(256바이트 아래, 세션 꼬리 없음).
#[must_use]
pub fn target_author_shape(s: &str) -> bool {
    s.len() <= 256
        && !s.contains('/')
        && s.split_once('@')
            .is_some_and(|(u, h)| !u.is_empty() && !h.is_empty())
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// 글 종류 낱말 꼴(`[a-z][a-z_]{0,23}`) — 뜻은 여는 쪽이 본다(모르는 낱말은 글이 아닌 것으로).
#[must_use]
pub fn kind_shape(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 24
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || *c == b'_')
}

/// 세션 slug 꼴(message.schema 주소의 `/` 뒤: `[a-z0-9][a-z0-9-]{0,31}`).
#[must_use]
pub fn agent_shape(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// 멘션 칸의 꼴 — 맞지 않으면 싣지도 옮기지도 않는다(그 칸만 버림, 글은 받음).
fn mention_shape(k: &str, v: &Value) -> bool {
    match k {
        "mentions" => v.as_array().is_some_and(|a| {
            !a.is_empty()
                && a.len() <= MENTIONS_MAX
                && a.iter()
                    .all(|x| x.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256))
        }),
        "of" => v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 64),
        _ => false,
    }
}

/// 한 글의 멘션 상한(#627 계약 §1).
const MENTIONS_MAX: usize = 20;

/// 연 평문(§12-17)을 (본문, 첨부 json1 문자열?, 처음 출처·멘션·보낸 에이전트 칸) 로. 머리가 `v:1` 이 아니면 `None`(bad_envelope). 첨부가 있으면
/// 묶음 15 의 `{"text","files"}` 로 다시 엮어 [`crate::files::unpack`] 에 넘긴다. 출처 칸은 문자열인 것만 — 믿을지(내 기기가
/// 보냈나)는 호출자가 정한다([`origin_into`]).
#[must_use]
pub fn split_plaintext(
    pt: &str,
) -> Option<(String, Option<String>, serde_json::Map<String, Value>)> {
    let (head, body) = pt.split_once('\n')?;
    let h: Value = serde_json::from_str(head).ok()?;
    if h.get("v").and_then(Value::as_u64) != Some(1) {
        return None;
    }
    let files = h
        .get("files")
        .map(|f| json!({"text": body, "files": f}).to_string());
    let origin = ORIGIN_KEYS
        .iter()
        .filter_map(|k| {
            h.get(*k)
                .filter(|v| v.is_string())
                .map(|v| ((*k).to_owned(), v.clone()))
        })
        .chain(MENTION_KEYS.iter().filter_map(|k| {
            h.get(*k)
                .filter(|v| mention_shape(k, v))
                .map(|v| ((*k).to_owned(), v.clone()))
        }))
        .chain(
            h.get(AGENT_KEY)
                .and_then(Value::as_str)
                .filter(|a| agent_shape(a))
                .map(|a| (AGENT_KEY.to_owned(), json!(a))),
        )
        .chain(
            h.get(TO_AGENT_KEY)
                .filter(|v| **v == Value::Bool(true))
                .map(|v| (TO_AGENT_KEY.to_owned(), v.clone())),
        )
        .chain(
            h.get(OWN_START_KEY)
                .filter(|v| **v == Value::Bool(true))
                .map(|v| (OWN_START_KEY.to_owned(), v.clone())),
        )
        .chain(
            h.get(TO_PEER_KEY)
                .filter(|v| **v == Value::Bool(true))
                .map(|v| (TO_PEER_KEY.to_owned(), v.clone())),
        )
        .chain(
            h.get(KIND_KEY)
                .and_then(Value::as_str)
                .filter(|k| kind_shape(k))
                .map(|k| (KIND_KEY.to_owned(), json!(k))),
        )
        .chain(
            h.get(TARGET_AUTHOR_KEY)
                .and_then(Value::as_str)
                .filter(|a| target_author_shape(a))
                .map(|a| (TARGET_AUTHOR_KEY.to_owned(), json!(a))),
        )
        .collect();
    Some((body.to_owned(), files, origin))
}

/// 처음 출처 칸을 코어로 넘길 본문(BodyPlain)에 싣는다 — 보낸 사람이 나일 때만(#490 28 §2). 동료가 `origin:"me"` 를 넣어
/// 사용자 지시처럼 보이게 하는 길을 막는다: 동료 것은 버린다. 보낸 기기는 MLS(`expect_sender`)와 서명 확인(내 폐기 안 된
/// 기기)이 이미 증명했다.
pub fn origin_into(body: &mut Value, mut origin: serde_json::Map<String, Value>, from_me: bool) {
    // #1092 보낸 에이전트 칸은 코어로 옮기지 않는다 — 앱은 봉투 from 이 기준.
    origin.remove(AGENT_KEY);
    // #1598·#1607 에이전트가 물은 요청의 답이라는 칸 — 누가 보냈든 본문으로 옮긴다(참일 때만). 받는 코어는 저장 전에 떼어
    // 휴대폰 알림 사본(붙어서 받은 길)에만 남긴다(`Core::receive`) — 화면·저장·다시 보내기에는 쓰지 않는다.
    if let Some(v) = origin
        .remove(TO_AGENT_KEY)
        .filter(|v| *v == Value::Bool(true))
    {
        if let Some(b) = body.as_object_mut() {
            b.insert(TO_AGENT_KEY.to_owned(), v);
        }
    }
    // #1318 보낸 사람이 시작한 요청 칸 — 누가 보냈든 본문으로 옮긴다(참일 때만). 받는 코어가 저장 전에 뗀다.
    if let Some(v) = origin
        .remove(OWN_START_KEY)
        .filter(|v| *v == Value::Bool(true))
    {
        if let Some(b) = body.as_object_mut() {
            b.insert(OWN_START_KEY.to_owned(), v);
        }
    }
    // #1598 남 앞 답 칸도 — 앱은 봉투 두 주소가 기준(알림 사본은 같은 함수로 다시 셈).
    origin.remove(TO_PEER_KEY);
    // #1470 글 종류 칸도 — 앱은 바깥 kind 가 기준.
    origin.remove(KIND_KEY);
    // #1470 반응의 원글 작성자 칸도 — 앱은 자기 저장소의 원글이 기준.
    origin.remove(TARGET_AUTHOR_KEY);
    // 멘션 칸(#627)은 누가 보냈든 옮긴다 — 코어가 보낸 이·멤버를 검사한다.
    let mentions: serde_json::Map<String, Value> = MENTION_KEYS
        .iter()
        .filter_map(|k| origin.remove(*k).map(|v| ((*k).to_owned(), v)))
        .collect();
    if let Some(b) = body.as_object_mut() {
        b.extend(mentions);
    }
    if !from_me {
        return;
    }
    if let Some(b) = body.as_object_mut() {
        b.extend(origin);
    }
}

fn user_of(address: Option<&Value>) -> Option<&str> {
    address?.as_str()?.split('@').next()
}

/// 받은 MLS 메시지의 그룹 id 와 대화 주소(pair 면 나 아닌 쪽 사람 주소, self 면 `me_addr`) — EvConversationSync 용.
#[must_use]
pub fn conversation_of(
    dir: &DirView,
    message: &Value,
    me_user: &str,
    me_addr: &str,
) -> Option<(Vec<u8>, String)> {
    let c = conv_of(dir, message)?;
    if c.kind == Kind::SelfDevices {
        return Some((c.gid, me_addr.to_owned()));
    }
    if c.kind == Kind::Group {
        // 받은 글의 `to` 는 보지 않는다(#1142) — 그룹 안 멘션·에이전트 답은 `to` 가 사람·에이전트 주소고, 대화는 늘 그 그룹이다.
        let server = me_addr.split_once('@').map_or("", |(_, s)| s);
        let conversation = group_conversation(&c.gid, server);
        return Some((c.gid, conversation));
    }
    let person = |p: &str| -> Option<String> {
        let a = message.pointer(p)?.as_str()?;
        Some(a.split_once('/').map_or(a, |(x, _)| x).to_owned())
    };
    let from = person("/from/address")?;
    let other = if from.split('@').next() == Some(me_user) {
        person("/to/address")?
    } else {
        from
    };
    Some((c.gid, other))
}

/// group 종류 그룹의 대화 주소 `+<gid>@<server>`(#1142). 받은 글의 `to` 로 정하지 않는다 — 그룹 안 멘션·에이전트 답은 `to` 가
/// 사람·에이전트 주소라, 그것이 `mls_conv` 에 남으면 알림이 1:1 꼴로 뜨고 알림 답장이 1:1 로 샌다. `server` 는 내 주소의 서버.
#[must_use]
pub fn group_conversation(gid: &[u8], server: &str) -> String {
    format!("+{}@{server}", header_of(gid))
}

/// 그룹의 대화 주소를 남긴다.
pub fn remember_conv(m: &Mls, gid: &[u8], conversation: &str) {
    if let Err(e) = m.provider.storage().set_conv(gid, conversation) {
        tracing::warn!(error = %e, "대화 주소 저장 실패");
    }
}

/// 막힌 대화들(접속 때 다시 알림).
#[must_use]
pub fn blocked_conversations(m: &Mls) -> Vec<(String, crate::mls_store::GroupState, Option<i64>)> {
    m.provider
        .storage()
        .blocked_conversations()
        .unwrap_or_default()
}

/// 그룹의 막힘 상태(없으면 보통).
#[must_use]
pub fn blocked(m: &Mls, gid: &[u8]) -> Option<crate::mls_store::GroupState> {
    m.provider
        .storage()
        .state(gid)
        .ok()
        .flatten()
        .map(|(s, _, _)| s)
}

/// 받은 메시지의 대화(헤더 `mls_group` 이 보낸·받는 사용자로 계산한 id 와 같아야 — §6, 클라이언트도 본다). 그룹이면
/// `to` 가 그 그룹 주소(`+gid@…`)거나 헤더 `group` 이 그 그룹이어야 한다.
fn conv_of(dir: &DirView, message: &Value) -> Option<Conv> {
    let header = message.get("mls_group").and_then(Value::as_str)?;
    if crate::mls_store::is_group_gid(header.as_bytes()) {
        let gid = crate::group_io::group_context(message)?;
        return (gid == header).then(|| group_conv(dir, header));
    }
    let from = user_of(message.pointer("/from/address"))?;
    let to = user_of(message.pointer("/to/address"))?;
    let c = conv(from, to);
    (header == header_of(&c.gid)).then_some(c)
}

fn payload(body: &Value, field: &str) -> Option<Vec<u8>> {
    encoding::decode(body.get(field)?.get("data")?.as_str()?, "mls").ok()
}

/// 받은 응용 메시지(`enc: mls, wire: app`)를 연다 — 보낸 잎이 봉투 `from.device_id` 와 같아야(§12-11 ⓔ).
///
/// # Errors
/// 꼴·대화 id 틀림 → `BadEnvelope`, 그룹 없음·못 엶 → `Unreadable`.
pub fn open_app(
    m: &Mls,
    dir: &DirView,
    message: &Value,
    now_secs: u64,
) -> Result<String, EnvelopeError> {
    let c = conv_of(dir, message).ok_or(EnvelopeError::BadEnvelope("mls_group"))?;
    let body = message
        .get("body")
        .ok_or(EnvelopeError::BadEnvelope("body"))?;
    if body.get("wire").and_then(Value::as_str) != Some("app") {
        return Err(EnvelopeError::BadEnvelope("wire"));
    }
    let bytes = payload(body, "payload").ok_or(EnvelopeError::BadEnvelope("payload"))?;
    let msg_id = message.get("msg_id").and_then(Value::as_str);
    // 다시 배달된 것(코어 ack 전에 끊김) — 이미 연 평문.
    if let Some(id) = msg_id {
        if let Some(t) = m.provider.storage().opened(id).ok().flatten() {
            // 그 msg_id 로 남긴 글이 이 봉투의 대화(그룹)가 아니면 쓰지 않는다 — 알림의 msg_id 는 relay 가 정한 값이다.
            if m.provider
                .storage()
                .opened_gid(id)
                .ok()
                .flatten()
                .is_some_and(|g| g != c.gid)
            {
                tracing::warn!("남긴 평문의 대화가 봉투와 다름 — 버림");
                return Err(EnvelopeError::Unreadable);
            }
            // 알림(push_open)이 봉투 없이 연 것이면 보낸 기기를 이제 봉투와 견준다(§12-11 ⓔ).
            if let Some(sender) = m.provider.storage().opened_sender(id).ok().flatten() {
                let from = message.pointer("/from/device_id").and_then(Value::as_str);
                if from != Some(sender.as_str()) {
                    tracing::warn!("알림으로 연 글의 보낸 기기가 봉투와 다름 — 버림");
                    return Err(EnvelopeError::Unreadable);
                }
            }
            return String::from_utf8(t.to_vec()).map_err(|_| EnvelopeError::Decrypt("utf8"));
        }
    }
    let mut g = load(m, &c.gid).ok_or(EnvelopeError::Unreadable)?;
    let ctx = RuleCtx {
        views: Default::default(),
        dir,
        members: &c.members,
        expect_sender: message.pointer("/from/device_id").and_then(Value::as_str),
        keep_as: msg_id,
        push_opened: false,
        group: None,
    };
    match mls::receive(&m.provider, &mut g, c.kind, &bytes, now_secs, &ctx) {
        Ok(Received::App { text, .. }) => {
            // rejoin_needed 때 lost_since 의 시작(§12-27 ⓐ).
            if let Some(at) = message
                .get("created_at")
                .and_then(Value::as_str)
                .and_then(|t| lodelai_effects::UnixMillis::parse_rfc3339(t).ok())
            {
                let _ = m.provider.storage().put_recv(&c.gid, at.0);
            }
            String::from_utf8(text).map_err(|_| EnvelopeError::Decrypt("utf8"))
        }
        Ok(_) => Err(EnvelopeError::BadEnvelope("not_app")),
        Err(e) => {
            tracing::warn!(error = %e, "MLS 응용 메시지를 열 수 없음");
            // 막힌 동안 버린 글 — 처음 때를 남긴다(§12-23 ③, 풀린 뒤 다시 받지 않는다).
            // 화면이 그 글 자리에 줄을 꽂도록 버린 글의 시각(없으면 지금).
            if matches!(e, mls::Error::Blocked(_)) {
                let at = message
                    .get("created_at")
                    .and_then(Value::as_str)
                    .and_then(|t| lodelai_effects::UnixMillis::parse_rfc3339(t).ok())
                    .map_or_else(
                        || i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX),
                        |t| t.0,
                    );
                let _ = m.provider.storage().put_lost(&c.gid, at);
            }
            Err(EnvelopeError::Unreadable)
        }
    }
}

/// 그 Handshake 의 대화가 이 기기에 있는 pair 면 (그룹 id, 지금 잎 device_id) — g025g 새 잎 알림의 앞뒤 비교용.
#[must_use]
pub fn pair_leaves(m: &Mls, dir: &DirView, message: &Value) -> Option<(Vec<u8>, Vec<String>)> {
    let c = conv_of(dir, message)?;
    if c.kind != mls::Kind::Pair {
        return None;
    }
    let g = load(m, &c.gid)?;
    let ds = g
        .members()
        .filter_map(|mem| crate::mls_rules::device_of(&mem.credential))
        .collect();
    Some((c.gid, ds))
}

/// Handshake 처리 결과.
#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    /// 처리했다(또는 버릴 것) — ack.
    Done,
    /// 디렉터리가 늦다 — 갱신 뒤 같은 메시지를 다시(ack 하지 않음). 값은 그 대화의 그룹 id(#725 — 같은 대화에서 또 오면
    /// 디렉터리를 당겨 온다).
    RetryDir(String),
    /// 멈춘 동안 온 것 — 풀린 뒤 다시 받는다(ack 하지 않음, 디렉터리와 무관).
    Retry,
    /// Commit 을 처리하지 못했다(내 몫이 깨짐 — 규칙 밖·막힘이 아님) — ack 하고 그 그룹(헤더 값)에 external commit 으로 다시
    /// 들어간다(§4-7 pair·self).
    Rejoin(String),
}

/// 산 기기가 아닌 잎 때문에 못 여는 Welcome 을 기다리는 시간 — 디렉터리가 한 번 더 올 틈만. 그 잎이 정말 끊긴 것이면 기다려도
/// 이 Welcome 은 열리지 않는다(#1479).
pub const WELCOME_GONE_LEAF_MS: i64 = 30_000;

/// 못 여는 Welcome 을 그대로 다시 받아 보는 시간. 지나면 다시 들기로 넘긴다(버리지 않는다): 트리에 산 기기가 아닌 잎이 남은
/// 까닭이면 짧게([`WELCOME_GONE_LEAF_MS`]), 그 밖(산 기기인데 사슬이 아직 등)은 Commit 과 같은 [`mls::RETRY_MAX_MS`].
#[must_use]
pub fn welcome_wait_ms(why: &str) -> i64 {
    if crate::mls_rules::gone_leaf(why) {
        WELCOME_GONE_LEAF_MS
    } else {
        mls::RETRY_MAX_MS
    }
}

/// 못 연(Retry) Welcome 을 어떻게 할지: 처음 Retry 된 때부터 [`welcome_wait_ms`] 안이면 디렉터리 갱신 뒤 다시 받고
/// ([`Handled::RetryDir`]), 지나면 기록을 지우고 다시 들기로 넘긴다([`Handled::Rejoin`]) — 버리지 않는다.
#[must_use]
pub fn welcome_retry(
    m: &Mls,
    gid: &[u8],
    welcome: &[u8],
    why: &'static str,
    now_ms: i64,
) -> Handled {
    let st = m.provider.storage();
    let since = st
        .retry_since(gid, &mls::commit_hash(welcome), now_ms)
        .unwrap_or(now_ms);
    if now_ms.saturating_sub(since) < welcome_wait_ms(why) {
        tracing::info!(why, "Welcome — 디렉터리 갱신 뒤 다시");
        return Handled::RetryDir(gid_key(gid));
    }
    tracing::warn!(why, "Welcome 이 풀리지 않음 — 다시 들어감");
    let _ = st.clear_retry(gid);
    Handled::Rejoin(header_of(gid))
}

/// [`Handled::RetryDir`] 의 열쇠 — 그룹 Commit(`mls_group` 헤더 글)과 겹치지 않게 앞에 `mls:`.
pub(crate) fn gid_key(gid: &[u8]) -> String {
    format!("mls:{}", header_of(gid))
}

/// 받은 Handshake(kind `mls`): `commit` 이면 그룹이 없으면 `welcome` 으로 들어가고, 있으면 Commit 을 처리한다. `start` 는 볼 것 없음.
#[must_use]
pub fn handle_handshake(m: &Mls, dir: &DirView, message: &Value, now_secs: u64) -> Handled {
    let Some(c) = conv_of(dir, message) else {
        tracing::warn!("Handshake 의 mls_group 이 대화와 다름 — 버림");
        return Handled::Done;
    };
    let Some(body) = message.get("body") else {
        return Handled::Done;
    };
    if body.get("wire").and_then(Value::as_str) != Some("commit") {
        return Handled::Done;
    }
    // 동시 시작(§7): 내 시작이 epoch_taken 으로 거절되기 전에 상대 Welcome 이 먼저 올 수 있다 — 내 그룹이 아직 나 혼자면
    // 상대 그룹으로 바꾼다(epoch_taken 처리는 혼자인 그룹만 지운다).
    let solo = load(m, &c.gid).is_some_and(|g| g.members().count() == 1);
    if solo && payload(body, "welcome").is_some() {
        drop_group(m, &c.gid);
    }
    match load(m, &c.gid) {
        None => {
            let Some(w) = payload(body, "welcome") else {
                return Handled::Done;
            };
            let ctx = RuleCtx {
                views: Default::default(),
                dir,
                members: &c.members,
                expect_sender: None,
                keep_as: None,
                push_opened: false,
                group: None,
            };
            let r = mls::join_welcome(&m.provider, &w, c.kind, &c.gid, &ctx);
            m.provider.scrub();
            match r {
                // 디렉터리가 늦다 — 다시 받는다. 상한([`welcome_wait_ms`])을 넘기면 버리지 않고 **다시 들기**로 넘긴다(#1479):
                // 이 Welcome 의 트리는 뒤에 Remove 가 나가도 안 바뀌니, 열리는 길은 새 GroupInfo 뿐이다.
                Err(mls::Error::Retry(why)) => {
                    let now_ms = i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                    welcome_retry(m, &c.gid, &w, why, now_ms)
                }
                // 이미 있는 잎의 멈춤 판정(키가 디렉터리와 다름 등) — 이 Welcome 은 기다려도 안 열리지만, 그 잎이 빠지면 새
                // GroupInfo 로는 들 수 있다. 기다림 없이 다시 들기로 넘긴다(#1479). 버리는 것은 형식·해독·MLS 오류뿐.
                Err(mls::Error::Stalled(why)) => {
                    tracing::warn!(why, "Welcome 의 잎이 규칙 밖 — 다시 들어감");
                    let _ = m.provider.storage().clear_retry(&c.gid);
                    Handled::Rejoin(header_of(&c.gid))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Welcome 으로 들어가지 않음");
                    Handled::Done
                }
                Ok(_) => {
                    let _ = m.provider.storage().clear_retry(&c.gid);
                    Handled::Done
                }
            }
        }
        Some(mut g) => {
            let Some(bytes) = payload(body, "payload") else {
                return Handled::Done;
            };
            let ctx = RuleCtx {
                views: Default::default(),
                dir,
                members: &c.members,
                expect_sender: message.pointer("/from/device_id").and_then(Value::as_str),
                keep_as: None,
                push_opened: false,
                group: None,
            };
            let epoch = g.epoch().as_u64();
            let r = mls::receive(&m.provider, &mut g, c.kind, &bytes, now_secs, &ctx);
            m.provider.scrub();
            match r {
                Err(mls::Error::Retry(why)) => {
                    tracing::info!(why, "Commit — 디렉터리 갱신 뒤 다시");
                    Handled::RetryDir(gid_key(&c.gid))
                }
                // 멈춘 동안 온 것은 ack 하지 않는다 — 풀린 뒤 다시 접속하면 relay 가 다시 준다(§12-19).
                Err(mls::Error::Blocked(_)) => Handled::Retry,
                Err(mls::Error::Stalled(why)) => {
                    tracing::warn!(why, "Commit 이 대화를 멈춤 — 디렉터리가 바뀌면 다시 봄");
                    keep_stalled(m, &c.gid, epoch, &bytes, message, None, now_secs);
                    Handled::Done
                }
                Err(mls::Error::Mls(e)) => {
                    tracing::warn!(error = %e, "Commit 처리 실패 — 다시 들어감");
                    Handled::Rejoin(header_of(&c.gid))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Commit 처리 실패");
                    Handled::Done
                }
                Ok(_) => Handled::Done,
            }
        }
    }
}

/// 대화를 멈추게 한 Handshake 를 남긴다(§12-19 — 디렉터리가 바뀌면 같은 길로 다시 처리).
pub fn keep_stalled(
    m: &Mls,
    gid: &[u8],
    epoch: u64,
    bytes: &[u8],
    message: &Value,
    group_seq: Option<u64>,
    now_secs: u64,
) {
    // stalled_server 는 스스로 다시 보지 않는다(§12-23 ②).
    if blocked(m, gid) != Some(crate::mls_store::GroupState::StalledDevice) {
        return;
    }
    let now_ms = i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    if let Err(e) = m.provider.storage().put_stalled(
        gid,
        epoch,
        &mls::commit_hash(bytes),
        &message.to_string(),
        group_seq,
        now_ms,
    ) {
        tracing::warn!(error = %e, "멈춘 Handshake 저장 실패");
    }
}

/// 멈춘 대화를 다시 처리하기 전 상태(§12-19) — [`stall_open`] 이 막음을 잠깐 풀고, [`stall_close`] 가 결과로 판정한다.
#[derive(Debug)]
pub struct StallSnap {
    state: crate::mls_store::GroupState,
    reason: String,
    since: i64,
    epoch: u64,
}

/// 다시 처리한 결과.
#[derive(Debug, PartialEq, Eq)]
pub enum Retried {
    /// 들어갔다(epoch 가 올라감) — 막음·행을 지웠다.
    Freed,
    /// 처리하지 못했다(내 몫이 깨짐) — 막음·행을 지웠고 호출자가 다시 들어간다(그 그룹 헤더 값).
    Rejoin(String),
    /// 그대로 — 원래 멈춤(상태·이유·처음 멈춘 때)을 되돌렸다.
    Still,
}

/// 멈춘 그룹의 막음을 잠깐 푼다(같은 길로 다시 처리하게). `stalled_device` 가 아니거나 그룹이 없으면 행을 지우고 `None`.
#[must_use]
pub fn stall_open(m: &Mls, gid: &[u8]) -> Option<StallSnap> {
    let st = m.provider.storage();
    let snap = st
        .state(gid)
        .ok()
        .flatten()
        .filter(|(state, _, _)| *state == crate::mls_store::GroupState::StalledDevice)
        .and_then(|(state, reason, since)| {
            Some(StallSnap {
                state,
                reason,
                since,
                epoch: load(m, gid)?.epoch().as_u64(),
            })
        });
    let Some(snap) = snap else {
        let _ = st.drop_stalled(gid);
        return None;
    };
    let _ = st.clear_state(gid);
    Some(snap)
}

/// 다시 처리한 뒤: epoch 가 올라갔으면 풀림, Rejoin 이면 막음 없이 다시 들어가게, 아니면 원래 멈춤을 되돌린다 — 디렉터리가 아직
/// 늦어 Retry 여도 열린 채 두지 않는다(열리면 뒤처진 epoch 로 보낸다). 다시 처리가 새로 남긴 다시 볼 기록·멈춤 시각은 버린다
/// (30일은 처음 멈춘 때부터).
pub fn stall_close(m: &Mls, gid: &[u8], snap: StallSnap, handled: &Handled) -> Retried {
    let st = m.provider.storage();
    let _ = st.clear_retry(gid);
    let _ = st.clear_state(gid);
    if let Handled::Rejoin(h) = handled {
        let _ = st.drop_stalled(gid);
        return Retried::Rejoin(h.clone());
    }
    if load(m, gid).is_some_and(|g| g.epoch().as_u64() > snap.epoch) {
        let _ = st.drop_stalled(gid);
        return Retried::Freed;
    }
    let _ = st.set_state(gid, snap.state, &snap.reason, snap.since);
    Retried::Still
}

// ------------------------------------------------------------------ group 종류(묶음 22 h, §12-13·§12-22)

/// 넣을 사람들의 잎 자격 있는 기기(이 기기 빼고) — group 만들기(처음 멤버 + 내 다른 기기)·add(그 사람).
#[must_use]
pub fn claim_users(dir: &DirView, users: &[String], my_device: &str) -> Vec<String> {
    use crate::mls_rules::Directory as _;
    let mut out = Vec::new();
    for user in users {
        for d in dir.devices(user) {
            if d.device_id != my_device
                && crate::mls_rules::leaf_ok(dir, user, &d.device_id, &d.ed25519)
                    == crate::mls_rules::Verdict::Ok
                && !out.contains(&d.device_id)
            {
                out.push(d.device_id);
            }
        }
    }
    out
}

/// 가져온 KeyPackage 가 그 사용자들 각각의 기기를 하나 이상 담았나(#605 — 그룹 만들기·add 는 넣을 사람 모두가 들어야 한다).
#[must_use]
pub fn kps_cover(dir: &DirView, kps: &[KeyPackage], users: &[String]) -> bool {
    use crate::mls_rules::Directory as _;
    let ids: Vec<String> = kps
        .iter()
        .filter_map(|kp| crate::mls_rules::device_of(kp.leaf_node().credential()))
        .collect();
    users
        .iter()
        .all(|u| dir.devices(u).iter().any(|d| ids.contains(&d.device_id)))
}

/// group 만들기 시작(epoch 0, `group_op=create`, wire start): 나 혼자(관리자 = 나) 그룹을 만들어 저장하고 서명한 프레임.
#[must_use]
pub fn group_start(m: &Mls, h: &Head<'_>, gid: &str) -> Option<String> {
    let t = m.provider.begin().ok()?;
    let g = mls::create_group(
        &m.provider,
        &m.signer,
        Kind::Group,
        gid.as_bytes(),
        &[h.from.to_owned()],
    )
    .ok()?;
    let gi = mls::to_bytes(
        &g.export_group_info(m.provider.crypto(), &m.signer, true)
            .ok()?,
    )
    .ok()?;
    t.commit().ok()?;
    m.provider.scrub();
    let Head {
        keys,
        from,
        to,
        msg_id,
        now,
    } = *h;
    let msg = json!({
        "v": lodelai_protocol::PROTOCOL_MIN, // 10 전용 칸 없음(#598 계약 0절)
        "msg_id": msg_id,
        "thread_id": msg_id,
        "kind": "group",
        "from": {"address": from, "author": "human", "device_id": keys.device_id().as_str()},
        "to": {"address": to},
        "group_op": "create",
        "base_seq": 0,
        "mls_group": gid,
        "epoch": 0,
        "body": {"enc": "mls", "wire": "start", "group_info": b64(&gi)},
        "created_at": now.to_rfc3339().ok()?,
        "expires_at": UnixMillis(now.0 + 30 * 86_400_000).to_rfc3339().ok()?,
    });
    send_frame(keys, msg)
}

/// group Commit 이 바꾸는 것(§12-13·§12-22).
pub enum Change<'a> {
    /// create·add — 그 KeyPackage 들을 넣는다.
    Add(&'a [KeyPackage]),
    /// remove·leave·org_left — 그 사용자의 잎 전부([`leaves_of`])를 뺀다.
    Remove(Vec<openmls::prelude::LeafNodeIndex>),
    /// admin — 0xF0A1 `admins` 를 이 목록으로.
    Admins(Vec<String>),
    /// 주기 Update(§7) — 내 잎 키를 새로.
    Update,
}

/// 그 사용자의 잎 자리. 기기 → 사용자는 디렉터리로, 디렉터리에서 사라진 기기(조직에서 빠짐·폐기)는 피어 표(`revoked` 로 남음)로.
#[must_use]
pub fn leaves_of(
    dir: &DirView,
    store: &crate::outbox::Store,
    g: &MlsGroup,
    user: &str,
) -> Vec<openmls::prelude::LeafNodeIndex> {
    use crate::mls_rules::Directory as _;
    let devs = dir.devices(user);
    g.members()
        .filter(|m| {
            crate::mls_rules::device_of(&m.credential).is_some_and(|d| {
                devs.iter().any(|x| x.device_id == d)
                    || store
                        .peer(&d)
                        .ok()
                        .flatten()
                        .is_some_and(|p| p.user == user)
            })
        })
        .map(|m| m.index)
        .collect()
}

/// 코어의 group 변경 행을 Commit 으로(§12-22·§12-13). 행의 msg_id·헤더를 그대로 쓰고 body 를 MLS 로 바꿔 서명한 프레임.
/// merge 는 commit_final 때.
#[must_use]
pub fn group_commit(
    m: &Mls,
    keys: &DeviceKeys,
    g: &mut MlsGroup,
    plain: &Value,
    change: &Change<'_>,
) -> Option<String> {
    let epoch = g.epoch().as_u64();
    let body = commit_body(m, g, change)?;
    let mut msg = plain.clone();
    msg["body"] = body;
    msg["mls_group"] = Value::String(header_of(g.group_id().as_slice()));
    msg["epoch"] = json!(epoch);
    if let Some(o) = msg.as_object_mut() {
        o.remove("state");
    }
    sign_frame(keys, msg)
}

/// pair·self 의 기기 단위 Commit(§12-15 — 새 기기 Add·폐기 기기 Remove·주기 Update). merge 는 ack 뒤([`merge`]).
#[must_use]
pub fn pair_commit(m: &Mls, h: &Head<'_>, g: &mut MlsGroup, change: &Change<'_>) -> Option<String> {
    let epoch = g.epoch().as_u64();
    let body = commit_body(m, g, change)?;
    handshake(h, g.group_id().as_slice(), epoch, body)
}

/// Commit 을 만들어 pending 으로 저장하고 `body`(`wire: commit`).
fn commit_body(m: &Mls, g: &mut MlsGroup, change: &Change<'_>) -> Option<Value> {
    let t = m.provider.begin().ok()?;
    let (commit, welcome, gi) = match change {
        Change::Add(kps) => {
            let (c, w, gi) = g.add_members(&m.provider, &m.signer, kps).ok()?;
            (c, Some(w), gi)
        }
        Change::Remove(idx) => {
            if idx.is_empty() {
                return None;
            }
            g.remove_members(&m.provider, &m.signer, idx).ok()?
        }
        Change::Admins(admins) => {
            let ext = mls::with_admins(g, admins)?;
            g.update_group_context_extensions(&m.provider, ext, &m.signer)
                .ok()?
        }
        Change::Update => {
            let (c, _, gi) = g
                .self_update(&m.provider, &m.signer, LeafNodeParameters::default())
                .ok()?
                .into_contents();
            (c, None, gi)
        }
    };
    let mut body = json!({
        "enc": "mls",
        "wire": "commit",
        "payload": b64(&mls::to_bytes(&commit).ok()?),
        "group_info": b64(&mls::to_bytes(&MlsMessageOut::from(gi?)).ok()?),
    });
    if let Some(w) = welcome {
        body["welcome"] = b64(&mls::to_bytes(&w).ok()?);
    }
    t.commit().ok()?;
    m.provider.scrub();
    Some(body)
}

/// external commit 으로 다시 들어가는 Commit 의 (epoch, body) — 이 기기의 옛 그룹은 지운다. 실패면 `None`(옛 그룹은 이미 없음).
fn external_body(m: &Mls, dir: &DirView, gi: &[u8], c: &Conv) -> Result<(u64, Value), RejoinFail> {
    drop_group(m, &c.gid);
    let ctx = RuleCtx {
        views: Default::default(),
        dir,
        members: &c.members,
        expect_sender: None,
        keep_as: None,
        push_opened: false,
        group: None,
    };
    let r = mls::join_external(&m.provider, &m.signer, gi, c.kind, &c.gid, &ctx);
    m.provider.scrub();
    let (g, commit, gi) = r.map_err(|e| {
        tracing::warn!(error = %e, "external commit 을 만들 수 없음");
        match e {
            mls::Error::Retry(why) => RejoinFail::Retry(why),
            mls::Error::Stalled(why) => RejoinFail::Stalled(why),
            mls::Error::Mls(_)
            | mls::Error::Codec
            | mls::Error::Rejected(_)
            | mls::Error::Stale => RejoinFail::Other,
            mls::Error::Blocked(_) | mls::Error::Store(_) => RejoinFail::Local,
        }
    })?;
    let body =
        json!({"enc": "mls", "wire": "commit", "payload": b64(&commit), "group_info": b64(&gi)});
    Ok((g.epoch().as_u64().saturating_sub(1), body))
}

/// 다시 들어가기(external commit)를 만들지 못한 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejoinFail {
    /// 받은 GroupInfo 의 트리 잎이 지금 디렉터리로는 통과하지 못한다(다시 보면 될 수 있다).
    Retry(&'static str),
    /// 트리 잎이 규칙 밖이다.
    Stalled(&'static str),
    /// 받은 GroupInfo 가 틀렸다(해독·MLS 오류·규칙 밖).
    Other,
    /// 이 기기 쪽 문제(저장·프레임 서명) — 그 대화의 상태가 아니다.
    Local,
}

impl RejoinFail {
    /// 이 까닭으로 계속 못 들 때 그 대화에 알릴 상태와, 그것을 **오래 기다린 뒤에만** 알리는지(#1479 — 물러서기만 하고 조용히
    /// 있지 않게). 끊긴 잎이 남은 것이면 [`GroupState::WaitingMember`], 그 밖은 받은 Commit 의 멈춤과 같은 값. 산 기기인데 사슬이
    /// 아직인 것(`no_chain` 등)은 받은 Commit 처럼 [`mls::RETRY_MAX_MS`] 를 기다린다(곧 풀리는 것이 보통). 이 기기 쪽 문제는 없음.
    #[must_use]
    pub fn plan(self) -> Option<(crate::mls_store::GroupState, bool)> {
        use crate::mls_store::GroupState;
        match self {
            Self::Retry(why) if crate::mls_rules::gone_leaf(why) => {
                Some((GroupState::WaitingMember, false))
            }
            Self::Retry(_) => Some((GroupState::StalledDevice, true)),
            Self::Stalled(why) if mls::server_fault(why) => {
                Some((GroupState::StalledServer, false))
            }
            Self::Stalled(_) => Some((GroupState::StalledDevice, false)),
            Self::Other => Some((GroupState::StalledServer, false)),
            Self::Local => None,
        }
    }
}

/// pair·self 에 external commit 으로 다시 들어가는 Handshake 프레임(§5a `rejoin_needed`). ack 면 끝(이미 merge 됨), 거절이면
/// 호출자가 그룹을 지운다.
/// # Errors
/// 못 만든 까닭([`RejoinFail`]).
pub fn rejoin_pair(
    m: &Mls,
    h: &Head<'_>,
    dir: &DirView,
    gi: &[u8],
    c: &Conv,
) -> Result<String, RejoinFail> {
    let (epoch, body) = external_body(m, dir, gi, c)?;
    handshake(h, &c.gid, epoch, body).ok_or(RejoinFail::Local)
}

/// group 에 external commit 으로 다시 들어가는 `update` 행 프레임(행 헤더 그대로)과 그 (epoch, commit_hash).
/// # Errors
/// 못 만든 까닭([`RejoinFail`]).
pub fn rejoin_group(
    m: &Mls,
    keys: &DeviceKeys,
    dir: &DirView,
    gi: &[u8],
    gid: &str,
    plain: &Value,
) -> Result<(String, u64, [u8; 32]), RejoinFail> {
    let (epoch, body) = external_body(m, dir, gi, &group_conv(dir, gid))?;
    let mut msg = plain.clone();
    msg["body"] = body;
    msg["mls_group"] = Value::String(gid.to_owned());
    msg["epoch"] = json!(epoch);
    if let Some(o) = msg.as_object_mut() {
        o.remove("state");
    }
    let frame = sign_frame(keys, msg).ok_or(RejoinFail::Local)?;
    let hash = frame_commit_hash(&frame).ok_or(RejoinFail::Local)?;
    Ok((frame, epoch, hash))
}

/// 헤더 `mls_group` 값 → 그룹 id 바이트([`header_of`] 의 거꾸로).
#[must_use]
pub fn gid_of_header(h: &str) -> Option<Vec<u8>> {
    if h.len() == 26 && h.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Some(h.as_bytes().to_vec())
    } else {
        encoding::decode(h, "mls_group").ok()
    }
}

/// 대화를 남긴 그룹 중 `device` 가 아직 잎이 아닌 것의 수(#577 '지금 끊기').
#[must_use]
pub fn groups_missing_leaf(m: &Mls, device: &str) -> usize {
    m.provider
        .storage()
        .conv_groups()
        .unwrap_or_default()
        .iter()
        .filter_map(|gid| load(m, gid))
        .filter(|g| leaf_of(g, device).is_none())
        .count()
}

/// 잎마다 (잎 번호, 기기 id) — 잎 번호 순.
#[must_use]
pub fn leaf_devices(g: &MlsGroup) -> Vec<(u32, String)> {
    let mut v: Vec<(u32, String)> = g
        .members()
        .filter_map(|m| Some((m.index.u32(), crate::mls_rules::device_of(&m.credential)?)))
        .collect();
    v.sort();
    v
}

/// 그 기기의 잎 자리.
#[must_use]
pub fn leaf_of(g: &MlsGroup, device: &str) -> Option<openmls::prelude::LeafNodeIndex> {
    g.members()
        .find(|m| crate::mls_rules::device_of(&m.credential).is_some_and(|d| d == device))
        .map(|m| m.index)
}

/// 내 Commit 의 commit_hash(서명 프레임의 payload 바이트 SHA-256 — relay 와 같은 계산).
#[must_use]
pub fn frame_commit_hash(frame: &str) -> Option<[u8; 32]> {
    let v: Value = serde_json::from_str(frame).ok()?;
    // blob 으로 옮긴 payload 는 그 내용의 SHA-256 이 곧 commit_hash 다(§5c·§12).
    if let Some(h) = v.pointer("/message/body/payload/blob/sha256") {
        return encoding::decode_array::<32>(h.as_str()?, "sha256").ok();
    }
    let p = v.pointer("/message/body/payload/data")?.as_str()?;
    Some(mls::commit_hash(&encoding::decode(p, "mls").ok()?))
}

/// 확정을 기다리는 group Commit 의 헤더를 남긴다(확정 때 GroupUpdate 로).
///
/// # Errors
/// 저장 오류.
pub fn put_commit_meta(
    m: &Mls,
    gid: &[u8],
    epoch: u64,
    hash: &[u8; 32],
    op: &str,
    actor: &str,
    subject: Option<&str>,
) -> Result<(), crate::mls_store::MlsStoreError> {
    m.provider
        .storage()
        .put_commit_meta(gid, epoch, hash, op, actor, subject)
}

/// 그 Commit 의 (op, actor, subject) — 꺼내 지운다.
#[must_use]
pub fn take_commit_meta(
    m: &Mls,
    gid: &[u8],
    epoch: u64,
    hash: &[u8; 32],
) -> Option<(String, String, Option<String>)> {
    m.provider
        .storage()
        .take_commit_meta(gid, epoch, hash)
        .ok()
        .flatten()
}

/// 확정 뒤 이 기기가 그 그룹에서 빠졌으면(내보내짐·조직에서 빠짐) 그룹을 지운다 — 그 뒤 보내기는 NotGroupMember.
pub fn drop_if_removed(m: &Mls, gid: &[u8]) {
    if load(m, gid).is_some_and(|g| !g.is_active()) {
        drop_group(m, gid);
    }
}

/// 확정 seq 를 남긴다(`joined` 면 이 기기가 들어온 seq 도).
pub fn note_group_seq(m: &Mls, gid: &[u8], seq: u64, joined: bool) {
    let _ = m
        .provider
        .storage()
        .set_group_meta(gid, None, Some(seq), joined.then_some(seq));
}

/// 지금 확정 seq.
#[must_use]
pub fn group_seq_of(m: &Mls, gid: &[u8]) -> u64 {
    m.provider
        .storage()
        .group_meta(gid)
        .ok()
        .flatten()
        .map_or(0, |(_, s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1569 시작을 보내는 것만으로는 대화 주소를 남기지 않는다(동시 시작에서 진 쪽이 「전에 쓰던 대화」로 보이면 안 됨) — ack 뒤
    /// [`remember_own_conv`] 가 받는 쪽과 같은 꼴(세션 slug 없음)로 남기고, group 종류는 거른다.
    #[test]
    fn 시작한_쪽_대화_주소는_받아들여진_뒤에_남긴다() {
        let dir = tempfile::tempdir().unwrap();
        let keys = DeviceKeys::generate(&[5u8; 64]);
        let m = Mls {
            provider: crate::mls::Provider::new(
                crate::mls_store::MlsStore::open(
                    &dir.path().join("c.db"),
                    &zeroize::Zeroizing::new([7; 32]),
                    std::sync::Arc::new(lodelai_effects::OsRng),
                )
                .unwrap(),
            ),
            signer: crate::mls::DeviceSigner::new(keys.signing.clone()),
        };
        let pair = conv("alice", "bob");
        let head = Head {
            keys: &keys,
            from: "alice@relay.test",
            to: "bob@relay.test",
            msg_id: "m1",
            now: UnixMillis(1),
        };
        assert!(start(&m, &head, &pair).is_some());
        assert_eq!(m.provider.storage().conv(&pair.gid).unwrap(), None);
        remember_own_conv(&m, &pair.gid, "bob@relay.test/s1");
        assert_eq!(
            m.provider.storage().conv(&pair.gid).unwrap().as_deref(),
            Some("bob@relay.test")
        );
        let group = b"01m7a4haaa65804m2qf7xj19sg";
        remember_own_conv(&m, group, "bob@relay.test");
        assert_eq!(m.provider.storage().conv(group).unwrap(), None);
    }

    /// #1479: 산 기기가 아닌 잎 때문의 Welcome 은 짧게만 기다리고, 그 밖의 까닭은 Commit 과 같은 상한 — 어느 쪽이든 지나면
    /// 버리지 않고 다시 들기로 넘긴다.
    #[test]
    fn 못_여는_welcome_을_기다리는_시간은_까닭으로_가른다() {
        assert_eq!(welcome_wait_ms("device_unknown"), WELCOME_GONE_LEAF_MS);
        assert_eq!(welcome_wait_ms("revoke_unproved"), WELCOME_GONE_LEAF_MS);
        assert_eq!(welcome_wait_ms("no_chain"), mls::RETRY_MAX_MS);
    }

    /// 평문을 머리(JSON 값)와 본문으로 — 머리 열쇠 차례에 기대지 않고 견준다.
    fn head_and_body(pt: &[u8]) -> (Value, String) {
        let text = std::str::from_utf8(pt).unwrap();
        let (head, body) = text.split_once('\n').unwrap();
        (serde_json::from_str(head).unwrap(), body.to_owned())
    }

    #[test]
    fn mentions_ride_the_plaintext_head_from_anyone() {
        // #627: 큐 본문의 mentions·of 가 평문 머리로 갔다가 돌아오고, 동료가 보낸 것도 본문에 싣는다(검사는 코어).
        let plain = json!({"kind": "chat", "body": {
            "enc": "plain", "text": "@b 봐 줘",
            "mentions": ["b@srv", "c@srv/api"], "of": "01JB0000000000000000000002"}});
        let pt = String::from_utf8(mls_plaintext(&plain, "@b 봐 줘").unwrap()).unwrap();
        let (body, _, extra) = split_plaintext(&pt).unwrap();
        let mut peer = json!({"enc": "plain", "text": body});
        origin_into(&mut peer, extra, false);
        assert_eq!(peer["mentions"], json!(["b@srv", "c@srv/api"]));
        assert_eq!(peer["of"], "01JB0000000000000000000002");
        // 꼴이 틀린 칸(21개·숫자)은 싣지도 옮기지도 않는다 — 글은 그대로.
        let many: Vec<String> = (0..21).map(|i| format!("u{i}@srv")).collect();
        let bad = json!({"kind": "chat", "body": {"enc": "plain", "text": "x", "mentions": many, "of": 7}});
        // 머리 열쇠 차례는 serde_json 기능(preserve_order — 워크스페이스에서 켜짐)에 따라 달라 글자로 견주지 않는다.
        assert_eq!(
            head_and_body(&mls_plaintext(&bad, "x").unwrap()),
            (json!({"kind": "chat", "v": 1}), "x".to_owned())
        );
        let forged = "{\"v\":1,\"mentions\":[1,2]}\nx";
        let (_, _, extra) = split_plaintext(forged).unwrap();
        assert!(extra.is_empty());
    }

    #[test]
    fn agent_rides_the_head_for_push_only() {
        // #1092: 세션이 보낸 글은 머리에 slug, 사람 글·이름 바꾸기엔 없음, 앱이 받는 길(origin_into)은 버린다.
        let plain = json!({"kind": "chat", "from": {"address": "alice@srv/api-2"},
            "body": {"enc": "plain", "text": "hi"}});
        let pt = String::from_utf8(mls_plaintext(&plain, "hi").unwrap()).unwrap();
        // 머리 키 차례는 serde_json preserve_order 가 workspace 에서 켜지느냐로 갈린다 — 값으로 견준다.
        let (head, text) = pt.split_once('\n').unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(head).unwrap(),
            json!({"v": 1, "agent": "api-2", "kind": "chat"})
        );
        assert_eq!(text, "hi");
        let (_, _, extra) = split_plaintext(&pt).unwrap();
        assert_eq!(extra.get(AGENT_KEY), Some(&json!("api-2")));
        for from_me in [true, false] {
            let mut body = json!({"enc": "plain", "text": "hi"});
            origin_into(&mut body, extra.clone(), from_me);
            assert_eq!(
                body,
                json!({"enc": "plain", "text": "hi"}),
                "코어로 가는 글에 agent 없음"
            );
        }
        let person = json!({"kind": "chat", "from": {"address": "alice@srv"},
            "body": {"enc": "plain", "text": "hi"}});
        assert_eq!(
            head_and_body(&mls_plaintext(&person, "hi").unwrap()),
            (json!({"kind": "chat", "v": 1}), "hi".to_owned())
        );
        let rename =
            json!({"kind": "group", "group_op": "rename", "from": {"address": "alice@srv/api"}});
        let pt = String::from_utf8(mls_plaintext(&rename, "{\"name\":\"n\"}").unwrap()).unwrap();
        assert!(!pt.contains("agent"), "{pt}");
        // 꼴이 틀린 칸은 버린다(글은 받음).
        for bad in [
            "\"Api\"",
            "\"-a\"",
            "\"\"",
            "7",
            &format!("\"{}\"", "a".repeat(33)),
        ] {
            let (body, _, extra) =
                split_plaintext(&format!("{{\"v\":1,\"agent\":{bad}}}\nx")).unwrap();
            assert_eq!(body, "x");
            assert!(extra.get(AGENT_KEY).is_none(), "{bad}");
        }
        assert!(agent_shape(&"a".repeat(32)) && agent_shape("0x-1"));
    }

    #[test]
    fn to_peer_rides_the_head_for_replies_to_someone_else() {
        // #1598: 답·거절의 받는 사람(사람 주소)이 보내는 사람과 다르면 머리에 참 하나 — 받는 쪽이 세션 주소여도 사람으로 견준다.
        let msg = |kind: &str, from: &str, to: &str| {
            json!({"v": 9, "kind": kind, "from": {"address": from}, "to": {"address": to},
                "body": {"enc": "plain", "text": "done"}})
        };
        for (kind, from, to, want) in [
            ("reply", "alice@s/web", "bob@s", true),
            ("rejected", "alice@s/web", "bob@s/api", true),
            ("reply", "alice@s/web", "alice@s", false),
            ("reply", "alice@s/web", "alice@s/other", false),
            ("chat", "alice@s/web", "bob@s", false),
            ("request", "alice@s/web", "bob@s", false),
        ] {
            let m = msg(kind, from, to);
            assert_eq!(to_peer(&m), want, "{kind} {from}→{to}");
            assert_eq!(
                pushed_parts(&m).unwrap().to_peer,
                want,
                "{kind} {from}→{to}"
            );
        }
        // 앱이 받는 길에는 옮기지 않는다(봉투가 기준).
        let pt = String::from_utf8(
            mls_plaintext(&msg("reply", "alice@s/web", "bob@s"), "done").unwrap(),
        )
        .unwrap();
        let (_, _, extra) = split_plaintext(&pt).unwrap();
        assert_eq!(extra.get(TO_PEER_KEY), Some(&json!(true)));
        let mut body = json!({"enc": "plain", "text": "done"});
        origin_into(&mut body, extra, true);
        assert!(body.get(TO_PEER_KEY).is_none(), "{body}");
        // 참이 아닌 값은 버린다.
        for bad in ["false", "1", "\"yes\""] {
            let (_, _, extra) =
                split_plaintext(&format!("{{\"v\":1,\"to_peer\":{bad}}}\nx")).unwrap();
            assert!(extra.get(TO_PEER_KEY).is_none(), "{bad}");
        }
    }

    #[test]
    fn to_agent_rides_the_head_for_push_only() {
        // #1598·#1607: 큐 본문 `to_agent: true`(에이전트가 물은 요청의 답)면 머리에 참 하나 — 받는 주소가 사람 주소여도(공개 전
        // 세션이 물은 요청). 칸 없는 답·이름 바꾸기엔 없음, 앱이 받는 길은 버린다.
        let reply = json!({"kind": "reply", "from": {"address": "alice@srv/api-2"},
            "to": {"address": "bob@srv"}, "group": "+g1@srv",
            "body": {"enc": "plain", "text": "done", "to_agent": true}});
        let pt = String::from_utf8(mls_plaintext(&reply, "done").unwrap()).unwrap();
        let (head, text) = pt.split_once('\n').unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(head).unwrap(),
            json!({"v": 1, "agent": "api-2", "to_agent": true, "to_peer": true, "kind": "reply"})
        );
        assert_eq!(text, "done");
        let (_, _, extra) = split_plaintext(&pt).unwrap();
        assert_eq!(extra.get(TO_AGENT_KEY), Some(&json!(true)));
        assert!(pushed_parts(&reply).unwrap().to_agent);
        // 받는 쪽은 누가 보냈든 본문으로(코어가 저장 전에 떼어 알림 사본에만 둔다).
        for from_me in [true, false] {
            let mut body = json!({"enc": "plain", "text": "done"});
            origin_into(&mut body, extra.clone(), from_me);
            assert_eq!(
                body,
                json!({"enc": "plain", "text": "done", "to_agent": true})
            );
        }
        // 사람이 물은 요청의 답(칸 없음)엔 없다 — 받는 주소가 세션 꼴이어도 slug 로 가르지 않는다.
        for to in ["bob@srv", "bob@srv/web"] {
            let to_person = json!({"kind": "reply", "from": {"address": "alice@srv/api-2"},
                "to": {"address": to}, "body": {"enc": "plain", "text": "done"}});
            let pt = String::from_utf8(mls_plaintext(&to_person, "done").unwrap()).unwrap();
            assert!(!pt.contains("to_agent"), "{pt}");
            assert!(!pushed_parts(&to_person).unwrap().to_agent);
        }
        let rename = json!({"kind": "group", "group_op": "rename",
            "from": {"address": "alice@srv"}, "to": {"address": "bob@srv/web"},
            "body": {"enc": "plain", "text": "", "to_agent": true}});
        let pt = String::from_utf8(mls_plaintext(&rename, "{\"name\":\"n\"}").unwrap()).unwrap();
        assert!(!pt.contains("to_agent"), "{pt}");
        // 참이 아닌 값은 버린다(글은 받음) — 옛 꼴(slug)도.
        for bad in ["\"web\"", "false", "\"\"", "7", "\"true\""] {
            let (body, _, extra) =
                split_plaintext(&format!("{{\"v\":1,\"to_agent\":{bad}}}\nx")).unwrap();
            assert_eq!(body, "x");
            assert!(extra.get(TO_AGENT_KEY).is_none(), "{bad}");
        }
    }

    #[test]
    fn own_start_rides_the_head_from_anyone() {
        // #1318: 큐 본문 `own_start: true`(보낸 사람이 시작한 동료 앞 request)면 머리에 참 하나, 받는 쪽은 누가 보냈든 본문으로
        // (출처 칸과 달리 — 코어가 켠 사람 글에서만 읽고 저장 전에 뗀다).
        let req = json!({"kind": "request", "from": {"address": "alice@srv/api"},
            "to": {"address": "bob@srv/web"},
            "body": {"enc": "plain", "text": "q", "own_start": true}});
        let pt = String::from_utf8(mls_plaintext(&req, "q").unwrap()).unwrap();
        let (head, _) = pt.split_once('\n').unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(head).unwrap(),
            json!({"v": 1, "agent": "api", "own_start": true, "kind": "request"})
        );
        let (_, _, extra) = split_plaintext(&pt).unwrap();
        for from_me in [true, false] {
            let mut body = json!({"enc": "plain", "text": "q"});
            origin_into(&mut body, extra.clone(), from_me);
            assert_eq!(
                body,
                json!({"enc": "plain", "text": "q", "own_start": true})
            );
        }
        // 칸 없는 글·참이 아닌 값엔 없다(글은 받음).
        let plain = json!({"kind": "request", "from": {"address": "alice@srv"},
            "body": {"enc": "plain", "text": "q"}});
        let pt = String::from_utf8(mls_plaintext(&plain, "q").unwrap()).unwrap();
        assert!(!pt.contains("own_start"), "{pt}");
        for bad in ["false", "\"true\"", "1", "\"\""] {
            let (body, _, extra) =
                split_plaintext(&format!("{{\"v\":1,\"own_start\":{bad}}}\nx")).unwrap();
            assert_eq!(body, "x");
            assert!(extra.get(OWN_START_KEY).is_none(), "{bad}");
        }
    }

    #[test]
    fn origin_rides_the_plaintext_head_and_only_mine_is_kept() {
        // #490 28 §2: 큐 본문의 처음 출처 칸이 평문 머리로 갔다가 그대로 돌아온다.
        let plain = json!({"kind": "request", "body": {
            "enc": "plain", "text": "a\nb", "origin": "me", "origin_msg": "01JB0000000000000000000001"}});
        let pt = String::from_utf8(mls_plaintext(&plain, "a\nb").unwrap()).unwrap();
        let (body, files, origin) = split_plaintext(&pt).unwrap();
        assert_eq!((body.as_str(), files), ("a\nb", None));
        assert_eq!(origin.get("origin"), Some(&json!("me")));
        assert_eq!(
            origin.get("origin_msg"),
            Some(&json!("01JB0000000000000000000001"))
        );

        // 내가 보낸 것만 본문에 싣는다.
        let mut mine = json!({"enc": "plain", "text": body});
        origin_into(&mut mine, origin.clone(), true);
        assert_eq!(mine["origin"], "me");
        // 동료가 보낸 머리의 origin 은 버린다(origin:"me" 로 게이트를 건너뛰지 못하게).
        let mut peer = json!({"enc": "plain", "text": "a\nb"});
        origin_into(&mut peer, origin, false);
        assert_eq!(peer, json!({"enc": "plain", "text": "a\nb"}));
    }

    #[test]
    fn old_head_without_origin_still_opens() {
        let (body, files, origin) = split_plaintext("{\"v\":1}\nhi").unwrap();
        assert_eq!((body.as_str(), files), ("hi", None));
        assert!(origin.is_empty());
        // 문자열이 아닌 값은 버린다.
        let (_, _, origin) = split_plaintext("{\"v\":1,\"origin\":7}\nhi").unwrap();
        assert!(origin.is_empty());
        // 칸 없는 큐 본문은 머리에 글 종류만(#1470).
        let plain = json!({"kind": "chat", "body": {"enc": "plain", "text": "hi"}});
        assert_eq!(
            head_and_body(&mls_plaintext(&plain, "hi").unwrap()),
            (json!({"kind": "chat", "v": 1}), "hi".to_owned())
        );
        // 종류를 모르는 큐 본문은 머리도 그대로 {"v":1}.
        let plain = json!({"body": {"enc": "plain", "text": "hi"}});
        assert_eq!(mls_plaintext(&plain, "hi").unwrap(), b"{\"v\":1}\nhi");
    }

    /// #1470: 글 종류는 암호문 안 머리에 실려 알림 길(push_open)이 읽고, 앱이 받는 길(바깥 kind 가 기준)에는 넘기지 않는다.
    #[test]
    fn kind_rides_in_head_for_push_only() {
        for kind in ["chat", "reaction", "system", "group", "request"] {
            let plain = json!({"kind": kind, "body": {"enc": "plain", "text": "x"}});
            let pt = String::from_utf8(mls_plaintext(&plain, "x").unwrap()).unwrap();
            let (body, _, extra) = split_plaintext(&pt).unwrap();
            assert_eq!(body, "x");
            assert_eq!(extra.get(KIND_KEY), Some(&json!(kind)), "{pt}");
            for from_me in [true, false] {
                let mut b = json!({"enc": "plain", "text": "x"});
                origin_into(&mut b, extra.clone(), from_me);
                assert_eq!(
                    b,
                    json!({"enc": "plain", "text": "x"}),
                    "코어로 가는 글에 kind 없음"
                );
            }
        }
        // 그룹 이름 바꾸기 머리(meta)에도 같이 실린다.
        let rename = json!({"kind": "group", "group_op": "rename", "from": {"address": "a@srv"}});
        let pt = String::from_utf8(mls_plaintext(&rename, "{\"name\":\"n\"}").unwrap()).unwrap();
        assert_eq!(
            split_plaintext(&pt).unwrap().2.get(KIND_KEY),
            Some(&json!("group"))
        );
        // 꼴이 틀린 종류는 싣지도 읽지도 않는다(글은 받음).
        let plain = json!({"kind": "Chat!", "body": {"enc": "plain", "text": "x"}});
        assert_eq!(mls_plaintext(&plain, "x").unwrap(), b"{\"v\":1}\nx");
        let (_, _, extra) = split_plaintext("{\"v\":1,\"kind\":7}\nx").unwrap();
        assert!(extra.get(KIND_KEY).is_none());
        assert!(
            kind_shape("own_control") && !kind_shape("") && !kind_shape("a".repeat(25).as_str())
        );
    }

    /// #1470: 반응의 원글 작성자는 큐 본문 칸에서 머리로 옮겨 알림 길만 읽는다 — 코어로는 넘기지 않고, 꼴이 틀리면 버린다.
    #[test]
    fn target_author_rides_in_head_for_push_only() {
        let plain = json!({"kind": "reaction",
            "body": {"enc": "plain", "text": "{}", "target_author": "dana@srv"}});
        let pt = String::from_utf8(mls_plaintext(&plain, "{}").unwrap()).unwrap();
        let (body, _, extra) = split_plaintext(&pt).unwrap();
        assert_eq!(body, "{}");
        assert_eq!(
            extra.get(TARGET_AUTHOR_KEY),
            Some(&json!("dana@srv")),
            "{pt}"
        );
        for from_me in [true, false] {
            let mut b = json!({"enc": "plain", "text": "{}"});
            origin_into(&mut b, extra.clone(), from_me);
            assert_eq!(b, json!({"enc": "plain", "text": "{}"}));
        }
        for bad in [
            json!("dana@srv/api"),
            json!("dana"),
            json!("@srv"),
            json!("a b@srv"),
            json!(7),
        ] {
            let plain = json!({"kind": "reaction",
                "body": {"enc": "plain", "text": "{}", "target_author": bad}});
            let pt = String::from_utf8(mls_plaintext(&plain, "{}").unwrap()).unwrap();
            assert!(!pt.contains("target_author"), "{pt}");
        }
        let (_, _, extra) = split_plaintext("{\"v\":1,\"target_author\":\"x\"}\n{}").unwrap();
        assert!(extra.get(TARGET_AUTHOR_KEY).is_none());
    }
}
