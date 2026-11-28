//! 상대 기기 공개키 — 디렉터리 TOFU(ADR 0006, protocol §7 "기기 공개키 배포", #132)와 수신 재검증.
//!
//! - 디렉터리의 각 기기 항목은 `ed25519` 로 `device_id` 를 **재계산해 대조**하고 `x25519_sig`(#313, `lodelai-xkey-v1`)를 검증한다.
//!   하나라도 틀리거나 **서명이 없으면** 버리고 [`Learned::Mismatch`] — 서버가 필드를 빼서 검증을 건너뛰게 두지 않는다. 지문이 맞아도
//!   x25519 가 바꿔 끼워졌으면 본문이 서버 키로 감싸지기 때문이다(e2e-envelope §2).
//! - 신뢰 상태(e2e-envelope §7, #313 결정 b): 처음 보는 사람의 첫 기기들 = `trusted`(TOFU 뿌리, [`Learned::FirstContact`]).
//!   이미 아는 사람에게 새 기기가 나타나면 `pending`([`Learned::NewDevice`]) — 사람이 확인하기 전엔 감싸지 않고 그 기기에서 온 것은
//!   보류한다. 전체 목록에서 사라진 기기 = `revoked`([`Learned::Revoked`]), 다시 나타나면 `pending`(같은 `device_id` 라도 다시 확인).
//!   `device_id` 는 공개키의 지문이므로 "키 변경"은 곧 "새 기기"다.
//! - **내 사용자 항목도 같은 규칙으로 배운다**(#339 — 내 다른 기기에 "새 기기 추가됨"): 처음 본 내 기기 집합 = 뿌리, 이후 = `pending`.
//!   이 기기 자신은 늘 `trusted` 이고 알리지 않는다. 감싸기 대상에서는 뺀다(M2 는 발신자 본인 기기를 감싸지 않는다 — `outbox::seal_send`).
//! - 이미 고정한 `device_id` 가 다른 사용자로 오면 무시하고 [`Learned::Mismatch`].
//! - **내 기기 서명**(#393, e2e-envelope §7a): `pending` 기기에 그 사용자의, 내가 `trusted` 로 둔 다른 기기가 한 서명
//!   (`certs`, `lodelai-devcert-v1`)이 맞으면 `trusted`([`Learned::CertTrusted`], 근거 `cert:<서명자>`). 방금 그렇게 믿게 된
//!   기기가 다른 기기의 서명자일 수 있어 바뀔 것이 없을 때까지 다시 본다. 서명자가 폐기되면 그 근거를 지우고 근거가 하나도
//!   남지 않은 기기만 `pending` 으로 되돌린다([`Learned::CertLost`]) — 사람 확인·TOFU 근거가 있으면 내리지 않는다.
//! - **뿌리 바뀜**(묶음 22 §2c): 사람마다 이번 목록의 뿌리([`mls_rules::roots`] — relay 와 같은 계산)를 마지막으로 본 것과
//!   비교해 바뀌었으면 [`Learned::RootChanged`](대화마다 조용한 기록 줄 하나). 처음 본 뿌리는 조용히 남긴다. 멈추지 않는다.

use lodelai_crypto::{encoding, verify_message, xkey, DeviceId, VerifyingKey};
use lodelai_effects::UnixMillis;
use serde_json::Value;

use crate::mls_rules::{self, DirDevice, Revocation};
use crate::outbox::{Peer, Store, Trust};
use crate::{RejectReason, Result};

/// 디렉터리에서 배운 것 중 알릴 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Learned {
    /// 처음 보는 사람의 기기 — `trusted` 로 고정(TOFU 뿌리).
    FirstContact(Peer),
    /// 이미 아는 사람의 새 기기(또는 사라졌다 다시 나타난 기기) — `pending`.
    NewDevice(Peer),
    /// 전체 목록에서 사라진 기기 — `revoked`.
    Revoked(Peer),
    /// 주인의 다른 기기 서명으로 `trusted`(#393 §7a-2).
    CertTrusted(Peer),
    /// 서명자가 폐기돼 근거가 없어진 기기 — `pending` 으로 되돌림(#393 §7a-4).
    CertLost(Peer),
    /// 그 사람의 뿌리가 바뀌었다(사슬이 끊김 — 모두 잃은 복구·서버 폐기·바꿔치기, 묶음 22 §2c). `root` = 새 뿌리 device_id.
    RootChanged {
        user: String,
        root: String,
    },
    Mismatch {
        user: String,
        device_id: String,
    },
}

/// 디렉터리의 사람 항목(#845 §7-14): 같은 조직 `people` + 수락된 연락처 `links` + 섞인 그룹의 `group_members`(같은 꼴의
/// 기기·인증서·폐기). 요청 중(`link_requests`)·초대는 넣지 않는다 — relay 가 links 에 수락된 사람만 싣고 끊기·차단은 행을 지우니
/// 저절로 빠진다. 같은 사용자는 처음 것 하나만. `(사용자 아이디, 항목, 그룹으로만 아는 사람인가)`.
pub(crate) fn person_items(frame: &Value) -> Vec<(String, &Value, bool)> {
    let mut out: Vec<(String, &Value, bool)> = Vec::new();
    for key in ["people", "links", "group_members"] {
        for p in frame
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let user = p
                .get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                .or_else(|| p.get("user").and_then(Value::as_str));
            let Some(user) = user.filter(|u| !u.is_empty()) else {
                continue;
            };
            if !out.iter().any(|(u, _, _)| u == user) {
                out.push((user.to_owned(), p, key == "group_members"));
            }
        }
    }
    out
}

/// `directory`·`directory.update` 의 사람 항목([`person_items`] — 같은 조직·연락처·그룹 멤버)을 읽어 고정하고 신뢰 상태를 맞춘다. `me` = 내 사용자,
/// `my_device` = 이 기기(늘 `trusted`, 알리지 않음), `server` = `ready.server`(서명 검증 입력), `now_ms` = 지금(기다림 시작).
///
/// # Errors
/// 저장 오류.
pub fn learn_directory(
    store: &Store,
    frame: &Value,
    me: &str,
    my_device: &str,
    server: &str,
    now_ms: i64,
) -> Result<Vec<Learned>> {
    let mut out = Vec::new();
    for (user, person, _) in person_items(frame) {
        let user = user.as_str();
        // 폐기된 행도 센다 — 기기를 다 뺐던 사람의 새 기기도 pending 이다.
        let known_before = store.peer_count(user)?;
        // #847: 내 항목의 TOFU 는 이 기기보다 먼저 든 기기에만(그 기기들은 이미 계정의 기기). 이 기기보다 뒤에 든 내 기기는
        // 이 기기나 다른 믿는 기기의 확인(cert)이 있어야 한다 — 첫 디렉터리 전에 등록된 휴대폰이 확인 없이 믿기지 않게.
        let added = |d: &Value| {
            d.get("added_at")
                .and_then(Value::as_str)
                .and_then(|t| UnixMillis::parse_rfc3339(t).ok())
                .map(|t| t.0)
        };
        let my_added = (user == me)
            .then(|| {
                person
                    .get("devices")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|d| d.get("device_id").and_then(Value::as_str) == Some(my_device))
                    .and_then(added)
            })
            .flatten();
        let mut listed: Vec<String> = Vec::new();
        // 키 검증을 지난 기기(뿌리 계산).
        let mut seen: Vec<DirDevice> = Vec::new();
        for d in person
            .get("devices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let device_id = d
                .get("device_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let ed = d
                .pointer("/device_pubkeys/ed25519")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let x = d
                .pointer("/device_pubkeys/x25519")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(dd) = dir_device(user, d) else {
                out.push(Learned::Mismatch {
                    user: user.to_owned(),
                    device_id: device_id.to_owned(),
                });
                continue;
            };
            seen.push(dd);
            if user == me && device_id == my_device {
                // 이 기기 자신 — 늘 trusted(뿌리), 카드 없음.
                match store.peer(device_id)? {
                    Some(p) if p.user == user => {
                        if p.trust != Trust::Trusted {
                            store.set_trust(device_id, Trust::Trusted)?;
                        }
                    }
                    Some(_) => {}
                    None => store.add_peer(&Peer {
                        device_id: device_id.to_owned(),
                        user: user.to_owned(),
                        ed25519: ed.to_owned(),
                        x25519: x.to_owned(),
                        trust: Trust::Trusted,
                        first_contact: false,
                    })?,
                }
                listed.push(device_id.to_owned());
                continue;
            }
            match store.peer(device_id)? {
                Some(p) if p.user == user => {
                    listed.push(device_id.to_owned());
                    let basis = store.basis(device_id)?;
                    if basis.iter().any(|b| is_planted(b)) {
                        let kept: Vec<String> =
                            basis.into_iter().filter(|b| !is_planted(b)).collect();
                        store.set_basis(device_id, &kept)?;
                    }
                    // 다시 나타난·옛 판에서 pending 으로 남은 동료 기기는 MLS 잎 자격이 정한다(묶음 22 §2c — 사람 확인 카드
                    // 없음). 내 기기만 확인 흐름.
                    if p.trust != Trust::Trusted && user != me {
                        store.set_trust(device_id, Trust::Trusted)?;
                        store.set_basis(device_id, &["mls_leaf".to_owned()])?;
                    } else if p.trust == Trust::Revoked {
                        store.set_trust(device_id, Trust::Pending)?;
                        store.set_basis(device_id, &[])?;
                        store.set_pending_since(device_id, Some(now_ms))?;
                        out.push(Learned::NewDevice(Peer {
                            trust: Trust::Pending,
                            first_contact: false,
                            ..p
                        }));
                    }
                }
                Some(_) => out.push(Learned::Mismatch {
                    user: user.to_owned(),
                    device_id: device_id.to_owned(),
                }),
                None => {
                    // 동료의 새 기기는 확인 카드 없이 받는다 — 보낼 잎은 MLS 잎 자격이 정한다(묶음 22 §2c). 내 새 기기만 pending.
                    // 시각을 모르면(옛 relay) 뒤에 든 것으로 본다 — 안전한 쪽, cert 가 오면 곧 풀린다.
                    let before_me = || matches!((added(d), my_added), (Some(t), Some(m)) if t < m);
                    let first = known_before == 0 && (user != me || before_me());
                    let trusted = first || user != me;
                    let p = Peer {
                        device_id: device_id.to_owned(),
                        user: user.to_owned(),
                        ed25519: ed.to_owned(),
                        x25519: x.to_owned(),
                        trust: if trusted {
                            Trust::Trusted
                        } else {
                            Trust::Pending
                        },
                        first_contact: first,
                    };
                    store.add_peer(&p)?;
                    if first {
                        store.set_basis(device_id, &["first_contact".to_owned()])?;
                    } else if trusted {
                        store.set_basis(device_id, &["mls_leaf".to_owned()])?;
                    } else {
                        store.set_pending_since(device_id, Some(now_ms))?;
                    }
                    listed.push(device_id.to_owned());
                    out.push(if first {
                        Learned::FirstContact(p)
                    } else {
                        Learned::NewDevice(p)
                    });
                }
            }
        }
        if let Some(root) = mls_rules::roots(server, user, &seen, &revocations_of(person)).root {
            match store.last_root(user)? {
                Some(old) if old == root => {}
                old => {
                    store.set_root(user, &root, now_ms)?;
                    if old.is_some() {
                        out.push(Learned::RootChanged {
                            user: user.to_owned(),
                            root,
                        });
                    }
                }
            }
        }
        // 전체 목록에서 사라진 기기 → revoked. 심어 두고 아직 등록 전인 내 기기(PLANTED)는 목록에 없어도
        // [`PLANTED_TTL_MS`] 까지는 그대로 — 지나면 표시를 지우고 보통 규칙(폐기)으로.
        for p in store.peers_of(user)? {
            if p.trust == Trust::Revoked || listed.contains(&p.device_id) {
                continue;
            }
            let basis = store.basis(&p.device_id)?;
            let planted_at = basis.iter().find_map(|b| {
                b.strip_prefix(PLANTED)
                    .and_then(|r| r.strip_prefix(':'))
                    .and_then(|t| t.parse::<i64>().ok())
            });
            if planted_at.is_some_and(|t| now_ms.saturating_sub(t) < PLANTED_TTL_MS) {
                continue;
            }
            if planted_at.is_some() {
                let kept: Vec<String> = basis.into_iter().filter(|b| !is_planted(b)).collect();
                store.set_basis(&p.device_id, &kept)?;
            }
            store.set_trust(&p.device_id, Trust::Revoked)?;
            out.push(Learned::Revoked(Peer {
                trust: Trust::Revoked,
                ..p
            }));
        }
        // 내 기기 서명(§7a) — 이 기기 자신은 뿌리라 볼 것이 없다.
        certs(store, person, user, my_device, server, now_ms, &mut out)?;
    }
    Ok(out)
}

/// 신뢰 근거 표시: 주인이 연결 코드로 심었고 아직 디렉터리에 나온 적 없는 내 기기([`crate::RelayClient::plant_own_device`]).
/// 저장 꼴은 `planted:<심은 시각 ms>`.
pub const PLANTED: &str = "planted";
/// 심은 기기가 이만큼 지나도 디렉터리에 안 나오면 보통 규칙으로(등록 실패 — 설계 c39e1519 권고).
pub const PLANTED_TTL_MS: i64 = 24 * 60 * 60 * 1000;

fn is_planted(b: &str) -> bool {
    b == PLANTED || b.starts_with("planted:")
}

/// 벽시계 ms — 디렉터리 처리(conn)와 같은 시계로 심은 시각을 잰다.
#[must_use]
pub fn wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `plant_own_device` 가 남기는 근거 값.
#[must_use]
pub fn planted_basis(now_ms: i64) -> String {
    format!("{PLANTED}:{now_ms}")
}

/// `device.revoke` 의 폐기 증명 `proof{at, sig}`(묶음 22 §12-11 ⓐ): 내 기기가 내 기기(또는 자신)를 끊을 때 싣는다 —
/// 받는 쪽이 뿌리 그래프에서 그 기기를 고리로 남겨 사슬이 끊기지 않게. `at` 은 주입된 시계의 지금(relay 가 ±5분을 본다).
#[must_use]
pub fn revoke_proof(
    keys: &lodelai_crypto::DeviceKeys,
    server: &str,
    device_id: &str,
    now: UnixMillis,
) -> Value {
    let at = now.to_rfc3339().unwrap_or_default();
    let sig = lodelai_crypto::devrevoke::sign(
        &keys.signing,
        &lodelai_crypto::devrevoke::Revoke {
            server,
            device_id,
            at: &at,
        },
    );
    serde_json::json!({"at": at, "sig": sig})
}

/// 디렉터리 기기 항목 하나 — 키 검증(device_id = ed25519 지문, x25519 서명)을 지난 것만(뿌리 계산·MLS 잎 자격).
fn dir_device(user: &str, d: &Value) -> Option<DirDevice> {
    let device_id = d.get("device_id").and_then(Value::as_str)?;
    let ed = d
        .pointer("/device_pubkeys/ed25519")
        .and_then(Value::as_str)?;
    let x = d
        .pointer("/device_pubkeys/x25519")
        .and_then(Value::as_str)?;
    let sig = d
        .pointer("/device_pubkeys/x25519_sig")
        .and_then(Value::as_str)?;
    let vk = VerifyingKey::from_b64(ed).ok()?;
    let x25519 = encoding::decode_array::<32>(x, "x25519").ok()?;
    let ok = DeviceId::parse(device_id).is_some_and(|id| id.matches(&vk))
        && xkey::verify(&vk, device_id, &x25519, sig);
    ok.then(|| DirDevice {
        device_id: device_id.to_owned(),
        user: user.to_owned(),
        ed25519: vk.to_bytes(),
        x25519,
        // 모르면 뿌리 후보 맨 뒤.
        added_ms: d
            .get("added_at")
            .and_then(Value::as_str)
            .and_then(|t| UnixMillis::parse_rfc3339(t).ok())
            .map_or(i64::MAX, |t| t.0),
        certs: certs_of(d),
    })
}

/// 이 기기가 내 뿌리 사슬 밖(승인 전)인가(#846·#888) — 디렉터리의 내 항목에 이 기기가 있고 뿌리가 서는데 잎 자격이 없으면
/// 참. 내 항목·이 기기가 없거나 뿌리를 못 세우면 모르는 것이라 거짓(받는 쪽 잎 자격과 같은 계산).
#[must_use]
pub fn device_pending(frame: &Value, server: &str, user: &str, device_id: &str) -> bool {
    let me = format!("{user}@{server}");
    let listed = frame
        .get("people")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("address").and_then(Value::as_str) == Some(me.as_str()))
        .filter_map(|p| p.get("devices").and_then(Value::as_array))
        .flatten()
        .any(|d| d.get("device_id").and_then(Value::as_str) == Some(device_id));
    if !listed {
        return false;
    }
    let roots = crate::mls_rules::roots_in(&DirView::new(frame, server), user);
    roots.root.is_some() && !roots.eligible.contains(device_id)
}

/// 받은 디렉터리 한 장의 MLS 잎 자격 보기([`mls_rules::Directory`]) — 키 검증을 지난 기기와 증명 있는 폐기만.
#[derive(Debug, Clone, Default)]
pub struct DirView {
    server: String,
    devices: Vec<DirDevice>,
    revocations: Vec<(String, Revocation)>,
    /// 디렉터리에서 사라진 기기 → 옛 사용자(피어 표 `revoked`).
    former: Vec<(String, String)>,
    /// 섞인 그룹의 멤버로만 아는 사용자(#845 §7-14) — 그룹 잎은 보지만 1:1 을 열지 않는다.
    group_only: Vec<String>,
}

impl DirView {
    /// `directory`·`directory.update` 프레임(또는 그 합본)에서.
    #[must_use]
    pub fn new(frame: &Value, server: &str) -> Self {
        let mut v = Self {
            server: server.to_owned(),
            ..Self::default()
        };
        for (user, person, group_only) in person_items(frame) {
            let user = user.as_str();
            if group_only {
                v.group_only.push(user.to_owned());
            }
            v.devices.extend(
                person
                    .get("devices")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|d| dir_device(user, d)),
            );
            v.revocations.extend(
                revocations_of(person)
                    .into_iter()
                    .map(|r| (user.to_owned(), r)),
            );
        }
        v
    }

    /// 그룹 멤버로만 아는 사용자(1:1 대상 아님, #845 §7-14).
    #[must_use]
    pub fn group_only(&self, user: &str) -> bool {
        self.group_only.iter().any(|u| u == user)
    }
}

impl DirView {
    /// 디렉터리에 있는 사람(잎 자격 있는 기기가 하나라도 있는).
    #[must_use]
    pub fn users(&self) -> Vec<String> {
        let mut u: Vec<String> = self.devices.iter().map(|d| d.user.clone()).collect();
        u.sort();
        u.dedup();
        u
    }

    /// 그룹 트리에 잎이 있을 수 있는 사람: [`Self::users`] + 산 기기는 없지만 폐기 기록이 실린 사람(#1201 — 하나뿐인 기기를
    /// 폐기한 멤버의 옛 잎을 `device_unknown` 이 아니라 폐기 잎으로 알아보게).
    #[must_use]
    pub fn leaf_users(&self) -> Vec<String> {
        let mut u = self.users();
        u.extend(self.revocations.iter().map(|(user, _)| user.clone()));
        u.sort();
        u.dedup();
        u
    }
}

impl DirView {
    /// 이 디렉터리에 산 기기로 실린 기기인가(누구 것이든).
    #[must_use]
    pub fn knows(&self, device_id: &str) -> bool {
        self.devices.iter().any(|d| d.device_id == device_id)
    }

    /// 피어 표의 `revoked` 기기를 옛 사용자로 붙인다([`mls_rules::Directory::former_user`]).
    #[must_use]
    pub fn with_former(mut self, store: &crate::outbox::Store) -> Self {
        self.former = store
            .peers()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.trust == Trust::Revoked)
            .map(|p| (p.device_id, p.user))
            .collect();
        self
    }
}

impl mls_rules::Directory for DirView {
    fn former_user(&self, device_id: &str) -> Option<String> {
        self.former
            .iter()
            .find(|(d, _)| d == device_id)
            .map(|(_, u)| u.clone())
    }
    fn server(&self) -> &str {
        &self.server
    }
    fn devices(&self, user: &str) -> Vec<DirDevice> {
        self.devices
            .iter()
            .filter(|d| d.user == user)
            .cloned()
            .collect()
    }
    fn revocations(&self, user: &str) -> Vec<Revocation> {
        self.revocations
            .iter()
            .filter(|(u, _)| u == user)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

/// 새 디렉터리에 앞 디렉터리에 없던 증명 있는 폐기가 실렸나(#1543) — 끊긴 잎 때문에 다시 들어가지 못하던 대화가 그 기록만으로
/// 열릴 수 있다. 앞 디렉터리가 아직 없으면(접속 직후) 거짓 — 그때는 다시 들기가 어차피 바로 돈다.
#[must_use]
pub fn revocation_gained(old: &Value, new: &Value) -> bool {
    if old.is_null() {
        return false;
    }
    let ids = |f: &Value| -> std::collections::HashSet<String> {
        person_items(f)
            .into_iter()
            .flat_map(|(_, person, _)| revocations_of(person))
            .map(|r| r.device_id)
            .collect()
    };
    let had = ids(old);
    ids(new).iter().any(|id| !had.contains(id))
}

/// 디렉터리 사람 항목의 `revocations`(증명 있는 폐기, §12-11 ⓐ). 꼴이 틀린 항목은 버린다(마디가 안 됨).
pub(crate) fn revocations_of(person: &Value) -> Vec<Revocation> {
    person
        .get("revocations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let s = |k: &str| r.get(k).and_then(Value::as_str);
            // 폐기 증명의 서명 입력에는 키가 없다(server·device_id·at) — 기기 아이디가 키의 해시이므로 여기서 견줘야 키가
            // 묶인다(#1511). 안 맞으면 버린다: relay 가 진짜 폐기 기록의 키만 바꿔 그 기기 이름으로 devcert 를 지어내지 못하게.
            let vk = VerifyingKey::from_b64(s("ed25519")?).ok()?;
            if !DeviceId::parse(s("device_id")?).is_some_and(|id| id.matches(&vk)) {
                return None;
            }
            Some(Revocation {
                device_id: s("device_id")?.to_owned(),
                added_ms: UnixMillis::parse_rfc3339(s("added_at")?).ok()?.0,
                ed25519: vk.to_bytes(),
                x25519: encoding::decode_array::<32>(s("x25519")?, "x25519").ok()?,
                certs: certs_of(r),
                at: s("at")?.to_owned(),
                signer: s("signer")?.to_owned(),
                sig: s("sig")?.to_owned(),
            })
        })
        .collect()
}

/// 디렉터리에 `signer` 가 `target` 기기에 한 내 기기 서명이 실렸나(#577 '지금 끊기' — 서명이 relay 에 닿았나). 서명 검증은 하지
/// 않는다(기다림 판단용 — 신뢰 판정은 [`mls_rules::roots`]).
#[must_use]
pub fn signed_by(frame: &Value, target: &str, signer: &str) -> bool {
    frame
        .get("people")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|p| {
            p.get("devices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|d| d.get("device_id").and_then(Value::as_str) == Some(target))
        .any(|d| certs_of(d).iter().any(|(s, _)| s == signer))
}

/// 디렉터리 기기 항목의 `certs` → (서명자, 서명).
fn certs_of(d: &Value) -> Vec<(String, String)> {
    d.get("certs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| {
            Some((
                c.get("signer")?.as_str()?.to_owned(),
                c.get("sig")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// 한 사람의 기기들에 서명 근거를 맞춘다(§7a-2·4). 먼저 폐기된 서명자의 근거를 지우고(근거 0개면 pending), 그다음
/// 바뀔 것이 없을 때까지 pending 기기의 서명을 본다.
fn certs(
    store: &Store,
    person: &Value,
    user: &str,
    my_device: &str,
    server: &str,
    now_ms: i64,
    out: &mut Vec<Learned>,
) -> Result<()> {
    let devices: Vec<&Value> = person
        .get("devices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    let entry = |id: &str| {
        devices
            .iter()
            .find(|d| d.get("device_id").and_then(Value::as_str) == Some(id))
            .copied()
    };
    let trusted_signer = |id: &str| -> Result<Option<Peer>> {
        Ok(store
            .peer(id)?
            .filter(|p| p.user == user && p.trust == Trust::Trusted && entry(id).is_some()))
    };
    // 4. 서명자가 폐기·사라졌으면 그 근거를 지운다. 근거가 없어진 기기만 pending(기다림을 지금부터 다시). 그 기기가 또
    //    다른 기기의 서명자일 수 있어 바뀔 것이 없을 때까지.
    loop {
        let mut lost = false;
        for p in store.peers_of(user)? {
            if p.trust != Trust::Trusted || p.device_id == my_device {
                continue;
            }
            let basis = store.basis(&p.device_id)?;
            let kept: Vec<String> = basis
                .iter()
                .filter(|b| {
                    b.strip_prefix("cert:").is_none_or(|signer| {
                        signer != p.device_id && trusted_signer(signer).ok().flatten().is_some()
                    })
                })
                .cloned()
                .collect();
            if kept.len() == basis.len() {
                continue;
            }
            store.set_basis(&p.device_id, &kept)?;
            if kept.is_empty() {
                store.set_trust(&p.device_id, Trust::Pending)?;
                store.set_pending_since(&p.device_id, Some(now_ms))?;
                out.push(Learned::CertLost(Peer {
                    trust: Trust::Pending,
                    ..p
                }));
                lost = true;
            }
        }
        if !lost {
            break;
        }
    }
    // 2. pending 기기에 믿는 서명자의 맞는 서명이 있으면 trusted — 새로 믿게 된 기기가 또 서명자일 수 있어 반복.
    loop {
        let mut changed = false;
        for p in store.peers_of(user)? {
            if p.trust != Trust::Pending {
                continue;
            }
            let Some(d) = entry(&p.device_id) else {
                continue;
            };
            let Ok(x) = encoding::decode_array::<32>(&p.x25519, "x25519") else {
                continue;
            };
            let mut signers = Vec::new();
            for (signer, sig) in certs_of(d) {
                if signer == p.device_id {
                    continue;
                }
                let Some(sp) = trusted_signer(&signer)? else {
                    continue;
                };
                let Ok(vk) = VerifyingKey::from_b64(&sp.ed25519) else {
                    continue;
                };
                let cert = lodelai_crypto::devcert::Cert {
                    server,
                    user,
                    device_id: &p.device_id,
                    x25519: &x,
                    signer: &signer,
                };
                if lodelai_crypto::devcert::verify(&vk, &cert, &sig) {
                    signers.push(format!("cert:{signer}"));
                } else {
                    tracing::warn!(
                        user,
                        device = p.device_id,
                        signer,
                        "내 기기 서명이 맞지 않음 — 무시"
                    );
                }
            }
            if signers.is_empty() {
                continue;
            }
            store.set_trust(&p.device_id, Trust::Trusted)?;
            store.set_basis(&p.device_id, &signers)?;
            store.set_pending_since(&p.device_id, None)?;
            out.push(Learned::CertTrusted(Peer {
                trust: Trust::Trusted,
                ..p
            }));
            changed = true;
        }
        if !changed {
            return Ok(());
        }
    }
}

/// 내 다른 기기에 내 기기 서명을 큐에 넣는다(`device.certify`, §7a-1). 같은 대상은 하나만(덮어씀) — 응답 없는 프레임.
///
/// # Errors
/// x25519 해석·저장 오류.
pub fn queue_certify(
    store: &Store,
    keys: &lodelai_crypto::DeviceKeys,
    server: &str,
    me: &str,
    device_id: &str,
    x25519_b64: &str,
) -> Result<()> {
    let x = encoding::decode_array::<32>(x25519_b64, "x25519")
        .map_err(|e| crate::Error::Relay(format!("x25519: {e}")))?;
    let signer = keys.device_id();
    let cert = lodelai_crypto::devcert::Cert {
        server,
        user: me,
        device_id,
        x25519: &x,
        signer: signer.as_str(),
    };
    let sig = lodelai_crypto::devcert::sign(&keys.signing, &cert);
    let f = serde_json::json!({"t": "device.certify", "device_id": device_id, "sig": sig});
    // 서명해 준 기기는 같은 묶음으로 적어 둔다(#1479 — 그 기기의 폐기 증명에는 서명하지 않는다).
    store.push_certify(device_id, &f.to_string())
}

/// relay 가 「이 기기(`my_device`)가 건 메일 확인 끊기로 끊겼다」고 준 내 기기들(#1479): 내 항목의
/// `recovery{state: "done", requester, targets}`(끊은 뒤 24시간)와 `unproved_revocations[{device_id, requester}]`(증명이 붙을
/// 때까지). relay 의 말일 뿐이다 — 서명할지는 [`late_proof_targets`] 가 정한다.
#[must_use]
pub fn recovery_cut_by(frame: &Value, me: &str, my_device: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in frame
        .get("people")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p.get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                == Some(me)
        })
    {
        let mine = |v: &Value| v.get("requester").and_then(Value::as_str) == Some(my_device);
        let done = p
            .get("recovery")
            .filter(|r| r.get("state").and_then(Value::as_str) == Some("done") && mine(r));
        let from_done = done
            .and_then(|r| r.get("targets"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        let from_list = p
            .get("unproved_revocations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|u| mine(u))
            .filter_map(|u| u.get("device_id").and_then(Value::as_str));
        for id in from_done.chain(from_list) {
            if !out.iter().any(|x| x == id) {
                out.push(id.to_owned());
            }
        }
    }
    out
}

/// 메일 확인 끊기를 걸면 끊길 대상: 내 항목에서 이 기기보다 먼저 든 기기(relay 규칙 — 「먼저 등록된 내 기기 전부」). 이 기기의
/// 등록 시각을 모르면 빈 목록.
#[must_use]
pub fn older_own_devices(frame: &Value, me: &str, my_device: &str) -> Vec<String> {
    let at = |d: &Value| {
        d.get("added_at")
            .and_then(Value::as_str)
            .and_then(|t| UnixMillis::parse_rfc3339(t).ok())
            .map(|t| t.0)
    };
    let devices: Vec<&Value> = person_items(frame)
        .into_iter()
        .filter(|(u, _, _)| u == me)
        .flat_map(|(_, p, _)| {
            p.get("devices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect();
    let id = |d: &Value| {
        d.get("device_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let Some(mine) = devices
        .iter()
        .find(|d| id(d).as_deref() == Some(my_device))
        .and_then(|d| at(d))
    else {
        return Vec::new();
    };
    devices
        .iter()
        .filter(|d| at(d).is_some_and(|t| t < mine))
        .filter_map(|d| id(d))
        .collect()
}

/// 이 기기가 내 다른 기기의 서명을 하나도 받지 않았나(#1479 옛 끊기 예외 ① — 디렉터리의 내 기기 줄 `certs` 가 빔).
/// 디렉터리가 certs 를 감추면 참으로 보인다 — 이 조건 하나에 기대지 않는다.
#[must_use]
pub fn unsigned_root(frame: &Value, me: &str, my_device: &str) -> bool {
    frame
        .get("people")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p.get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                == Some(me)
        })
        .flat_map(|p| {
            p.get("devices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .find(|d| d.get("device_id").and_then(Value::as_str) == Some(my_device))
        .is_some_and(|d| certs_of(d).is_empty())
}

/// 뒤늦은 폐기 증명을 이만큼 보내고도 받아지지 않으면 그 기기는 그만둔다(#1479 — relay 가 거절 까닭을 가르지 않는다).
pub const LATE_PROOF_TRIES: u32 = 5;

/// 뒤늦은 폐기 증명(#1479)에 서명할 기기: 적어 둔 대상(`noted`) 가운데 relay 가 「그 끊기로 끊겼다」고 준 것(`relay_targets`)만.
/// relay 말만으로는 서명하지 않는다. 빼는 것:
/// - 이 기기 자신, 이 디렉터리에 산 기기로 있는 것(산 기기에 보내면 그대로 끊긴다 — 호출자는 새로 당긴 디렉터리로 부른다)
/// - 이미 끝났거나(`proved`·`refused`) [`LATE_PROOF_TRIES`] 를 채운 것
/// - **옛 끊기의 대상(`legacy` — relay 목록에서 받아 적은 것)만**: 이 기기가 내 기기 서명을 내 준 기기(`certified`)와 그 아래
///   (디렉터리 certs 로 이어지는 만큼 — 서명 검증 없이 넓게 막는다. 디렉터리가 certs 를 감추면 그 아래의 아래는 못 막는다).
///   걸 때 적어 둔 대상은 사용자가 화면에서 보고 끊기로 정한 기기라 서명해 줬는지를 보지 않는다(새 기기는 붙자마자 옛 기기에
///   자동 재서명을 큐에 넣는다 — 그것까지 막으면 직접 건 끊기의 증명이 영영 안 나간다).
#[must_use]
pub fn late_proof_targets(
    noted: &[crate::outbox::RecoverNoted],
    certified: &[String],
    relay_targets: &[String],
    frame: &Value,
    me: &str,
    my_device: &str,
) -> Vec<String> {
    let mine: Vec<&Value> = frame
        .get("people")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| {
            p.get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                == Some(me)
        })
        .collect();
    let rows = |k: &'static str| {
        mine.iter()
            .flat_map(move |p| p.get(k).and_then(Value::as_array).into_iter().flatten())
    };
    let id_of = |d: &Value| {
        d.get("device_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let live: Vec<String> = rows("devices").filter_map(id_of).collect();
    // 내 사슬 아래: 자신·서명해 준 기기에서 시작해, 그중 하나의 서명이 실린 기기를 더는 늘지 않을 때까지 더한다.
    let mut under: Vec<String> = std::iter::once(my_device.to_owned())
        .chain(certified.iter().cloned())
        .collect();
    loop {
        let more: Vec<String> = rows("devices")
            .chain(rows("revocations"))
            .filter(|d| certs_of(d).iter().any(|(s, _)| under.contains(s)))
            .filter_map(id_of)
            .filter(|id| !under.contains(id))
            .collect();
        if more.is_empty() {
            break;
        }
        under.extend(more);
    }
    noted
        .iter()
        .filter(|n| matches!(n.state.as_str(), "scheduled" | "cut") && n.tries < LATE_PROOF_TRIES)
        .filter(|n| !(n.legacy && under.contains(&n.device_id)))
        .map(|n| &n.device_id)
        .filter(|id| relay_targets.contains(id) && *id != my_device && !live.contains(id))
        .cloned()
        .collect()
}

/// 내가 서명해야 할 내 다른 기기(§7a-1 자동 재서명): 내가 `trusted` 로 둔, 이번 디렉터리에 있는 내 기기 중 `certs` 에
/// 이 기기(`my_device`)의 서명이 없는 것. pending·다른 사용자·사라진 기기·이 기기가 끊기를 걸어 둔 대상은 넣지 않는다.
/// `(device_id, x25519 b64)`.
///
/// # Errors
/// 저장 오류.
pub fn to_certify(
    store: &Store,
    frame: &Value,
    me: &str,
    my_device: &str,
) -> Result<Vec<(String, String)>> {
    let mut want = Vec::new();
    let Some(people) = frame.get("people").and_then(Value::as_array) else {
        return Ok(want);
    };
    // #1479: 이 기기가 메일 확인 끊기를 걸며 적어 둔 대상은 서명하지 않는다(끊기 전 `scheduled`·끊긴 뒤 `cut`) — 걸 때 지운
    // 서명 행이 다음 디렉터리에서 다시 큐에 들지 않게. 취소되면 적어 둔 것이 지워져 다시 서명한다.
    let cutting: Vec<String> = store
        .recover_noted()?
        .into_iter()
        .filter(|n| !n.legacy && matches!(n.state.as_str(), "scheduled" | "cut"))
        .map(|n| n.device_id)
        .collect();
    for person in people {
        if person
            .get("address")
            .and_then(Value::as_str)
            .and_then(|a| a.split('@').next())
            != Some(me)
        {
            continue;
        }
        for d in person
            .get("devices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(id) = d.get("device_id").and_then(Value::as_str) else {
                continue;
            };
            if id == my_device
                || certs_of(d).iter().any(|(s, _)| s == my_device)
                || cutting.iter().any(|c| c == id)
            {
                continue;
            }
            if let Some(p) = store
                .peer(id)?
                .filter(|p| p.user == me && p.trust == Trust::Trusted)
            {
                want.push((p.device_id, p.x25519));
            }
        }
    }
    Ok(want)
}

/// 수신 재검증 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// 서명은 맞지만 발신 기기를 아직 신뢰하지 않는다(`pending`·`revoked`) — 보류(#313 결정 c).
    Held,
    /// 아직 모르는 기기 — 디렉터리를 새로 고친 뒤 다시 본다.
    UnknownDevice(String),
    /// 내 다른 기기가 상대에게 보낸 것(서명 확인됨, 받는 주소는 상대) — Handshake 만 처리하고 코어에는 보내지 않는다.
    OwnCopy,
    Reject(RejectReason),
}

/// `deliver` 의 메시지를 재검증한다(protocol §7.2 "수신 코어도 검증한다").
///
/// 순서: 받는 주소가 나(`to.address` 의 사용자 = `me`, 서버 = `server`) → 발신 기기 키 → 서명 → `from.address` 의 사용자 = 그 기기의
/// 사용자 → (`reply`·`rejected`·`system`) `reply_to` 가 내가 보낸 것이고 그 받는 사람이 지금 보낸 사람(거두기 system 은 빼고 —
/// 코어가 X 의 발신자와 대조).
///
/// # Errors
/// 저장 오류.
pub fn verify(store: &Store, message: &Value, me: &str, server: &str) -> Result<Verdict> {
    // 받는 주소가 나인가. 없으면 반신뢰 서버가 남(bob)에게 서명된 진짜 요청을 나에게 전달해 내 세션에 주입되게 할 수 있다(#147 리뷰).
    let to = message
        .pointer("/to/address")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (to_user, to_rest) = to.split_once('@').unwrap_or_default();
    let to_server = to_rest.split('/').next().unwrap_or_default();
    // 그룹(묶음 16): to 가 그룹이거나 헤더 group 이 있으면 '받는 주소가 나' 대신 '나와 보낸 사람이 그 그룹의 로컬 지금 멤버'를 본다
    // (아래 서명 뒤 — 내 기기가 수신 기기인지는 봉투 열기가 가린다). 그 밖은 지금처럼.
    let group = crate::group_io::group_context(message);
    // 내 다른 기기가 상대에게 보낸 것(pair 의 잎이라 relay 가 나에게도 준다, 묶음 22) — 서명이 내 기기인지 아래에서 본다.
    let claimed_from = message
        .pointer("/from/address")
        .and_then(Value::as_str)
        .and_then(|a| a.split('@').next());
    let own_copy = group.is_none() && to_user != me && claimed_from == Some(me);
    if to_server != server || (group.is_none() && to_user != me && !own_copy) {
        return Ok(Verdict::Reject(RejectReason::UnknownDelivery));
    }
    let device_id = message
        .pointer("/from/device_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(peer) = store.peer(device_id)? else {
        return Ok(Verdict::UnknownDevice(device_id.to_owned()));
    };
    let Ok(vk) = VerifyingKey::from_b64(&peer.ed25519) else {
        return Ok(Verdict::Reject(RejectReason::BadSignature));
    };
    if verify_message(message, &vk).is_err() {
        return Ok(Verdict::Reject(RejectReason::BadSignature));
    }
    let from_user = message
        .pointer("/from/address")
        .and_then(Value::as_str)
        .and_then(|a| a.split('@').next())
        .unwrap_or_default();
    if from_user != peer.user {
        return Ok(Verdict::Reject(RejectReason::BadSignature));
    }
    if own_copy {
        // 폐기된 내 기기의 것은 받지 않는다(§7 — 서명이 디렉터리의 폐기 안 된 내 기기).
        if peer.trust == Trust::Revoked {
            return Ok(Verdict::Reject(RejectReason::BadSignature));
        }
        return Ok(Verdict::OwnCopy);
    }
    let kind = message
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // 거두기(묶음 14 #403): reply_to 는 상대가 **나에게** 보낸 X 다 — 내가 보낸 것이 아니므로 아래 대조를 하지 않는다. X 의 발신
    // 사용자 = 이 발신 사용자 대조는 X 를 아는 코어가 한다(서명·발신 기기 사용자는 위에서 봤다).
    let withdrawn =
        kind == "system" && message.get("reason").and_then(Value::as_str) == Some("withdrawn");
    // 그룹 글은 MLS(묶음 22)로만 — 그룹 잎만 열 수 있다. 옛 box 그룹 글(로컬 멤버 표 대조)은 받지 않는다.
    let mls = message.pointer("/body/enc").and_then(Value::as_str) == Some("mls");
    if group.is_some() && kind != "group" && !mls {
        return Ok(Verdict::Reject(RejectReason::NotGroupMember));
    }
    // reply_to 대조는 내가 받는 사람일 때만(그룹의 다른 멤버는 X 를 보낸 적이 없다).
    if matches!(kind, "reply" | "rejected" | "system") && !withdrawn && to_user == me {
        let reply_to = message
            .get("reply_to")
            .and_then(Value::as_str)
            .unwrap_or_default();
        // 내가 보낸 메시지이고, 그 받는 사람이 지금 보낸 사람이어야 한다.
        if store.sent_to(reply_to)?.as_deref() != Some(from_user) {
            return Ok(Verdict::Reject(RejectReason::UnknownDelivery));
        }
    }
    // 보류(held)는 없다(묶음 22 §2c) — MLS 는 보낸 잎이 그룹 잎이어야 열리고, 잎 자격은 디렉터리 뿌리 그래프가 정한다.
    let _ = peer;
    Ok(Verdict::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodelai_crypto::{encoding, sign_message, DeviceKeys};
    use serde_json::json;

    /// 시험의 "나" 는 `me`.
    fn learn_directory(s: &Store, frame: &Value) -> Result<Vec<Learned>> {
        super::learn_directory(s, frame, "me", "k1_me", "local", 1_000)
    }

    /// 내 기기로 본다(bob = 나) — 확인·devcert 흐름은 내 기기만 남았다(묶음 22 §2c). 이 기기(`this_device`)를 가장 늦게 든
    /// 기기로 목록에 더한다 — 시각 없는 다른 기기는 그보다 먼저 든 것으로 찍는다(#847: 내 TOFU 는 이 기기보다 앞선 기기만).
    fn learn_mine(s: &Store, frame: &Value) -> Result<Vec<Learned>> {
        learn_mine_at(s, frame, 1_000)
    }

    fn learn_mine_at(s: &Store, frame: &Value, now_ms: i64) -> Result<Vec<Learned>> {
        let this = this_device();
        let mut f = stamp(frame, this.device_id().as_str());
        for person in f["people"].as_array_mut().into_iter().flatten() {
            if person["address"] == "bob@local" {
                let mut e = entry(&this);
                e["added_at"] = json!(LATE);
                person["devices"].as_array_mut().unwrap().push(e);
            }
        }
        super::learn_directory(s, &f, "bob", this.device_id().as_str(), "local", now_ms)
    }

    const EARLY: &str = "2026-01-01T00:00:00.000Z";
    const LATE: &str = "2026-12-31T00:00:00.000Z";

    fn this_device() -> DeviceKeys {
        DeviceKeys::generate(&[99u8; 64])
    }

    /// 시각 없는 기기에 시각을 찍는다 — `this` 는 가장 늦게, 나머지는 먼저.
    fn stamp(frame: &Value, this: &str) -> Value {
        let mut f = frame.clone();
        for person in f["people"].as_array_mut().into_iter().flatten() {
            for d in person["devices"].as_array_mut().into_iter().flatten() {
                if d.get("added_at").is_none() {
                    d["added_at"] = json!(if d["device_id"] == this { LATE } else { EARLY });
                }
            }
        }
        f
    }

    fn ids(l: &[Learned]) -> Vec<(&'static str, String)> {
        // 뿌리 바뀜은 따로 본다(`뿌리가_바뀌면_한_번_알린다`).
        l.iter()
            .filter_map(|x| match x {
                Learned::FirstContact(p) => Some(("first", p.device_id.clone())),
                Learned::NewDevice(p) => Some(("new", p.device_id.clone())),
                Learned::Revoked(p) => Some(("revoked", p.device_id.clone())),
                Learned::CertTrusted(p) => Some(("cert", p.device_id.clone())),
                Learned::CertLost(p) => Some(("lost", p.device_id.clone())),
                Learned::Mismatch { device_id, .. } => Some(("mismatch", device_id.clone())),
                Learned::RootChanged { .. } => None,
            })
            .collect()
    }

    fn entry(k: &DeviceKeys) -> Value {
        let id = k.device_id().as_str().to_owned();
        let x = k.exchange.public_key();
        json!({"device_id": id, "device_pubkeys": {
            "ed25519": k.signing.verifying_key().to_b64(),
            "x25519": encoding::encode(&x),
            "x25519_sig": xkey::sign(&k.signing, &id, &x)}})
    }

    /// 서명자 `signer` 가 `user` 의 기기 `target` 에 한 내 기기 서명 항목(`certs[]`).
    fn cert(signer: &DeviceKeys, user: &str, target: &DeviceKeys, server: &str) -> Value {
        let x = target.exchange.public_key();
        let (tid, sid) = (target.device_id(), signer.device_id());
        let c = lodelai_crypto::devcert::Cert {
            server,
            user,
            device_id: tid.as_str(),
            x25519: &x,
            signer: sid.as_str(),
        };
        json!({"signer": signer.device_id().as_str(), "sig": lodelai_crypto::devcert::sign(&signer.signing, &c)})
    }

    fn with_certs(k: &DeviceKeys, certs: Vec<Value>) -> Value {
        let mut e = entry(k);
        e["certs"] = json!(certs);
        e
    }

    fn bob(devs: Vec<Value>) -> Value {
        dir(json!([{"address": "bob@local", "devices": devs}]))
    }

    /// #847: 내 계정의 첫 디렉터리에 이 기기보다 뒤에 든 내 기기가 이미 있어도 TOFU 로 믿지 않는다 — 이 기기보다 먼저 든
    /// 기기만 처음 본 뿌리(first_contact)다. 같은 시각·시각 모름도 뒤로 본다(확인 카드, cert 가 오면 풀린다).
    #[test]
    fn 내_첫_디렉터리의_나보다_뒤에_든_내_기기는_확인_전이다() {
        let (mac, phone, other) = (
            DeviceKeys::generate(&[31; 64]),
            DeviceKeys::generate(&[32; 64]),
            DeviceKeys::generate(&[33; 64]),
        );
        let at = |k: &DeviceKeys, t: Option<&str>| {
            let mut e = entry(k);
            if let Some(t) = t {
                e["added_at"] = json!(t);
            }
            e
        };
        let frame = bob(vec![
            at(&mac, Some("2026-11-06T00:00:00.000Z")),
            at(&phone, Some("2026-11-06T00:00:05.000Z")),
            at(&other, None),
        ]);
        let learn = |s: &Store, me: &DeviceKeys| {
            super::learn_directory(s, &frame, "bob", me.device_id().as_str(), "local", 1_000)
                .unwrap()
        };
        let trust =
            |s: &Store, k: &DeviceKeys| s.peer(k.device_id().as_str()).unwrap().unwrap().trust;

        // 맥(먼저 든 기기)의 첫 디렉터리: 뒤에 든 휴대폰·시각 모르는 기기는 pending.
        let s = Store::memory().unwrap();
        let l = learn(&s, &mac);
        assert_eq!(trust(&s, &phone), Trust::Pending, "{:?}", ids(&l));
        assert_eq!(trust(&s, &other), Trust::Pending, "{:?}", ids(&l));
        assert!(ids(&l).contains(&("new", phone.device_id().as_str().to_owned())));

        // 휴대폰(뒤에 든 기기)의 첫 디렉터리: 앞선 맥은 계정의 기기 — first_contact.
        let s = Store::memory().unwrap();
        let l = learn(&s, &phone);
        assert_eq!(trust(&s, &mac), Trust::Trusted, "{:?}", ids(&l));
        assert_eq!(trust(&s, &other), Trust::Pending, "{:?}", ids(&l));

        // 맥이 연결 코드로 승인하며 심어 둔 휴대폰(plant_own_device)은 뒤에 들었어도 그대로 trusted — 새 기기 갈래가 아니다.
        let s = Store::memory().unwrap();
        s.insert_peer_with_basis(
            &Peer {
                device_id: phone.device_id().as_str().to_owned(),
                user: "bob".into(),
                ed25519: phone.signing.verifying_key().to_b64(),
                x25519: encoding::encode(&phone.exchange.public_key()),
                trust: Trust::Trusted,
                first_contact: false,
            },
            &[planted_basis(1_000), "human".to_owned()],
        )
        .unwrap();
        let l = learn(&s, &mac);
        assert_eq!(trust(&s, &phone), Trust::Trusted, "{:?}", ids(&l));

        // 같은 시각도 뒤로 본다.
        let same = bob(vec![
            at(&mac, Some("2026-11-06T00:00:00.000Z")),
            at(&phone, Some("2026-11-06T00:00:00.000Z")),
        ]);
        let s = Store::memory().unwrap();
        super::learn_directory(&s, &same, "bob", mac.device_id().as_str(), "local", 1_000).unwrap();
        assert_eq!(trust(&s, &phone), Trust::Pending);
    }

    /// 뿌리 바뀜(묶음 22 §2c): 처음 본 뿌리는 조용히, 증명 없이 사슬이 끊겨 바뀌면 RootChanged 하나, 같으면 없음.
    #[test]
    fn 뿌리가_바뀌면_한_번_알린다() {
        let s = Store::memory().unwrap();
        let (b1, b2) = (
            DeviceKeys::generate(&[21; 64]),
            DeviceKeys::generate(&[22; 64]),
        );
        let at = |k: &DeviceKeys, t: &str, certs: Vec<Value>| {
            let mut e = entry(k);
            e["added_at"] = json!(t);
            e["certs"] = json!(certs);
            e
        };
        let roots = |l: &[Learned]| {
            l.iter()
                .filter_map(|x| match x {
                    Learned::RootChanged { user, root } => Some((user.clone(), root.clone())),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let both = bob(vec![
            at(&b1, "2026-10-01T00:00:00.000Z", vec![]),
            at(
                &b2,
                "2026-10-02T00:00:00.000Z",
                vec![cert(&b1, "bob", &b2, "local")],
            ),
        ]);
        assert!(
            roots(&learn_directory(&s, &both).unwrap()).is_empty(),
            "처음은 조용히"
        );
        assert_eq!(
            s.last_root("bob").unwrap().as_deref(),
            Some(b1.device_id().as_str())
        );
        assert!(roots(&learn_directory(&s, &both).unwrap()).is_empty());
        // 서버가 증명 없이 b1 을 폐기(그 서명도 사라짐) → b2 가 뿌리.
        let cut = bob(vec![at(&b2, "2026-10-02T00:00:00.000Z", vec![])]);
        assert_eq!(
            roots(&learn_directory(&s, &cut).unwrap()),
            vec![("bob".to_owned(), b2.device_id().as_str().to_owned())]
        );
        assert!(
            roots(&learn_directory(&s, &cut).unwrap()).is_empty(),
            "한 번만"
        );
    }

    /// #1516: 걸기 전에 미리 적은 줄(asked)은 relay 답으로 확정되기 전엔 뒤늦은 증명·다시 서명 안 하기·「내가 건 끊기 있음」에
    /// 쓰이지 않는다. 답이 오면 relay 대상만 scheduled 로 남고 나머지는 지워진다.
    #[test]
    fn 미리_적은_끊기_대상은_relay_답으로_확정된다() {
        let s = Store::memory().unwrap();
        let ids = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        s.note_recover_asked(&ids(&["a", "b"])).unwrap();
        let rows = |s: &Store| {
            s.recover_noted()
                .unwrap()
                .into_iter()
                .map(|n| (n.device_id, n.state))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            rows(&s),
            vec![
                ("a".to_owned(), "asked".to_owned()),
                ("b".to_owned(), "asked".to_owned())
            ]
        );
        assert!(
            !s.recover_noted_own().unwrap(),
            "확정 전 줄은 건 끊기로 세지 않는다"
        );
        let frame = json!({"people": [{"address": "me@local", "devices": [{"device_id": "me2"}]}]});
        assert!(
            super::late_proof_targets(
                &s.recover_noted().unwrap(),
                &[],
                &ids(&["a", "b"]),
                &frame,
                "me",
                "me2"
            )
            .is_empty(),
            "확정 전 줄에는 증명을 서명하지 않는다"
        );
        // relay 답: a 와 c 만 대상 — a 는 올리고 c 는 새로, b 는 지운다.
        s.confirm_recover_targets(&ids(&["a", "c"])).unwrap();
        assert_eq!(
            rows(&s),
            vec![
                ("a".to_owned(), "scheduled".to_owned()),
                ("c".to_owned(), "scheduled".to_owned())
            ]
        );
        assert!(s.recover_noted_own().unwrap());
        // 이미 끊긴(cut) 줄은 다시 걸어도 그대로, 걸기가 실패하면 미리 적은 줄만 지운다.
        s.set_recover_state("a", "cut").unwrap();
        s.note_recover_asked(&ids(&["a", "d"])).unwrap();
        s.forget_recover_asked().unwrap();
        assert_eq!(
            rows(&s),
            vec![
                ("a".to_owned(), "cut".to_owned()),
                ("c".to_owned(), "scheduled".to_owned())
            ]
        );
    }

    /// #1516: 끊기를 걸 때 요청을 보내기 전에 적어 둘 대상 — 이 기기보다 먼저 든 내 기기만(남의 기기·뒤에 든 기기 아님).
    #[test]
    fn 이_기기보다_먼저_든_내_기기() {
        let d = |id: &str, at: &str| json!({"device_id": id, "added_at": at});
        let f = json!({"people": [
            {"address": "bob@local", "devices": [d("b1", "2026-10-01T00:00:00.000Z")]},
            {"address": "me@local", "devices": [
                d("old1", "2026-10-01T00:00:00.000Z"),
                d("old2", "2026-10-02T00:00:00.000Z"),
                d("me2", "2026-10-03T00:00:00.000Z"),
                d("later", "2026-10-04T00:00:00.000Z"),
                json!({"device_id": "notime"}),
            ]},
        ]});
        assert_eq!(
            super::older_own_devices(&f, "me", "me2"),
            vec!["old1", "old2"]
        );
        assert!(super::older_own_devices(&f, "me", "notime").is_empty());
        assert!(super::older_own_devices(&f, "me", "gone").is_empty());
    }

    /// #1516: 이 기기가 시작하는 정당한 길마다 **내** 뿌리·이 기기의 잎 자격이 어떻게 되나(쥐기 판정의 바탕). 뿌리가 바뀌는
    /// 길은 메일 확인 끊기(관리자가 앞당긴 것 포함) 하나뿐이고 그때 새 뿌리는 이 기기 자신이다. 이 기기가 들어 있다가 빠지는
    /// 길은 없다.
    #[test]
    fn 정당한_길에서_내_뿌리와_이_기기의_잎_자격() {
        use lodelai_crypto::devrevoke;
        let (o, t, n) = (
            DeviceKeys::generate(&[41; 64]),
            DeviceKeys::generate(&[42; 64]),
            DeviceKeys::generate(&[43; 64]),
        );
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        let (t_o, t_t, t_n) = (
            "2026-10-01T00:00:00.000Z",
            "2026-10-02T00:00:00.000Z",
            "2026-10-03T00:00:00.000Z",
        );
        let live = |k: &DeviceKeys, at: &str, certs: Vec<Value>| {
            let mut e = entry(k);
            e["added_at"] = json!(at);
            e["certs"] = json!(certs);
            e
        };
        // `signer` 가 증명한 `k` 의 폐기 기록.
        let gone = |k: &DeviceKeys, at: &str, certs: Vec<Value>, signer: &DeviceKeys| {
            let cut = "2026-10-05T00:00:00.000Z";
            json!({
                "device_id": id(k),
                "added_at": at,
                "ed25519": k.signing.verifying_key().to_b64(),
                "x25519": encoding::encode(&k.exchange.public_key()),
                "certs": certs,
                "at": cut,
                "signer": id(signer),
                "sig": devrevoke::sign(
                    &signer.signing,
                    &devrevoke::Revoke { server: "local", device_id: &id(k), at: cut },
                ),
            })
        };
        // (뿌리, 이 기기 t 가 잎 자격인가)
        let see = |devices: Vec<Value>, revs: Vec<Value>| {
            let f = dir(json!([{"address": "bob@local", "devices": devices, "revocations": revs}]));
            let r = mls_rules::roots_in(&DirView::new(&f, "local"), "bob");
            (r.root, r.eligible.contains(&id(&t)))
        };
        let c = |signer: &DeviceKeys, target: &DeviceKeys| cert(signer, "bob", target, "local");

        // 기기 더하기(t 가 뿌리, 새 기기 n): 등록 직후 → t 가 서명한 뒤. 뿌리 그대로.
        let start = see(vec![live(&t, t_t, vec![])], vec![]);
        assert_eq!(start, (Some(id(&t)), true));
        assert_eq!(
            see(vec![live(&t, t_t, vec![]), live(&n, t_n, vec![])], vec![]),
            start
        );
        assert_eq!(
            see(
                vec![live(&t, t_t, vec![]), live(&n, t_n, vec![c(&t, &n)])],
                vec![]
            ),
            start
        );
        // 기기 더하기(t 가 뿌리 o 아래, 새 기기 n 에 t 가 서명). 뿌리 그대로.
        let under = see(
            vec![live(&o, t_o, vec![]), live(&t, t_t, vec![c(&o, &t)])],
            vec![],
        );
        assert_eq!(under, (Some(id(&o)), true));
        assert_eq!(
            see(
                vec![
                    live(&o, t_o, vec![]),
                    live(&t, t_t, vec![c(&o, &t)]),
                    live(&n, t_n, vec![c(&t, &n)]),
                ],
                vec![]
            ),
            under
        );
        // 내 다른 기기 끊기(증명 실음): 뿌리 o 를 t 가 끊어도 o 는 마디로 남아 뿌리 그대로.
        assert_eq!(
            see(
                vec![live(&t, t_t, vec![c(&o, &t)])],
                vec![gone(&o, t_o, vec![], &t)]
            ),
            under
        );
        // 아래 기기 n 을 끊음: 그대로.
        assert_eq!(
            see(
                vec![live(&o, t_o, vec![]), live(&t, t_t, vec![c(&o, &t)])],
                vec![gone(&n, t_n, vec![c(&t, &n)], &t)]
            ),
            under
        );
        // 견줌(정당한 길 아님 — 증명 없이 뿌리가 사라짐): 뿌리가 t 로 바뀐다.
        assert_eq!(
            see(vec![live(&t, t_t, vec![c(&o, &t)])], vec![]),
            (Some(id(&t)), true)
        );
        // 견줌(정당한 길 아님 — 사이 기기 t 가 증명 없이 사라진 n 쪽에서 봄): o→t→n 에서 t 가 증명 없이 빠지면 n 은 사슬 없음.
        let chain_cut = dir(json!([{"address": "bob@local", "devices": [
            live(&o, t_o, vec![]), live(&n, t_n, vec![c(&t, &n)])]}]));
        let r = mls_rules::roots_in(&DirView::new(&chain_cut, "local"), "bob");
        assert_eq!(r.root, Some(id(&o)));
        assert!(!r.eligible.contains(&id(&n)), "들어 있다가 빠짐");

        // 메일 확인 끊기(t 가 새 기기, 옛 기기 o 를 잃음): 걸기 전·기다림 → 끊김(증명 전) → 뒤늦은 증명.
        let waiting = see(vec![live(&o, t_o, vec![]), live(&t, t_t, vec![])], vec![]);
        assert_eq!(
            waiting,
            (Some(id(&o)), false),
            "새 기기는 아직 사슬 없음(빠짐 전이 아님)"
        );
        let cut = see(vec![live(&t, t_t, vec![])], vec![]);
        assert_eq!(cut, (Some(id(&t)), true), "뿌리가 이 기기로 바뀐다");
        assert_eq!(
            see(vec![live(&t, t_t, vec![])], vec![gone(&o, t_o, vec![], &t)]),
            cut,
            "뒤늦은 증명이 붙어도 그대로(o 는 산 기기에 닿지 않는다)"
        );
        // 새 기기가 옛 기기에 자동 재서명을 해 둔 채 끊겨도 같다.
        assert_eq!(
            see(
                vec![live(&t, t_t, vec![])],
                vec![gone(&o, t_o, vec![c(&t, &o)], &t)]
            ),
            cut
        );
    }

    /// #1511: 폐기 기록의 키가 그 기기 아이디와 안 맞으면 버린다. 진짜로 증명 폐기된 뿌리 b1 의 기록에서 relay 가 키만 자기
    /// 것으로 바꾸고 「b1 이 서명한」 devcert 를 지어 가짜 기기를 끼워도, 그 기기는 잎 자격이 없다.
    #[test]
    fn 폐기_기록의_키를_바꿔_지어낸_서명은_잎_자격을_주지_않는다() {
        use lodelai_crypto::devrevoke;
        let (b1, b2, relay, fake) = (
            DeviceKeys::generate(&[31; 64]),
            DeviceKeys::generate(&[32; 64]),
            DeviceKeys::generate(&[33; 64]),
            DeviceKeys::generate(&[34; 64]),
        );
        let at = "2026-10-03T00:00:00.000Z";
        let b1_id = b1.device_id().as_str().to_owned();
        let revoked = |ed: &DeviceKeys| {
            json!({
                "device_id": b1_id,
                "added_at": "2026-10-01T00:00:00.000Z",
                "ed25519": ed.signing.verifying_key().to_b64(),
                "x25519": encoding::encode(&b1.exchange.public_key()),
                "certs": [],
                "at": at,
                "signer": b2.device_id().as_str(),
                "sig": devrevoke::sign(
                    &b2.signing,
                    &devrevoke::Revoke { server: "local", device_id: &b1_id, at },
                ),
            })
        };
        let live = |k: &DeviceKeys, t: &str, certs: Vec<Value>| {
            let mut e = entry(k);
            e["added_at"] = json!(t);
            e["certs"] = json!(certs);
            e
        };
        // relay 가 지은 서명: 서명자 이름은 b1, 실제 키는 relay 것.
        let forged = {
            let x = fake.exchange.public_key();
            let fid = fake.device_id();
            let c = lodelai_crypto::devcert::Cert {
                server: "local",
                user: "bob",
                device_id: fid.as_str(),
                x25519: &x,
                signer: &b1_id,
            };
            json!({"signer": b1_id, "sig": lodelai_crypto::devcert::sign(&relay.signing, &c)})
        };
        let frame = |rec: Value| {
            dir(json!([{"address": "bob@local",
                "devices": [
                    live(&b2, "2026-10-02T00:00:00.000Z", vec![cert(&b1, "bob", &b2, "local")]),
                    live(&fake, "2026-10-04T00:00:00.000Z", vec![forged.clone()]),
                ],
                "revocations": [rec]}]))
        };
        let eligible = |f: &Value| mls_rules::roots_in(&DirView::new(f, "local"), "bob").eligible;
        // 진짜 기록: b1 이 뿌리로 남고 b2 만 잎(지어낸 서명은 b1 의 진짜 키로 안 맞는다).
        let honest = eligible(&frame(revoked(&b1)));
        assert!(honest.contains(b2.device_id().as_str()));
        assert!(!honest.contains(fake.device_id().as_str()));
        // 키를 바꾼 기록: 버려져 b1 은 마디가 아니다 — 가짜 기기는 여전히 잎이 아니다.
        let swapped = eligible(&frame(revoked(&relay)));
        assert!(!swapped.contains(fake.device_id().as_str()), "{swapped:?}");
    }

    /// #393 §7a-2·3: 아는 사람의 새 기기는 pending(기다림 시작 = 지금). 내가 믿는 그 사람의 다른 기기가 한 맞는 서명이
    /// 오면 trusted(근거 cert:서명자, 기다림 지움). TOFU 뿌리는 근거 first_contact.
    #[test]
    fn 믿는_기기의_서명이_맞으면_새_기기를_믿는다() {
        let s = Store::memory().unwrap();
        let (b1, b2) = (
            DeviceKeys::generate(&[11u8; 64]),
            DeviceKeys::generate(&[12u8; 64]),
        );
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        learn_mine(&s, &bob(vec![entry(&b1)])).unwrap();
        assert_eq!(s.basis(&id(&b1)).unwrap(), ["first_contact"]);
        let l = learn_mine(&s, &bob(vec![entry(&b1), entry(&b2)])).unwrap();
        assert_eq!(ids(&l), vec![("new", id(&b2))]);
        assert_eq!(s.pending_since(&id(&b2)).unwrap(), Some(1_000));
        let l = learn_mine(
            &s,
            &bob(vec![
                entry(&b1),
                with_certs(&b2, vec![cert(&b1, "bob", &b2, "local")]),
            ]),
        )
        .unwrap();
        assert_eq!(ids(&l), vec![("cert", id(&b2))]);
        let p = s.peer(&id(&b2)).unwrap().unwrap();
        assert_eq!(p.trust, Trust::Trusted);
        assert_eq!(s.basis(&id(&b2)).unwrap(), [format!("cert:{}", id(&b1))]);
        assert_eq!(s.pending_since(&id(&b2)).unwrap(), None);
        // 다시 받아도 조용하다.
        assert!(learn_mine(
            &s,
            &bob(vec![
                entry(&b1),
                with_certs(&b2, vec![cert(&b1, "bob", &b2, "local")])
            ])
        )
        .unwrap()
        .is_empty());
    }

    /// §7a-2·6: 서명이 다른 서버·다른 사용자·다른 대상 것이거나, 서명자가 내가 믿지 않는(pending) 기기·대상 자신·디렉터리에
    /// 없는 기기면 믿지 않는다(서버는 서명을 지어낼 수 없다 — 빼는 것만 가능).
    #[test]
    fn 틀린_서명이나_믿지_않는_서명자는_무시한다() {
        let s = Store::memory().unwrap();
        let b1 = DeviceKeys::generate(&[21u8; 64]);
        let b2 = DeviceKeys::generate(&[22u8; 64]);
        let b3 = DeviceKeys::generate(&[23u8; 64]);
        let gone = DeviceKeys::generate(&[24u8; 64]);
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        learn_mine(&s, &bob(vec![entry(&b1)])).unwrap();
        learn_mine(&s, &bob(vec![entry(&b1), entry(&b2), entry(&b3)])).unwrap();
        for bad in [
            cert(&b1, "bob", &b2, "other.server"),
            cert(&b1, "eve", &b2, "local"),
            cert(&b1, "bob", &b3, "local"),
            cert(&b3, "bob", &b2, "local"),
            cert(&b2, "bob", &b2, "local"),
            cert(&gone, "bob", &b2, "local"),
        ] {
            let l = learn_mine(
                &s,
                &bob(vec![
                    entry(&b1),
                    with_certs(&b2, vec![bad.clone()]),
                    entry(&b3),
                ]),
            )
            .unwrap();
            assert!(l.is_empty(), "{bad}: {l:?}");
            assert_eq!(
                s.peer(&id(&b2)).unwrap().unwrap().trust,
                Trust::Pending,
                "{bad}"
            );
        }
    }

    /// §7a-2 연쇄: 방금 서명으로 믿게 된 기기가 다른 기기의 서명자면 같은 디렉터리에서 그것도 믿는다.
    /// §7a-4: 서명자가 폐기되면 그 근거만 지우고, 근거가 없어진 기기는 pending(기다림을 지금부터) — 연쇄도 같이.
    /// 사람이 확인한 기기(근거 human)는 서명 근거를 잃어도 내리지 않는다.
    #[test]
    fn 연쇄_서명과_서명자_폐기() {
        let s = Store::memory().unwrap();
        let k = |n: u8| DeviceKeys::generate(&[n; 64]);
        let (b1, b2, b3, b4) = (k(31), k(32), k(33), k(34));
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        learn_mine(&s, &bob(vec![entry(&b1)])).unwrap();
        learn_mine(
            &s,
            &bob(vec![entry(&b1), entry(&b2), entry(&b3), entry(&b4)]),
        )
        .unwrap();
        // b4 는 사람이 확인(근거 human).
        s.set_trust(&id(&b4), Trust::Trusted).unwrap();
        s.add_basis(&id(&b4), "human").unwrap();
        let full = |with_b1: bool| {
            let mut v = Vec::new();
            if with_b1 {
                v.push(entry(&b1));
            }
            let c2 = if with_b1 {
                vec![cert(&b1, "bob", &b2, "local")]
            } else {
                vec![]
            };
            let c4 = if with_b1 {
                vec![cert(&b1, "bob", &b4, "local")]
            } else {
                vec![]
            };
            v.push(with_certs(&b2, c2));
            v.push(with_certs(&b3, vec![cert(&b2, "bob", &b3, "local")]));
            v.push(with_certs(&b4, c4));
            bob(v)
        };
        let l = learn_mine(&s, &full(true)).unwrap();
        assert_eq!(ids(&l), vec![("cert", id(&b2)), ("cert", id(&b3))]);
        assert_eq!(s.peer(&id(&b3)).unwrap().unwrap().trust, Trust::Trusted);
        // b4 는 이미 trusted — 서명은 근거로 더하지 않아도 그대로 trusted.
        // b1 폐기(relay 가 b1 의 서명도 뺀다) → b2(cert:b1 뿐) pending, b3(cert:b2 뿐) pending, b4(human) 유지.
        let l = learn_mine_at(&s, &full(false), 5_000).unwrap();
        assert_eq!(
            ids(&l),
            vec![("revoked", id(&b1)), ("lost", id(&b2)), ("lost", id(&b3))]
        );
        for d in [&b2, &b3] {
            assert_eq!(s.peer(&id(d)).unwrap().unwrap().trust, Trust::Pending);
            assert_eq!(s.pending_since(&id(d)).unwrap(), Some(5_000));
            assert!(s.basis(&id(d)).unwrap().is_empty());
        }
        assert_eq!(s.peer(&id(&b4)).unwrap().unwrap().trust, Trust::Trusted);
        assert_eq!(s.basis(&id(&b4)).unwrap(), ["human"]);
    }

    /// 설계 (b): 내 새 기기 카드는 내 기존 기기 여럿에 뜬다 — 그중 한 기기(home)가 서명하면 다른 내 기기(this)도
    /// 디렉터리의 서명으로 그 기기를 trusted 로 둔다(사람이 두 번 확인하지 않게). 내 기기도 같은 검증 경로를 탄다.
    #[test]
    fn 내_다른_기기가_서명한_내_새_기기는_이_기기도_믿는다() {
        let s = Store::memory().unwrap();
        let k = |n: u8| DeviceKeys::generate(&[n; 64]);
        let (this, home, new) = (k(51), k(52), k(53));
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        let me = |devs: Vec<Value>| {
            stamp(
                &dir(json!([{"address": "me@local", "devices": devs}])),
                this.device_id().as_str(),
            )
        };
        let learn = |f: &Value| super::learn_directory(&s, f, "me", &id(&this), "local", 1_000);
        learn(&me(vec![entry(&this), entry(&home)])).unwrap();
        let l = learn(&me(vec![entry(&this), entry(&home), entry(&new)])).unwrap();
        assert_eq!(ids(&l), vec![("new", id(&new))]);
        let l = learn(&me(vec![
            entry(&this),
            entry(&home),
            with_certs(&new, vec![cert(&home, "me", &new, "local")]),
        ]))
        .unwrap();
        assert_eq!(ids(&l), vec![("cert", id(&new))]);
        assert_eq!(s.peer(&id(&new)).unwrap().unwrap().trust, Trust::Trusted);
        // 그 뒤 이 기기도 자기 서명을 보탠다(자동 재서명).
        let f = me(vec![
            entry(&this),
            entry(&home),
            with_certs(&new, vec![cert(&home, "me", &new, "local")]),
        ]);
        let want: Vec<String> = super::to_certify(&s, &f, "me", &id(&this))
            .unwrap()
            .into_iter()
            .map(|(d, _)| d)
            .collect();
        assert!(want.contains(&id(&new)), "{want:?}");
    }

    /// #1479: 뒤늦은 폐기 증명은 적어 둔 대상 ∩ relay 목록에만 서명한다. 자신·산 기기·끝난 것·상한을 채운 것은 뺀다. 걸 때 적어 둔
    /// 대상은 서명해 줬는지를 보지 않고, 옛 끊기의 대상(relay 목록에서 받아 적은 것)은 서명해 준 기기와 그 아래를 뺀다 — 디렉터리가
    /// certs 를 빼고 줘도.
    #[test]
    fn 뒤늦은_폐기_증명에_서명할_기기() {
        use crate::outbox::RecoverNoted;
        let ids = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<String>>();
        let row = |id: &str, state: &str, tries: u32, legacy: bool| RecoverNoted {
            device_id: id.to_owned(),
            state: state.to_owned(),
            tries,
            legacy,
        };
        let d = |id: &str, signers: &[&str]| json!({"device_id": id, "certs": signers.iter().map(|x| json!({"signer": x, "sig": "x"})).collect::<Vec<_>>()});
        let frame = |devices: Vec<Value>, revs: Vec<Value>| {
            json!({"people": [
                {"address": "me@local", "devices": devices, "revocations": revs},
                {"address": "bob@local", "devices": [d("old", &[])]},
            ]})
        };
        let gone = frame(vec![d("me2", &[])], vec![]);
        let pick = |n: &[RecoverNoted], cert: &[&str], relay: &[&str], f: &Value| {
            super::late_proof_targets(n, &ids(cert), &ids(relay), f, "me", "me2")
        };
        let old = ids(&["old"]);
        // 적어 둔 대상이고 relay 도 끊겼다고 한 것만.
        assert_eq!(
            pick(&[row("old", "cut", 0, false)], &[], &["old"], &gone),
            old
        );
        assert_eq!(
            pick(&[row("old", "scheduled", 0, false)], &[], &["old"], &gone),
            old
        );
        assert!(
            pick(&[row("old", "cut", 0, false)], &[], &[], &gone).is_empty(),
            "relay 목록에 없음"
        );
        assert!(
            pick(&[], &[], &["old"], &gone).is_empty(),
            "relay 말만으로는 서명 안 함"
        );
        // 끝난 것·상한.
        assert!(pick(&[row("old", "proved", 1, false)], &[], &["old"], &gone).is_empty());
        assert!(pick(&[row("old", "refused", 1, false)], &[], &["old"], &gone).is_empty());
        let full = row("old", "cut", super::LATE_PROOF_TRIES, false);
        assert!(pick(&[full], &[], &["old"], &gone).is_empty());
        // 산 기기로 있으면 보내지 않는다(다른 사람의 같은 id 는 보지 않는다). 자신도.
        let alive = frame(vec![d("me2", &[]), d("old", &[])], vec![]);
        assert!(pick(&[row("old", "cut", 0, false)], &[], &["old"], &alive).is_empty());
        assert!(pick(&[row("me2", "cut", 0, false)], &[], &["me2"], &gone).is_empty());
        assert!(pick(&[row("me2", "cut", 0, true)], &[], &["me2"], &gone).is_empty());
        // 걸 때 적어 둔 대상: 서명해 준 기기여도 서명한다(새 기기의 자동 재서명이 큐에 들었던 옛 기기).
        assert_eq!(
            pick(&[row("old", "cut", 0, false)], &["old"], &["old"], &gone),
            old
        );
        // 옛 끊기의 대상: 서명해 준 기기면 서명하지 않는다 — 디렉터리가 certs 를 빼고 줘도.
        assert!(pick(&[row("old", "cut", 0, true)], &["old"], &["old"], &gone).is_empty());
        // 서명해 준 기기(mid)가 서명한 기기(old)도 디렉터리 certs 로 이어지는 만큼 — 산 기기 줄이든 폐기 줄이든.
        let via_live = frame(vec![d("me2", &[]), d("mid", &[])], vec![d("old", &["mid"])]);
        assert!(pick(&[row("old", "cut", 0, true)], &["mid"], &["old"], &via_live).is_empty());
        let via_rev = frame(
            vec![d("me2", &[])],
            vec![d("mid", &["me2"]), d("old", &["mid"])],
        );
        assert!(pick(&[row("old", "cut", 0, true)], &[], &["old"], &via_rev).is_empty());
        // 사슬과 무관한 서명은 막지 않는다.
        let other = frame(vec![d("me2", &[])], vec![d("old", &["older"])]);
        assert_eq!(
            pick(&[row("old", "cut", 0, true)], &[], &["old"], &other),
            old
        );
        // relay 목록: 이 기기가 건 끊기의 것만(끝난 걸기 24시간 + 증명 없는 폐기 목록), 겹치면 한 번.
        let listed = json!({"people": [{"address": "me@local", "devices": [d("me2", &[])],
        "recovery": {"state": "done", "requester": "me2", "targets": ["old"]},
        "unproved_revocations": [
            {"device_id": "old", "requester": "me2"},
            {"device_id": "older", "requester": "me2"},
            {"device_id": "x", "requester": "other"},
        ]}]});
        assert_eq!(
            super::recovery_cut_by(&listed, "me", "me2"),
            ids(&["old", "older"])
        );
        let theirs = json!({"people": [{"address": "me@local", "devices": [d("me2", &["me1"])],
            "recovery": {"state": "done", "requester": "other", "targets": ["old"]}}]});
        assert!(super::recovery_cut_by(&theirs, "me", "me2").is_empty());
        let pending = json!({"people": [{"address": "me@local", "devices": [d("me2", &[])],
            "recovery": {"state": "scheduled", "requester": "me2", "targets": ["old"]}}]});
        assert!(
            super::recovery_cut_by(&pending, "me", "me2").is_empty(),
            "아직 안 끊김"
        );
        // 옛 끊기 예외의 조건: 이 기기가 내 다른 기기의 서명을 받지 않았을 때만.
        assert!(super::unsigned_root(&listed, "me", "me2"));
        assert!(!super::unsigned_root(&theirs, "me", "me2"));
    }

    /// #1479: 서명해 준 기기는 서명 프레임과 한 묶음으로 적히고, 옛 서명은 피어 표 근거에서 한 번만 옮겨 적는다.
    #[test]
    fn 서명해_준_기기를_적어_둔다() {
        let s = Store::memory().unwrap();
        let k = |n: u8| DeviceKeys::generate(&[n; 64]);
        let (this, home) = (k(51), k(52));
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        let x = lodelai_crypto::encoding::encode(&home.exchange.public_key());
        super::queue_certify(&s, &this, "local", "me", &id(&home), &x).unwrap();
        super::queue_certify(&s, &this, "local", "me", &id(&home), &x).unwrap();
        assert_eq!(s.certified().unwrap(), vec![id(&home)]);
        assert_eq!(s.len().unwrap(), 1, "같은 대상의 프레임은 하나");
        // 끊기 대상: 한 번 적히면 그대로, 취소는 아직 끊기지 않은 것만 지운다.
        // 끊기로 정한 기기에 줄, 아직 안 나간 서명은 같은 묶음에서 지운다(「서명해 준 기기」 칸은 그대로).
        s.note_recover_targets(&[id(&home)]).unwrap();
        assert_eq!(s.len().unwrap(), 0, "끊기 대상에 줄 서명 행이 남음");
        assert_eq!(s.certified().unwrap(), vec![id(&home)]);
        s.drop_recover_scheduled().unwrap();
        s.note_recover_targets(&["a".to_owned(), "b".to_owned()])
            .unwrap();
        s.set_recover_state("a", "cut").unwrap();
        s.bump_recover_tries("a").unwrap();
        s.note_recover_targets(&["a".to_owned()]).unwrap();
        s.set_recover_state("zz", "cut").unwrap();
        s.drop_recover_scheduled().unwrap();
        let left = s.recover_noted().unwrap();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(
            (
                left[0].device_id.as_str(),
                left[0].state.as_str(),
                left[0].tries,
                left[0].legacy
            ),
            ("a", "cut", 1, false)
        );
        // 옛 끊기의 대상은 표시를 달고 끊긴 것으로 적힌다 — 「걸 때 적은 것이 있나」는 이것을 세지 않는다.
        assert!(s.recover_noted_own().unwrap());
        s.note_recover_legacy(&["old".to_owned()]).unwrap();
        assert!(s
            .recover_noted()
            .unwrap()
            .iter()
            .any(|n| n.device_id == "old" && n.legacy && n.state == "cut"));
        // 옮겨 적기는 한 번만.
        s.seed_certified(&id(&this)).unwrap();
        s.seed_certified(&id(&this)).unwrap();
        assert_eq!(s.certified().unwrap(), vec![id(&home)]);
    }

    /// #1479: 이 기기가 메일 확인 끊기를 걸어 둔 대상은 다음 디렉터리에서 다시 서명 큐에 들지 않는다(걸 때 지운 행이 되살아나지
    /// 않게). 취소되면 다시 서명한다. 옛 끊기로 적힌(legacy) 것은 막지 않는다.
    #[test]
    fn 끊기를_걸어_둔_기기는_다시_서명하지_않는다() {
        let s = Store::memory().unwrap();
        let k = |n: u8| DeviceKeys::generate(&[n; 64]);
        let (this, home) = (k(61), k(62));
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        let f = stamp(
            &dir(json!([{"address": "me@local", "devices": [entry(&this), entry(&home)]}])),
            this.device_id().as_str(),
        );
        super::learn_directory(&s, &f, "me", &id(&this), "local", 1_000).unwrap();
        // 디렉터리를 받을 때 conn 이 하는 그대로: 서명할 기기를 찾아 큐에 넣는다.
        let step = || {
            for (d, x) in super::to_certify(&s, &f, "me", &id(&this)).unwrap() {
                super::queue_certify(&s, &this, "local", "me", &d, &x).unwrap();
            }
            s.len().unwrap()
        };
        assert_eq!(step(), 1);
        s.note_recover_targets(&[id(&home)]).unwrap();
        assert_eq!(step(), 0, "예약 뒤 다음 디렉터리에서 서명 행이 되살아남");
        s.set_recover_state(&id(&home), "cut").unwrap();
        assert_eq!(step(), 0, "끊긴 뒤에도");
        s.set_recover_state(&id(&home), "scheduled").unwrap();
        s.drop_recover_scheduled().unwrap();
        assert_eq!(step(), 1, "취소되면 다시 서명");
        // 횟수 되돌리기는 0 아래로 내려가지 않는다.
        s.note_recover_targets(&["t".to_owned()]).unwrap();
        s.unbump_recover_tries("t").unwrap();
        s.bump_recover_tries("t").unwrap();
        s.bump_recover_tries("t").unwrap();
        s.unbump_recover_tries("t").unwrap();
        let t = s.recover_noted().unwrap();
        assert_eq!(
            t.iter().find(|n| n.device_id == "t").map(|n| n.tries),
            Some(1)
        );
    }

    /// §7a-1 자동 재서명: 내가 믿는 내 다른 기기 중 디렉터리에 이 기기의 서명이 없는 것만. pending·다른 사용자·사라진 기기는
    /// 서명하지 않는다. 큐에 넣은 서명은 relay·동료가 검증하는 식(§3)과 맞는다.
    #[test]
    fn 서명할_내_기기와_서명_프레임() {
        let s = Store::memory().unwrap();
        let k = |n: u8| DeviceKeys::generate(&[n; 64]);
        let (this, home, work) = (k(41), k(42), k(43));
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();
        let me = |devs: Vec<Value>| {
            stamp(
                &dir(
                    json!([{"address": "me@local", "devices": devs}, {"address": "bob@local", "devices": [entry(&k(44))]}]),
                ),
                this.device_id().as_str(),
            )
        };
        let learn = |f: &Value| super::learn_directory(&s, f, "me", &id(&this), "local", 1_000);
        learn(&me(vec![entry(&this), entry(&home)])).unwrap();
        learn(&me(vec![entry(&this), entry(&home), entry(&work)])).unwrap(); // work = pending
        let f = me(vec![entry(&this), entry(&home), entry(&work)]);
        let want = super::to_certify(&s, &f, "me", &id(&this)).unwrap();
        assert_eq!(
            want.iter().map(|(d, _)| d.clone()).collect::<Vec<_>>(),
            vec![id(&home)]
        );
        // 이미 이 기기의 서명이 있으면 없음.
        let signed = me(vec![
            entry(&this),
            with_certs(&home, vec![cert(&this, "me", &home, "local")]),
            entry(&work),
        ]);
        assert!(super::to_certify(&s, &signed, "me", &id(&this))
            .unwrap()
            .is_empty());
        // 큐에 넣은 프레임의 서명이 맞다.
        super::queue_certify(&s, &this, "local", "me", &id(&home), &want[0].1).unwrap();
        let item = s.peek().unwrap().expect("큐에 하나");
        assert_eq!(item.kind, "device", "응답 없는 프레임");
        let v: Value = serde_json::from_str(&item.frame).unwrap();
        assert_eq!(v["t"], "device.certify");
        assert_eq!(v["device_id"], id(&home));
        let x = home.exchange.public_key();
        let c = lodelai_crypto::devcert::Cert {
            server: "local",
            user: "me",
            device_id: &id(&home),
            x25519: &x,
            signer: &id(&this),
        };
        assert!(lodelai_crypto::devcert::verify(
            &this.signing.verifying_key(),
            &c,
            v["sig"].as_str().unwrap()
        ));
    }

    /// #313: x25519_sig 가 없거나 x25519 가 바꿔 끼워졌으면 지문이 맞아도 버린다(서버가 필드를 빼서 검증을 건너뛰지 못한다).
    #[test]
    fn my_own_devices_follow_the_same_trust_rule() {
        // #339: 내 사용자 항목도 배운다. 이 기기 자신은 늘 trusted 이고 알리지 않는다.
        let s = Store::memory().unwrap();
        let this = DeviceKeys::generate(&[5u8; 64]);
        let home = DeviceKeys::generate(&[6u8; 64]);
        let work = DeviceKeys::generate(&[7u8; 64]);
        let me = |devs: Vec<Value>| {
            stamp(
                &dir(json!([{"address": "me@local", "devices": devs}])),
                this.device_id().as_str(),
            )
        };
        let learn = |f: &Value| {
            super::learn_directory(&s, f, "me", this.device_id().as_str(), "local", 1_000)
        };
        let id = |k: &DeviceKeys| k.device_id().as_str().to_owned();

        // 첫 디렉터리의 내 다른 기기 = 뿌리(분실 복구 때 잃은 기기도 여기 — 카드 없이 목록에서 지운다).
        let l = learn(&me(vec![entry(&this), entry(&home)])).unwrap();
        assert_eq!(ids(&l), vec![("first", id(&home))]);
        assert_eq!(s.peer(&id(&this)).unwrap().unwrap().trust, Trust::Trusted);
        // 그 뒤 새 기기(이메일로 추가) = pending → "새 기기 추가됨" 카드.
        let l = learn(&me(vec![entry(&this), entry(&home), entry(&work)])).unwrap();
        assert_eq!(ids(&l), vec![("new", id(&work))]);
        assert_eq!(s.peer(&id(&work)).unwrap().unwrap().trust, Trust::Pending);
        // 목록에서 빠지면 revoked. 이 기기 자신은 어떤 경우에도 알리지 않는다.
        let l = learn(&me(vec![entry(&this), entry(&home)])).unwrap();
        assert_eq!(ids(&l), vec![("revoked", id(&work))]);
        // 이 기기 행이 (옛 데이터로) trusted 가 아니어도 되돌린다.
        s.set_trust(&id(&this), Trust::Pending).unwrap();
        assert!(learn(&me(vec![entry(&this), entry(&home)]))
            .unwrap()
            .is_empty());
        assert_eq!(s.peer(&id(&this)).unwrap().unwrap().trust, Trust::Trusted);
    }

    #[test]
    fn x25519_sig_missing_or_swapped_key_is_mismatch() {
        let s = Store::memory().unwrap();
        let b1 = DeviceKeys::generate(&[2u8; 64]);
        let evil = DeviceKeys::generate(&[9u8; 64]);
        let mut no_sig = entry(&b1);
        no_sig["device_pubkeys"]
            .as_object_mut()
            .unwrap()
            .remove("x25519_sig");
        let mut swapped = entry(&b1);
        swapped["device_pubkeys"]["x25519"] = json!(encoding::encode(&evil.exchange.public_key()));
        let mut garbage = entry(&b1);
        garbage["device_pubkeys"]["x25519_sig"] = json!("AAAA");
        for e in [no_sig, swapped, garbage] {
            let l = learn_directory(&s, &dir(json!([{"address": "bob@local", "devices": [e]}])))
                .unwrap();
            assert_eq!(
                l,
                vec![Learned::Mismatch {
                    user: "bob".into(),
                    device_id: b1.device_id().as_str().into()
                }]
            );
            assert!(
                s.peer(b1.device_id().as_str()).unwrap().is_none(),
                "배우지 않는다"
            );
        }
        // 맞는 항목이면 배운다
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b1)]}])),
        )
        .unwrap();
        assert_eq!(ids(&l), vec![("first", b1.device_id().as_str().to_owned())]);
        assert!(s.peer(b1.device_id().as_str()).unwrap().is_some());
    }

    #[test]
    fn planted_own_device_waits_for_registration_then_falls_back() {
        let s = Store::memory().unwrap();
        let mine = DeviceKeys::generate(&[7u8; 64]);
        let id = mine.device_id().as_str().to_owned();
        s.insert_peer(&Peer {
            device_id: id.clone(),
            user: "me".into(),
            ed25519: mine.signing.verifying_key().to_b64(),
            x25519: encoding::encode(&mine.exchange.public_key()),
            trust: Trust::Trusted,
            first_contact: false,
        })
        .unwrap();
        s.set_basis(&id, &[planted_basis(1_000), "human".into()])
            .unwrap();
        let empty = dir(json!([{"address": "me@local", "devices": []}]));
        let at =
            |now: i64| super::learn_directory(&s, &empty, "me", "k1_me", "local", now).unwrap();
        assert!(
            at(1_000 + PLANTED_TTL_MS - 1).is_empty(),
            "등록 전 — 그대로"
        );
        assert_eq!(s.peer(&id).unwrap().unwrap().trust, Trust::Trusted);
        assert_eq!(
            ids(&at(1_000 + PLANTED_TTL_MS)),
            vec![("revoked", id.clone())]
        );
        assert_eq!(s.basis(&id).unwrap(), vec!["human".to_owned()]);
    }

    /// #1543: 앞 디렉터리에 없던 증명 있는 폐기가 실릴 때만 참 — 같은 기록·첫 디렉터리·꼴이 틀린 기록은 거짓.
    #[test]
    fn 새_폐기_기록이_실렸는지() {
        use lodelai_crypto::devrevoke;
        let (b1, b2) = (
            DeviceKeys::generate(&[41; 64]),
            DeviceKeys::generate(&[42; 64]),
        );
        let at = "2026-10-03T00:00:00.000Z";
        let b1_id = b1.device_id().as_str().to_owned();
        let rec = |ed: &DeviceKeys| {
            json!({
                "device_id": b1_id,
                "added_at": "2026-10-01T00:00:00.000Z",
                "ed25519": ed.signing.verifying_key().to_b64(),
                "x25519": encoding::encode(&b1.exchange.public_key()),
                "certs": [],
                "at": at,
                "signer": b2.device_id().as_str(),
                "sig": devrevoke::sign(
                    &b2.signing,
                    &devrevoke::Revoke { server: "local", device_id: &b1_id, at },
                ),
            })
        };
        let frame = |recs: Vec<Value>| {
            dir(json!([{"address": "bob@local", "devices": [], "revocations": recs}]))
        };
        let (none, with) = (frame(vec![]), frame(vec![rec(&b1)]));
        assert!(revocation_gained(&none, &with));
        assert!(!revocation_gained(&with, &with), "같은 기록");
        assert!(!revocation_gained(&with, &none), "빠진 것은 아님");
        assert!(!revocation_gained(&Value::Null, &with), "첫 디렉터리");
        assert!(
            !revocation_gained(&none, &frame(vec![rec(&b2)])),
            "키가 기기 아이디와 안 맞는 기록"
        );
    }

    fn dir(people: Value) -> Value {
        json!({"t": "directory", "people": people, "sessions": []})
    }

    fn signed(k: &DeviceKeys, from: &str, kind: &str, reply_to: Option<&str>) -> Value {
        let mut m = json!({
            "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": "01JB0000000000000000000009", "thread_id": "01JB0000000000000000000009", "kind": kind,
            "from": {"address": from, "author": "human", "device_id": k.device_id().as_str()},
            "to": {"address": "me@local"}, "body": {"enc": "plain", "text": "x"},
            "created_at": "2026-10-23T04:12:56.000Z", "expires_at": "2026-10-24T04:12:56.000Z"
        });
        if let Some(r) = reply_to {
            m["reply_to"] = json!(r);
        }
        sign_message(&mut m, &k.signing).unwrap();
        m
    }

    #[test]
    fn tofu_new_device_and_mismatch() {
        let s = Store::memory().unwrap();
        let b1 = DeviceKeys::generate(&[2u8; 64]);
        let b2 = DeviceKeys::generate(&[3u8; 64]);
        let (id1, id2) = (
            b1.device_id().as_str().to_owned(),
            b2.device_id().as_str().to_owned(),
        );
        // 처음 보는 사람: trusted 로 고정(TOFU 뿌리)
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b1)]}])),
        )
        .unwrap();
        assert_eq!(ids(&l), vec![("first", id1.clone())]);
        let p1 = s.peer(&id1).unwrap().unwrap();
        assert_eq!((p1.trust, p1.first_contact), (Trust::Trusted, true));
        // 같은 목록 다시: 아무 일 없음
        assert!(learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b1)]}]))
        )
        .unwrap()
        .is_empty());
        // 동료의 새 기기: 카드 없이 trusted(묶음 22 §2c — MLS 잎 자격이 정함), first_contact 아님
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b1), entry(&b2)]}])),
        )
        .unwrap();
        assert_eq!(ids(&l), vec![("new", id2.clone())]);
        let p2 = s.peer(&id2).unwrap().unwrap();
        assert_eq!((p2.trust, p2.first_contact), (Trust::Trusted, false));
        // b1 이 목록에서 사라짐 → revoked, 다시 나타나면 trusted(동료 기기 — 확인 카드 없음)
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b2)]}])),
        )
        .unwrap();
        assert_eq!(ids(&l), vec![("revoked", id1.clone())]);
        assert_eq!(s.peer(&id1).unwrap().unwrap().trust, Trust::Revoked);
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "bob@local", "devices": [entry(&b1), entry(&b2)]}])),
        )
        .unwrap();
        assert!(ids(&l).is_empty());
        assert_eq!(s.peer(&id1).unwrap().unwrap().trust, Trust::Trusted);
        // 반신뢰 서버가 b1 의 id 에 다른 키를 끼움 → 버리고 경고
        let mut forged = entry(&b1);
        forged["device_pubkeys"]["ed25519"] = json!(b2.signing.verifying_key().to_b64());
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "eve@local", "devices": [forged]}])),
        )
        .unwrap();
        assert!(matches!(&l[0], Learned::Mismatch { .. }));
        // 이미 bob 으로 고정된 기기가 다른 사람으로 오면 무시
        let l = learn_directory(
            &s,
            &dir(json!([{"address": "eve@local", "devices": [entry(&b1)]}])),
        )
        .unwrap();
        assert_eq!(
            l,
            vec![Learned::Mismatch {
                user: "eve".into(),
                device_id: b1.device_id().as_str().into()
            }]
        );
        assert_eq!(
            s.peer(b1.device_id().as_str()).unwrap().unwrap().user,
            "bob"
        );
    }

    #[test]
    fn verify_rules() {
        let s = Store::memory().unwrap();
        let bob = DeviceKeys::generate(&[2u8; 64]);
        let eve = DeviceKeys::generate(&[4u8; 64]);
        // 모르는 기기
        assert_eq!(
            verify(&s, &signed(&bob, "bob@local", "chat", None), "me", "local").unwrap(),
            Verdict::UnknownDevice(bob.device_id().as_str().into())
        );
        learn_directory(&s, &dir(json!([{"address": "bob@local", "devices": [entry(&bob)]}, {"address": "eve@local", "devices": [entry(&eve)]}]))).unwrap();
        assert_eq!(
            verify(&s, &signed(&bob, "bob@local", "chat", None), "me", "local").unwrap(),
            Verdict::Ok
        );
        // 서명 변조
        let mut m = signed(&bob, "bob@local", "chat", None);
        m["body"]["text"] = json!("변조");
        assert_eq!(
            verify(&s, &m, "me", "local").unwrap(),
            Verdict::Reject(RejectReason::BadSignature)
        );
        // eve 의 기기가 bob 이라고 주장(자기 키로 서명은 맞음)
        assert_eq!(
            verify(&s, &signed(&eve, "bob@local", "chat", None), "me", "local").unwrap(),
            Verdict::Reject(RejectReason::BadSignature)
        );
        // reply_to 가 내가 보낸 것이 아님
        assert_eq!(
            verify(
                &s,
                &signed(
                    &bob,
                    "bob@local",
                    "reply",
                    Some("01JB0000000000000000000001")
                ),
                "me",
                "local"
            )
            .unwrap(),
            Verdict::Reject(RejectReason::UnknownDelivery)
        );
        s.mark_sent("01JB0000000000000000000001", "bob").unwrap();
        assert_eq!(
            verify(
                &s,
                &signed(
                    &bob,
                    "bob@local",
                    "reply",
                    Some("01JB0000000000000000000001")
                ),
                "me",
                "local"
            )
            .unwrap(),
            Verdict::Ok
        );
        // 확인 안 한·폐기 표시 기기에서 온 것(서명은 맞음)도 보류 없음(묶음 22 §2c — MLS 잎 자격이 정함)
        s.set_trust(bob.device_id().as_str(), Trust::Pending)
            .unwrap();
        assert_eq!(
            verify(&s, &signed(&bob, "bob@local", "chat", None), "me", "local").unwrap(),
            Verdict::Ok
        );
        s.set_trust(bob.device_id().as_str(), Trust::Revoked)
            .unwrap();
        assert_eq!(
            verify(&s, &signed(&bob, "bob@local", "chat", None), "me", "local").unwrap(),
            Verdict::Ok
        );
    }

    #[test]
    fn delivery_meant_for_someone_else_is_rejected() {
        // 반신뢰 서버가 bob 에게 간 진짜(서명 맞는) 요청을 나(me)에게 전달 → 받지 않는다.
        let s = Store::memory().unwrap();
        let alice = DeviceKeys::generate(&[7u8; 64]);
        learn_directory(
            &s,
            &dir(json!([{"address": "alice@local", "devices": [entry(&alice)]}])),
        )
        .unwrap();
        let mut to_bob = signed(&alice, "alice@local", "chat", None);
        to_bob["to"] = json!({"address": "bob@local"});
        sign_message(&mut to_bob, &alice.signing).unwrap();
        assert_eq!(
            verify(&s, &to_bob, "me", "local").unwrap(),
            Verdict::Reject(RejectReason::UnknownDelivery)
        );
        // 같은 사용자 이름이라도 다른 서버
        let mut other_server = signed(&alice, "alice@local", "chat", None);
        other_server["to"] = json!({"address": "me@elsewhere"});
        sign_message(&mut other_server, &alice.signing).unwrap();
        assert_eq!(
            verify(&s, &other_server, "me", "local").unwrap(),
            Verdict::Reject(RejectReason::UnknownDelivery)
        );
        // 내 세션 주소로 온 것은 통과
        let mut to_my_session = signed(&alice, "alice@local", "chat", None);
        to_my_session["to"] = json!({"address": "me@local/backend"});
        sign_message(&mut to_my_session, &alice.signing).unwrap();
        assert_eq!(
            verify(&s, &to_my_session, "me", "local").unwrap(),
            Verdict::Ok
        );
        // 내 다른 기기가 bob 에게 보낸 것(pair 잎이라 나에게도 옴, 묶음 22) → 사본. 남이 나를 사칭하면 서명에서 걸린다.
        let mine = DeviceKeys::generate(&[8u8; 64]);
        learn_directory(
            &s,
            &dir(json!([
                {"address": "alice@local", "devices": [entry(&alice)]},
                {"address": "me@local", "devices": [entry(&mine)]},
            ])),
        )
        .unwrap();
        let mut own = signed(&mine, "me@local", "mls", None);
        own["to"] = json!({"address": "bob@local"});
        sign_message(&mut own, &mine.signing).unwrap();
        assert_eq!(verify(&s, &own, "me", "local").unwrap(), Verdict::OwnCopy);
        let mut fake = signed(&alice, "me@local", "mls", None);
        fake["to"] = json!({"address": "bob@local"});
        sign_message(&mut fake, &alice.signing).unwrap();
        assert_eq!(
            verify(&s, &fake, "me", "local").unwrap(),
            Verdict::Reject(RejectReason::BadSignature)
        );
        // 회신: 내가 bob 에게 보낸 메시지에 alice 가 reply_to 로 답함 → 거부(원 메시지의 받는 사람 ≠ 지금 보낸 사람)
        s.mark_sent("01JB0000000000000000000002", "bob").unwrap();
        assert_eq!(
            verify(
                &s,
                &signed(
                    &alice,
                    "alice@local",
                    "reply",
                    Some("01JB0000000000000000000002")
                ),
                "me",
                "local"
            )
            .unwrap(),
            Verdict::Reject(RejectReason::UnknownDelivery)
        );
    }
}

#[cfg(test)]
mod peer_pending_upgrade {
    use super::*;
    use lodelai_crypto::DeviceKeys;
    use serde_json::json;

    /// 옛 판에서 pending 으로 남은 동료 기기는 다음 디렉터리에서 trusted(근거 mls_leaf) — 카드가 다시 뜨지 않는다(묶음 22 §2c).
    #[test]
    fn 옛_pending_동료_기기는_디렉터리에서_trusted() {
        let s = Store::memory().unwrap();
        let b1 = DeviceKeys::generate(&[41u8; 64]);
        let id = b1.device_id().as_str().to_owned();
        let entry = json!({
            "device_id": id,
            "device_pubkeys": {
                "ed25519": b1.signing.verifying_key().to_b64(),
                "x25519": encoding::encode(&b1.exchange.public_key()),
                "x25519_sig": lodelai_crypto::xkey::sign(&b1.signing, &id, &b1.exchange.public_key()),
            },
        });
        let dir = json!({"people": [{"address": "bob@local", "devices": [entry]}]});
        learn_directory(&s, &dir, "me", "k1_me", "local", 1_000).unwrap();
        s.set_trust(&id, Trust::Pending).unwrap();
        learn_directory(&s, &dir, "me", "k1_me", "local", 2_000).unwrap();
        assert_eq!(s.peer(&id).unwrap().unwrap().trust, Trust::Trusted);
        assert_eq!(s.basis(&id).unwrap(), ["mls_leaf"]);
    }
}
