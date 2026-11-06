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

/// `directory`·`directory.update` 의 `people`(전체 목록)을 읽어 고정하고 신뢰 상태를 맞춘다. `me` = 내 사용자,
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
    let Some(people) = frame.get("people").and_then(Value::as_array) else {
        return Ok(out);
    };
    for person in people {
        let Some(user) = person
            .get("address")
            .and_then(Value::as_str)
            .and_then(|a| a.split('@').next())
        else {
            continue;
        };
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

/// 받은 디렉터리 한 장의 MLS 잎 자격 보기([`mls_rules::Directory`]) — 키 검증을 지난 기기와 증명 있는 폐기만.
#[derive(Debug, Clone, Default)]
pub struct DirView {
    server: String,
    devices: Vec<DirDevice>,
    revocations: Vec<(String, Revocation)>,
    /// 디렉터리에서 사라진 기기 → 옛 사용자(피어 표 `revoked`).
    former: Vec<(String, String)>,
}

impl DirView {
    /// `directory`·`directory.update` 프레임(또는 그 합본)에서.
    #[must_use]
    pub fn new(frame: &Value, server: &str) -> Self {
        let mut v = Self {
            server: server.to_owned(),
            ..Self::default()
        };
        for person in frame
            .get("people")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(user) = person
                .get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
            else {
                continue;
            };
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
}

impl DirView {
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

/// 디렉터리 사람 항목의 `revocations`(증명 있는 폐기, §12-11 ⓐ). 꼴이 틀린 항목은 버린다(마디가 안 됨).
fn revocations_of(person: &Value) -> Vec<Revocation> {
    person
        .get("revocations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let s = |k: &str| r.get(k).and_then(Value::as_str);
            Some(Revocation {
                device_id: s("device_id")?.to_owned(),
                added_ms: UnixMillis::parse_rfc3339(s("added_at")?).ok()?.0,
                ed25519: VerifyingKey::from_b64(s("ed25519")?).ok()?.to_bytes(),
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
    store.push(
        &format!("certify:{device_id}"),
        "device",
        None,
        None,
        &f.to_string(),
        true,
    )
}

/// 내가 서명해야 할 내 다른 기기(§7a-1 자동 재서명): 내가 `trusted` 로 둔, 이번 디렉터리에 있는 내 기기 중 `certs` 에
/// 이 기기(`my_device`)의 서명이 없는 것. pending·다른 사용자·사라진 기기는 넣지 않는다. `(device_id, x25519 b64)`.
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
            if id == my_device || certs_of(d).iter().any(|(s, _)| s == my_device) {
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
