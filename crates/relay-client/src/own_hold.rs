//! 내 기기 그룹 변경을 쥠(#1516 결정 7156954668).
//!
//! 받는 쪽은 한 사용자의 뿌리를 「산 기기에 닿는 가장 이른 마디」로 계산한다([`mls_rules::roots`]). relay 가 더 이른 기기를 지어
//! 넣으면 그것이 뿌리가 되고 그 아래에서 잎 자격·폐기 증명을 지을 수 있다. 내 계정의 진짜 뿌리는 이 기기가 가장 잘 안다 —
//! 그래서 **내 뿌리가 바뀌거나 이 기기가 뿌리 아래에서 빠지는**(들어 있다가 빠지는 전이만) 디렉터리는, 이 기기가 시작한 정당한
//! 변경이 아니면 받아들이지 않는다: 디렉터리 프레임에서 내 항목의 `devices`·`revocations` 를 **마지막으로 받아들인 모습**으로
//! 갈아 끼워 아래로 흘린다([`step`]). 디렉터리를 읽는 자리(피어 표·자동 재서명·뒤늦은 증명·받는 Commit 의 잎 자격·duty·다시
//! 들기)가 모두 그 프레임을 보므로 한 자리로 쥔다. 내 항목의 다른 칸(`recovery` 등)과 다른 사람 항목은 그대로다.
//!
//! - 정당한 변경(이 기기가 시작): 이 기기가 시작한 길 가운데 뿌리가 바뀌는 것은 메일 확인 끊기 하나이고 그때 새 뿌리는 이
//!   기기다(시험 `keys::tests::정당한_길에서_내_뿌리와_이_기기의_잎_자격`). 시간 창 없이 내용으로 본다 — 새 뿌리가 이 기기이고,
//!   사라진 내 산 기기가 모두 이 기기가 끊기를 걸며 적어 둔 대상(`recover_noted`, 옛 끊기 아님)일 때만.
//! - 처음 본 모습(받아들인 것이 없음 — 새 기기·옛 판에서 올라옴)은 조용히 받아들인다(기준점).
//! - 푸는 길은 사람 하나([`crate::RelayClient::apply_devices_held`] — 설정 › 내 기기 카드의 단추): 그때 본 모습(뿌리·이 기기
//!   자격)을 받아들이기로 적고 디렉터리를 다시 받는다. 다시 온 것이 그 모습과 다르면 다시 쥔다. 저절로 풀지 않는다.
//! - 이 기기가 산 기기 목록에 없거나(폐기 — 다른 길) 뿌리가 서지 않으면 보지 않는다.

use serde_json::Value;

use crate::keys::DirView;
use crate::mls_rules;
use crate::outbox::Store;
use crate::Result;

/// 왜 쥐었나.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 내 뿌리 기기가 바뀌었다.
    Root,
    /// 이 기기가 내 뿌리 아래에서 빠졌다(사슬 없음).
    Out,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Out => "out",
        }
    }
    pub(crate) fn from_db(s: &str) -> Self {
        if s == "out" {
            Self::Out
        } else {
            Self::Root
        }
    }
}

/// 쥔 상태(카드 하나) — 마지막으로 본 모습.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub kind: Kind,
    /// 본 뿌리 기기.
    pub root: String,
    /// 본 모습에서 이 기기가 뿌리 아래인가.
    pub eligible: bool,
    /// 그 뿌리 기기의 이름·등록 시각(디렉터리에 산 기기로 실려 있을 때만 — relay 의 말).
    pub name: Option<String>,
    pub added_at: Option<String>,
    /// 처음 쥔 때(ms).
    pub since: i64,
}

/// 저장 줄 하나(`own_gate`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Row {
    /// 받아들인 내 `devices`·`revocations`(JSON 글).
    pub devices: String,
    pub revocations: String,
    pub root: String,
    pub eligible: bool,
    pub held: Option<Held>,
    /// 사람이 받아들이기로 한 모습(뿌리·이 기기 자격) — 다음 디렉터리가 이것이면 받아들인다.
    pub approved: Option<(String, bool)>,
}

/// [`step`] 이 알릴 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// 새로 쥐었다(알림 한 번).
    Held(Held),
    /// 쥔 채 본 모습이 달라졌다(카드 줄만 갈아 끼움).
    Updated(Held),
    /// 풀렸다(사람이 받아들인 모습이 왔다).
    Released,
}

fn my_entry<'a>(frame: &'a Value, me: &str) -> Option<(&'static str, usize, &'a Value)> {
    for key in ["people", "links", "group_members"] {
        for (i, p) in frame
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let user = p
                .get("address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                .or_else(|| p.get("user").and_then(Value::as_str));
            if user == Some(me) {
                return Some((key, i, p));
            }
        }
    }
    None
}

fn live_ids(devices: &Value) -> Vec<&str> {
    devices
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d.get("device_id").and_then(Value::as_str))
        .collect()
}

/// 받은 디렉터리 프레임 하나를 본다. 쥐어야 하면(또는 쥔 채면) 내 항목의 `devices`·`revocations` 를 받아들인 모습으로 갈아
/// 끼운 프레임을, 아니면 받은 그대로를 돌려준다. 둘째는 알릴 것.
///
/// # Errors
/// 저장 오류.
pub fn step(
    store: &Store,
    mut frame: Value,
    me: &str,
    my_device: &str,
    server: &str,
    now_ms: i64,
) -> Result<(Value, Option<Changed>)> {
    let Some((key, at, person)) = my_entry(&frame, me) else {
        return Ok((frame, None));
    };
    let devices = person.get("devices").cloned().unwrap_or(Value::Null);
    let revocations = person.get("revocations").cloned().unwrap_or(Value::Null);
    // 내 항목만으로 판정한다(같은 계산 — 키 검증을 지난 기기와 꼴이 맞는 폐기 기록만).
    let own = serde_json::json!({"people": [{"address": format!("{me}@{server}"),
        "devices": devices, "revocations": revocations}]});
    let view = DirView::new(&own, server);
    let roots = mls_rules::roots_in(&view, me);
    let here = live_ids(&devices).contains(&my_device);
    let Some(root) = roots.root.clone().filter(|_| here) else {
        // 이 기기가 목록에 없음·뿌리가 서지 않음 — 판정할 것이 없다. 받아들인 모습이 있으면 그것으로 얼린다: 이 기기만 같이
        // 뺀 프레임으로 내 다른 기기를 증명 없이 끊긴 것으로 만들지 못하게(폐기 반영도 쥔다). 이 기기가 정말 끊겼으면
        // 디렉터리가 아니라 `device_revoked` 로 안다. 받아들인 모습이 아직 없으면 받은 그대로.
        return match store.own_gate()? {
            Some(row) => Ok((frozen(frame, key, at, &row), None)),
            None => Ok((frame, None)),
        };
    };
    let eligible = roots.eligible.contains(my_device);
    let accept = |frame: Value, released: bool| -> Result<(Value, Option<Changed>)> {
        store.set_own_gate(&Row {
            devices: devices.to_string(),
            revocations: revocations.to_string(),
            root: root.clone(),
            eligible,
            held: None,
            approved: None,
        })?;
        Ok((frame, released.then_some(Changed::Released)))
    };
    let Some(row) = store.own_gate()? else {
        // 받아들인 모습이 아직 없다(새 기기·옛 판에서 올라옴). 내 뿌리의 기억(`roots` 표 — 옛 판도 적어 왔다)이 있으면 그것이
        // 기준점이다: 첫 디렉터리의 뿌리가 그와 다르면 조용히 받아들이지 않고 쥔다(판을 올리는 순간이 「한 번은 아무 뿌리나
        // 받아들이는」 창이 되지 않게). 기억이 없을 때만 첫 모습이 기준점.
        let remembered = store.last_root(me)?;
        let own_recovery = root == my_device && store.recover_noted()?.iter().any(|n| !n.legacy);
        return match remembered {
            Some(old) if old != root && !own_recovery => {
                let base = baseline(store, me, my_device, server, &devices, &revocations, &old)?;
                let held = describe(&base, &root, eligible, &devices, now_ms);
                let row = Row {
                    held: Some(held.clone()),
                    ..base
                };
                store.set_own_gate(&row)?;
                Ok((frozen(frame, key, at, &row), Some(Changed::Held(held))))
            }
            _ => accept(frame, false),
        };
    };
    let seen = (root.clone(), eligible);
    if let Some(held) = &row.held {
        // 쥔 채: 사람이 받아들인 모습이 왔으면 풀고, 아니면 계속 얼린다(저절로 풀지 않는다).
        if row.approved.as_ref() == Some(&seen) {
            return accept(frame, true);
        }
        let now = describe(&row, &root, eligible, &devices, held.since);
        // 받아들이기로 한 것과 다른 모습이 왔다 — 다시 쥔다(알림도 다시).
        let again = row.approved.is_some();
        let changed = if again {
            Some(Changed::Held(now.clone()))
        } else if now != *held {
            Some(Changed::Updated(now.clone()))
        } else {
            None
        };
        if changed.is_some() {
            store.set_own_gate(&Row {
                held: Some(now),
                approved: None,
                ..row.clone()
            })?;
        }
        frame = frozen(frame, key, at, &row);
        return Ok((frame, changed));
    }
    let root_changed = row.root != root;
    let dropped = row.eligible && !eligible;
    if !root_changed && !dropped {
        return accept(frame, false);
    }
    // 정당한 변경: 이 기기가 건 메일 확인 끊기(관리자가 앞당긴 것 포함) — 새 뿌리가 이 기기이고, 사라진 내 산 기기가 모두
    // 그때 적어 둔 대상.
    if root_changed && !dropped && root == my_device {
        let noted: Vec<String> = store
            .recover_noted()?
            .into_iter()
            .filter(|n| !n.legacy)
            .map(|n| n.device_id)
            .collect();
        let before: Value = serde_json::from_str(&row.devices).unwrap_or(Value::Null);
        let now = live_ids(&devices);
        let gone: Vec<&str> = live_ids(&before)
            .into_iter()
            .filter(|id| !now.contains(id))
            .collect();
        if !gone.is_empty() && gone.iter().all(|id| noted.iter().any(|n| n == id)) {
            return accept(frame, false);
        }
    }
    // 받아들인 내 기기가 스스로 증명한 변경: 옛 뿌리가 사라졌고, 사라진 기기마다 **받아들인 모습의 기기 키**로 서명한 폐기
    // 증명이 실려 있으며, 새 뿌리가 받아들인 모습에 이미 있던 기기다. relay 가 지어낼 수 없다(그 기기들의 키가 있어야 한다) —
    // 옛 기기를 스스로 끊은(로그아웃) 뒤 서명 못 받은 새 기기가 뿌리가 되는 길(#1201)이 이것이다.
    if root_changed
        && !dropped
        && proved_by_accepted(&row, &devices, &revocations, &root, me, my_device, server)
    {
        return accept(frame, false);
    }
    let held = describe(&row, &root, eligible, &devices, now_ms);
    store.set_own_gate(&Row {
        held: Some(held.clone()),
        approved: None,
        ..row.clone()
    })?;
    Ok((frozen(frame, key, at, &row), Some(Changed::Held(held))))
}

/// 뿌리 바뀜이 받아들인 모습의 기기들이 스스로 증명한 것인가: ① 옛 뿌리가 산 기기 목록에서 사라졌고 ② 사라진 받아들인 기기마다
/// 새 프레임에 폐기 기록이 있고 그 서명이 **그 기기 자신 또는 받아들인 모습에서 뿌리 아래였던 기기**의 키로 맞으며 ③ 새
/// 뿌리가 **이 기기 자신이거나 받아들인 모습에서 뿌리 아래였던 기기**다. 등록 순서만 바꿔 뿌리를 옮기는 것(사라진 기기 없음)·지어낸 기기가 뿌리가 되는 것은
/// 해당하지 않는다.
fn proved_by_accepted(
    row: &Row,
    devices: &Value,
    revocations: &Value,
    root: &str,
    me: &str,
    my_device: &str,
    server: &str,
) -> bool {
    use mls_rules::Directory as _;
    let address = format!("{me}@{server}");
    let before: Value = serde_json::from_str(&row.devices).unwrap_or(Value::Null);
    let before_revs: Value = serde_json::from_str(&row.revocations).unwrap_or(Value::Null);
    let view = DirView::new(
        &serde_json::json!({"people": [{"address": address, "devices": before, "revocations": before_revs}]}),
        server,
    );
    let accepted = view.devices(me);
    // 서명자는 그 기기 자신이거나 받아들인 모습에서 뿌리 아래(잎 자격)였던 기기만 — 디렉터리의 증명 규칙과 같은 선
    // ([`mls_rules::proved_set`]). 받아들인 모습에 실려만 있던 서명 못 받은 기기의 서명은 받지 않는다.
    let eligible = mls_rules::roots_in(&view, me).eligible;
    let now = live_ids(devices);
    let gone: Vec<&mls_rules::DirDevice> = accepted
        .iter()
        .filter(|d| !now.contains(&d.device_id.as_str()))
        .collect();
    // 새 뿌리는 이 기기 자신이거나 받아들인 모습에서 뿌리 아래였던 기기만 — 서명 없이 실리는 것은 쥐지 않고 받아들여지므로,
    // 실려만 있던 기기가 뿌리가 되는 것은 통과시키지 않는다.
    if !gone.iter().any(|d| d.device_id == row.root)
        || !(root == my_device || eligible.contains(root))
    {
        return false;
    }
    let records = crate::keys::revocations_of(&serde_json::json!({"revocations": revocations}));
    gone.iter().all(|d| {
        records.iter().any(|r| {
            r.device_id == d.device_id
                && r.ed25519 == d.ed25519
                && accepted
                    .iter()
                    .find(|s| {
                        s.device_id == r.signer
                            && (r.signer == d.device_id || eligible.contains(&r.signer))
                    })
                    .and_then(|s| lodelai_crypto::VerifyingKey::from_bytes(&s.ed25519).ok())
                    .is_some_and(|k| {
                        lodelai_crypto::devrevoke::verify(
                            &k,
                            &lodelai_crypto::devrevoke::Revoke {
                                server,
                                device_id: &r.device_id,
                                at: &r.at,
                            },
                            &r.sig,
                        )
                    })
        })
    })
}

/// 받아들인 모습 없이 쥘 때의 기준 모습: 받은 내 항목에서 **이 기기가 이미 아는 내 기기**(피어 표, 폐기 아님)와 이 기기만 남긴
/// 것 — 모르는 기기는 들이지 않는다. 뿌리는 기억하던 것. 앞 모습을 모르므로 사라진 기기를 되살리지는 못한다(폐기 반영은 이
/// 한 경우에만 못 쥔다).
fn baseline(
    store: &Store,
    me: &str,
    my_device: &str,
    server: &str,
    devices: &Value,
    revocations: &Value,
    remembered: &str,
) -> Result<Row> {
    let peers = store.peers_of(me)?;
    let known = |v: &Value, any_trust: bool| -> Vec<Value> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter(|d| {
                let id = d.get("device_id").and_then(Value::as_str);
                id == Some(my_device)
                    || peers.iter().any(|p| {
                        Some(p.device_id.as_str()) == id
                            && (any_trust || p.trust != crate::outbox::Trust::Revoked)
                    })
            })
            .cloned()
            .collect()
    };
    let (devices, revocations) = (
        Value::Array(known(devices, false)),
        Value::Array(known(revocations, true)),
    );
    let own = serde_json::json!({"people": [{"address": format!("{me}@{server}"),
        "devices": devices, "revocations": revocations}]});
    let eligible = mls_rules::roots_in(&DirView::new(&own, server), me)
        .eligible
        .contains(my_device);
    Ok(Row {
        devices: devices.to_string(),
        revocations: revocations.to_string(),
        root: remembered.to_owned(),
        eligible,
        held: None,
        approved: None,
    })
}

fn describe(row: &Row, root: &str, eligible: bool, devices: &Value, since: i64) -> Held {
    let entry = devices
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d.get("device_id").and_then(Value::as_str) == Some(root));
    let text = |k: &str| {
        entry
            .and_then(|d| d.get(k))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    Held {
        // 뿌리가 그대로인데 이 기기만 빠졌으면 out, 뿌리가 바뀌었으면(이 기기가 빠졌든 아니든) root.
        kind: if row.root == root && row.eligible && !eligible {
            Kind::Out
        } else {
            Kind::Root
        },
        root: root.to_owned(),
        eligible,
        name: text("name"),
        added_at: text("added_at"),
        since,
    }
}

/// 내 항목의 `devices`·`revocations` 를 받아들인 모습으로.
fn frozen(mut frame: Value, key: &str, at: usize, row: &Row) -> Value {
    if let Some(p) = frame
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .and_then(|a| a.get_mut(at))
        .and_then(Value::as_object_mut)
    {
        for (k, text) in [("devices", &row.devices), ("revocations", &row.revocations)] {
            match serde_json::from_str::<Value>(text) {
                Ok(Value::Null) | Err(_) => {
                    p.remove(k);
                }
                Ok(v) => {
                    p.insert(k.to_owned(), v);
                }
            }
        }
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodelai_crypto::{devcert, devrevoke, encoding, xkey, DeviceKeys};
    use serde_json::json;

    const T0: &str = "2026-10-01T00:00:00.000Z";
    const T1: &str = "2026-10-02T00:00:00.000Z";
    const T2: &str = "2026-10-03T00:00:00.000Z";
    const T3: &str = "2026-10-04T00:00:00.000Z";

    fn id(k: &DeviceKeys) -> String {
        k.device_id().as_str().to_owned()
    }

    fn live(k: &DeviceKeys, at: &str, certs: Vec<Value>) -> Value {
        let x = k.exchange.public_key();
        json!({"device_id": id(k), "added_at": at, "certs": certs, "device_pubkeys": {
            "ed25519": k.signing.verifying_key().to_b64(),
            "x25519": encoding::encode(&x),
            "x25519_sig": xkey::sign(&k.signing, &id(k), &x)}})
    }

    fn cert(signer: &DeviceKeys, target: &DeviceKeys) -> Value {
        let x = target.exchange.public_key();
        let (tid, sid) = (id(target), id(signer));
        let c = devcert::Cert {
            server: "local",
            user: "me",
            device_id: &tid,
            x25519: &x,
            signer: &sid,
        };
        json!({"signer": sid, "sig": devcert::sign(&signer.signing, &c)})
    }

    /// `signer` 가 증명한 `k` 의 폐기 기록.
    fn gone(k: &DeviceKeys, at: &str, signer: &DeviceKeys) -> Value {
        let cut = "2026-10-05T00:00:00.000Z";
        json!({"device_id": id(k), "added_at": at,
            "ed25519": k.signing.verifying_key().to_b64(),
            "x25519": encoding::encode(&k.exchange.public_key()),
            "certs": [], "at": cut, "signer": id(signer),
            "sig": devrevoke::sign(&signer.signing,
                &devrevoke::Revoke { server: "local", device_id: &id(k), at: cut })})
    }

    fn dir(devices: Vec<Value>, revs: Vec<Value>) -> Value {
        json!({"t": "directory", "people": [
            {"address": "bo@local", "devices": []},
            {"address": "me@local", "devices": devices, "revocations": revs,
             "recovery": {"state": "none"}},
        ]})
    }

    fn keys() -> (DeviceKeys, DeviceKeys, DeviceKeys, DeviceKeys) {
        (
            DeviceKeys::generate(&[51; 64]),
            DeviceKeys::generate(&[52; 64]),
            DeviceKeys::generate(&[53; 64]),
            DeviceKeys::generate(&[54; 64]),
        )
    }

    fn run(s: &Store, this: &DeviceKeys, f: &Value) -> (Value, Option<Changed>) {
        step(s, f.clone(), "me", &id(this), "local", 7).unwrap()
    }

    fn mine(f: &Value) -> Vec<String> {
        f["people"][1]["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["device_id"].as_str().unwrap().to_owned())
            .collect()
    }

    /// relay 가 더 이른 기기를 지어 넣고 진짜 기기에 devcert 까지 지어 주면 뿌리가 바뀐다 — 쥐고, 내 항목은 받아들인 모습으로
    /// 얼려 흘린다. 같은 것이 또 와도 알림은 한 번, 뿌리가 또 바뀌면 카드 줄만. 다시 켜도(같은 저장) 쥔 채다.
    #[test]
    fn 지어낸_뿌리는_쥐고_받아들인_모습으로_얼린다() {
        let s = Store::memory().unwrap();
        let (o, t, fake, fake2) = keys();
        let honest = dir(
            vec![live(&o, T1, vec![]), live(&t, T2, vec![cert(&o, &t)])],
            vec![],
        );
        let (f, c) = run(&s, &t, &honest);
        assert_eq!(
            (f, c),
            (honest.clone(), None),
            "처음 본 모습은 조용히 받아들인다"
        );
        assert_eq!(run(&s, &t, &honest), (honest.clone(), None));
        assert_eq!(s.own_gate().unwrap().unwrap().root, id(&o));
        // 지어낸 더 이른 기기 fake 가 o 에 서명 → fake 가 뿌리.
        let mut named = live(&fake, T0, vec![]);
        named["name"] = json!("Mallory Mac");
        let forged = dir(
            vec![
                named,
                live(&o, T1, vec![cert(&fake, &o)]),
                live(&t, T2, vec![cert(&o, &t)]),
            ],
            vec![],
        );
        let (f, c) = run(&s, &t, &forged);
        let held = Held {
            kind: Kind::Root,
            root: id(&fake),
            eligible: true,
            name: Some("Mallory Mac".into()),
            added_at: Some(T0.into()),
            since: 7,
        };
        assert_eq!(c, Some(Changed::Held(held.clone())));
        assert_eq!(
            mine(&f),
            vec![id(&o), id(&t)],
            "지어낸 기기는 아래로 안 흐른다"
        );
        assert_eq!(f["people"][1]["devices"], honest["people"][1]["devices"]);
        assert_eq!(
            f["people"][0], forged["people"][0],
            "다른 사람 항목은 그대로"
        );
        // 또 와도 알림 없음, 여전히 얼림.
        let (f, c) = run(&s, &t, &forged);
        assert_eq!(c, None);
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        // 쥔 동안 진짜 모습으로 돌아와도 저절로 풀지 않는다(본 모습만 갈아 끼움).
        let (_, c) = run(&s, &t, &honest);
        assert!(
            matches!(c, Some(Changed::Updated(ref h)) if h.root == id(&o)),
            "{c:?}"
        );
        // 또 다른 지어낸 뿌리 — 카드 줄만 갈아 끼움(처음 쥔 때는 그대로).
        let forged2 = dir(
            vec![
                live(&fake2, T0, vec![]),
                live(&o, T1, vec![cert(&fake2, &o)]),
                live(&t, T2, vec![cert(&o, &t)]),
            ],
            vec![],
        );
        let (f, c) = run(&s, &t, &forged2);
        assert!(
            matches!(c, Some(Changed::Updated(ref h)) if h.root == id(&fake2) && h.name.is_none() && h.since == 7),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        let row = s.own_gate().unwrap().unwrap();
        assert_eq!(row.root, id(&o), "받아들인 뿌리는 그대로");
        assert_eq!(row.held.unwrap().root, id(&fake2));
    }

    /// 푸는 길은 사람 하나: 받아들이기로 한 모습이 다시 오면 반영하고, 다른 모습이 오면 다시 쥔다(알림도 다시).
    #[test]
    fn 받아들이기로_한_모습만_반영한다() {
        let s = Store::memory().unwrap();
        let (o, t, n, other) = keys();
        let before = dir(
            vec![live(&o, T1, vec![]), live(&t, T2, vec![cert(&o, &t)])],
            vec![],
        );
        run(&s, &t, &before);
        // 내 다른 기기 n 이 건 메일 확인 끊기로 o 가 증명 없이 끊김(이 기기는 대상이 아니었다) → 뿌리가 t. 이 기기가 시작한
        // 것이 아니라 쥔다(#1516 결정 — 내 다른 기기가 시작한 것도).
        let after = dir(vec![live(&t, T2, vec![]), live(&n, T3, vec![])], vec![]);
        let (f, c) = run(&s, &t, &after);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.kind == Kind::Root && h.root == id(&t))
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        // 사람이 받아들임.
        let row = s.own_gate().unwrap().unwrap();
        let h = row.held.clone().unwrap();
        s.set_own_gate(&Row {
            approved: Some((h.root, h.eligible)),
            ..row
        })
        .unwrap();
        // 그 사이 다른 모습(또 다른 뿌리)이 오면 다시 쥔다.
        let swapped = dir(
            vec![
                live(&other, T0, vec![]),
                live(&t, T2, vec![cert(&other, &t)]),
            ],
            vec![],
        );
        let (f, c) = run(&s, &t, &swapped);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.root == id(&other)),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        assert!(s.own_gate().unwrap().unwrap().approved.is_none());
        // 다시 받아들이고 그 모습이 오면 반영.
        let row = s.own_gate().unwrap().unwrap();
        s.set_own_gate(&Row {
            approved: Some((id(&t), true)),
            ..row
        })
        .unwrap();
        let (f, c) = run(&s, &t, &after);
        assert_eq!(c, Some(Changed::Released));
        assert_eq!(f, after);
        let row = s.own_gate().unwrap().unwrap();
        assert_eq!((row.root, row.held, row.approved), (id(&t), None, None));
        assert_eq!(run(&s, &t, &after), (after, None));
    }

    /// 들어 있다가 빠지는 전이만 「빠짐」: o→m→t 에서 m 이 증명 없이 사라지면 t 는 사슬 없음. 처음부터 사슬 밖인 새 기기가
    /// 그대로 밖인 것은 쥐지 않는다.
    #[test]
    fn 이_기기가_뿌리_아래에서_빠지면_쥔다() {
        let s = Store::memory().unwrap();
        let (o, t, m, _) = keys();
        let before = dir(
            vec![
                live(&o, T0, vec![]),
                live(&m, T1, vec![cert(&o, &m)]),
                live(&t, T2, vec![cert(&m, &t)]),
            ],
            vec![],
        );
        run(&s, &t, &before);
        let cut = dir(
            vec![live(&o, T0, vec![]), live(&t, T2, vec![cert(&m, &t)])],
            vec![],
        );
        let (f, c) = run(&s, &t, &cut);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.kind == Kind::Out && h.root == id(&o) && !h.eligible),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&m), id(&t)]);
        // 새 기기(아직 서명 전)는 처음부터 밖 — 쥐지 않는다.
        let s2 = Store::memory().unwrap();
        let fresh = dir(vec![live(&o, T0, vec![]), live(&t, T2, vec![])], vec![]);
        assert_eq!(run(&s2, &t, &fresh), (fresh.clone(), None));
        assert_eq!(run(&s2, &t, &fresh), (fresh, None));
        // 이 기기가 목록에 없는 프레임: 받아들인 모습이 아직 없으면 받은 그대로(판정할 것이 없다).
        let s3 = Store::memory().unwrap();
        let without = dir(vec![live(&o, T0, vec![])], vec![]);
        assert_eq!(run(&s3, &t, &without), (without.clone(), None));
        assert!(s3.own_gate().unwrap().is_none());
        // 받아들인 모습이 있으면 그것으로 얼린다 — 이 기기와 다른 기기 m 을 같이 뺀 프레임으로 m 을 끊긴 것으로 만들지 못한다.
        let (f, c) = run(&s, &t, &without);
        assert_eq!(c, None);
        assert_eq!(mine(&f), vec![id(&o), id(&m), id(&t)]);
        let s4 = Store::memory().unwrap();
        run(&s4, &t, &before);
        let (f, c) = run(&s4, &t, &without);
        assert_eq!(c, None, "쥔 상태가 아니어도");
        assert_eq!(mine(&f), vec![id(&o), id(&m), id(&t)]);
        assert!(s4.own_gate().unwrap().unwrap().held.is_none());
    }

    /// 이 기기가 시작한 정당한 길은 쥐지 않는다: 기기 더하기, 증명 실은 끊기(뿌리를 끊어도 마디로 남는다), 이 기기가 건 메일
    /// 확인 끊기(새 뿌리 = 이 기기, 사라진 기기 = 걸며 적어 둔 대상). 적어 둔 것이 없으면 같은 모습도 쥔다.
    #[test]
    fn 이_기기가_시작한_변경은_쥐지_않는다() {
        let (o, t, n, _) = keys();
        // 더하기 → 서명 → 뿌리를 증명 실어 끊기.
        let s = Store::memory().unwrap();
        for f in [
            dir(
                vec![live(&o, T1, vec![]), live(&t, T2, vec![cert(&o, &t)])],
                vec![],
            ),
            dir(
                vec![
                    live(&o, T1, vec![]),
                    live(&t, T2, vec![cert(&o, &t)]),
                    live(&n, T3, vec![]),
                ],
                vec![],
            ),
            dir(
                vec![
                    live(&o, T1, vec![]),
                    live(&t, T2, vec![cert(&o, &t)]),
                    live(&n, T3, vec![cert(&t, &n)]),
                ],
                vec![],
            ),
            dir(
                vec![
                    live(&t, T2, vec![cert(&o, &t)]),
                    live(&n, T3, vec![cert(&t, &n)]),
                ],
                vec![gone(&o, T1, &t)],
            ),
        ] {
            assert_eq!(run(&s, &t, &f), (f.clone(), None));
        }
        assert_eq!(s.own_gate().unwrap().unwrap().root, id(&o));
        // 메일 확인 끊기(t = 새 기기): 기다림 → 끊김 → 뒤늦은 증명.
        let waiting = dir(vec![live(&o, T1, vec![]), live(&t, T2, vec![])], vec![]);
        let cut = dir(vec![live(&t, T2, vec![])], vec![]);
        let proved = dir(vec![live(&t, T2, vec![])], vec![gone(&o, T1, &t)]);
        let s = Store::memory().unwrap();
        run(&s, &t, &waiting);
        s.note_recover_targets(&[id(&o)]).unwrap();
        assert_eq!(run(&s, &t, &cut), (cut.clone(), None));
        assert_eq!(run(&s, &t, &proved), (proved, None));
        assert_eq!(s.own_gate().unwrap().unwrap().root, id(&t));
        // 걸지 않았는데 같은 모습이 오면 쥔다.
        let s = Store::memory().unwrap();
        run(&s, &t, &waiting);
        let (f, c) = run(&s, &t, &cut);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.root == id(&t)),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        // 적어 둔 대상 밖의 기기까지 사라졌으면 쥔다.
        let s = Store::memory().unwrap();
        let three = dir(
            vec![
                live(&o, T0, vec![]),
                live(&n, T1, vec![cert(&o, &n)]),
                live(&t, T2, vec![]),
            ],
            vec![],
        );
        run(&s, &t, &three);
        s.note_recover_targets(&[id(&o)]).unwrap();
        assert!(matches!(run(&s, &t, &cut).1, Some(Changed::Held(_))));
    }

    /// 받아들인 모습이 아직 없는 기기(옛 판에서 올라옴): 내 뿌리의 기억이 있으면 그것이 기준점 — 첫 디렉터리의 뿌리가 다르면
    /// 쥐고, 이 기기가 이미 아는 내 기기만 남겨 흘린다. 기억이 없거나 같으면 조용히 받아들인다. 이 기기가 건 끊기로 뿌리가 이
    /// 기기가 된 것은 받아들인다.
    #[test]
    fn 받아들인_모습이_없어도_기억하던_뿌리와_다르면_쥔다() {
        use crate::outbox::{Peer, Trust};
        let (o, t, fake, _) = keys();
        let honest = dir(
            vec![live(&o, T1, vec![]), live(&t, T2, vec![cert(&o, &t)])],
            vec![],
        );
        let forged = dir(
            vec![
                live(&fake, T0, vec![]),
                live(&o, T1, vec![cert(&fake, &o)]),
                live(&t, T2, vec![cert(&o, &t)]),
            ],
            vec![],
        );
        let old_install = |root: Option<&DeviceKeys>| {
            let s = Store::memory().unwrap();
            s.add_peer(&Peer {
                device_id: id(&o),
                user: "me".into(),
                ed25519: String::new(),
                x25519: String::new(),
                trust: Trust::Trusted,
                first_contact: true,
            })
            .unwrap();
            if let Some(r) = root {
                s.set_root("me", &id(r), 1).unwrap();
            }
            s
        };
        // 기억하던 뿌리 o, 첫 디렉터리의 뿌리는 지어낸 fake → 쥔다. 모르는 기기는 흐르지 않는다.
        let s = old_install(Some(&o));
        let (f, c) = run(&s, &t, &forged);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.kind == Kind::Root && h.root == id(&fake)),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        let row = s.own_gate().unwrap().unwrap();
        assert_eq!(row.root, id(&o), "기준점은 기억하던 뿌리");
        let (f, c) = run(&s, &t, &forged);
        assert_eq!(c, None);
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
        // 기억과 같으면·기억이 없으면 조용히 받아들인다.
        let s = old_install(Some(&o));
        assert_eq!(run(&s, &t, &honest), (honest.clone(), None));
        let s = old_install(None);
        assert_eq!(run(&s, &t, &forged), (forged.clone(), None));
        // 이 기기가 건 끊기로 뿌리가 이 기기가 됨 — 받아들인다. 걸지 않았으면 쥔다.
        let cut = dir(vec![live(&t, T2, vec![])], vec![]);
        let s = old_install(Some(&o));
        s.note_recover_targets(&[id(&o)]).unwrap();
        assert_eq!(run(&s, &t, &cut), (cut.clone(), None));
        let s = old_install(Some(&o));
        assert!(matches!(run(&s, &t, &cut).1, Some(Changed::Held(_))));
    }

    /// 옛 뿌리 기기가 스스로 끊고(자기 폐기 증명) 서명 못 받은 새 기기가 뿌리가 되는 길(#1201)은 쥐지 않는다 — 그 증명은 받아들인
    /// 모습의 그 기기 키로만 지을 수 있다. 증명이 없거나, 받아들인 적 없는 키로 서명했거나, 지어낸 기기가 뿌리가 되면 쥔다.
    #[test]
    fn 받아들인_기기가_스스로_증명한_뿌리_바뀜은_쥐지_않는다() {
        let (o, t, fake, n) = keys();
        let waiting = dir(vec![live(&o, T1, vec![]), live(&t, T2, vec![])], vec![]);
        let seeded = || {
            let s = Store::memory().unwrap();
            run(&s, &t, &waiting);
            s
        };
        // o 가 스스로 끊음: 뿌리가 이 기기 t 로 — 받아들인다.
        let own = dir(vec![live(&t, T2, vec![])], vec![gone(&o, T1, &o)]);
        let s = seeded();
        assert_eq!(run(&s, &t, &own), (own.clone(), None));
        assert_eq!(s.own_gate().unwrap().unwrap().root, id(&t));
        // 증명 없음 → 쥔다.
        assert!(matches!(
            run(&seeded(), &t, &dir(vec![live(&t, T2, vec![])], vec![])).1,
            Some(Changed::Held(_))
        ));
        // 받아들인 적 없는 기기(fake)가 서명한 증명 → 쥔다.
        let by_fake = dir(vec![live(&t, T2, vec![])], vec![gone(&o, T1, &fake)]);
        assert!(matches!(
            run(&seeded(), &t, &by_fake).1,
            Some(Changed::Held(_))
        ));
        // o 는 스스로 끊었지만 새 뿌리가 지어낸 기기 → 쥔다.
        let forged = dir(
            vec![live(&fake, T0, vec![]), live(&t, T2, vec![cert(&fake, &t)])],
            vec![gone(&o, T1, &o)],
        );
        assert!(matches!(
            run(&seeded(), &t, &forged).1,
            Some(Changed::Held(_))
        ));
        // 받아들인 모습에 실려만 있던 서명 못 받은 기기(fake — 뿌리보다 뒤에 들어 쥐지 않고 실렸다)가 뿌리의 폐기를 서명 → 쥔다.
        let s = Store::memory().unwrap();
        let listed = dir(
            vec![
                live(&o, T1, vec![]),
                live(&t, T2, vec![cert(&o, &t)]),
                live(&fake, T3, vec![]),
            ],
            vec![],
        );
        assert_eq!(run(&s, &t, &listed), (listed.clone(), None));
        let cut_by_unsigned = dir(
            vec![live(&t, T2, vec![cert(&o, &t)]), live(&fake, T3, vec![])],
            vec![gone(&o, T1, &fake)],
        );
        assert!(
            matches!(run(&s, &t, &cut_by_unsigned).1, Some(Changed::Held(_))),
            "서명 못 받은 기기의 증명은 받지 않는다"
        );
        // 뿌리 아래였던 기기(t 자신)가 서명한 증명이면 뿌리는 마디로 남아 바뀌지 않는다(쥘 일 없음).
        let s = Store::memory().unwrap();
        run(&s, &t, &listed);
        let cut_by_t = dir(
            vec![live(&t, T2, vec![cert(&o, &t)]), live(&fake, T3, vec![])],
            vec![gone(&o, T1, &t)],
        );
        assert_eq!(run(&s, &t, &cut_by_t), (cut_by_t.clone(), None));
        // 새 뿌리가 받아들인 모습에 **실려만 있던**(서명 못 받은) 다른 기기 n 이면 쥔다 — 이 기기가 믿은 적 없는 기기다.
        let s = Store::memory().unwrap();
        run(
            &s,
            &t,
            &dir(
                vec![
                    live(&o, T0, vec![]),
                    live(&n, T1, vec![]),
                    live(&t, T2, vec![]),
                ],
                vec![],
            ),
        );
        let next = dir(
            vec![live(&n, T1, vec![]), live(&t, T2, vec![])],
            vec![gone(&o, T0, &o)],
        );
        assert!(matches!(run(&s, &t, &next).1, Some(Changed::Held(ref h)) if h.root == id(&n)));
    }

    /// 예외 갈래의 새 뿌리는 이 기기 자신이거나 받아들인 모습에서 뿌리 아래였던 기기여야 한다. 서명 없이 실리는 것은 뿌리
    /// 바뀜도 빠짐도 아니라 쥐지 않고 받아들여지므로, 그런 기기 x 가 실린 뒤 내가 뿌리 o 를 정당하게 스스로 끊는 순간 — relay
    /// 가 o 의 서명을 빼고 x 가 이 기기에 한 서명을 실어 이 기기를 x 아래로 옮기면 — 옛 뿌리 사라짐·증명 맞음·이 기기 빠짐
    /// 아님이 다 서도 쥔다.
    #[test]
    fn 실려만_있던_기기가_새_뿌리가_되면_옛_뿌리의_증명이_맞아도_쥔다() {
        let (o, t, x, _) = keys();
        let s = Store::memory().unwrap();
        let listed = dir(
            vec![
                live(&o, T0, vec![]),
                live(&x, T1, vec![]),
                live(&t, T2, vec![cert(&o, &t)]),
            ],
            vec![],
        );
        assert_eq!(
            run(&s, &t, &listed),
            (listed.clone(), None),
            "서명 없이 실리는 것은 쥐지 않는다"
        );
        let moved = dir(
            vec![live(&x, T1, vec![]), live(&t, T2, vec![cert(&x, &t)])],
            vec![gone(&o, T0, &o)],
        );
        let (f, c) = run(&s, &t, &moved);
        assert!(
            matches!(c, Some(Changed::Held(ref h)) if h.kind == Kind::Root && h.root == id(&x) && h.eligible),
            "{c:?}"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&x), id(&t)]);
        // 같은 장면에서 새 뿌리가 이 기기 자신이면(서명 못 받은 새 기기 t 만 남음 — #1201) 쥐지 않는다.
        let s = Store::memory().unwrap();
        let waiting = dir(vec![live(&o, T0, vec![]), live(&t, T2, vec![])], vec![]);
        run(&s, &t, &waiting);
        let alone = dir(vec![live(&t, T2, vec![])], vec![gone(&o, T0, &o)]);
        assert_eq!(run(&s, &t, &alone), (alone.clone(), None));
        // 새 뿌리가 받아들인 모습에서 뿌리 아래였던 기기 m 이면 쥐지 않는다(o→m→t, o 가 스스로 끊고 relay 가 o 의 기록에서
        // 서명을 빼 m 이 뿌리가 됨 — m 은 이 기기가 이미 믿던 기기).
        let (o, t, m, _) = keys();
        let s = Store::memory().unwrap();
        run(
            &s,
            &t,
            &dir(
                vec![
                    live(&o, T0, vec![]),
                    live(&m, T1, vec![cert(&o, &m)]),
                    live(&t, T2, vec![cert(&m, &t)]),
                ],
                vec![],
            ),
        );
        let trusted_root = dir(
            vec![live(&m, T1, vec![]), live(&t, T2, vec![cert(&m, &t)])],
            vec![gone(&o, T0, &o)],
        );
        assert_eq!(run(&s, &t, &trusted_root), (trusted_root.clone(), None));
        assert_eq!(s.own_gate().unwrap().unwrap().root, id(&m));
    }

    /// 쥔 동안에도 내 항목의 다른 칸(메일 확인 끊기 상태 등)은 새 프레임 그대로 흐른다.
    #[test]
    fn 쥔_동안_내_항목의_다른_칸은_그대로() {
        let s = Store::memory().unwrap();
        let (o, t, fake, _) = keys();
        run(
            &s,
            &t,
            &dir(
                vec![live(&o, T1, vec![]), live(&t, T2, vec![cert(&o, &t)])],
                vec![],
            ),
        );
        let mut forged = dir(
            vec![
                live(&fake, T0, vec![]),
                live(&o, T1, vec![cert(&fake, &o)]),
                live(&t, T2, vec![cert(&o, &t)]),
            ],
            vec![gone(&fake, T0, &fake)],
        );
        forged["people"][1]["recovery"] = json!({"state": "scheduled", "requester": "x"});
        let (f, c) = run(&s, &t, &forged);
        assert!(matches!(c, Some(Changed::Held(_))));
        assert_eq!(f["people"][1]["recovery"]["state"], "scheduled");
        assert_eq!(
            f["people"][1]["revocations"],
            json!([]),
            "받아들인 폐기 기록(없음)"
        );
        assert_eq!(mine(&f), vec![id(&o), id(&t)]);
    }
}
