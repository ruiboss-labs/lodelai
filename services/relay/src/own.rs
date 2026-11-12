//! 내 기기끼리(#870 휴대폰 '내 에이전트'). 저장되는 드문 글(kind `own_*`)은 [`crate::rules::route`]·[`crate::mls`] 가 보고,
//! 여기는 저장하지 않는 두 프레임이다.
//! - `own_stream`: 내 기기 하나에 흘림. 같은 사용자의 폐기 안 된 기기가 지금 hello.own 으로 붙어 있으면 그 연결에만
//!   넘기고, 아니면 버린다. 저장·ack·푸시·오류가 없다. 속(`data`)은 relay 가 모르는 암호문이다.
//! - `own_alert`: 내 맥에 사람 손을 기다리는 카드가 생김(`kind` usage 면 사용량 한도 가까움, #890). 붙지 않은 내 다른 기기에
//!   종류별 고정 문구 푸시(기기마다 종류별 1분에 1번).
//!
//! 어긋나면 모두 조용히 버린다 — 오류를 내면 그 기기가 있는지·붙어 있는지 드러난다.

use std::collections::HashMap;
use std::sync::Mutex;

use lodelai_protocol::constants as c;

use crate::frames::ServerFrame;
use crate::rules::Authed;

/// 보낸 기기 → 받는 기기 짝마다 초당 프레임 수 상한(바이트 상한과 따로 — 작은 프레임을 쏟는 것을 막는다). 화면 4fps 에 상태·청함이
/// 섞여도 넉넉한 값.
pub const STREAM_FRAMES_PER_S: u32 = 32;

/// own_alert 푸시 간격(기기마다).
pub const ALERT_GAP_MS: i64 = 60_000;

/// 표가 이만큼 넘으면 지난 창의 칸을 지운다.
const PRUNE_AT: usize = 4_096;

/// 짝마다 1초 창의 (창 시작 ms, 바이트, 프레임 수).
type Window = (i64, u64, u32);

/// (보낸 기기, 받는 기기) → 창.
#[derive(Default)]
pub struct StreamGate(Mutex<HashMap<(String, String), Window>>);

impl StreamGate {
    /// 이 프레임을 넘겨도 되나 — 되면 센다.
    pub fn allow(&self, from: &str, to: &str, bytes: u64, now_ms: i64) -> bool {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if m.len() >= PRUNE_AT {
            m.retain(|_, (start, _, _)| now_ms - *start < 1_000);
        }
        let e = m
            .entry((from.to_owned(), to.to_owned()))
            .or_insert((now_ms, 0, 0));
        if now_ms - e.0 >= 1_000 {
            *e = (now_ms, 0, 0);
        }
        if e.1 + bytes > c::OWN_STREAM_BYTES_PER_S || e.2 >= STREAM_FRAMES_PER_S {
            return false;
        }
        e.1 += bytes;
        e.2 += 1;
        true
    }
}

/// 기기마다 마지막 kind 푸시 시각(own_alert·초대 따로 하나씩).
#[derive(Default)]
pub struct AlertGate(Mutex<HashMap<String, i64>>);

impl AlertGate {
    pub(crate) fn take(&self, device: &str, now_ms: i64) -> bool {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if m.len() >= PRUNE_AT {
            m.retain(|_, t| now_ms - *t < ALERT_GAP_MS);
        }
        match m.get(device) {
            Some(t) if now_ms - *t < ALERT_GAP_MS => false,
            _ => {
                m.insert(device.to_owned(), now_ms);
                true
            }
        }
    }
}

/// base64url(무패딩) 글자 수 → 디코드 바이트 수.
fn decoded_len(b64: &str) -> u64 {
    (b64.len() as u64 * 3) / 4
}

/// C→S `own_stream`. 넘겼으면 `true`(시험용 — 프레임 답은 없다).
pub fn stream(
    app: &crate::Relay,
    who: &Authed,
    to_device: &str,
    epoch: u64,
    seq: u64,
    data: &str,
) -> bool {
    if !who.own || to_device == who.device_id {
        return false;
    }
    let bytes = decoded_len(data);
    if bytes == 0 || bytes > c::OWN_STREAM_MAX_BYTES {
        return false;
    }
    // 같은 사용자의 폐기 안 된 기기만(남의 기기·폐기된 기기는 모르는 기기와 같게 버림).
    match app.db.device(to_device) {
        Ok(Some((owner, _))) if owner == who.user => {}
        _ => return false,
    }
    if !app
        .own_stream_gate
        .allow(&who.device_id, to_device, bytes, app.effects.clock.now().0)
    {
        return false;
    }
    let Ok(frame) =
        serde_json::from_value::<lodelai_protocol::ws::OwnStreamNotice>(serde_json::json!({
            "t": "own_stream",
            "from_device": who.device_id,
            "epoch": epoch,
            "seq": seq,
            "data": data,
        }))
    else {
        return false;
    };
    let frame = ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::OwnStreamNotice(
        frame,
    )));
    app.conns.send_device_own(&who.user, to_device, &frame) > 0
}

/// C→S `own_alert`(`usage` = #890 사용량 한도 가까움, 아니면 카드). 푸시를 맡긴 기기(시험용).
pub fn alert(app: &crate::Relay, who: &Authed, usage: bool) -> Vec<String> {
    if !who.own || app.push.get().is_none() {
        return Vec::new();
    }
    // 승인 전 기기는 보내지도 받지도 못한다(#882 리뷰) — 이메일 코드만으로 붙은 기기가 알림을 꾸미거나 받지 않게.
    let eligible = crate::mls::eligible_devices(app, &who.user);
    if !eligible.contains(&who.device_id) {
        return Vec::new();
    }
    let now = app.effects.clock.now().0;
    let targets: Vec<String> = app
        .db
        .devices_of(&who.user)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.device_id)
        .filter(|d| *d != who.device_id && !app.conns.device_online(d))
        .filter(|d| eligible.contains(d))
        // 옛 앱(hello.own 을 실은 적 없음)은 이 kind 의 문구가 없다 — iOS 는 키 글자를 그대로 띄운다.
        .filter(|d| {
            app.db
                .devices_own(std::slice::from_ref(d))
                .is_ok_and(|s| !s.is_empty())
        })
        .filter(|d| app.db.push_token(d).ok().flatten().is_some())
        // 종류마다 따로 1분 — 카드 알림이 사용량 알림을 (또는 그 반대로) 막지 않는다.
        .filter(|d| {
            let key = if usage {
                format!("{d}#usage")
            } else {
                d.clone()
            };
            app.own_alert_gate.take(&key, now)
        })
        .collect();
    let kind = if usage {
        crate::push::PushKind::OwnUsage
    } else {
        crate::push::PushKind::OwnAlert
    };
    crate::push::on_kind(app, &targets, kind);
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_gate_caps_bytes_and_frames_per_pair() {
        let g = StreamGate::default();
        let max = c::OWN_STREAM_BYTES_PER_S;
        assert!(g.allow("a", "b", max - 10, 0));
        assert!(!g.allow("a", "b", 11, 500), "1초 안 바이트 넘침");
        assert!(g.allow("a", "c", 11, 500), "다른 짝은 따로");
        assert!(g.allow("a", "b", 11, 1_000), "다음 창");
        for i in 1..STREAM_FRAMES_PER_S {
            assert!(g.allow("x", "y", 1, 2_000 + i64::from(i)));
        }
        assert!(g.allow("x", "y", 1, 2_000));
        assert!(!g.allow("x", "y", 1, 2_100), "프레임 수 넘침");
    }

    #[test]
    fn alert_gate_once_per_minute_per_device() {
        let g = AlertGate::default();
        assert!(g.take("d1", 0));
        assert!(!g.take("d1", ALERT_GAP_MS - 1));
        assert!(g.take("d2", 1));
        assert!(g.take("d1", ALERT_GAP_MS));
    }

    #[test]
    fn decoded_len_matches_base64url_unpadded() {
        assert_eq!(decoded_len("AAAA"), 3);
        assert_eq!(decoded_len("AAA"), 2);
        assert_eq!(decoded_len("AA"), 1);
    }
}
