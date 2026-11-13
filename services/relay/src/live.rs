//! #882 실시간 현황(ADR 0014). 맥이 보낸 숫자(`own_live`)를 사용자마다 합해 내 휴대폰에 Live Activity·FCM 데이터 푸시를 낸다.
//!
//! - **메모리에만 둔다** — 저장·감사 없음, 값·토큰은 tracing 에도 남기지 않는다.
//! - 받는 휴대폰(`push.live on`)이 하나도 없으면 맥에 `own_live.want{on:false}` 를 알려 보내지 않게 한다.
//! - 우선순위: 기다림이 늘 때·끝남·맥 끊김만 높음(기기마다 분당 [`HIGH_PER_MIN`] — 넘으면 보통 길). 보통은 기기마다
//!   [`WINDOW_MS`] 창 끝에 마지막 값 하나.
//! - relay 가 다시 뜨면 메모리가 비어 맥의 첫 `own_live` 까지 아무것도 보내지 않는다(틀린 0 으로 끝내지 않기).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::push::{LiveEvent, LivePush, Push};
use crate::rules::Authed;

/// 기기마다 보통 갱신 창.
pub const WINDOW_MS: i64 = 5_000;
/// 기기마다 분당 높음(우선순위 10) 상한.
pub const HIGH_PER_MIN: usize = 6;
/// 맥 연결마다 own_live 간격 하한(초당 1).
pub const FRAME_GAP_MS: i64 = 1_000;
/// 맥이 다 끊긴 채 이만큼이면 활동을 끝남 꼴 없이 끝낸다.
pub const MAC_GONE_END_MS: i64 = 30 * 60_000;
/// end 뒤 끝남 꼴을 두는 시간.
pub const DONE_DISMISS_MS: i64 = 15 * 60_000;
/// iOS 활동 상한(8시간) 전에 이어 띄우는 때.
pub const RESTART_AFTER_MS: i64 = 7 * 3_600_000 + 50 * 60_000;
/// 활동 토큰 없이 start 를 보낸 뒤 다시 start 를 허용하기까지(그 사이 토큰이 안 오면 앱을 못 깨운 것).
pub const START_RETRY_MS: i64 = 5 * 60_000;

/// 맥 하나가 보낸 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vals {
    pub busy: u32,
    pub approval: u32,
    pub question: u32,
    pub oldest_ms: Option<i64>,
}

/// 사용자 합(휴대폰에 보내는 꼴).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Agg {
    pub busy: u32,
    pub approval: u32,
    pub question: u32,
    pub oldest_ms: Option<i64>,
    /// 이번 묶음 시작(합이 0 → 0 아님이 된 때).
    pub run_ms: i64,
    pub mac: bool,
    /// 맥이 다 끊긴 때(경과를 거기서 멈춰 보임).
    pub frozen_ms: Option<i64>,
}

impl Agg {
    fn zero(&self) -> bool {
        self.busy == 0 && self.approval == 0 && self.question == 0
    }
    fn waits(&self) -> u32 {
        self.approval.saturating_add(self.question)
    }
}

#[derive(Default)]
struct UserLive {
    /// 붙어 있는 맥마다 마지막 값(끊기면 뺀다).
    macs: HashMap<String, Vals>,
    /// 마지막으로 보낸 합.
    sent: Option<Agg>,
}

#[derive(Default)]
struct Slot {
    last_ms: Option<i64>,
    pending: Option<Agg>,
    armed: bool,
}

#[derive(Default)]
struct Inner {
    users: HashMap<String, UserLive>,
    /// 기기마다 보통 창.
    slots: HashMap<String, Slot>,
    /// 기기마다 최근 높음 보낸 시각.
    high: HashMap<String, VecDeque<i64>>,
    /// 맥 기기마다 마지막으로 받은 own_live 시각.
    frames: HashMap<String, i64>,
    /// 사용자마다 마지막으로 알린 want.
    want: HashMap<String, bool>,
}

#[derive(Default)]
pub struct Live(Mutex<Inner>);

impl Live {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 현황을 받는 그 사용자의 기기 — 승인된(잎 자격 있는) 기기만(#882 리뷰: 이메일 코드만으로 붙은 승인 전 기기가 숫자를 받지 않게).
fn targets(app: &crate::Relay, user: &str) -> Vec<crate::db::LiveTarget> {
    let mut t = app.db.live_targets(user).unwrap_or_default();
    if t.is_empty() {
        return t;
    }
    let eligible = crate::mls::eligible_devices(app, user);
    t.retain(|x| eligible.contains(&x.device_id));
    t
}

/// 그 사용자에게 현황을 받는 휴대폰이 있나.
fn wanted(app: &crate::Relay, user: &str) -> bool {
    app.push.get().is_some() && !targets(app, user).is_empty()
}

/// S→C `own_live.want{on}`.
fn want_frame(on: bool) -> Option<crate::frames::ServerFrame> {
    serde_json::from_value::<lodelai_protocol::ws::OwnLiveWant>(
        serde_json::json!({"t": "own_live.want", "on": on}),
    )
    .ok()
    .map(|f| crate::frames::ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::OwnLiveWant(f))))
}

/// 접속(ready 뒤) 때 hello.own 맥 연결에 보낼 `own_live.want`. 푸시 자격이 없으면 없음.
pub fn want_on_connect(app: &crate::Relay, user: &str) -> Option<crate::frames::ServerFrame> {
    app.push.get()?;
    let on = wanted(app, user);
    app.live.lock().want.insert(user.to_owned(), on);
    want_frame(on)
}

/// want 가 바뀌었으면 그 사용자의 hello.own 연결 모두에 알린다. off 면 그 사용자 값을 지운다.
fn refresh_want(app: &crate::Relay, user: &str) {
    let on = wanted(app, user);
    let changed = {
        let mut g = app.live.lock();
        let was = g.want.insert(user.to_owned(), on);
        if !on {
            g.users.remove(user);
        }
        was != Some(on)
    };
    if changed {
        if let Some(f) = want_frame(on) {
            for d in app.conns.online_devices(user) {
                app.conns.send_device_own(user, &d, &f);
            }
        }
    }
}

/// C→S `own_live`. 받았으면(합에 넣었으면) `true`(시험용 — 프레임 답은 없다).
pub fn on_frame(app: &crate::Relay, who: &Authed, v: Vals) -> bool {
    if !who.own || app.push.get().is_none() {
        return false;
    }
    // 승인 전 기기는 숫자를 꾸밀 수 있다 — 연결 문(#888)이 이미 버리지만 여기서도 거른다.
    if !crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) {
        return false;
    }
    let now = app.effects.clock.now().0;
    {
        let mut g = app.live.lock();
        if g.frames
            .get(&who.device_id)
            .is_some_and(|t| now - *t < FRAME_GAP_MS)
        {
            return false;
        }
        g.frames.insert(who.device_id.clone(), now);
        if g.want.get(&who.user) == Some(&false) {
            return false;
        }
    }
    if !wanted(app, &who.user) {
        return false;
    }
    app.live
        .lock()
        .users
        .entry(who.user.clone())
        .or_default()
        .macs
        .insert(who.device_id.clone(), v);
    recompute(app, &who.user, now);
    true
}

/// 그 맥 기기의 마지막 연결이 끊겼다.
pub fn on_mac_gone(app: &crate::Relay, user: &str, device: &str) {
    let had = {
        let mut g = app.live.lock();
        g.frames.remove(device);
        g.users
            .get_mut(user)
            .is_some_and(|u| u.macs.remove(device).is_some())
    };
    if had {
        recompute(app, user, app.effects.clock.now().0);
    }
}

/// 합을 다시 내고, 마지막 보낸 것과 다르면 받는 기기마다 보낸다.
fn recompute(app: &crate::Relay, user: &str, now: i64) {
    let (agg, high) = {
        let mut g = app.live.lock();
        let Some(u) = g.users.get_mut(user) else {
            return;
        };
        let prev = u.sent;
        let agg = if u.macs.is_empty() {
            // 맥이 다 끊김: 마지막 보낸 합 그대로 + mac false. 보낸 적 없으면 할 일 없음.
            let Some(p) = prev else {
                return;
            };
            Agg {
                mac: false,
                frozen_ms: p.frozen_ms.or(Some(now)),
                ..p
            }
        } else {
            let mut a = Agg {
                mac: true,
                ..Agg::default()
            };
            for v in u.macs.values() {
                a.busy = a.busy.saturating_add(v.busy);
                a.approval = a.approval.saturating_add(v.approval);
                a.question = a.question.saturating_add(v.question);
                a.oldest_ms = match (a.oldest_ms, v.oldest_ms) {
                    (Some(x), Some(y)) => Some(x.min(y)),
                    (x, y) => x.or(y),
                };
            }
            if a.busy == 0 {
                a.oldest_ms = None;
            }
            a.run_ms = match prev {
                Some(p) if !p.zero() => p.run_ms,
                Some(p) if a.zero() => p.run_ms,
                _ => now,
            };
            a
        };
        if prev == Some(agg) {
            return;
        }
        let base = prev.unwrap_or(Agg {
            mac: true,
            ..Agg::default()
        });
        u.sent = Some(agg);
        // 처음 값이 0 이면 보낼 것이 없다.
        if prev.is_none() && agg.zero() {
            return;
        }
        let high =
            agg.waits() > base.waits() || (agg.zero() && !base.zero()) || (base.mac && !agg.mac);
        (agg, high)
    };
    for t in targets(app, user) {
        schedule(app, &t.device_id, agg, high, now);
    }
}

/// 기기 하나에: 높음이면(분당 상한 안) 바로, 아니면 5초 창.
fn schedule(app: &crate::Relay, device: &str, agg: Agg, high: bool, now: i64) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let wait = {
        let mut g = app.live.lock();
        let high_ok = high && {
            let q = g.high.entry(device.to_owned()).or_default();
            while q.front().is_some_and(|t| now - *t >= 60_000) {
                q.pop_front();
            }
            if q.len() < HIGH_PER_MIN {
                q.push_back(now);
                true
            } else {
                false
            }
        };
        let slot = g.slots.entry(device.to_owned()).or_default();
        let open = !slot.armed && slot.last_ms.is_none_or(|t| now - t >= WINDOW_MS);
        if high_ok || open {
            slot.last_ms = Some(now);
            slot.pending = None;
            None
        } else {
            slot.pending = Some(agg);
            if slot.armed {
                return;
            }
            slot.armed = true;
            Some(
                slot.last_ms
                    .map_or(WINDOW_MS, |t| (t + WINDOW_MS - now).clamp(0, WINDOW_MS)),
            )
        }
    };
    let Some(wait) = wait else {
        fire(app, device, agg, high, now);
        return;
    };
    let Some(weak) = app.push.get().and_then(|o| o.relay_weak()) else {
        return;
    };
    let device = device.to_owned();
    rt.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(
            u64::try_from(wait).unwrap_or(0),
        ))
        .await;
        let Some(app) = weak.upgrade() else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || {
            let now = app.effects.clock.now().0;
            let job = {
                let mut g = app.live.lock();
                let Some(slot) = g.slots.get_mut(&device) else {
                    return;
                };
                slot.armed = false;
                slot.last_ms = Some(now);
                slot.pending.take()
            };
            if let Some(agg) = job {
                fire(&app, &device, agg, false, now);
            }
        })
        .await;
    });
}

/// 그 기기 행을 보고 실제 푸시 하나(iOS 는 활동 토큰·start 토큰에 따라 update·end·start).
fn fire(app: &crate::Relay, device: &str, agg: Agg, high: bool, now: i64) {
    let Ok(Some(user)) = app.db.device(device).map(|d| d.map(|(u, _)| u)) else {
        return;
    };
    let Some(t) = targets(app, &user)
        .into_iter()
        .find(|t| t.device_id == device)
    else {
        return;
    };
    if t.platform != "apns" {
        send(
            app,
            &t,
            t.token.clone(),
            LiveEvent::Update,
            agg,
            high,
            None,
            now,
        );
        return;
    }
    if let Some(tok) = t.activity_token.clone() {
        if agg.zero() {
            send(
                app,
                &t,
                tok,
                LiveEvent::End,
                agg,
                high,
                Some(now + DONE_DISMISS_MS),
                now,
            );
            let _ = app.db.live_mark(device, true, None);
        } else {
            send(app, &t, tok, LiveEvent::Update, agg, high, None, now);
        }
        return;
    }
    start_if_allowed(app, &t, agg, high, now);
}

/// 활동 토큰이 없을 때: start 토큰이 있고 합이 0 이 아니고, 앞서 보낸 start 의 토큰을 기다리는 중이 아니면 push-to-start.
fn start_if_allowed(app: &crate::Relay, t: &crate::db::LiveTarget, agg: Agg, high: bool, now: i64) {
    let Some(start) = t.start_token.clone() else {
        return;
    };
    if agg.zero() || t.start_sent_ms.is_some_and(|s| now - s < START_RETRY_MS) {
        return;
    }
    send(app, t, start, LiveEvent::Start, agg, high, None, now);
    let _ = app.db.live_mark(&t.device_id, false, Some(now));
}

#[allow(clippy::too_many_arguments)]
fn send(
    app: &crate::Relay,
    t: &crate::db::LiveTarget,
    token: String,
    event: LiveEvent,
    state: Agg,
    high: bool,
    dismissal_ms: Option<i64>,
    now: i64,
) {
    let Some(out) = app.push.get().cloned() else {
        return;
    };
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let (platform, env) = crate::push::platform_env(&t.platform, &t.env);
    let push = Push {
        token,
        live: Some(LivePush {
            event,
            high,
            state,
            now_ms: now,
            dismissal_ms,
        }),
        ..Push::default()
    };
    out.send_direct(&rt, &t.device_id, platform, env, push, now);
}

/// C→S `push.live`. 답 프레임.
pub fn on_push_live(
    app: &crate::Relay,
    who: &Authed,
    req: String,
    on: bool,
    start_token: Option<String>,
    activity: Option<(String, i64)>,
) -> crate::frames::ServerFrame {
    // 승인 전 기기는 현황을 받지 못한다 — 연결 문(#888)이 이미 거절하지만 여기서도.
    if !crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) {
        return crate::frames::ServerFrame::Error {
            code: crate::frames::ErrorCode::DeviceUnconfirmed,
            message: "not approved".into(),
            r#ref: Some(req),
        };
    }
    let set = app.db.push_live_set(
        &who.device_id,
        on,
        start_token.as_deref(),
        activity.as_ref().map(|(t, ms)| (t.as_str(), *ms)),
    );
    let was = match set {
        Ok(Some(was)) => was,
        Ok(None) => {
            return crate::frames::ServerFrame::Error {
                code: crate::frames::ErrorCode::Protocol,
                message: "push.live".into(),
                r#ref: Some(req),
            }
        }
        Err(_) => return crate::rules::internal_error(),
    };
    refresh_want(app, &who.user);
    // 일하는 중에 켠 기기는 다음 변화까지 기다리지 않고 지금 합을 한 번 받는다.
    if on && !was {
        let sent = app.live.lock().users.get(&who.user).and_then(|u| u.sent);
        if let Some(agg) = sent.filter(|a| !a.zero()) {
            schedule(app, &who.device_id, agg, false, app.effects.clock.now().0);
        }
    }
    let ok = serde_json::from_value::<lodelai_protocol::ws::PushLiveOk>(
        serde_json::json!({"t": "push.live.ok", "req": req}),
    );
    match ok {
        Ok(f) => {
            crate::frames::ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::PushLiveOk(f)))
        }
        Err(_) => crate::rules::internal_error(),
    }
}

/// 만료 tick: 맥이 다 끊긴 채 30분이면 활동을 끝남 꼴 없이 끝내고 그 사용자 값을 지운다. 활동이 7시간 50분이면 이어 띄운다.
pub fn tick(app: &crate::Relay) {
    if app.push.get().is_none() {
        return;
    }
    let now = app.effects.clock.now().0;
    let users: Vec<(String, Agg)> = app
        .live
        .lock()
        .users
        .iter()
        .filter_map(|(u, l)| l.sent.map(|a| (u.clone(), a)))
        .collect();
    for (user, agg) in users {
        let targets = targets(app, &user);
        if !agg.mac && agg.frozen_ms.is_some_and(|f| now - f >= MAC_GONE_END_MS) {
            for t in targets.iter().filter(|t| t.platform == "apns") {
                if let Some(tok) = t.activity_token.clone() {
                    send(app, t, tok, LiveEvent::End, agg, false, Some(now), now);
                    let _ = app.db.live_mark(&t.device_id, true, None);
                }
            }
            app.live.lock().users.remove(&user);
            continue;
        }
        if agg.zero() {
            continue;
        }
        for t in targets.iter().filter(|t| t.platform == "apns") {
            let (Some(tok), Some(started)) = (t.activity_token.clone(), t.activity_ms) else {
                continue;
            };
            if now - started < RESTART_AFTER_MS || t.start_token.is_none() {
                continue;
            }
            send(app, t, tok, LiveEvent::End, agg, false, Some(now), now);
            let _ = app.db.live_mark(&t.device_id, true, None);
            let fresh = crate::db::LiveTarget {
                activity_token: None,
                activity_ms: None,
                start_sent_ms: None,
                ..t.clone()
            };
            start_if_allowed(app, &fresh, agg, false, now);
        }
    }
}
