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
/// #1104 휴대폰에 보내는 에이전트 줄 상한(자르는 곳은 relay 한 곳).
pub const LIVE_ITEMS_MAX: usize = 3;
/// #1104 맥 하나가 싣는 줄 상한(선 계약 `maxItems`).
pub const MAC_ITEMS_MAX: usize = 6;

/// #1104 줄 상태 — 이 순서로 줄을 잇는다. #1749 `Trust`·`Start` = 폴더 신뢰·첫 실행 물음에 멈춤(맥에서만 답함).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemSt {
    Approval,
    Question,
    Trust,
    Start,
    Busy,
}

impl ItemSt {
    pub const ORDER: [Self; 5] = [
        Self::Approval,
        Self::Question,
        Self::Trust,
        Self::Start,
        Self::Busy,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Question => "question",
            Self::Trust => "trust",
            Self::Start => "start",
            Self::Busy => "busy",
        }
    }

    /// #1749 `push.live.waits` 없는 기기에 보내는 꼴 — 맥에서만 답하는 두 기다림은 승인 줄로.
    #[must_use]
    pub fn folded(self) -> Self {
        match self {
            Self::Trust | Self::Start => Self::Approval,
            s => s,
        }
    }
}

/// #1104 에이전트 한 줄 — 뜻 없는 8 hex id(맥의 own_state conv)와 상태, 처리 중이면 턴 시작.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub id: u32,
    pub st: ItemSt,
    pub since_ms: Option<i64>,
}

impl Item {
    #[must_use]
    pub fn id_hex(&self) -> String {
        format!("{:08x}", self.id)
    }
}

/// 맥 하나가 보낸 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vals {
    pub busy: u32,
    /// #1749 `trust`·`start` 는 빼고 센 승인 기다림(옛 맥은 둘을 여기 더해 보낸다 — 그때 두 칸은 0).
    pub approval: u32,
    pub question: u32,
    /// #1749 폴더 신뢰 물음에 멈춘 수.
    pub trust: u32,
    /// #1749 첫 실행 물음에 멈춘 수.
    pub start: u32,
    pub oldest_ms: Option<i64>,
    /// #1104 에이전트 줄(맥이 보낸 순서, 기능 표시를 모르는 맥이면 비어 있음).
    pub items: [Option<Item>; MAC_ITEMS_MAX],
}

impl Vals {
    /// 줄의 상태별 수가 그 수를 넘지 않나(어긋나면 프레임을 버린다).
    #[must_use]
    pub fn items_fit(&self) -> bool {
        let n = |st| self.items.iter().flatten().filter(|i| i.st == st).count();
        let le = |c: usize, v: u32| u32::try_from(c).is_ok_and(|c| c <= v);
        le(n(ItemSt::Approval), self.approval)
            && le(n(ItemSt::Question), self.question)
            && le(n(ItemSt::Trust), self.trust)
            && le(n(ItemSt::Start), self.start)
            && le(n(ItemSt::Busy), self.busy)
    }
}

/// 사용자 합(휴대폰에 보내는 꼴).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Agg {
    pub busy: u32,
    pub approval: u32,
    pub question: u32,
    /// #1749 폴더 신뢰 물음에 멈춘 수.
    pub trust: u32,
    /// #1749 첫 실행 물음에 멈춘 수.
    pub start: u32,
    pub oldest_ms: Option<i64>,
    /// 이번 묶음 시작(합이 0 → 0 아님이 된 때).
    pub run_ms: i64,
    pub mac: bool,
    /// 맥이 다 끊긴 때(경과를 거기서 멈춰 보임).
    pub frozen_ms: Option<i64>,
    /// #1104 앞 [`LIVE_ITEMS_MAX`] 줄(상태 순 → 맥 device_id 순 → 맥이 보낸 순).
    pub items: [Option<Item>; LIVE_ITEMS_MAX],
    /// #1749 `push.live.waits` 없는 기기에 보낼 앞 줄 — 맥마다 줄을 접은 **뒤에** 차례를 매기고 자른 것(접은 꼴 = #1749 전 꼴).
    pub items_folded: [Option<Item>; LIVE_ITEMS_MAX],
}

impl Agg {
    fn zero(&self) -> bool {
        self.busy == 0 && self.waits() == 0
    }
    /// 나를 기다리는 수 = 승인 + 질문 + 폴더 신뢰 + 시작 확인.
    fn waits(&self) -> u32 {
        self.approval
            .saturating_add(self.question)
            .saturating_add(self.trust)
            .saturating_add(self.start)
    }
    /// 보내는 줄 수.
    #[must_use]
    pub fn shown(&self) -> u32 {
        u32::try_from(self.items.iter().flatten().count()).unwrap_or(0)
    }
    /// #1104 가려진 줄 수 = 세 수의 합 − 보낸 줄 수.
    #[must_use]
    pub fn more(&self) -> u32 {
        self.busy
            .saturating_add(self.waits())
            .saturating_sub(self.shown())
    }
    /// #1104 가려진 것 중 기다림이 있나 = 기다림 수(승인·질문·폴더 신뢰·시작 확인) > 보낸 기다림 줄 수.
    #[must_use]
    pub fn more_waiting(&self) -> bool {
        let shown_waits = self
            .items
            .iter()
            .flatten()
            .filter(|i| i.st != ItemSt::Busy)
            .count();
        u32::try_from(shown_waits).is_ok_and(|n| self.waits() > n)
    }
    /// 줄을 청하지 않은 기기에 보내는 꼴.
    fn without_items(self) -> Self {
        Self {
            items: [None; LIVE_ITEMS_MAX],
            items_folded: [None; LIVE_ITEMS_MAX],
            ..self
        }
    }
    /// #1749 `push.live.waits` 없는 기기에 보내는 꼴: 두 수는 승인에 더하고 줄은 접어 매긴 앞 줄. 같은 에이전트 상태에서 #1749 전
    /// relay 가 내던 것과 같다(합·가려진 수·기다림 판정 모두 그대로).
    #[must_use]
    pub fn folded(self) -> Self {
        Self {
            approval: self
                .approval
                .saturating_add(self.trust)
                .saturating_add(self.start),
            trust: 0,
            start: 0,
            items: self.items_folded,
            ..self
        }
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
    /// 사용자마다 마지막으로 알린 want(on, items).
    want: HashMap<String, (bool, bool)>,
    /// 이 relay 가 켜진 뒤 토큰 없이 start 를 보낸 기기(#1103). DB 표시만 있고 여기 없으면 재시작 전 판의 것 — relay 가 다시
    /// 켜지면 그 판이 끝났는지 모르므로(합 0 을 못 봄) 막지 않는다. 막으면 배포 직후 첫 카드가 조용히 안 떴다(백엔드 리뷰 #1130).
    started: std::collections::HashSet<String>,
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
    want_of(app, user).0
}

/// (현황을 받는 휴대폰이 있나, 그중 줄을 그리는 휴대폰이 있나 — #1104).
fn want_of(app: &crate::Relay, user: &str) -> (bool, bool) {
    if app.push.get().is_none() {
        return (false, false);
    }
    let t = targets(app, user);
    (!t.is_empty(), t.iter().any(|x| x.items))
}

/// S→C `own_live.want{on, items}`.
fn want_frame((on, items): (bool, bool)) -> Option<crate::frames::ServerFrame> {
    serde_json::from_value::<lodelai_protocol::ws::OwnLiveWant>(
        serde_json::json!({"t": "own_live.want", "on": on, "items": on && items}),
    )
    .ok()
    .map(|f| crate::frames::ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::OwnLiveWant(f))))
}

/// 접속(ready 뒤) 때 hello.own 맥 연결에 보낼 `own_live.want`. 푸시 자격이 없으면 없음.
pub fn want_on_connect(app: &crate::Relay, user: &str) -> Option<crate::frames::ServerFrame> {
    app.push.get()?;
    let w = want_of(app, user);
    app.live.lock().want.insert(user.to_owned(), w);
    want_frame(w)
}

/// want 가 바뀌었으면 그 사용자의 hello.own 연결 모두에 알린다. off 면 그 사용자 값을 지운다.
fn refresh_want(app: &crate::Relay, user: &str) {
    let w = want_of(app, user);
    let changed = {
        let mut g = app.live.lock();
        let was = g.want.insert(user.to_owned(), w);
        if !w.0 {
            g.users.remove(user);
        }
        was != Some(w)
    };
    if changed {
        if let Some(f) = want_frame(w) {
            for d in app.conns.online_devices(user) {
                app.conns.send_device_own(user, &d, &f);
            }
        }
    }
}

/// C→S `own_live`. 받았으면(합에 넣었으면) `true`(시험용 — 프레임 답은 없다).
pub fn on_frame(app: &crate::Relay, who: &Authed, v: Vals) -> bool {
    if !who.own || app.push.get().is_none() || !v.items_fit() {
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
        if g.want.get(&who.user).is_some_and(|w| !w.0) {
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
                a.trust = a.trust.saturating_add(v.trust);
                a.start = a.start.saturating_add(v.start);
                a.oldest_ms = match (a.oldest_ms, v.oldest_ms) {
                    (Some(x), Some(y)) => Some(x.min(y)),
                    (x, y) => x.or(y),
                };
            }
            if a.busy == 0 {
                a.oldest_ms = None;
            }
            a.items = merge_items(&u.macs, false);
            a.items_folded = merge_items(&u.macs, true);
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

/// #1104 맥마다의 줄을 상태 순(approval → question → trust → start → busy) → 맥 device_id 순 → 맥이 보낸 순으로 이어 앞
/// [`LIVE_ITEMS_MAX`] 만. #1749 `fold` 면 줄 상태를 먼저 접고([`ItemSt::folded`]) 나서 매긴다.
fn merge_items(macs: &HashMap<String, Vals>, fold: bool) -> [Option<Item>; LIVE_ITEMS_MAX] {
    let mut sorted: Vec<(&String, &Vals)> = macs.iter().collect();
    sorted.sort_by(|x, y| x.0.cmp(y.0));
    let st_of = |i: &Item| if fold { i.st.folded() } else { i.st };
    let mut out = [None; LIVE_ITEMS_MAX];
    let mut rows = ItemSt::ORDER.into_iter().flat_map(|st| {
        sorted.iter().flat_map(move |(_, v)| {
            v.items
                .iter()
                .flatten()
                .filter(move |i| st_of(i) == st)
                .map(move |i| Item { st, ..*i })
        })
    });
    for slot in &mut out {
        *slot = rows.next();
    }
    out
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
    // 토큰 없이 띄운 활동의 판이 끝남(합 0) — 다음 판엔 다시 start 할 수 있게.
    if agg.zero() && t.start_sent_ms.is_some() {
        let _ = app.db.live_start_clear(device);
        app.live.lock().started.remove(device);
    }
    start_if_allowed(app, &t, agg, high, now);
}

/// 활동 토큰이 없을 때: start 토큰이 있고 합이 0 이 아니고, 이 판에 아직 start 를 보내지 않았으면 push-to-start.
/// 한 판(합이 0 이 아닌 동안)에 한 번만 — 앱이 꺼져 있으면 relay 가 띄운 활동의 갱신 토큰이 안 와 시간으로 다시 보내면 잠금 화면에
/// 같은 카드가 쌓인다(#1103). 토큰이 오면(push.live) 또는 판이 끝나면(합 0·맥 끊김 끝) 표시가 지워진다.
fn start_if_allowed(app: &crate::Relay, t: &crate::db::LiveTarget, agg: Agg, high: bool, now: i64) {
    let Some(start) = t.start_token.clone() else {
        return;
    };
    if agg.zero() || start_blocked(app, t, now) {
        return;
    }
    send(app, t, start, LiveEvent::Start, agg, high, None, now);
    let _ = app.db.live_mark(&t.device_id, false, Some(now));
    app.live.lock().started.insert(t.device_id.clone());
}

/// 이 판에 이미 start 를 보냈나 — 이 relay 가 보낸 것이고, iOS 활동 상한(8시간) 전 이어 띄우는 때(RESTART_AFTER_MS)가 아직이면.
/// 그보다 오래된 표시는 시스템이 활동을 끝냈을 때라 다시 띄운다(안 그러면 긴 판 뒤 카드가 끝까지 안 뜸).
fn start_blocked(app: &crate::Relay, t: &crate::db::LiveTarget, now: i64) -> bool {
    t.start_sent_ms.is_some_and(|s| now - s < RESTART_AFTER_MS)
        && app.live.lock().started.contains(&t.device_id)
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
    // #1749 start·trust 를 그리지 못하는 기기엔 승인으로 접어 보낸다(옛 휴대폰 — 모르는 st 를 처리 중으로 그리거나 줄을 버림).
    let state = if t.waits { state } else { state.folded() };
    // #1104 줄을 청하지 않은 기기엔 싣지 않는다.
    let state = if t.items {
        state
    } else {
        state.without_items()
    };
    let push = Push {
        token,
        // #1567 한 토큰에 계정이 여럿인 휴대폰이 어느 계정 현황인지(FCM data `a` 만 — APNs 활동 토큰은 활동마다 따로).
        account: Some(crate::push::account_tag(&t.salt)),
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
#[allow(clippy::too_many_arguments)]
pub fn on_push_live(
    app: &crate::Relay,
    who: &Authed,
    req: String,
    on: bool,
    start_token: Option<String>,
    activity: Option<(String, i64)>,
    items: bool,
    waits: bool,
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
        items,
        waits,
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
                if t.start_sent_ms.is_some() {
                    let _ = app.db.live_start_clear(&t.device_id);
                }
                app.live.lock().started.remove(&t.device_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn it(id: u32, st: ItemSt) -> Option<Item> {
        Some(Item {
            id,
            st,
            since_ms: None,
        })
    }

    fn vals(items: &[Option<Item>]) -> Vals {
        let mut v = Vals {
            busy: 9,
            approval: 9,
            question: 9,
            trust: 9,
            start: 9,
            oldest_ms: None,
            items: [None; MAC_ITEMS_MAX],
        };
        v.items[..items.len()].copy_from_slice(items);
        v
    }

    /// #1104 맥 둘: 상태 순 → 맥 device_id 순 → 보낸 순, 앞 3 줄.
    #[test]
    fn merge_items_orders_by_state_then_mac_then_sent() {
        let mut m = HashMap::new();
        m.insert(
            "mac-b".to_owned(),
            vals(&[it(1, ItemSt::Busy), it(2, ItemSt::Question)]),
        );
        m.insert(
            "mac-a".to_owned(),
            vals(&[
                it(3, ItemSt::Busy),
                it(4, ItemSt::Question),
                it(5, ItemSt::Busy),
            ]),
        );
        let got: Vec<u32> = merge_items(&m, false)
            .iter()
            .flatten()
            .map(|i| i.id)
            .collect();
        assert_eq!(got, vec![4, 2, 3]);
        m.insert("mac-c".to_owned(), vals(&[it(6, ItemSt::Approval)]));
        let got: Vec<u32> = merge_items(&m, false)
            .iter()
            .flatten()
            .map(|i| i.id)
            .collect();
        assert_eq!(got, vec![6, 4, 2]);
        assert!(merge_items(&HashMap::new(), false)
            .iter()
            .all(Option::is_none));
    }

    /// #1749 다섯 상태 차례: approval → question → trust → start → busy. 접으면 둘이 approval 이 되어 질문보다 앞 —
    /// 맥마다 접고 나서 매긴 것과 같다(접은 꼴 = #1749 전 꼴).
    #[test]
    fn merge_items_orders_five_states_and_folds_before_ordering() {
        let mut m = HashMap::new();
        m.insert(
            "mac-a".to_owned(),
            vals(&[
                it(1, ItemSt::Question),
                it(2, ItemSt::Start),
                it(3, ItemSt::Busy),
            ]),
        );
        m.insert(
            "mac-b".to_owned(),
            vals(&[it(4, ItemSt::Question), it(5, ItemSt::Trust)]),
        );
        let row = |i: &Option<Item>| i.map(|i| (i.id, i.st));
        let got: Vec<_> = merge_items(&m, false).iter().map(row).collect();
        assert_eq!(
            got,
            vec![
                Some((1, ItemSt::Question)),
                Some((4, ItemSt::Question)),
                Some((5, ItemSt::Trust))
            ]
        );
        let folded: Vec<_> = merge_items(&m, true).iter().map(row).collect();
        assert_eq!(
            folded,
            vec![
                Some((2, ItemSt::Approval)),
                Some((5, ItemSt::Approval)),
                Some((1, ItemSt::Question))
            ]
        );
        // 옛 맥이 접어 보냈을 때의 합과 같다.
        let mut old = HashMap::new();
        old.insert(
            "mac-a".to_owned(),
            vals(&[
                it(2, ItemSt::Approval),
                it(1, ItemSt::Question),
                it(3, ItemSt::Busy),
            ]),
        );
        old.insert(
            "mac-b".to_owned(),
            vals(&[it(5, ItemSt::Approval), it(4, ItemSt::Question)]),
        );
        assert_eq!(merge_items(&old, false), merge_items(&m, true));
    }

    /// #1749 접은 합: 두 수는 승인에 더하고, 가려진 수·기다림 판정은 접기 전과 같다.
    #[test]
    fn folded_agg_adds_waits_to_approval() {
        let a = Agg {
            busy: 2,
            approval: 1,
            question: 1,
            trust: 1,
            start: 2,
            items: [
                it(1, ItemSt::Approval),
                it(2, ItemSt::Question),
                it(3, ItemSt::Trust),
            ],
            items_folded: [
                it(1, ItemSt::Approval),
                it(3, ItemSt::Approval),
                it(4, ItemSt::Approval),
            ],
            ..Agg::default()
        };
        let f = a.folded();
        assert_eq!((f.approval, f.question, f.trust, f.start), (4, 1, 0, 0));
        assert!(f.items.iter().flatten().all(|i| i.st == ItemSt::Approval));
        assert_eq!((a.waits(), a.more(), a.more_waiting()), (5, 4, true));
        assert_eq!((f.waits(), f.more(), f.more_waiting()), (5, 4, true));
        assert!(!a.zero());
        let only_start = Agg {
            start: 1,
            ..Agg::default()
        };
        assert!(!only_start.zero() && !only_start.folded().zero());
        let mut v = vals(&[it(1, ItemSt::Start), it(2, ItemSt::Start)]);
        v.start = 1;
        assert!(!v.items_fit());
        v.start = 2;
        assert!(v.items_fit());
    }

    /// #1104 more = 합 − 보낸 줄, moreWaiting = 기다림 수 > 보낸 기다림 줄.
    #[test]
    fn more_counts_hidden_rows() {
        let a = Agg {
            busy: 3,
            approval: 1,
            question: 1,
            items: [
                it(1, ItemSt::Approval),
                it(2, ItemSt::Question),
                it(3, ItemSt::Busy),
            ],
            ..Agg::default()
        };
        assert_eq!((a.more(), a.more_waiting()), (2, false));
        let b = Agg { approval: 2, ..a };
        assert_eq!((b.more(), b.more_waiting()), (3, true));
        assert!(vals(&[it(1, ItemSt::Approval)]).items_fit());
        let mut v = vals(&[it(1, ItemSt::Approval)]);
        v.approval = 0;
        assert!(!v.items_fit());
    }
}
