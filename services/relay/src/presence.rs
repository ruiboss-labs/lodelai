//! 동료 접속 표시(묶음 14 B1). 접속 여부는 메모리에만 둔다 — 마지막 접속 시각을 저장하지도 보내지도 않는다.
//! 숨기기 설정(`presence.set`)만 `users.share_presence` 에 남는다.
//!
//! 연결은 바로 알리고, 끊김은 `presence_grace`(60초) 동안 접속 중으로 보인다(잠깐 재연결로 깜박이지 않게).
//! 같은 사용자의 변화는 `presence_coalesce`(30초)에 한 번까지 합쳐 `directory.update` 로 보낸다.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::time::Instant;

use crate::{blocking, ws, App};

#[derive(Default)]
struct Entry {
    /// 마지막 연결이 끊긴 때. 다시 연결되면 `None`.
    offline_since: Option<Instant>,
    /// 이 사용자의 변화로 마지막 `directory.update` 를 보낸 때.
    last_sent: Option<Instant>,
    /// 합치기 창 안이라 뒤로 미룬 방송이 있다.
    scheduled: bool,
}

#[derive(Default)]
pub struct Presence {
    inner: Mutex<HashMap<String, Entry>>,
    /// 기기 → 마지막 연결이 끊긴 때(#569 ③). 다시 붙으면 그 연결이 끊길 때 새 값으로 바뀐다 — 타이머는 자기 값일 때만.
    devices_off: Mutex<HashMap<String, Instant>>,
}

impl Presence {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 디렉터리에 실을 접속 여부: 연결이 있거나 끊긴 지 유예 안.
    pub fn online(&self, app: &crate::Relay, user: &str) -> bool {
        app.conns.is_online(user)
            || self
                .lock()
                .get(user)
                .and_then(|e| e.offline_since)
                .is_some_and(|t| t.elapsed() < app.config.presence_grace)
    }
}

/// 연결 등록 **직전**에 부른다. 그 전에 접속 중으로 보였는지 — 아니면 등록 **뒤** [`announce`] 한다(등록 전에 방송하면
/// 그 디렉터리에 아직 꺼진 것으로 실릴 수 있다).
pub fn connecting(app: &App, user: &str) -> bool {
    let was_online = app.presence.online(app, user);
    if let Some(e) = app.presence.lock().get_mut(user) {
        e.offline_since = None;
    }
    was_online
}

/// 접속 변화를 같은 조직에 알린다(합치기 규칙은 [`request_broadcast`]).
pub fn announce(app: &App, user: &str) {
    request_broadcast(app, user);
}

/// 연결을 뺀 **뒤**에 부른다. 마지막 연결이었으면 유예 뒤에도 끊겨 있을 때만 알린다.
pub fn disconnected(app: &App, user: &str) {
    if app.conns.is_online(user) {
        return;
    }
    let since = Instant::now();
    app.presence
        .lock()
        .entry(user.to_owned())
        .or_default()
        .offline_since = Some(since);
    let (app, user) = (app.clone(), user.to_owned());
    tokio::spawn(async move {
        tokio::time::sleep(app.config.presence_grace).await;
        let still = app
            .presence
            .lock()
            .get(&user)
            .is_some_and(|e| e.offline_since == Some(since));
        if still && !app.conns.is_online(&user) {
            request_broadcast(&app, &user);
        }
    });
}

/// 연결을 뺀 **뒤**에 부른다(#569 ③). 그 기기의 마지막 연결이었으면 `session_dead_grace` 뒤에도 그 기기가 다시 붙지 않았을
/// 때만 그 기기가 공개한 세션을 dead 로 바꾸고, 바뀐 것이 있으면 같은 조직에 `directory.update`(접속 표시와 달리 합치지
/// 않는다 — 세션 상태 변화다).
pub fn device_disconnected(app: &App, user: &str, device: &str) {
    if app.conns.online_devices(user).iter().any(|d| d == device) {
        return;
    }
    let since = Instant::now();
    app.presence
        .devices_off
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(device.to_owned(), since);
    let (app, user, device) = (app.clone(), user.to_owned(), device.to_owned());
    tokio::spawn(async move {
        tokio::time::sleep(app.config.session_dead_grace).await;
        {
            let mut m = app
                .presence
                .devices_off
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if m.get(&device) != Some(&since) {
                return;
            }
            m.remove(&device);
        }
        if app.conns.online_devices(&user).contains(&device) {
            return;
        }
        let _ = blocking(&app, move |r| {
            let n = r.db.sessions_dead_for_device(&user, &device).unwrap_or(0);
            if n > 0 {
                ws::broadcast_directory_of(r, &user);
            }
        })
        .await;
    });
}

/// 그 사용자의 접속 변화를 같은 조직에 알린다. 합치기 창 안이면 창 끝으로 미루고, 이미 미뤄 둔 것이 있으면 그것에 맡긴다.
/// 보내는 디렉터리는 보낼 때 다시 계산하므로 마지막 상태가 간다.
fn request_broadcast(app: &App, user: &str) {
    if !app.config.presence_updates {
        return;
    }
    let now = Instant::now();
    let delay = {
        let mut m = app.presence.lock();
        let e = m.entry(user.to_owned()).or_default();
        if e.scheduled {
            return;
        }
        match e.last_sent {
            Some(t) if now.duration_since(t) < app.config.presence_coalesce => {
                e.scheduled = true;
                Some(app.config.presence_coalesce - now.duration_since(t))
            }
            _ => {
                e.last_sent = Some(now);
                None
            }
        }
    };
    let (app, user) = (app.clone(), user.to_owned());
    tokio::spawn(async move {
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
            if let Some(e) = app.presence.lock().get_mut(&user) {
                e.scheduled = false;
                e.last_sent = Some(Instant::now());
            }
        }
        let _ = blocking(&app, move |r| ws::broadcast_presence_of(r, &user)).await;
    });
}

// ---------------------------------------------------------------- 입력 중 표시(묶음 36 #613)

/// 입력 중 표시를 주고받는 가장 낮은 hello.v — 아래 연결엔 S→C typing 을 보내지 않는다([`ws::for_version`]).
pub const TYPING_FROM: u64 = 11;

/// 한 연결의 입력 중 상한 — `to` 마다 같은 값(on·off)은 초당 1, 값이 바뀌면 따로 초당 1(합쳐 최대 2 — 비움이 6초 남지 않게,
/// 설계 리뷰 6515374026). 남의 화면을 깜빡이게 쓰지 못하게 넘친 것은 버린다. 연결 루프가 쥔다.
#[derive(Default)]
pub struct TypingGate(HashMap<(String, bool), Instant>);

impl TypingGate {
    /// 서로 다른 `to` 를 이만큼까지만 기억한다(다른 주소를 계속 바꿔 보내 표가 자라지 않게 — 넘치면 비우고 새로).
    const KEYS_MAX: usize = 64;

    pub fn allow(&mut self, to: &str, on: bool, now: Instant) -> bool {
        let key = (to.to_owned(), on);
        if let Some(t) = self.0.get(&key) {
            if now.duration_since(*t) < std::time::Duration::from_secs(1) {
                return false;
            }
        }
        if self.0.len() >= Self::KEYS_MAX && !self.0.contains_key(&key) {
            self.0.clear();
        }
        self.0.insert(key, now);
        true
    }
}

/// C→S `typing{to, on}`(#613 계약 §1): 저장·대기열·응답 없이 받는 사람의 지금 연결된 기기에만 S→C `typing{from, group?, on}`.
/// `from` 은 인증된 이 연결의 사용자. 범위는 메시지 보내기와 같다(1:1 = 같은 조직·막지 않음, 그룹 = 내가 지금 멤버 — 받는 쪽은
/// 나를 뺀 멤버 전원). 접속 표시를 끈 사람은 보내지도 받지도 않는다(맞교환). 어긋나면 조용히 버린다(대상이 있는지 드러나지 않게).
/// 내 다른 기기·판 11 아래 연결엔 가지 않는다(받는 사람만 고르고, 판은 쓰기 직전에 거른다).
pub fn typing(app: &crate::Relay, who: &crate::rules::Authed, to: &str, on: bool) {
    let db = &app.db;
    if !db.share_presence(&who.user).unwrap_or(false) {
        return;
    }
    let Some(addr) = crate::frames::Address::parse(to) else {
        return;
    };
    if addr.server != app.config.server_name || addr.slug.is_some() {
        return;
    }
    let from_org = db.user_org(&who.user).ok().flatten();
    let (users, group) = if addr.is_group() {
        let Some(gid) = addr.gid() else {
            return;
        };
        let Ok(Some(g)) = db.group_view(gid) else {
            return;
        };
        if from_org.as_deref() != Some(g.org.as_str()) || !g.members.contains(&who.user) {
            return;
        }
        let users: Vec<String> = g.members.into_iter().filter(|m| *m != who.user).collect();
        (users, Some(to.to_owned()))
    } else {
        let user = addr.user;
        if user == who.user
            || from_org.is_none()
            || db.user_org(&user).ok().flatten() != from_org
            || db.is_blocked(&user, &who.user).unwrap_or(true)
        {
            return;
        }
        (vec![user], None)
    };
    let from = format!("{}@{}", who.user, app.config.server_name);
    let Ok(frame) = serde_json::from_value::<lodelai_protocol::ws::TypingNotice>(
        serde_json::json!({"t": "typing", "from": from, "group": group, "on": on}),
    ) else {
        return;
    };
    let frame =
        crate::frames::ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::TypingNotice(frame)));
    for u in users {
        if db.share_presence(&u).unwrap_or(false) {
            app.conns.send_user(&u, &frame);
        }
    }
}
