//! WebSocket: 핸드셰이크(protocol §7.1)와 프레임 루프(§7.2).
//!
//! `hello → challenge → auth → ready`. 모르는 기기·사용자 불일치·서명 실패는 모두 같은 `error protocol` 한 줄 뒤 끊는다.
//! challenge 는 기기가 있든 없든 항상 보낸다(기기 존재 열거 방지).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use lodelai_crypto::{encoding, verify_challenge, DeviceId, VerifyingKey};
use tokio::sync::{mpsc, Notify};

use crate::db::{AdminAct, AdminOutcome, MemberOutcome, PublicSession, RevokeOutcome, SelfRevoke};
use crate::frames::{
    ClientFrame, DeviceCert, DevicePubkeys, DirectoryBody, DirectoryDevice, DirectoryOrg,
    DirectoryPerson, DirectoryRevocation, DirectorySession, DirectoryTeam, ErrorCode, RevokedBy,
    ServerFrame,
};
use crate::rules::{self, Authed};
use crate::{blocking, App, Relay};

/// 핸드셰이크 전체 시간 상한.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 초대 토큰 유효 시간(#355, security §6 — 7일, 1회용).
pub const INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 관리자당 초대 발급 상한(#355 설계): 1시간에 20개.
pub const INVITE_WINDOW_MS: i64 = 60 * 60 * 1000;
pub const INVITE_MAX: i64 = 20;
/// 인증 전(hello·auth) 텍스트 프레임 상한(#320). 둘 다 수백 바이트다. 업그레이드 때 정한 상한(`max_frame_bytes`)은 연결
/// 도중 못 바꾸므로 받은 길이를 직접 보고 끊는다 — 인증 없는 연결이 큰 프레임으로 비용을 쓰지 못하게.
pub const HANDSHAKE_MAX_FRAME_BYTES: usize = 4096;
/// 나중 기기가 먼저 기기를 폐기하기 전 대기(#339 2026-10-24 결정 — 24시간). 기준은 요청 기기의 등록 시각.
pub const DEVICE_REVOKE_WAIT_MS: i64 = 24 * 60 * 60 * 1000;

/// 연결의 쓰기 줄. 값은 `Utf8Bytes`(참조 셈) — 여러 연결에 같은 프레임을 보낼 때 한 벌을 나눠 쓴다(묶음 22 §5d, 잎 200 에
/// 같은 암호문을 연결마다 복제하지 않게). 연결 하나에 보내는 곳은 `String` 을 그대로 넘긴다.
#[derive(Clone)]
struct Tx(mpsc::UnboundedSender<Utf8Bytes>);

impl Tx {
    fn send(&self, text: impl Into<Utf8Bytes>) -> Result<(), ()> {
        self.0.send(text.into()).map_err(|_| ())
    }
}

struct Conn {
    id: u64,
    device_id: String,
    tx: Tx,
    /// 기기가 폐기되면 그 기기의 다른 연결도 닫는다(#325).
    kill: Arc<Notify>,
}

/// 사용자별 접속 중인 연결.
#[derive(Default)]
pub struct Connections {
    inner: Mutex<HashMap<String, Vec<Conn>>>,
    next: AtomicU64,
}

impl Connections {
    fn add(&self, who: &Authed, tx: Tx) -> (u64, Arc<Notify>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let kill = Arc::new(Notify::new());
        self.lock().entry(who.user.clone()).or_default().push(Conn {
            id,
            device_id: who.device_id.clone(),
            tx,
            kill: kill.clone(),
        });
        (id, kill)
    }

    /// 그 기기의 연결을 모두 닫게 한다(폐기, #325). `notify_one` 이라 아직 기다리지 않는 연결도 다음 대기에서 깬다.
    pub(crate) fn close_device(&self, user: &str, device_id: &str) {
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.device_id == device_id) {
                c.kill.notify_one();
            }
        }
    }

    /// 그 사용자의 모든 연결을 닫게 한다(내보내기·나가기, 묶음 5).
    fn close_user(&self, user: &str) {
        if let Some(v) = self.lock().get(user) {
            for c in v {
                c.kill.notify_one();
            }
        }
    }

    /// 그 기기의 연결에만 보낸다(관리자가 기기 하나를 끊을 때 — 같은 사람의 다른 기기가 자기 폐기로 읽지 않게, 묶음 5).
    fn send_device(&self, user: &str, device_id: &str, frame: &ServerFrame) {
        let text = Utf8Bytes::from(frame.to_json());
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| c.device_id == device_id) {
                let _ = c.tx.send(text.clone());
            }
        }
    }

    fn remove(&self, user: &str, id: u64) {
        let mut m = self.lock();
        if let Some(v) = m.get_mut(user) {
            v.retain(|c| c.id != id);
            if v.is_empty() {
                m.remove(user);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Conn>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 그 기기들의 연결에만 보낸다(기기별 보관의 실시간 `deliver`, protocol §7.2-6).
    pub fn send_devices(&self, user: &str, device_ids: &[String], frame: &ServerFrame) {
        let text = Utf8Bytes::from(frame.to_json());
        if let Some(v) = self.lock().get(user) {
            for c in v.iter().filter(|c| device_ids.contains(&c.device_id)) {
                let _ = c.tx.send(text.clone());
            }
        }
    }

    /// 그 기기들의 연결에 보낸다 — 사용자를 가리지 않고(그룹 메시지는 여러 사람의 기기로 간다, 묶음 16).
    pub fn send_any_devices(&self, device_ids: &[String], frame: &ServerFrame) {
        let text = frame.to_json();
        for c in self
            .lock()
            .values()
            .flatten()
            .filter(|c| device_ids.contains(&c.device_id))
        {
            let _ = c.tx.send(text.clone());
        }
    }

    /// 그 사용자의 모든 연결에 보낸다. 보낸 연결 수.
    pub fn send_user(&self, user: &str, frame: &ServerFrame) -> usize {
        let text = Utf8Bytes::from(frame.to_json());
        self.lock().get(user).map_or(0, |v| {
            v.iter().filter(|c| c.tx.send(text.clone()).is_ok()).count()
        })
    }

    /// 모든 연결을 닫게 한다(relay 정리, #328).
    pub fn close_all(&self) {
        for c in self.lock().values().flatten() {
            c.kill.notify_one();
        }
    }

    pub fn users(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    /// 그 사용자의 열린 연결 수(`server.status.devices.connected` — 조직 사람별로 더한다).
    pub fn connections_of(&self, user: &str) -> usize {
        self.lock().get(user).map_or(0, Vec::len)
    }

    /// 그 사용자의 접속한 기기(§7 duty 후보).
    pub fn online_devices(&self, user: &str) -> Vec<String> {
        self.lock()
            .get(user)
            .map(|v| v.iter().map(|c| c.device_id.clone()).collect())
            .unwrap_or_default()
    }

    pub fn is_online(&self, user: &str) -> bool {
        self.lock().contains_key(user)
    }
}

pub async fn upgrade(
    State(app): State<App>,
    ip: Option<axum::Extension<crate::http::ClientIp>>,
    ws: WebSocketUpgrade,
) -> Response {
    // 인증 전 시도의 IP 상한(#364) — 원격 relay 만. 로컬은 모든 연결이 127.0.0.1 이라 재접속이 서로 막힌다.
    if let Some(axum::Extension(crate::http::ClientIp(Some(ip)))) = ip.filter(|_| app.config.remote)
    {
        if !app.ip_limiter.allow(&ip, app.effects.clock.now()) {
            return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    let max = app.config.max_frame_bytes;
    let server = server_header_value(&app.config.server_name);
    let features = features_header_value(&app.config);
    let mut resp = ws
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |socket| run(app, socket));
    // §12-28 ①: 받는 판 범위. 옛 relay(헤더 없음)는 판이 다른 hello 를 auth 로 끊어서, 앱이 이것으로 진짜 인증 실패와 가른다.
    resp.headers_mut()
        .insert(PROTOCOL_HEADER, protocol_header_value());
    // §12-29 ①: 서명을 검사할 서버 이름 — 앱이 접속 호스트와 견줘 어긋남을 가입 전에 알린다.
    if let Some(v) = server {
        resp.headers_mut().insert(SERVER_HEADER, v);
    }
    // §12-30 ②: 켜진 기능 — 앱이 연결마다 읽어 꺼진 기능(그룹)의 입구를 닫는다.
    resp.headers_mut().insert(FEATURES_HEADER, features);
    resp
}

/// 101 응답과 `/v1/healthz` 응답의 판 범위 헤더(§12-28 ①, `<MIN>-<VERSION>`). 101 헤더는 프록시가 지울 수 있어 healthz 에도 싣는다.
pub const PROTOCOL_HEADER: &str = "lodelai-protocol";

/// [`PROTOCOL_HEADER`] 의 값 `<MIN>-<VERSION>`.
pub fn protocol_header_value() -> axum::http::HeaderValue {
    axum::http::HeaderValue::from_str(&format!(
        "{}-{}",
        lodelai_protocol::PROTOCOL_MIN,
        lodelai_protocol::PROTOCOL_VERSION
    ))
    .expect("숫자와 '-' 뿐")
}

/// 101 응답과 `/v1/healthz` 응답의 서버 이름 헤더(§12-29 ①, #534) — challenge 서명을 검사할 `server_name`. 앱은 이 값으로
/// 서명하지 않고(되쓰기 막기) 접속 호스트와 견주기만 한다.
pub const SERVER_HEADER: &str = "lodelai-server";

/// [`SERVER_HEADER`] 의 값. 헤더에 못 싣는 이름이면 `None`(싣지 않음 — 앱은 견주지 않는다).
pub fn server_header_value(server_name: &str) -> Option<axum::http::HeaderValue> {
    axum::http::HeaderValue::from_str(server_name).ok()
}

/// 101 응답과 `/v1/healthz` 응답의 켜진 기능 헤더(§12-30 ②, #535) — 쉼표 목록: `groups`(설정), `device_name`(늘 — #490 묶음
/// 28 §4 `device.name` 을 아는 relay. PROTOCOL 판을 올리지 않아 앱은 이것으로만 보내도 되는지 안다 — 모르는 relay 는 ref 없는
/// error{protocol} 을 돌려줘 앱이 다른 관리 요청의 거절로 읽는다). **늘 싣는다**: 줄이 없으면 앱은 '모름'(옛 relay·터널이
/// 지움)으로 보니, 켜진 것이 없으면 값 `none`(빈 헤더는 프록시가 지울 수 있다).
pub const FEATURES_HEADER: &str = "lodelai-features";

/// [`FEATURES_HEADER`] 의 값 — 켜진 기능 쉼표 목록, 없으면 `none`.
pub fn features_header_value(config: &crate::Config) -> axum::http::HeaderValue {
    let on: Vec<&str> = [
        ("groups", config.groups),
        ("device_name", true),
        ("kp_reset", true),
        // 0.2.6 #809: delivered_ack.unreadable 을 아는 relay — 앱은 이것이 있을 때만 싣는다.
        ("unreadable_ack", true),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect();
    let v = if on.is_empty() {
        "none".to_owned()
    } else {
        on.join(",")
    };
    axum::http::HeaderValue::from_str(&v).expect("영문 소문자와 쉼표뿐")
}

/// 요청 프레임의 식별자(#537 (d)) — `send` 는 그 메시지의 `msg_id`, 그 밖은 `req`. 오류 답의 `ref` 로 쓴다.
fn request_ref(frame: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(frame).ok()?;
    let id = if v["t"] == "send" {
        v.pointer("/message/msg_id")
    } else {
        v.get("req")
    };
    id.and_then(serde_json::Value::as_str).map(str::to_owned)
}

/// 핸드셰이크 실패 이유 — hello 의 판이 범위 밖.
const VERSION_UNSUPPORTED: &str = "version_unsupported";

/// 프레임에 싣는 시각(RFC3339).
fn at_of(ms: i64) -> Option<String> {
    lodelai_effects::UnixMillis(ms).to_rfc3339().ok()
}

fn error_frame(code: ErrorCode, message: &str) -> String {
    ServerFrame::Error {
        code,
        message: message.to_owned(),
        r#ref: None,
    }
    .to_json()
}

async fn recv_frame(socket: &mut WebSocket) -> Option<Result<ClientFrame, ()>> {
    loop {
        match socket.next().await? {
            Ok(Message::Text(t)) if t.len() > HANDSHAKE_MAX_FRAME_BYTES => return Some(Err(())),
            Ok(Message::Text(t)) => return Some(ClientFrame::parse(t.as_str()).ok_or(())),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Binary(_)) => return Some(Err(())),
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

/// 핸드셰이크. 성공하면 인증된 주체, 폐기된 기기가 자기 키로 맞게 서명했으면 안쪽 `Err((누가, 언제 끊었나))`.
async fn handshake(
    app: &App,
    socket: &mut WebSocket,
) -> Result<Result<Authed, (Option<RevokedBy>, Option<i64>)>, &'static str> {
    let Some(Ok(ClientFrame::Hello { v, device_id, user })) = recv_frame(socket).await else {
        return Err("hello 가 아니다");
    };
    // 판이 범위 밖이면 서명을 보기 전에 명시 오류로 닫는다(묶음 22 §12-24 — auth 실패와 구별, 판 번호는 비밀이 아님).
    if !(lodelai_protocol::PROTOCOL_MIN..=lodelai_protocol::PROTOCOL_VERSION).contains(&v) {
        return Err(VERSION_UNSUPPORTED);
    }
    let mut nonce = [0u8; 32];
    app.effects
        .rng
        .try_fill(&mut nonce)
        .map_err(|_| "internal")?;
    let nonce_b64 = encoding::encode(&nonce);
    socket
        .send(Message::Text(
            ServerFrame::Challenge {
                nonce: nonce_b64.clone(),
            }
            .to_json()
            .into(),
        ))
        .await
        .map_err(|_| "send")?;
    let Some(Ok(ClientFrame::Auth { sig })) = recv_frame(socket).await else {
        return Err("auth 가 아니다");
    };
    // 이 아래 실패는 모두 같은 응답이다 — 폐기된 기기가 자기 키로 맞게 서명했을 때만 빼고(#339).
    let id = device_id.clone();
    let (registered, revoked, revoked_by) = blocking(app, move |r| {
        (
            r.db.device(&id).ok().flatten(),
            r.db.revoked_device(&id).ok().flatten(),
            r.db.revoked_by(&id).ok().flatten(),
        )
    })
    .await
    .ok_or("internal")?;
    let signed_by = |row: &Option<(String, String)>| {
        // 9·10 이 함께 돈다(#598 ②) — 범위는 위에서 봤고 서명은 판을 묶지 않는다(lodelai-auth-v1 은 둘 다 같음).
        (lodelai_protocol::PROTOCOL_MIN..=lodelai_protocol::PROTOCOL_VERSION).contains(&v)
            && row.as_ref().is_some_and(|(u, pk)| {
                *u == user
                    && VerifyingKey::from_b64(pk).is_ok_and(|k| {
                        DeviceId::parse(&device_id).is_some_and(|id| id.matches(&k))
                            && verify_challenge(
                                &k,
                                &app.config.server_name,
                                &device_id,
                                &nonce_b64,
                                &sig,
                            )
                            .is_ok()
                    })
            })
    };
    if signed_by(&registered) {
        Ok(Ok(Authed {
            user,
            device_id,
            v: u64::from(v),
        }))
    } else if signed_by(&revoked) {
        Ok(Err(
            revoked_by.map_or((None, None), |(by, ms)| (by, Some(ms)))
        ))
    } else {
        Err("auth")
    }
}

async fn run(app: App, mut socket: WebSocket) {
    let who = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&app, &mut socket)).await {
        Ok(Ok(Ok(who))) => who,
        Ok(outcome) => {
            let frame = match outcome {
                Ok(Err((by, ms))) => {
                    tracing::debug!("핸드셰이크 — 폐기된 기기");
                    ServerFrame::Revoked {
                        by,
                        at: ms.and_then(at_of),
                    }
                    .to_json()
                }
                Err("internal") => error_frame(ErrorCode::Internal, "handshake"),
                Err(VERSION_UNSUPPORTED) => {
                    tracing::debug!("핸드셰이크 — 판이 맞지 않음");
                    ServerFrame::Ws(Box::new(lodelai_protocol::ws::Frame::Error(
                        lodelai_protocol::ws::Error {
                            at: None,
                            by: None,
                            code: lodelai_protocol::ws::ErrorCode::VersionUnsupported,
                            max: Some(u64::from(lodelai_protocol::PROTOCOL_VERSION)),
                            until: None,
                            reason: None,
                            message: "handshake".into(),
                            min: Some(u64::from(lodelai_protocol::PROTOCOL_MIN)),
                            ref_: None,
                            t: lodelai_protocol::ws::ErrorT::Error,
                        },
                    )))
                    .to_json()
                }
                Err(why) => {
                    tracing::debug!(why, "핸드셰이크 실패");
                    error_frame(ErrorCode::Protocol, "handshake")
                }
                Ok(Ok(_)) => unreachable!(),
            };
            let _ = socket.send(Message::Text(frame.into())).await;
            let _ = socket.close().await;
            return;
        }
        Err(_) => {
            let _ = socket.close().await;
            return;
        }
    };

    let (mut sink, mut stream) = socket.split();
    let (raw_tx, mut rx) = mpsc::unbounded_channel::<Utf8Bytes>();
    let tx = Tx(raw_tx);

    // 순서: ready 를 먼저 큐에 넣고 → 연결 등록 → 그다음 쌓인 것을 쏟는다. 등록과 조회 사이에 도착한 메시지는
    // 실시간 deliver 와 pending 양쪽으로 두 번 갈 수 있지만(수신 코어가 msg_id 로 거른다) 빠지지는 않는다.
    // ready.pending 은 등록 직전 기준이라 실제 deliver 수보다 적을 수 있다.
    let (user, device) = (who.user.clone(), who.device_id.clone());
    let hello_v = who.v;
    let Some((pending_before, admin)) = blocking(&app, move |r| {
        // 이 기기가 붙은 판(#598 ② — 디렉터리 `v`). 실패해도 접속은 잇는다(모르면 9 로 보임).
        let _ = r.db.set_device_hello_v(&device, hello_v);
        (
            r.db.pending_for(&user, &device)
                .map(|v| v.len())
                .unwrap_or(0),
            // 원격 relay 만 "내가 관리자인가"를 알린다(묶음 5 — 화면 가르기용, 권한은 relay 가 따로 본다).
            r.config.remote.then(|| {
                r.db.is_org_admin(&user).unwrap_or(false)
                    || r.db.admin().ok().flatten().as_deref() == Some(user.as_str())
            }),
        )
    })
    .await
    else {
        return;
    };
    let now = app.effects.clock.now().to_rfc3339().unwrap_or_default();
    let _ = tx.send(
        ServerFrame::Ready {
            server: app.config.server_name.clone(),
            now,
            pending: pending_before as u64,
            admin,
        }
        .to_json(),
    );
    let was_online = crate::presence::connecting(&app, &who.user);
    // 연결 등록 → 쌓인 것 쏟기를 그룹 순서 잠금 안에서(묶음 16 §3a ④): 그룹이 있으면 directory·groups(조직 빠짐 힌트)를 먼저
    // 보내, 떨어져 있던 동안의 조직 빠짐을 쌓인 변경보다 먼저 알게 한다. 잠근 동안 실시간 그룹 변경이 이 연결 큐에 먼저 끼지 못한다.
    let (w, q) = (who.clone(), tx.clone());
    let Some((conn_id, kill)) = blocking(&app, move |r| {
        let _order = r
            .group_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let added = r.conns.add(&w, q.clone());
        // 그룹이 있으면 directory → groups(조직 빠짐 힌트) → 쌓인 것(§3a ④ 접속 때 순서, 8b85eddb) — 쌓인 그룹 변경이 없어도.
        // 디렉터리가 힌트보다 먼저여야 클라이언트가 지난 접속의 목록으로 힌트를 미루지 않는다.
        if let Some(f) = groups_frame_if_any(r, &w.user) {
            with_directory_order(r, || {
                let _ = q.send(ServerFrame::Directory(directory(r, &w.user)).to_json());
            });
            let _ = q.send(f.to_json());
        }
        // 묶음 22 §12-14: 저장한 nack commit_void → 그룹마다 마지막 결과 → 쌓인 것.
        for f in crate::mls_group::on_connect_frames(r, &w.device_id) {
            let _ = q.send(f);
        }
        // 0.2.6 #809: 꺼져 있던 동안 알릴 때가 된 못 엶 보고(이 연결은 이미 등록됨).
        crate::rules::notify_unreadable(r);
        let pending = r.db.pending_for(&w.user, &w.device_id).unwrap_or_default();
        for (m, group_seq) in pending {
            let Ok(message) = serde_json::from_str::<serde_json::Value>(&m) else {
                continue;
            };
            // 내 다른 기기가 보낸 것의 사본(묶음 22 §7) — 꺼져 있던 동안 바뀐 보낸 쪽 상태를 싣는다.
            let view = message
                .get("msg_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| r.db.header(id).ok().flatten())
                .filter(|h| h.from_user == w.user && h.to_user != w.user)
                .map(|h| h.sender_view);
            let mut f = serde_json::json!({"t": "deliver", "message": message});
            if let Some(s) = group_seq {
                f["group_seq"] = serde_json::json!(s);
            }
            if let Some(v) = view {
                f["sender_view"] = serde_json::Value::String(v);
            }
            let _ = q.send(Utf8Bytes::from(f.to_string()));
        }
        // #598 ②: 꺼져 있던 동안 못 알린 recipient_outdated(보낸 코어가 v9 로 다시 보내게).
        for f in crate::rules::outdated_notices(r, &w) {
            let _ = q.send(f.to_json());
        }
        added
    })
    .await
    else {
        crate::presence::disconnected(&app, &who.user);
        return;
    };
    // 묶음 22 §3: KeyPackage 가 모자라면 채우라고 알린다.
    {
        let (app, who) = (app.clone(), who.clone());
        let _ = blocking(&app, move |r| {
            crate::mls::on_ready(r, &who);
            // #577: 마지막 접속 시각·걸린 걸기의 대상이면 막기 카드 재료.
            crate::recovery::on_auth(r, &who);
        })
        .await;
    }
    if !was_online {
        crate::presence::announce(&app, &who.user);
    }
    // 묶음 22 §12-27 ⓑ: 이 기기가 접속한 날(UTC 0시)을 남기고, 날짜가 바뀌었을 때만 내 다른 기기들에 directory.update(하루 한 번).
    // 내 항목에만 실리므로 동료에게는 보내지 않는다.
    {
        let (app, who) = (app.clone(), who.clone());
        let _ = blocking(&app, move |r| {
            let now = r.effects.clock.now().0;
            let day = now - now.rem_euclid(24 * 60 * 60 * 1000);
            if r.db.touch_device_day(&who.device_id, day).unwrap_or(false) {
                // 접속한 이 기기는 곧 directory.list 로 받는다 — 내 다른 기기에만(접속 직후 프레임 순서를 바꾸지 않게).
                let others: Vec<String> = r
                    .conns
                    .online_devices(&who.user)
                    .into_iter()
                    .filter(|d| *d != who.device_id)
                    .collect();
                if !others.is_empty() {
                    with_directory_order(r, || {
                        r.conns.send_devices(
                            &who.user,
                            &others,
                            &ServerFrame::DirectoryUpdate(directory(r, &who.user)),
                        );
                    });
                }
            }
        })
        .await;
    }

    let conn_v = who.v;
    let writer = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            let Some(text) = for_version(text, conn_v) else {
                continue;
            };
            if sink.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // 서버 ping(protocol §7.2). 생존 판정은 앱 텍스트 프레임만 본다 — WebSocket 제어 프레임은 세지 않는다.
    let mut ping = tokio::time::interval(app.config.ping_interval);
    ping.tick().await; // 첫 틱은 즉시 — 버린다
    let mut last_rx = tokio::time::Instant::now();
    let mut typing_gate = crate::presence::TypingGate::default();
    loop {
        let frame = tokio::select! {
            next = stream.next() => match next {
                Some(Ok(Message::Text(t))) => t,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                // 끊김 원인 추적용(주소·내용 없이 사용자·기기만).
                _ => {
                    tracing::info!(user = %who.user, device = %who.device_id, "앱이 연결을 닫음");
                    break;
                }
            },
            () = kill.notified() => {
                tracing::info!(user = %who.user, device = %who.device_id, "연결 강제 종료");
                break;
            }
            _ = ping.tick() => {
                if last_rx.elapsed() >= app.config.idle_timeout {
                    tracing::info!(user = %who.user, device = %who.device_id, "유휴 연결 종료");
                    break;
                }
                let _ = tx.send(ServerFrame::Ping.to_json());
                continue;
            }
        };
        last_rx = tokio::time::Instant::now();
        // 0. rate limit — 파싱 직후, 다른 검사 전.
        if !app.limiter.allow(&who.user, app.effects.clock.now()) {
            let _ = tx.send(error_frame(ErrorCode::RateLimited, "rate limited"));
            tracing::info!(user = %who.user, device = %who.device_id, "rate limit 으로 연결 종료");
            break;
        }
        let Some(parsed) = ClientFrame::parse(frame.as_str()) else {
            // send 의 메시지가 스키마에 맞지 않으면 ref = msg_id 로 알려 보낸 쪽이 큐에서 뺄 수 있게 한다.
            let raw: Option<serde_json::Value> = serde_json::from_str(frame.as_str()).ok();
            // 입력 중 표시(#613)는 어긋나도(세션 주소 등) 조용히 버린다 — 오류를 내면 대상이 있는지 드러난다.
            if raw.as_ref().is_some_and(|v| v["t"] == "typing") {
                continue;
            }
            let reply = match raw
                .as_ref()
                .filter(|v| v["t"] == "send")
                .and_then(|v| v.get("message"))
            {
                Some(m) => rules::send_format_error(m),
                None => rules::protocol_error("프레임 형식"),
            };
            let _ = tx.send(reply.to_json());
            continue;
        };
        // 입력 중 표시(#613): 응답 없음. 판 11 아래 연결이 보낸 것·연결마다 to·값마다 초당 1 을 넘은 것은 버린다.
        if let ClientFrame::Typing { to, on } = parsed {
            if who.v >= crate::presence::TYPING_FROM
                && typing_gate.allow(&to, on, tokio::time::Instant::now())
            {
                let w = who.clone();
                if blocking(&app, move |r| crate::presence::typing(r, &w, &to, on))
                    .await
                    .is_none()
                {
                    break;
                }
            }
            continue;
        }
        // 기기 폐기(#325·#339): 순서 고정 — 폐기 커밋 → device.revoked → 같은 조직에 directory.update → 폐기된 기기의 연결 닫음.
        if let ClientFrame::DeviceRevoke { device_id, proof } = &parsed {
            let target = device_id.clone().filter(|d| *d != who.device_id);
            // 묶음 22 devrevoke: 증명이 있으면 먼저 검사 — 틀리면 error{protocol}, 폐기하지 않는다.
            let proof = match proof {
                Some((at, sig)) => {
                    let (w, t, at, sig) = (
                        who.clone(),
                        target.clone().unwrap_or_else(|| who.device_id.clone()),
                        at.clone(),
                        sig.clone(),
                    );
                    let Some(checked) =
                        blocking(&app, move |r| crate::mls::revoke_proof(r, &w, &t, at, sig)).await
                    else {
                        break;
                    };
                    let Some(p) = checked else {
                        let _ = tx.send(error_frame(ErrorCode::Protocol, "device.revoke"));
                        continue;
                    };
                    Some(p)
                }
                None => None,
            };
            let Some(target) = target else {
                // 자기 폐기(#325) — 이 연결도 닫는다.
                let w = who.clone();
                let now = app.effects.clock.now().0;
                let p = proof.clone();
                let Some(done) = blocking(&app, move |r| {
                    r.db.revoke_device(&w.device_id, now, p.as_ref())
                })
                .await
                else {
                    break;
                };
                match done {
                    Ok(SelfRevoke::Revoked) => {}
                    // 유일한 관리자의 마지막 기기(묶음 5) — 연결은 그대로 둔다.
                    Ok(SelfRevoke::LastAdmin) => {
                        let _ = tx.send(error_frame(ErrorCode::LastAdmin, "device.revoke"));
                        continue;
                    }
                    Ok(SelfRevoke::Gone) | Err(_) => {
                        let _ = tx.send(error_frame(ErrorCode::Internal, "device.revoke"));
                        continue;
                    }
                }
                tracing::info!(user = %who.user, device = %who.device_id, "기기 폐기");
                // 묶음 22 §7: 그 기기의 잎을 남은 잎이 빼게(remove_device), 뿌리가 바뀌어 자격이 생긴 기기는 들이게.
                {
                    let u = who.user.clone();
                    let _ = blocking(&app, move |r| {
                        crate::mls_group::void_revoked_senders(r);
                        crate::mls::refresh_add_duties(r, &u);
                        crate::mls::rejoin_orphaned(r, &u);
                    })
                    .await;
                }
                // #577: 지금 끊기(자기 폐기)·요청 기기 폐기 — 걸기를 다시 본다.
                {
                    let u = who.user.clone();
                    let _ = blocking(&app, move |r| crate::recovery::on_trust_change(r, &u)).await;
                }
                let _ = tx.send(
                    ServerFrame::DeviceRevoked {
                        device_id: device_id.clone(),
                        by: Some(RevokedBy::Device),
                        at: at_of(now),
                    }
                    .to_json(),
                );
                let w = who.clone();
                let _ = blocking(&app, move |r| broadcast_directory(r, &w)).await;
                app.conns.close_device(&who.user, &who.device_id);
                linger_until_closed(&mut stream).await;
                break;
            };
            // 같은 사용자의 다른 기기(#339) — 요청한 연결은 유지한다.
            let (w, t) = (who.clone(), target.clone());
            let now = app.effects.clock.now().0;
            let Some(outcome) = blocking(&app, move |r| {
                let trusted = crate::mls::eligible_devices(r, &w.user).contains(&w.device_id);
                r.db.revoke_other(
                    &w.device_id,
                    &t,
                    now,
                    DEVICE_REVOKE_WAIT_MS,
                    proof.as_ref(),
                    trusted,
                )
            })
            .await
            else {
                break;
            };
            match outcome {
                Ok(RevokeOutcome::Revoked { user: owner }) => {
                    tracing::info!(user = %who.user, by = %who.device_id, device = %target, "다른 기기 폐기");
                    {
                        let u = owner.clone();
                        let _ = blocking(&app, move |r| {
                            crate::mls_group::void_revoked_senders(r);
                            crate::mls::refresh_add_duties(r, &u);
                            crate::mls::rejoin_orphaned(r, &u);
                            crate::recovery::on_trust_change(r, &u);
                        })
                        .await;
                    }
                    let _ = tx.send(
                        ServerFrame::DeviceRevoked {
                            device_id: Some(target.clone()),
                            by: Some(if owner == who.user {
                                RevokedBy::Device
                            } else {
                                RevokedBy::Admin
                            }),
                            at: at_of(now),
                        }
                        .to_json(),
                    );
                    let w = who.clone();
                    let _ = blocking(&app, move |r| broadcast_directory(r, &w)).await;
                    // 대상 기기의 주인(관리자가 남의 기기를 끊으면 요청자와 다르다, #355). 남의 기기면 끊기기 전에
                    // 그 기기에만 알린다(묶음 5 — 꺼져 있었으면 재접속 때 error{device_revoked, by}).
                    if owner != who.user {
                        app.conns.send_device(
                            &owner,
                            &target,
                            &ServerFrame::DeviceRevoked {
                                device_id: None,
                                by: Some(RevokedBy::Admin),
                                at: at_of(now),
                            },
                        );
                    }
                    app.conns.close_device(&owner, &target);
                }
                Ok(RevokeOutcome::AlreadyRevoked) => {
                    let _ = tx.send(
                        ServerFrame::DeviceRevoked {
                            device_id: Some(target),
                            by: None,
                            at: None,
                        }
                        .to_json(),
                    );
                }
                Ok(RevokeOutcome::TooEarly) => {
                    let _ = tx.send(error_frame(ErrorCode::TooEarly, "device.revoke"));
                }
                // 남의 기기·모르는 id 는 같은 바이트(열거 방지).
                Ok(RevokeOutcome::Unknown) => {
                    let _ = tx.send(error_frame(ErrorCode::Protocol, "device.revoke"));
                }
                Err(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Internal, "device.revoke"));
                }
            }
            continue;
        }
        // 조직 나가기(묶음 5): 폐기 커밋 → 내 모든 연결에 device.revoked{by:left} → 같은 조직에 directory.update → 내 연결 모두 닫음.
        if matches!(parsed, ClientFrame::MemberLeave) {
            let w = who.clone();
            let now = app.effects.clock.now().0;
            // 폐기 커밋 → directory.update 사이에 그룹 변경 전달이 끼지 않게(묶음 16 §3a ④) — 한 블록 안에서 잠근 채로.
            let Some(outcome) = blocking(&app, move |r| {
                let _order = r
                    .group_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let out = r.db.member_leave(&w.user, now);
                if matches!(out, Ok(MemberOutcome::Done { .. })) {
                    r.conns.send_user(
                        &w.user,
                        &ServerFrame::DeviceRevoked {
                            device_id: None,
                            by: Some(RevokedBy::Left),
                            at: at_of(now),
                        },
                    );
                    announce_org_removal(r, &w.user);
                }
                out
            })
            .await
            else {
                break;
            };
            match outcome {
                Ok(MemberOutcome::Done { .. }) => {
                    tracing::info!(user = %who.user, "조직 나감");
                    // #599: 폐기된 내 기기들이 보낸 확정 전 Commit — group_order 를 놓은 뒤.
                    let _ = blocking(&app, crate::mls_group::void_revoked_senders).await;
                    app.conns.close_user(&who.user);
                    // #622 후속(설계 리뷰 6515564969): 요청한 연결은 자기 폐기와 같이 앱이 읽고 닫을 때까지 둔다.
                    linger_until_closed(&mut stream).await;
                    break;
                }
                Ok(MemberOutcome::LastAdmin) => {
                    let _ = tx.send(error_frame(ErrorCode::LastAdmin, "member.leave"));
                }
                Ok(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Protocol, "member.leave"));
                }
                Err(_) => {
                    let _ = tx.send(error_frame(ErrorCode::Internal, "member.leave"));
                }
            }
            continue;
        }
        // #702: directory.list 의 답도 만들기와 큐 넣기를 같은 잠금 안에서 — dispatch 가 돌려준 뒤 넣으면 그 사이 방송이 먼저 들어가
        // 이 낡은 답이 새 모습을 덮는다.
        if matches!(parsed, ClientFrame::DirectoryList) {
            let (w, q) = (who.clone(), tx.clone());
            if blocking(&app, move |r| {
                with_directory_order(r, || {
                    let _ = q.send(ServerFrame::Directory(directory(r, &w.user)).to_json());
                });
            })
            .await
            .is_none()
            {
                break;
            }
            continue;
        }
        // 앞 프레임의 처리를 기다린 뒤 다음을 읽는다 — 한 연결 안의 순서를 지킨다(병렬 dispatch 금지).
        let w = who.clone();
        let rid = request_ref(frame.as_str());
        // send 의 답(ack) 뒤에 알리는 것들: #598 ② recipient_outdated, #577 §9 ② 기기 바뀜 실패(같은 연결 큐 순서).
        let sent = matches!(parsed, ClientFrame::Send { .. });
        let Some(reply) = blocking(&app, move |r| dispatch(r, &w, parsed)).await else {
            break;
        };
        if let Some(mut reply) = reply {
            // #537 (d): 요청에 대한 오류는 internal 이라도 ref 를 단다 — 보낸 쪽이 어느 행·요청의 오류인지 알아 기다림을 푼다.
            if let (
                ServerFrame::Error {
                    r#ref: r @ None, ..
                },
                Some(id),
            ) = (&mut reply, rid)
            {
                *r = Some(id);
            }
            let _ = tx.send(reply.to_json());
        }
        // #598 ②: send 의 답(ack) 뒤에 recipient_outdated — 보낸 기기에만, ack 보다 먼저 가지 않게.
        if sent {
            let w = who.clone();
            if let Some(fs) = blocking(&app, move |r| crate::rules::outdated_notices(r, &w)).await {
                for f in fs {
                    let _ = tx.send(f.to_json());
                }
            }
        }
        if sent {
            let _ = blocking(&app, crate::recovery::notify_device_changed).await;
        }
    }

    app.conns.remove(&who.user, conn_id);
    {
        let (u, d) = (who.user.clone(), who.device_id.clone());
        let _ = blocking(&app, move |r| crate::recovery::on_disconnect(r, &u, &d)).await;
    }
    crate::presence::disconnected(&app, &who.user);
    crate::presence::device_disconnected(&app, &who.user, &who.device_id);
    drop(tx);
    let _ = writer.await;
}

/// 조직 관리자 동작 적용(#355): 관리자 판정·적용 → 같은 조직에 directory.update. 실패는 모두 같은 `error{protocol}`(ref 없음).
fn admin(app: &Relay, who: &Authed, act: &AdminAct<'_>) -> Option<ServerFrame> {
    match app.db.admin_act(&who.user, act) {
        Ok(AdminOutcome::Done) => {
            broadcast_directory(app, who);
            None
        }
        Ok(AdminOutcome::NameTaken) => Some(ServerFrame::Error {
            code: ErrorCode::NameTaken,
            message: "team 이름".into(),
            r#ref: None,
        }),
        _ => Some(rules::protocol_error("org·team")),
    }
}

/// 내 기기 서명 검사(#393, protocol §7.2 `device.certify`): 서명자 = 이 연결의 기기(폐기 안 됨), 대상 = 같은 사용자의
/// 폐기 안 된 다른 기기, `lodelai-devcert-v1` 서명이 서명자 키로 맞음.
fn certify_ok(app: &Relay, who: &Authed, target: &str, sig: &str) -> bool {
    if target == who.device_id {
        return false;
    }
    let Ok(devices) = app.db.devices_of(&who.user) else {
        return false;
    };
    let (Some(signer), Some(t)) = (
        devices.iter().find(|d| d.device_id == who.device_id),
        devices.iter().find(|d| d.device_id == target),
    ) else {
        return false;
    };
    let (Ok(vk), Ok(x25519)) = (
        lodelai_crypto::VerifyingKey::from_b64(&signer.ed25519),
        lodelai_crypto::encoding::decode_array::<32>(&t.x25519, "x25519"),
    ) else {
        return false;
    };
    let cert = lodelai_crypto::devcert::Cert {
        server: &app.config.server_name,
        user: &who.user,
        device_id: target,
        x25519: &x25519,
        signer: &who.device_id,
    };
    lodelai_crypto::devcert::verify(&vk, &cert, sig)
}

/// 조직·팀 이름 규칙(표시 이름과 같다).
fn org_name(name: &str) -> Option<String> {
    lodelai_protocol::display_name::normalize(name).ok()
}

/// #737: 확인되지 않은(잎 자격 없는) 기기의 관리자 동작은 막는다 — 관리자 이메일을 뺏은 사람이 새 기기를 붙여 확인 전에
/// 조직을 바꾸지 못하게. 관리자가 아니면 여기서 거르지 않는다(원래 갈래가 protocol 로 거절).
fn unconfirmed_admin(app: &Relay, who: &Authed, what: &str) -> Option<ServerFrame> {
    if !app.db.is_org_admin(&who.user).unwrap_or(false) {
        return None;
    }
    if crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) {
        return None;
    }
    Some(ServerFrame::Error {
        code: ErrorCode::DeviceUnconfirmed,
        message: what.into(),
        r#ref: None,
    })
}

/// #737 관리자 폐기: 같은 조직 다른 사람의 메일 확인 끊기 대상 기기를 지금 끊는다. 순서는 `member.remove` 와 같게 — 폐기
/// 커밋 → 그 기기에 device.revoked{by: admin} → MLS duty → 걸기 다시 보기 → directory.update → 연결 닫음 → 메일.
fn member_revoke_device(
    app: &Relay,
    who: &Authed,
    user: &str,
    device_id: &str,
) -> Option<ServerFrame> {
    if let Some(e) = unconfirmed_admin(app, who, "member.revoke_device") {
        return Some(e);
    }
    let now = app.effects.clock.now().0;
    {
        let _order = app
            .group_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match app.db.admin_revoke_device(&who.user, user, device_id, now) {
            Ok(true) => {}
            Ok(false) => return Some(rules::protocol_error("member.revoke_device")),
            Err(_) => return Some(rules::internal_error()),
        }
        tracing::info!(by = %who.user, user = %user, device = %device_id, "관리자가 예전 기기 끊음");
        app.conns.send_devices(
            user,
            &[device_id.to_owned()],
            &ServerFrame::DeviceRevoked {
                device_id: None,
                by: Some(RevokedBy::AdminDevice),
                at: at_of(now),
            },
        );
    }
    crate::mls_group::void_revoked_senders(app);
    crate::mls::refresh_add_duties(app, user);
    crate::mls::rejoin_orphaned(app, user);
    crate::recovery::on_admin_cut(app, user, now);
    broadcast_directory_of(app, user);
    app.conns.close_device(user, device_id);
    crate::recovery::mail_admin_cut(app, user, now);
    None
}

fn dispatch(app: &Relay, who: &Authed, frame: ClientFrame) -> Option<ServerFrame> {
    let admin_act = match &frame {
        ClientFrame::OrgAdmin { .. } => Some("org.admin"),
        ClientFrame::MemberRemove { .. } => Some("member.remove"),
        ClientFrame::OrgUpdate { .. } => Some("org.update"),
        ClientFrame::TeamCreate { .. } => Some("team.create"),
        ClientFrame::TeamUpdate { .. } => Some("team.update"),
        ClientFrame::TeamDelete { .. } => Some("team.delete"),
        // 확인 전 기기가 남(또는 자기 다른 계정)을 초대하면 이 기기를 끊어도 그 계정이 조직에 남는다.
        ClientFrame::InviteCreate { .. } => Some("invite.create"),
        _ => None,
    };
    if let Some(e) = admin_act.and_then(|w| unconfirmed_admin(app, who, w)) {
        return Some(e);
    }
    match frame {
        ClientFrame::Send { message } => Some(rules::handle_send(app, who, message)),
        ClientFrame::DeliveredAck { msg_id, unreadable } => {
            rules::handle_delivered_ack(app, who, &msg_id, unreadable);
            None
        }
        ClientFrame::Status {
            msg_id,
            state,
            abort_reason,
            fail_reason,
            at,
        } => rules::handle_status(
            app,
            who,
            &msg_id,
            &state,
            abort_reason.as_deref(),
            fail_reason.as_deref(),
            &at,
        ),
        ClientFrame::SessionPublish {
            slug,
            grade,
            liveness,
            display,
            title,
            folder,
            project,
            capabilities: _,
            busy,
            audience,
            agent,
            no,
        } => {
            // 세션 표시 이름·제목·폴더도 사람 표시 이름과 같은 규칙(#348, m1-spec §2) — 동료 세션의
            // list_sessions·화면으로 들어간다. 하나라도 어긋나면 프레임 전체를 거부한다.
            // 폴더는 cwd 마지막 성분만 — 경로 구분자도 거부한다(normalize_folder, 코어도 같은 함수로 거른다).
            let (Ok(display), Ok(title), Ok(folder)) = (
                optional(
                    display.as_deref(),
                    lodelai_protocol::display_name::normalize,
                ),
                optional(title.as_deref(), lodelai_protocol::display_name::normalize),
                optional(
                    folder.as_deref(),
                    lodelai_protocol::display_name::normalize_folder,
                ),
            ) else {
                return Some(rules::protocol_error("session.publish 형식"));
            };
            // 프로젝트(묶음 23 §5): 구분 이름은 성분마다 폴더 규칙 + 전체 64자 — 전체 경로가 새지 않게. id 꼴은 스키마가 봄.
            let project = match project {
                None => None,
                Some((id, name)) => {
                    match lodelai_protocol::display_name::normalize_project_name(&name) {
                        Ok(n) => Some((id, n)),
                        Err(_) => return Some(rules::protocol_error("session.publish 형식")),
                    }
                }
            };
            if !valid_slug(&slug)
                || !matches!(grade.as_str(), "question" | "task")
                || !matches!(liveness.as_str(), "live:channel" | "live:pty" | "dead")
            {
                return Some(rules::protocol_error("session.publish 형식"));
            }
            let Some(audience) = checked_audience(app, &who.user, audience) else {
                return Some(rules::protocol_error("session.publish audience"));
            };
            let s = PublicSession {
                user: who.user.clone(),
                slug,
                grade,
                liveness,
                display,
                title,
                folder,
                project,
                busy,
                audience,
                agent,
                no,
                offline: false,
            };
            if app.db.publish_session(&s, Some(&who.device_id)).is_err() {
                return Some(rules::protocol_error("session.publish"));
            }
            broadcast_directory(app, who);
            None
        }
        ClientFrame::SessionUnpublish { slug } => {
            let _ = app.db.unpublish_session(&who.user, &slug);
            broadcast_directory(app, who);
            None
        }
        // 연결의 읽기 고리는 directory.list 를 여기 오기 전에 잠금 안에서 답한다(#702). 여기는 그 밖의 부르는 곳(시험)용.
        ClientFrame::DirectoryList => Some(ServerFrame::Directory(directory(app, &who.user))),
        ClientFrame::ProfileUpdate {
            display_name,
            teams,
            clear_avatar,
        } => {
            // 없는 필드는 안 바꾼다(#355). 둘 다 검사한 뒤에 바꾼다 — 하나만 바뀌고 오류가 나지 않게.
            let display = match display_name
                .as_deref()
                .map(lodelai_protocol::display_name::normalize)
            {
                None => None,
                Some(Ok(d)) => Some(d),
                Some(Err(_)) => return Some(rules::protocol_error("profile.update 형식")),
            };
            if let Some(ts) = &teams {
                if !matches!(app.db.set_user_teams(&who.user, ts), Ok(true)) {
                    return Some(rules::protocol_error("profile.update teams"));
                }
            }
            if let Some(d) = &display {
                if app.db.set_display(&who.user, d).is_err() {
                    return Some(rules::protocol_error("profile.update"));
                }
            }
            // 사진 지우기(묶음 15 §2): 이미 없고 다른 필드도 없으면 방송하지 않는다.
            let mut cleared = false;
            if clear_avatar {
                match app.db.clear_avatar(&who.user) {
                    Ok(old) => {
                        cleared = old.is_some();
                        crate::blob::remove_files(app, &old.into_iter().collect::<Vec<_>>());
                    }
                    Err(_) => return Some(rules::protocol_error("profile.update")),
                }
            }
            if cleared || display.is_some() || teams.is_some() {
                broadcast_directory(app, who);
            }
            None
        }
        ClientFrame::OrgUpdate { name, clear_avatar } => {
            // 둘 다 없으면 형식 오류. 이름 규칙·관리자는 바꾸기 전에 모두 본다(하나만 바뀌지 않게).
            let name = match name.as_deref().map(org_name) {
                None => None,
                Some(Some(n)) => Some(n),
                Some(None) => return Some(rules::protocol_error("org·team 이름 형식")),
            };
            if name.is_none() && !clear_avatar {
                return Some(rules::protocol_error("org.update"));
            }
            let org = if clear_avatar {
                match app.db.org_admin_of(&who.user) {
                    Ok(Some(org)) => Some(org),
                    _ => return Some(rules::protocol_error("org·team")),
                }
            } else {
                None
            };
            // 조직 사진 지우기(#554) 먼저 — 이름도 바꾸면 그 방송에 지운 결과가 실린다. 이미 없으면 방송하지 않는다.
            let mut cleared = false;
            if let Some(org) = org {
                match app.db.clear_org_avatar(&org) {
                    Ok(old) => {
                        cleared = old.is_some();
                        crate::blob::remove_files(app, &old.into_iter().collect::<Vec<_>>());
                    }
                    Err(_) => return Some(rules::protocol_error("org.update")),
                }
            }
            if let Some(n) = &name {
                return admin(app, who, &AdminAct::OrgRename { name: n });
            }
            if cleared {
                broadcast_directory(app, who);
            }
            None
        }
        ClientFrame::TeamCreate { name } => match org_name(&name) {
            Some(n) => {
                let id = app.effects.ids.next_ulid();
                admin(app, who, &AdminAct::TeamCreate { id: &id, name: &n })
            }
            None => Some(rules::protocol_error("org·team 이름 형식")),
        },
        ClientFrame::TeamUpdate { id, name } => match org_name(&name) {
            Some(n) => admin(app, who, &AdminAct::TeamRename { id: &id, name: &n }),
            None => Some(rules::protocol_error("org·team 이름 형식")),
        },
        ClientFrame::TeamDelete { id } => admin(app, who, &AdminAct::TeamDelete { id: &id }),
        ClientFrame::InviteCreate { email } => {
            let email = match email.as_deref().map(crate::http::normalize_email) {
                None => None,
                Some(Some(e)) => Some(e),
                Some(None) => return Some(rules::protocol_error("invite.create 형식")),
            };
            let mut raw = [0u8; 32];
            if app.effects.rng.try_fill(&mut raw).is_err() {
                return Some(ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "invite.create".into(),
                    r#ref: None,
                });
            }
            let token = encoding::encode(&raw);
            let now = app.effects.clock.now().0;
            let expires = now + INVITE_TTL_MS;
            let hash = crate::http::invite_hash(&token);
            match app.db.admin_act(
                &who.user,
                &AdminAct::Invite {
                    token_hash: &hash,
                    email: email.as_deref(),
                    now_ms: now,
                    expires_ms: expires,
                    window_ms: INVITE_WINDOW_MS,
                    max: INVITE_MAX,
                },
            ) {
                Ok(AdminOutcome::Done) => Some(ServerFrame::InviteCreated {
                    token,
                    expires_at: lodelai_effects::UnixMillis(expires)
                        .to_rfc3339()
                        .unwrap_or_default(),
                }),
                // 발급 상한은 연결을 끊는 rate_limited 가 아니라 이 요청만 거절한다 — protocol 과 구분해 알린다.
                Ok(AdminOutcome::RateLimited) => Some(ServerFrame::Error {
                    code: ErrorCode::RateLimited,
                    message: "invite.create".into(),
                    r#ref: None,
                }),
                _ => Some(rules::protocol_error("invite.create")),
            }
        }
        // run() 이 dispatch 전에 처리한다(응답·방송·닫기 순서 때문에).
        ClientFrame::DeviceRevoke { .. } => None,
        ClientFrame::BlobReserve {
            req,
            ct_len,
            avatar,
            for_org,
        } => Some(crate::blob::reserve(
            app, who, &req, ct_len, avatar, for_org,
        )),
        ClientFrame::BlobGet { req, blob_id } => {
            Some(crate::blob::get_ticket(app, who, &req, &blob_id))
        }
        ClientFrame::BlobFetched { blob_id } => {
            crate::blob::fetched(app, who, &blob_id);
            None
        }
        ClientFrame::GroupsList => match groups_frame(app, &who.user) {
            Ok(f) => Some(f),
            Err(_) => Some(ServerFrame::Error {
                code: ErrorCode::Internal,
                message: "groups.list".into(),
                r#ref: None,
            }),
        },
        ClientFrame::GroupsReplay { group, from_seq } => {
            // 그룹 끔(묶음 16 §3b)이면 모르는 그룹과 같다.
            let gid = crate::frames::Address::parse(&group)
                .filter(|a| app.config.groups && a.server == app.config.server_name)
                .and_then(|a| a.gid().map(str::to_owned));
            let found = gid.map(|g| app.db.group_replay(&g, &who.user, &who.device_id, from_seq));
            match found {
                Some(Ok(Some(items))) => {
                    for (m, seq) in items {
                        if let Ok(message) = serde_json::from_str(&m) {
                            app.conns.send_device(
                                &who.user,
                                &who.device_id,
                                &ServerFrame::Deliver {
                                    message,
                                    group_seq: Some(seq),
                                },
                            );
                        }
                    }
                    None
                }
                _ => Some(rules::protocol_error("groups.replay")),
            }
        }
        // 연결 루프가 먼저 받는다(연결마다 상한) — 여기 오지 않는다.
        ClientFrame::Typing { .. } => None,
        ClientFrame::PresenceSet { share } => match app.db.set_share_presence(&who.user, share) {
            Ok(true) => {
                tracing::info!(user = %who.user, share, "접속 표시 설정");
                broadcast_directory(app, who);
                None
            }
            Ok(false) => None,
            Err(_) => Some(ServerFrame::Error {
                code: ErrorCode::Internal,
                message: "presence.set".into(),
                r#ref: None,
            }),
        },
        ClientFrame::DeviceCertify { device_id, sig } => {
            if !certify_ok(app, who, &device_id, &sig) {
                return Some(rules::protocol_error("device.certify"));
            }
            let now = app.effects.clock.now().0;
            match app
                .db
                .put_device_cert(&who.device_id, &device_id, &sig, now)
            {
                Ok(true) => {}
                // 같은 쌍·같은 sig — 바뀐 것이 없으니 방송하지 않는다(설계 리뷰 eb674083).
                Ok(false) => return None,
                Err(_) => {
                    return Some(ServerFrame::Error {
                        code: ErrorCode::Internal,
                        message: "device.certify".into(),
                        r#ref: None,
                    })
                }
            }
            tracing::info!(user = %who.user, by = %who.device_id, device = %device_id, "내 기기 서명");
            broadcast_directory(app, who);
            // 묶음 22 §7: 새로 잎 자격을 얻은 기기를 내 다른 기기가 들이게.
            crate::mls::refresh_add_duties(app, &who.user);
            // #577: 요청 기기가 잎 자격을 얻었으면 메일 확인 끊기는 끝난다.
            crate::recovery::on_trust_change(app, &who.user);
            None
        }
        ClientFrame::DeviceRecover => crate::recovery::start(app, who),
        ClientFrame::DeviceRecoverCancel => crate::recovery::cancel(app, who),
        ClientFrame::DeviceRecoverBlock => crate::recovery::block(app, who),
        // 묶음 4 의 연결 코드 등록은 묶음 5 에서 없앴다 — 서버 relay 는 이메일 가입·초대로만 사람·기기를 들인다(m1-spec §17.3).
        ClientFrame::DeviceRegister { .. } => Some(rules::protocol_error("device.register")),
        ClientFrame::MemberRevokeDevice { user, device_id } => {
            member_revoke_device(app, who, &user, &device_id)
        }
        ClientFrame::OrgAdmin { user, admin } => match app.db.set_admin(&who.user, &user, admin) {
            Ok(MemberOutcome::Done { .. }) => {
                tracing::info!(by = %who.user, user = %user, admin, "관리자 바꿈");
                broadcast_directory(app, who);
                None
            }
            Ok(MemberOutcome::Unchanged) => None,
            Ok(MemberOutcome::LastAdmin) => Some(ServerFrame::Error {
                code: ErrorCode::LastAdmin,
                message: "org.admin".into(),
                r#ref: None,
            }),
            _ => Some(rules::protocol_error("org.admin")),
        },
        ClientFrame::MemberRemove { user } => {
            let now = app.effects.clock.now().0;
            let (reply, removed) = {
                // 폐기 커밋 → directory.update 사이에 그룹 변경 전달이 끼지 않게(묶음 16 §3a ④).
                let _order = app
                    .group_order
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                member_remove(app, who, &user, now)
            };
            // #599: 내보낸 사람의 폐기된 기기가 보낸 확정 전 Commit — group_order 를 놓은 뒤.
            if removed {
                crate::mls_group::void_revoked_senders(app);
            }
            reply
        }
        // run() 이 dispatch 전에 처리한다(나간 뒤 이 연결을 닫아야 해서).
        ClientFrame::MemberLeave => None,
        ClientFrame::DeviceName { name } => device_name(app, who, &name),
        // 원격 relay 의 관리자 누구나(묶음 5). 응답은 로그에 남기지 않는다.
        ClientFrame::ServerStatus => {
            let org = app
                .config
                .remote
                .then(|| app.db.user_org(&who.user).ok().flatten())
                .flatten()
                .filter(|_| app.db.is_org_admin(&who.user).unwrap_or(false));
            let Some(org) = org else {
                return Some(rules::protocol_error("server.status"));
            };
            Some(match crate::status::server_status(app, &org) {
                Some(s) => ServerFrame::ServerStatus(Box::new(s)),
                None => ServerFrame::Error {
                    code: ErrorCode::Internal,
                    message: "server.status".into(),
                    r#ref: None,
                },
            })
        }
        ClientFrame::Ping => Some(ServerFrame::Pong),
        ClientFrame::KeyPackagesPublish {
            items,
            last_resort,
            reset,
        } => crate::mls::publish(app, who, &items, last_resort.as_deref(), reset),
        ClientFrame::KeyPackagesClaim { device_ids } => crate::mls::claim(app, who, &device_ids),
        ClientFrame::GroupInfoGet { group } => Some(crate::mls::group_info_get(app, who, &group)),
        ClientFrame::CommitVote {
            group,
            epoch,
            commit_hash,
            ack,
        } => {
            crate::mls_group::vote(app, who, &group, epoch, &commit_hash, ack);
            None
        }
        ClientFrame::Pong => None,
        ClientFrame::Hello { .. } | ClientFrame::Auth { .. } => {
            Some(rules::protocol_error("이미 인증됨"))
        }
    }
}

/// 선택 이름 필드 검사 — 없으면 `Ok(None)`, 있으면 `check` 를 통과한 값.
fn optional<E>(
    raw: Option<&str>,
    check: fn(&str) -> Result<String, E>,
) -> Result<Option<String>, E> {
    raw.map(check).transpose()
}

fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `session.publish.audience` 검사(묶음 20 §2): 없거나 `org` 면 `Some(None)`(조직 전체). `people` 은 1~256명, 중복 없음,
/// 나 자신 없음 — 어기면 `None`(error{protocol}). 지금 내 조직에 없는 아이디는 빼고 저장한다(내보낸·나간 사람 행은 같은 조직이라
/// 남는다 — 라우팅에서 범위 밖으로 친다).
fn checked_audience(
    app: &Relay,
    me: &str,
    a: Option<lodelai_protocol::ws::Audience>,
) -> Option<Option<Vec<String>>> {
    use lodelai_protocol::ws::AudienceKind;
    let Some(a) = a else { return Some(None) };
    match a.kind {
        AudienceKind::Org => a.users.is_empty().then_some(None),
        AudienceKind::People => {
            let org = app.db.user_org(me).ok().flatten()?;
            let mut seen = std::collections::HashSet::new();
            let shape_ok = !a.users.is_empty()
                && a.users.len() <= AUDIENCE_MAX
                && a.users
                    .iter()
                    .all(|u| u.as_str() != me && seen.insert(u.as_str()));
            if !shape_ok {
                return None;
            }
            // 지금 내 조직에 없는 아이디(모름·다른 조직으로 옮김)는 거절하지 않고 뺀다(d3284b3c) — 주인 코어가 쥔 옛 범위로 다시
            // publish 할 때마다 거절되지 않게. 좁히는 쪽으로만 틀린다. 다 빠지면 빈 목록(주인만).
            Some(Some(
                a.users
                    .into_iter()
                    .map(String::from)
                    .filter(|u| app.db.user_org(u).ok().flatten().as_deref() == Some(org.as_str()))
                    .collect(),
            ))
        }
    }
}

/// 옛 판 연결로 나갈 프레임을 그 판 꼴로 낮춘다(#598 ② 계약 4절 — 판이 섞여 도는 동안의 안전망). 판 13 이상은 그대로.
/// - typing(#613): 판 11 아래엔 보내지 않는다(`None`).
/// - 전체 directory: 판 13 아래엔 세션 항목의 agent·no, 사람 항목 recovery 의 postponed(#737)를 뺀다(12 앱은
///   additionalProperties false).
/// - error `device_unconfirmed`(#737): 판 13 아래엔 `protocol` 로.
/// - `device.revoked`·`error{device_revoked}` 의 `by: admin_device`(#737): 판 13 아래엔 `admin` 으로.
/// - directory·directory.update: `DirectoryDevice.v` 를 뺀다(9 앱의 DirectoryDevice 는 additionalProperties false).
/// - status `done`: `aborted{abort_reason: turn_ended}` 로(9 앱은 done 을 모른다 — 지금과 같은 '중단' 표시).
///
/// 문자열에 그 표식이 없으면 파싱하지 않는다(대부분의 프레임).
pub fn for_version(text: Utf8Bytes, v: u64) -> Option<Utf8Bytes> {
    if v >= SESSION_FIELDS_FROM {
        return Some(text);
    }
    let s = text.as_str();
    // 판 11 아래 앱은 typing 을 모른다(#613 계약 §5) — 보내지 않는다.
    if v < crate::presence::TYPING_FROM && s.contains("\"t\":\"typing\"") {
        return None;
    }
    // 판 13 아래 앱의 전체 `directory`(접속·directory.list 답)는 세션 항목이 모르는 칸을 거절한다(additionalProperties
    // false·deny_unknown_fields) — 13 칸 agent·no 를 뺀다(백엔드 리뷰 Y2). directory.update 는 모르는 칸을 받으니 그대로.
    let full_dir = s.contains("\"t\":\"directory\"");
    let old = v < 10;
    let dir_v = old && s.contains("\"t\":\"directory");
    let done = old && s.contains("\"t\":\"status\"") && s.contains("\"state\":\"done\"");
    let unconfirmed = s.contains("\"device_unconfirmed\"");
    let admin_device = s.contains("\"admin_device\"");
    if !full_dir && !dir_v && !done && !unconfirmed && !admin_device {
        return Some(text);
    }
    let Ok(mut f) = serde_json::from_str::<serde_json::Value>(s) else {
        return Some(text);
    };
    if full_dir && f["t"] == "directory" {
        for x in f["sessions"].as_array_mut().into_iter().flatten() {
            if let Some(o) = x.as_object_mut() {
                o.remove("agent");
                o.remove("no");
                o.remove("offline");
            }
        }
        // #737: 12 앱의 DirectoryRecovery 도 additionalProperties false.
        for p in f["people"].as_array_mut().into_iter().flatten() {
            if let Some(o) = p["recovery"].as_object_mut() {
                o.remove("postponed");
            }
        }
    }
    // #737: 12 앱의 error.code 는 닫힌 enum — 모르는 device_unconfirmed 는 protocol 로(전과 같은 거절).
    if unconfirmed && f["t"] == "error" && f["code"] == "device_unconfirmed" {
        f["code"] = serde_json::Value::String("protocol".into());
    }
    // #737: 12 앱의 by 도 닫힌 enum — 관리자의 옛 기기 끊기는 admin 으로(전과 같은 문구).
    if admin_device
        && (f["t"] == "device.revoked" || f["t"] == "error")
        && f["by"] == "admin_device"
    {
        f["by"] = serde_json::Value::String("admin".into());
    }
    if dir_v {
        for p in f["people"].as_array_mut().into_iter().flatten() {
            for d in p["devices"].as_array_mut().into_iter().flatten() {
                if let Some(o) = d.as_object_mut() {
                    o.remove("v");
                }
            }
        }
    }
    if done && f["t"] == "status" && f["state"] == "done" {
        f["state"] = serde_json::Value::String("aborted".into());
        f["abort_reason"] = serde_json::Value::String("turn_ended".into());
    }
    Some(Utf8Bytes::from(f.to_string()))
}

/// 전체 `directory` 세션 항목에 agent(Codex C2)·no(관문 Y2) 를 싣는 판 — 그 아래 연결엔 [`for_version`] 이 뺀다.
const SESSION_FIELDS_FROM: u64 = 13;

/// 관리자 내보내기(`member.remove`, 묶음 5) — 호출자가 `group_order` 를 쥔 채. 응답과 내보냈는지.
fn member_remove(app: &Relay, who: &Authed, user: &str, now: i64) -> (Option<ServerFrame>, bool) {
    match app.db.member_remove(&who.user, user, now) {
        // 순서: 폐기 커밋 → 그 사람의 연결에 device.revoked{by:admin} → 같은 조직에 directory.update → 그 사람 연결 닫음.
        Ok(MemberOutcome::Done { .. }) => {
            tracing::info!(by = %who.user, user = %user, "내보냄");
            app.conns.send_user(
                user,
                &ServerFrame::DeviceRevoked {
                    device_id: None,
                    by: Some(RevokedBy::Admin),
                    at: at_of(now),
                },
            );
            announce_org_removal(app, &who.user);
            app.conns.close_user(user);
            (None, true)
        }
        _ => (Some(rules::protocol_error("member.remove")), false),
    }
}

/// 자기 폐기·조직 나가기 응답 뒤 앱이 읽고 닫기를 기다리는 상한(#622). 앱은 받자마자 닫으므로 보통 바로 끝난다.
pub const REVOKED_LINGER: std::time::Duration = std::time::Duration::from_secs(2);

/// #622: 요청한 연결은 앱이 `device.revoked` 를 읽고 스스로 닫을 때까지(최대 [`REVOKED_LINGER`]) 열어 둔다. 바로 닫으면 앱이 앞서
/// 받은 프레임(duty·directory 등)에 답해 쓰다가 끊긴 연결에 막혀, 버퍼에 와 있던 응답을 읽기 전에 연결을 버리고 요청을
/// 실패(Unreachable)로 끝낸다 — 폐기·나가기는 됐는데 사람에게 오류가 뜬다. 그동안 받은 프레임은 버린다.
async fn linger_until_closed<S, E>(stream: &mut S)
where
    S: futures_util::Stream<Item = Result<Message, E>> + Unpin,
{
    let _ = tokio::time::timeout(REVOKED_LINGER, async {
        while let Some(Ok(m)) = stream.next().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}

/// `people` 범위 상한(묶음 20 §1).
pub const AUDIENCE_MAX: usize = 256;

/// 같은 조직의 사람·공개 세션(+ hosted 면 조직·팀·이메일, #355). 조직 밖은 빈 결과.
pub fn directory(app: &Relay, user: &str) -> DirectoryBody {
    let Ok(Some(org)) = app.db.user_org(user) else {
        return DirectoryBody::default();
    };
    // M1 `local` 은 orgs 행이 없다 — 조직·팀·이메일을 싣지 않는다.
    let org_info = app.db.org_info(&org).ok().flatten();
    let hosted = org_info.is_some();
    let server = &app.config.server_name;
    // 이 받는 사람이 초대한 사람(M1 결함 ①) — 받는 사람마다 다르다(누가 누구를 초대했는지는 퍼지지 않는다).
    // 받는 사람을 초대한 사람(§17.3 `invited_me`) — 본인은 가입 때 이미 봤으니 새로 드러나는 것은 없다.
    let (invited, inviter) = if hosted {
        (
            app.db.invited_by(user).unwrap_or_default(),
            app.db.inviter_of(user).ok().flatten(),
        )
    } else {
        (std::collections::HashSet::new(), None)
    };
    // 접속 표시(묶음 14 B1): 숨긴 사람의 것은 싣지 않고, 받는 사람이 숨겼으면 아무의 것도 싣지 않는다(맞교환).
    let hidden = app.db.presence_hidden_in_org(&org).unwrap_or_default();
    let avatars = app.db.avatars_in_org(&org).unwrap_or_default();
    let sees_presence = !hidden.contains(user);
    // #737: 관리자는 기기 바꾸는 중인 사람의 옛 기기(걸기 대상)의 마지막 접속(일 단위)을 본다 — '옛 기기 끊기' 판단 재료.
    let viewer_admin = app.db.is_org_admin(user).unwrap_or(false);
    let now_ms = app.effects.clock.now().0;
    let people = app
        .db
        .people_in_org(&org)
        .unwrap_or_default()
        .into_iter()
        .map(|(u, display)| {
            let (email, teams) = if hosted {
                let (e, t) = app.db.user_meta(&u).unwrap_or_default();
                (e, Some(t))
            } else {
                (None, None)
            };
            let certs = app.db.device_certs_of(&u).unwrap_or_default();
            let my_online = if u == user {
                app.conns.online_devices(&u)
            } else {
                Vec::new()
            };
            let switching_targets: Vec<String> = if viewer_admin && u != user {
                app.db
                    .recovery(&u)
                    .ok()
                    .flatten()
                    .filter(|r| r.state == crate::db::RecoveryState::Scheduled)
                    .map(|r| r.targets)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let online =
                (sees_presence && !hidden.contains(&u)).then(|| app.presence.online(app, &u));
            DirectoryPerson {
                online,
                avatar: avatars.get(&u).cloned(),
                invited_by_me: invited.contains(&u).then_some(true),
                invited_me: (inviter.as_deref() == Some(u.as_str())).then_some(true),
                address: format!("{u}@{server}"),
                display,
                email,
                teams,
                devices: app
                    .db
                    .devices_of(&u)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|d| DirectoryDevice {
                        certs: certs
                            .iter()
                            .filter(|(t, ..)| *t == d.device_id)
                            .map(|(_, signer, sig)| DeviceCert {
                                signer: signer.clone(),
                                sig: sig.clone(),
                            })
                            .collect(),
                        // 내 기기에만(§12-27 ⓑ) — 동료의 접속 시각은 새지 않는다. 예외(#737): 관리자에게 기기 바꾸는 중인
                        // 사람의 옛 기기(걸기 대상)만.
                        last_seen_at: d
                            .last_seen_day
                            .filter(|_| u == user || switching_targets.contains(&d.device_id))
                            .and_then(|t| lodelai_effects::UnixMillis(t).to_rfc3339().ok()),
                        // #577: 같은 규칙 — 내 기기에만(마지막으로 붙어 있던 시각, ms). 지금 붙어 있으면 이 디렉터리를 만든
                        // 시각(코어 seen_since_me — 새 기기 추가 전부터 끊김 없이 붙어 있던 옛 기기도 '봤다'로).
                        last_auth_at: d
                            .last_auth_ms
                            .filter(|_| u == user)
                            .map(|t| {
                                if my_online.contains(&d.device_id) {
                                    now_ms
                                } else {
                                    t
                                }
                            })
                            .and_then(|t| lodelai_effects::UnixMillis(t).to_rfc3339().ok()),
                        device_id: d.device_id,
                        device_pubkeys: DevicePubkeys {
                            ed25519: d.ed25519,
                            x25519: d.x25519,
                            x25519_sig: d.x25519_sig,
                        },
                        added_at: lodelai_effects::UnixMillis(d.created_ms).to_rfc3339().ok(),
                        // 기기 이름은 요청한 사람 자신의 항목에만(#490 — 실명이 들어가기 쉬움).
                        name: if u == user { d.name } else { None },
                        // 앱 판(#598 ②) — 모두에게(보내는 코어가 10 전용 칸을 실을지 가른다). 9 연결엔 쓰기 직전에 뺀다.
                        v: d.hello_v.and_then(|v| u64::try_from(v).ok()),
                    })
                    .collect(),
                revocations: crate::mls::needed_revocations(app, &u)
                    .into_iter()
                    .map(|r| DirectoryRevocation {
                        certs: certs
                            .iter()
                            .filter(|(t, ..)| *t == r.device_id)
                            .map(|(_, signer, sig)| DeviceCert {
                                signer: signer.clone(),
                                sig: sig.clone(),
                            })
                            .collect(),
                        added_at: lodelai_effects::UnixMillis(r.created_ms)
                            .to_rfc3339()
                            .unwrap_or_default(),
                        device_id: r.device_id,
                        ed25519: r.ed25519,
                        x25519: r.x25519,
                        at: r.proof.at,
                        signer: r.proof.signer,
                        sig: r.proof.sig,
                    })
                    .collect(),
                recovery: crate::recovery::directory_view(app, user, &u),
            }
        })
        .collect();
    let sessions = app
        .db
        .sessions_in_org(&org)
        .unwrap_or_default()
        .into_iter()
        // 묶음 20: 받는 사람이 주인이거나 범위 안인 세션만 — 범위 목록 자체는 싣지 않는다.
        .filter(|s| s.reaches(user))
        .map(|s| DirectorySession {
            offline: (s.offline && s.liveness_is_dead()).then_some(true),
            address: format!("{}@{server}/{}", s.user, s.slug),
            grade: s.grade,
            liveness: s.liveness,
            display: s.display,
            title: s.title,
            folder: s.folder,
            project: s
                .project
                .map(|(id, name)| crate::frames::ProjectRef { id, name }),
            busy: s.busy.then_some(true),
            agent: s.agent,
            no: s.no,
        })
        .collect();
    let teams = hosted.then(|| {
        app.db
            .teams_of_org(&org)
            .unwrap_or_default()
            .into_iter()
            .map(|(id, name)| DirectoryTeam { id, name })
            .collect()
    });
    DirectoryBody {
        people,
        sessions,
        org: org_info.map(|(name, admins)| DirectoryOrg {
            avatar: app.db.org_avatar(&org).ok().flatten(),
            id: org.clone(),
            name,
            admins,
        }),
        teams,
    }
}

/// 그 사용자의 `groups`(묶음 16): 지금 멤버인 그룹·마지막 seq·조직 빠짐으로 나간 멤버(§3a ④).
fn groups_frame(app: &Relay, user: &str) -> Result<ServerFrame, crate::db::DbError> {
    // 그룹 끔(묶음 16 §3b): 빈 목록 — 접속 때 프레임·조직 빠짐 힌트도 이 빈 목록으로 나가지 않는다.
    if !app.config.groups {
        return Ok(ServerFrame::Groups(Vec::new()));
    }
    let server = &app.config.server_name;
    Ok(ServerFrame::Groups(
        app.db
            .groups_of(user)?
            .into_iter()
            .map(|g| {
                (
                    format!("+{}@{server}", g.gid),
                    g.seq,
                    g.org_left
                        .into_iter()
                        .map(|(u, s)| (format!("{u}@{server}"), s))
                        .collect(),
                )
            })
            .collect(),
    ))
}

/// 그룹이 하나라도 있을 때만 [`groups_frame`](읽기 오류면 없음).
fn groups_frame_if_any(app: &Relay, user: &str) -> Option<ServerFrame> {
    match groups_frame(app, user) {
        Ok(ServerFrame::Groups(items)) if !items.is_empty() => Some(ServerFrame::Groups(items)),
        _ => None,
    }
}

/// 조직 빠짐(내보내기·나가기) 커밋 뒤 알림(묶음 16 §3a ④): 같은 조직에 `directory.update`, 그다음 그룹이 있는 사람에게 `groups`
/// (조직 빠짐 힌트). 부르는 쪽이 `group_order` 를 잡고 커밋부터 여기까지 한 줄로 세운다 — 그 뒤 어떤 group 메시지보다 먼저 간다.
pub fn announce_org_removal(app: &Relay, user: &str) {
    broadcast_directory_of(app, user);
    // 묶음 22: 그 사람의 잎을 빼는 org_left Commit 일(remove_user)을 남은 접속 기기에.
    crate::mls::dispatch_duties(app, None);
    let org = app.db.user_org(user).ok().flatten();
    for u in app.conns.users() {
        if app.db.user_org(&u).ok().flatten() != org || app.db.is_removed(&u).unwrap_or(true) {
            continue;
        }
        if let Some(f) = groups_frame_if_any(app, &u) {
            app.conns.send_user(&u, &f);
        }
    }
}

/// 같은 조직의 접속 중인 사용자들에게 `directory.update`(전체 목록).
/// `device.name`(#490 묶음 28 §4): NFC·규칙 검사 → 같은 값이면 아무것도 안 함 → 기기당 시간당 상한 → 저장 → 본인 연결들에만
/// directory.update(이름은 본인 항목에만 실리므로 동료에게는 바뀐 것이 없다). 이름은 로그에 싣지 않는다.
fn device_name(app: &Relay, who: &Authed, raw: &str) -> Option<ServerFrame> {
    let Ok(name) = lodelai_protocol::display_name::normalize_device_name(raw) else {
        return Some(rules::protocol_error("device.name 형식"));
    };
    match app.db.device_name(&who.device_id) {
        Ok(Some(cur)) if cur == name => return None,
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return Some(rules::protocol_error("device.name")),
    }
    if !app
        .device_name_limiter
        .allow(&who.device_id, app.effects.clock.now())
    {
        return Some(ServerFrame::Error {
            code: ErrorCode::RateLimited,
            message: "device.name".into(),
            r#ref: None,
        });
    }
    match app.db.set_device_name(&who.device_id, name.as_deref()) {
        Ok(true) => {
            with_directory_order(app, || {
                let frame = ServerFrame::DirectoryUpdate(directory(app, &who.user));
                app.conns.send_user(&who.user, &frame);
            });
            None
        }
        Ok(false) => None,
        Err(_) => Some(rules::protocol_error("device.name")),
    }
}

pub fn broadcast_directory(app: &Relay, who: &Authed) {
    broadcast_directory_of(app, &who.user);
}

/// [`broadcast_directory`] 를 사용자 이름으로(연결 밖에서).
pub fn broadcast_directory_of(app: &Relay, user: &str) {
    broadcast_directory_to(app, user, false);
}

/// 접속 변화(묶음 14 B1): 그 사용자 본인에게는 보내지 않는다 — 자기 접속은 새 소식이 아니고, 등록 전에 심어 둔 내 기기를
/// 디렉터리가 덮는 창(relay-client 의 '목록에 없으면 폐기')을 늘리지 않는다.
pub fn broadcast_presence_of(app: &Relay, user: &str) {
    broadcast_directory_to(app, user, true);
}

/// 디렉터리 모습을 만들고 큐에 넣는 일을 [`crate::Relay::directory_order`] 안에서(#702). 만든 순서 = 큐에 들어간 순서라서
/// 받는 쪽은 늘 마지막에 만든 모습을 마지막에 받는다(연결이 여럿이어도, 다시 붙어도 — 접속 때 모습도 이 안에서 만든다).
pub fn with_directory_order<T>(app: &Relay, f: impl FnOnce() -> T) -> T {
    let _order = app
        .directory_order
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

fn broadcast_directory_to(app: &Relay, user: &str, skip_self: bool) {
    with_directory_order(app, || broadcast_directory_locked(app, user, skip_self));
}

fn broadcast_directory_locked(app: &Relay, user: &str, skip_self: bool) {
    let org = app.db.user_org(user).ok().flatten();
    for u in app.conns.users() {
        if skip_self && u == user {
            continue;
        }
        // 내보낸 사람·나간 사람(연결이 닫히기 전)에게는 보내지 않는다 — 이미 조직 밖이다.
        if app.db.user_org(&u).ok().flatten() == org && !app.db.is_removed(&u).unwrap_or(true) {
            app.conns
                .send_user(&u, &ServerFrame::DirectoryUpdate(directory(app, &u)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #702: 여러 스레드가 거의 같은 때 사람을 더하고 방송해도, 받는 연결의 디렉터리 모습은 뒤로 가지 않는다(사람 수가 줄지
    /// 않음) — 만든 순서 = 큐 순서. 잠금이 없으면 부하에서 낡은 모습이 새 모습 뒤에 들어간다.
    #[test]
    fn 거의_같은_때의_방송도_낡은_디렉터리가_새_것을_덮지_않는다() {
        const THREADS: usize = 8;
        const EACH: usize = 25;
        let app = crate::Relay::new(
            crate::Config::local("local"),
            crate::Effects::system(),
            crate::db::Db::memory().unwrap(),
        );
        app.db
            .register_device("bob", None, "b1", "e", "x", "s", 0, false)
            .unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let bob = Authed {
            user: "bob".into(),
            device_id: "b1".into(),
            v: 12,
        };
        app.conns.add(&bob, Tx(tx));
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let app = &app;
                s.spawn(move || {
                    for i in 0..EACH {
                        let u = format!("u{t}x{i}");
                        app.db
                            .register_device(
                                &u,
                                None,
                                &format!("d{t}x{i}"),
                                "e",
                                "x",
                                "s",
                                0,
                                false,
                            )
                            .unwrap();
                        broadcast_directory_of(app, &u);
                    }
                });
            }
        });
        let mut seen = Vec::new();
        while let Ok(f) = rx.try_recv() {
            let v: serde_json::Value = serde_json::from_str(f.as_str()).unwrap();
            assert_eq!(v["t"], "directory.update");
            seen.push(v["people"].as_array().unwrap().len());
        }
        assert_eq!(seen.len(), THREADS * EACH);
        assert!(
            seen.windows(2).all(|w| w[0] <= w[1]),
            "디렉터리가 뒤로 갔다: {seen:?}"
        );
        assert_eq!(seen.last(), Some(&(THREADS * EACH + 1)));
    }

    /// 묶음 22 §5d·⑦: 같은 프레임을 200 연결에 보내도 한 벌을 나눠 쓴다(연결마다 복제하지 않음).
    /// #598 ②: 판 9 연결엔 DirectoryDevice.v 를 빼고 status done 을 aborted{turn_ended} 로, 10 은 그대로.
    #[test]
    fn 판_9_연결엔_10_전용_칸과_상태를_낮춘다() {
        let dir = r#"{"t":"directory.update","people":[{"address":"a@x","devices":[{"device_id":"d1","v":10}]}]}"#;
        let st = r#"{"t":"status","msg_id":"m","state":"done","at":"2026-10-30T00:00:00Z"}"#;
        let other = r#"{"t":"status","msg_id":"m","state":"replied","at":"2026-10-30T00:00:00Z"}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        assert_eq!(v(dir, 9)["people"][0]["devices"][0].get("v"), None);
        assert_eq!(v(dir, 10)["people"][0]["devices"][0]["v"], 10);
        assert_eq!(v(st, 9)["state"], "aborted");
        assert_eq!(v(st, 9)["abort_reason"], "turn_ended");
        assert_eq!(v(st, 10)["state"], "done");
        assert_eq!(
            for_version(Utf8Bytes::from(other), 9).unwrap().as_str(),
            other,
            "표식 없으면 손대지 않음"
        );
        // #613: typing 은 판 11 아래 연결엔 보내지 않는다.
        let ty = r#"{"t":"typing","from":"a@x","on":true}"#;
        assert!(for_version(Utf8Bytes::from(ty), 10).is_none());
        assert!(for_version(Utf8Bytes::from(ty), 9).is_none());
        assert_eq!(for_version(Utf8Bytes::from(ty), 11).unwrap().as_str(), ty);
        assert_eq!(v(st, 11)["state"], "done");
    }

    /// 백엔드 리뷰 Y2: 판 13 아래 연결의 전체 directory 에선 세션 항목의 agent·no 를 뺀다(12 앱은 모르는 칸이 든 directory 를
    /// 통째로 못 읽는다). directory.update 는 모르는 칸을 받으니 그대로, 13 은 그대로. 판 9 의 기기 v 빼기도 같이 된다.
    #[test]
    fn 판_13_아래_전체_directory_엔_세션_agent_no_를_뺀다() {
        let full = r#"{"t":"directory","people":[{"address":"a@x","devices":[{"device_id":"d1","v":10}]}],"sessions":[{"address":"a@x/s","grade":"task","liveness":"dead","agent":"codex","no":6,"offline":true}]}"#;
        let upd = r#"{"t":"directory.update","people":[],"sessions":[{"address":"a@x/s","grade":"task","liveness":"dead","agent":"codex","no":6}]}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        for n in [9, 10, 11, 12] {
            let s = &v(full, n)["sessions"][0];
            assert!(
                s.get("agent").is_none() && s.get("no").is_none() && s.get("offline").is_none(),
                "{n}: {s}"
            );
            assert_eq!(s["address"], "a@x/s");
            assert_eq!(v(upd, n)["sessions"][0]["no"], 6, "{n}: update 는 그대로");
        }
        assert_eq!(v(full, 9)["people"][0]["devices"][0].get("v"), None);
        assert_eq!(v(full, 12)["people"][0]["devices"][0]["v"], 10);
        assert_eq!(
            for_version(Utf8Bytes::from(full), 13).unwrap().as_str(),
            full
        );
    }

    /// #737: 판 13 아래엔 전체 directory 의 recovery.postponed 를 빼고, error device_unconfirmed 는 protocol 로.
    #[test]
    fn 판_13_아래엔_postponed_를_빼고_device_unconfirmed_는_protocol() {
        let full = r#"{"t":"directory","people":[{"address":"a@x","devices":[],"recovery":{"state":"scheduled","at":"2026-11-03T00:00:00.000Z","postponed":true}}],"sessions":[]}"#;
        let err = r#"{"t":"error","code":"device_unconfirmed","message":"org.admin"}"#;
        let v = |t: &str, n| {
            serde_json::from_str::<serde_json::Value>(
                for_version(Utf8Bytes::from(t), n).unwrap().as_str(),
            )
            .unwrap()
        };
        for n in [9, 12] {
            let r = &v(full, n)["people"][0]["recovery"];
            assert!(r.get("postponed").is_none(), "{n}: {r}");
            assert_eq!(r["state"], "scheduled");
            assert_eq!(v(err, n)["code"], "protocol");
        }
        assert_eq!(v(full, 13)["people"][0]["recovery"]["postponed"], true);
        assert_eq!(v(err, 13)["code"], "device_unconfirmed");
        let rv = r#"{"t":"device.revoked","by":"admin_device","at":"2026-11-03T00:00:00.000Z"}"#;
        let er = r#"{"t":"error","code":"device_revoked","by":"admin_device","message":"auth"}"#;
        assert_eq!(v(rv, 12)["by"], "admin");
        assert_eq!(v(er, 12)["by"], "admin");
        assert_eq!(v(rv, 13)["by"], "admin_device");
    }

    #[test]
    fn send_devices_shares_one_copy() {
        let conns = Connections::default();
        let mut rxs = Vec::new();
        let mut ids = Vec::new();
        for i in 0..200 {
            let (t, r) = mpsc::unbounded_channel::<Utf8Bytes>();
            let who = Authed {
                user: "alice".into(),
                device_id: format!("d{i}"),
                v: u64::from(lodelai_protocol::PROTOCOL_VERSION),
            };
            conns.add(&who, Tx(t));
            ids.push(who.device_id);
            rxs.push(r);
        }
        let frame = ServerFrame::Deliver {
            message: serde_json::json!({"body": "x".repeat(40_000)}),
            group_seq: None,
        };
        conns.send_devices("alice", &ids, &frame);
        let got: Vec<Utf8Bytes> = rxs.iter_mut().map(|r| r.try_recv().unwrap()).collect();
        let first = got[0].as_str().as_ptr();
        assert!(got.iter().all(|t| t.as_str().as_ptr() == first));
        assert!(got[0].len() > 40_000);
    }
}
