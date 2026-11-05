//! lodelai-relay — 중계 서버 라이브러리 (U4, #56). 설계: `docs/design/protocol.md` §7, `security.md` §6·§7.2, ADR 0002·0006.
//!
//! - [`Relay`]: 설정·효과(`Clock`/`IdGen`/`Rng`)·DB 를 받아 axum [`axum::Router`] 를 만든다. 시험은 이걸 in-process 로 올린다.
//! - [`ws`]: WebSocket 핸드셰이크(hello → challenge → auth → ready)와 프레임 루프.
//! - [`rules`]: protocol §7.2 서버 규칙 0~7. `unroutable` 은 **한 함수** [`rules::unroutable_nack`] 에서만 만든다(바이트 동일성).
//! - [`db`]: SQLite(`users`, `devices`, `sessions_public`, `envelopes`, `blocks`).
//! - [`http`]: `/v1/healthz`, `/v1/devices`(M1 로컬: 등록 토큰, hosted 가입이 켜져 있으면 이메일 가입 토큰도), `/v1/signup`·`/v1/signup/verify`(#339).
//! - [`mail`]: 가입 확인 메일(지금은 개발용 가짜 — 파일).
//!
//! - [`cli`]: 실행 파일 인자·하위 명령과 진입점 [`run`](`main.rs`·앱 사이드카가 부름).
//!
//! 서버는 본문을 해석하지 않는다. 라우팅에 필요한 헤더만 읽는다.

pub mod blob;
pub mod cli;
pub mod db;
pub mod frames;
pub mod http;
pub mod limiter;
pub mod mail;
pub mod mls;
pub mod mls_group;
pub mod presence;
pub mod recovery;
pub mod rules;
pub mod status;
pub mod ws;

pub use cli::run;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use lodelai_effects::{Clock, IdGen, Rng};
use tokio::net::TcpListener;

/// 주입되는 효과. 제품은 `SystemClock`/`OsRng`/`UlidGen::system()`, 시험은 testkit 의 고정 구현.
#[derive(Clone)]
pub struct Effects {
    pub clock: Arc<dyn Clock>,
    pub ids: Arc<dyn IdGen>,
    pub rng: Arc<dyn Rng>,
}

impl Effects {
    pub fn system() -> Self {
        Self {
            clock: Arc::new(lodelai_effects::SystemClock),
            ids: Arc::new(lodelai_effects::UlidGen::system()),
            rng: Arc::new(lodelai_effects::OsRng),
        }
    }
}

/// 서버 설정.
#[derive(Clone, Debug)]
pub struct Config {
    /// `ready.server` 와 challenge 서명에 들어가는 서버 이름. 주소의 `@<server>` 부분과 같다.
    pub server_name: String,
    /// 이 포트로만 `Host` 를 받는다. `bind` 뒤에 실제 포트로 채운다.
    pub port: u16,
    /// 사용자별 초당 프레임 수(토큰 버킷 리필). 버킷 크기는 `rate_burst`.
    pub rate_per_sec: u32,
    pub rate_burst: u32,
    /// WebSocket 프레임 최대 크기. 본문 상한(32 KiB)보다 조금 큰 값 — 서명 검증 전에 큰 프레임을 끊는다.
    pub max_frame_bytes: usize,
    /// `POST /v1/devices` 등록 토큰. `None` 이면 등록을 닫는다. M1 은 앱이 stdin 으로 넘긴다.
    pub registration_token: Option<String>,
    /// 연결마다 서버가 `ping` 을 보내는 간격(protocol §7.2, 30초).
    pub ping_interval: std::time::Duration,
    /// 이만큼 아무 텍스트 프레임도 안 오면 연결을 끊는다. 클라이언트도 30초마다 `ping` 을 보내므로 세 번 놓친 셈.
    pub idle_timeout: std::time::Duration,
    /// 원격 relay(묶음 4, #364 — Cloudflare 등 프록시 뒤). 참이면 등록 토큰 경로는 끄고 이메일 가입·`ready.admin`·
    /// `server.status` 를 쓴다(`device.register` 는 묶음 5 에서 없앰 — 늘 protocol).
    pub remote: bool,
    /// 이 Host 도 받는다(공개 도메인 — `<도메인>`·`<도메인>:443`). Origin 이 있으면 거부는 그대로.
    pub public_host: Option<String>,
    /// Cloudflare Tunnel 뒤(#364): 연결이 loopback 일 때만 `CF-Connecting-IP` 를 클라이언트 IP 로 믿는다.
    pub behind_cloudflare: bool,
    /// 지금 개인정보 처리방침 판(묶음 5, `--privacy-version`, 날짜 문자열). 가입 메일 요청의 `privacy.version` 이 이것과
    /// 같아야 한다. `None`(로컬 개발)이면 판이 있기만 하면 받는다.
    pub privacy_version: Option<String>,
    /// 운영자 처리방침 주소(묶음 29 §1-4, `--privacy-url`, https 만). `GET /v1/privacy` 의 `url` — 없으면 싣지 않고 앱이
    /// hosted 기본을 쓴다.
    pub privacy_url: Option<String>,
    /// 대기 명단 주소(#737, hosted — `--waitlist-url`). 있으면 조직 만들기 허용이 없는 새 이메일의 verify 응답에
    /// `waitlist_url` 을 싣는다(앱이 코드 칸 대신 대기 명단 안내를 보인다).
    pub waitlist_url: Option<String>,
    /// 가입 메일 relay 전체 UTC 하루 상한(묶음 29 §1-3, env `LODELAI_MAIL_PER_DAY`, 기본 80 — Resend 무료 한도 아래).
    pub mail_per_day: i64,
    /// 데이터 폴더(`--data`) — `server.status` 의 디스크·DB 크기(묶음 5). `None`(메모리 DB 시험)이면 디스크를 판정하지 않는다.
    pub data_dir: Option<std::path::PathBuf>,
    /// 끊긴 뒤에도 이만큼은 접속 중으로 보인다(묶음 14 B1 — 60초).
    pub presence_grace: std::time::Duration,
    /// 기기의 마지막 연결이 끊긴 뒤 이만큼 지나도 다시 붙지 않으면 그 기기가 공개한 세션을 dead 로(#569 ③ — 10초).
    pub session_dead_grace: std::time::Duration,
    /// 같은 사용자의 접속 변화 `directory.update` 는 이 간격에 한 번까지(묶음 14 B1 — 30초).
    pub presence_coalesce: std::time::Duration,
    /// 접속 변화로 `directory.update` 를 보낼지(제품은 늘 켬). 다른 프레임의 순서를 보는 시험만 끈다 — 디렉터리의 `online`
    /// 값은 이것과 무관하게 실린다.
    pub presence_updates: bool,
    /// 묶음 22 §5a: 기기마다 받지 않은 Handshake 상한(넘으면 오래 기다린 그룹부터 비우고 `rejoin_needed`). 시험만 낮춘다.
    pub handshake_cap: crate::db::HandshakeCap,
    /// 첨부 폴더(묶음 15). 없으면 `data_dir/blobs`, 그것도 없으면(메모리 DB 시험) 임시 폴더.
    pub blob_dir: Option<std::path::PathBuf>,
    /// blob 폴더 디스크 남은 공간이 이보다 적으면 `blob.reserve` 가 `storage_full`(`--blob-min-free`, 기본 5 GiB).
    pub blob_min_free: u64,
    /// 사용자당 폐기 안 된 기기 상한(묶음 16 §3a, `--max-devices-per-user`, 기본 4). 넘는 등록은 409 `too_many_devices`.
    pub max_devices_per_user: usize,
    /// 원격 relay 의 코드 없는 조직 만들기(묶음 18 §2, `--org-create code|open`, 기본 `code`). 로컬 relay 는 상관없이 코드 없이 만든다.
    pub org_create_open: bool,
    /// `open` 일 때만 보는 조직 만들기 상한(묶음 18 §3).
    pub org_create_limits: OrgCreateLimits,
    /// 그룹(묶음 16 §3b). `Config` 기본은 `GROUPS_ENABLED`(묶음 22 부터 켬), 실행 파일은 `--groups` 가 있어야 켠다. 꺼지면 그룹 send·kind group 은 바이트 동일 `unroutable`,
    /// `groups.list` 는 빈 목록, 접속 때 `groups` 프레임·조직 빠짐 힌트 없음. DB 표는 그대로 만든다.
    pub groups: bool,
    /// 메일 확인 끊기(#577 §4): 건 뒤 이만큼 지나면 먼저 등록된 기기를 끊는다(기본 24h). 시험 relay 만 줄인다.
    pub recovery_wait: std::time::Duration,
    /// 막힘·건 쪽 취소 뒤 이만큼은 다시 걸 수 없다(`recover_refused{cooldown}`, 기본 24h). 끝난 걸기(done)가 디렉터리에
    /// 남는 시간도 이것이다.
    pub recovery_cooldown: std::time::Duration,
    /// 막기 3번을 세는 창(`recover_refused{exhausted}`, 기본 30일).
    pub recovery_block_window: std::time::Duration,
}

/// 코드 없는 조직 만들기 상한(묶음 18 §3). 성공한 만들기만 센다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgCreateLimits {
    /// 같은 이메일(`email_mac`)이 30일에 만든 수(`--org-create-per-email-30d`, 기본 3).
    pub per_email_30d: i64,
    /// 같은 IP 가 24시간에 만든 수(`--org-create-per-ip-day`, 기본 5 — 메모리).
    pub per_ip_day: u32,
    /// relay 전체 UTC 하루(`--org-create-per-day`, 기본 50).
    pub per_day: i64,
    /// 내보내지 않은 멤버가 있는 조직 수 상한(`--max-orgs`, 기본 50 — 10-26 결정) — 넘으면 403 `org_create_closed`.
    pub max_orgs: i64,
}

impl Default for OrgCreateLimits {
    fn default() -> Self {
        Self {
            per_email_30d: 3,
            per_ip_day: 5,
            per_day: 50,
            max_orgs: 50,
        }
    }
}

impl Config {
    pub fn local(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            port: 0,
            rate_per_sec: 20,
            rate_burst: 60,
            // relay·relay-client 가 같은 상수(#315). M1 평문 본문은 JSON 이스케이프로 최대 6배(제어 문자 \u00XX)가 되므로
            // 본문 상한 32 KiB 의 최악 + 헤더가 들어가야 한다.
            max_frame_bytes: lodelai_protocol::constants::WS_MAX_FRAME_BYTES as usize,
            registration_token: None,
            ping_interval: std::time::Duration::from_secs(30),
            idle_timeout: std::time::Duration::from_secs(90),
            remote: false,
            public_host: None,
            behind_cloudflare: false,
            privacy_version: None,
            privacy_url: None,
            waitlist_url: None,
            mail_per_day: crate::http::SIGNUP_LIMITS.global_day,
            data_dir: None,
            presence_grace: std::time::Duration::from_secs(60),
            session_dead_grace: std::time::Duration::from_secs(10),
            presence_coalesce: std::time::Duration::from_secs(30),
            presence_updates: true,
            handshake_cap: crate::db::HandshakeCap {
                count: 2_000,
                bytes: 64 * 1024 * 1024,
            },
            blob_dir: None,
            blob_min_free: 5 * 1024 * 1024 * 1024,
            max_devices_per_user: db::DEFAULT_MAX_DEVICES,
            org_create_open: false,
            org_create_limits: OrgCreateLimits::default(),
            groups: lodelai_protocol::constants::GROUPS_ENABLED,
            recovery_wait: std::time::Duration::from_secs(24 * 3600),
            recovery_cooldown: std::time::Duration::from_secs(24 * 3600),
            recovery_block_window: std::time::Duration::from_secs(30 * 24 * 3600),
        }
    }
}

/// 공유 상태. `Router` 의 `State`.
pub struct Relay {
    pub config: Config,
    pub effects: Effects,
    pub db: db::Db,
    pub conns: ws::Connections,
    /// 동료 접속 표시(묶음 14 B1, 메모리에만).
    pub presence: presence::Presence,
    /// 첨부 파일 폴더(묶음 15).
    pub blob_dir: std::path::PathBuf,
    /// 사용자별 `blob.reserve` 시간당 상한(묶음 15).
    pub blob_limiter: limiter::Limiter,
    /// 프로필 사진 올리기 예약(묶음 27 #427 — 사용자마다 시간당 AVATAR_RESERVE_PER_HOUR, 첨부 예산과 따로).
    pub avatar_limiter: limiter::Limiter,
    /// 기기 이름 바꾸기(#490 묶음 28 §4 — 기기마다 시간당 DEVICE_NAME_PER_HOUR, directory.update 폭주 막기).
    pub device_name_limiter: limiter::Limiter,
    pub limiter: limiter::Limiter,
    /// 클라이언트 IP 단위(#364): 인증 전 핸드셰이크·설정 코드 시도. IP 를 모르면(로컬) 보지 않는다.
    pub ip_limiter: limiter::Limiter,
    /// 가입 메일·초대 확인의 IP 상한(묶음 5 — 1시간 20번, 원격만, 메모리에만).
    pub signup_ip_limiter: limiter::Limiter,
    /// 코드 없는 조직 만들기의 IP 상한(묶음 18 §3 — 24시간에 `per_ip_day`, 성공한 뒤에만 쓴다, 메모리에만).
    pub org_create_ip_limiter: limiter::Limiter,
    /// 조직 만들기 코드 늦춤(relay 0.1.2): 가입 이메일당 틀린 코드 5번이면 1시간, IP 당 시도 20번/시간, relay 전체 200번/시간.
    pub setup_code_email_fails: limiter::LockWindow,
    pub setup_code_ip: limiter::LockWindow,
    pub setup_code_all: limiter::LockWindow,
    /// hosted 가입(`/v1/signup`, 이메일로 기기 추가 — #339). `None` 이면 가입 경로를 닫는다(M1 로컬 기본).
    pub mailer: Option<Arc<dyn mail::Mailer>>,
    /// `POST /v1/wipe` 를 받았다 — 이후 요청은 503(#328).
    pub wiped: std::sync::atomic::AtomicBool,
    /// 묶음 22 MLS: Commit 의 읽기 → 검증 → 적용을 한 줄로(같은 epoch 의 Commit 둘이 끼어들지 않게).
    pub mls_order: std::sync::Mutex<()>,
    /// 서버를 끝낸다([`serve`] 가 반환 — 정리 뒤 프로세스 종료).
    pub stop: tokio::sync::Notify,
    /// 프로세스 시작(`server.status.started_ms`).
    pub started_ms: i64,
    /// `server.status` 계산값 10초 캐시.
    pub status_cache: status::Cache,
    /// 그룹 변경 전달과 조직 빠짐(폐기 커밋 → directory.update)을 한 줄로 세운다(묶음 16 §3a ④) — 빠짐의 directory.update 가 그 뒤
    /// 어떤 group 메시지보다 먼저 가야 클라이언트마다 같은 상태가 된다.
    pub group_order: std::sync::Mutex<()>,
    /// 디렉터리 모습 만들기와 큐 넣기를 한 줄로(#702). 둘 사이가 벌어지면 거의 같은 때의 두 방송이 만든 순서와 다르게 큐에
    /// 들어가 낡은 모습이 새 모습을 덮는다(끊은 기기를 상대가 모름 → 새 기기 메시지 no_chain). `directory`·`directory.update` 를
    /// 보내는 곳은 모두 [`ws::with_directory_order`] 안에서 만들고 넣는다. 잠금 순서: `group_order` → 이것 → `conns`(거꾸로 잡지 않는다).
    pub directory_order: std::sync::Mutex<()>,
}

pub type App = Arc<Relay>;

/// 실제 인터넷에 없는 시험용 도메인인가(RFC 2606·6761: `.test`·`.localhost`·`.invalid`·`.example`). 원격 relay 가
/// 개발용 가짜 메일(`--dev-mail`)을 받는 것은 이런 공개 도메인일 때뿐이다(시험용 원격 relay, 묶음 5).
#[must_use]
pub fn is_test_domain(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    ["test", "localhost", "invalid", "example"]
        .iter()
        .any(|tld| h == *tld || h.ends_with(&format!(".{tld}")))
}

/// IP 당 인증 전 시도: 1분에 30번(버킷 30, 초당 0.5 회복).
pub const IP_PER_SEC: f64 = 0.5;
pub const IP_BURST: f64 = 30.0;
/// IP 당 가입 메일·초대 확인: 1시간에 20번(묶음 5).
pub const SIGNUP_IP_PER_HOUR: f64 = 20.0;

impl Relay {
    pub fn new(config: Config, effects: Effects, db: db::Db) -> App {
        Self::with_mailer(config, effects, db, None)
    }

    /// hosted 가입을 켠 relay(#339). `mailer` 가 확인 코드를 보낸다.
    pub fn with_mailer(
        config: Config,
        effects: Effects,
        db: db::Db,
        mailer: Option<Arc<dyn mail::Mailer>>,
    ) -> App {
        use lodelai_protocol::constants as c;
        let limiter = limiter::Limiter::new(config.rate_per_sec, config.rate_burst);
        let blob_dir = config
            .blob_dir
            .clone()
            .or_else(|| config.data_dir.as_ref().map(|d| d.join("blobs")))
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "lodelai-blobs-{}-{}",
                    std::process::id(),
                    effects.clock.now().0
                ))
            });
        blob::clear_tmp(&blob_dir);
        db.set_max_devices(config.max_devices_per_user);
        // #569 ③: 기동 때는 연결이 하나도 없다 — 꺼진 채 relay 가 다시 뜬 기기의 세션이 live 로 남지 않게.
        if let Err(e) = db.sessions_dead_all() {
            tracing::warn!(error = %e, "기동 때 공개 세션 dead 처리 실패");
        }
        let per_ip_day = f64::from(config.org_create_limits.per_ip_day);
        let started_ms = effects.clock.now().0;
        Arc::new(Self {
            config,
            effects,
            db,
            conns: ws::Connections::default(),
            presence: presence::Presence::default(),
            blob_dir,
            blob_limiter: limiter::Limiter::with_rate(
                c::BLOB_RESERVE_PER_HOUR as f64 / 3600.0,
                c::BLOB_RESERVE_PER_HOUR as f64,
            ),
            avatar_limiter: limiter::Limiter::with_rate(
                c::AVATAR_RESERVE_PER_HOUR as f64 / 3600.0,
                c::AVATAR_RESERVE_PER_HOUR as f64,
            ),
            device_name_limiter: limiter::Limiter::with_rate(
                c::DEVICE_NAME_PER_HOUR as f64 / 3600.0,
                c::DEVICE_NAME_PER_HOUR as f64,
            ),
            limiter,
            ip_limiter: limiter::Limiter::with_rate(IP_PER_SEC, IP_BURST),
            signup_ip_limiter: limiter::Limiter::with_rate(
                SIGNUP_IP_PER_HOUR / 3600.0,
                SIGNUP_IP_PER_HOUR,
            ),
            org_create_ip_limiter: limiter::Limiter::with_rate(per_ip_day / 86_400.0, per_ip_day),
            setup_code_email_fails: limiter::LockWindow::new(
                http::SETUP_CODE_EMAIL_FAILS,
                http::SETUP_CODE_THROTTLE_MS,
            ),
            setup_code_ip: limiter::LockWindow::new(
                http::SETUP_CODE_IP_PER_HOUR,
                http::SETUP_CODE_THROTTLE_MS,
            ),
            setup_code_all: limiter::LockWindow::new(
                http::SETUP_CODE_ALL_PER_HOUR,
                http::SETUP_CODE_THROTTLE_MS,
            ),
            mailer,
            wiped: std::sync::atomic::AtomicBool::new(false),
            mls_order: std::sync::Mutex::new(()),
            stop: tokio::sync::Notify::new(),
            started_ms,
            status_cache: status::Cache::default(),
            group_order: std::sync::Mutex::new(()),
            directory_order: std::sync::Mutex::new(()),
        })
    }

    /// axum Router. `port` 는 `Host` 검사에 쓰므로 바인딩 뒤의 실제 포트가 설정에 들어 있어야 한다.
    pub fn router(app: App) -> Router {
        Router::new()
            .route("/v1/healthz", get(http::healthz))
            .route("/v1/devices", post(http::register_device))
            .route("/v1/signup", post(http::signup))
            .route("/v1/signup/verify", post(http::signup_verify))
            .route("/v1/privacy", get(http::privacy))
            .route("/v1/invites/check", post(http::invites_check))
            .route("/v1/connected", get(http::connected))
            .route("/v1/wipe", post(http::wipe))
            .route("/v1/ws", get(ws::upgrade))
            // 첨부(묶음 15): 이 경로만 본문 상한을 끈다 — 길이는 예약값으로 핸들러가 센다.
            .route(
                "/v1/blobs/{blob_id}",
                axum::routing::put(blob::put)
                    .get(blob::get)
                    .layer(axum::extract::DefaultBodyLimit::disable()),
            )
            .layer(axum::middleware::from_fn_with_state(
                app.clone(),
                http::local_guard,
            ))
            .with_state(app)
    }

    /// 만료 스캔 한 번(`clock_expired`). 제품은 주기 태스크가, 시험은 직접 부른다.
    pub fn expire_tick(&self) -> usize {
        let n = rules::expire_tick(self);
        // #577: at 이 지난 메일 확인 끊기(재시작 뒤 지난 것도).
        recovery::tick(self);
        blob::sweep(self);
        // 묶음 16: 다시 받을 수 없게 된 그룹 로그 행.
        if let Err(e) = self.db.group_log_sweep() {
            tracing::warn!(error = %e, "그룹 로그 정리 실패");
        }
        // 묶음 18: 30일 지난 조직 만들기 기록(email_mac).
        if let Err(e) = self.db.org_creates_sweep(self.effects.clock.now().0) {
            tracing::warn!(error = %e, "조직 만들기 기록 정리 실패");
        }
        // 처리방침 0.2.0: 기한 지나고 30일 지난 조직 만들기 코드·승인(쓰지 않은 것).
        if let Err(e) = self.db.setup_codes_sweep(self.effects.clock.now().0) {
            tracing::warn!(error = %e, "조직 만들기 코드 정리 실패");
        }
        n
    }
}

/// DB 를 만지는 동기 작업을 비동기 작업자 밖(`spawn_blocking`)에서 돌린다(#169).
/// 패닉이면 `None` — 호출자는 그 연결·요청을 끝낸다(결정 없음으로 흘리지 않는다).
pub async fn blocking<T: Send + 'static>(
    app: &App,
    f: impl FnOnce(&Relay) -> T + Send + 'static,
) -> Option<T> {
    let app = app.clone();
    match tokio::task::spawn_blocking(move || f(&app)).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(error = %e, "blocking 작업 실패");
            None
        }
    }
}

/// `127.0.0.1:<port>` 에 바인딩한다(`0.0.0.0` 금지, S-PEER-6). 실제 주소를 돌려준다.
///
/// # Errors
/// 바인딩 실패.
pub async fn bind_local(port: u16) -> std::io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// 바인딩된 리스너로 서버를 돌린다. 만료 스캔 주기 태스크도 같이 띄운다. `POST /v1/wipe` 뒤에는 `Ok` 로 반환한다.
///
/// # Errors
/// 서버 오류.
pub async fn serve(app: App, listener: TcpListener) -> std::io::Result<()> {
    let ticker = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let n = blocking(&app, Relay::expire_tick).await.unwrap_or(0);
                if n > 0 {
                    tracing::info!(expired = n, "봉투 만료");
                }
            }
        })
    };
    let stop = app.clone();
    let result = tokio::select! {
        r = axum::serve(
            listener,
            Relay::router(app).into_make_service_with_connect_info::<SocketAddr>(),
        ) => r,
        () = stop.stop.notified() => Ok(()),
    };
    ticker.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn blocking_returns_value_and_turns_panic_into_none() {
        let app = Relay::new(
            Config::local("local"),
            Effects::system(),
            db::Db::memory().unwrap(),
        );
        let name = blocking(&app, |r| r.config.server_name.clone()).await;
        assert_eq!(name.as_deref(), Some("local"));
        let panicked: Option<()> = blocking(&app, |_| panic!("시험용 패닉")).await;
        assert!(panicked.is_none());
    }

    #[test]
    fn test_domains_are_reserved_tlds_only() {
        for h in [
            "lodelai.test",
            "LODELAI.TEST.",
            "localhost",
            "a.localhost",
            "lodelai.example",
            "x.invalid",
        ] {
            assert!(is_test_domain(h), "{h}");
        }
        for h in [
            "relay.example.com",
            "test.com",
            "example.com",
            "mytest",
            "lodelai.testing",
        ] {
            assert!(!is_test_domain(h), "{h}");
        }
    }
}
