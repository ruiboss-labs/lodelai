//! 첨부 파일(묶음 15 `docs/design/bundle-15-files.md` §2, ADR 0009).
//!
//! 파일은 `<blob_dir>/<blob_id 앞 2자>/<blob_id>`(폴더 0700, 파일 0600), 메타데이터는 DB `blobs`. relay 는 암호문만 들고
//! 키를 모른다. 올리기·받기는 인증된 ws 에서 받은 1회용 토큰으로 HTTP(`PUT`·`GET /v1/blobs/{blob_id}`).
//!
//! - PUT 은 스트리밍으로 임시 파일(`<blob_dir>/tmp/`)에 쓰며 길이를 센다. 예약 길이를 넘는 순간 끊고(413), 모자라면 400.
//!   임시 파일은 어떤 경로로 끝나도 남지 않는다([`TmpFile`], 기동 때도 비운다). 이 경로만 axum 본문 상한을 끈다 — 대신
//!   전체 10분·30초 무응답이면 408.
//! - `blob.get`·GET 의 실패는 모두 같은 응답(열거 방지).
//! - 토큰은 로그에 남기지 않는다.

use std::path::{Path, PathBuf};

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path as UrlPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use lodelai_crypto::encoding;
use lodelai_protocol::constants as c;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::db::NewBlob;
use crate::frames::{is_blob_id, ErrorCode, ServerFrame};
use crate::http::ClientIp;
use crate::rules::Authed;
use crate::{blocking, App, Relay};

/// PNG 시그니처(프로필 사진 검사).
const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
/// 프로필 사진 가로·세로 상한(ADR 0009 §8 — 앱은 256 으로 다시 인코딩).
const AVATAR_MAX_SIDE: u32 = 512;
/// GET 읽기 조각.
const READ_CHUNK: usize = 64 * 1024;
/// 이보다 오래된 고아 파일·임시 파일만 청소한다(진행 중인 PUT 을 건드리지 않게).
const ORPHAN_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);
/// PUT 본문 받기 전체 상한(25 MiB 를 느린 회선으로도 넉넉히).
const PUT_TOTAL: std::time::Duration = std::time::Duration::from_secs(600);
/// PUT 도중 이만큼 아무 바이트도 안 오면 끊는다.
const PUT_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// 그 blob 의 파일 경로. `blob_id` 는 [`is_blob_id`] 를 통과한 값만 온다(경로 구분자 없음).
fn path_of(app: &Relay, blob_id: &str) -> PathBuf {
    app.blob_dir.join(&blob_id[..2]).join(blob_id)
}

/// MLS Handshake 의 blob 칸(묶음 22 §5c)을 relay 가 직접 읽는다 — 길이·SHA-256 이 맞을 때만 바이트. relay 가 Commit 을
/// 검사하고 GroupInfo 를 두기 위해서다(MLS 바이트 그대로라 relay 가 읽어도 비밀이 없다).
pub fn read_verified(app: &Relay, blob_id: &str, size: u64, sha256_b64: &str) -> Option<Vec<u8>> {
    if !is_blob_id(blob_id) {
        return None;
    }
    let bytes = std::fs::read(path_of(app, blob_id)).ok()?;
    let want = encoding::decode(sha256_b64, "sha256").ok()?;
    (bytes.len() as u64 == size && Sha256::digest(&bytes).as_slice() == want.as_slice())
        .then_some(bytes)
}

/// 조직 사진 바이트(#554 초대 확인 화면 — 가입 전이라 blob.get 을 못 쓴다). 사진 상한을 넘거나 없으면 `None`.
pub fn read_avatar(app: &Relay, blob_id: &str) -> Option<Vec<u8>> {
    if !is_blob_id(blob_id) {
        return None;
    }
    let bytes = std::fs::read(path_of(app, blob_id)).ok()?;
    (bytes.len() as u64 <= c::AVATAR_MAX_BYTES).then_some(bytes)
}

/// 파일을 지운다(없으면 그만).
pub fn remove_files(app: &Relay, ids: &[String]) {
    for id in ids.iter().filter(|i| is_blob_id(i)) {
        match std::fs::remove_file(path_of(app, id)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(blob_id = %id, error = %e, "첨부 파일 지우기 실패"),
        }
    }
}

fn mkdir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

fn random_b64(app: &Relay, n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    app.effects.rng.try_fill(&mut b).ok()?;
    Some(encoding::encode(&b))
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// blob 폴더가 있는 파일시스템의 남은 바이트. 모르면 `None`(검사하지 않음).
pub fn free_bytes(app: &Relay) -> Option<u64> {
    let _ = mkdir_private(&app.blob_dir);
    crate::status::disk_of(&app.blob_dir).map(|(free, _)| free)
}

fn ref_error(code: ErrorCode, what: &str, req: &str) -> ServerFrame {
    ServerFrame::Error {
        code,
        message: what.to_owned(),
        r#ref: Some(req.to_owned()),
    }
}

/// `blob.reserve`(§2.3). 검사 순서: 크기 → 합계 → 시간당 → 디스크. `for_org`(#554)면 그 앞에 사진인지·조직 관리자인지.
pub fn reserve(
    app: &Relay,
    who: &Authed,
    req: &str,
    ct_len: u64,
    avatar: bool,
    for_org: bool,
    for_device: Option<&str>,
) -> ServerFrame {
    // #881 지난 대화 옮기기 조각: message 만, 요청 기기·받을 기기 둘 다 같은 사용자의 승인된 기기, 받을 기기는 나 아님.
    // 어긋나면 다 같은 protocol(이유를 가르지 않음 — 남의 기기 열거 방지).
    if let Some(to) = for_device {
        let eligible = crate::mls::eligible_devices(app, &who.user);
        if avatar
            || for_org
            || to == who.device_id
            || !eligible.contains(&who.device_id)
            || !eligible.iter().any(|d| d == to)
        {
            return ref_error(ErrorCode::Protocol, "blob.reserve", req);
        }
    }
    // 조직 사진(#554): 사람 사진 길 그대로, 요청 사용자가 지금 자기 조직의 관리자일 때만. PUT 끝에서 다시 본다.
    let org = if for_org {
        match (avatar, app.db.org_admin_of(&who.user)) {
            (true, Ok(Some(org))) => Some(org),
            (true, Err(_)) => return ref_error(ErrorCode::Internal, "blob.reserve", req),
            _ => return ref_error(ErrorCode::Protocol, "blob.reserve", req),
        }
    } else {
        None
    };
    let max = if avatar {
        c::AVATAR_MAX_BYTES
    } else {
        lodelai_crypto::blob::blob_ct_len(c::FILE_MAX_BYTES)
    };
    if ct_len == 0 || ct_len > max {
        return ref_error(ErrorCode::Protocol, "blob.reserve", req);
    }
    if !avatar && for_device.is_none() {
        match app.db.blob_pending(&who.user) {
            Ok(p) if p.saturating_add(ct_len) > c::BLOB_USER_PENDING_MAX_BYTES => {
                return ref_error(ErrorCode::Quota, "blob.reserve", req)
            }
            Ok(_) => {}
            Err(_) => return ref_error(ErrorCode::Internal, "blob.reserve", req),
        }
    }
    // 사진은 사진 상한만(묶음 27 #427 — 시간당 10번), 첨부 예산을 쓰지 않는다.
    let limiter = if avatar {
        &app.avatar_limiter
    } else {
        &app.blob_limiter
    };
    if !limiter.allow(&who.user, app.effects.clock.now()) {
        return ref_error(ErrorCode::RateLimited, "blob.reserve", req);
    }
    if free_bytes(app).is_some_and(|f| f < app.config.blob_min_free) {
        tracing::warn!("첨부 디스크 하한 — 예약 거부");
        return ref_error(ErrorCode::StorageFull, "blob.reserve", req);
    }
    let (Some(blob_id), Some(token)) = (random_b64(app, 16), random_b64(app, 32)) else {
        return ref_error(ErrorCode::Internal, "blob.reserve", req);
    };
    let now = app.effects.clock.now().0;
    let hash = token_hash(&token);
    let row = NewBlob {
        blob_id: &blob_id,
        user: &who.user,
        device: &who.device_id,
        avatar,
        for_org: org.as_deref(),
        for_device,
        ct_len,
        put_token_hash: &hash,
        put_token_exp: now + c::BLOB_PUT_TOKEN_TTL_S as i64 * 1000,
        now_ms: now,
    };
    match app.db.blob_reserve_daily(
        &row,
        c::BLOB_USER_PENDING_MAX_BYTES,
        app.config.blob_daily_max,
    ) {
        Ok(crate::db::Reserve::Done) => {
            tracing::info!(user = %who.user, blob_id = %blob_id, ct_len, avatar, "첨부 예약");
            ServerFrame::BlobReserved {
                req: req.to_owned(),
                blob_id,
                put_token: token,
            }
        }
        Ok(crate::db::Reserve::Pending) => ref_error(ErrorCode::Quota, "blob.reserve", req),
        // 옮기기 조각을 보내는 앱은 daily_quota 를 아는 스키마로 지어졌다 — 판으로 내리지 않는다(quota 로 내리면 흐름 제어로 읽고
        // 끝없이 기다림, #881 판정 1).
        Ok(crate::db::Reserve::Daily) if for_device.is_some() => {
            daily_quota_frame(c::OWN_CONTROL_PROTOCOL, req, now)
        }
        Ok(crate::db::Reserve::Daily) => daily_quota(app, who, req, now),
        Err(_) => ref_error(ErrorCode::Internal, "blob.reserve", req),
    }
}

/// #876 하루 첨부 합 거절 — `error{daily_quota, ref, until 다음 UTC 0시}`. 이 코드를 모르는 옛 판(hello.v <
/// OWN_CONTROL_PROTOCOL)엔 `quota`(옛 앱의 error.code 는 닫힌 enum). 로그는 사용자마다 1분에 한 줄, 바이트·파일 정보 없음.
fn daily_quota(app: &Relay, who: &Authed, req: &str, now: i64) -> ServerFrame {
    if app.daily_quota_log.take(&who.user, now) {
        tracing::info!(user = %who.user, "첨부 하루 상한");
    }
    daily_quota_frame(who.v, req, now)
}

/// 연결 판 `v` 에 맞는 하루 상한 거절(순수 — 판을 올리기 전엔 WS 로 16 연결이 없어 단위 시험으로 본다).
fn daily_quota_frame(v: u64, req: &str, now: i64) -> ServerFrame {
    const DAY_MS: i64 = 86_400_000;
    if v < c::OWN_CONTROL_PROTOCOL {
        return ref_error(ErrorCode::Quota, "blob.reserve", req);
    }
    let until = (now.div_euclid(DAY_MS) + 1) * DAY_MS;
    let f = serde_json::json!({
        "t": "error", "code": "daily_quota", "message": "blob.reserve", "ref": req,
        "until": lodelai_effects::UnixMillis(until).to_rfc3339().unwrap_or_default(),
    });
    match serde_json::from_value::<lodelai_protocol::ws::Frame>(f) {
        Ok(f) => ServerFrame::Ws(Box::new(f)),
        Err(_) => ref_error(ErrorCode::Quota, "blob.reserve", req),
    }
}

/// `blob.get`(§2.3). 인가 실패·모름·지워짐은 모두 같은 `error{protocol, ref}`.
pub fn get_ticket(app: &Relay, who: &Authed, req: &str, blob_id: &str) -> ServerFrame {
    let refused = || ref_error(ErrorCode::Protocol, "blob.get", req);
    if !is_blob_id(blob_id) {
        return refused();
    }
    let Some(token) = random_b64(app, 32) else {
        return ref_error(ErrorCode::Internal, "blob.get", req);
    };
    let exp = app.effects.clock.now().0 + c::BLOB_GET_TOKEN_TTL_S as i64 * 1000;
    // #881 옮기기 조각: 표를 줄 때 받을 기기가 지금도 승인된 기기인지 다시 본다(폐기는 DB 쿼리가 봄).
    match app.db.blob_is_history(blob_id) {
        Ok(true) if !crate::mls::eligible_devices(app, &who.user).contains(&who.device_id) => {
            return refused();
        }
        Ok(_) => {}
        Err(_) => return ref_error(ErrorCode::Internal, "blob.get", req),
    }
    match app
        .db
        .blob_grant(blob_id, &who.user, &who.device_id, &token_hash(&token), exp)
    {
        Ok(true) => ServerFrame::BlobTicket {
            req: req.to_owned(),
            blob_id: blob_id.to_owned(),
            get_token: token,
        },
        Ok(false) => refused(),
        Err(_) => ref_error(ErrorCode::Internal, "blob.get", req),
    }
}

/// `blob.fetched`(§2.3). 수신 기기(폐기 안 된) 모두 받았으면 파일을 지운다. 응답 없음.
pub fn fetched(app: &Relay, who: &Authed, blob_id: &str) {
    if !is_blob_id(blob_id) {
        return;
    }
    let now = app.effects.clock.now().0;
    match app.db.blob_fetched(blob_id, &who.device_id, now) {
        Ok(Some(true)) => {
            remove_files(app, &[blob_id.to_owned()]);
            tracing::info!(blob_id, "첨부 모두 받음 — 지움");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(blob_id, error = %e, "첨부 받음 기록 실패"),
    }
}

/// 청소(§2.6, expire_tick 에서). DB 가 지운 첨부의 파일, 행 없는 고아 파일(정보 파기 A·중단된 PUT), 오래된 임시 파일.
pub fn sweep(app: &Relay) {
    let now = app.effects.clock.now().0;
    match app
        .db
        .blob_sweep(now, c::BLOB_UNATTACHED_TTL_S as i64 * 1000)
    {
        Ok(ids) => {
            if !ids.is_empty() {
                tracing::info!(count = ids.len(), "첨부 청소");
            }
            remove_files(app, &ids);
        }
        Err(e) => tracing::warn!(error = %e, "첨부 청소 실패"),
    }
    let Ok(dirs) = std::fs::read_dir(&app.blob_dir) else {
        return;
    };
    for d in dirs.flatten() {
        let is_tmp = d.file_name() == "tmp";
        let Ok(files) = std::fs::read_dir(d.path()) else {
            continue;
        };
        for f in files.flatten() {
            let old = f
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= ORPHAN_GRACE);
            let name = f.file_name().to_string_lossy().into_owned();
            let orphan = is_tmp || (is_blob_id(&name) && !app.db.blob_known(&name).unwrap_or(true));
            if old && orphan {
                let _ = std::fs::remove_file(f.path());
            }
        }
    }
}

/// 기동 때: 앞 프로세스가 남긴 임시 파일(끝나지 않은 PUT)을 지운다.
pub fn clear_tmp(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
}

/// 첨부를 모두 지운다(`/v1/wipe`).
pub fn wipe(app: &Relay) {
    if let Err(e) = std::fs::remove_dir_all(&app.blob_dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, "첨부 폴더 지우기 실패");
        }
    }
}

// ------------------------------------------------------------------ HTTP

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// 토큰이 맞지 않은 blob 요청(묶음 15 리뷰 ①). PUT·GET 은 토큰이 인증이라 IP 상한을 쓰지 않고, 토큰 확인에 실패한 요청만
/// IP 상한에 센다 — 넘으면 429, 아니면 404(로컬 relay 는 모든 요청이 127.0.0.1 한 버킷이라 맞는 요청까지 세면 막힌다).
fn refused(app: &App, ip: Option<&Extension<ClientIp>>) -> Response {
    match ip {
        Some(Extension(ClientIp(Some(ip))))
            if !app.ip_limiter.allow(ip, app.effects.clock.now()) =>
        {
            StatusCode::TOO_MANY_REQUESTS.into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// 끝날 때 지우는 임시 파일(성공하면 [`TmpFile::keep`]).
struct TmpFile(Option<PathBuf>);

impl TmpFile {
    fn keep(mut self) -> PathBuf {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for TmpFile {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// 프로필 사진: PNG 시그니처 + IHDR 가로·세로 1~512.
fn png_ok(head: &[u8]) -> bool {
    if head.len() < 24 || head[..8] != PNG_SIG || &head[12..16] != b"IHDR" {
        return false;
    }
    let w = u32::from_be_bytes([head[16], head[17], head[18], head[19]]);
    let h = u32::from_be_bytes([head[20], head[21], head[22], head[23]]);
    (1..=AVATAR_MAX_SIDE).contains(&w) && (1..=AVATAR_MAX_SIDE).contains(&h)
}

/// PNG 조각을 따라가다 `eXIf` 가 있으면 참. 꼴이 깨진 곳이나 `IEND` 에서 멈춘다(그 뒤는 앱의 디코더가 거절한다).
fn has_exif(png: &[u8]) -> bool {
    let mut at = PNG_SIG.len();
    while let Some(head) = png.get(at..at + 8) {
        let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        match &head[4..8] {
            b"eXIf" => return true,
            b"IEND" => return false,
            _ => {}
        }
        // 길이(4) + 종류(4) + 내용 + CRC(4).
        match at.checked_add(12).and_then(|n| n.checked_add(len)) {
            Some(next) if next <= png.len() => at = next,
            _ => return false,
        }
    }
    false
}

/// `PUT /v1/blobs/{blob_id}`(§2.4).
pub async fn put(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    UrlPath(blob_id): UrlPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (Some(token), true) = (bearer(&headers), is_blob_id(&blob_id)) else {
        return refused(&app, ip.as_ref());
    };
    let hash = token_hash(token);
    let id = blob_id.clone();
    let now = app.effects.clock.now().0;
    let Some(Ok(Some((user, avatar, ct_len, org)))) =
        blocking(&app, move |r| r.db.blob_put_begin(&id, &hash, now)).await
    else {
        return refused(&app, ip.as_ref());
    };
    let status = match receive(&app, &blob_id, &user, avatar, org, ct_len, body).await {
        Ok(()) => return StatusCode::NO_CONTENT.into_response(),
        Err(s) => s,
    };
    let id = blob_id.clone();
    let _ = blocking(&app, move |r| r.db.blob_put_failed(&id)).await;
    tracing::info!(blob_id = %blob_id, status = status.as_u16(), "첨부 올리기 실패");
    status.into_response()
}

async fn receive(
    app: &App,
    blob_id: &str,
    user: &str,
    avatar: bool,
    org: Option<String>,
    ct_len: u64,
    body: Body,
) -> Result<(), StatusCode> {
    let internal = |e: std::io::Error| {
        tracing::warn!(error = %e, "첨부 쓰기 실패");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    let tmp_dir = app.blob_dir.join("tmp");
    mkdir_private(&tmp_dir).map_err(internal)?;
    let name = random_b64(app, 16).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let tmp = TmpFile(Some(tmp_dir.join(name)));
    let tmp_path = tmp.0.clone().unwrap_or_default();
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .await
        .map_err(internal)?;
    let mut written = 0u64;
    let mut stream = body.into_data_stream();
    let deadline = tokio::time::Instant::now() + PUT_TOTAL;
    loop {
        let wait = PUT_IDLE.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        let Ok(next) = tokio::time::timeout(wait, stream.next()).await else {
            return Err(StatusCode::REQUEST_TIMEOUT);
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        written += chunk.len() as u64;
        if written > ct_len {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        file.write_all(&chunk).await.map_err(internal)?;
    }
    if written != ct_len {
        return Err(StatusCode::BAD_REQUEST);
    }
    file.flush().await.map_err(internal)?;
    drop(file);
    if avatar {
        // 사진은 AVATAR_MAX_BYTES(128 KiB) 이하라 통째로 본다 — 머리(PNG·크기)와 EXIF 조각(묶음 27 #427: 위치 같은
        // 메타데이터가 조직에 퍼지지 않게. 앱은 다시 인코딩해 보내므로 정상 사진엔 없다).
        let bytes = tokio::fs::read(&tmp_path).await.map_err(internal)?;
        if !png_ok(&bytes) || has_exif(&bytes) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let dest = path_of(app, blob_id);
    if let Some(parent) = dest.parent() {
        mkdir_private(parent).map_err(internal)?;
    }
    std::fs::rename(tmp.keep(), &dest).map_err(internal)?;
    let (id, u) = (blob_id.to_owned(), user.to_owned());
    let done = blocking(app, move |r| {
        // 조직 사진(#554): 예약 뒤 관리자에서 내려갔거나 조직을 옮겼으면 받지 않는다(호출자가 행을 지운다).
        if let Some(org) = &org {
            if r.db.org_admin_of(&u).ok().flatten().as_ref() != Some(org) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        if !r.db.blob_put_done(&id).unwrap_or(false) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if avatar {
            // 조직 사진은 관리자를 바꾸는 트랜잭션 안에서 한 번 더 본다(위 검사와 이 사이에 내려갔을 수 있다).
            let old = match &org {
                Some(org) => match r.db.set_org_avatar(org, &u, &id) {
                    Ok(Some(old)) => Ok(old),
                    Ok(None) => return Err(StatusCode::FORBIDDEN),
                    Err(e) => Err(e),
                },
                None => r.db.set_avatar(&u, &id),
            };
            match old {
                Ok(old) => remove_files(r, &old.into_iter().collect::<Vec<_>>()),
                Err(_) => return Err(StatusCode::BAD_REQUEST),
            }
            crate::ws::broadcast_directory_of(r, &u);
        }
        Ok(())
    })
    .await
    .unwrap_or(Err(StatusCode::BAD_REQUEST));
    if let Err(status) = done {
        // 그 사이 청소로 예약이 사라졌거나 조직 관리자가 아니게 됐다 — 자리에 둔 파일도 지운다.
        let _ = std::fs::remove_file(&dest);
        return Err(status);
    }
    tracing::info!(user, blob_id, ct_len, avatar, "첨부 올림");
    Ok(())
}

/// `GET /v1/blobs/{blob_id}`(§2.4). 실패는 모두 404.
pub async fn get(
    State(app): State<App>,
    ip: Option<Extension<ClientIp>>,
    UrlPath(blob_id): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let not_found = || StatusCode::NOT_FOUND.into_response();
    let (Some(token), true) = (bearer(&headers), is_blob_id(&blob_id)) else {
        return refused(&app, ip.as_ref());
    };
    let hash = token_hash(token);
    let id = blob_id.clone();
    let now = app.effects.clock.now().0;
    if blocking(&app, move |r| r.db.blob_take_ticket(&hash, &id, now))
        .await
        .and_then(Result::ok)
        != Some(true)
    {
        return refused(&app, ip.as_ref());
    }
    let Ok(file) = tokio::fs::File::open(path_of(&app, &blob_id)).await else {
        return not_found();
    };
    let Ok(meta) = file.metadata().await else {
        return not_found();
    };
    let stream = futures_util::stream::unfold(file, |mut f| async move {
        let mut buf = vec![0u8; READ_CHUNK];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(Bytes::from(buf)), f))
            }
            Err(e) => Some((Err(e), f)),
        }
    });
    let mut resp = Body::from_stream(stream).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_quota_frame_by_version() {
        // 2026-11-11 13:00 UTC → 다음 UTC 0시.
        let now = 1_794_402_000_000;
        let f: serde_json::Value =
            serde_json::from_str(&daily_quota_frame(c::OWN_CONTROL_PROTOCOL, "r9", now).to_json())
                .unwrap();
        assert_eq!(
            (
                f["t"].as_str(),
                f["code"].as_str(),
                f["ref"].as_str(),
                f["until"].as_str()
            ),
            (
                Some("error"),
                Some("daily_quota"),
                Some("r9"),
                Some("2026-11-12T00:00:00.000Z")
            ),
            "{f}"
        );
        // 이 코드를 모르는 옛 판엔 quota(until 없음).
        let f: serde_json::Value = serde_json::from_str(
            &daily_quota_frame(c::OWN_CONTROL_PROTOCOL - 1, "r9", now).to_json(),
        )
        .unwrap();
        assert_eq!(
            (f["code"].as_str(), f.get("until")),
            (Some("quota"), None),
            "{f}"
        );
    }

    #[test]
    fn png_header_check() {
        let mut h = Vec::from(PNG_SIG);
        h.extend_from_slice(&[0, 0, 0, 13]);
        h.extend_from_slice(b"IHDR");
        h.extend_from_slice(&256u32.to_be_bytes());
        h.extend_from_slice(&256u32.to_be_bytes());
        assert!(png_ok(&h));
        let mut big = h.clone();
        big[16..20].copy_from_slice(&513u32.to_be_bytes());
        assert!(!png_ok(&big));
        let mut not_png = h.clone();
        not_png[1] = b'X';
        assert!(!png_ok(&not_png));
        assert!(!png_ok(&h[..20]));
    }

    #[test]
    fn exif_chunk_is_found() {
        let chunk = |kind: &[u8], data: &[u8]| {
            let mut c = Vec::from(u32::try_from(data.len()).unwrap().to_be_bytes());
            c.extend_from_slice(kind);
            c.extend_from_slice(data);
            c.extend_from_slice(&[0, 0, 0, 0]);
            c
        };
        let mut base = Vec::from(PNG_SIG);
        base.extend(chunk(b"IHDR", &[0; 13]));
        base.extend(chunk(b"IDAT", &[1, 2, 3]));
        let mut clean = base.clone();
        clean.extend(chunk(b"IEND", &[]));
        assert!(!has_exif(&clean));
        let mut exif = base.clone();
        exif.extend(chunk(b"eXIf", b"MM\0*GPS"));
        exif.extend(chunk(b"IEND", &[]));
        assert!(has_exif(&exif));
        // IEND 뒤나 깨진 길이 뒤는 보지 않는다.
        let mut after = clean.clone();
        after.extend(chunk(b"eXIf", b"x"));
        assert!(!has_exif(&after));
        let mut broken = base;
        broken.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        broken.extend_from_slice(b"IDAT");
        broken.extend(chunk(b"eXIf", b"x"));
        assert!(!has_exif(&broken));
    }
}
