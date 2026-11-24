//! 첨부 올리기·받기(묶음 15 §3). 연결 루프가 연결마다 띄우는 작업들이다 — 연결이 끝나면 멈추고([`Tasks`]), 다음 연결에서 처음부터.
//!
//! - 올리기: 큐 맨 앞이 `upload` 행일 때 하나. 파일마다 `blob.reserve` → (그때 받은 blob_id 를 AAD 로) 새 FK·prefix 로
//!   `seal_blob` → PUT. 다 올리면 헤더 `blobs`·본문 `pt=json1` 로 봉투·서명해 그 행을 `send` 로 바꾼다. 실패는 행을 빼고
//!   `Nack` — relay 의 `quota` 는 `upload_quota`(F6), `storage_full` 은 `upload_storage`(F7), 그 밖(형식·네트워크·파일이 바뀜)은
//!   `upload_failed`. 연결이 끊긴 것은 실패가 아니다(다음 연결에서 다시).
//! - 받기: `downloads` 표의 것을 동시 2개까지. `blob.get` → GET(임시) → `open_blob`(해시 먼저) → `blobs-in/<msg_id>-<idx>`.
//!   relay 에 없으면 `Unavailable`, 해시·AEAD 가 틀리면 `BadFile`(둘 다 다시 받지 않음), 네트워크·입출력은 행을 두고
//!   연결된 채 [`download_backoff`] 뒤에 다시(연결이 바뀌면 곧바로). 받다 만 암호문은 임시 파일([`part_path`])에 남아
//!   다음 시도가 `Range` 로 잇는다(#1012).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lodelai_crypto::blob::{blob_ct_len, open_blob, seal_blob, BlobError};
use lodelai_crypto::{encoding, DeviceKeys};
use lodelai_effects::Rng;
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::outbox::{Download, Store, UploadSpec};
use crate::{AttachmentFailure, AttachmentOutcome, Inbound};

/// 폴더를 0700 으로 만든다(이미 있으면 권한을 맞춘다).
#[cfg(unix)]
pub fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Windows: 모드 비트가 없다 — 앱 데이터(`%LOCALAPPDATA%`) 아래라 사용자 프로필 ACL(본인·SYSTEM·Administrators)을 물려받는다.
#[cfg(windows)]
pub fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().recursive(true).create(dir)
}

/// 새 파일을 0600 으로(남은 것이 있으면 지우고) — 풀어 둔 평문 첨부가 다른 사용자에게 읽히지 않게.
pub fn private_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // Windows 는 모드 비트가 없다 — [`private_dir`] 와 같은 까닭으로 폴더 ACL 을 물려받는다.
    #[cfg(unix)]
    opts.mode(0o600);
    opts.open(path)
}

/// relay 응답(예약·표) 기다리는 상한.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// 동시에 받는 첨부 수.
pub const DOWNLOADS_AT_ONCE: usize = 2;

/// `n` 번째 받기를 시작한 뒤, 그것이 일시 실패했을 때 다시 받기까지(연결된 채, 계약 617858e4): 30초·2분·그 뒤 10분마다.
/// 해시·AEAD 실패(`BadFile`)·relay 에 없음(`Unavailable`)은 행을 끝내므로 다시 받지 않는다.
pub fn download_backoff(n: u32) -> Duration {
    match n {
        0 | 1 => Duration::from_secs(30),
        2 => Duration::from_secs(120),
        _ => Duration::from_secs(600),
    }
}

/// `req` 로 짝을 맞추는 relay 응답: `Ok((blob_id, token))` 또는 `Err((error.code, error.until))`(`until` 은 `daily_quota` 처럼
/// 다시 될 시각이 같이 오는 거절만 — RFC 3339).
type Answer = Result<(String, String), (String, Option<String>)>;

/// 연결 하나의 응답 대기표.
#[derive(Default)]
pub struct Waiters {
    next: AtomicU64,
    map: Mutex<HashMap<String, oneshot::Sender<Answer>>>,
}

impl Waiters {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<Answer>>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn open(&self, prefix: char) -> (String, oneshot::Receiver<Answer>) {
        let req = format!("{prefix}{}", self.next.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        self.lock().insert(req.clone(), tx);
        (req, rx)
    }

    /// `blob.reserved`·`blob.ticket`·`error{ref}` 가 기다리던 것의 답이면 넘기고 `true`.
    pub fn answer(&self, frame: &Value) -> bool {
        let g = |k: &str| frame.get(k).and_then(Value::as_str);
        let (Some(t), Some(req)) = (g("t"), g("req").or_else(|| g("ref"))) else {
            return false;
        };
        let answer = match t {
            "blob.reserved" => match (g("blob_id"), g("put_token")) {
                (Some(b), Some(k)) if is_blob_id(b) && is_token(k) => {
                    Ok((b.to_owned(), k.to_owned()))
                }
                _ => Err(("protocol".to_owned(), None)),
            },
            "blob.ticket" => match (g("blob_id"), g("get_token")) {
                (Some(b), Some(k)) if is_blob_id(b) && is_token(k) => {
                    Ok((b.to_owned(), k.to_owned()))
                }
                _ => Err(("protocol".to_owned(), None)),
            },
            "error" => Err((
                g("code").unwrap_or("protocol").to_owned(),
                g("until").map(str::to_owned),
            )),
            _ => return false,
        };
        match self.lock().remove(req) {
            Some(tx) => {
                let _ = tx.send(answer);
                true
            }
            None => false,
        }
    }
}

/// 작업이 쓰는 것. 연결마다 새로 만든다(`frames`·`waiters` 는 그 연결 것).
#[derive(Clone)]
pub struct Ctx {
    pub store: Arc<Store>,
    pub keys: DeviceKeys,
    pub rng: Arc<dyn Rng>,
    pub target: crate::tls::Target,
    pub dir: PathBuf,
    pub frames: mpsc::UnboundedSender<String>,
    pub waiters: Arc<Waiters>,
    pub inbound: mpsc::Sender<Inbound>,
    /// 프로필 사진 PUT 일시 실패 뒤 물러서기(첫 간격, 상한 — [`crate::Config::avatar_retry_first`]).
    pub avatar_retry: (Duration, Duration),
    /// 올리기가 이만큼 답이 없으면 '네트워크 기다림'을 한 번([`crate::Config::avatar_slow_notice`]).
    pub avatar_slow_notice: Duration,
    /// 이어진 일시 실패 수(이 연결 동안). 올리기가 끝나면(성공·거절) 0.
    pub avatar_fails: Arc<std::sync::atomic::AtomicU32>,
    /// 이 올리기의 '네트워크 기다림'을 이미 냈는가(느림 알림·첫 실패 중 하나만). 올리기가 끝나면(성공·거절) false.
    pub avatar_waiting_shown: Arc<std::sync::atomic::AtomicBool>,
}

/// 연결이 끝나면 작업을 멈춘다.
#[derive(Default)]
pub struct Tasks {
    pub upload: Option<(i64, tokio::task::JoinHandle<()>)>,
    pub downloads: Vec<((String, u32), tokio::task::JoinHandle<()>)>,
    /// 프로필 사진 올리기(묶음 15 B9) — 큐 행 하나. 도는 동안 큐는 멈춘다.
    pub avatar_put: Option<tokio::task::JoinHandle<()>>,
    /// 프로필 사진 받기. 끊기면 멈추고 요청자는 [`crate::Error::Unreachable`].
    pub avatar_gets: Vec<tokio::task::JoinHandle<()>>,
    /// #881 지난 대화 조각 올리기·받기 — 보내기 큐와 따로 돈다(큰 옮기기가 보통 글을 막지 않게). 끊기면 멈추고 요청자는
    /// [`crate::Error::Unreachable`].
    pub history: Vec<tokio::task::JoinHandle<()>>,
}

impl Tasks {
    pub fn reap(&mut self) {
        if self.upload.as_ref().is_some_and(|(_, h)| h.is_finished()) {
            self.upload = None;
        }
        self.downloads.retain(|(_, h)| !h.is_finished());
        if self
            .avatar_put
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            self.avatar_put = None;
        }
        self.avatar_gets.retain(|h| !h.is_finished());
        self.history.retain(|h| !h.is_finished());
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        if let Some((_, h)) = &self.upload {
            h.abort();
        }
        for (_, h) in &self.downloads {
            h.abort();
        }
        if let Some(h) = &self.avatar_put {
            h.abort();
        }
        for h in &self.avatar_gets {
            h.abort();
        }
        for h in &self.history {
            h.abort();
        }
    }
}

/// 실패 종류.
pub(crate) enum Stop {
    /// 연결이 끊겼다 — 다음 연결에서 처음부터.
    Disconnected,
    /// 이 메시지는 못 보낸다.
    Failed(&'static str),
    /// relay 가 거절했다(`error.code` 그대로, `until` 이 같이 왔으면 그것도).
    Refused(String, Option<String>),
}

/// relay 거절 코드 → 화면이 가르는 `Nack` reason(F6·F7). 나머지는 `None`(= `upload_failed`).
fn refused_reason(code: &str) -> Option<&'static str> {
    match code {
        "quota" => Some("upload_quota"),
        "storage_full" => Some("upload_storage"),
        // #876 하루 첨부 한도 — 다음 UTC 0시(`until`)에 풀린다.
        "daily_quota" => Some("upload_daily"),
        _ => None,
    }
}

pub(crate) async fn ask(
    c: &Ctx,
    prefix: char,
    frame: impl FnOnce(&str) -> Value,
) -> Result<(String, String), Stop> {
    let (req, rx) = c.waiters.open(prefix);
    if c.frames.send(frame(&req).to_string()).is_err() {
        return Err(Stop::Disconnected);
    }
    match tokio::time::timeout(ANSWER_WAIT, rx).await {
        Ok(Ok(Ok(a))) => Ok(a),
        Ok(Ok(Err((code, until)))) => {
            tracing::info!(code, "첨부 요청 거절");
            Err(Stop::Refused(code, until))
        }
        // 대기표가 버려졌다(연결 끝) 또는 답이 없다 — 연결 문제로 본다.
        _ => Err(Stop::Disconnected),
    }
}

fn random(c: &Ctx, n: usize) -> Result<Vec<u8>, Stop> {
    let mut b = vec![0u8; n];
    c.rng.try_fill(&mut b).map_err(|_| Stop::Failed("난수"))?;
    Ok(b)
}

/// 로컬 파일 이름(올릴 암호문·받은 평문) — relay·보낸 사람이 준 값(blob_id·msg_id)으로 로컬 경로를 만들지 않는다
/// (묶음 15 리뷰 ③). 받기 임시 파일은 [`part_path`].
fn local_name(c: &Ctx) -> Result<String, Stop> {
    Ok(random(c, 16)?.iter().map(|b| format!("{b:02x}")).collect())
}

fn b64url_chars(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// relay 가 만든 blob_id: 16바이트 base64url(22자). 경로·HTTP 요청 줄에 들어가므로 꼴을 먼저 본다(리뷰 ③ — CRLF·`..`·`/`).
pub fn is_blob_id(s: &str) -> bool {
    s.len() == 22 && b64url_chars(s)
}

/// 받기 임시 파일(#1012 §3): `<dir>/in/<sha256(blob_id) hex>.part`. 시도마다 같은 이름이어야 이어받는다. blob_id 를
/// 그대로 쓰지 않는다 — 받은 값으로 로컬 경로를 만들지 않고(묶음 15 리뷰 ③), 맥 기본 볼륨은 대소문자를 가리지 않는다.
#[must_use]
pub fn part_path(dir: &std::path::Path, blob_id: &str) -> PathBuf {
    use sha2::Digest;
    let name: String = sha2::Sha256::digest(blob_id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    dir.join("in").join(format!("{name}.part"))
}

/// 받기 임시 파일을 마지막으로 쓴 지 이만큼 지나면 시작 때 쓴다(#1012 §3 ⑤).
pub const PART_KEEP: Duration = Duration::from_secs(48 * 60 * 60);

/// 지금 받는 중인 임시 파일(프로세스 전체). blob 하나에 받기 하나 — 같은 파일에 둘이 쓰면 깨진다.
static PARTS_BUSY: Mutex<std::collections::BTreeSet<PathBuf>> =
    Mutex::new(std::collections::BTreeSet::new());
/// 나눠 받은 것이 틀려 이미 한 번 처음부터 다시 받게 한 임시 파일 — 또 틀리면 끝낸다. 그 blob 이 끝나면 지운다.
static PARTS_REDONE: Mutex<std::collections::BTreeSet<PathBuf>> =
    Mutex::new(std::collections::BTreeSet::new());

fn parts(
    m: &'static Mutex<std::collections::BTreeSet<PathBuf>>,
) -> std::sync::MutexGuard<'static, std::collections::BTreeSet<PathBuf>> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 임시 파일 하나를 쥔 표시. 놓으면(작업이 끝나거나 연결이 끝나 그만두면) 풀린다.
pub(crate) struct PartLock(PathBuf);

impl PartLock {
    /// 이미 누가 받는 중이면 `None`.
    pub(crate) fn take(path: &std::path::Path) -> Option<Self> {
        parts(&PARTS_BUSY)
            .insert(path.to_owned())
            .then(|| Self(path.to_owned()))
    }
}

impl Drop for PartLock {
    fn drop(&mut self) {
        parts(&PARTS_BUSY).remove(&self.0);
    }
}

/// 그 blob 의 받기가 끝났다(받음·최종 실패·버림) — 임시 파일과 '한 번 다시 받음' 표시를 지운다.
pub(crate) fn part_done(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    parts(&PARTS_REDONE).remove(path);
}

/// 다 채운 임시 파일이 틀렸다(길이·해시·열기). 나눠 받은 것이고 아직 다시 받게 한 적이 없으면 지우고 `true`(일시 오류로
/// 한 번 더 처음부터 — 나눠 받다 섞인 파일 때문에 멀쩡한 것을 영영 못 받지 않게). 아니면 정리하고 `false`(끝낸다).
pub(crate) fn part_redo(path: &std::path::Path, got: crate::blobio::Got) -> bool {
    let _ = std::fs::remove_file(path);
    if got == crate::blobio::Got::Pieced && parts(&PARTS_REDONE).insert(path.to_owned()) {
        return true;
    }
    parts(&PARTS_REDONE).remove(path);
    false
}

/// 그 blob 의 임시 파일에 받아 둔 바이트(없으면 0).
#[must_use]
pub fn part_have(dir: &std::path::Path, blob_id: &str) -> u64 {
    std::fs::metadata(part_path(dir, blob_id)).map_or(0, |m| m.len())
}

/// 그 blob 들의 임시 파일을 지운다(코어가 그 받기를 버렸다).
pub fn parts_drop<S: AsRef<str>>(dir: &std::path::Path, blob_ids: &[S]) {
    for id in blob_ids {
        part_done(&part_path(dir, id.as_ref()));
    }
}

/// 시작 때 쓸기(#1012 §3 ⑤): 받는 폴더의 `*.part` 가운데 `keep`(받을 행·진행 중 옮기기의 blob_id)에 없는 것, 그리고
/// 마지막으로 쓴 지 [`PART_KEEP`] 넘은 것(옛 판의 무작위 이름 것 포함)을 지운다. 지금 받는 중인 것·`.part` 아닌 것(받은
/// 평문)은 두고, 지운 수를 돌려준다.
pub fn parts_sweep<S: AsRef<str>>(
    dir: &std::path::Path,
    keep: &[S],
    now: std::time::SystemTime,
) -> usize {
    let keep: std::collections::BTreeSet<PathBuf> =
        keep.iter().map(|id| part_path(dir, id.as_ref())).collect();
    let Ok(rd) = std::fs::read_dir(dir.join("in")) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("part") {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > PART_KEEP);
        if (old || !keep.contains(&path))
            && !parts(&PARTS_BUSY).contains(&path)
            && std::fs::remove_file(&path).is_ok()
        {
            parts(&PARTS_REDONE).remove(&path);
            n += 1;
        }
    }
    n
}

/// PUT·GET 토큰(32바이트 base64url = 43자). `Authorization` 줄에 들어간다.
fn is_token(s: &str) -> bool {
    s.len() == 43 && b64url_chars(s)
}

/// msg_id: ULID(Crockford base32 26자).
fn is_msg_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
        })
}

/// 큐의 `upload` 행 하나를 올리고 `send` 로 바꾼다. 실패면 행을 빼고 알린다.
pub async fn upload(c: Ctx, seq: i64) {
    let spec = match c.store.upload_spec(seq) {
        Ok(Some(s)) => serde_json::from_str::<UploadSpec>(&s).ok(),
        _ => None,
    };
    let Some(spec) = spec else {
        tracing::warn!(seq, "올리기 사양을 읽을 수 없음 — 행을 뺀다");
        let _ = c.store.remove(seq);
        return;
    };
    let msg_id = spec
        .message
        .get("msg_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut until = None;
    let reason = match upload_files(&c, seq, &spec).await {
        Ok(()) => return,
        // 끊김이면 이 작업은 곧 멈춘다. 연결된 채 응답이 없었으면(시간 초과) 곧바로 새 예약을 거듭 만들지 않게 쉬었다가
        // 같은 행을 다시(리뷰 ②).
        Err(Stop::Disconnected) => {
            tokio::time::sleep(download_backoff(1)).await;
            return;
        }
        Err(Stop::Failed(why)) => {
            tracing::info!(msg_id, why, "첨부 올리기 실패");
            "upload_failed"
        }
        Err(Stop::Refused(code, u)) => {
            let reason = refused_reason(&code).unwrap_or("upload_failed");
            // 다시 될 시각은 하루 한도만 싣는다(#876 — 화면이 '{time}부터 다시').
            if reason == "upload_daily" {
                until = u;
            }
            reason
        }
    };
    let _ = c.store.remove(seq);
    let _ = c
        .inbound
        .send(Inbound::Nack {
            msg_id,
            reason: reason.into(),
            until,
        })
        .await;
}

/// 읽으며 평문 SHA-256 을 잰다(암호화와 같은 한 번의 읽기 — 잰 것과 보낸 것이 같은 바이트).
struct HashingReader<R> {
    inner: R,
    hash: sha2::Sha256,
}

impl<R: std::io::Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        use sha2::Digest;
        Self {
            inner,
            hash: sha2::Sha256::new(),
        }
    }

    fn hex(self) -> String {
        use sha2::Digest;
        self.hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

impl<R: std::io::Read> std::io::Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.read(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// 파일 하나를 올리는 한 번의 시도(새 예약 → 암호화 → PUT).
enum Put {
    Done((String, [u8; 32], [u8; 19], [u8; 32])),
    /// 네트워크 오류·408·429·5xx — 새 예약으로 다시 해 볼 만하다.
    Transient,
}

/// 첨부 PUT 을 새 예약으로 다시 해 보는 최대 횟수(리뷰 ②).
const PUT_ATTEMPTS: u32 = 3;

async fn put_one(
    c: &Ctx,
    out_dir: &std::path::Path,
    f: &crate::outbox::UploadFile,
    ct_len: u64,
) -> Result<Put, Stop> {
    let (blob_id, token) = ask(
        c,
        'u',
        |req| json!({"t": "blob.reserve", "req": req, "ct_len": ct_len, "purpose": "message"}),
    )
    .await?;
    let fk: [u8; 32] = random(c, 32)?
        .try_into()
        .map_err(|_| Stop::Failed("난수"))?;
    let prefix: [u8; 19] = random(c, 19)?
        .try_into()
        .map_err(|_| Stop::Failed("난수"))?;
    let tmp = out_dir.join(local_name(c)?);
    let (src, dst, id) = (f.path.clone(), tmp.clone(), blob_id.clone());
    let sealed = tokio::task::spawn_blocking(move || {
        let mut r = HashingReader::new(std::io::BufReader::new(std::fs::File::open(&src)?));
        let w = std::io::BufWriter::new(private_file(&dst)?);
        let v = seal_blob(&fk, &prefix, &id, &mut r, w)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok::<_, std::io::Error>((v, r.hex()))
    })
    .await;
    let ((len, sha), plain_sha) = match sealed {
        Ok(Ok(v)) => v,
        _ => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Stop::Failed("암호화"));
        }
    };
    // 코어가 검사한 사본과 지금 읽은 평문이 다르면 보내지 않는다(묶음 15 QA 🟢 — 재해시 뒤 바뀐 파일).
    if f.sha256.as_ref().is_some_and(|want| *want != plain_sha) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Stop::Failed("파일이 바뀜"));
    }
    if len != ct_len {
        let _ = std::fs::remove_file(&tmp);
        return Err(Stop::Failed("파일이 바뀜"));
    }
    let put = crate::blobio::put(&c.target, &blob_id, &token, &tmp, len).await;
    let _ = std::fs::remove_file(&tmp);
    match put {
        Ok(204) => Ok(Put::Done((blob_id, fk, prefix, sha))),
        Ok(code @ (408 | 429 | 500..=599)) => {
            tracing::info!(code, "첨부 PUT 일시 실패");
            Ok(Put::Transient)
        }
        Ok(code) => {
            tracing::info!(code, "첨부 PUT 거절");
            Err(Stop::Failed("PUT"))
        }
        Err(e) => {
            tracing::info!(error = %e, "첨부 PUT 실패");
            Ok(Put::Transient)
        }
    }
}

async fn upload_files(c: &Ctx, seq: i64, spec: &UploadSpec) -> Result<(), Stop> {
    let out_dir = c.dir.join("out");
    private_dir(&out_dir).map_err(|_| Stop::Failed("임시 폴더"))?;
    let mut entries = Vec::with_capacity(spec.files.len());
    let mut ids = Vec::with_capacity(spec.files.len());
    for f in &spec.files {
        // 넣을 때와 크기가 다르면 파일이 바뀌었다 — 보내지 않는다.
        if std::fs::metadata(&f.path).map(|m| m.len()).ok() != Some(f.size) {
            return Err(Stop::Failed("파일이 바뀜"));
        }
        let ct_len = blob_ct_len(f.size);
        let mut attempt = 0;
        let (blob_id, fk, prefix, sha) = loop {
            attempt += 1;
            match put_one(c, &out_dir, f, ct_len).await? {
                Put::Done(v) => break v,
                // 네트워크·5xx 는 새 예약으로 몇 번 더(리뷰 ②) — 예약을 거듭 만들면 사용자 합계·시간당 상한이 줄므로 물러서며.
                Put::Transient if attempt < PUT_ATTEMPTS => {
                    tokio::time::sleep(download_backoff(attempt)).await;
                }
                Put::Transient => return Err(Stop::Failed("PUT")),
            }
        };
        let mut e = json!({
            "blob_id": blob_id,
            "name": f.name,
            "mime": f.mime,
            "size": f.size,
            "ct_sha256": encoding::encode(&sha),
            "fk": encoding::encode(&fk),
            "prefix": encoding::encode(&prefix),
        });
        if let Some(r) = &f.role {
            e["role"] = json!(r);
        }
        if let Some((w, h)) = f.size_px {
            e["w"] = json!(w);
            e["h"] = json!(h);
        }
        entries.push(e);
        ids.push(blob_id);
    }
    let mut m = spec.message.clone();
    let text = m
        .pointer("/body/text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    m["blobs"] = json!(ids);
    // 본문의 다른 칸(처음 출처 `origin`·`origin_msg`, 멘션 `mentions`·`of`)은 그대로 둔다 — 봉인 때 MLS 평문 머리로 간다.
    // 새로 만들면 첨부 요청만 출처가 빠져 받는 맥이 동료 기준으로 버렸다(#967 실기).
    let mut body = m
        .get("body")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    body.insert("enc".into(), json!("plain"));
    body.insert("pt".into(), json!("json1"));
    body.insert(
        "text".into(),
        json!(json!({"text": text, "files": entries}).to_string()),
    );
    m["body"] = Value::Object(body);
    // MLS(묶음 22) — 올린 뒤 평문만 두고 봉인은 연결 루프가 큐 맨 앞에서.
    let frame = String::new();
    match c.store.promote_upload(seq, &frame, &m.to_string()) {
        Ok(_) => Ok(()),
        Err(_) => Err(Stop::Failed("큐")),
    }
}

/// 받은 메시지 본문이 `pt=json1` 이면 펼친다: core 에 넘길 `body`(키·해시 뺀 `files`)와 받을 목록. 헤더 `blobs` 와 `files[].blob_id`
/// 의 집합·순서가 다르거나 모양이 틀리면 `None`(bad_envelope).
#[must_use]
pub fn unpack(message: &Value, text: &str) -> Option<(Value, Vec<Download>)> {
    use lodelai_protocol::constants as k;
    let msg_id = message.get("msg_id")?.as_str().filter(|m| is_msg_id(m))?;
    let inner: Value = serde_json::from_str(text).ok()?;
    let body_text = inner.get("text")?.as_str()?;
    let files = inner.get("files")?.as_array()?;
    let header: Vec<&str> = message
        .get("blobs")?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    if files.is_empty()
        || files.len() > k::FILES_PER_MESSAGE as usize
        || files.len() != header.len()
    {
        return None;
    }
    let mut shown = Vec::with_capacity(files.len());
    let mut jobs = Vec::with_capacity(files.len());
    for (i, (f, h)) in files.iter().zip(&header).enumerate() {
        let g = |k: &str| f.get(k).and_then(Value::as_str);
        let blob_id = g("blob_id")?;
        let name = g("name")?;
        let size = f.get("size")?.as_u64()?;
        let (fk, prefix, sha) = (g("fk")?, g("prefix")?, g("ct_sha256")?);
        let ok_keys = encoding::decode_array::<32>(fk, "fk").is_ok()
            && encoding::decode_array::<19>(prefix, "prefix").is_ok()
            && encoding::decode_array::<32>(sha, "ct_sha256").is_ok();
        if blob_id != *h
            || !is_blob_id(blob_id)
            || name.is_empty()
            || name.len() > 255
            || size > k::FILE_MAX_BYTES
            || !ok_keys
        {
            return None;
        }
        let idx = u32::try_from(i).ok()?;
        let mut s = json!({"idx": idx, "blob_id": blob_id, "name": name, "mime": g("mime").unwrap_or(""), "size": size});
        if let Some(r) = g("role") {
            s["role"] = json!(r);
        }
        // 그림 크기(#612, 보낸 사람 주장) — 정수일 때만 넘긴다. 범위 검사는 코어가 한다.
        for k in ["w", "h"] {
            if let Some(n) = f.get(k).and_then(Value::as_u64) {
                s[k] = json!(n);
            }
        }
        shown.push(s);
        jobs.push(Download {
            msg_id: msg_id.to_owned(),
            idx,
            blob_id: blob_id.to_owned(),
            fk: fk.to_owned(),
            prefix: prefix.to_owned(),
            sha256: sha.to_owned(),
            size,
        });
    }
    Some((
        json!({"enc": "plain", "text": body_text, "files": shown}),
        jobs,
    ))
}

/// 첨부 하나를 받는다. 끝(받음·못 받음)이면 표에서 지우고 core 에 알린다. 연결 문제면 그대로 둔다(다음 연결).
pub async fn download(c: Ctx, d: Download) {
    let in_dir = c.dir.join("in");
    if private_dir(&in_dir).is_err() {
        return;
    }
    let outcome = match fetch(&c, &d, &in_dir).await {
        Ok(o) => o,
        Err(()) => return,
    };
    if let AttachmentOutcome::Received { .. }
    | AttachmentOutcome::Failed(AttachmentFailure::BadFile) = &outcome
    {
        // 받았다(틀린 것도) — relay 가 더 들고 있지 않게.
        let _ = c
            .frames
            .send(json!({"t": "blob.fetched", "blob_id": d.blob_id}).to_string());
    }
    match c.store.finish_download(&d.msg_id, d.idx) {
        Ok(true) => {}
        // 받는 사이 코어가 지웠다(drop_downloads — 기기 거부·만료·거두기): 받은 파일을 버리고 알리지 않는다.
        Ok(false) => {
            if let AttachmentOutcome::Received { path, .. } = &outcome {
                let _ = std::fs::remove_file(path);
            }
            return;
        }
        Err(_) => return,
    }
    let _ = c
        .inbound
        .send(Inbound::Attachment {
            msg_id: d.msg_id,
            idx: d.idx,
            blob_id: d.blob_id,
            outcome,
        })
        .await;
}

async fn fetch(c: &Ctx, d: &Download, in_dir: &std::path::Path) -> Result<AttachmentOutcome, ()> {
    // 임시 파일은 blob 마다 하나(#1012 §3) — 누가 받는 중이면 물러선다.
    let tmp = part_path(&c.dir, &d.blob_id);
    let Some(_busy) = PartLock::take(&tmp) else {
        return Err(());
    };
    let token = match ask(
        c,
        'd',
        |req| json!({"t": "blob.get", "req": req, "blob_id": d.blob_id}),
    )
    .await
    {
        Ok((_, token)) => token,
        // 영구: 없음·인가 실패(protocol). 그 밖(rate_limited·internal·시간 초과)은 물러섰다 다시(리뷰 ②).
        Err(Stop::Refused(code, _)) if code == "protocol" => {
            part_done(&tmp);
            return Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable));
        }
        Err(_) => return Err(()),
    };
    let got =
        crate::blobio::get_resume(&c.target, &d.blob_id, &token, &tmp, blob_ct_len(d.size)).await;
    // 일시 오류(끊김·무응답·429·408·5xx)에는 받은 것을 지우지 않는다 — 다음 시도가 이어받는다(#1012 §3).
    let got = match got {
        Ok(Ok(g)) => g,
        Ok(Err(404)) => {
            part_done(&tmp);
            tracing::info!("첨부 GET 404");
            return Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable));
        }
        Ok(Err(code)) => {
            tracing::info!(code, "첨부 GET 거절 — 물러섰다 다시");
            return Err(());
        }
        // 저장 공간이 없다(#1080) — 물러섰다 다시 받아도 같은 자리에서 막혀 끝없이 돈다. 받던 것을 지우고 끝낸다.
        Err(e) if crate::blobio::no_space(&e) => {
            tracing::warn!(error = %e, "첨부 임시 파일을 쓸 저장 공간 없음");
            part_done(&tmp);
            return Ok(AttachmentOutcome::Failed(AttachmentFailure::Storage));
        }
        Err(e) => {
            tracing::info!(error = %e, "첨부 GET 실패 — 물러섰다 다시");
            return Err(());
        }
    };
    let (Ok(fk), Ok(prefix), Ok(sha)) = (
        encoding::decode_array::<32>(&d.fk, "fk"),
        encoding::decode_array::<19>(&d.prefix, "prefix"),
        encoding::decode_array::<32>(&d.sha256, "ct_sha256"),
    ) else {
        part_done(&tmp);
        return Ok(AttachmentOutcome::Failed(AttachmentFailure::BadFile));
    };
    let Ok(base) = local_name(c) else {
        return Err(());
    };
    let out = in_dir.join(&base);
    let (src, dst, id) = (tmp.clone(), out.clone(), d.blob_id.clone());
    let opened = tokio::task::spawn_blocking(move || -> Result<u64, BlobError> {
        let r = std::io::BufReader::new(std::fs::File::open(&src)?);
        let w = std::io::BufWriter::new(private_file(&dst)?);
        open_blob(&fk, &prefix, &id, r, &sha, w)
    })
    .await;
    match opened {
        Ok(Ok(n)) if n == d.size => {
            part_done(&tmp);
            Ok(AttachmentOutcome::Received { path: out, size: n })
        }
        // 풀어 쓸 저장 공간이 없다(#1080) — 다시 해도 같다. 암호문·쓰다 만 것을 지우고 끝낸다.
        Ok(Err(BlobError::Io(e))) if crate::blobio::no_space(&e) => {
            let _ = std::fs::remove_file(&out);
            part_done(&tmp);
            tracing::warn!(error = %e, "첨부를 풀어 쓸 저장 공간 없음");
            Ok(AttachmentOutcome::Failed(AttachmentFailure::Storage))
        }
        // 다 받은 암호문은 둔다 — 다음 시도는 GET 없이 다시 연다.
        Ok(Err(BlobError::Io(e))) => {
            let _ = std::fs::remove_file(&out);
            tracing::warn!(error = %e, "첨부 풀기 입출력 실패 — 물러섰다 다시");
            Err(())
        }
        _ => {
            let _ = std::fs::remove_file(&out);
            // 나눠 받은 것이 틀리면 한 번은 처음부터 다시 받는다(#1012 §4-3). 한 번에 받은 것·다시 받은 것이 틀리면 끝.
            if part_redo(&tmp, got) {
                tracing::info!("나눠 받은 첨부가 틀림 — 처음부터 다시");
                return Err(());
            }
            Ok(AttachmentOutcome::Failed(AttachmentFailure::BadFile))
        }
    }
}

/// 프로필 사진 PUT 한 번의 상한 — 이 행이 큐 맨 앞을 막으므로 첨부(`HTTP_TOTAL`)보다 짧게.
const AVATAR_PUT_WAIT: Duration = Duration::from_secs(60);
/// 프로필 사진 PUT 이 `fails` 번째로 이어서 일시 실패했을 때 같은 행을 다시 올리기까지: `first`, 두 배씩, `max` 까지(#530 —
/// 사진 한 장이 일시 실패로 30초 멈추지 않게, 연결된 채 곧바로 되풀이하지도 않게).
#[must_use]
pub fn avatar_retry_delay(first: Duration, max: Duration, fails: u32) -> Duration {
    first
        .saturating_mul(1u32.checked_shl(fails).unwrap_or(u32::MAX))
        .min(max)
}

/// 프로필 사진 받기(묶음 15 B9, ADR 0009 §8). 사진은 같은 조직이 받는 평문 PNG 라 봉투·FK 가 없다. 받은 바이트 그대로
/// (`AVATAR_MAX_BYTES` 이하) — 디코딩·검사는 코어.
pub struct AvatarFetch {
    pub blob_id: String,
    pub done: oneshot::Sender<crate::Result<Vec<u8>>>,
}

/// 큐 맨 앞의 프로필 사진 행(`avatar`) 하나를 올린다: `blob.reserve{purpose: avatar}` → PUT. relay 가 PNG 를 확인하고
/// `users.avatar_blob` 을 바꾼 뒤 directory.update — 성공은 그것으로 안다. relay 가 거절하면 행을 빼고
/// [`Inbound::AvatarFailed`], 네트워크·시간 초과는 행을 두고 [`avatar_retry_delay`] 뒤 다시(그동안 큐는 멈춘 채). 그사이 지우기·새 사진으로 바뀌었으면(같은
/// 큐 키라 행이 바뀐다) 이 행만 빠진 것이라 아무것도 지우지 않는다. 연결 루프는 이 작업이 끝날 때까지 큐를 보내지 않는다 —
/// 늦게 끝난 PUT 이 뒤의 지우기를 되살리지 않게(계약 856eb04c).
async fn avatar_back_off(c: &Ctx, org: bool) {
    let n = c
        .avatar_fails
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // 처음 실패면 화면에 '네트워크 기다림'을 한 번(조용한 끝없는 재시도였다, 0.2.0) — 거절이 아니라 행은 남아 다시 올린다.
    // 느림 알림([`avatar_upload`])이 이미 냈으면 다시 내지 않는다.
    if n == 0
        && !c
            .avatar_waiting_shown
            .swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        avatar_waiting(c, org).await;
    }
    tokio::time::sleep(avatar_retry_delay(c.avatar_retry.0, c.avatar_retry.1, n)).await;
}

async fn avatar_waiting(c: &Ctx, org: bool) {
    let _ = c
        .inbound
        .send(Inbound::AvatarFailed {
            reason: "waiting_network".into(),
            org,
        })
        .await;
}

/// `org` 면 조직 사진(#554) — `blob.reserve{for: "org"}`, relay 가 예약 때와 PUT 끝에 관리자인지 본다. 답이
/// [`Ctx::avatar_slow_notice`] 넘게 없으면 기다리던 채로 '네트워크 기다림'을 한 번 낸다(relay 가 멈춰 연결은 열림 — 관문 acct ⑤).
pub async fn avatar_upload(c: Ctx, seq: i64, org: bool) {
    let work = avatar_upload_once(&c, seq, org);
    tokio::pin!(work);
    tokio::select! {
        () = &mut work => return,
        () = tokio::time::sleep(c.avatar_slow_notice) => {}
    }
    if !c
        .avatar_waiting_shown
        .swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        tracing::info!("프로필 사진 올리기 답이 늦음 — 기다림 줄");
        avatar_waiting(&c, org).await;
    }
    work.await;
}

async fn avatar_upload_once(c: &Ctx, seq: i64, org: bool) {
    let png = match c.store.upload_spec(seq) {
        Ok(Some(b)) => encoding::decode(&b, "avatar").ok(),
        _ => None,
    };
    let Some(png) = png else {
        tracing::warn!(seq, "프로필 사진 행을 읽을 수 없음 — 행을 뺀다");
        let _ = c.store.remove(seq);
        return;
    };
    let refused = match ask(c, 'a', |req| {
        let mut f =
            json!({"t": "blob.reserve", "req": req, "ct_len": png.len(), "purpose": "avatar"});
        if org {
            f["for"] = json!("org");
        }
        f
    })
    .await
    {
        Err(Stop::Disconnected) => return,
        Err(Stop::Refused(code, _)) => Some(code),
        Err(Stop::Failed(why)) => Some(why.to_owned()),
        Ok((blob_id, token)) => {
            let put = tokio::time::timeout(
                AVATAR_PUT_WAIT,
                crate::blobio::put_bytes(&c.target, &blob_id, &token, &png),
            )
            .await;
            match put {
                Ok(Ok(204)) => None,
                Ok(Ok(status)) => Some(format!("put_{status}")),
                Ok(Err(e)) => {
                    tracing::info!(error = %e, "프로필 사진 PUT 실패 — 물러섰다 다시");
                    avatar_back_off(c, org).await;
                    return;
                }
                Err(_) => {
                    tracing::info!("프로필 사진 PUT 시간 초과 — 물러섰다 다시");
                    avatar_back_off(c, org).await;
                    return;
                }
            }
        }
    };
    c.avatar_fails
        .store(0, std::sync::atomic::Ordering::Relaxed);
    c.avatar_waiting_shown
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = c.store.remove(seq);
    if let Some(reason) = refused {
        tracing::info!(reason, "프로필 사진 올리기 거절");
        let _ = c.inbound.send(Inbound::AvatarFailed { reason, org }).await;
    }
}

pub async fn avatar_fetch(c: Ctx, f: AvatarFetch) {
    let max = lodelai_protocol::constants::AVATAR_MAX_BYTES;
    let (req, rx) = c.waiters.open('p');
    let r = async {
        if c.frames
            .send(json!({"t": "blob.get", "req": req, "blob_id": f.blob_id}).to_string())
            .is_err()
        {
            return Err(crate::Error::Unreachable);
        }
        let token = match tokio::time::timeout(ANSWER_WAIT, rx).await {
            Ok(Ok(Ok((_, token)))) => token,
            Ok(Ok(Err((code, _)))) => return Err(crate::Error::Relay(code)),
            _ => return Err(crate::Error::Unreachable),
        };
        match crate::blobio::get_bytes(&c.target, &f.blob_id, &token, max).await {
            Ok(Ok(b)) => Ok(b),
            Ok(Err(status)) => Err(crate::Error::Relay(format!("get_{status}"))),
            Err(e) => {
                tracing::info!(error = %e, "프로필 사진 GET 실패");
                Err(crate::Error::Unreachable)
            }
        }
    }
    .await;
    let _ = f.done.send(r);
}

/// #881 지난 대화 옮기기 조각 하나(relay blob, `for_device`) — 올린 결과이자 받을 때 필요한 것.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryBlob {
    pub blob_id: String,
    /// 암호문 바이트.
    pub size: u64,
    /// 암호문 SHA-256.
    pub sha256: [u8; 32],
    /// STREAM prefix(조각마다 새 난수).
    pub prefix: [u8; 19],
}

/// #881 조각 동작 — 옮기기의 순서·흐름 제어·다시 하기는 호출자(코어)가 정한다. 여기는 조각 하나만 안다.
pub enum HistoryOp {
    /// `blob.reserve{for_device}` → 조각 키로 봉함 → PUT. relay 거절은 코드 그대로 [`crate::Error::Relay`]
    /// (`quota`·`daily_quota`·`storage_full`·`protocol`·`rate_limited` — 뜻은 호출자가 가른다).
    Put {
        to_device: String,
        key: zeroize::Zeroizing<[u8; 32]>,
        plain: Vec<u8>,
        done: oneshot::Sender<crate::Result<HistoryBlob>>,
    },
    /// `blob.get` → GET → 조각 키로 엶(크기·SHA-256·AEAD 확인). 풀린 크기가 `max_plain` 을 넘는 조각은 받지 않는다.
    Get {
        blob: HistoryBlob,
        key: zeroize::Zeroizing<[u8; 32]>,
        max_plain: u64,
        done: oneshot::Sender<crate::Result<Vec<u8>>>,
    },
    /// `blob.fetched` — 받은 기기가 들인 뒤, 또는 올린 기기가 남은 조각을 치울 때. 답 없음.
    Fetched { blob_id: String },
}

fn history_err(e: Stop) -> crate::Error {
    match e {
        Stop::Disconnected => crate::Error::Unreachable,
        Stop::Failed(why) => crate::Error::Message(why.into()),
        Stop::Refused(code, _) => crate::Error::Relay(code),
    }
}

pub async fn history_put(
    c: Ctx,
    to_device: String,
    key: zeroize::Zeroizing<[u8; 32]>,
    plain: Vec<u8>,
    done: oneshot::Sender<crate::Result<HistoryBlob>>,
) {
    let r = async {
        let ct_len = blob_ct_len(plain.len() as u64);
        let (blob_id, token) = ask(&c, 'h', |req| {
            json!({"t": "blob.reserve", "req": req, "ct_len": ct_len, "purpose": "message", "for_device": to_device})
        })
        .await
        .map_err(history_err)?;
        let prefix: [u8; 19] = random(&c, 19)
            .map_err(history_err)?
            .try_into()
            .map_err(|_| crate::Error::Message("난수".into()))?;
        let id = blob_id.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            let mut ct = Vec::with_capacity(usize::try_from(ct_len).unwrap_or(0));
            seal_blob(&key, &prefix, &id, plain.as_slice(), &mut ct).map(|(len, sha)| (ct, len, sha))
        })
        .await;
        let Ok(Ok((ct, len, sha))) = sealed else {
            return Err(crate::Error::Message("암호화".into()));
        };
        match crate::blobio::put_bytes(&c.target, &blob_id, &token, &ct).await {
            Ok(204) => Ok(HistoryBlob {
                blob_id,
                size: len,
                sha256: sha,
                prefix,
            }),
            Ok(code) => {
                tracing::info!(code, "지난 대화 조각 PUT 거절");
                Err(crate::Error::Relay(format!("put_{code}")))
            }
            Err(e) => {
                tracing::info!(error = %e, "지난 대화 조각 PUT 실패");
                Err(crate::Error::Unreachable)
            }
        }
    }
    .await;
    let _ = done.send(r);
}

/// 받기 일은 결과를 받을 쪽이 사라지면(`done` 이 닫힘 — 코어가 기다림을 버렸다) 그만둔다(#1012 §5-2). 받던 것은 임시
/// 파일에 남아 다음 시도가 잇는다.
pub async fn history_get(
    c: Ctx,
    blob: HistoryBlob,
    key: zeroize::Zeroizing<[u8; 32]>,
    max_plain: u64,
    mut done: oneshot::Sender<crate::Result<Vec<u8>>>,
) {
    let r = tokio::select! {
        r = history_fetch(&c, blob, key, max_plain) => r,
        () = done.closed() => return,
    };
    let _ = done.send(r);
}

async fn history_fetch(
    c: &Ctx,
    blob: HistoryBlob,
    key: zeroize::Zeroizing<[u8; 32]>,
    max_plain: u64,
) -> crate::Result<Vec<u8>> {
    // 보낸 기기가 준 값이 HTTP 요청 줄에 들어간다 — 꼴을 먼저 본다.
    if !is_blob_id(&blob.blob_id) || blob.size > blob_ct_len(max_plain) {
        return Err(crate::Error::Relay("protocol".into()));
    }
    let in_dir = c.dir.join("in");
    if let Err(e) = private_dir(&in_dir) {
        if crate::blobio::no_space(&e) {
            return Err(crate::Error::NoSpace);
        }
        return Err(crate::Error::Message("임시 폴더".into()));
    }
    // 임시 파일은 blob 마다 하나(#1012 §3) — 앞 받기가 아직 쥐고 있으면 물러선다.
    let tmp = part_path(&c.dir, &blob.blob_id);
    let Some(_busy) = PartLock::take(&tmp) else {
        return Err(crate::Error::Unreachable);
    };
    let token = match ask(
        c,
        'h',
        |req| json!({"t": "blob.get", "req": req, "blob_id": blob.blob_id}),
    )
    .await
    {
        Ok((_, token)) => token,
        // 일시 거절(프레임 상한·서버 오류)은 GET 5xx 와 같이 끊김으로 — 받던 것을 남겨 다음 시도가 잇는다.
        Err(Stop::Refused(code, _)) if matches!(code.as_str(), "rate_limited" | "internal") => {
            tracing::info!(code, "지난 대화 조각 표 일시 거절");
            return Err(crate::Error::Unreachable);
        }
        Err(e) => {
            if matches!(e, Stop::Refused(..)) {
                part_done(&tmp);
            }
            return Err(history_err(e));
        }
    };
    let got =
        match crate::blobio::get_resume(&c.target, &blob.blob_id, &token, &tmp, blob.size).await {
            Ok(Ok(g)) => g,
            // 일시(408·429·5xx): 받은 것을 두고 다음 시도가 잇는다(#1012 §3).
            Ok(Err(status @ (408 | 429 | 500..=599))) => {
                tracing::info!(status, "지난 대화 조각 GET 일시 거절");
                return Err(crate::Error::Unreachable);
            }
            Ok(Err(status)) => {
                part_done(&tmp);
                return Err(crate::Error::Relay(format!("get_{status}")));
            }
            // 저장 공간이 없어 임시 파일을 못 썼다(#1080) — 끊김으로 돌리면 다시 받아도 같은 자리에서 막힌다. 받던 것은
            // 지워 자리를 돌려준다.
            Err(e) if crate::blobio::no_space(&e) => {
                tracing::warn!(error = %e, "지난 대화 조각 임시 파일을 쓸 저장 공간 없음");
                part_done(&tmp);
                return Err(crate::Error::NoSpace);
            }
            Err(e) => {
                tracing::info!(error = %e, "지난 대화 조각 GET 실패");
                return Err(crate::Error::Unreachable);
            }
        };
    let src = tmp.clone();
    let opened = tokio::task::spawn_blocking(move || {
        let ct = std::fs::read(&src).ok()?;
        if ct.len() as u64 != blob.size {
            return None;
        }
        let mut out = Vec::new();
        open_blob(
            &key,
            &blob.prefix,
            &blob.blob_id,
            ct.as_slice(),
            &blob.sha256,
            &mut out,
        )
        .ok()
        .map(|_| out)
    })
    .await;
    match opened {
        Ok(Some(out)) => {
            part_done(&tmp);
            Ok(out)
        }
        // 나눠 받은 조각이 틀리면 한 번은 처음부터 다시 받는다(계약 §12). 한 번에 받은 것·다시 받은 것이 틀리면 끝.
        _ if part_redo(&tmp, got) => {
            tracing::info!("나눠 받은 지난 대화 조각이 틀림 — 처음부터 다시");
            Err(crate::Error::Unreachable)
        }
        _ => Err(crate::Error::Message("조각을 열 수 없음".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #530: 사진 PUT 일시 실패 뒤 물러서기 — 5초에서 두 배씩 30초까지, 실패 수가 커도 넘치지 않는다.
    #[test]
    fn avatar_retry_is_5s_doubling_to_30s() {
        let s = Duration::from_secs;
        let d: Vec<_> = (0..6).map(|n| avatar_retry_delay(s(5), s(30), n)).collect();
        assert_eq!(d, [s(5), s(10), s(20), s(30), s(30), s(30)]);
        assert_eq!(avatar_retry_delay(s(5), s(30), u32::MAX), s(30));
    }

    #[test]
    fn relay_supplied_ids_are_checked_before_paths_and_headers() {
        assert!(is_blob_id("AAAAAAAAAAAAAAAAAAAAAA"));
        for bad in [
            "../../etc/passwd_xxxxxx",
            "AAAAAAAAAAAAAAAAAAAA\r\n",
            "/abs/AAAAAAAAAAAAAAAAAA",
            "short",
        ] {
            assert!(!is_blob_id(bad), "{bad}");
        }
        assert!(is_token(&"a".repeat(43)));
        assert!(!is_token(&format!("{}\r\nX: y", "a".repeat(37))));
        assert!(is_msg_id("01HZY3K5J8Q2W9V7M4N6P0R1ST"));
        assert!(!is_msg_id("01HZY3K5J8Q2W9V7M4N6P0R1S/"));
        let w = Waiters::default();
        let (req, mut rx) = w.open('u');
        assert!(w.answer(&json!({"t": "blob.reserved", "req": req, "blob_id": "../x", "put_token": "a".repeat(43)})));
        assert_eq!(rx.try_recv().unwrap(), Err(("protocol".to_owned(), None)));
        // #876: 거절에 같이 온 until 은 그대로 넘긴다.
        let (req, mut rx) = w.open('u');
        assert!(w.answer(&json!({"t": "error", "ref": req, "code": "daily_quota", "until": "2026-11-12T00:00:00Z"})));
        assert_eq!(
            rx.try_recv().unwrap(),
            Err((
                "daily_quota".to_owned(),
                Some("2026-11-12T00:00:00Z".to_owned())
            ))
        );
    }

    #[test]
    fn download_retry_backs_off_30s_2m_then_10m() {
        let secs: Vec<u64> = (1..=5).map(|n| download_backoff(n).as_secs()).collect();
        assert_eq!(secs, [30, 120, 600, 600, 600]);
    }

    #[test]
    fn relay_refusals_map_to_screen_reasons() {
        assert_eq!(refused_reason("quota"), Some("upload_quota"));
        assert_eq!(refused_reason("storage_full"), Some("upload_storage"));
        assert_eq!(refused_reason("daily_quota"), Some("upload_daily"));
        for other in ["rate_limited", "protocol", "internal", "blob_unavailable"] {
            assert_eq!(refused_reason(other), None, "{other}");
        }
    }

    fn entry(id: &str) -> Value {
        json!({"blob_id": id, "name": "a.txt", "mime": "text/plain", "size": 3,
               "fk": encoding::encode(&[1u8; 32]), "prefix": encoding::encode(&[2u8; 19]),
               "ct_sha256": encoding::encode(&[3u8; 32])})
    }

    fn msg(blobs: &[&str]) -> Value {
        json!({"msg_id": "01JB0000000000000000000001", "blobs": blobs})
    }

    #[test]
    fn unpack_requires_header_and_body_to_agree() {
        let (a, b) = ("AAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBB");
        let text = json!({"text": "hi", "files": [entry(a), entry(b)]}).to_string();
        let (body, jobs) = unpack(&msg(&[a, b]), &text).unwrap();
        assert_eq!(body["text"], "hi");
        assert_eq!(body["files"][1]["idx"], 1);
        assert!(body["files"][0].get("fk").is_none());
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[1].blob_id, b);
        // 순서·개수·집합이 다르면 거부.
        assert!(unpack(&msg(&[b, a]), &text).is_none());
        assert!(unpack(&msg(&[a]), &text).is_none());
        // 키 길이가 틀리면 거부.
        let mut bad = entry(a);
        bad["fk"] = json!("AAAA");
        let t = json!({"text": "", "files": [bad]}).to_string();
        assert!(unpack(&msg(&[a]), &t).is_none());
        // 크기 상한·빈 이름.
        let mut big = entry(a);
        big["size"] = json!(lodelai_protocol::constants::FILE_MAX_BYTES + 1);
        assert!(unpack(&msg(&[a]), &json!({"text": "", "files": [big]}).to_string()).is_none());
        let mut noname = entry(a);
        noname["name"] = json!("");
        assert!(unpack(
            &msg(&[a]),
            &json!({"text": "", "files": [noname]}).to_string()
        )
        .is_none());
        assert!(unpack(&msg(&[a]), "not json").is_none());
    }
    // ── #1012 이어받기 ────────────────────────────────────────────────────────

    use crate::blobio::fake_http::{ok, rest, serve, status};
    use crate::blobio::Got;

    const BLOB: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const FK: [u8; 32] = [5; 32];
    const PREFIX: [u8; 19] = [6; 19];

    fn plain() -> Vec<u8> {
        (0..150_000u32).map(|i| (i % 241) as u8).collect()
    }

    /// (암호문, 암호문 SHA-256).
    fn sealed(blob_id: &str) -> (Vec<u8>, [u8; 32]) {
        let mut ct = Vec::new();
        let (_, sha) = seal_blob(&FK, &PREFIX, blob_id, plain().as_slice(), &mut ct).unwrap();
        (ct, sha)
    }

    /// 표(`blob.get`)에 늘 답하는 연결 흉내. `refuse` 면 그 코드로 거절.
    fn ctx(dir: &std::path::Path, target: crate::tls::Target, refuse: Option<&'static str>) -> Ctx {
        let (frames, mut rx) = mpsc::unbounded_channel::<String>();
        let waiters = Arc::new(Waiters::default());
        let w = waiters.clone();
        tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                let v: Value = serde_json::from_str(&f).unwrap();
                if v["t"] != "blob.get" {
                    continue;
                }
                let answer = match refuse {
                    Some(code) => json!({"t": "error", "ref": v["req"], "code": code}),
                    None => json!({"t": "blob.ticket", "req": v["req"], "blob_id": v["blob_id"],
                                   "get_token": "t".repeat(43)}),
                };
                w.answer(&answer);
            }
        });
        let (inbound, _) = mpsc::channel(8);
        Ctx {
            store: Arc::new(Store::open(&dir.join("q.db")).unwrap()),
            keys: DeviceKeys::generate(&[7; 64]),
            rng: Arc::new(lodelai_effects::OsRng),
            target,
            dir: dir.to_owned(),
            frames,
            waiters,
            inbound,
            avatar_retry: (Duration::from_secs(5), Duration::from_secs(30)),
            avatar_slow_notice: Duration::from_secs(30),
            avatar_fails: Arc::default(),
            avatar_waiting_shown: Arc::default(),
        }
    }

    fn job(blob_id: &str, sha: &[u8; 32]) -> Download {
        Download {
            msg_id: "01JB0000000000000000000001".into(),
            idx: 0,
            blob_id: blob_id.into(),
            fk: encoding::encode(&FK),
            prefix: encoding::encode(&PREFIX),
            sha256: encoding::encode(sha),
            size: plain().len() as u64,
        }
    }

    fn in_dir(dir: &std::path::Path) -> PathBuf {
        let d = dir.join("in");
        private_dir(&d).unwrap();
        d
    }

    #[test]
    fn 임시_파일_이름은_blob_id_의_해시이고_시도마다_같다() {
        let dir = std::path::Path::new("/x");
        let a = part_path(dir, BLOB);
        assert_eq!(a, part_path(dir, BLOB));
        assert_ne!(a, part_path(dir, "aAAAAAAAAAAAAAAAAAAAAA"));
        let name = a.file_name().unwrap().to_str().unwrap();
        assert_eq!(a.parent().unwrap(), dir.join("in"));
        assert_eq!(name.len(), 64 + ".part".len());
        assert!(name
            .strip_suffix(".part")
            .unwrap()
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn 끊긴_첨부는_다음_시도가_이어받아_연다() {
        let dir = tempfile::tempdir().unwrap();
        let (ct, sha) = sealed(BLOB);
        let (t, seen) = serve(vec![ok(&ct, 40_000), status(503), rest(&ct, 40_000)]).await;
        let c = ctx(dir.path(), t, None);
        let (d, ind) = (job(BLOB, &sha), in_dir(dir.path()));
        let part = part_path(dir.path(), BLOB);
        // 끊김·5xx 에는 받은 것을 지우지 않는다.
        assert!(fetch(&c, &d, &ind).await.is_err());
        assert_eq!(std::fs::metadata(&part).unwrap().len(), 40_000);
        assert!(fetch(&c, &d, &ind).await.is_err());
        assert_eq!(std::fs::metadata(&part).unwrap().len(), 40_000);
        let Ok(AttachmentOutcome::Received { path, size }) = fetch(&c, &d, &ind).await else {
            panic!("이어받아 받음");
        };
        assert_eq!(size, plain().len() as u64);
        assert_eq!(std::fs::read(path).unwrap(), plain());
        assert!(!part.exists(), "다 받아 열면 지운다");
        assert!(seen.lock().unwrap()[2].contains("Range: bytes=40000-\r\n"));
    }

    #[tokio::test]
    async fn relay_에_없으면_받던_것을_지운다() {
        let (ct, sha) = sealed(BLOB);
        // GET 404.
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![status(404)]).await;
        let c = ctx(dir.path(), t, None);
        let ind = in_dir(dir.path());
        let part = part_path(dir.path(), BLOB);
        std::fs::write(&part, &ct[..100]).unwrap();
        assert!(matches!(
            fetch(&c, &job(BLOB, &sha), &ind).await,
            Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable))
        ));
        assert!(!part.exists());
        // 표 거절(protocol).
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(Vec::new()).await;
        let c = ctx(dir.path(), t, Some("protocol"));
        let ind = in_dir(dir.path());
        let part = part_path(dir.path(), BLOB);
        std::fs::write(&part, &ct[..100]).unwrap();
        assert!(matches!(
            fetch(&c, &job(BLOB, &sha), &ind).await,
            Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable))
        ));
        assert!(!part.exists());
    }

    #[tokio::test]
    async fn 나눠_받은_것의_해시가_틀리면_한_번만_처음부터_다시_받는다() {
        let (ct, sha) = sealed(BLOB);
        let mut bad = ct.clone();
        bad[10] ^= 1;
        // 나눠 받은 것이 틀림 → 지우고 일시 오류, 다시 받은 것이 맞으면 받는다.
        let dir = tempfile::tempdir().unwrap();
        let (t, seen) = serve(vec![rest(&ct, 100), ok(&ct, ct.len())]).await;
        let c = ctx(dir.path(), t, None);
        let (d, ind) = (job(BLOB, &sha), in_dir(dir.path()));
        let part = part_path(dir.path(), BLOB);
        std::fs::write(&part, &bad[..100]).unwrap();
        assert!(fetch(&c, &d, &ind).await.is_err());
        assert!(!part.exists());
        assert!(matches!(
            fetch(&c, &d, &ind).await,
            Ok(AttachmentOutcome::Received { .. })
        ));
        assert!(!seen.lock().unwrap()[1].contains("Range:"));
        // 다시 받은 것도 (또 나눠 받아) 틀리면 끝낸다 — 끝없이 받지 않는다.
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![rest(&ct, 100), ok(&ct, 50), rest(&ct, 50)]).await;
        let c = ctx(dir.path(), t, None);
        let (d, ind) = (job(BLOB, &sha), in_dir(dir.path()));
        let part = part_path(dir.path(), BLOB);
        std::fs::write(&part, &bad[..100]).unwrap();
        assert!(fetch(&c, &d, &ind).await.is_err(), "한 번 더");
        assert!(fetch(&c, &d, &ind).await.is_err(), "끊김");
        std::fs::write(&part, &bad[..50]).unwrap();
        assert!(matches!(
            fetch(&c, &d, &ind).await,
            Ok(AttachmentOutcome::Failed(AttachmentFailure::BadFile))
        ));
        assert!(!part.exists());
        // 다 차 있던 것(GET 없이)이 틀려도 나눠 받은 것으로 친다.
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![ok(&ct, ct.len())]).await;
        let c = ctx(dir.path(), t, None);
        let (d, ind) = (job(BLOB, &sha), in_dir(dir.path()));
        std::fs::write(part_path(dir.path(), BLOB), &bad).unwrap();
        assert!(fetch(&c, &d, &ind).await.is_err());
        assert!(matches!(
            fetch(&c, &d, &ind).await,
            Ok(AttachmentOutcome::Received { .. })
        ));
    }

    #[tokio::test]
    async fn 한_번에_받은_것의_해시가_틀리면_바로_끝낸다() {
        let (ct, sha) = sealed(BLOB);
        let mut bad = ct.clone();
        bad[10] ^= 1;
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![ok(&bad, bad.len())]).await;
        let c = ctx(dir.path(), t, None);
        assert!(matches!(
            fetch(&c, &job(BLOB, &sha), &in_dir(dir.path())).await,
            Ok(AttachmentOutcome::Failed(AttachmentFailure::BadFile))
        ));
        assert!(!part_path(dir.path(), BLOB).exists());
    }

    #[tokio::test]
    async fn 같은_blob_은_하나만_받는다() {
        let (ct, sha) = sealed(BLOB);
        let dir = tempfile::tempdir().unwrap();
        let (t, seen) = serve(vec![ok(&ct, ct.len())]).await;
        let c = ctx(dir.path(), t, None);
        let (d, ind) = (job(BLOB, &sha), in_dir(dir.path()));
        let part = part_path(dir.path(), BLOB);
        let busy = PartLock::take(&part).unwrap();
        assert!(PartLock::take(&part).is_none());
        assert!(fetch(&c, &d, &ind).await.is_err(), "받는 중이면 물러선다");
        assert!(seen.lock().unwrap().is_empty());
        drop(busy);
        assert!(matches!(
            fetch(&c, &d, &ind).await,
            Ok(AttachmentOutcome::Received { .. })
        ));
        assert!(PartLock::take(&part).is_some(), "끝나면 풀린다");
    }

    fn hblob(ct: &[u8], sha: [u8; 32]) -> HistoryBlob {
        HistoryBlob {
            blob_id: BLOB.into(),
            size: ct.len() as u64,
            sha256: sha,
            prefix: PREFIX,
        }
    }

    #[tokio::test]
    async fn 지난_대화_조각도_이어받고_틀린_것은_한_번만_다시_받는다() {
        let (ct, sha) = sealed(BLOB);
        let key = || zeroize::Zeroizing::new(FK);
        let max = plain().len() as u64;
        let dir = tempfile::tempdir().unwrap();
        let (t, seen) = serve(vec![ok(&ct, 30_000), status(503), rest(&ct, 30_000)]).await;
        let c = ctx(dir.path(), t, None);
        let part = part_path(dir.path(), BLOB);
        for _ in 0..2 {
            assert!(matches!(
                history_fetch(&c, hblob(&ct, sha), key(), max).await,
                Err(crate::Error::Unreachable)
            ));
            assert_eq!(part_have(dir.path(), BLOB), 30_000);
        }
        assert_eq!(
            history_fetch(&c, hblob(&ct, sha), key(), max)
                .await
                .unwrap(),
            plain()
        );
        assert!(!part.exists());
        assert!(seen.lock().unwrap()[2].contains("Range: bytes=30000-\r\n"));

        // 나눠 받은 조각이 틀리면 한 번은 끊김으로(처음부터 다시), 한 번에 받은 것이 틀리면 못 여는 조각.
        let mut bad = ct.clone();
        bad[10] ^= 1;
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![rest(&ct, 100), ok(&bad, bad.len())]).await;
        let c = ctx(dir.path(), t, None);
        let part = part_path(dir.path(), BLOB);
        private_dir(&dir.path().join("in")).unwrap();
        std::fs::write(&part, &bad[..100]).unwrap();
        assert!(matches!(
            history_fetch(&c, hblob(&ct, sha), key(), max).await,
            Err(crate::Error::Unreachable)
        ));
        assert!(!part.exists());
        assert!(matches!(
            history_fetch(&c, hblob(&ct, sha), key(), max).await,
            Err(crate::Error::Message(_))
        ));
        assert!(!part.exists());

        // relay 에 없음(404) — 지우고 거절 코드.
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(vec![status(404)]).await;
        let c = ctx(dir.path(), t, None);
        private_dir(&dir.path().join("in")).unwrap();
        std::fs::write(part_path(dir.path(), BLOB), &ct[..100]).unwrap();
        assert!(matches!(
            history_fetch(&c, hblob(&ct, sha), key(), max).await,
            Err(crate::Error::Relay(code)) if code == "get_404"
        ));
        assert_eq!(part_have(dir.path(), BLOB), 0);
    }

    /// 표(`blob.get`)의 일시 거절(프레임 상한·서버 오류)에는 받던 것을 지우지 않는다 — 조각은 끊김으로, 보통 첨부는
    /// 물러섰다 다시. 그 밖 거절(없음·인가 실패)은 지우고 끝낸다.
    #[tokio::test]
    async fn 표의_일시_거절에는_받던_것을_남긴다() {
        let (ct, sha) = sealed(BLOB);
        let key = || zeroize::Zeroizing::new(FK);
        let max = plain().len() as u64;
        for code in ["rate_limited", "internal"] {
            let dir = tempfile::tempdir().unwrap();
            let (t, seen) = serve(Vec::new()).await;
            let c = ctx(dir.path(), t, Some(code));
            let ind = in_dir(dir.path());
            std::fs::write(part_path(dir.path(), BLOB), &ct[..100]).unwrap();
            assert!(
                matches!(
                    history_fetch(&c, hblob(&ct, sha), key(), max).await,
                    Err(crate::Error::Unreachable)
                ),
                "{code}"
            );
            assert_eq!(part_have(dir.path(), BLOB), 100, "{code}");
            assert!(fetch(&c, &job(BLOB, &sha), &ind).await.is_err(), "{code}");
            assert_eq!(part_have(dir.path(), BLOB), 100, "{code}");
            assert!(seen.lock().unwrap().is_empty());
        }
        // 그 밖 거절 — 조각은 거절 코드 그대로, 받던 것은 지운다.
        let dir = tempfile::tempdir().unwrap();
        let (t, _) = serve(Vec::new()).await;
        let c = ctx(dir.path(), t, Some("protocol"));
        in_dir(dir.path());
        std::fs::write(part_path(dir.path(), BLOB), &ct[..100]).unwrap();
        assert!(matches!(
            history_fetch(&c, hblob(&ct, sha), key(), max).await,
            Err(crate::Error::Relay(code)) if code == "protocol"
        ));
        assert_eq!(part_have(dir.path(), BLOB), 0);
    }

    /// 코어가 기다림을 버리면(`done` 이 닫힘) 받기 일이 멈추고 임시 파일을 놓는다 — 받은 것은 남는다.
    #[tokio::test]
    async fn 결과를_받을_쪽이_사라지면_조각_받기를_그만둔다() {
        let (ct, sha) = sealed(BLOB);
        let dir = tempfile::tempdir().unwrap();
        let mut step = ok(&ct, 20_000);
        step.hang = true;
        let (t, _) = serve(vec![step]).await;
        let c = ctx(dir.path(), t, None);
        let part = part_path(dir.path(), BLOB);
        let (done, rx) = oneshot::channel();
        let task = tokio::spawn(history_get(
            c,
            hblob(&ct, sha),
            zeroize::Zeroizing::new(FK),
            plain().len() as u64,
            done,
        ));
        for _ in 0..500 {
            if part_have(dir.path(), BLOB) == 20_000 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(part_have(dir.path(), BLOB), 20_000);
        assert!(PartLock::take(&part).is_none(), "받는 중");
        drop(rx);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("받기 일이 멈춤")
            .unwrap();
        assert!(PartLock::take(&part).is_some());
        assert_eq!(part_have(dir.path(), BLOB), 20_000);
    }

    #[test]
    fn 시작_쓸기는_주인_없는_것과_48시간_넘은_것만_지운다() {
        let dir = tempfile::tempdir().unwrap();
        let ind = in_dir(dir.path());
        let (kept, other, busy) = (
            "KKKKKKKKKKKKKKKKKKKKKK",
            "OOOOOOOOOOOOOOOOOOOOOO",
            "BBBBBBBBBBBBBBBBBBBBBB",
        );
        let stale = ind.join("0123456789abcdef0123456789abcdef.part"); // 옛 판의 무작위 이름
        let received = ind.join("0123456789abcdef0123456789abcdef"); // 받은 평문
        for p in [
            part_path(dir.path(), kept),
            part_path(dir.path(), other),
            part_path(dir.path(), busy),
            stale.clone(),
            received.clone(),
        ] {
            std::fs::write(p, b"x").unwrap();
        }
        let _lock = PartLock::take(&part_path(dir.path(), busy)).unwrap();
        let now = std::time::SystemTime::now();
        assert_eq!(parts_sweep(dir.path(), &[kept], now), 2);
        assert!(part_path(dir.path(), kept).exists());
        assert!(part_path(dir.path(), busy).exists(), "받는 중인 것은 둔다");
        assert!(!part_path(dir.path(), other).exists());
        assert!(!stale.exists());
        assert!(received.exists(), ".part 아닌 것은 건드리지 않는다");
        // 마지막으로 쓴 지 48시간 안이면 두고, 넘으면 주인이 있어도 지운다.
        let soon = now + PART_KEEP - Duration::from_secs(60);
        assert_eq!(parts_sweep(dir.path(), &[kept], soon), 0);
        let late = now + PART_KEEP + Duration::from_secs(60);
        assert_eq!(parts_sweep(dir.path(), &[kept], late), 1);
        assert!(!part_path(dir.path(), kept).exists());
        assert!(part_path(dir.path(), busy).exists());
    }

    #[test]
    fn 한_번_더는_나눠_받은_것에_한_번뿐이고_끝나면_표시를_지운다() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.part");
        assert!(!part_redo(&p, Got::Whole));
        assert!(part_redo(&p, Got::Pieced));
        assert!(!part_redo(&p, Got::Pieced), "두 번째는 끝");
        assert!(part_redo(&p, Got::Pieced), "끝난 뒤엔 표시가 없다");
        part_done(&p);
        assert!(part_redo(&p, Got::Pieced));
        part_done(&p);
    }
}
