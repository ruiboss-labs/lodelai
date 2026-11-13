//! 첨부 올리기·받기(묶음 15 §3). 연결 루프가 연결마다 띄우는 작업들이다 — 연결이 끝나면 멈추고([`Tasks`]), 다음 연결에서 처음부터.
//!
//! - 올리기: 큐 맨 앞이 `upload` 행일 때 하나. 파일마다 `blob.reserve` → (그때 받은 blob_id 를 AAD 로) 새 FK·prefix 로
//!   `seal_blob` → PUT. 다 올리면 헤더 `blobs`·본문 `pt=json1` 로 봉투·서명해 그 행을 `send` 로 바꾼다. 실패는 행을 빼고
//!   `Nack` — relay 의 `quota` 는 `upload_quota`(F6), `storage_full` 은 `upload_storage`(F7), 그 밖(형식·네트워크·파일이 바뀜)은
//!   `upload_failed`. 연결이 끊긴 것은 실패가 아니다(다음 연결에서 다시).
//! - 받기: `downloads` 표의 것을 동시 2개까지. `blob.get` → GET(임시) → `open_blob`(해시 먼저) → `blobs-in/<msg_id>-<idx>`.
//!   relay 에 없으면 `Unavailable`, 해시·AEAD 가 틀리면 `BadFile`(둘 다 다시 받지 않음), 네트워크·입출력은 행을 두고
//!   연결된 채 [`download_backoff`] 뒤에 다시(연결이 바뀌면 처음부터).

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
pub fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// 새 파일을 0600 으로(남은 것이 있으면 지우고) — 풀어 둔 평문 첨부가 다른 사용자에게 읽히지 않게.
pub fn private_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
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

/// 임시 파일 이름 — relay·보낸 사람이 준 값(blob_id·msg_id)으로 로컬 경로를 만들지 않는다(묶음 15 리뷰 ③).
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
            return Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable))
        }
        Err(_) => return Err(()),
    };
    let Ok(base) = local_name(c) else {
        return Err(());
    };
    let tmp = in_dir.join(format!("{base}.part"));
    let out = in_dir.join(&base);
    let got = crate::blobio::get(&c.target, &d.blob_id, &token, &tmp, blob_ct_len(d.size)).await;
    match got {
        Ok(Ok(())) => {}
        Ok(Err(404)) => {
            let _ = std::fs::remove_file(&tmp);
            tracing::info!("첨부 GET 404");
            return Ok(AttachmentOutcome::Failed(AttachmentFailure::Unavailable));
        }
        // 429·408·5xx 등은 일시(리뷰 ②) — 행을 두고 물러섰다 다시.
        Ok(Err(code)) => {
            let _ = std::fs::remove_file(&tmp);
            tracing::info!(code, "첨부 GET 거절 — 물러섰다 다시");
            return Err(());
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            tracing::info!(error = %e, "첨부 GET 실패 — 물러섰다 다시");
            return Err(());
        }
    }
    let (Ok(fk), Ok(prefix), Ok(sha)) = (
        encoding::decode_array::<32>(&d.fk, "fk"),
        encoding::decode_array::<19>(&d.prefix, "prefix"),
        encoding::decode_array::<32>(&d.sha256, "ct_sha256"),
    ) else {
        let _ = std::fs::remove_file(&tmp);
        return Ok(AttachmentOutcome::Failed(AttachmentFailure::BadFile));
    };
    let (src, dst, id) = (tmp.clone(), out.clone(), d.blob_id.clone());
    let opened = tokio::task::spawn_blocking(move || -> Result<u64, BlobError> {
        let r = std::io::BufReader::new(std::fs::File::open(&src)?);
        let w = std::io::BufWriter::new(private_file(&dst)?);
        open_blob(&fk, &prefix, &id, r, &sha, w)
    })
    .await;
    let _ = std::fs::remove_file(&tmp);
    match opened {
        Ok(Ok(n)) if n == d.size => Ok(AttachmentOutcome::Received { path: out, size: n }),
        Ok(Err(BlobError::Io(e))) => {
            let _ = std::fs::remove_file(&out);
            tracing::warn!(error = %e, "첨부 풀기 입출력 실패 — 물러섰다 다시");
            Err(())
        }
        _ => {
            let _ = std::fs::remove_file(&out);
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

pub async fn history_get(
    c: Ctx,
    blob: HistoryBlob,
    key: zeroize::Zeroizing<[u8; 32]>,
    max_plain: u64,
    done: oneshot::Sender<crate::Result<Vec<u8>>>,
) {
    let r = async {
        // 보낸 기기가 준 값이 HTTP 요청 줄에 들어간다 — 꼴을 먼저 본다.
        if !is_blob_id(&blob.blob_id) || blob.size > blob_ct_len(max_plain) {
            return Err(crate::Error::Relay("protocol".into()));
        }
        let (_, token) = ask(
            &c,
            'h',
            |req| json!({"t": "blob.get", "req": req, "blob_id": blob.blob_id}),
        )
        .await
        .map_err(history_err)?;
        let ct = match crate::blobio::get_bytes(&c.target, &blob.blob_id, &token, blob.size).await {
            Ok(Ok(b)) => b,
            Ok(Err(status)) => return Err(crate::Error::Relay(format!("get_{status}"))),
            Err(e) => {
                tracing::info!(error = %e, "지난 대화 조각 GET 실패");
                return Err(crate::Error::Unreachable);
            }
        };
        if ct.len() as u64 != blob.size {
            return Err(crate::Error::Message("조각 크기가 다름".into()));
        }
        let opened = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            open_blob(
                &key,
                &blob.prefix,
                &blob.blob_id,
                ct.as_slice(),
                &blob.sha256,
                &mut out,
            )
            .map(|_| out)
        })
        .await;
        match opened {
            Ok(Ok(out)) => Ok(out),
            _ => Err(crate::Error::Message("조각을 열 수 없음".into())),
        }
    }
    .await;
    let _ = done.send(r);
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
}
