//! 첨부 HTTP(묶음 15 §3): `PUT`·`GET /v1/blobs/{blob_id}` 를 파일 ↔ 소켓 스트리밍으로. 파일 전체를 메모리에 올리지 않는다.
//! 토큰은 로그에 남기지 않는다.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::tls::Target;

/// 한 번의 PUT·GET 전체 상한(25 MiB 를 느린 회선으로도).
const HTTP_TOTAL: Duration = Duration::from_secs(600);
/// 응답 머리 줄 상한.
const HEAD_MAX: usize = 8 * 1024;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn connect(t: &Target) -> std::io::Result<Box<dyn Io>> {
    let tcp = TcpStream::connect((t.host.as_str(), t.port)).await?;
    if !t.tls {
        return Ok(Box::new(tcp));
    }
    let name = rustls::pki_types::ServerName::try_from(t.host.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let s = tokio_rustls::TlsConnector::from(crate::tls::client_config())
        .connect(name, tcp)
        .await?;
    Ok(Box::new(s))
}

fn bad(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_owned())
}

/// 응답 머리를 읽는다: (상태 코드, Content-Length). 본문은 `r` 에 남는다.
async fn read_head(r: &mut BufReader<Box<dyn Io>>) -> std::io::Result<(u16, Option<u64>)> {
    read_head_with(r, |_, _| {}).await
}

/// [`read_head`] + 머리 줄마다 `on_header(이름, 값)`.
async fn read_head_with(
    r: &mut BufReader<Box<dyn Io>>,
    mut on_header: impl FnMut(&str, &str),
) -> std::io::Result<(u16, Option<u64>)> {
    let mut total = 0usize;
    let mut status = None;
    let mut len = None;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await?;
        total += n;
        if n == 0 || total > HEAD_MAX {
            return Err(bad("HTTP 응답 머리"));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if status.is_none() {
            status = line.split_whitespace().nth(1).and_then(|c| c.parse().ok());
            if status.is_none() {
                return Err(bad("HTTP 상태 줄"));
            }
        } else if let Some((k, v)) = line.split_once(':') {
            on_header(k.trim(), v.trim());
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().ok();
            }
        }
    }
    Ok((status.unwrap_or(0), len))
}

/// relay 판 범위 헤더(묶음 22 §12-28, `<MIN>-<VERSION>`). 8 이상 relay 는 `/v1/ws` 101 과 `/v1/healthz` 에 싣는다.
pub const PROTOCOL_HEADER: &str = "lodelai-protocol";

/// relay 서버 이름 헤더(22 §12-29). 8 이상 relay 는 [`PROTOCOL_HEADER`] 와 같은 자리에 싣는다.
pub const SERVER_HEADER: &str = "lodelai-server";

/// relay 가 켠 기능 헤더(22 §12-30, 쉼표 목록·켠 것이 없으면 `none`). 8 이상 relay 는 [`PROTOCOL_HEADER`] 와 같은 자리에 늘 싣는다.
pub const FEATURES_HEADER: &str = "lodelai-features";

/// [`FEATURES_HEADER`] 값 → 그룹을 쓸 수 있나. 줄이 없으면(8 전 relay·터널이 지움) 모름 `None`, 있으면 목록에 `groups` 가
/// 있는지(`none` 이면 `false`).
#[must_use]
pub fn groups_of(features: Option<&str>) -> Option<bool> {
    features.map(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("groups"))
    })
}

/// [`PROTOCOL_HEADER`] 값(`<MIN>-<VERSION>`)을 `(min, max)` 로. 꼴이 틀리면 `None`.
#[must_use]
pub fn protocol_range(value: &str) -> Option<(u32, u32)> {
    let (a, b) = value.trim().split_once('-')?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// [`FEATURES_HEADER`] 값 → 이 relay 가 `device.name`(#490 28 §4)을 아나. 줄이 없으면(옛 relay·터널이 지움) `false` —
/// 모르는 relay 에 보내면 ref 없는 `error{protocol}` 이 와 관리 요청의 답과 섞이므로 '해 봄' 없이 보내지 않는다(계약 749b8afa).
#[must_use]
pub fn device_name_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("device_name"))
    })
}

/// 기능 헤더에 `device_os`(판 15 — `device.name` 의 `os` 칸을 아는 relay)가 있나. 없거나 모르면 `false`(싣지 않는다 — 옛
/// relay 는 모르는 칸이 든 device.name 을 error{protocol} 로 거절한다).
#[must_use]
pub fn device_os_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("device_os"))
    })
}

/// 기능 헤더에 `kp_reset`(0.2.5 g025f B — `key_packages.publish.reset` 을 아는 relay)이 있나. 없거나 모르면 `false`(싣지 않는다 —
/// 옛 relay 는 모르는 칸이 든 프레임을 error{protocol} 로 거절한다).
#[must_use]
pub fn kp_reset_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("kp_reset"))
    })
}

/// 기능 헤더에 `unreadable_ack`(0.2.6 #809 — `delivered_ack.unreadable` 을 아는 relay)이 있나. 없거나 모르면 `false`(싣지 않는다 —
/// 옛 relay 는 모르는 칸이 든 프레임을 error{protocol} 로 거절한다).
#[must_use]
pub fn unreadable_ack_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("unreadable_ack"))
    })
}

/// relay 가 내 기기 맞추기 글(own_control·own_control_result·own_delete)과 own_stream·own_alert 를 받는가(#870·#872 —
/// 판 숫자가 아니라 이 기능 표시로만 켠다).
#[must_use]
pub fn own_control_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("own_control"))
    })
}

/// relay 가 hello `look` 을 받고 디렉터리에 look 을 싣는가(#874 — 판 상한 조건과 OR 은 conn 의 own_known).
#[must_use]
pub fn look_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case("look")))
}

/// relay 가 연락처(#845 link.*·디렉터리 links)를 아는가 — 기능 표시 `contacts`.
#[must_use]
pub fn contacts_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("contacts"))
    })
}

/// relay 가 가입 뒤 조직 옮기기(#845 §7-46 `org.code.check`·`org.join`·`org.create`)를 아는가 — 기능 표시 `org_move`
/// (판으로 대신하지 않는다 — §7-46 은 PROTOCOL 을 올리지 않음).
#[must_use]
pub fn org_move_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("org_move"))
    })
}

/// relay 가 조직 나가기(#877 `org.leave` — 개인 공간으로 옮김)를 아는가 — 기능 표시 `org_leave`.
#[must_use]
pub fn org_leave_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("org_leave"))
    })
}

/// relay 101 의 `Lodelai-Features` 에 그 기능 표시가 있는가(#845 둘째의 `lists`·`org_external`·`org_external_preview`).
#[must_use]
pub fn feature_of(features: Option<&str>, name: &str) -> bool {
    features.is_some_and(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case(name)))
}

/// relay 가 조직 고유색(`org.update{color}` · 디렉터리 `org.color` · 초대의 `org_color`)을 아는가 — 기능 표시 `org_color`.
#[must_use]
pub fn org_color_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("org_color"))
    })
}

/// #961: relay 가 세션 liveness `live:next_turn`·hello.next_turn 을 아나.
#[must_use]
pub fn next_turn_of(features: Option<&str>) -> bool {
    feature_of(features, "next_turn")
}

/// relay 가 디렉터리 내 기기 항목의 `away`(#870 맥 잠듦 — sleep·quit·lost)를 아는가 — 기능 표시 `away`.
#[must_use]
pub fn away_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case("away")))
}

/// relay 가 계정 단위 대화 고정(#880 pin.set·디렉터리 pins)을 아는가 — 기능 표시 `pins`.
#[must_use]
pub fn pins_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case("pins")))
}

/// relay 가 지난 대화 옮기기 조각(#881 blob.reserve `for_device`)을 아는가 — 기능 표시 `history_transfer`.
#[must_use]
pub fn history_transfer_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("history_transfer"))
    })
}

/// relay 가 계정 단위 대화 음소거(#845 §7-56 mute.set·디렉터리 mutes)를 아는가 — 기능 표시 `mutes`.
#[must_use]
pub fn mutes_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| v.split(',').any(|f| f.trim().eq_ignore_ascii_case("mutes")))
}

/// relay 가 기기별 알림 갈래 끄기(#845 §7-55 push.register.off)를 아는가 — 기능 표시 `push_prefs`.
#[must_use]
pub fn push_prefs_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("push_prefs"))
    })
}

/// relay 가 `own_alert.kind`(#890 — card·usage)를 아는가 — 기능 표시 `own_alert_kinds`.
#[must_use]
pub fn own_alert_kinds_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("own_alert_kinds"))
    })
}

/// relay 가 실시간 현황(#882 — C→S `own_live`, S→C `own_live.want`)을 아는가 — 기능 표시 `own_live`.
#[must_use]
pub fn own_live_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("own_live"))
    })
}

/// relay 가 hello `no_duty` 를 받는가(푸시 설정과 무관하게 늘 알린다 — 서버 고르기 §3, 옛 relay 는 푸시를 켰을 때만).
#[must_use]
pub fn no_duty_of(features: Option<&str>) -> bool {
    features.is_some_and(|v| {
        v.split(',')
            .any(|f| f.trim().eq_ignore_ascii_case("no_duty"))
    })
}

/// `GET /v1/healthz` 응답 머리에서 읽은 것. 헤더가 없으면(8 전 relay·터널이 지움) `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthzHeaders {
    /// [`PROTOCOL_HEADER`] 값(`<MIN>-<VERSION>`).
    pub protocol: Option<String>,
    /// [`SERVER_HEADER`] 값.
    pub server: Option<String>,
    /// [`FEATURES_HEADER`] 값. 그룹 여부는 [`groups_of`].
    pub features: Option<String>,
}

impl HealthzHeaders {
    /// [`PROTOCOL_HEADER`] 를 `(min, max)` 로. 꼴이 틀리면 `None`.
    #[must_use]
    pub fn protocol_range(&self) -> Option<(u32, u32)> {
        protocol_range(self.protocol.as_deref()?)
    }

    /// 그룹을 쓸 수 있나([`groups_of`]).
    #[must_use]
    pub fn groups(&self) -> Option<bool> {
        groups_of(self.features.as_deref())
    }
}

/// `GET /v1/healthz` 응답 머리의 판 범위·서버 이름 헤더(§12-28 ②·§12-29). 상태 코드는 보지 않는다.
///
/// # Errors
/// 연결·읽기 실패, 응답 머리 형식, 시간 초과(5초).
pub async fn healthz_headers(t: &Target) -> std::io::Result<HealthzHeaders> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut s = connect(t).await?;
        let head = format!(
            "GET /v1/healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            t.host_header()
        );
        s.write_all(head.as_bytes()).await?;
        let mut r = BufReader::new(s);
        let mut h = HealthzHeaders::default();
        read_head_with(&mut r, |k, v| {
            if k.eq_ignore_ascii_case(PROTOCOL_HEADER) {
                h.protocol = Some(v.to_owned());
            } else if k.eq_ignore_ascii_case(SERVER_HEADER) {
                h.server = Some(v.to_owned());
            } else if k.eq_ignore_ascii_case(FEATURES_HEADER) {
                h.features = Some(v.to_owned());
            }
        })
        .await?;
        Ok(h)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "healthz 시간 초과"))?
}

/// `GET /v1/healthz` 응답에 [`PROTOCOL_HEADER`] 가 있나(§12-28 ② — 101 헤더를 터널이 지웠을 때 가른다).
///
/// # Errors
/// [`healthz_headers`] 와 같다.
pub async fn healthz_has_protocol(t: &Target) -> std::io::Result<bool> {
    Ok(healthz_headers(t).await?.protocol.is_some())
}

/// `path` 의 `len` 바이트를 올린다. 상태 코드(204 = 성공).
///
/// # Errors
/// 연결·읽기·쓰기 실패, 시간 초과.
pub async fn put(
    t: &Target,
    blob_id: &str,
    token: &str,
    path: &Path,
    len: u64,
) -> std::io::Result<u16> {
    let f = tokio::fs::File::open(path).await?.take(len);
    put_from(t, blob_id, token, f, len).await
}

/// 메모리의 바이트를 그대로 올린다(프로필 사진 — 평문 PNG, 묶음 15 B9). 상태 코드(204 = 성공).
///
/// # Errors
/// 연결·쓰기 실패, 시간 초과.
pub async fn put_bytes(
    t: &Target,
    blob_id: &str,
    token: &str,
    body: &[u8],
) -> std::io::Result<u16> {
    put_from(t, blob_id, token, body, body.len() as u64).await
}

async fn put_from(
    t: &Target,
    blob_id: &str,
    token: &str,
    mut body: impl AsyncRead + Unpin,
    len: u64,
) -> std::io::Result<u16> {
    tokio::time::timeout(HTTP_TOTAL, async {
        let mut s = connect(t).await?;
        let head = format!(
            "PUT /v1/blobs/{blob_id} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\n\r\n",
            t.host_header()
        );
        s.write_all(head.as_bytes()).await?;
        tokio::io::copy(&mut body, &mut s).await?;
        s.flush().await?;
        let mut r = BufReader::new(s);
        Ok(read_head(&mut r).await?.0)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "PUT 시간 초과"))?
}

/// 이어받는 GET 에서 바이트가 이만큼 안 오면 끊는다(#1012 §2-5 — 뒤로 간 휴대폰의 죽은 소켓을 [`HTTP_TOTAL`] 동안
/// 붙들지 않게). 연결·머리 읽기에도 건다.
pub const GET_IDLE: Duration = Duration::from_secs(30);

/// [`get_resume`] 가 임시 파일을 다 채운 길.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Got {
    /// 이번 요청 하나로 처음부터 끝까지(200).
    Whole,
    /// 앞 시도가 남긴 것에 이어(206), 또는 이미 다 차 있어 GET 없이 — 여러 번에 나눠 받은 것.
    Pieced,
}

/// `Content-Range: bytes N-M/L` → `(N, M, L)`.
fn content_range(v: &str) -> Option<(u64, u64, u64)> {
    let rest = v.trim().strip_prefix("bytes")?.trim_start();
    let (range, total) = rest.split_once('/')?;
    let (a, b) = range.split_once('-')?;
    Some((
        a.trim().parse().ok()?,
        b.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// 임시 파일을 0600 으로 열어(없으면 만든다) 길이를 `start` 로 맞추고 그 자리에 선다 — 200 은 0(비움), 206 은 받은 길이.
/// append 로 열지 않는다: 그만둔 앞 작업의 늦은 쓰기가 떨어져도 같은 자리 같은 바이트다.
fn open_part(path: &Path, start: u64) -> std::io::Result<std::fs::File> {
    use std::io::Seek;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.set_len(start)?;
    f.seek(std::io::SeekFrom::Start(start))?;
    Ok(f)
}

/// 저장 공간이 없어 난 쓰기 실패인가(ENOSPC·EDQUOT, #1080) — 다시 해도 같은 자리에서 막힌다.
#[must_use]
pub fn no_space(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
    )
}

fn remove_part(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// 임시 파일 `part` 에 이어받는다(#1012 §2). 받다 만 것이 있으면 `Range` 를 보내 206 이면 이어 쓰고, 200 이면(옛 relay·
/// 범위를 떼는 중간자) 비우고 처음부터 쓴다. 이미 다 차 있으면 GET 없이 [`Got::Pieced`].
///
/// 끊김·무응답([`GET_IDLE`])·시간 초과는 오류이고 그때까지 쓴 것은 남는다(파일 길이 = 받은 길이). 200·206 이 아닌 상태는
/// `Ok(Err(상태))` 로 돌려주고 임시 파일을 건드리지 않는다(지울지는 호출자). 206 의 범위·길이가 어긋나면 임시 파일을
/// 지우고 오류(다음 시도는 처음부터).
///
/// # Errors
/// 연결·읽기·쓰기 실패, 길이·범위 불일치, 무응답, 시간 초과.
pub async fn get_resume(
    t: &Target,
    blob_id: &str,
    token: &str,
    part: &Path,
    want_len: u64,
) -> std::io::Result<Result<Got, u16>> {
    get_resume_with(t, blob_id, token, part, want_len, GET_IDLE).await
}

/// [`get_resume`] — 무응답 상한을 받는다(시험).
pub(crate) async fn get_resume_with(
    t: &Target,
    blob_id: &str,
    token: &str,
    part: &Path,
    want_len: u64,
    idle: Duration,
) -> std::io::Result<Result<Got, u16>> {
    let mut have = match std::fs::metadata(part) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    if have > want_len {
        remove_part(part);
        have = 0;
    }
    if have > 0 && have == want_len {
        return Ok(Ok(Got::Pieced));
    }
    let silent = || std::io::Error::new(std::io::ErrorKind::TimedOut, "GET 무응답");
    tokio::time::timeout(HTTP_TOTAL, async {
        let mut s = tokio::time::timeout(idle, connect(t))
            .await
            .map_err(|_| silent())??;
        let range = if have > 0 {
            format!("Range: bytes={have}-\r\n")
        } else {
            String::new()
        };
        let head = format!(
            "GET /v1/blobs/{blob_id} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n{range}\r\n",
            t.host_header()
        );
        s.write_all(head.as_bytes()).await?;
        let mut r = BufReader::new(s);
        let mut cr = None;
        let (status, len) = tokio::time::timeout(
            idle,
            read_head_with(&mut r, |k, v| {
                if k.eq_ignore_ascii_case("content-range") {
                    cr = Some(content_range(v));
                }
            }),
        )
        .await
        .map_err(|_| silent())??;
        let (start, got) = match status {
            206 => {
                let fits = have > 0
                    && cr == Some(Some((have, want_len - 1, want_len)))
                    && len == Some(want_len - have);
                if !fits {
                    remove_part(part);
                    return Err(bad("GET 범위 응답"));
                }
                (have, Got::Pieced)
            }
            200 => {
                if len != Some(want_len) {
                    return Err(bad("GET 길이"));
                }
                (0, Got::Whole)
            }
            other => return Ok(Err(other)),
        };
        let mut f = tokio::fs::File::from_std(open_part(part, start)?);
        let mut left = want_len - start;
        let mut buf = vec![0u8; 64 * 1024];
        let body: std::io::Result<()> = async {
            while left > 0 {
                let cap = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                let n = tokio::time::timeout(idle, r.read(&mut buf[..cap]))
                    .await
                    .map_err(|_| silent())??;
                if n == 0 {
                    return Err(bad("GET 본문이 짧다"));
                }
                f.write_all(&buf[..n]).await?;
                left -= n as u64;
            }
            Ok(())
        }
        .await;
        // 끊겨 나갈 때도 쓴 것을 내려 둔다 — 호출자가 바로 받은 길이를 본다.
        let flushed = f.flush().await;
        body?;
        flushed?;
        drop(f);
        if std::fs::metadata(part)?.len() != want_len {
            remove_part(part);
            return Err(bad("GET 임시 파일 길이"));
        }
        Ok(Ok(got))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "GET 시간 초과"))?
}

/// 받아서 메모리로(프로필 사진). 길이를 모르므로 `Content-Length` 가 있고 `max` 이하일 때만 읽는다.
///
/// # Errors
/// 연결·읽기 실패, 길이 없음·상한 넘음·본문이 짧음, 시간 초과.
pub async fn get_bytes(
    t: &Target,
    blob_id: &str,
    token: &str,
    max: u64,
) -> std::io::Result<Result<Vec<u8>, u16>> {
    tokio::time::timeout(HTTP_TOTAL, async {
        let mut s = connect(t).await?;
        let head = format!(
            "GET /v1/blobs/{blob_id} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n\r\n",
            t.host_header()
        );
        s.write_all(head.as_bytes()).await?;
        let mut r = BufReader::new(s);
        let (status, len) = read_head(&mut r).await?;
        if status != 200 {
            return Ok(Err(status));
        }
        let Some(len) = len.filter(|l| *l <= max) else {
            return Err(bad("GET 길이"));
        };
        let mut body = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        (&mut r).take(len).read_to_end(&mut body).await?;
        if body.len() as u64 != len {
            return Err(bad("GET 본문이 짧다"));
        }
        Ok(Ok(body))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "GET 시간 초과"))?
}

#[cfg(test)]
mod no_space_tests {
    use super::no_space;

    /// #1080: 저장 공간 없음(ENOSPC)·할당량 넘음(EDQUOT)만 참 — 끊김·권한 같은 다른 실패는 아니다.
    #[test]
    fn 저장_공간_없음만_가린다() {
        let edquot = if cfg!(target_os = "linux") { 122 } else { 69 };
        assert!(no_space(&std::io::Error::from_raw_os_error(28)));
        assert!(no_space(&std::io::Error::from_raw_os_error(edquot)));
        // EACCES·EPIPE·시간 초과.
        assert!(!no_space(&std::io::Error::from_raw_os_error(13)));
        assert!(!no_space(&std::io::Error::from_raw_os_error(32)));
        assert!(!no_space(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "GET 무응답"
        )));
    }
}

#[cfg(test)]
mod own_control_tests {
    use super::own_control_of;

    #[test]
    fn own_control_은_기능_표시가_있을_때만() {
        assert!(own_control_of(Some("groups, own_control,look")));
        assert!(own_control_of(Some("OWN_CONTROL")));
        assert!(!own_control_of(Some("groups,own_control_result")));
        assert!(!own_control_of(Some("none")));
        assert!(!own_control_of(None));
    }

    #[test]
    fn own_alert_종류는_기능_표시가_있을_때만() {
        use super::own_alert_kinds_of;
        assert!(own_alert_kinds_of(Some("own_control, own_alert_kinds")));
        assert!(!own_alert_kinds_of(Some("own_control,own_alert")));
        assert!(!own_alert_kinds_of(None));
        use super::own_live_of;
        assert!(own_live_of(Some("own_control,own_live")));
        assert!(!own_live_of(Some("own_control,own_live_x")));
    }
}

/// 시험용 가짜 HTTP — 연결마다 정한 응답 하나를 돌려주고 받은 요청 머리를 적는다.
#[cfg(test)]
pub(crate) mod fake_http {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::tls::Target;

    pub(crate) struct Step {
        pub head: String,
        pub body: Vec<u8>,
        /// 본문을 보낸 뒤 닫지 않고 붙든다(무응답).
        pub hang: bool,
    }

    /// 200 — `Content-Length` 는 전체, 본문은 앞 `send` 바이트만(전체보다 짧으면 끊긴 것).
    pub(crate) fn ok(data: &[u8], send: usize) -> Step {
        Step {
            head: format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n\r\n",
                data.len()
            ),
            body: data[..send].to_vec(),
            hang: false,
        }
    }

    /// 206 — `from` 뒤 전부.
    pub(crate) fn rest(data: &[u8], from: usize) -> Step {
        Step {
            head: format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {from}-{}/{}\r\nContent-Length: {}\r\n\r\n",
                data.len() - 1,
                data.len(),
                data.len() - from
            ),
            body: data[from..].to_vec(),
            hang: false,
        }
    }

    pub(crate) fn status(code: u16) -> Step {
        Step {
            head: format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n"),
            body: Vec::new(),
            hang: false,
        }
    }

    /// 차례대로 응답하는 서버. 돌려주는 것: 붙을 곳, 받은 요청 머리들.
    pub(crate) async fn serve(steps: Vec<Step>) -> (Target, Arc<Mutex<Vec<String>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            for step in steps {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(n) if n > 0 => req.extend_from_slice(&b[..n]),
                        _ => break,
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req).into_owned());
                let _ = s.write_all(step.head.as_bytes()).await;
                let _ = s.write_all(&step.body).await;
                let _ = s.flush().await;
                if step.hang {
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                        drop(s);
                    });
                } else {
                    let _ = s.shutdown().await;
                }
            }
        });
        (
            Target {
                tls: false,
                host: "127.0.0.1".into(),
                port,
            },
            seen,
        )
    }
}

/// #1012 §2 — 이어받는 GET.
#[cfg(test)]
mod resume_tests {
    use super::fake_http::{ok, rest, serve, status, Step};
    use super::*;

    const ID: &str = "AAAAAAAAAAAAAAAAAAAAAA";

    fn data() -> Vec<u8> {
        (0..200_000u32).map(|i| (i % 251) as u8).collect()
    }

    fn token() -> String {
        "t".repeat(43)
    }

    async fn run(t: &Target, part: &Path, want: u64) -> std::io::Result<Result<Got, u16>> {
        get_resume_with(t, ID, &token(), part, want, Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn 처음_받기는_범위_없이_200_을_통째로_쓴다() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        let d = data();
        let (t, seen) = serve(vec![ok(&d, d.len())]).await;
        assert_eq!(
            run(&t, &part, d.len() as u64).await.unwrap(),
            Ok(Got::Whole)
        );
        assert_eq!(std::fs::read(&part).unwrap(), d);
        assert_eq!(
            std::fs::metadata(&part).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!seen.lock().unwrap()[0].to_lowercase().contains("range:"));
    }

    #[tokio::test]
    async fn 끊긴_뒤에는_받은_자리부터_이어받아_원본과_같다() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        let d = data();
        let cut = 70_001;
        let (t, seen) = serve(vec![ok(&d, cut), rest(&d, cut)]).await;
        assert!(run(&t, &part, d.len() as u64).await.is_err(), "끊김");
        assert_eq!(std::fs::metadata(&part).unwrap().len(), cut as u64);
        assert_eq!(
            run(&t, &part, d.len() as u64).await.unwrap(),
            Ok(Got::Pieced)
        );
        assert_eq!(std::fs::read(&part).unwrap(), d);
        assert!(seen.lock().unwrap()[1].contains(&format!("Range: bytes={cut}-\r\n")));
    }

    #[tokio::test]
    async fn 범위를_보냈는데_200_이면_비우고_처음부터_쓴다() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        let d = data();
        std::fs::write(&part, vec![9u8; 1234]).unwrap();
        let (t, seen) = serve(vec![ok(&d, d.len())]).await;
        assert_eq!(
            run(&t, &part, d.len() as u64).await.unwrap(),
            Ok(Got::Whole)
        );
        assert_eq!(std::fs::read(&part).unwrap(), d);
        assert!(seen.lock().unwrap()[0].contains("Range: bytes=1234-\r\n"));
    }

    #[tokio::test]
    async fn 범위_응답의_시작_전체_길이가_어긋나면_임시_파일을_지운다() {
        let d = data();
        let len = d.len();
        let wrong = |head: String| Step {
            head,
            body: d[100..].to_vec(),
            hang: false,
        };
        for head in [
            // 시작이 다름.
            format!(
                "HTTP/1.1 206 X\r\nContent-Range: bytes 99-{}/{len}\r\nContent-Length: {}\r\n\r\n",
                len - 1,
                len - 100
            ),
            // 전체가 다름.
            format!(
                "HTTP/1.1 206 X\r\nContent-Range: bytes 100-{}/{}\r\nContent-Length: {}\r\n\r\n",
                len - 1,
                len + 1,
                len - 100
            ),
            // 길이가 다름.
            format!(
                "HTTP/1.1 206 X\r\nContent-Range: bytes 100-{}/{len}\r\nContent-Length: {}\r\n\r\n",
                len - 1,
                len - 101
            ),
            // 머리가 없음.
            format!("HTTP/1.1 206 X\r\nContent-Length: {}\r\n\r\n", len - 100),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let part = dir.path().join("a.part");
            std::fs::write(&part, &d[..100]).unwrap();
            let (t, _) = serve(vec![wrong(head.clone())]).await;
            assert!(run(&t, &part, len as u64).await.is_err(), "{head}");
            assert!(!part.exists(), "{head}");
        }
    }

    #[tokio::test]
    async fn 바이트가_안_오면_끊고_받은_것은_남긴다() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        let d = data();
        let mut step = ok(&d, 5000);
        step.hang = true;
        let (t, _) = serve(vec![step]).await;
        let started = std::time::Instant::now();
        let e = get_resume_with(
            &t,
            ID,
            &token(),
            &part,
            d.len() as u64,
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(std::fs::read(&part).unwrap(), &d[..5000]);
    }

    #[tokio::test]
    async fn 다른_상태는_돌려주고_임시_파일을_건드리지_않는다() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        std::fs::write(&part, [1u8; 10]).unwrap();
        for code in [404u16, 429, 503] {
            let (t, _) = serve(vec![status(code)]).await;
            assert_eq!(run(&t, &part, 100).await.unwrap(), Err(code));
            assert_eq!(std::fs::metadata(&part).unwrap().len(), 10);
        }
    }

    #[tokio::test]
    async fn 이미_다_찼으면_요청하지_않고_넘치면_처음부터() {
        let dir = tempfile::tempdir().unwrap();
        let part = dir.path().join("a.part");
        let d = data();
        // 다 참 — 서버가 없어도 된다.
        std::fs::write(&part, &d).unwrap();
        let (t, seen) = serve(Vec::new()).await;
        assert_eq!(
            run(&t, &part, d.len() as u64).await.unwrap(),
            Ok(Got::Pieced)
        );
        assert!(seen.lock().unwrap().is_empty());
        // 바라는 것보다 김 — 지우고 범위 없이 처음부터.
        std::fs::write(&part, vec![7u8; d.len() + 1]).unwrap();
        let (t, seen) = serve(vec![ok(&d, d.len())]).await;
        assert_eq!(
            run(&t, &part, d.len() as u64).await.unwrap(),
            Ok(Got::Whole)
        );
        assert_eq!(std::fs::read(&part).unwrap(), d);
        assert!(!seen.lock().unwrap()[0].to_lowercase().contains("range:"));
    }
}
