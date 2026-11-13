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

/// 받아서 `out` 에 쓴다. 200 이 아니거나 길이가 `want_len` 과 다르면 오류(받은 것은 호출자가 지운다).
///
/// # Errors
/// 연결·읽기·쓰기 실패, 상태 코드, 길이 불일치, 시간 초과.
pub async fn get(
    t: &Target,
    blob_id: &str,
    token: &str,
    out: &Path,
    want_len: u64,
) -> std::io::Result<Result<(), u16>> {
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
        if len != Some(want_len) {
            return Err(bad("GET 길이"));
        }
        let mut f = tokio::fs::File::from_std(crate::files::private_file(out)?);
        let n = tokio::io::copy(&mut (&mut r).take(want_len), &mut f).await?;
        f.flush().await?;
        if n != want_len {
            return Err(bad("GET 본문이 짧다"));
        }
        Ok(Ok(()))
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
