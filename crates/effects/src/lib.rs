//! 시간·ID·난수 주입 (U13b, #68). 앱 코어·relay·작은 보조 바이너리가 같은 트레이트를 쓰고, 시험은 결정적 구현을 꽂는다.
//!
//! 규칙(architecture §3.2): 상태 머신·정책 엔진·서버 규칙은 이 셋과 입력 이벤트 외의 전역 상태를 읽지 않는다.
//! - 벽시계 비교(`expires_at` 등)는 [`Clock::now`] 만 쓴다. **타이머(sleep·timeout)는 여기 없다** — 시험은
//!   tokio 의 `time::pause`/`advance` 로 한다(이 크레이트는 tokio 에 의존하지 않는다).
//! - 모든 구현은 `&self` + `Send + Sync`(`Arc<dyn …>` 로 주입).
//! - 시험용 구현(`FixedClock`·`SeedRng`·`SeqIdGen`)은 `lodelai-testkit` 에 있다. 제품 바이너리에는 시간 주입 플래그를 두지 않는다.
//!
//! 의존성은 `time`(RFC 3339 변환)과 `getrandom`(OS 난수)뿐이다. 작은 보조 바이너리도 쓸 수 있게 유지한다.

mod ulid;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub use ulid::{decode_ulid_millis, encode_ulid, is_ulid};

/// UTC 유닉스 밀리초. DB 저장도 이 값(i64)이고 RFC 3339 변환은 프레임 직렬화 경계에서만 한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(pub i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError(pub String);

impl std::fmt::Display for TimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TimeError {}

impl UnixMillis {
    pub fn saturating_add(self, millis: i64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    /// 정규 형식 `YYYY-MM-DDTHH:MM:SS.mmmZ`(UTC, 밀리초 3자리 고정).
    /// 서명·JCS 비교가 문자열 바이트에 걸리므로 형식이 하나뿐이어야 한다.
    ///
    /// # Errors
    /// 표현할 수 없는 범위(연도 ±9999 밖)이면 오류.
    pub fn to_rfc3339(self) -> Result<String, TimeError> {
        let nanos = i128::from(self.0) * 1_000_000;
        let dt = OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .map_err(|e| TimeError(format!("범위 밖 시각 {}: {e}", self.0)))?;
        let base = dt
            .format(&Rfc3339)
            .map_err(|e| TimeError(format!("RFC 3339 변환 실패: {e}")))?;
        // `time` 은 소수부를 필요한 만큼만 찍으므로(없거나 1~9자리) 밀리초 3자리로 고정한다.
        let (head, _) = base
            .split_once('.')
            .or_else(|| base.strip_suffix('Z').map(|h| (h, "")))
            .ok_or_else(|| TimeError(format!("예상 밖 형식: {base}")))?;
        Ok(format!("{head}.{:03}Z", self.0.rem_euclid(1000)))
    }

    /// RFC 3339(오프셋 허용) 를 읽는다. 밀리초 미만은 버린다.
    ///
    /// # Errors
    /// RFC 3339 가 아니면 오류.
    pub fn parse_rfc3339(s: &str) -> Result<Self, TimeError> {
        let dt = OffsetDateTime::parse(s, &Rfc3339)
            .map_err(|e| TimeError(format!("RFC 3339 아님 `{s}`: {e}")))?;
        let ms = dt.unix_timestamp_nanos().div_euclid(1_000_000);
        i64::try_from(ms)
            .map(Self)
            .map_err(|_| TimeError(format!("범위 밖 `{s}`")))
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> UnixMillis;
}

/// 난수를 얻지 못했다(OS 난수 실패 등).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RngError(pub String);

impl std::fmt::Display for RngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "난수 실패: {}", self.0)
    }
}

impl std::error::Error for RngError {}

/// 난수. 암호용 구현은 OS 난수, 시험용은 시드 고정 결정적 구현.
///
/// 구현은 [`Rng::try_fill`] 만 채운다. [`Rng::fill`] 은 실패 시 패닉하는 편의 함수이며 **코어·relay 용**이다.
/// 패닉(exit 101)이 fail-open 이 되는 곳(hook 같은 보조 바이너리)은 반드시 `try_fill` 로 받아 마커 규칙(exit 2/0)을 적용한다.
pub trait Rng: Send + Sync {
    /// # Errors
    /// 난수를 얻지 못했을 때.
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError>;

    /// # Panics
    /// `try_fill` 이 실패하면 패닉한다 — 난수 없이 토큰·nonce 를 만들면 안 된다.
    fn fill(&self, buf: &mut [u8]) {
        self.try_fill(buf).expect("난수를 얻지 못했다");
    }
}

/// ULID(26자, 대문자 Crockford) 생성. **같은 밀리초 안에서 단조 증가**해야 한다(정렬 키로 쓴다).
/// 구현은 [`IdGen::try_next_ulid`] 만 채운다. 패닉이 fail-open 이 되는 곳(hook)은 `try_` 판을 쓴다.
pub trait IdGen: Send + Sync {
    /// # Errors
    /// 난수를 얻지 못했을 때.
    fn try_next_ulid(&self) -> Result<String, RngError>;

    /// # Panics
    /// `try_next_ulid` 가 실패하면 패닉한다.
    fn next_ulid(&self) -> String {
        self.try_next_ulid().expect("ULID 를 만들지 못했다")
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixMillis {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        UnixMillis(ms)
    }
}

/// OS 난수(`getrandom`). 실패는 `Err` 로 돌려준다(패닉은 `fill` 의 기본 구현에서만).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl Rng for OsRng {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        getrandom::fill(buf).map_err(|e| RngError(e.to_string()))
    }
}

/// `Clock` + `Rng` 로 만드는 단조 증가 ULID 생성기(시스템·시험 공용: 구현체만 바꿔 꽂는다).
pub struct UlidGen {
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    last: Mutex<Option<(u64, u128)>>,
}

impl UlidGen {
    pub fn new(clock: Arc<dyn Clock>, rng: Arc<dyn Rng>) -> Self {
        Self {
            clock,
            rng,
            last: Mutex::new(None),
        }
    }

    /// 시스템 시계 + OS 난수.
    pub fn system() -> Self {
        Self::new(Arc::new(SystemClock), Arc::new(OsRng))
    }

    fn fresh_random(&self) -> Result<u128, RngError> {
        let mut b = [0u8; 10];
        self.rng.try_fill(&mut b)?;
        Ok(b.iter().fold(0u128, |acc, x| (acc << 8) | u128::from(*x)))
    }
}

const RAND_MASK: u128 = (1u128 << 80) - 1;

impl IdGen for UlidGen {
    fn try_next_ulid(&self) -> Result<String, RngError> {
        let now = u64::try_from(self.clock.now().0.max(0)).unwrap_or(0);
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 시계가 거꾸로 가도 ULID 는 거꾸로 가지 않는다.
        let (ms, rand) = match *last {
            Some((prev_ms, prev_rand)) if now <= prev_ms => {
                if prev_rand < RAND_MASK {
                    (prev_ms, prev_rand + 1)
                } else {
                    (prev_ms + 1, self.fresh_random()?)
                }
            }
            _ => (now, self.fresh_random()?),
        };
        *last = Some((ms, rand));
        Ok(encode_ulid(ms, rand))
    }
}
