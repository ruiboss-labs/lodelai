//! `lodelai-effects` 의 시험용 구현: 고정 시계, 시드 고정 난수, 난수 실패 주입, 결정적 ID.
//!
//! 제품 바이너리에는 시간 주입 플래그를 두지 않는다. 시험은 이 구현을 `Arc<dyn …>` 로 꽂는다.
//! 타이머(sleep·timeout)는 여기서 다루지 않는다 — tokio `time::pause`/`advance` 를 쓴다
//! (`#[tokio::test(start_paused = true)]`, current_thread 런타임).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lodelai_effects::{encode_ulid, Clock, IdGen, Rng, RngError, UlidGen, UnixMillis};

/// 시험이 직접 움직이는 시계.
#[derive(Debug)]
pub struct FixedClock(AtomicI64);

impl FixedClock {
    pub fn new(ms: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(ms)))
    }

    pub fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }

    /// `ms` 만큼 앞으로(음수면 시계 역행 시험).
    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis(self.0.load(Ordering::SeqCst))
    }
}

/// 시드 고정 난수(xorshift64*). 같은 시드는 같은 바이트열을 낸다 — 서명·토큰 재현 시험용(암호용 아님).
#[derive(Debug)]
pub struct SeedRng(Mutex<crate::rng::Rng>);

impl SeedRng {
    pub fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(crate::rng::Rng::new(seed))))
    }
}

impl Rng for SeedRng {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        let mut r = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for chunk in buf.chunks_mut(8) {
            let bytes = r.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// 항상 실패하거나, 처음 `n` 번만 실패하거나, 처음 `n` 번은 성공하고 그 뒤 실패하는 난수.
/// hook 이 패닉하지 않고 마커 규칙을 타는지, 생성 도중 실패해도 상태가 깨지지 않는지 시험한다.
#[derive(Debug)]
pub struct FailingRng {
    always: bool,
    remaining: AtomicU64,
    /// `after(n)`: 앞으로 성공할 횟수. `None` 이면 이 모드가 아니다.
    succeed_left: Option<AtomicU64>,
    called: AtomicBool,
}

impl FailingRng {
    pub fn always() -> Arc<Self> {
        Arc::new(Self {
            always: true,
            remaining: AtomicU64::new(0),
            succeed_left: None,
            called: AtomicBool::new(false),
        })
    }

    pub fn first(n: u64) -> Arc<Self> {
        Arc::new(Self {
            always: false,
            remaining: AtomicU64::new(n),
            succeed_left: None,
            called: AtomicBool::new(false),
        })
    }

    /// 처음 `n` 번은 성공(0 으로 채움)하고 그 뒤로는 계속 실패한다.
    pub fn after(n: u64) -> Arc<Self> {
        Arc::new(Self {
            always: false,
            remaining: AtomicU64::new(0),
            succeed_left: Some(AtomicU64::new(n)),
            called: AtomicBool::new(false),
        })
    }

    pub fn was_called(&self) -> bool {
        self.called.load(Ordering::SeqCst)
    }
}

impl Rng for FailingRng {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        self.called.store(true, Ordering::SeqCst);
        if let Some(left) = &self.succeed_left {
            let ok = left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            return if ok {
                buf.fill(0);
                Ok(())
            } else {
                Err(RngError("주입된 난수 실패(after)".into()))
            };
        }
        let fail = self.always
            || self
                .remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
        if fail {
            Err(RngError("주입된 난수 실패".into()))
        } else {
            buf.fill(0);
            Ok(())
        }
    }
}

/// 카운터 기반 결정적 ULID: 시각은 시계에서, 난수 부분은 호출 순번. 시계가 거꾸로 가도 시각 부분은 줄지 않으므로
/// (`UlidGen` 과 같은 성질) **항상 엄격히 증가**하고 재현된다.
pub struct SeqIdGen {
    clock: Arc<dyn Clock>,
    counter: AtomicU64,
    last_ms: AtomicU64,
}

impl SeqIdGen {
    pub fn new(clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            clock,
            counter: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
        })
    }
}

impl IdGen for SeqIdGen {
    fn try_next_ulid(&self) -> Result<String, RngError> {
        let now = u64::try_from(self.clock.now().0.max(0)).unwrap_or(0);
        let ms = self.last_ms.fetch_max(now, Ordering::SeqCst).max(now);
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(encode_ulid(ms, u128::from(n)))
    }
}

/// 시계·난수를 같이 쓰는 표준 시험 번들.
pub struct TestEffects {
    pub clock: Arc<FixedClock>,
    pub rng: Arc<SeedRng>,
    pub ids: Arc<UlidGen>,
}

impl TestEffects {
    /// `start_ms` 에서 시작하는 시계와 `seed` 난수, 그 둘로 만든 단조 ULID 생성기.
    pub fn new(start_ms: i64, seed: u64) -> Self {
        let clock = FixedClock::new(start_ms);
        let rng = SeedRng::new(seed);
        let ids = Arc::new(UlidGen::new(clock.clone(), rng.clone()));
        Self { clock, rng, ids }
    }
}
