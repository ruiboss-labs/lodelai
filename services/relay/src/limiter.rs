//! 규칙 0: 사용자 단위 토큰 버킷. 파싱 직후, 다른 검사 전에 본다(열거·서명 검증 비용 공격 방지).
//! 같은 틀을 원격 relay 의 IP 상한(#364)에도 쓴다 — 키가 끝없이 늘 수 있어 표가 [`PRUNE_AT`] 를 넘으면 다 회복된 버킷을 지운다.

use std::collections::HashMap;
use std::sync::Mutex;

use lodelai_effects::UnixMillis;

/// 표가 이만큼 넘으면 다 회복된 버킷(새로 만든 것과 같은 상태)을 지운다.
pub const PRUNE_AT: usize = 10_000;

pub struct Limiter {
    per_sec: f64,
    burst: f64,
    buckets: Mutex<Buckets>,
}

struct Buckets {
    map: HashMap<String, (f64, i64)>,
    /// 다음 정리 기준. 정리 뒤에도 크면(지금 쓰이는 버킷이 많다) 두 배로 올려 요청마다 훑지 않는다.
    prune_at: usize,
}

impl Limiter {
    pub fn new(per_sec: u32, burst: u32) -> Self {
        Self::with_rate(f64::from(per_sec), f64::from(burst))
    }

    /// 초당 회복이 1 보다 작은 버킷(분 단위 상한, #364).
    pub fn with_rate(per_sec: f64, burst: f64) -> Self {
        Self {
            per_sec,
            burst,
            buckets: Mutex::new(Buckets {
                map: HashMap::new(),
                prune_at: PRUNE_AT,
            }),
        }
    }

    /// 지금 [`Self::allow`] 하면 받을까(토큰은 쓰지 않는다). 성공한 뒤에만 세는 상한(묶음 18 조직 만들기 IP)이 먼저 본다.
    pub fn would_allow(&self, key: &str, now: UnixMillis) -> bool {
        let buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buckets.map.get(key).is_none_or(|(tokens, at)| {
            let elapsed = (now.0 - *at).max(0) as f64 / 1000.0;
            (tokens + elapsed * self.per_sec).min(self.burst) >= 1.0
        }) && self.burst >= 1.0
    }

    /// 토큰 하나를 쓴다. 남은 게 없으면 `false`.
    pub fn allow(&self, key: &str, now: UnixMillis) -> bool {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.map.len() >= buckets.prune_at {
            let (per_sec, burst) = (self.per_sec, self.burst);
            buckets.map.retain(|_, (tokens, at)| {
                let elapsed = (now.0 - *at).max(0) as f64 / 1000.0;
                *tokens + elapsed * per_sec < burst
            });
            buckets.prune_at = PRUNE_AT.max(buckets.map.len() * 2);
        }
        let entry = buckets
            .map
            .entry(key.to_owned())
            .or_insert((self.burst, now.0));
        let elapsed = (now.0 - entry.1).max(0) as f64 / 1000.0;
        entry.0 = (entry.0 + elapsed * self.per_sec).min(self.burst);
        entry.1 = now.0;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills_with_clock() {
        let l = Limiter::new(10, 3);
        let t0 = UnixMillis(1_000);
        assert!(l.allow("u", t0));
        assert!(l.allow("u", t0));
        assert!(l.allow("u", t0));
        assert!(!l.allow("u", t0));
        assert!(l.allow("other", t0));
        // 100ms 뒤 토큰 1개
        assert!(l.allow("u", UnixMillis(1_100)));
        assert!(!l.allow("u", UnixMillis(1_100)));
    }

    #[test]
    fn would_allow_does_not_spend() {
        let l = Limiter::with_rate(5.0 / 86_400.0, 5.0);
        let t0 = UnixMillis(0);
        for _ in 0..5 {
            assert!(l.would_allow("ip", t0));
            assert!(l.would_allow("ip", t0));
            assert!(l.allow("ip", t0));
        }
        assert!(!l.would_allow("ip", t0));
        assert!(l.would_allow("other", t0));
        // 하루 뒤엔 다 회복.
        assert!(l.would_allow("ip", UnixMillis(86_400_000)));
    }

    #[test]
    fn table_drops_refilled_buckets_past_prune_at() {
        // IP 상한과 같은 꼴: 분당 30(초당 0.5), 다 회복까지 60초.
        let l = Limiter::with_rate(0.5, 30.0);
        let len = |l: &Limiter| l.buckets.lock().unwrap().map.len();
        for i in 0..PRUNE_AT {
            assert!(l.allow(&format!("ip{i}"), UnixMillis(0)));
        }
        assert_eq!(len(&l), PRUNE_AT);
        // 아직 회복 중이면 지우지 않는다(지우면 상한이 풀린다) — 기준만 두 배로.
        assert!(l.allow("late", UnixMillis(1_000)));
        assert_eq!(len(&l), PRUNE_AT + 1);
        // 60초 뒤엔 모두 다 회복 — 다음 정리 때 지워진다.
        for i in 0..PRUNE_AT {
            assert!(l.allow(&format!("next{i}"), UnixMillis(61_000)));
        }
        assert!(len(&l) <= PRUNE_AT + 2, "{}", len(&l));
        // 회복 중인 버킷은 정리를 지나도 상한을 지킨다.
        let k = Limiter::with_rate(0.5, 2.0);
        assert!(k.allow("a", UnixMillis(0)));
        assert!(k.allow("a", UnixMillis(0)));
        k.buckets.lock().unwrap().prune_at = 1;
        assert!(!k.allow("a", UnixMillis(0)));
    }
}
