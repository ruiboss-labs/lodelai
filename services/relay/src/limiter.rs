//! 규칙 0: 사용자 단위 토큰 버킷. 파싱 직후, 다른 검사 전에 본다(열거·서명 검증 비용 공격 방지).
//! 같은 틀을 원격 relay 의 IP 상한(#364)에도 쓴다 — 키가 끝없이 늘 수 있어 표가 [`PRUNE_AT`] 를 넘으면 다 회복된 버킷을 지운다.

use std::collections::HashMap;
use std::sync::Mutex;

use lodelai_effects::UnixMillis;

/// 토큰 하나로 볼 값 — 분 단위 회복(초당 1/6 등)은 부동소수점으로 정확히 1 이 되지 않는다.
const ONE: f64 = 1.0 - 1e-9;

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
            (tokens + elapsed * self.per_sec).min(self.burst) >= ONE
        }) && self.burst >= ONE
    }

    /// 토큰 하나가 생기는 가장 이른 시각(지금 있으면 `now`) — rate_limited 의 `until`.
    pub fn free_at(&self, key: &str, now: UnixMillis) -> UnixMillis {
        let buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tokens = buckets.map.get(key).map_or(self.burst, |(tokens, at)| {
            let elapsed = (now.0 - *at).max(0) as f64 / 1000.0;
            (tokens + elapsed * self.per_sec).min(self.burst)
        });
        if tokens >= ONE || self.per_sec <= 0.0 {
            return now;
        }
        UnixMillis(now.0 + ((1.0 - tokens) / self.per_sec * 1000.0).ceil() as i64)
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
        if entry.0 >= ONE {
            entry.0 = (entry.0 - 1.0).max(0.0);
            true
        } else {
            false
        }
    }
}

/// 모든 통 × 모든 키에서 토큰 하나씩 — 하나라도 비었으면 아무것도 쓰지 않고 다시 될 가장 늦은 시각(ms)을 돌려준다.
pub fn spend_all(limiters: &[&Limiter], keys: &[String], now: UnixMillis) -> Result<(), i64> {
    let until = keys
        .iter()
        .flat_map(|k| limiters.iter().map(move |l| l.free_at(k, now).0))
        .max()
        .unwrap_or(now.0);
    if until > now.0 {
        return Err(until);
    }
    for k in keys {
        for l in limiters {
            l.allow(k, now);
        }
    }
    Ok(())
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
    fn free_at_is_when_one_token_is_back() {
        // 분당 10.
        let l = Limiter::with_rate(10.0 / 60.0, 10.0);
        let t0 = UnixMillis(1_000);
        assert_eq!(l.free_at("u", t0).0, t0.0);
        for _ in 0..10 {
            assert!(l.allow("u", t0));
        }
        assert_eq!(l.free_at("u", t0).0, 7_000);
        assert!(!l.allow("u", UnixMillis(6_999)));
        assert!(l.allow("u", UnixMillis(7_000)));
    }

    /// #845 ③: 사용자·IP 두 키 — 같은 IP 의 다른 사용자도 IP 통이 비면 걸리고, 걸린 시도는 아무 통도 쓰지 않는다.
    #[test]
    fn spend_all_shares_ip_bucket_and_spends_nothing_when_refused() {
        let minute = Limiter::with_rate(10.0 / 60.0, 10.0);
        let day = Limiter::with_rate(300.0 / 86_400.0, 300.0);
        let ls = [&minute, &day];
        let t0 = UnixMillis(0);
        let a = ["u:a".to_owned(), "ip:1.2.3.4".to_owned()];
        let b = ["u:b".to_owned(), "ip:1.2.3.4".to_owned()];
        let c = ["u:c".to_owned(), "ip:5.6.7.8".to_owned()];
        for _ in 0..10 {
            assert_eq!(spend_all(&ls, &a, t0), Ok(()));
        }
        assert_eq!(spend_all(&ls, &a, t0), Err(6_000));
        assert_eq!(spend_all(&ls, &b, t0), Err(6_000), "같은 IP");
        assert_eq!(spend_all(&ls, &c, t0), Ok(()), "다른 IP");
        // b 의 걸린 시도는 u:b 를 쓰지 않았다 — 하루 통에 299 가 남아 있다.
        assert_eq!(day.free_at("u:b", t0).0, t0.0);
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

/// 창 안에서 `max` 번이 되면 그때부터 `window_ms` 동안 막는 셈(relay 0.1.2 조직 만들기 코드 늦춤 — 토큰 버킷과 달리 다 차면
/// 한 시간 통째로 쉰다). 메모리에만 — 재시작하면 처음부터.
pub struct LockWindow {
    max: u32,
    window_ms: i64,
    map: Mutex<HashMap<String, Lock>>,
}

#[derive(Clone, Copy)]
struct Lock {
    start: i64,
    count: u32,
    until: i64,
}

impl LockWindow {
    #[must_use]
    pub fn new(max: u32, window_ms: i64) -> Self {
        Self {
            max,
            window_ms,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// 지금 막혀 있으면 남은 ms.
    pub fn blocked(&self, key: &str, now: UnixMillis) -> Option<i64> {
        let map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(key)
            .filter(|l| l.until > now.0)
            .map(|l| l.until - now.0)
    }

    /// 한 번 센다. 이번에 막히기 시작했으면 `true`(로그 한 줄용).
    pub fn hit(&self, key: &str, now: UnixMillis) -> bool {
        let mut map = self
            .map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= PRUNE_AT {
            map.retain(|_, l| l.until > now.0 || now.0 - l.start < self.window_ms);
        }
        let l = map.entry(key.to_owned()).or_insert(Lock {
            start: now.0,
            count: 0,
            until: 0,
        });
        if now.0 - l.start >= self.window_ms && l.until <= now.0 {
            *l = Lock {
                start: now.0,
                count: 0,
                until: 0,
            };
        }
        l.count += 1;
        if l.count >= self.max && l.until <= now.0 {
            l.until = now.0 + self.window_ms;
            return true;
        }
        false
    }
}
