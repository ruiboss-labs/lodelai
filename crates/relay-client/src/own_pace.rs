//! 내 기기 흘림(`own_stream`) 줄 세우기(#1042).
//!
//! relay 는 보낸 기기→받는 기기 짝마다 '첫 프레임부터 1초' 창 안에서 [`BYTES_PER_S`]·[`FRAMES_PER_S`] 를 넘는 프레임을 답 없이
//! 버린다. 그래서 보내는 쪽이 받는 기기마다 FIFO 로 줄 세워 그 안으로 내보낸다 — 순서 유지, 버리지 않음.
//! - 예산은 relay 와 같은 숫자, 여유는 창을 [`WINDOW`](1.25초)로 늘려서 둔다(망에서 뭉쳐 닿아도 relay 의 어느 1초 창에도 넘지
//!   않게). 예산을 줄이면 가장 큰 프레임 하나가 못 나간다.
//! - 바이트는 relay 가 세는 것과 같은 봉인된 data 길이(평문 + nonce·tag, [`SEALED_EXTRA`]).
//! - 줄 상한은 받는 기기마다 [`QUEUE_MAX_BYTES`](예산 3초 치) — 넘으면 넣지 않고 부른 쪽에 `false`. 3초 치면 가장 나빠도 약 3.75초
//!   밀리고, 휴대폰의 가장 짧은 물음 기다림(`apps/mobile/src/own/agentCtl.ts` `ASK_MS` 5초)보다 짧다.
//! - 끊기면 줄을 비운다([`Pacer::clear`]) — own_stream 은 지금 붙어 있는 기기에만이다.
//!
//! 봉인(seq)은 내보낼 때 한다 — 줄에는 평문으로 둔다(버린 프레임이 seq 를 먹지 않게, 기다리는 사이 epoch 이 바뀌어도 맞게).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use lodelai_protocol::constants as c;

use crate::conn::OwnStreamOut;

/// 짝 하나의 초당 바이트 예산(relay 와 같음).
pub const BYTES_PER_S: u64 = c::OWN_STREAM_BYTES_PER_S;
/// 짝 하나의 초당 프레임 수 예산(relay 와 같음).
pub const FRAMES_PER_S: u64 = c::OWN_STREAM_FRAMES_PER_S;
/// 예산을 세는 미끄러지는 창 — relay 의 1초보다 넉넉하게.
pub const WINDOW: Duration = Duration::from_millis(1_250);
/// 받는 기기마다 줄에 둘 수 있는 봉인 바이트 합(예산 3초 치).
pub const QUEUE_MAX_BYTES: u64 = 3 * BYTES_PER_S;
/// 봉인이 평문에 더하는 길이(nonce 24 + tag 16) — relay 가 세는 data 디코드 길이 = 평문 + 이것.
pub const SEALED_EXTRA: u64 = 24 + 16;

/// 프레임 하나가 relay 에서 세이는 바이트.
#[must_use]
pub fn sealed_len(o: &OwnStreamOut) -> u64 {
    o.data.len() as u64 + SEALED_EXTRA
}

#[derive(Default)]
struct Dev {
    q: VecDeque<OwnStreamOut>,
    queued: u64,
    /// 창 안에서 내보낸 것(때, 바이트). 끊겨도 남긴다 — relay 창은 기기 짝에 묶여 있어 다시 붙은 직후에도 센다.
    sent: VecDeque<(Instant, u64)>,
    /// 줄이 넘쳐 버리는 중 — 다시 하나라도 들어갈 때까지 넘침을 한 번만 알린다(로그가 쏟아지지 않게).
    overflowing: bool,
}

impl Dev {
    fn trim(&mut self, now: Instant) {
        while self
            .sent
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) >= WINDOW)
        {
            self.sent.pop_front();
        }
    }

    fn used(&self) -> u64 {
        self.sent.iter().map(|(_, b)| b).sum()
    }

    /// 맨 앞 프레임이 지금 나가도 되나.
    fn fits(&self, bytes: u64) -> bool {
        (self.sent.len() as u64) < FRAMES_PER_S && self.used() + bytes <= BYTES_PER_S
    }
}

/// [`Pacer::push`] 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Push {
    /// 줄에 들어갔다.
    Queued,
    /// 넣지 못하고 버렸다. `first` = 이 기기 줄이 넘치기 시작한 첫 프레임(또는 한 프레임 상한을 넘은 것) — 부른 쪽은 이때만
    /// 남긴다. 그 뒤 넘침은 셈만([`Pacer::dropped`]).
    Dropped { first: bool },
}

impl Push {
    /// 줄에 들어갔나.
    #[must_use]
    pub fn queued(self) -> bool {
        self == Self::Queued
    }
}

/// 받는 기기마다의 줄. 시계는 부른 쪽이 넘긴다(시험이 당길 수 있게).
#[derive(Default)]
pub struct Pacer {
    devs: HashMap<String, Dev>,
    /// 넣지 못하고 버린 프레임 수(부른 쪽에는 [`Push::Dropped`]).
    pub dropped: u64,
}

impl Pacer {
    /// 줄에 넣는다. 한 프레임이 상한(`OWN_STREAM_MAX_BYTES`)을 넘거나 그 기기 줄이 [`QUEUE_MAX_BYTES`] 를 넘게 되면 넣지 않고
    /// [`Push::Dropped`].
    pub fn push(&mut self, o: OwnStreamOut) -> Push {
        let bytes = sealed_len(&o);
        if bytes > c::OWN_STREAM_MAX_BYTES {
            self.dropped += 1;
            return Push::Dropped { first: true };
        }
        let d = self.devs.entry(o.to_device.clone()).or_default();
        if d.queued + bytes > QUEUE_MAX_BYTES {
            self.dropped += 1;
            let first = !d.overflowing;
            d.overflowing = true;
            return Push::Dropped { first };
        }
        d.overflowing = false;
        d.queued += bytes;
        d.q.push_back(o);
        Push::Queued
    }

    /// 지금 내보내도 되는 프레임을 꺼낸다(기기마다 순서대로, 예산 안에서). 꺼낸 것은 보냈다고 센다.
    pub fn ready(&mut self, now: Instant) -> Vec<OwnStreamOut> {
        let mut out = Vec::new();
        for d in self.devs.values_mut() {
            d.trim(now);
            while let Some(bytes) = d.q.front().map(sealed_len) {
                if !d.fits(bytes) {
                    break;
                }
                if let Some(o) = d.q.pop_front() {
                    d.queued -= bytes;
                    d.sent.push_back((now, bytes));
                    out.push(o);
                }
            }
        }
        self.devs
            .retain(|_, d| !d.q.is_empty() || !d.sent.is_empty());
        out
    }

    /// 줄이 남아 있으면 다음에 볼 때(가장 이른 창 빠짐). 줄이 비었으면 `None`.
    #[must_use]
    pub fn next_at(&self) -> Option<Instant> {
        self.devs
            .values()
            .filter(|d| !d.q.is_empty())
            .filter_map(|d| d.sent.front().map(|(t, _)| *t + WINDOW))
            .min()
    }

    /// 줄을 비운다(끊김·own 을 모르는 relay). 내보낸 기록(`sent`)은 남긴다 — relay 창은 기기 짝마다라 예산을 다 쓴 직후 1초 안에
    /// 다시 붙어도 relay 가 버리지 않게.
    pub fn clear(&mut self) {
        for d in self.devs.values_mut() {
            d.q.clear();
            d.queued = 0;
            d.overflowing = false;
        }
        self.devs.retain(|_, d| !d.sent.is_empty());
    }

    /// 아무것도 기다리지 않나.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.devs.values().all(|d| d.q.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(to: &str, n: usize, tag: u8) -> OwnStreamOut {
        OwnStreamOut {
            to_device: to.into(),
            data: vec![tag; n],
            checkpoint: false,
        }
    }

    #[test]
    fn bytes_budget_then_next_window_in_order() {
        let mut p = Pacer::default();
        let big = c::OWN_STREAM_MAX_BYTES as usize - SEALED_EXTRA as usize;
        for i in 0..3 {
            assert!(p.push(f("a", big, i)).queued());
        }
        let t0 = Instant::now();
        let first = p.ready(t0);
        assert_eq!(first.len(), 1, "49152 둘은 65536 을 넘는다");
        assert_eq!(first[0].data[0], 0);
        assert!(p.ready(t0 + Duration::from_millis(1_249)).is_empty());
        assert_eq!(p.next_at(), Some(t0 + WINDOW));
        let second = p.ready(t0 + WINDOW);
        assert_eq!(second.iter().map(|o| o.data[0]).collect::<Vec<_>>(), [1]);
        let third = p.ready(t0 + WINDOW * 2);
        assert_eq!(third.iter().map(|o| o.data[0]).collect::<Vec<_>>(), [2]);
        assert!(p.idle());
        assert_eq!(p.next_at(), None);
    }

    #[test]
    fn frame_count_budget() {
        let mut p = Pacer::default();
        for i in 0..40u8 {
            assert!(p.push(f("a", 1, i)).queued());
        }
        let t0 = Instant::now();
        assert_eq!(
            p.ready(t0).len(),
            usize::try_from(FRAMES_PER_S).unwrap_or(0)
        );
        let rest = p.ready(t0 + WINDOW);
        assert_eq!(rest.len(), 40 - usize::try_from(FRAMES_PER_S).unwrap_or(0));
        assert_eq!(rest[0].data[0], 32, "순서 그대로");
    }

    #[test]
    fn devices_have_own_budget() {
        let mut p = Pacer::default();
        let big = c::OWN_STREAM_MAX_BYTES as usize - SEALED_EXTRA as usize;
        assert!(p.push(f("a", big, 0)).queued());
        assert!(p.push(f("a", big, 1)).queued());
        assert!(p.push(f("b", big, 2)).queued());
        assert_eq!(p.ready(Instant::now()).len(), 2, "a 하나·b 하나");
    }

    #[test]
    fn queue_cap_refuses_and_counts() {
        let mut p = Pacer::default();
        let big = c::OWN_STREAM_MAX_BYTES as usize - SEALED_EXTRA as usize;
        let fit = (QUEUE_MAX_BYTES / c::OWN_STREAM_MAX_BYTES) as u8;
        for i in 0..fit {
            assert!(p.push(f("a", big, i)).queued());
        }
        assert_eq!(
            p.push(f("a", big, 99)),
            Push::Dropped { first: true },
            "줄 상한 — 넘침 첫 프레임"
        );
        assert_eq!(
            p.push(f("a", big, 98)),
            Push::Dropped { first: false },
            "그 뒤 넘침은 셈만"
        );
        assert!(p.push(f("b", 10, 0)).queued(), "다른 기기는 따로");
        assert!(!p.push(f("c", big + 1, 0)).queued(), "한 프레임 상한");
        assert_eq!(p.dropped, 3);
        // 하나 내보내 창 기록을 남긴 뒤 비운다 — 줄은 비고 창 기록은 남아 바로 다음 큰 프레임은 창이 빠질 때까지 기다린다.
        let t0 = Instant::now();
        assert_eq!(p.ready(t0).len(), 2, "a 하나·b 하나");
        p.clear();
        assert!(p.idle());
        assert!(p.push(f("a", big, 0)).queued());
        assert!(p.ready(t0).is_empty(), "다시 붙은 직후에도 relay 창을 센다");
        assert_eq!(p.ready(t0 + WINDOW).len(), 1);
        p.clear();
        assert!(p.push(f("a", big, 0)).queued(), "비운 뒤 다시 들어간다");
    }
}
