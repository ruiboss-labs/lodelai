//! 내 기기끼리 흘림 `own_stream`(#870, 설계 mobile-870 '고침' 2·코어 §3 리뷰 nonce 절).
//!
//! relay 는 속을 모른다 — 키는 self 그룹 MLS exporter 에서 뽑는다:
//! - `base_e = MLS-Exporter("lodelai own stream v1", "", 32)` — epoch 마다 하나.
//! - 짝 키 = `HKDF-SHA256-Expand(base_e, info = "lodelai own stream pair v1" ‖ 0x00 ‖ from ‖ to, 32)` — 기기 짝·방향마다
//!   다르다. 두 id 는 25자여야 한다(아니면 잠그지도 풀지도 않음).
//! - AEAD = XChaCha20-Poly1305, `data = nonce(24, CSPRNG) ‖ 암호문 ‖ tag(16)`.
//! - AAD = `to(25) ‖ from(25) ‖ epoch(u64 BE) ‖ seq(u64 BE)` — device id 는 `k1_` + 22자로 늘 25자라 이어 붙여도 모호하지 않다.
//! - 받는 쪽은 지금 epoch 와 바로 앞 epoch 의 base 만 쥔다(메모리). 앞 epoch base 는 merge 직전에 뽑아 둔다 — openmls 는 지난
//!   epoch 의 exporter 를 주지 않는다.
//! - 재생: (보낸 기기, epoch) 마다 가장 큰 seq + 64 창. 창 밖·중복은 버린다.
//! - seq: 프로세스 시작 때 `max(저장된 마지막 + 1, 지금 µs)` 에서 하나씩 올린다 — 다시 켜도 줄지 않게(받는 쪽 창이 막지 않게).
//!   저장은 부른 쪽이 keyframe 때(`checkpoint`).
//!
//! 확인 끝난 내 기기인지(§3)는 여기서 보지 않는다 — 풀리면 self 그룹 잎이라는 것까지만 안다. 코어가 본다.

use std::collections::{BTreeMap, HashMap};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// exporter 라벨(설계 그대로).
pub const EXPORTER_LABEL: &str = "lodelai own stream v1";
const PAIR_INFO: &[u8] = b"lodelai own stream pair v1";
const NONCE: usize = 24;
const TAG: usize = 16;
/// 평문 상한 — 선 위 data(디코드 바이트)가 `OWN_STREAM_MAX_BYTES` 를 넘지 않게 nonce·tag 를 뺀다.
pub const PLAIN_MAX: usize =
    lodelai_protocol::constants::OWN_STREAM_MAX_BYTES as usize - NONCE - TAG;
const WINDOW: u64 = 64;
const DEVICE_LEN: usize = 25;

/// epoch base 에서 짝·방향 키(HKDF-Expand 한 블록 = HMAC(base, info ‖ 0x01)). id 가 25자가 아니면 `None`.
fn pair_key(base: &[u8; 32], from: &str, to: &str) -> Option<Zeroizing<[u8; 32]>> {
    if from.len() != DEVICE_LEN || to.len() != DEVICE_LEN {
        return None;
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).ok()?;
    mac.update(PAIR_INFO);
    mac.update(&[0]);
    mac.update(from.as_bytes());
    mac.update(to.as_bytes());
    mac.update(&[1]);
    Some(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn aad(to: &str, from: &str, epoch: u64, seq: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(DEVICE_LEN * 2 + 16);
    a.extend_from_slice(to.as_bytes());
    a.extend_from_slice(from.as_bytes());
    a.extend_from_slice(&epoch.to_be_bytes());
    a.extend_from_slice(&seq.to_be_bytes());
    a
}

/// 잠근다. `nonce` 는 CSPRNG 24바이트(부른 쪽이 Rng 로).
///
/// 평문이 [`PLAIN_MAX`] 를 넘거나 id 가 25자가 아니면 `None`.
#[must_use]
pub fn seal(
    base: &[u8; 32],
    from: &str,
    to: &str,
    epoch: u64,
    seq: u64,
    nonce: [u8; NONCE],
    plain: &[u8],
) -> Option<Vec<u8>> {
    if plain.len() > PLAIN_MAX {
        return None;
    }
    let key = pair_key(base, from, to)?;
    let ct = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad(to, from, epoch, seq),
            },
        )
        .ok()?;
    let mut out = Vec::with_capacity(NONCE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// 푼다 — 키·AAD 가 맞지 않거나 꼴이 틀리면 `None`.
#[must_use]
pub fn open(
    base: &[u8; 32],
    from: &str,
    to: &str,
    epoch: u64,
    seq: u64,
    data: &[u8],
) -> Option<Vec<u8>> {
    if data.len() < NONCE + TAG {
        return None;
    }
    let (nonce, ct) = data.split_at(NONCE);
    let key = pair_key(base, from, to)?;
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &aad(to, from, epoch, seq),
            },
        )
        .ok()
}

/// self 그룹 epoch base — 지금 것과 바로 앞 것 둘만(메모리).
#[derive(Default)]
pub struct Bases {
    by_epoch: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl Bases {
    /// 그 epoch 의 base 를 넣는다(이미 있으면 그대로). 가장 높은 둘만 남기고, 버린 epoch 의 재생 창도 `windows` 에서 지운다.
    pub fn put(&mut self, epoch: u64, base: [u8; 32], windows: &mut Windows) {
        self.by_epoch
            .entry(epoch)
            .or_insert_with(|| Zeroizing::new(base));
        while self.by_epoch.len() > 2 {
            let Some((&old, _)) = self.by_epoch.iter().next() else {
                break;
            };
            self.by_epoch.remove(&old);
            windows.forget_below(old + 1);
        }
    }

    #[must_use]
    pub fn get(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.by_epoch.get(&epoch).map(|b| &**b)
    }

    /// 가장 낮게 쥔 epoch — 그보다 옛것은 받지 않는다.
    #[must_use]
    pub fn lowest(&self) -> Option<u64> {
        self.by_epoch.keys().next().copied()
    }
}

/// (보낸 기기, epoch) 마다 재생 창: 가장 큰 seq 와 그 아래 64 개 비트.
#[derive(Default)]
pub struct Windows {
    by: HashMap<(String, u64), (u64, u64)>,
}

impl Windows {
    /// 처음 보는 seq 면 표시하고 `true`. 중복·창 밖(가장 큰 것보다 64 이상 아래)이면 `false`.
    pub fn accept(&mut self, from: &str, epoch: u64, seq: u64) -> bool {
        let Some((top, bits)) = self.by.get_mut(&(from.to_owned(), epoch)) else {
            self.by.insert((from.to_owned(), epoch), (seq, 1));
            return true;
        };
        if seq > *top {
            let shift = seq - *top;
            *bits = if shift >= WINDOW { 0 } else { *bits << shift };
            *bits |= 1;
            *top = seq;
            return true;
        }
        let back = *top - seq;
        if back >= WINDOW {
            return false;
        }
        let bit = 1u64 << back;
        if *bits & bit != 0 {
            return false;
        }
        *bits |= bit;
        true
    }

    /// 그 epoch 아래 창을 지운다(base 를 버릴 때 같이).
    pub fn forget_below(&mut self, epoch: u64) {
        self.by.retain(|(_, e), _| *e >= epoch);
    }
}

/// 보내는 seq — `max(저장된 마지막 + 1, 지금 µs)` 에서 시작해 하나씩 올린다.
#[derive(Debug)]
pub struct Seq {
    next: u64,
}

impl Seq {
    #[must_use]
    pub fn start(saved_last: Option<u64>, now_ms: u64) -> Self {
        let now_us = now_ms.saturating_mul(1000);
        Self {
            next: saved_last.map_or(now_us, |s| s.saturating_add(1).max(now_us)),
        }
    }

    pub fn take(&mut self) -> u64 {
        let s = self.next;
        self.next = self.next.saturating_add(1);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "k1_AAAAAAAAAAAAAAAAAAAAAA";
    const B: &str = "k1_BBBBBBBBBBBBBBBBBBBBBB";

    #[test]
    fn 짝_방향마다_키가_다르고_aad_가_맞아야_풀린다() {
        let base = [7u8; 32];
        let d = seal(&base, A, B, 3, 10, [1; 24], b"hi").unwrap();
        assert_eq!(d.len(), 24 + 2 + 16);
        assert_eq!(open(&base, A, B, 3, 10, &d).unwrap(), b"hi");
        assert!(open(&base, B, A, 3, 10, &d).is_none(), "반대 방향 키");
        assert!(open(&base, A, B, 4, 10, &d).is_none(), "epoch");
        assert!(open(&base, A, B, 3, 11, &d).is_none(), "seq");
        assert!(
            open(&[8u8; 32], A, B, 3, 10, &d).is_none(),
            "다른 epoch base"
        );
        let mut bad = d.clone();
        bad[30] ^= 1;
        assert!(open(&base, A, B, 3, 10, &bad).is_none());
        assert!(open(&base, A, B, 3, 10, &d[..39]).is_none());
        assert!(seal(&base, A, B, 3, 10, [1; 24], &vec![0; PLAIN_MAX + 1]).is_none());
        assert!(seal(&base, A, B, 3, 10, [1; 24], &vec![0; PLAIN_MAX]).is_some());
        assert!(
            seal(&base, "k1_short", B, 3, 10, [1; 24], b"x").is_none(),
            "25자 아님"
        );
        assert!(open(&base, A, "k1_short", 3, 10, &d).is_none());
    }

    #[test]
    fn 재생_창은_중복과_64_밖을_버린다() {
        let mut w = Windows::default();
        assert!(w.accept(A, 1, 100));
        assert!(!w.accept(A, 1, 100), "중복");
        assert!(w.accept(A, 1, 98), "늦게 온 것");
        assert!(!w.accept(A, 1, 98));
        assert!(w.accept(A, 1, 163));
        assert!(!w.accept(A, 1, 99), "64 창 밖");
        assert!(w.accept(A, 1, 100 + 64), "창 안 처음");
        assert!(w.accept(A, 2, 5), "epoch 마다 따로");
        assert!(w.accept(B, 1, 100), "기기마다 따로");
        w.forget_below(2);
        assert!(w.accept(A, 1, 100), "지운 창은 새로");
    }

    #[test]
    fn base_는_가장_높은_두_epoch_만() {
        let mut b = Bases::default();
        let mut w = Windows::default();
        w.accept(A, 1, 1);
        b.put(1, [1; 32], &mut w);
        b.put(2, [2; 32], &mut w);
        b.put(2, [9; 32], &mut w);
        assert_eq!(b.get(2), Some(&[2; 32]), "있으면 그대로");
        b.put(3, [3; 32], &mut w);
        assert!(b.get(1).is_none());
        assert_eq!(b.lowest(), Some(2));
        assert!(w.accept(A, 1, 1), "버린 epoch 의 창도 지움");
    }

    #[test]
    fn seq_는_다시_켜도_줄지_않는다() {
        let mut s = Seq::start(None, 1_000);
        assert_eq!(s.take(), 1_000_000);
        assert_eq!(s.take(), 1_000_001);
        // 시계가 뒤로 가도 저장된 것 위에서.
        let mut s = Seq::start(Some(5_000_000), 1_000);
        assert_eq!(s.take(), 5_000_001);
        let mut s = Seq::start(Some(5), 1_000);
        assert_eq!(s.take(), 1_000_000);
    }
}
