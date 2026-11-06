use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::Arc;

use lodelai_effects::{
    decode_ulid_millis, encode_ulid, is_ulid, Clock, IdGen, OsRng, Rng, RngError, SystemClock,
    UlidGen, UnixMillis,
};

struct Fixed(AtomicI64);
impl Clock for Fixed {
    fn now(&self) -> UnixMillis {
        UnixMillis(self.0.load(Ordering::SeqCst))
    }
}

struct Counter(AtomicU8);
impl Rng for Counter {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        for b in buf {
            *b = self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

struct Zero;
impl Rng for Zero {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(0);
        Ok(())
    }
}

struct Max;
impl Rng for Max {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        buf.fill(0xFF);
        Ok(())
    }
}

struct Broken;
impl Rng for Broken {
    fn try_fill(&self, _: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("test".into()))
    }
}

fn gen_with(ms: i64, rng: Arc<dyn Rng>) -> (UlidGen, Arc<Fixed>) {
    let clock = Arc::new(Fixed(AtomicI64::new(ms)));
    (UlidGen::new(clock.clone(), rng), clock)
}

#[test]
fn rfc3339_has_one_canonical_form() {
    assert_eq!(
        UnixMillis(0).to_rfc3339().unwrap(),
        "1970-01-01T00:00:00.000Z"
    );
    assert_eq!(
        UnixMillis(1_792_695_228_777).to_rfc3339().unwrap(),
        "2026-10-22T18:53:48.777Z"
    );
    // 소수부가 0 이거나 3자리 미만이어도 항상 3자리.
    assert_eq!(
        UnixMillis(1_000).to_rfc3339().unwrap(),
        "1970-01-01T00:00:01.000Z"
    );
    assert_eq!(
        UnixMillis(1_007).to_rfc3339().unwrap(),
        "1970-01-01T00:00:01.007Z"
    );
    // 1970 이전도 3자리·올림 없이.
    assert_eq!(
        UnixMillis(-1).to_rfc3339().unwrap(),
        "1969-12-31T23:59:59.999Z"
    );
}

#[test]
fn rfc3339_round_trips_and_accepts_offsets_and_seconds_precision() {
    for ms in [0_i64, 1, 999, 1_792_695_228_777, -86_400_001] {
        let s = UnixMillis(ms).to_rfc3339().unwrap();
        assert_eq!(
            UnixMillis::parse_rfc3339(&s).unwrap(),
            UnixMillis(ms),
            "{s}"
        );
    }
    // 프로토콜 문서 예시는 초 단위(소수부 없음).
    assert_eq!(
        UnixMillis::parse_rfc3339("2026-10-23T04:12:56Z").unwrap(),
        UnixMillis(1_792_728_776_000)
    );
    assert_eq!(
        UnixMillis::parse_rfc3339("2026-10-23T13:12:56+09:00").unwrap(),
        UnixMillis(1_792_728_776_000)
    );
    // 밀리초 미만은 버린다.
    assert_eq!(
        UnixMillis::parse_rfc3339("1970-01-01T00:00:00.0019Z").unwrap(),
        UnixMillis(1)
    );
    assert!(UnixMillis::parse_rfc3339("2026-10-23 04:12:56").is_err());
    assert!(UnixMillis::parse_rfc3339("not a time").is_err());
}

#[test]
fn ulid_encoding_matches_the_spec_vector() {
    // ULID 스펙 예시: 01ARZ3NDEKTSV4RRFFQ69G5FAV = 2016-07-30T23:54:10.259Z.
    assert_eq!(
        decode_ulid_millis("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        Some(1_469_922_850_259)
    );
    let s = encode_ulid(1_469_922_850_259, 0);
    assert_eq!(&s[..10], "01ARZ3NDEK");
    assert_eq!(&s[10..], "0000000000000000");
}

#[test]
fn ulid_validation() {
    assert!(is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
    assert!(!is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FA"), "25자");
    assert!(!is_ulid("81ARZ3NDEKTSV4RRFFQ69G5FAV"), "128비트 초과");
    assert!(
        !is_ulid("01ARZ3NDEKTSV4RRFFQ69G5FAU"),
        "U 는 Crockford 에 없다"
    );
    assert!(
        !is_ulid("01arz3ndektsv4rrffq69g5fav"),
        "소문자는 같은 ID 의 다른 문자열이라 거부"
    );
    assert!(decode_ulid_millis("01arz3ndektsv4rrffq69g5fav").is_none());
    assert!(decode_ulid_millis("short").is_none());
    let max = encode_ulid(0xFFFF_FFFF_FFFF, (1u128 << 80) - 1);
    assert_eq!(&max[..1], "7");
    assert!(is_ulid(&max));
}

#[test]
fn same_millisecond_ids_are_strictly_increasing() {
    let (g, _clock) = gen_with(1_700_000_000_000, Arc::new(Counter(AtomicU8::new(0))));
    let ids: Vec<String> = (0..50).map(|_| g.next_ulid()).collect();
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
    assert!(ids.iter().all(|i| is_ulid(i)));
    assert!(ids
        .iter()
        .all(|i| decode_ulid_millis(i) == Some(1_700_000_000_000)));
}

#[test]
fn ids_never_go_backwards_when_the_clock_does() {
    let (g, clock) = gen_with(1_000, Arc::new(Counter(AtomicU8::new(0))));
    let a = g.next_ulid();
    clock.0.store(500, Ordering::SeqCst);
    let b = g.next_ulid();
    assert!(a < b, "{a} !< {b}");
    assert_eq!(
        decode_ulid_millis(&b),
        Some(1_000),
        "시계가 거꾸로 가도 시각 부분은 줄지 않는다"
    );
}

#[test]
fn ids_sort_by_time_across_milliseconds() {
    let (g, clock) = gen_with(1_000, Arc::new(Zero));
    let a = g.next_ulid();
    clock.0.store(1_001, Ordering::SeqCst);
    let b = g.next_ulid();
    assert!(a < b);
}

#[test]
fn random_overflow_bumps_the_millisecond() {
    let (g, _clock) = gen_with(2_000, Arc::new(Max));
    let a = g.next_ulid(); // 난수 부분이 전부 1 인 값
    let b = g.next_ulid(); // 더 증가시킬 수 없다 → 밀리초를 올린다
    assert!(a < b, "{a} !< {b}");
    assert_eq!(decode_ulid_millis(&b), Some(2_001));
}

#[test]
fn deterministic_with_fixed_inputs() {
    let make = || gen_with(1_700_000_000_000, Arc::new(Counter(AtomicU8::new(7)))).0;
    let (a, b) = (make(), make());
    assert_eq!(
        (a.next_ulid(), a.next_ulid()),
        (b.next_ulid(), b.next_ulid())
    );
}

#[test]
fn system_implementations_work() {
    let now = SystemClock.now();
    assert!(now.0 > 1_700_000_000_000, "시스템 시계가 비정상: {now:?}");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    OsRng.try_fill(&mut a).unwrap();
    OsRng.try_fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
    let g = UlidGen::system();
    let (x, y) = (g.next_ulid(), g.next_ulid());
    assert!(is_ulid(&x) && x < y);
}

#[test]
fn failing_rng_returns_err_instead_of_panicking() {
    // hook 같은 보조 바이너리는 패닉(exit 101)이 fail-open 이 되므로 try_ 판이 Err 를 돌려줘야 한다.
    let (g, _clock) = gen_with(1_000, Arc::new(Broken));
    assert_eq!(g.try_next_ulid(), Err(RngError("test".into())));
    let mut buf = [0u8; 4];
    assert!(Broken.try_fill(&mut buf).is_err());
}

#[test]
#[should_panic(expected = "난수를 얻지 못했다")]
fn fill_panics_when_try_fill_fails() {
    let mut buf = [0u8; 4];
    Broken.fill(&mut buf);
}

struct FailsOnce(std::sync::atomic::AtomicBool);
impl Rng for FailsOnce {
    fn try_fill(&self, buf: &mut [u8]) -> Result<(), RngError> {
        if self.0.swap(false, Ordering::SeqCst) {
            return Err(RngError("일시 실패".into()));
        }
        buf.fill(0);
        Ok(())
    }
}

#[test]
fn a_failed_generation_leaves_state_intact_and_recovers() {
    let (g, _clock) = gen_with(
        5_000,
        Arc::new(FailsOnce(std::sync::atomic::AtomicBool::new(true))),
    );
    assert!(g.try_next_ulid().is_err());
    let a = g.try_next_ulid().expect("복구");
    let b = g.next_ulid();
    assert!(is_ulid(&a) && a < b);
    assert_eq!(decode_ulid_millis(&a), Some(5_000));
}
