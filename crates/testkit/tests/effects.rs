use std::sync::Arc;

use lodelai_effects::{decode_ulid_millis, is_ulid, Clock, IdGen, Rng, UlidGen};
use lodelai_testkit::effects::{FailingRng, FixedClock, SeedRng, SeqIdGen, TestEffects};

#[test]
fn fixed_clock_moves_only_when_told() {
    let c = FixedClock::new(1_000);
    assert_eq!(c.now().0, 1_000);
    c.advance(250);
    assert_eq!(c.now().0, 1_250);
    c.advance(-300);
    assert_eq!(c.now().0, 950, "시계 역행도 만들 수 있다");
    c.set(5);
    assert_eq!(c.now().0, 5);
}

#[test]
fn seed_rng_is_reproducible_and_seed_dependent() {
    let (a, b, c) = (SeedRng::new(1), SeedRng::new(1), SeedRng::new(2));
    let (mut x, mut y, mut z) = ([0u8; 37], [0u8; 37], [0u8; 37]);
    a.fill(&mut x);
    b.fill(&mut y);
    c.fill(&mut z);
    assert_eq!(x, y);
    assert_ne!(x, z);
    assert_ne!(x, [0u8; 37]);
    // 이어서 뽑으면 다른 값(상태가 진행한다).
    let mut x2 = [0u8; 37];
    a.fill(&mut x2);
    assert_ne!(x, x2);
}

#[test]
fn failing_rng_fails_then_recovers() {
    let always = FailingRng::always();
    assert!(!always.was_called());
    assert!(always.try_fill(&mut [0u8; 8]).is_err());
    assert!(always.was_called());

    let twice = FailingRng::first(2);
    assert!(twice.try_fill(&mut [0u8; 8]).is_err());
    assert!(twice.try_fill(&mut [0u8; 8]).is_err());
    assert!(twice.try_fill(&mut [0u8; 8]).is_ok());
}

#[test]
fn seq_idgen_is_strictly_increasing_and_reproducible() {
    let run = || {
        let clock = FixedClock::new(1_700_000_000_000);
        let g = SeqIdGen::new(clock.clone());
        let mut ids = vec![g.next_ulid(), g.next_ulid(), g.next_ulid()];
        clock.advance(1);
        ids.push(g.next_ulid());
        clock.advance(-5_000); // 시계 역행: 시각 부분은 줄지 않고 ID 는 계속 증가
        ids.push(g.next_ulid());
        ids
    };
    let ids = run();
    assert_eq!(ids, run(), "같은 입력은 같은 ID");
    assert!(ids.iter().all(|i| is_ulid(i)));
    // 정렬 순서 = 생성 순서.
    assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ids:?}");
}

#[test]
fn test_effects_bundle_drives_a_monotonic_ulid_gen() {
    let fx = TestEffects::new(10_000, 42);
    let a = fx.ids.next_ulid();
    let b = fx.ids.next_ulid();
    assert!(a < b);
    assert_eq!(decode_ulid_millis(&a), Some(10_000));
    fx.clock.advance(1);
    let c = fx.ids.next_ulid();
    assert!(b < c);
    assert_eq!(decode_ulid_millis(&c), Some(10_001));
    // 같은 시드·시작 시각이면 같은 열.
    let fx2 = TestEffects::new(10_000, 42);
    assert_eq!(fx2.ids.next_ulid(), a);
}

#[test]
fn ulid_gen_with_failing_rng_reports_instead_of_panicking() {
    let g = UlidGen::new(FixedClock::new(1), FailingRng::always());
    assert!(g.try_next_ulid().is_err());
    let g2 = UlidGen::new(FixedClock::new(1), FailingRng::first(1));
    assert!(g2.try_next_ulid().is_err());
    assert!(g2.try_next_ulid().is_ok(), "일시 실패 뒤 복구");
    let _ = Arc::new(g2); // Arc<dyn IdGen> 로 주입 가능
}

#[test]
fn seq_idgen_never_decreases_when_the_clock_goes_back() {
    let clock = FixedClock::new(10_000);
    let g = SeqIdGen::new(clock.clone());
    let a = g.next_ulid();
    clock.advance(-9_000);
    let b = g.next_ulid();
    assert!(a < b, "{a} !< {b}");
    assert_eq!(decode_ulid_millis(&b), Some(10_000));
}

#[test]
fn failing_rng_after_n_succeeds_then_fails() {
    let r = FailingRng::after(2);
    assert!(r.try_fill(&mut [1u8; 8]).is_ok());
    assert!(r.try_fill(&mut [1u8; 8]).is_ok());
    assert!(r.try_fill(&mut [1u8; 8]).is_err());
    assert!(r.try_fill(&mut [1u8; 8]).is_err());
    // UlidGen: 첫 ID 의 난수 한 번은 성공, 그 뒤 새 난수가 필요한 시점(ms 가 바뀜)부터 실패 — 상태는 그대로.
    let clock = FixedClock::new(1);
    let g = UlidGen::new(clock.clone(), FailingRng::after(1));
    let a = g.try_next_ulid().expect("첫 난수 성공");
    let b = g.try_next_ulid().expect("같은 ms 는 난수 증가만 필요");
    assert!(a < b);
    clock.advance(1);
    assert!(
        g.try_next_ulid().is_err(),
        "ms 가 바뀌면 새 난수가 필요 → 실패"
    );
}
