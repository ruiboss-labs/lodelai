//! 선 머신 yaml(machines/wire.yaml)에 대한 L1 시험 (U13a, #36). 앱 머신(chat·remote_turn) 몫은 앱 쪽 크레이트로 옮겼다(#559).
//! QA test-strategy §2.1: 전수 + property. 원천 yaml 이 바뀌면 이 시험이 먼저 깨진다.

use lodelai_testkit::conformance::{exhaustive_cases, run, Reference};
use lodelai_testkit::coverage::check;
use lodelai_testkit::machine::Machines;
use lodelai_testkit::props;

fn yaml() -> Machines {
    lodelai_testkit::load_default().expect("wire.yaml 을 읽을 수 있어야 한다")
}

#[test]
fn loads_expected_machines() {
    let y = yaml();
    assert_eq!(
        y.version, 3,
        "yaml 키 구조 버전이 바뀌었다 — 로더·시험을 같이 갱신"
    );
    for name in [
        "request_recipient",
        "request_sender_view",
        "envelope_server",
    ] {
        let m = y.must(name);
        assert!(!m.rows.is_empty(), "{name}: 행이 없다");
        if let Some(init) = &m.initial {
            assert!(
                m.states.contains(init),
                "{name}: initial `{init}` 이 states 에 없다"
            );
        }
    }
}

#[test]
fn every_machine_has_exactly_one_row_per_input() {
    let y = yaml();
    let mut total = 0;
    for m in &y.machines {
        let rep = check(m);
        assert!(
            rep.is_clean(),
            "{}: coverage 실패\n gaps={:#?}\n overlaps={:#?}\n unknown_states={:?}\n undeclared_events={:?}\n terminal_exits={:?}",
            m.name,
            rep.gaps,
            rep.overlaps,
            rep.unknown_states,
            rep.undeclared_events,
            rep.terminal_exits
        );
        assert!(rep.combos_checked > 0, "{}: 검사한 조합이 없다", m.name);
        total += rep.combos_checked;
    }
    assert!(
        total > 100,
        "전수 검사 조합 수가 비정상적으로 적다: {total}"
    );
}

#[test]
fn guard_keys_are_declared_in_guard_inputs() {
    // 선언 없는 가드 키는 값 영역을 추론해야 해서 시험이 약해진다(오타도 못 잡는다).
    let y = yaml();
    let mut undeclared = Vec::new();
    for m in &y.machines {
        for k in check(m).undeclared_guard_keys {
            undeclared.push(format!("{}.{k}", m.name));
        }
    }
    assert!(
        undeclared.is_empty(),
        "guard_inputs 에 선언되지 않은 가드 키: {undeclared:?} (yaml 의 guard_inputs 에 영역을 선언한다)"
    );
}

#[test]
fn reference_implementation_conforms_to_itself() {
    let y = yaml();
    let mismatches = run(&y, &mut Reference(&y));
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    let n: usize = y.machines.iter().map(|m| exhaustive_cases(m).len()).sum();
    assert!(n > 300, "전수 케이스 수가 비정상적으로 적다: {n}");
}

// ---- property (props.rs) -------------------------------------------------------------------

#[test]
fn properties_hold_on_the_real_yaml() {
    let y = yaml();
    let bad: Vec<_> = props::all(&y)
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    assert!(bad.is_empty(), "property 위반: {bad:#?}");
}
