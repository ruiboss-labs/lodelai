//! 변형 시험: yaml 을 일부러 망가뜨리면 검사가 **실패해야 한다**. 검사가 공허하지 않다는 증거.
//! 선 머신 몫만 — remote_turn 을 망가뜨리는 변형(m1~m5·m9)은 앱 쪽 크레이트에 있다(#559).

use lodelai_testkit::coverage::check;
use lodelai_testkit::machine::{Machines, Row};
use lodelai_testkit::props;

fn base() -> Machines {
    lodelai_testkit::load_default().expect("yaml")
}

fn push_row(
    ms: &mut Machines,
    machine: &str,
    from: &str,
    event: &str,
    to: &str,
    guard: &[(&str, &[&str])],
) {
    let m = ms
        .machines
        .iter_mut()
        .find(|m| m.name == machine)
        .expect("machine");
    let index = m.rows.len();
    m.rows.push(Row {
        index,
        from: from.into(),
        event: event.into(),
        to: to.into(),
        guard: guard
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    v.iter().map(|x| (*x).to_string()).collect(),
                )
            })
            .collect(),
        actions: vec![],
        generated: false,
    });
}

fn machine_mut<'a>(ms: &'a mut Machines, name: &str) -> &'a mut lodelai_testkit::machine::Machine {
    ms.machines
        .iter_mut()
        .find(|m| m.name == name)
        .expect("machine")
}

#[test]
fn original_is_clean() {
    let y = base();
    assert!(props::all(&y).iter().all(|(_, v)| v.is_empty()));
    assert!(y.machines.iter().all(|m| check(m).is_clean()));
}

#[test]
fn m6_clock_tick_changing_state_is_a_p2_violation() {
    let mut y = base();
    let m = machine_mut(&mut y, "request_recipient");
    let r = m
        .rows
        .iter_mut()
        .find(|r| r.event == "clock_tick")
        .expect("row");
    r.to = "expired".into();
    assert!(!props::p2(y.must("request_recipient")).is_empty());
}

#[test]
fn m7_auto_accept_is_detected() {
    let mut y = base();
    push_row(
        &mut y,
        "request_recipient",
        "pending",
        "session_live_idle",
        "accepted",
        &[],
    );
    assert!(!props::no_auto_accept(y.must("request_recipient")).is_empty());
}

#[test]
fn m8_injection_without_marker_guard_is_detected() {
    let mut y = base();
    let m = machine_mut(&mut y, "request_recipient");
    let r = m
        .rows
        .iter_mut()
        .find(|r| r.to == "injected" && r.from == "accepted")
        .expect("row");
    r.guard.retain(|(k, _)| k != "marker_write");
    assert!(!props::injection_guards(y.must("request_recipient")).is_empty());
}

#[test]
fn m10_terminal_exit_is_detected() {
    let mut y = base();
    push_row(
        &mut y,
        "request_recipient",
        "rejected",
        "human_accept",
        "accepted",
        &[],
    );
    let m = y.must("request_recipient");
    assert!(!props::terminal_is_inert(m).is_empty());
    assert!(!check(m).terminal_exits.is_empty());
}
