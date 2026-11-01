//! 상태 머신 yaml 의 property 를 코드로 옮긴 검사. 각 함수는 **위반 목록**을 돌려준다(비어 있으면 통과).
//! 시험은 원본 yaml 에서 빈 목록을, 일부러 망가뜨린 변형(`tests/mutation.rs`)에서 비지 않은 목록을 단언한다 —
//! 검사가 공허하지 않다는 증거. 선 머신 성질만 — 앱 머신(remote_turn)의 보안 성질 P1·P4·P7·P8 은 앱 쪽 시험에 있다(#570).

use crate::machine::{Machine, Machines, Row};

fn fmt(r: &Row) -> String {
    format!(
        "#{} {} --{}--> {} guard={:?}",
        r.index, r.from, r.event, r.to, r.guard
    )
}

/// P2: clock_tick 은 어떤 상태도 바꾸지 않고 가드도 없다.
pub fn p2(m: &Machine) -> Vec<String> {
    m.rows
        .iter()
        .filter(|r| r.event == "clock_tick" && (r.from != r.to || !r.guard.is_empty()))
        .map(|r| format!("P2: {} {}", m.name, fmt(r)))
        .collect()
}

/// 옛 AC-AR-8(묶음 24 §1a 로 바뀜): pending → accepted 는 사람의 수락 이벤트 또는 코어의 `policy_accept` 뿐 — 그 밖의
/// 길로 accepted 가 되지 않는다.
pub fn no_auto_accept(m: &Machine) -> Vec<String> {
    m.rows
        .iter()
        .filter(|r| r.to == "accepted" && r.from != "accepted")
        .filter(|r| {
            !(r.from == "pending"
                && matches!(
                    r.event.as_str(),
                    "human_accept" | "human_accept_draft" | "policy_accept"
                ))
        })
        .map(|r| format!("AC-AR-8: 자동 수락 의심 {}", fmt(r)))
        .collect()
}

/// S-HOOK-3·AC-GR-6: injected 로 들어가는 모든 행이 설정 검증·직렬화·마커 쓰기 가드를 요구한다.
pub fn injection_guards(m: &Machine) -> Vec<String> {
    let mut v = Vec::new();
    for r in m
        .rows
        .iter()
        .filter(|r| r.to == "injected" && r.from != "injected")
    {
        if !matches!(r.from.as_str(), "accepted" | "queued") {
            v.push(format!("injected 진입 출발 상태가 이상하다 {}", fmt(r)));
        }
        for (k, val) in [
            ("hooks_config_verified", "true"),
            ("remote_turn_free", "true"),
            ("marker_write", "ok"),
        ] {
            if !r.guard_is(k, &[val]) {
                v.push(format!("injected 진입에 {k}={val} 가드가 없다 {}", fmt(r)));
            }
        }
    }
    v
}

/// 종료 상태는 상태를 바꾸지 않고 세션으로 전송하지 않는다.
pub fn terminal_is_inert(m: &Machine) -> Vec<String> {
    let mut v = Vec::new();
    for r in m.rows.iter().filter(|r| m.is_terminal(&r.from)) {
        if r.to != r.from {
            v.push(format!("종료 상태에서 나간다 {}", fmt(r)));
        }
        if r.actions
            .iter()
            .any(|a| a == "send" || a.starts_with("send_reply"))
            && r.from != "replied"
        {
            v.push(format!("종료 상태에서 전송 액션 {}", fmt(r)));
        }
    }
    v
}

/// 머신별로 위 검사를 모은다. `(검사 이름, 위반)` 목록.
pub fn all(ms: &Machines) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for m in &ms.machines {
        out.push((format!("{}:p2", m.name), p2(m)));
        out.push((format!("{}:terminal", m.name), terminal_is_inert(m)));
    }
    if let Some(rr) = ms.get("request_recipient") {
        out.push((
            "request_recipient:no_auto_accept".into(),
            no_auto_accept(rr),
        ));
        out.push((
            "request_recipient:injection_guards".into(),
            injection_guards(rr),
        ));
    }
    out
}
