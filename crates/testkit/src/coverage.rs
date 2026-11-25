//! (상태 × 이벤트 × 가드 입력) 전수 검사.
//!
//! 규칙(yaml legend): 한 (상태, 이벤트) 에 행이 있으면 모든 가드 입력 조합에서 **정확히 한 행**이 맞아야 한다.
//! 행이 하나도 없는 조합은 "무시: 상태 불변 + 기록"(암묵 무시)이며 빈틈이 아니다.

use std::collections::{BTreeMap, BTreeSet};

use crate::machine::{Env, Machine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub state: String,
    pub event: String,
    pub env: Env,
    /// 겹친 경우 맞은 행 번호들.
    pub rows: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct Report {
    /// 행은 있지만 이 입력에는 맞는 행이 없다.
    pub gaps: Vec<Finding>,
    /// 이 입력에 둘 이상 맞는다.
    pub overlaps: Vec<Finding>,
    /// 가드에 쓰였지만 `guard_inputs` 에 선언되지 않은 키(값 영역을 행에서 추론했다).
    pub undeclared_guard_keys: BTreeSet<String>,
    /// 행의 `from`/`to` 가 `states` 에 없다.
    pub unknown_states: Vec<String>,
    /// 머신이 `events` 를 선언했는데 행에서 선언 밖 이벤트를 쓴다.
    pub undeclared_events: Vec<String>,
    /// 종료 상태에서 다른 상태로 나가는 행.
    pub terminal_exits: Vec<String>,
    /// 행이 하나도 없는 (상태, 이벤트) 쌍의 수.
    pub implicit_ignores: usize,
    /// 검사한 (상태, 이벤트, 입력) 조합의 수.
    pub combos_checked: usize,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.gaps.is_empty()
            && self.overlaps.is_empty()
            && self.unknown_states.is_empty()
            && self.undeclared_events.is_empty()
            && self.terminal_exits.is_empty()
    }
}

/// 가드 키 하나의 값 영역: 선언이 있으면 그것, 없으면 행에 쓰인 값(+ bool 이면 true/false, 아니면 `<other>`).
fn domain(machine: &Machine, key: &str, seen: &BTreeSet<String>) -> Vec<String> {
    if let Some(d) = machine.guard_inputs.get(key) {
        return d.clone();
    }
    let boolish = seen.iter().all(|v| v == "true" || v == "false");
    if boolish {
        vec!["true".into(), "false".into()]
    } else {
        let mut v: Vec<String> = seen.iter().cloned().collect();
        v.push("<other>".into());
        v
    }
}

/// 값 영역들의 곱집합을 `Env` 목록으로 만든다.
pub fn combos(keys: &[String], domains: &[Vec<String>]) -> Vec<Env> {
    let mut out: Vec<Env> = vec![BTreeMap::new()];
    for (k, dom) in keys.iter().zip(domains) {
        let mut next = Vec::with_capacity(out.len() * dom.len());
        for env in &out {
            for v in dom {
                let mut e = env.clone();
                e.insert(k.clone(), v.clone());
                next.push(e);
            }
        }
        out = next;
    }
    out
}

/// 한 (상태, 이벤트) 의 가드 키 목록과 입력 조합.
pub fn input_space(machine: &Machine, state: &str, event: &str) -> Vec<Env> {
    let rows = machine.rows_for(state, event);
    let mut seen: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in &rows {
        for (k, vals) in &r.guard {
            seen.entry(k.clone())
                .or_default()
                .extend(vals.iter().cloned());
        }
    }
    let keys: Vec<String> = seen.keys().cloned().collect();
    let domains: Vec<Vec<String>> = keys.iter().map(|k| domain(machine, k, &seen[k])).collect();
    combos(&keys, &domains)
}

pub fn check(machine: &Machine) -> Report {
    let mut rep = Report::default();
    let states: BTreeSet<&str> = machine.states.iter().map(String::as_str).collect();
    let declared: BTreeSet<&str> = machine.events.iter().map(String::as_str).collect();

    for r in &machine.rows {
        for s in [&r.from, &r.to] {
            if !states.contains(s.as_str()) {
                rep.unknown_states
                    .push(format!("{}: 행 #{} 의 상태 `{s}`", machine.name, r.index));
            }
        }
        if !declared.is_empty() && !declared.contains(r.event.as_str()) {
            rep.undeclared_events.push(format!(
                "{}: 행 #{} 의 이벤트 `{}`",
                machine.name, r.index, r.event
            ));
        }
        if machine.is_terminal(&r.from) && r.to != r.from {
            rep.terminal_exits.push(format!(
                "{}: 종료 상태 `{}` 에서 `{}` 로 나가는 행 #{} ({})",
                machine.name, r.from, r.to, r.index, r.event
            ));
        }
        for (k, _) in &r.guard {
            if !machine.guard_inputs.contains_key(k) {
                rep.undeclared_guard_keys.insert(k.clone());
            }
        }
    }

    for state in &machine.states {
        for event in machine.all_events() {
            if machine.rows_for(state, &event).is_empty() {
                rep.implicit_ignores += 1;
                continue;
            }
            for env in input_space(machine, state, &event) {
                rep.combos_checked += 1;
                let hits: Vec<usize> = machine
                    .rows_for(state, &event)
                    .into_iter()
                    .filter(|r| r.matches(&env))
                    .map(|r| r.index)
                    .collect();
                let f = |rows: Vec<usize>| Finding {
                    state: state.clone(),
                    event: event.clone(),
                    env: env.clone(),
                    rows,
                };
                match hits.len() {
                    0 => rep.gaps.push(f(hits)),
                    1 => {}
                    _ => rep.overlaps.push(f(hits)),
                }
            }
        }
    }
    rep
}
