//! 차분 시험: 구현(core 의 상태 머신)이 yaml 의 참조 인터프리터와 같은 결과를 내는지.
//!
//! U2 가 [`Implementation`] 을 구현해 [`run`] 에 넘기면 모든 (상태 × 이벤트 × 가드 입력) 케이스를 돌려
//! 어긋난 것을 돌려준다. 참조 구현 [`Reference`] 는 이 크레이트 시험이 자기 자신과의 일치를 확인한다.

use std::collections::BTreeSet;

use crate::coverage::input_space;
use crate::machine::{Env, Machine, Machines, Outcome};
use crate::rng::Rng;

/// 구현이 내는 결과. `None` = 무시(상태 불변 + 기록).
pub type StepResult = Option<(String, Vec<String>)>;

pub trait Implementation {
    fn step(&mut self, machine: &str, state: &str, event: &str, env: &Env) -> StepResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub machine: String,
    pub state: String,
    pub event: String,
    pub env: Env,
    pub expected: StepResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub case: Case,
    pub actual: StepResult,
}

/// 머신 하나의 전수 케이스. 행이 없는 쌍은 "무시" 기대 한 건씩.
///
/// # Panics
/// yaml 에 겹치는 행이 있으면(= `coverage::check` 가 실패할 상태) 패닉한다.
pub fn exhaustive_cases(machine: &Machine) -> Vec<Case> {
    let mut cases = Vec::new();
    for state in &machine.states {
        for event in machine.all_events() {
            let envs = if machine.rows_for(state, &event).is_empty() {
                vec![Env::new()]
            } else {
                input_space(machine, state, &event)
            };
            for env in envs {
                let expected = match machine.step(state, &event, &env) {
                    Outcome::Fired { to, actions, .. } => Some((to, actions)),
                    Outcome::NoRow => None,
                    Outcome::Ambiguous(rows) => {
                        panic!("{}: 겹치는 행 {rows:?} ({state} / {event})", machine.name)
                    }
                };
                cases.push(Case {
                    machine: machine.name.clone(),
                    state: state.clone(),
                    event: event.clone(),
                    env,
                    expected,
                });
            }
        }
    }
    cases
}

pub fn run(machines: &Machines, imp: &mut dyn Implementation) -> Vec<Mismatch> {
    let mut bad = Vec::new();
    for m in &machines.machines {
        for case in exhaustive_cases(m) {
            let actual = imp.step(&case.machine, &case.state, &case.event, &case.env);
            if actual != case.expected {
                bad.push(Mismatch { case, actual });
            }
        }
    }
    bad
}

/// yaml 을 그대로 실행하는 참조 구현.
pub struct Reference<'a>(pub &'a Machines);

impl Implementation for Reference<'_> {
    fn step(&mut self, machine: &str, state: &str, event: &str, env: &Env) -> StepResult {
        match self.0.must(machine).step(state, event, env) {
            Outcome::Fired { to, actions, .. } => Some((to, actions)),
            Outcome::NoRow | Outcome::Ambiguous(_) => None,
        }
    }
}

// ---- 시드 고정 random walk 차분 ----------------------------------------------------------------

/// 걷는 동안 참조 인터프리터의 액션으로 갱신하는 컨텍스트. 가드 입력 중 **상태에서 파생되는 것**
/// (`escalated`·`marker_bound`)은 무작위가 아니라 여기서 정한다(그래야 도달 불가능한 입력 조합이 안 나온다).
#[derive(Debug, Default, Clone)]
pub struct WalkContext {
    pub escalated: bool,
    pub marker_bound: bool,
}

impl WalkContext {
    fn apply(&mut self, actions: &[String]) {
        for a in actions {
            match a.as_str() {
                "set_escalated" => self.escalated = true,
                "clear_marker" => *self = Self::default(),
                "bind_prompt_id" => self.marker_bound = true,
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkMismatch {
    pub seed: u64,
    pub step: usize,
    pub state: String,
    pub event: String,
    pub env: Env,
    pub expected: StepResult,
    pub actual: StepResult,
}

fn walk_env(m: &Machine, rng: &mut Rng, ctx: &WalkContext) -> Env {
    let mut keys: BTreeSet<String> = m.guard_inputs.keys().cloned().collect();
    for r in &m.rows {
        keys.extend(r.guard.iter().map(|(k, _)| k.clone()));
    }
    keys.into_iter()
        .map(|k| {
            let v = match k.as_str() {
                "escalated" => ctx.escalated.to_string(),
                "marker_bound" => ctx.marker_bound.to_string(),
                _ => match m.guard_inputs.get(&k) {
                    Some(d) => rng.pick(d).cloned().unwrap_or_default(),
                    None => rng
                        .pick(&["true", "false"])
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                },
            };
            (k, v)
        })
        .collect()
}

/// 시드 고정 이벤트 열을 참조 인터프리터와 구현에 같이 넣고 매 스텝 결과(다음 상태·액션)를 비교한다.
/// 상태는 참조가 따라가며, 구현에는 매 스텝 현재 상태를 넘긴다(상태를 직접 들고 있는 집행자는 그 값과 자기 상태가
/// 같은지 스스로 단언할 수 있다). 단일 step 전수 대조(`run`)가 못 보는 **스텝 간 이어짐**(마커·escalated·
/// bound_prompt_id)을 본다.
///
/// # Panics
/// 머신이 없거나 yaml 에 겹치는 행이 있으면(= `coverage::check` 실패 상태) 패닉한다.
pub fn random_walk_diff(
    ms: &Machines,
    machine: &str,
    imp: &mut dyn Implementation,
    seeds: std::ops::Range<u64>,
    steps: usize,
) -> Vec<WalkMismatch> {
    let m = ms.must(machine);
    let events = m.all_events();
    let mut bad = Vec::new();
    for seed in seeds {
        let mut rng = Rng::new(seed);
        let mut state = m.initial.clone().unwrap_or_else(|| m.states[0].clone());
        let mut ctx = WalkContext::default();
        for step in 0..steps {
            let event = rng.pick(&events).cloned().expect("이벤트가 있다");
            let env = walk_env(m, &mut rng, &ctx);
            let expected = match m.step(&state, &event, &env) {
                Outcome::Fired { to, actions, .. } => Some((to, actions)),
                Outcome::NoRow => None,
                Outcome::Ambiguous(rows) => {
                    panic!("{machine}: 겹치는 행 {rows:?} ({state} / {event})")
                }
            };
            let actual = imp.step(machine, &state, &event, &env);
            if actual != expected {
                bad.push(WalkMismatch {
                    seed,
                    step,
                    state: state.clone(),
                    event: event.clone(),
                    env: env.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
            if let Some((to, actions)) = expected {
                ctx.apply(&actions);
                state = to;
            }
        }
    }
    bad
}
