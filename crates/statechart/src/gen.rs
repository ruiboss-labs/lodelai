//! yaml(version 3) → 머신별 State/Event/가드/Action enum 과 순수 전이 함수 `step()` 의 Rust 코드.
//! 공개 선 머신(`machines/wire.yaml`)은 이 크레이트 build.rs 가, 앱 머신은 그 크레이트 build.rs 가 같은 함수로 만든다(#559).
//! yaml 이 legend 규칙을 어기면 오류다(검증은 [`crate::model`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::model::{self, Machine, Row};

/// yaml 글 → 생성 코드. `root` 는 생성 코드가 `Step`·`MissingGuard`·`StateMachine` 을 찾는 경로다 — 이 크레이트 안이면
/// `"crate"`, 다른 크레이트면 `"::lodelai_statechart"`. `source` 는 머리 주석에 적는 yaml 경로.
///
/// # Errors
/// yaml 형식이 틀리거나 legend 규칙을 어기면 사람이 읽을 메시지.
pub fn generate(yaml: &str, root: &str, source: &str) -> Result<String, String> {
    let spec = model::load(yaml).map_err(|e| e.to_string())?;
    let names: BTreeSet<&str> = spec.machines.iter().map(|m| m.name.as_str()).collect();
    let mut out = String::new();
    writeln!(
        out,
        "// 생성 파일 — build.rs 가 {source} 에서 만든다. 직접 고치지 말 것."
    )
    .unwrap();
    writeln!(out, "pub const YAML_VERSION: i64 = {};", spec.version).unwrap();
    let list: Vec<String> = spec
        .machines
        .iter()
        .map(|m| format!("{:?}", m.name))
        .collect();
    writeln!(out, "pub const MACHINES: &[&str] = &[{}];", list.join(", ")).unwrap();
    for m in &spec.machines {
        gen_machine(&mut out, m, &names, root);
    }
    Ok(out)
}

fn pascal(s: &str) -> String {
    s.split(['_', '.', '-'])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

fn is_bool(domain: &[String]) -> bool {
    let set: BTreeSet<&str> = domain.iter().map(String::as_str).collect();
    set == BTreeSet::from(["true", "false"])
}

/// 이름 목록 → serde 이름을 보존하는 enum + as_str/from_name/ALL.
fn gen_enum(out: &mut String, ty: &str, doc: &str, names: &[String]) {
    writeln!(out, "    /// {doc}").unwrap();
    writeln!(out, "    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]").unwrap();
    writeln!(out, "    pub enum {ty} {{").unwrap();
    for n in names {
        writeln!(
            out,
            "        #[serde(rename = {n:?})]\n        {},",
            pascal(n)
        )
        .unwrap();
    }
    writeln!(out, "    }}\n    impl {ty} {{").unwrap();
    let all: Vec<String> = names
        .iter()
        .map(|n| format!("Self::{}", pascal(n)))
        .collect();
    writeln!(
        out,
        "        pub const ALL: &'static [Self] = &[{}];",
        all.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "        pub const fn as_str(self) -> &'static str {{\n            match self {{"
    )
    .unwrap();
    for n in names {
        writeln!(out, "                Self::{} => {n:?},", pascal(n)).unwrap();
    }
    writeln!(out, "            }}\n        }}").unwrap();
    writeln!(
        out,
        "        pub fn from_name(s: &str) -> Option<Self> {{\n            match s {{"
    )
    .unwrap();
    for n in names {
        writeln!(out, "                {n:?} => Some(Self::{}),", pascal(n)).unwrap();
    }
    writeln!(
        out,
        "                _ => None,\n            }}\n        }}\n    }}"
    )
    .unwrap();
}

struct GuardTy {
    key: String,
    /// Rust 타입(`bool` 또는 enum 이름).
    ty: String,
    is_bool: bool,
}

fn gen_machine(out: &mut String, m: &Machine, names: &BTreeSet<&str>, root: &str) {
    let rows = m.expand().expect("검증됨");
    writeln!(out, "\n/// 머신 `{}`.\n#[allow(clippy::match_same_arms, clippy::too_many_lines, clippy::enum_variant_names, clippy::match_single_binding)]\npub mod {} {{", m.name, m.name).unwrap();
    writeln!(
        out,
        "    use {root}::{{MissingGuard, Step as GenericStep}};"
    )
    .unwrap();
    writeln!(out, "    pub const NAME: &str = {:?};", m.name).unwrap();

    let state_names: Vec<String> = m.states.iter().map(|s| s.name.clone()).collect();
    gen_enum(out, "State", "상태.", &state_names);
    writeln!(out, "    impl State {{").unwrap();
    let terminals: Vec<String> = m
        .states
        .iter()
        .filter(|s| s.terminal)
        .map(|s| format!("Self::{}", pascal(&s.name)))
        .collect();
    let body = if terminals.is_empty() {
        "false".to_string()
    } else {
        format!("matches!(self, {})", terminals.join(" | "))
    };
    writeln!(out, "        #[allow(clippy::unused_self)]\n        pub const fn is_terminal(self) -> bool {{\n            {body}\n        }}").unwrap();
    if m.states.iter().all(|s| s.rank.is_some()) {
        writeln!(out, "        /// 발신자 뷰 rank(높을수록 진행). 받은 status 의 rank 가 더 높을 때만 적용한다.\n        pub const fn rank(self) -> i64 {{\n            match self {{").unwrap();
        for s in &m.states {
            writeln!(
                out,
                "                Self::{} => {},",
                pascal(&s.name),
                s.rank.unwrap()
            )
            .unwrap();
        }
        writeln!(out, "            }}\n        }}").unwrap();
    }
    if names.contains("request_sender_view")
        && m.states.iter().any(|s| s.visible_to_sender.is_some())
    {
        writeln!(out, "        /// 발신자에게 보이는 상태. 없으면 발신자에게 status 를 보내지 않는 상태다(`held`·`unreadable`, #313).\n        pub const fn visible_to_sender(self) -> Option<super::request_sender_view::State> {{\n            match self {{").unwrap();
        for s in &m.states {
            match &s.visible_to_sender {
                Some(v) => writeln!(
                    out,
                    "                Self::{} => Some(super::request_sender_view::State::{}),",
                    pascal(&s.name),
                    pascal(v)
                ),
                None => writeln!(out, "                Self::{} => None,", pascal(&s.name)),
            }
            .unwrap();
        }
        writeln!(out, "            }}\n        }}").unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(
        out,
        "    pub const INITIAL: State = State::{};",
        pascal(&m.initial)
    )
    .unwrap();

    gen_enum(out, "Event", "이벤트.", &m.events);

    if !m.abort_reasons.is_empty() {
        gen_enum(out, "AbortReason", "aborted 의 사유.", &m.abort_reasons);
    }

    // 가드 입력 타입
    let mut guards = Vec::new();
    for (key, domain) in &m.guard_inputs {
        if is_bool(domain) {
            guards.push(GuardTy {
                key: key.clone(),
                ty: "bool".into(),
                is_bool: true,
            });
        } else if key == "abort_reason" && !m.abort_reasons.is_empty() {
            guards.push(GuardTy {
                key: key.clone(),
                ty: "AbortReason".into(),
                is_bool: false,
            });
        } else {
            let ty = format!("Guard{}", pascal(key));
            gen_enum(out, &ty, &format!("가드 입력 `{key}`."), domain);
            guards.push(GuardTy {
                key: key.clone(),
                ty,
                is_bool: false,
            });
        }
    }
    writeln!(out, "    /// 가드 입력. 이번 (상태, 이벤트) 의 행이 참조하는 키만 채우면 된다 — 참조된 키가 비어 있으면 `step` 이 오류.").unwrap();
    writeln!(
        out,
        "    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]\n    pub struct Guards {{"
    )
    .unwrap();
    for g in &guards {
        writeln!(out, "        #[serde(skip_serializing_if = \"Option::is_none\")]\n        pub {}: Option<{}>,", g.key, g.ty).unwrap();
    }
    writeln!(out, "    }}\n    impl Guards {{").unwrap();
    writeln!(out, "        /// 이름·문자열 값으로 채운다(시험·로그 재생용). 모르는 키나 값이면 false.\n        #[allow(unused_variables)]\n        pub fn set_by_name(&mut self, key: &str, value: &str) -> bool {{\n            match key {{").unwrap();
    for g in &guards {
        if g.is_bool {
            writeln!(out, "                {:?} => match value {{ \"true\" => {{ self.{} = Some(true); true }} \"false\" => {{ self.{} = Some(false); true }} _ => false }},", g.key, g.key, g.key).unwrap();
        } else {
            writeln!(out, "                {:?} => {}::from_name(value).map(|v| self.{} = Some(v)).is_some(),", g.key, g.ty, g.key).unwrap();
        }
    }
    writeln!(
        out,
        "                _ => false,\n            }}\n        }}\n    }}"
    )
    .unwrap();

    // 액션
    let mut action_names: BTreeSet<String> = BTreeSet::new();
    for r in &rows {
        for a in &r.actions {
            action_names.insert(a.name.clone());
        }
    }
    writeln!(out, "    /// 전이가 집행자에게 요청하는 일. 순서대로 실행하고, 하나라도 실패하면 전이하지 않는다(집행자 규칙).").unwrap();
    writeln!(
        out,
        "    #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n    pub enum Action {{"
    )
    .unwrap();
    for a in &action_names {
        match a.as_str() {
            "set_abort_reason" => writeln!(out, "        SetAbortReason(AbortReason),").unwrap(),
            "set_reason" => writeln!(out, "        SetReason(&'static str),").unwrap(),
            _ => writeln!(out, "        {},", pascal(a)).unwrap(),
        }
    }
    writeln!(out, "    }}\n    impl Action {{\n        pub const fn name(self) -> &'static str {{\n            match self {{").unwrap();
    for a in &action_names {
        match a.as_str() {
            "set_abort_reason" => {
                writeln!(out, "                Self::SetAbortReason(_) => {a:?},").unwrap()
            }
            "set_reason" => writeln!(out, "                Self::SetReason(_) => {a:?},").unwrap(),
            _ => writeln!(out, "                Self::{} => {a:?},", pascal(a)).unwrap(),
        }
    }
    writeln!(out, "            }}\n        }}").unwrap();
    writeln!(out, "        /// `name` 또는 `name=인자` (yaml 표기와 같은 한 문자열).\n        pub fn render(self) -> String {{\n            match self {{").unwrap();
    if action_names.contains("set_abort_reason") {
        writeln!(out, "                Self::SetAbortReason(r) => format!(\"set_abort_reason={{}}\", r.as_str()),").unwrap();
    }
    if action_names.contains("set_reason") {
        writeln!(
            out,
            "                Self::SetReason(r) => format!(\"set_reason={{r}}\"),"
        )
        .unwrap();
    }
    writeln!(
        out,
        "                other => other.name().to_string(),\n            }}\n        }}\n    }}"
    )
    .unwrap();

    // step
    writeln!(out, "    pub type Step = GenericStep<State, Action>;").unwrap();
    writeln!(out, "    /// 순수 전이 함수. I/O·시계 없음. 일치하는 행이 없으면 `Step::Ignored`(legend: 상태 불변 + 기록).").unwrap();
    writeln!(out, "    ///\n    /// # Errors\n    /// 이번 (상태, 이벤트) 의 행이 참조하는 가드가 `None` 이면 [`MissingGuard`] — 집행자 버그를 무시로 삼키지 않는다.").unwrap();
    writeln!(out, "    #[allow(unused_variables)]\n    pub fn step(state: State, event: Event, g: &Guards) -> Result<Step, MissingGuard> {{").unwrap();
    let mut groups: BTreeMap<(&str, &str), Vec<&Row>> = BTreeMap::new();
    for r in &rows {
        groups.entry((&r.from, &r.event)).or_default().push(r);
    }
    writeln!(out, "        match (state, event) {{").unwrap();
    for ((from, event), group) in &groups {
        let keys: BTreeSet<&String> = group.iter().flat_map(|r| r.guard.keys()).collect();
        writeln!(
            out,
            "            (State::{}, Event::{}) => {{",
            pascal(from),
            pascal(event)
        )
        .unwrap();
        for k in &keys {
            writeln!(out, "                let {k} = g.{k}.ok_or(MissingGuard {{ machine: NAME, key: {k:?} }})?;").unwrap();
        }
        if group.len() == 1 && group[0].guard.is_empty() {
            writeln!(
                out,
                "                Ok(Step::Transition {{ to: State::{}, actions: {} }})",
                pascal(&group[0].to),
                actions_lit(group[0])
            )
            .unwrap();
        } else {
            for r in group {
                let conds: Vec<String> = r
                    .guard
                    .iter()
                    .map(|(k, vals)| {
                        let gt = guards.iter().find(|g| &g.key == k).expect("검증됨");
                        if gt.is_bool {
                            if vals.len() == 2 {
                                "true".to_string()
                            } else {
                                format!("{}{k}", if vals[0] == "true" { "" } else { "!" })
                            }
                        } else {
                            let pats: Vec<String> = vals
                                .iter()
                                .map(|v| format!("{}::{}", gt.ty, pascal(v)))
                                .collect();
                            format!("matches!({k}, {})", pats.join(" | "))
                        }
                    })
                    .collect();
                writeln!(out, "                // transitions[{}]", r.src).unwrap();
                writeln!(out, "                if {} {{\n                    return Ok(Step::Transition {{ to: State::{}, actions: {} }});\n                }}",
                    conds.join(" && "), pascal(&r.to), actions_lit(r)).unwrap();
            }
            writeln!(out, "                Ok(Step::Ignored)").unwrap();
        }
        writeln!(out, "            }}").unwrap();
    }
    if groups.len() < m.states.len() * m.events.len() {
        writeln!(out, "            _ => Ok(Step::Ignored),").unwrap();
    }
    writeln!(out, "        }}\n    }}").unwrap();
    writeln!(out, "    /// 이 머신을 [`{root}::StateMachine`] 으로 다루는 표지 타입.\n    #[derive(Debug, Clone, Copy)]\n    pub struct Machine;").unwrap();
    writeln!(out, "    impl {root}::StateMachine for Machine {{").unwrap();
    writeln!(
        out,
        "        const NAME: &'static str = NAME;\n        const INITIAL: State = INITIAL;"
    )
    .unwrap();
    writeln!(out, "        type State = State;\n        type Event = Event;\n        type Guards = Guards;\n        type Action = Action;").unwrap();
    writeln!(out, "        fn step(state: State, event: Event, guards: &Guards) -> Result<Step, MissingGuard> {{ step(state, event, guards) }}").unwrap();
    writeln!(
        out,
        "        fn state_name(s: State) -> &'static str {{ s.as_str() }}"
    )
    .unwrap();
    writeln!(
        out,
        "        fn state_from_name(s: &str) -> Option<State> {{ State::from_name(s) }}"
    )
    .unwrap();
    writeln!(
        out,
        "        fn event_name(e: Event) -> &'static str {{ e.as_str() }}"
    )
    .unwrap();
    writeln!(
        out,
        "        fn is_terminal(s: State) -> bool {{ s.is_terminal() }}"
    )
    .unwrap();
    writeln!(
        out,
        "        fn render_action(a: Action) -> String {{ a.render() }}"
    )
    .unwrap();
    writeln!(out, "    }}\n}}").unwrap();
}

fn actions_lit(r: &Row) -> String {
    let items: Vec<String> = r
        .actions
        .iter()
        .map(|a| match (a.name.as_str(), &a.param) {
            ("set_abort_reason", Some(p)) => {
                format!("Action::SetAbortReason(AbortReason::{})", pascal(p))
            }
            ("set_reason", Some(p)) => format!("Action::SetReason({p:?})"),
            (n, _) => format!("Action::{}", pascal(n)),
        })
        .collect();
    format!("&[{}]", items.join(", "))
}
