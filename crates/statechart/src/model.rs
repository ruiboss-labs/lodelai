//! 상태 머신 yaml(version 3) 모델: 파싱 → 검증 → 행 펼치기 → 전수 케이스 열거.
//!
//! 이 파일 하나를 `build.rs`(코드 생성)와 라이브러리(`model` feature, 시험)가 같이 쓴다. 파서가 둘이면 모델이 어긋난다.
//! 규칙의 원천은 yaml 의 `legend`. 검증 실패는 빌드 실패다.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_yaml_ng::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError(pub String);

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ModelError {}

type Result<T> = std::result::Result<T, ModelError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ModelError(msg.into()))
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub version: i64,
    pub machines: Vec<Machine>,
}

#[derive(Debug, Clone)]
pub struct StateDef {
    pub name: String,
    pub terminal: bool,
    pub rank: Option<i64>,
    pub visible_to_sender: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDef {
    pub name: String,
    pub param: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Same,
    State(String),
}

/// yaml 의 transitions 한 항목(펼치기 전).
#[derive(Debug, Clone)]
pub struct RowDef {
    /// transitions 안의 순번(0부터). 에러 메시지에 쓴다.
    pub index: usize,
    pub from: Vec<String>,
    pub events: Vec<String>,
    /// 키 → 허용 값 목록(정규화된 문자열).
    pub guard: BTreeMap<String, Vec<String>>,
    pub to: Option<Target>,
    pub actions: Vec<ActionDef>,
    pub rule_rank: bool,
}

#[derive(Debug, Clone)]
pub struct Machine {
    pub name: String,
    pub initial: String,
    pub states: Vec<StateDef>,
    pub events: Vec<String>,
    /// 선언 순서를 지킨다(생성 코드의 필드 순서).
    pub guard_inputs: Vec<(String, Vec<String>)>,
    pub abort_reasons: Vec<String>,
    pub event_target: Vec<(String, String)>,
    pub rows: Vec<RowDef>,
}

/// 펼친 행: 출발 상태·이벤트가 하나이고 to 가 해소됐다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub src: usize,
    pub from: String,
    pub event: String,
    pub guard: BTreeMap<String, Vec<String>>,
    pub to: String,
    pub actions: Vec<ActionDef>,
}

/// 전수 케이스 한 점.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub from: String,
    pub event: String,
    /// 이 (상태, 이벤트) 의 행들이 참조한 가드 키만, 값 하나씩.
    pub guards: BTreeMap<String, String>,
    pub expected: Expected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    Transition {
        to: String,
        actions: Vec<ActionDef>,
    },
    /// 일치하는 행 없음: legend 의 기본 무시(상태 불변 + 기록).
    Ignored,
}

// ---------------------------------------------------------------- 파싱

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn str_list(v: &Value, what: &str) -> Result<Vec<String>> {
    match v {
        Value::Sequence(items) => items
            .iter()
            .map(|i| {
                scalar(i).ok_or_else(|| ModelError(format!("{what}: 스칼라가 아닌 항목 {i:?}")))
            })
            .collect(),
        other => scalar(other)
            .map(|s| vec![s])
            .ok_or_else(|| ModelError(format!("{what}: 문자열 또는 목록이어야 함"))),
    }
}

fn get<'a>(m: &'a Value, key: &str) -> Option<&'a Value> {
    m.as_mapping().and_then(|mm| mm.get(key))
}

fn req<'a>(m: &'a Value, key: &str, ctx: &str) -> Result<&'a Value> {
    get(m, key).ok_or_else(|| ModelError(format!("{ctx}: `{key}` 없음")))
}

fn req_str(m: &Value, key: &str, ctx: &str) -> Result<String> {
    scalar(req(m, key, ctx)?)
        .ok_or_else(|| ModelError(format!("{ctx}: `{key}` 는 문자열이어야 함")))
}

fn parse_action(v: &Value, ctx: &str) -> Result<ActionDef> {
    match v {
        Value::String(s) => Ok(ActionDef {
            name: s.clone(),
            param: None,
        }),
        Value::Mapping(m) if m.len() == 1 => {
            let (k, val) = m.iter().next().expect("len 1");
            let name =
                scalar(k).ok_or_else(|| ModelError(format!("{ctx}: 액션 이름이 문자열이 아님")))?;
            let param = scalar(val).ok_or_else(|| {
                ModelError(format!("{ctx}: 액션 `{name}` 의 인자가 스칼라가 아님"))
            })?;
            Ok(ActionDef {
                name,
                param: Some(param),
            })
        }
        other => err(format!("{ctx}: 액션 형식이 이상함 {other:?}")),
    }
}

fn parse_row(v: &Value, index: usize, machine: &str) -> Result<RowDef> {
    let ctx = format!("{machine}.transitions[{index}]");
    if get(v, "on").is_some()
        || v.as_mapping()
            .is_some_and(|m| m.contains_key(Value::Bool(true)))
    {
        return err(format!(
            "{ctx}: 이벤트 키는 `event:` 다(`on:` 금지 — YAML 1.1 에서 불리언)"
        ));
    }
    let rule_rank = match get(v, "rule") {
        None => false,
        Some(r) if scalar(r).as_deref() == Some("rank") => true,
        Some(r) => return err(format!("{ctx}: 모르는 rule {r:?}")),
    };
    let from = str_list(req(v, "from", &ctx)?, &format!("{ctx}.from"))?;
    let events = str_list(req(v, "event", &ctx)?, &format!("{ctx}.event"))?;
    let mut guard = BTreeMap::new();
    if let Some(g) = get(v, "guard") {
        let gm = g
            .as_mapping()
            .ok_or_else(|| ModelError(format!("{ctx}.guard: 매핑이어야 함")))?;
        for (k, val) in gm {
            let key =
                scalar(k).ok_or_else(|| ModelError(format!("{ctx}.guard: 키가 문자열이 아님")))?;
            guard.insert(key.clone(), str_list(val, &format!("{ctx}.guard.{key}"))?);
        }
    }
    let to = match get(v, "to") {
        None => None,
        Some(t) => {
            let s = scalar(t).ok_or_else(|| ModelError(format!("{ctx}.to: 문자열이어야 함")))?;
            Some(if s == "same" {
                Target::Same
            } else {
                Target::State(s)
            })
        }
    };
    if !rule_rank && to.is_none() {
        return err(format!("{ctx}: `to` 없음"));
    }
    let actions = match get(v, "actions") {
        None => Vec::new(),
        Some(Value::Sequence(items)) => items
            .iter()
            .map(|a| parse_action(a, &format!("{ctx}.actions")))
            .collect::<Result<_>>()?,
        Some(_) => return err(format!("{ctx}.actions: 목록이어야 함")),
    };
    Ok(RowDef {
        index,
        from,
        events,
        guard,
        to,
        actions,
        rule_rank,
    })
}

fn parse_machine(v: &Value) -> Result<Machine> {
    let name = req_str(v, "name", "machines[]")?;
    let ctx = name.clone();
    let initial = req_str(v, "initial", &ctx)?;
    let states = match req(v, "states", &ctx)? {
        Value::Sequence(items) => items
            .iter()
            .map(|s| {
                Ok(StateDef {
                    name: req_str(s, "name", &format!("{ctx}.states"))?,
                    terminal: get(s, "terminal").and_then(Value::as_bool).unwrap_or(false),
                    rank: get(s, "rank").and_then(Value::as_i64),
                    visible_to_sender: get(s, "visible_to_sender").and_then(scalar),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return err(format!("{ctx}.states: 목록이어야 함")),
    };
    let events = str_list(req(v, "events", &ctx)?, &format!("{ctx}.events"))?;
    let mut guard_inputs = Vec::new();
    if let Some(g) = get(v, "guard_inputs") {
        for (k, val) in g
            .as_mapping()
            .ok_or_else(|| ModelError(format!("{ctx}.guard_inputs: 매핑이어야 함")))?
        {
            let key = scalar(k)
                .ok_or_else(|| ModelError(format!("{ctx}.guard_inputs: 키가 문자열이 아님")))?;
            guard_inputs.push((
                key.clone(),
                str_list(val, &format!("{ctx}.guard_inputs.{key}"))?,
            ));
        }
    }
    let abort_reasons = match get(v, "abort_reasons") {
        Some(a) => str_list(a, &format!("{ctx}.abort_reasons"))?,
        None => Vec::new(),
    };
    let mut event_target = Vec::new();
    if let Some(t) = get(v, "event_target") {
        for (k, val) in t
            .as_mapping()
            .ok_or_else(|| ModelError(format!("{ctx}.event_target: 매핑이어야 함")))?
        {
            event_target.push((
                scalar(k).ok_or_else(|| ModelError(format!("{ctx}.event_target: 키")))?,
                scalar(val).ok_or_else(|| ModelError(format!("{ctx}.event_target: 값")))?,
            ));
        }
    }
    let rows = match req(v, "transitions", &ctx)? {
        Value::Sequence(items) => items
            .iter()
            .enumerate()
            .map(|(i, r)| parse_row(r, i, &name))
            .collect::<Result<Vec<_>>>()?,
        _ => return err(format!("{ctx}.transitions: 목록이어야 함")),
    };
    Ok(Machine {
        name,
        initial,
        states,
        events,
        guard_inputs,
        abort_reasons,
        event_target,
        rows,
    })
}

/// yaml 문자열을 읽어 검증까지 끝낸 모델을 돌려준다.
///
/// # Errors
/// 형식이 틀리거나 `legend` 규칙을 어기면 오류.
pub fn load(yaml: &str) -> Result<Spec> {
    let doc: Value =
        serde_yaml_ng::from_str(yaml).map_err(|e| ModelError(format!("YAML 파싱 실패: {e}")))?;
    let version = get(&doc, "version").and_then(Value::as_i64).unwrap_or(0);
    if version != 3 {
        return err(format!(
            "상태 머신 yaml version {version} — 이 생성기는 version 3 만 읽는다"
        ));
    }
    let machines = match req(&doc, "machines", "최상위")? {
        Value::Sequence(items) => items
            .iter()
            .map(parse_machine)
            .collect::<Result<Vec<_>>>()?,
        _ => return err("machines: 목록이어야 함"),
    };
    let spec = Spec { version, machines };
    validate(&spec)?;
    Ok(spec)
}

// ---------------------------------------------------------------- 펼치기

impl Machine {
    pub fn state(&self, name: &str) -> Option<&StateDef> {
        self.states.iter().find(|s| s.name == name)
    }

    pub fn domain(&self, key: &str) -> Option<&[String]> {
        self.guard_inputs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// `from: [..]`·`event: [..]` 를 펼치고 `to: same` 을 해소하고 `rule: rank` 를 명시 행으로 바꾼다.
    ///
    /// # Errors
    /// rank 규칙에 필요한 rank·event_target 이 없으면 오류.
    pub fn expand(&self) -> Result<Vec<Row>> {
        let mut out = Vec::new();
        for r in &self.rows {
            for from in &r.from {
                for event in &r.events {
                    let (to, actions) = if r.rule_rank {
                        let target = self
                            .event_target
                            .iter()
                            .find(|(e, _)| e == event)
                            .map(|(_, t)| t.clone())
                            .ok_or_else(|| {
                                ModelError(format!(
                                    "{}.transitions[{}]: event_target 에 `{event}` 없음",
                                    self.name, r.index
                                ))
                            })?;
                        let rank = |s: &str| {
                            self.state(s).and_then(|d| d.rank).ok_or_else(|| {
                                ModelError(format!("{}: 상태 `{s}` 에 rank 없음", self.name))
                            })
                        };
                        if rank(&target)? > rank(from)? {
                            (target, Vec::new())
                        } else {
                            (
                                from.clone(),
                                vec![ActionDef {
                                    name: "log_ignored".into(),
                                    param: None,
                                }],
                            )
                        }
                    } else {
                        let to = match r.to.as_ref().expect("검증됨") {
                            Target::Same => from.clone(),
                            Target::State(s) => s.clone(),
                        };
                        (to, r.actions.clone())
                    };
                    out.push(Row {
                        src: r.index,
                        from: from.clone(),
                        event: event.clone(),
                        guard: r.guard.clone(),
                        to,
                        actions,
                    });
                }
            }
        }
        Ok(out)
    }

    /// (상태, 이벤트) 마다 그 행들이 참조한 가드 키의 곱집합을 펼친 전수 케이스(U13a).
    /// 참조 키만 펼치므로 remote_turn 도 수백 개 수준이다.
    ///
    /// # Errors
    /// 펼치기 실패 또는 가드 겹침.
    pub fn cases(&self) -> Result<Vec<Case>> {
        let rows = self.expand()?;
        let mut out = Vec::new();
        for s in &self.states {
            for e in &self.events {
                let group: Vec<&Row> = rows
                    .iter()
                    .filter(|r| r.from == s.name && &r.event == e)
                    .collect();
                let keys: BTreeSet<&String> = group.iter().flat_map(|r| r.guard.keys()).collect();
                for assignment in self.assignments(&keys) {
                    let hits: Vec<&&Row> =
                        group.iter().filter(|r| matches(r, &assignment)).collect();
                    let expected = match hits.as_slice() {
                        [] => Expected::Ignored,
                        [r] => Expected::Transition {
                            to: r.to.clone(),
                            actions: r.actions.clone(),
                        },
                        many => {
                            return err(format!(
                                "{}: ({}, {}) 가드 {:?} 에 행 {:?} 가 동시에 일치(상호 배타 위반)",
                                self.name,
                                s.name,
                                e,
                                assignment,
                                many.iter().map(|r| r.src).collect::<Vec<_>>()
                            ))
                        }
                    };
                    out.push(Case {
                        from: s.name.clone(),
                        event: e.clone(),
                        guards: assignment,
                        expected,
                    });
                }
            }
        }
        Ok(out)
    }

    fn assignments(&self, keys: &BTreeSet<&String>) -> Vec<BTreeMap<String, String>> {
        let mut acc = vec![BTreeMap::new()];
        for k in keys {
            let domain = self.domain(k).unwrap_or(&[]);
            acc = acc
                .into_iter()
                .flat_map(|a| {
                    domain.iter().map(move |v| {
                        let mut b = a.clone();
                        b.insert((*k).clone(), v.clone());
                        b
                    })
                })
                .collect();
        }
        acc
    }
}

fn matches(r: &Row, assignment: &BTreeMap<String, String>) -> bool {
    r.guard
        .iter()
        .all(|(k, allowed)| assignment.get(k).is_some_and(|v| allowed.contains(v)))
}

// ---------------------------------------------------------------- 검증

fn validate(spec: &Spec) -> Result<()> {
    let mut names = BTreeSet::new();
    for m in &spec.machines {
        if !names.insert(&m.name) {
            return err(format!("머신 이름 중복 `{}`", m.name));
        }
        validate_machine(m)?;
    }
    Ok(())
}

fn validate_machine(m: &Machine) -> Result<()> {
    let n = &m.name;
    let mut seen = BTreeSet::new();
    for s in &m.states {
        if !seen.insert(&s.name) {
            return err(format!("{n}: 상태 이름 중복 `{}`", s.name));
        }
        if s.name == "same" {
            return err(format!("{n}: `same` 은 상태 이름으로 쓸 수 없다"));
        }
    }
    if m.state(&m.initial).is_none() {
        return err(format!(
            "{n}: initial `{}` 이 선언된 상태가 아님",
            m.initial
        ));
    }
    let mut ev = BTreeSet::new();
    for e in &m.events {
        if !ev.insert(e) {
            return err(format!("{n}: 이벤트 중복 `{e}`"));
        }
    }
    for (e, t) in &m.event_target {
        if !ev.contains(e) {
            return err(format!("{n}.event_target: `{e}` 는 events 에 없다"));
        }
        if m.state(t).is_none() {
            return err(format!("{n}.event_target: `{t}` 는 선언된 상태가 아님"));
        }
    }
    for r in &m.rows {
        let ctx = format!("{n}.transitions[{}]", r.index);
        for f in &r.from {
            if m.state(f).is_none() {
                return err(format!("{ctx}: from `{f}` 은 선언된 상태가 아님"));
            }
        }
        for e in &r.events {
            if !ev.contains(e) {
                return err(format!("{ctx}: event `{e}` 는 events 에 없다"));
            }
        }
        if let Some(Target::State(t)) = &r.to {
            if m.state(t).is_none() {
                return err(format!("{ctx}: to `{t}` 은 선언된 상태가 아님"));
            }
        }
        for (k, vals) in &r.guard {
            let domain = m.domain(k).ok_or_else(|| {
                ModelError(format!("{ctx}: 가드 키 `{k}` 는 guard_inputs 에 없다"))
            })?;
            for v in vals {
                if !domain.contains(v) {
                    return err(format!(
                        "{ctx}: 가드 `{k}` 의 값 `{v}` 는 도메인 {domain:?} 밖"
                    ));
                }
            }
        }
        for a in &r.actions {
            match (a.name.as_str(), &a.param) {
                ("set_abort_reason", Some(p)) if !m.abort_reasons.contains(p) => {
                    return err(format!(
                        "{ctx}: set_abort_reason `{p}` 는 abort_reasons 에 없다"
                    ));
                }
                ("set_abort_reason" | "set_reason", None) => {
                    return err(format!("{ctx}: `{}` 는 인자가 필요하다", a.name));
                }
                (other, Some(_)) if other != "set_abort_reason" && other != "set_reason" => {
                    return err(format!("{ctx}: 액션 `{other}` 는 인자를 받지 않는다"));
                }
                _ => {}
            }
        }
    }

    let rows = m.expand()?;
    for r in &rows {
        let from = m.state(&r.from).expect("검증됨");
        if from.terminal && r.to != r.from {
            return err(format!(
                "{n}.transitions[{}]: 종료 상태 `{}` 에서 `{}` 로 나간다(종료 상태 예외는 상태 불변만)",
                r.src, r.from, r.to
            ));
        }
    }
    // 가드 없는 행이 있는 (상태, 이벤트) 에 다른 행이 있으면 안 된다 — 아래 겹침 검사가 잡지만 메시지를 분명히 한다.
    let mut groups: BTreeMap<(&str, &str), Vec<&Row>> = BTreeMap::new();
    for r in &rows {
        groups.entry((&r.from, &r.event)).or_default().push(r);
    }
    for ((s, e), g) in &groups {
        if g.len() > 1 && g.iter().any(|r| r.guard.is_empty()) {
            return err(format!(
                "{n}: ({s}, {e}) 에 가드 없는 행과 다른 행이 같이 있다 {:?}",
                g.iter().map(|r| r.src).collect::<Vec<_>>()
            ));
        }
    }
    m.cases()?; // 가드 상호 배타(겹치면 오류)
    if ev.contains(&"clock_tick".to_string()) {
        for s in &m.states {
            let ok = rows.iter().any(|r| {
                r.from == s.name && r.event == "clock_tick" && r.to == s.name && r.guard.is_empty()
            });
            if !ok {
                return err(format!(
                    "{n}: 상태 `{}` 에 clock_tick → same 행이 없다(P2)",
                    s.name
                ));
            }
        }
    }
    Ok(())
}
