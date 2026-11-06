//! yaml 모델을 펼쳐(`from`·`on` 목록, `to: same`, rank 규칙) 참조 인터프리터로 쓴다.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::model::{Doc, MachineDef, Property, RawRow};

/// 가드 입력값. 키는 `guard_inputs` 이름, 값은 문자열(`true`/`false` 포함).
pub type Env = BTreeMap<String, String>;

/// 펼친 전이 행 하나: (출발 상태, 이벤트) 한 쌍과 가드 조건.
#[derive(Debug, Clone)]
pub struct Row {
    /// 머신 안의 순번(진단 메시지용).
    pub index: usize,
    pub from: String,
    pub event: String,
    pub to: String,
    /// `(키, 허용 값 목록)`. 모든 키가 맞아야 한다. 비어 있으면 항상 참.
    pub guard: Vec<(String, Vec<String>)>,
    pub actions: Vec<String>,
    /// rank 규칙으로 생성된 행인지.
    pub generated: bool,
}

impl Row {
    pub fn matches(&self, env: &Env) -> bool {
        self.guard
            .iter()
            .all(|(k, allowed)| env.get(k).is_some_and(|v| allowed.contains(v)))
    }

    pub fn guard_value(&self, key: &str) -> Option<&[String]> {
        self.guard
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// 가드 `key` 가 정확히 `values`(순서 무관) 를 허용하는가.
    pub fn guard_is(&self, key: &str, values: &[&str]) -> bool {
        self.guard_value(key).is_some_and(|v| {
            v.len() == values.len() && values.iter().all(|x| v.iter().any(|y| y == x))
        })
    }

    pub fn has_action(&self, name: &str) -> bool {
        self.actions.iter().any(|a| a == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Fired {
        row: usize,
        to: String,
        actions: Vec<String>,
    },
    /// 어떤 행도 맞지 않는다 → 문서 규칙상 "무시: 상태 불변 + 기록".
    NoRow,
    /// 둘 이상 맞는다 → yaml 결함(coverage 검사가 잡는다).
    Ambiguous(Vec<usize>),
}

#[derive(Debug, Clone)]
pub struct Machine {
    pub name: String,
    pub initial: Option<String>,
    pub states: Vec<String>,
    pub terminal: BTreeSet<String>,
    /// 머신이 선언한 이벤트(없으면 비어 있다).
    pub events: Vec<String>,
    pub guard_inputs: BTreeMap<String, Vec<String>>,
    pub rows: Vec<Row>,
    pub properties: Vec<Property>,
}

impl Machine {
    pub fn rows_for(&self, state: &str, event: &str) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| r.from == state && r.event == event)
            .collect()
    }

    /// 선언된 이벤트와 행에서 쓰인 이벤트의 합집합(정렬).
    pub fn all_events(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = self.events.iter().cloned().collect();
        set.extend(self.rows.iter().map(|r| r.event.clone()));
        set.into_iter().collect()
    }

    pub fn is_terminal(&self, state: &str) -> bool {
        self.terminal.contains(state)
    }

    pub fn step(&self, state: &str, event: &str, env: &Env) -> Outcome {
        let hits: Vec<&Row> = self
            .rows_for(state, event)
            .into_iter()
            .filter(|r| r.matches(env))
            .collect();
        match hits.as_slice() {
            [] => Outcome::NoRow,
            [one] => Outcome::Fired {
                row: one.index,
                to: one.to.clone(),
                actions: one.actions.clone(),
            },
            many => Outcome::Ambiguous(many.iter().map(|r| r.index).collect()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Machines {
    pub version: u32,
    pub machines: Vec<Machine>,
}

impl Machines {
    /// # Errors
    /// 파일 읽기·yaml 파싱·펼치기 실패.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text)
    }

    /// # Errors
    /// yaml 이 모델과 맞지 않거나 rank 규칙이 깨졌을 때.
    pub fn parse(text: &str) -> Result<Self, String> {
        let doc: Doc = serde_yaml_ng::from_str(text).map_err(|e| format!("yaml: {e}"))?;
        let machines = doc
            .machines
            .into_iter()
            .map(compile)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: doc.version,
            machines,
        })
    }

    /// 다른 yaml 의 머신을 뒤에 붙인다(선 yaml + 앱 yaml 을 한 묶음으로 시험할 때, #559). 같은 이름이 있으면 오류.
    ///
    /// # Errors
    /// 판(version)이 다르거나 머신 이름이 겹칠 때.
    pub fn merge(mut self, other: Self) -> Result<Self, String> {
        if self.version != other.version {
            return Err(format!(
                "yaml 판이 다르다: {} ≠ {}",
                self.version, other.version
            ));
        }
        for m in other.machines {
            if self.get(&m.name).is_some() {
                return Err(format!("머신 `{}` 이 두 yaml 에 다 있다", m.name));
            }
            self.machines.push(m);
        }
        Ok(self)
    }

    pub fn get(&self, name: &str) -> Option<&Machine> {
        self.machines.iter().find(|m| m.name == name)
    }

    /// 이름으로 찾되 없으면 패닉(시험 코드용).
    ///
    /// # Panics
    /// 그 이름의 머신이 없을 때.
    pub fn must(&self, name: &str) -> &Machine {
        self.get(name)
            .unwrap_or_else(|| panic!("읽은 yaml 에 머신 `{name}` 이 없다"))
    }
}

fn compile(def: MachineDef) -> Result<Machine, String> {
    let states: Vec<String> = def.states.iter().map(|s| s.name.clone()).collect();
    let ranks: BTreeMap<&str, i64> = def
        .states
        .iter()
        .filter_map(|s| s.rank.map(|r| (s.name.as_str(), r)))
        .collect();
    let mut rows = Vec::new();
    for raw in &def.transitions {
        expand(&def, &ranks, raw, &mut rows)?;
    }
    for (i, r) in rows.iter_mut().enumerate() {
        r.index = i;
    }
    Ok(Machine {
        initial: def.initial,
        terminal: def
            .states
            .iter()
            .filter(|s| s.terminal)
            .map(|s| s.name.clone())
            .collect(),
        events: def.events,
        guard_inputs: def
            .guard_inputs
            .into_iter()
            .map(|(k, v)| (k, v.iter().map(crate::model::Scalar::key).collect()))
            .collect(),
        rows,
        properties: def.properties,
        states,
        name: def.name,
    })
}

fn expand(
    def: &MachineDef,
    ranks: &BTreeMap<&str, i64>,
    raw: &RawRow,
    out: &mut Vec<Row>,
) -> Result<(), String> {
    let froms = raw.from.clone().into_vec();
    let events = raw
        .on
        .clone()
        .ok_or_else(|| format!("{}: 이벤트 키(on/event) 가 없는 행", def.name))?
        .into_vec();
    let guard: Vec<(String, Vec<String>)> = raw
        .guard
        .as_ref()
        .map(|g| {
            g.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.clone()
                            .into_vec()
                            .iter()
                            .map(crate::model::Scalar::key)
                            .collect(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let actions: Vec<String> = raw
        .actions
        .iter()
        .map(crate::model::Action::render)
        .collect();
    for from in &froms {
        for event in &events {
            let (to, acts, generated) =
                match raw.rule.as_deref() {
                    Some("rank") => {
                        let target = def.event_target.get(event).ok_or_else(|| {
                            format!("{}: event_target 에 `{event}` 없음", def.name)
                        })?;
                        let rank_of = |s: &str| {
                            ranks
                                .get(s)
                                .copied()
                                .ok_or_else(|| format!("{}: 상태 `{s}` 에 rank 없음", def.name))
                        };
                        if rank_of(target)? > rank_of(from)? {
                            (target.clone(), Vec::new(), true)
                        } else {
                            (from.clone(), vec!["log_ignored".to_string()], true)
                        }
                    }
                    Some(other) => return Err(format!("{}: 알 수 없는 rule `{other}`", def.name)),
                    None => {
                        let to = raw.to.clone().ok_or_else(|| {
                            format!("{}: `to` 없는 행 ({from} / {event})", def.name)
                        })?;
                        let to = if to == "same" { from.clone() } else { to };
                        (to, actions.clone(), false)
                    }
                };
            out.push(Row {
                index: 0,
                from: from.clone(),
                event: event.clone(),
                to,
                guard: guard.clone(),
                actions: acts,
                generated,
            });
        }
    }
    Ok(())
}
