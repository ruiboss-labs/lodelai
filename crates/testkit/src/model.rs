//! 상태 머신 yaml 의 serde 모델. 모르는 키는 무시한다(문서 쪽 주석·notes 가 늘어도 깨지지 않게).

use std::collections::BTreeMap;

use serde::Deserialize;

/// yaml 스칼라 가드 값. `true`/`false` 와 문자열을 같은 키 공간(`"true"`·`"false"`)으로 본다.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    Bool(bool),
    Str(String),
}

impl Scalar {
    pub fn key(&self) -> String {
        match self {
            Scalar::Bool(b) => b.to_string(),
            Scalar::Str(s) => s.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(x) => vec![x],
            OneOrMany::Many(v) => v,
        }
    }
}

/// 액션: 이름만 있거나 `{이름: 값}` 한 쌍.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Action {
    Name(String),
    WithArg(BTreeMap<String, Scalar>),
}

impl Action {
    /// `set_abort_reason=turn_ended` 처럼 한 문자열로 편다.
    pub fn render(&self) -> String {
        match self {
            Action::Name(n) => n.clone(),
            Action::WithArg(m) => m
                .iter()
                .map(|(k, v)| format!("{k}={}", v.key()))
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateDef {
    pub name: String,
    #[serde(default)]
    pub terminal: bool,
    /// `request_sender_view` 의 status 순서(rank 규칙).
    #[serde(default)]
    pub rank: Option<i64>,
}

/// yaml 한 줄(펼치기 전). 이벤트 키는 `on`(현행)과 `event`(#32 이후) 를 모두 받는다.
#[derive(Debug, Clone, Deserialize)]
pub struct RawRow {
    pub from: OneOrMany<String>,
    #[serde(default, alias = "event")]
    pub on: Option<OneOrMany<String>>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub guard: Option<BTreeMap<String, OneOrMany<Scalar>>>,
    #[serde(default)]
    pub actions: Vec<Action>,
    /// `rank` 이면 `event_target` 과 상태의 `rank` 로 전수 행을 만든다.
    #[serde(default)]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Property {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MachineDef {
    pub name: String,
    #[serde(default)]
    pub initial: Option<String>,
    pub states: Vec<StateDef>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub guard_inputs: BTreeMap<String, Vec<Scalar>>,
    #[serde(default)]
    pub transitions: Vec<RawRow>,
    #[serde(default)]
    pub event_target: BTreeMap<String, String>,
    #[serde(default)]
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Doc {
    pub version: u32,
    pub machines: Vec<MachineDef>,
}
