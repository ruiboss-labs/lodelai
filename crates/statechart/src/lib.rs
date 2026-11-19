//! lodelai 선(wire) 상태 머신 — `machines/wire.yaml`(version 3) 에서 빌드 때 생성한다. 앱 머신(chat·remote_turn)은
//! 앱 쪽 크레이트가 [`gen::generate`](feature `gen`)로 같은 꼴을 만든다(#559).
//!
//! 머신마다 모듈 하나: `State`·`Event`·가드 입력(`Guards`)·`Action` enum 과 순수 함수 `step()`.
//! `step()` 은 I/O·시계가 없고 "어느 상태로, 어떤 액션을 순서대로" 만 돌려준다. 액션 실행과 "앞 액션이 실패하면
//! 전이하지 않는다" 는 규칙은 집행자(코어 U3·U8·U9, relay)의 몫이다. 일치하는 행이 없으면 `Step::Ignored` —
//! legend 의 "상태 불변 + 기록" 이므로 집행자가 기록한다.
//!
//! yaml 이 legend 규칙(가드 상호 배타, 종료 상태 탈출 금지, 모든 상태의 `clock_tick → same` 등)을 어기면
//! **빌드가 실패한다.** 차분 시험의 오라클은 이 크레이트와 독립 구현인 `lodelai-testkit` 이다.

#[cfg(any(test, feature = "model"))]
pub mod model;

/// yaml → 생성 코드. 다른 크레이트 build.rs 가 자기 머신을 만들 때 쓴다(build-dependency, feature `gen`).
#[cfg(feature = "gen")]
pub mod gen;

/// 전이 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<S, A: 'static> {
    /// `to` 로 간다(`to == 출발 상태` 이면 상태 불변 행). 액션은 순서대로.
    Transition { to: S, actions: &'static [A] },
    /// 일치하는 행 없음: 상태 불변 + 기록.
    Ignored,
}

/// 이번 (상태, 이벤트) 의 행이 참조하는 가드 입력이 비어 있다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingGuard {
    pub machine: &'static str,
    pub key: &'static str,
}

impl std::fmt::Display for MissingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 가드 입력 `{}` 가 없다", self.machine, self.key)
    }
}

impl std::error::Error for MissingGuard {}

/// 생성된 머신 모듈 공통 인터페이스. 저장소·집행자가 머신마다 따로 쓰지 않고 제네릭으로 다룬다.
pub trait StateMachine {
    const NAME: &'static str;
    const INITIAL: Self::State;
    type State: Copy + Eq + std::fmt::Debug + 'static;
    type Event: Copy + Eq + std::fmt::Debug;
    type Guards: std::fmt::Debug + serde::Serialize;
    type Action: Copy + Eq + std::fmt::Debug + 'static;

    /// # Errors
    /// 참조된 가드 입력이 비면 [`MissingGuard`].
    fn step(
        state: Self::State,
        event: Self::Event,
        guards: &Self::Guards,
    ) -> Result<Step<Self::State, Self::Action>, MissingGuard>;
    fn state_name(s: Self::State) -> &'static str;
    fn state_from_name(s: &str) -> Option<Self::State>;
    fn event_name(e: Self::Event) -> &'static str;
    fn is_terminal(s: Self::State) -> bool;
    fn render_action(a: Self::Action) -> String;
}

include!(concat!(env!("OUT_DIR"), "/machines.rs"));

#[cfg(test)]
mod model_tests {
    //! 검증이 실제로 빌드를 막는지: 진짜 yaml 을 한 군데씩 망가뜨려 본다.
    use super::model::load;

    const YAML: &str = include_str!("../machines/wire.yaml");

    fn broken(from: &str, to: &str) -> String {
        assert!(
            YAML.contains(from),
            "시험 전제: yaml 에 `{from}` 가 있어야 한다"
        );
        YAML.replacen(from, to, 1)
    }

    fn expect_err(yaml: &str, needle: &str) {
        let e = load(yaml).expect_err("검증이 통과하면 안 된다");
        assert!(
            e.0.contains(needle),
            "오류 메시지에 `{needle}` 가 없다: {e}"
        );
    }

    #[test]
    fn 실제_yaml_은_통과() {
        let spec = load(YAML).unwrap();
        assert_eq!(spec.machines.len(), 3);
    }

    #[test]
    fn 가드_겹침() {
        // injected 의 tool_reply 한 행에서 가드를 빼면 같은 (상태, 이벤트) 의 draft_mode: true 행과 겹친다.
        let y = broken(
            "{from: injected, event: tool_reply, guard: {draft_mode: false}, to: replied",
            "{from: injected, event: tool_reply, to: replied",
        );
        expect_err(&y, "가드 없는 행과 다른 행");
    }

    #[test]
    fn 가드_값이_서로_겹침() {
        let y = broken(
            "{from: injected, event: tool_reply, guard: {draft_mode: false}, to: replied",
            "{from: injected, event: tool_reply, guard: {draft_mode: [true, false]}, to: replied",
        );
        expect_err(&y, "상호 배타 위반");
    }

    #[test]
    fn 종료_상태_탈출() {
        let y = broken(
            "{from: replied,  event: tool_reply, guard: {replied_by: [agent]}, to: same,",
            "{from: replied,  event: tool_reply, guard: {replied_by: [agent]}, to: pending,",
        );
        expect_err(&y, "종료 상태 `replied`");
    }

    #[test]
    fn 선언_안_된_이벤트() {
        let y = broken(
            "{from: pending,  event: human_accept,",
            "{from: pending,  event: human_acept,",
        );
        expect_err(&y, "human_acept");
    }

    #[test]
    fn on_키_금지() {
        let y = broken(
            "{from: pending,  event: human_accept,",
            "{from: pending,  on: human_accept,",
        );
        expect_err(&y, "event:");
    }

    #[test]
    fn 도메인_밖_가드_값() {
        let y = broken(
            "{from: injected, event: tool_reply, guard: {draft_mode: false}, to: replied",
            "{from: injected, event: tool_reply, guard: {draft_mode: maybe}, to: replied",
        );
        expect_err(&y, "도메인");
    }

    #[test]
    fn clock_tick_빠짐() {
        let y = broken(
            "      - {from: [stored, device_received, expired], event: clock_tick, to: same}",
            "      - {from: [stored, device_received], event: clock_tick, to: same}",
        );
        expect_err(&y, "clock_tick");
    }

    #[test]
    fn 버전_확인() {
        let y = broken("version: 3", "version: 2");
        expect_err(&y, "version 3");
    }
}
