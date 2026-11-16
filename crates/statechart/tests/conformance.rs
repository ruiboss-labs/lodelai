//! 생성된 `step()` 을 독립 오라클(`lodelai-testkit` 의 참조 인터프리터)과 전수 대조하고,
//! 성질(P2·rank·AC-AR-8)을 **이 구현의 결과**에 대해 확인한다. 선 머신 셋만 — 앱 머신(chat·remote_turn)의 같은 시험은
//! 앱 머신 크레이트에 있다(#559).

use lodelai_statechart::{request_recipient, request_sender_view, Step};
use lodelai_testkit::conformance::{exhaustive_cases, run, Implementation, StepResult};
use lodelai_testkit::machine::Env;

/// 문자열 경계 어댑터: 이름 → 생성 타입 → step → 문자열.
struct Generated;

macro_rules! dispatch {
    ($m:ident, $state:expr, $event:expr, $env:expr) => {{
        let s = $m::State::from_name($state)
            .unwrap_or_else(|| panic!("{}: 모르는 상태 {}", $m::NAME, $state));
        let e = $m::Event::from_name($event)
            .unwrap_or_else(|| panic!("{}: 모르는 이벤트 {}", $m::NAME, $event));
        let mut g = $m::Guards::default();
        for (k, v) in $env {
            assert!(g.set_by_name(k, v), "{}: 가드 {k}={v} 를 못 넣음", $m::NAME);
        }
        match $m::step(s, e, &g).unwrap_or_else(|err| panic!("{err}")) {
            Step::Transition { to, actions } => Some((
                to.as_str().to_string(),
                actions.iter().map(|a| a.render()).collect(),
            )),
            Step::Ignored => None,
        }
    }};
}

impl Implementation for Generated {
    fn step(&mut self, machine: &str, state: &str, event: &str, env: &Env) -> StepResult {
        use lodelai_statechart::envelope_server;
        match machine {
            "request_recipient" => dispatch!(request_recipient, state, event, env),
            "request_sender_view" => dispatch!(request_sender_view, state, event, env),
            "envelope_server" => dispatch!(envelope_server, state, event, env),
            other => panic!("모르는 머신 {other}"),
        }
    }
}

fn machines() -> lodelai_testkit::machine::Machines {
    lodelai_testkit::load_default().expect("yaml")
}

#[test]
fn 생성된_step_이_참조_인터프리터와_전수_일치() {
    let ms = machines();
    let total: usize = ms.machines.iter().map(|m| exhaustive_cases(m).len()).sum();
    let bad = run(&ms, &mut Generated);
    assert!(
        bad.is_empty(),
        "{}/{total} 건 불일치. 처음 5건:\n{:#?}",
        bad.len(),
        &bad[..bad.len().min(5)]
    );
    assert!(
        total > 300,
        "케이스가 너무 적다({total}) — 열거가 깨졌는지 확인"
    );
    assert_eq!(lodelai_statechart::MACHINES.len(), ms.machines.len());
}

/// 오라클 케이스를 돌려 이 구현의 결과를 모은다(성질 검사용).
fn outcomes(machine: &str) -> Vec<(String, String, Env, StepResult)> {
    let ms = machines();
    let m = ms.must(machine);
    exhaustive_cases(m)
        .into_iter()
        .map(|c| {
            let r = Generated.step(machine, &c.state, &c.event, &c.env);
            (c.state, c.event, c.env, r)
        })
        .collect()
}

#[test]
fn p2_clock_tick_은_어떤_상태도_바꾸지_않는다() {
    for m in lodelai_statechart::MACHINES {
        for (state, event, _, r) in outcomes(m) {
            if event == "clock_tick" {
                let (to, _) = r.unwrap_or_else(|| panic!("{m}: {state} 에 clock_tick 행이 없다"));
                assert_eq!(to, state, "{m}: clock_tick 이 {state} → {to}");
            }
        }
    }
}

#[test]
fn rank_규칙을_독립적으로_다시_계산해도_같다() {
    use request_sender_view::{Event, Guards, State};
    // yaml 의 event_target 을 여기서 손으로 적는다(생성 코드와 독립).
    let target = |e: Event| -> Option<State> {
        Some(match e {
            Event::ServerAck => State::Stored,
            Event::ServerDeviceReceived => State::Received,
            Event::StatusPending => State::Pending,
            Event::StatusAccepted => State::Accepted,
            Event::StatusFailed => State::Failed,
            Event::StatusConsumed => State::Consumed,
            Event::StatusReplied => State::Replied,
            Event::StatusRejected => State::Rejected,
            Event::StatusAborted => State::Aborted,
            Event::StatusDone => State::Done,
            Event::StatusExpired | Event::LocalExpired => State::Expired,
            // 다시 보내기(#447·#577)·거두기(묶음 14 #403)는 rank 규칙 밖 — 명시 행이다.
            Event::ServerNack
            | Event::ClockTick
            | Event::HumanRetry
            | Event::DeviceTrusted
            | Event::RecipientRejoined
            | Event::StatusWithdrawn => return None,
        })
    };
    // rank 행의 from(yaml 손으로) — aborted 는 비종료지만 rank 행 밖이다(#591, 아래 늦게 답함 시험).
    let ranked = |s: State| {
        matches!(
            s,
            State::Sent
                | State::Stored
                | State::Received
                | State::Pending
                | State::Accepted
                | State::Failed
                | State::Consumed
        )
    };
    for &s in State::ALL {
        for &e in Event::ALL {
            let Some(t) = target(e) else { continue };
            // aborted(#591)·done(#598 ②)의 늦은 답은 명시 행이다(아래 시험).
            if matches!(s, State::Aborted | State::Done) && e == Event::StatusReplied {
                continue;
            }
            let got = request_sender_view::step(s, e, &Guards::default()).unwrap();
            let expected_to = if ranked(s) && t.rank() > s.rank() {
                t
            } else {
                s
            };
            match got {
                Step::Transition { to, .. } => assert_eq!(to, expected_to, "{s:?} --{e:?}"),
                Step::Ignored => panic!("{s:?} --{e:?}: 행이 없다"),
            }
        }
    }
}

/// #598 ②: 답이 필요 없는 request 는 턴이 답 없이 끝나면 done(사람 알림 없음), 아니면 지금처럼 aborted(turn_ended).
/// 보낸 쪽 done 은 늦은 답(status_replied)으로만 replied, 받는 쪽 done 은 늦은 답을 보낸다.
#[test]
fn 답이_필요_없는_요청은_done_으로_끝나고_늦은_답은_받는다() {
    use request_recipient::{
        Action as A, Event as E, GuardRepliedBy as B, Guards as G, State as S,
    };
    let step = |s, e, g: &G| match request_recipient::step(s, e, g).unwrap() {
        Step::Transition { to, actions } => (to, actions),
        Step::Ignored => panic!("{s:?} --{e:?}: 행이 없다"),
    };
    let no_reply = |n| G {
        no_reply: Some(n),
        ..G::default()
    };
    let (to, actions) = step(S::Consumed, E::TurnEndedNoReply, &no_reply(true));
    assert_eq!(to, S::Done);
    assert!(
        !actions.iter().any(|a| matches!(a, A::NotifyOwner)),
        "{actions:?}"
    );
    assert_eq!(
        step(S::Consumed, E::TurnEndedNoReply, &no_reply(false)).0,
        S::Aborted
    );
    let agent = G {
        replied_by: Some(B::Agent),
        ..G::default()
    };
    let (to, actions) = step(S::Done, E::ToolReply, &agent);
    assert_eq!(to, S::Done);
    assert!(
        actions.iter().any(|a| matches!(a, A::SendLateReply)),
        "{actions:?}"
    );
    assert_eq!(step(S::Done, E::HumanReplyDirect, &G::default()).0, S::Done);

    use request_sender_view::{Event as SE, Guards as SG, State as SS};
    match request_sender_view::step(SS::Done, SE::StatusReplied, &SG::default()).unwrap() {
        Step::Transition { to, .. } => assert_eq!(to, SS::Replied),
        Step::Ignored => panic!("done --status_replied: 행이 없다"),
    }
    match request_sender_view::step(SS::Consumed, SE::StatusDone, &SG::default()).unwrap() {
        Step::Transition { to, .. } => assert_eq!(to, SS::Done),
        Step::Ignored => panic!("consumed --status_done: 행이 없다"),
    }
}

/// #591 늦게 답함: aborted 는 늦은 회신 사유(turn_ended·needs_task)의 status_replied 로만 replied — 다른 사유·사유 없음은 그대로.
#[test]
fn 중단된_요청은_늦은_회신_사유일_때만_replied_로_간다() {
    use request_sender_view::{Event, GuardAbortReason as R, Guards, State};
    for r in [
        R::TurnEnded,
        R::NeedsTask,
        R::OwnerAborted,
        R::SessionExited,
        R::ModeEscalated,
        R::DraftDiscarded,
        R::None,
    ] {
        let g = Guards {
            abort_reason: Some(r),
            ..Guards::default()
        };
        let got = request_sender_view::step(State::Aborted, Event::StatusReplied, &g).unwrap();
        let expected = if matches!(r, R::TurnEnded | R::NeedsTask) {
            State::Replied
        } else {
            State::Aborted
        };
        match got {
            Step::Transition { to, .. } => assert_eq!(to, expected, "{r:?}"),
            Step::Ignored => panic!("{r:?}: 행이 없다"),
        }
    }
    assert!(
        request_sender_view::step(State::Aborted, Event::StatusReplied, &Guards::default())
            .is_err(),
        "사유를 안 채우면 오류"
    );
}

#[test]
fn 거두기는_수락_전에만_withdrawn_으로_간다() {
    use request_sender_view::{Event, Guards, State};
    for &s in State::ALL {
        let got = request_sender_view::step(s, Event::StatusWithdrawn, &Guards::default()).unwrap();
        let expected = match s {
            State::Sent | State::Stored | State::Received | State::Pending => State::Withdrawn,
            other => other,
        };
        match got {
            Step::Transition { to, .. } => assert_eq!(to, expected, "{s:?}"),
            Step::Ignored => panic!("{s:?} --status_withdrawn: 행이 없다"),
        }
    }
    // withdrawn 은 종료 — 뒤늦은 accepted 로 나오지 않는다(먼저 온 것이 이김).
    let got =
        request_sender_view::step(State::Withdrawn, Event::StatusAccepted, &Guards::default())
            .unwrap();
    assert!(matches!(
        got,
        Step::Transition {
            to: State::Withdrawn,
            ..
        }
    ));
}

/// 옛 AC-AR-8(묶음 24 §1a 로 바뀜): accepted 로 가는 길은 pending 에서 사람의 수락 또는 코어의 `policy_accept` 뿐.
#[test]
fn ac_ar_8_사람의_수락과_policy_accept_외에_accepted_로_가는_경로가_없다() {
    for (state, event, env, r) in outcomes("request_recipient") {
        if let Some((to, _)) = r {
            if to == "accepted" && state != "accepted" {
                assert!(
                    state == "pending"
                        && matches!(
                            event.as_str(),
                            "human_accept" | "human_accept_draft" | "policy_accept"
                        ),
                    "{state} --{event} {env:?}--> accepted"
                );
            }
        }
    }
}

#[test]
fn 참조된_가드가_비면_무시가_아니라_오류() {
    use request_recipient::{Event, Guards, State};
    let err = request_recipient::step(State::Accepted, Event::SessionLiveIdle, &Guards::default())
        .unwrap_err();
    assert_eq!(err.key, "hooks_config_verified");
}

#[test]
fn 직렬화_이름은_yaml_이름_그대로() {
    assert_eq!(request_recipient::State::Injected.as_str(), "injected");
    assert_eq!(
        request_recipient::AbortReason::from_name("mode_escalated"),
        Some(request_recipient::AbortReason::ModeEscalated)
    );
    assert_eq!(
        request_recipient::State::Discarded.visible_to_sender(),
        Some(request_sender_view::State::Aborted)
    );
    assert_eq!(request_recipient::State::Held.visible_to_sender(), None);
    assert_eq!(
        request_recipient::State::Unreadable.visible_to_sender(),
        None
    );
    assert_eq!(
        request_recipient::INITIAL,
        request_recipient::State::Pending
    );
}
