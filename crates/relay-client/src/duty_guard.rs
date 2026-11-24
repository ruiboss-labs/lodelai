//! #1517 relay 가 시킨 `remove_device` 를 Commit 으로 만들기 전의 확인 — 그 잎이 **이번 접속에서 받은** 디렉터리로 산 기기가
//! 아닐 때만 뺀다. 받는 쪽은 산 기기 잎의 Remove 를 멈추므로(`mls_rules` `remove_live`), 만드는 쪽이 같은 것을 안 보면 relay 가
//! 시킨 Commit 하나로 그 대화의 다른 기기가 다 멈춘다.
//!
//! 차례(판정 7056412984): 디렉터리를 이번 접속에서 못 받았으면 기다린다(「모름」을 「아님」으로 읽지 않는다) → 받았고 산
//! 기기가 아니면 Commit → 산 기기로 보이면 `directory.list` 를 묻고 물러선다 → **그 물음 뒤에 온 답**에서도 산 기기면 행을
//! 버린다(감사 줄, 같은 일에 한 번). 붙어 있는데 답이 안 오면 [`GIVE_UP`] 뒤에 버린다 — 쥐고 있으면 그 대화의 뒤 행이 다 막힌다.
//! 버린 일은 relay 에 남아 있고(`mls_duties`), relay 는 다시 붙은 후보에게 다시 준다 — 「이번엔 안 함」이다. 붙어 있는 동안은
//! 다시 주지 않는다(주기 틱은 처음 받는 후보에게만) — 다른 접속 후보는 처음 나눌 때 이미 같이 받았다.
//!
//! 여기는 순수한 판정만(시험하기 쉽게). 디렉터리 보기·보내기·행 지우기는 `conn`.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::time::Instant;

/// 붙어 있는데 디렉터리 답이 안 올 때 행을 쥐는 상한.
pub(crate) const GIVE_UP: Duration = Duration::from_secs(120);

/// 버리는 까닭.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refused {
    /// 물은 뒤 온 디렉터리 답에서도 산 기기다.
    Live,
    /// 디렉터리 답이 오지 않아 확인하지 못했다.
    NoAnswer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// 산 기기가 아니다 — Remove Commit 을 만든다.
    Commit,
    /// `directory.list` 를 묻고 물러선다.
    Ask,
    /// 답을 기다리며 물러선다.
    Wait,
    /// 행을 버린다.
    Drop(Refused),
}

struct Row {
    seq: i64,
    since: Instant,
    /// 물었을 때의 [`Guard::answers`] — 그보다 커지면 물은 뒤에 답이 온 것. 아직 안 물었으면 `None`.
    asked: Option<u64>,
}

/// (그룹 헤더, 대상 기기).
type Key = (String, String);

#[derive(Default)]
pub struct Guard {
    /// 이번 접속에서 받은 디렉터리 프레임 수.
    got: u64,
    /// 그중 `directory`(`directory.list` 의 답 — 방송 `directory.update` 는 세지 않는다).
    answers: u64,
    /// 확인을 기다리는 행. 접속마다 비운다(셈과 수명이 같아야 한다).
    rows: HashMap<Key, Row>,
    /// 감사 줄을 낸 (일, 까닭) — 접속을 넘겨 남긴다(거짓말하는 relay 는 붙을 때마다 같은 일을 준다). 까닭마다 따로: 「답 없음」이
    /// 먼저 나갔다고 「산 기기」 줄이 묻히지 않게.
    audited: HashSet<(Key, Refused)>,
}

impl Guard {
    /// 새 접속 — 셈과 기다리던 행을 비운다.
    pub(crate) fn connected(&mut self) {
        self.got = 0;
        self.answers = 0;
        self.rows.clear();
    }

    /// 디렉터리 프레임을 받아 저장했다. 다시 볼 행의 seq 들.
    pub(crate) fn directory(&mut self, answer: bool) -> Vec<i64> {
        self.got += 1;
        if answer {
            self.answers += 1;
        }
        self.rows.values().map(|r| r.seq).collect()
    }

    /// 그 잎을 빼는 행의 다음 걸음. `live` 는 지금 디렉터리로 본 받는 쪽 규칙(`RuleCtx::remove_blocked`).
    pub(crate) fn step(
        &mut self,
        gid: &str,
        device: &str,
        seq: i64,
        live: bool,
        now: Instant,
    ) -> Step {
        let key = (gid.to_owned(), device.to_owned());
        if self.got > 0 && !live {
            self.rows.remove(&key);
            return Step::Commit;
        }
        let (got, answers) = (self.got, self.answers);
        let row = self.rows.entry(key.clone()).or_insert(Row {
            seq,
            since: now,
            asked: None,
        });
        row.seq = seq;
        let late = now.saturating_duration_since(row.since) >= GIVE_UP;
        let step = if got == 0 {
            // 접속 때 물은 디렉터리가 아직 안 왔다 — 새로 묻지 않고 그 답을 기다린다.
            if late {
                Step::Drop(Refused::NoAnswer)
            } else {
                Step::Wait
            }
        } else {
            match row.asked {
                None => {
                    row.asked = Some(answers);
                    row.since = now;
                    Step::Ask
                }
                Some(a) if answers > a => Step::Drop(Refused::Live),
                Some(_) if late => Step::Drop(Refused::NoAnswer),
                Some(_) => Step::Wait,
            }
        };
        if matches!(step, Step::Drop(_)) {
            self.rows.remove(&key);
        }
        step
    }

    /// 이 일의 감사 줄을 처음 내는가.
    pub(crate) fn audit_once(&mut self, gid: &str, device: &str, why: Refused) -> bool {
        self.audited
            .insert(((gid.to_owned(), device.to_owned()), why))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: &str = "g";
    const D: &str = "dev";

    #[test]
    fn 디렉터리를_못_받았으면_산_기기가_아니어도_만들지_않는다() {
        let mut g = Guard::default();
        let t = Instant::now();
        assert_eq!(g.step(G, D, 1, false, t), Step::Wait);
        assert_eq!(g.directory(true), vec![1]);
        assert_eq!(g.step(G, D, 1, false, t), Step::Commit);
        assert!(g.directory(false).is_empty(), "끝난 행은 깨우지 않는다");
    }

    #[test]
    fn 받았고_없으면_바로_만든다() {
        let mut g = Guard::default();
        g.directory(false);
        assert_eq!(g.step(G, D, 1, false, Instant::now()), Step::Commit);
    }

    #[test]
    fn 산_기기면_묻고_물은_뒤_온_답에서도_산_기기면_버린다() {
        let mut g = Guard::default();
        let t = Instant::now();
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Ask);
        assert_eq!(g.step(G, D, 1, true, t), Step::Wait, "답 전에는 기다림");
        // 방송은 물음의 답이 아니다 — 깨우기만 하고 버리지 않는다.
        assert_eq!(g.directory(false), vec![1]);
        assert_eq!(g.step(G, D, 1, true, t), Step::Wait);
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Drop(Refused::Live));
        // 같은 일이 다시 와도 감사 줄은 하나.
        assert!(g.audit_once(G, D, Refused::Live));
        assert!(!g.audit_once(G, D, Refused::Live));
        assert!(g.audit_once(G, "other", Refused::Live));
        // 까닭이 다르면 따로 — 「답 없음」이 먼저 나갔어도 「산 기기」 줄은 남는다.
        assert!(g.audit_once(G, D, Refused::NoAnswer));
        assert!(!g.audit_once(G, D, Refused::NoAnswer));
    }

    #[test]
    fn 새_답이나_방송에서_없어졌으면_만든다() {
        let mut g = Guard::default();
        let t = Instant::now();
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Ask);
        g.directory(false);
        assert_eq!(
            g.step(G, D, 1, false, t),
            Step::Commit,
            "「아님」은 어느 프레임으로든"
        );
        // 다시 같은 일이 와 산 기기로 보이면 처음부터 묻는다.
        assert_eq!(g.step(G, D, 2, true, t), Step::Ask);
    }

    #[test]
    fn 답이_안_오면_상한_뒤에_버린다() {
        let mut g = Guard::default();
        let t = Instant::now();
        assert_eq!(g.step(G, D, 1, true, t), Step::Wait);
        assert_eq!(
            g.step(G, D, 1, true, t + GIVE_UP),
            Step::Drop(Refused::NoAnswer)
        );
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Ask);
        assert_eq!(
            g.step(G, D, 1, true, t + GIVE_UP - Duration::from_secs(1)),
            Step::Wait
        );
        assert_eq!(
            g.step(G, D, 1, true, t + GIVE_UP),
            Step::Drop(Refused::NoAnswer)
        );
    }

    #[test]
    fn 새_접속은_셈과_기다리던_행을_같이_비운다() {
        let mut g = Guard::default();
        let t = Instant::now();
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Ask);
        g.connected();
        // 옛 접속의 물음 표식이 남으면 새 접속의 첫 답이 「물은 뒤 답」으로 읽힌다.
        assert_eq!(g.step(G, D, 1, true, t), Step::Wait);
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Ask);
        g.directory(true);
        assert_eq!(g.step(G, D, 1, true, t), Step::Drop(Refused::Live));
    }
}
