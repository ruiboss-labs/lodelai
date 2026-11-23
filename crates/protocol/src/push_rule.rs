//! 「이 글로 사람에게 알림을 낼까」 규칙(#1546 판정 7041668764). relay(보관 직후 푸시)와 휴대폰(뒤에서 짧게 붙어 받은 글의
//! 알림)이 같은 함수로 가른다 — 두 벌이면 한쪽만 알리는 글이 생긴다.
//!
//! 그 앞에 한 가지: 받는 사람 자신이 직접 쓴 글은 알리지 않는다([`own_written`], #1638).
//!
//! 판정은 세 겹이다: ① 알릴 글인가([`wakes`]) ② 그 사람이 그 갈래를 껐나([`category`]) ③ 그 대화를 음소거했나
//! ([`mutable`] 인 종류만 음소거에 걸린다). 반응의 깨울 사람(머리 `wake`)은 ① 과 같이 본다. 한 번에 보려면 [`notifies`].

/// 보관된(또는 받은) 응용 메시지의 겉 — relay 가 보는 머리 칸만.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stored<'a> {
    /// 머리 `kind`.
    pub kind: &'a str,
    /// MLS 응용 메시지인가(Handshake 가 아님).
    pub app: bool,
    /// 고친 글인가(머리 `edits`).
    pub edits: bool,
    /// 그룹 글인가(머리 `group` — 받는 주소가 그룹이거나 그룹 안 멘션·에이전트 답).
    pub group: bool,
}

/// 사람에게 알릴 글인가 — 응용 메시지이고, 알릴 것이 없는 종류(`mls`·`system`: 거두기·요청 끝남 통지, `group`: 멤버 변경,
/// 내 기기끼리 `own_*`)와 고침이 아닐 때.
#[must_use]
pub fn wakes(m: &Stored<'_>) -> bool {
    m.app
        && !m.edits
        && !matches!(
            m.kind,
            "mls" | "system" | "group" | "own_control" | "own_control_result" | "own_delete"
        )
}

/// 사람이 끌 수 있는 갈래(`push_tokens.off` 의 낱말). 끌 수 없는 종류는 `None` — 늘 알린다. 그룹 글은 종류와 무관하게 `group`.
#[must_use]
pub fn category(m: &Stored<'_>) -> Option<&'static str> {
    if m.group {
        return Some("group");
    }
    match m.kind {
        "chat" | "reaction" => Some("chat"),
        "request" | "reply" | "rejected" => Some("agents"),
        _ => None,
    }
}

/// 대화 음소거에 걸리는 종류인가 — 사람 글과 반응만(§7-56: 요청·답·거절은 음소거와 상관없이 간다).
#[must_use]
pub fn mutable(kind: &str) -> bool {
    matches!(kind, "chat" | "reaction")
}

/// 음소거 대화 주소의 저장·비교 꼴 — 아이디·서버는 소문자, slug 는 그대로.
#[must_use]
pub fn mute_key(conv: &str) -> String {
    match conv.split_once('/') {
        Some((person, slug)) => format!("{}/{slug}", person.to_lowercase()),
        None => conv.to_lowercase(),
    }
}

/// 그 글이 걸리는 음소거 열쇠들(#1630) — 음소거는 대화 단위다. 그룹 글이면 그룹 주소 하나. 아니면 **보낸 주소**와, 그것이
/// 세션 주소(`아이디@서버/slug`)면 **그 사람 주소**도: 앱의 1:1 대화는 사람 단위라 그 사람의 에이전트가 쓴 글이 한 대화에
/// 모이고, 그 사람을 음소거하면 그 에이전트 글도 걸린다. 아이디·서버는 소문자로(저장 `mute.set` 과 같은 꼴), slug 는 그대로.
///
/// relay(푸시 거름)와 휴대폰(뒤에서 받은 글의 알림)이 같은 열쇠로 견준다 — 저장된 음소거 가운데 하나라도 여기 들면 음소거다.
#[must_use]
pub fn mute_keys(group: Option<&str>, from: &str) -> Vec<String> {
    if let Some(g) = group {
        return vec![mute_key(g)];
    }
    let exact = mute_key(from);
    match exact.split_once('/') {
        Some((person, _)) => {
            let person = person.to_owned();
            vec![exact, person]
        }
        None => vec![exact],
    }
}

/// 받는 사람 자신이 **직접 쓴** 글인가(#1638) — 사람이 쓴 글(`from.author == "human"`)이고 보낸 주소가 사람 주소(slug 없음)
/// 이며 받는 사람과 같을 때. 내가 다른 기기에서 쓴 글·반응·직접 한 답(에이전트 초안을 내가 보낸 것 포함)은 내 휴대폰에 알리지
/// 않는다(대화 음소거·끈 갈래와 무관, 종류와도 무관). 내 **에이전트**가 쓴 글은 내가 모르는 사이 오간 것이라 알린다(#1092) —
/// 보통 세션 주소로 나가지만, 사람 주소 앞으로 온 요청에 세션이 한 답은 사람 주소로 나가므로 주소만 보지 않고 `author` 를
/// 같이 본다. `human` = 머리 `from.author` 가 `human` 인가(코어가 찍고 서명에 든다), `receiver` = 받는 사람 주소(`아이디@서버`).
/// 아이디·서버는 대소문자를 가리지 않는다.
///
/// relay 는 머리 `from` 이 인증된 보낸 기기의 주인임을 저장 때 강제한다 — 남이 내 주소를 써서 내 알림을 끌 수 없다.
#[must_use]
pub fn own_written(from: &str, human: bool, receiver: &str) -> bool {
    human && !from.contains('/') && !from.is_empty() && from.eq_ignore_ascii_case(receiver)
}

/// 세 겹을 한 번에. `woken` = 머리 `wake`(반응의 깨울 사람)가 있을 때 받는 사람이 거기 드는가(칸이 없으면 `None` — 모두),
/// `off` = 그 사람이 끈 갈래들, `muted` = 그 대화가 지금 음소거인가.
#[must_use]
pub fn notifies<S: AsRef<str>>(
    m: &Stored<'_>,
    woken: Option<bool>,
    off: &[S],
    muted: bool,
) -> bool {
    wakes(m)
        && woken != Some(false)
        && !category(m).is_some_and(|c| off.iter().any(|o| o.as_ref() == c))
        && !(muted && mutable(m.kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(kind: &str, group: bool) -> Stored<'_> {
        Stored {
            kind,
            app: true,
            edits: false,
            group,
        }
    }

    /// 표본: 종류 × 그룹 × 끈 갈래 × 음소거 × 깨울 사람.
    #[test]
    fn 알림_규칙_표본() {
        let none: &[&str] = &[];
        // (종류, 그룹, 깨울 사람, 끈 갈래, 음소거, 알림)
        type Case<'a> = (&'a str, bool, Option<bool>, &'a [&'a str], bool, bool);
        let cases: &[Case<'_>] = &[
            ("chat", false, None, none, false, true),
            ("chat", false, None, &["chat"], false, false),
            ("chat", false, None, &["agents", "group"], false, true),
            ("chat", false, None, none, true, false),
            ("chat", true, None, &["chat"], false, true),
            ("chat", true, None, &["group"], false, false),
            ("chat", true, None, none, true, false),
            ("reaction", false, None, none, false, true),
            ("reaction", false, None, &["chat"], false, false),
            ("reaction", false, None, none, true, false),
            ("reaction", true, Some(true), none, false, true),
            ("reaction", true, Some(false), none, false, false),
            ("reaction", false, Some(false), none, false, false),
            ("request", false, None, none, false, true),
            ("request", false, None, &["agents"], false, false),
            ("request", false, None, none, true, true),
            ("reply", false, None, &["chat"], true, true),
            ("rejected", false, None, &["agents"], false, false),
            ("reply", true, None, &["agents"], false, true),
            ("reply", true, None, &["group"], false, false),
            ("reply", true, None, none, true, true),
            ("system", false, None, none, false, false),
            ("group", true, None, none, false, false),
            ("mls", false, None, none, false, false),
            ("own_control", false, None, none, false, false),
            ("own_control_result", false, None, none, false, false),
            ("own_delete", false, None, none, false, false),
        ];
        for (kind, group, woken, off, muted, want) in cases {
            assert_eq!(
                notifies(&m(kind, *group), *woken, off, *muted),
                *want,
                "{kind} group={group} woken={woken:?} off={off:?} muted={muted}"
            );
        }
        // 음소거 열쇠(#1630): 사람을 음소거하면 그 사람의 에이전트 글도 걸린다. 그룹 글은 그룹 주소만.
        assert_eq!(mute_keys(None, "Dana@Local"), vec!["dana@local"]);
        assert_eq!(
            mute_keys(None, "Dana@Local/Api"),
            vec!["dana@local/Api", "dana@local"]
        );
        assert_eq!(
            mute_keys(Some("+01jb00000000000000000000g1@Local"), "dana@local/api"),
            vec!["+01jb00000000000000000000g1@local"]
        );
        // 내가 직접 쓴 글(#1638): 사람이 썼고 사람 주소이며 받는 사람과 같을 때만 — 내 에이전트 글(세션 주소든, 사람 주소로 나간
        // 에이전트 답이든)·남의 글·다른 서버의 같은 아이디는 아님.
        assert!(own_written("dana@local", true, "dana@local"));
        assert!(own_written("Dana@Local", true, "dana@local"));
        assert!(!own_written("dana@local", false, "dana@local"));
        assert!(!own_written("dana@local/api", true, "dana@local"));
        assert!(!own_written("dana@local/api", false, "dana@local"));
        assert!(!own_written("eve@local", true, "dana@local"));
        assert!(!own_written("dana@other", true, "dana@local"));
        assert!(!own_written("", true, ""));
        // 고친 글·Handshake 는 종류와 무관하게 알리지 않는다.
        let mut e = m("chat", false);
        e.edits = true;
        assert!(!notifies(&e, None, none, false));
        let mut h = m("chat", false);
        h.app = false;
        assert!(!notifies(&h, None, none, false));
    }
}
