//! 그룹 공통 값(묶음 16). 옛 fan-out 멤버 상태·적용 규칙(ADR 0010 §3)은 MLS(묶음 22, ADR 0012)로 바뀌어 지웠다 — 멤버·관리자는
//! 그룹 잎과 GroupContext 가 정한다(`mls_conn::group_state`·`mls_rules`).

/// 그룹 이름 상한(글자 수, 묶음 16 §2 — 화면 `EvGroup.name` maxLength 와 같다).
pub(crate) const NAME_MAX_CHARS: usize = 64;
