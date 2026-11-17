//! 그룹 주소 도우미(묶음 16 주소 꼴). 옛 fan-out 그룹 상태·받기 순서·수신 기기 계산(묶음 16 §3)은 MLS(묶음 22)로 바뀌어 지웠다 —
//! 그룹 상태는 `mls_conn::group_state`, 순서는 relay 의 `group_seq`·Commit 확정.

use serde_json::Value;

/// 그룹 주소 `+<gid>@server` → gid.
#[must_use]
pub fn gid_of(address: &str) -> Option<&str> {
    let (u, _) = address.split_once('@')?;
    let g = u.strip_prefix('+')?;
    (g.len() == 26
        && g.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()))
    .then_some(g)
}

/// 메시지의 그룹(to 가 그룹이면 그것, 아니면 헤더 `group`).
#[must_use]
pub fn group_context(message: &Value) -> Option<String> {
    let to = message.pointer("/to/address").and_then(Value::as_str)?;
    gid_of(to)
        .or_else(|| {
            message
                .get("group")
                .and_then(Value::as_str)
                .and_then(gid_of)
        })
        .map(str::to_owned)
}

/// 사람 주소(`user@server[/slug]` → `user@server`).
#[must_use]
pub fn person_of(address: &str) -> String {
    address.split('/').next().unwrap_or(address).to_owned()
}
