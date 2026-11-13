//! 코어가 만드는 서명 전 글 꼴(보내기 큐에 넣는 `Outgoing::Send`·`Outgoing::GroupChange` 의 `message`). relay-client 가 본문을
//! MLS 로 봉인하고 `from.device_id` 를 자기 값으로 고쳐 싣는다. 시험(mls_e2e)과 실기 씨앗 도구(examples/seed.rs)가 같이 쓴다 —
//! 같은 JSON 을 두 번 치지 않게.

use lodelai_effects::UnixMillis;
use serde_json::{json, Value};

/// 사람이 쓴 1:1·그룹 글(`kind: chat`, 본문 `{enc: plain, text}`). 받는 쪽 코어는 보통 대화 글로 받는다.
#[must_use]
pub fn chat(
    msg_id: &str,
    now: UnixMillis,
    expires: UnixMillis,
    from: &str,
    to: &str,
    text: &str,
) -> Value {
    json!({
        "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": msg_id, "thread_id": msg_id, "kind": "chat",
        "from": {"address": from, "author": "human", "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"},
        "to": {"address": to},
        "body": {"enc": "plain", "text": text},
        "created_at": now.to_rfc3339().unwrap_or_default(),
        "expires_at": expires.to_rfc3339().unwrap_or_default(),
    })
}

/// 그룹 변경(코어 `group_change_out` 꼴): kind group, `+gid@server` 앞, `group_op`·`subjects?`·`base_seq 0`, 본문 `{op, name?}`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn group_change(
    msg_id: &str,
    now: UnixMillis,
    expires: UnixMillis,
    from: &str,
    group: &str,
    op: &str,
    subjects: &[&str],
    name: Option<&str>,
) -> Value {
    let mut m = chat(msg_id, now, expires, from, group, "");
    m["kind"] = json!("group");
    m["group_op"] = json!(op);
    m["base_seq"] = json!(0);
    if !subjects.is_empty() {
        m["subjects"] = json!(subjects);
    }
    let mut asked = json!({"op": op});
    if let Some(n) = name {
        asked["name"] = json!(n);
    }
    m["body"] = json!({"enc": "plain", "text": asked.to_string()});
    m
}
