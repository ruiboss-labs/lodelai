//! L1 (U1 완료 기준): fixtures 가 생성 타입으로 손실 없이 왕복하고(JCS 바이트 동일), 재서명된 `sig` 가 검증된다.
//! TS 쪽(`packages/protocol/src/fixtures.test.ts`)은 같은 fixtures 의 `sig` 를 자기 JCS 로 검증한다 — 두 언어의 JCS 바이트가
//! 같아야만 통과하므로 교차 검증이 된다.

use std::path::{Path, PathBuf};

use lodelai_crypto::{jcs, verify_message, DeviceId, VerifyingKey};
use lodelai_protocol::message::Message;
use lodelai_protocol::{states, ws};
use serde_json::{json, Value};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/protocol/fixtures")
}

fn fixtures() -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = std::fs::read_dir(fixture_dir())
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            let name = p.file_name()?.to_str()?.to_owned();
            (name.ends_with(".json") && name != "keys.json").then(|| {
                (
                    name,
                    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap(),
                )
            })
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() >= 7, "fixtures 가 비었다");
    out
}

fn kind_of(m: &Message) -> &'static str {
    match m {
        Message::ChatMessage(_) => "chat",
        Message::RequestMessage(_) => "request",
        Message::ReplyMessage(_) => "reply",
        Message::RejectedMessage(_) => "rejected",
        Message::SystemMessage(_) => "system",
        Message::GroupMessage(_) => "group",
        Message::ReactionMessage(_) => "reaction",
        Message::OwnMessage(_) => "own",
    }
}

#[test]
fn fixtures_round_trip_through_generated_types() {
    for (name, v) in fixtures() {
        let m: Message =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            kind_of(&m),
            v["kind"].as_str().unwrap(),
            "{name}: 다른 가지로 읽혔다"
        );
        let back = serde_json::to_value(&m).unwrap();
        assert_eq!(
            jcs::to_string(&back).unwrap(),
            jcs::to_string(&v).unwrap(),
            "{name}: 생성 타입 왕복에서 바이트가 달라졌다"
        );
    }
}

#[test]
fn fixtures_are_signed_by_their_device() {
    let keys: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_dir().join("keys.json")).unwrap())
            .unwrap();
    for (name, v) in fixtures() {
        let user = v["from"]["address"]
            .as_str()
            .unwrap()
            .split('@')
            .next()
            .unwrap();
        let k = &keys[user];
        let vk = VerifyingKey::from_b64(k["ed25519"].as_str().unwrap()).unwrap();
        assert_eq!(v["from"]["device_id"], k["device_id"], "{name}");
        assert!(
            DeviceId::parse(k["device_id"].as_str().unwrap())
                .unwrap()
                .matches(&vk),
            "{name}"
        );
        verify_message(&v, &vk).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn discriminator_is_enforced() {
    let (_, reply) = fixtures()
        .into_iter()
        .find(|(n, _)| n == "reply_agent.json")
        .unwrap();
    // reply 와 rejected 는 필드가 같다 — kind 로만 갈린다
    let mut as_rejected = reply.clone();
    as_rejected["kind"] = json!("rejected");
    let m: Message = serde_json::from_value(as_rejected).unwrap();
    assert_eq!(kind_of(&m), "rejected");
    let mut bogus = reply.clone();
    bogus["kind"] = json!("bogus");
    assert!(serde_json::from_value::<Message>(bogus).is_err());
    // additionalProperties:false
    let mut extra = reply.clone();
    extra["surprise"] = json!(1);
    assert!(serde_json::from_value::<Message>(extra).is_err());
    // 시각 정규형(밀리초 3자리)이 아니면 거부
    let mut sloppy = reply;
    sloppy["created_at"] = json!("2026-10-23T04:12:56Z");
    assert!(serde_json::from_value::<Message>(sloppy).is_err());
}

#[test]
fn ws_frames_and_states() {
    let f: ws::Frame = serde_json::from_value(
        json!({"t": "nack", "msg_id": "01JB0000000000000000000001", "reason": "unroutable"}),
    )
    .unwrap();
    assert!(matches!(f, ws::Frame::Nack(_)));
    let f: ws::Frame = serde_json::from_value(json!({"t": "pong"})).unwrap();
    assert!(matches!(f, ws::Frame::Pong(_)));
    assert!(serde_json::from_value::<ws::Frame>(json!({"t": "nope"})).is_err());

    // 상태 enum 은 statechart 그대로
    let s: states::SenderViewState = serde_json::from_value(json!("aborted")).unwrap();
    assert_eq!(s, lodelai_statechart::request_sender_view::State::Aborted);
    let st: ws::Status = serde_json::from_value(json!({"t": "status", "msg_id": "01JB0000000000000000000001", "state": "aborted", "abort_reason": "turn_ended", "at": "2026-10-23T04:12:56.000Z"})).unwrap();
    assert_eq!(
        serde_json::to_value(&st).unwrap()["abort_reason"],
        "turn_ended"
    );
}

/// ws `StatusState` 는 states `SenderViewState` 를 손으로 옮기고 `read` 를 더한 것이다(#308). 둘이 갈라지지 않게 묶는다.
#[test]
fn status_state_is_sender_view_state_plus_read() {
    let schema = |f: &str| -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../packages/protocol/schema")
                    .join(f),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let names = |v: &Value| -> std::collections::BTreeSet<String> {
        v["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    };
    let mut want = names(&schema("states.schema.json")["$defs"]["SenderViewState"]);
    want.insert("read".into());
    // chat 확인함(묶음 14 B3) — 발신자 뷰 상태가 아니라 chat 표시.
    want.insert("acknowledged".into());
    assert_eq!(
        names(&schema("ws.schema.json")["$defs"]["StatusState"]),
        want
    );
}
