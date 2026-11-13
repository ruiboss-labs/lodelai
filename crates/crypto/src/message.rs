//! 메시지 서명·검증 (protocol.md §3 "서명 대상").
//!
//! 서명 입력 = `lodelai-msg-v1` ‖ 0x00 ‖ JCS(`state`·`sig` 를 뺀 메시지 객체). 서버와 수신 코어가 모두 같은 함수로 검증한다.
//! `serde_json::Value` 위에서 동작하므로 protocol 타입이 바뀌어도 이 크레이트는 안 바뀐다.

use serde_json::{Map, Value};

use crate::keys::{SigningKeyPair, VerifyingKey};
use crate::{encoding, jcs, Error, Result};

/// 서명에서 빼는 필드.
pub const EXCLUDED_FIELDS: [&str; 2] = ["state", "sig"];

/// `sig` 필드 이름.
pub const SIG_FIELD: &str = "sig";

/// 메시지 서명의 도메인 태그.
pub const DOMAIN: &str = "lodelai-msg-v1";

/// `state`·`sig` 를 뺀 객체의 JCS 바이트(도메인 태그 없음). TS 와 바이트 비교할 때 쓴다.
///
/// # Errors
/// 객체가 아니거나 JCS 직렬화가 실패하면 오류.
pub fn canonical_payload(message: &Value) -> Result<Vec<u8>> {
    let obj = message.as_object().ok_or(Error::NotAnObject)?;
    let filtered: Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| !EXCLUDED_FIELDS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    jcs::to_vec(&Value::Object(filtered))
}

/// 서명 입력 바이트: `lodelai-msg-v1` ‖ 0x00 ‖ [`canonical_payload`].
///
/// # Errors
/// [`canonical_payload`] 와 같다.
pub fn signing_payload(message: &Value) -> Result<Vec<u8>> {
    Ok(encoding::domain_separated(
        DOMAIN,
        &canonical_payload(message)?,
    ))
}

/// 메시지에 서명해 `sig` 를 채운다(있던 값은 덮어쓴다). 반환은 넣은 `sig` 문자열.
///
/// # Errors
/// [`signing_payload`] 와 같다.
pub fn sign_message(message: &mut Value, key: &SigningKeyPair) -> Result<String> {
    let payload = signing_payload(message)?;
    let sig = encoding::encode(&key.sign(&payload));
    message
        .as_object_mut()
        .ok_or(Error::NotAnObject)?
        .insert(SIG_FIELD.to_owned(), Value::String(sig.clone()));
    Ok(sig)
}

/// 메시지의 `sig` 를 공개키로 검증한다. 호출자는 그 공개키가 `from.device_id` 의 것인지 따로 확인한다.
///
/// # Errors
/// `sig` 없음·형식 불량·검증 실패는 모두 오류. 서버는 어느 경우든 `nack reason=auth`.
pub fn verify_message(message: &Value, key: &VerifyingKey) -> Result<()> {
    let sig = message
        .get(SIG_FIELD)
        .and_then(Value::as_str)
        .ok_or(Error::MissingSignature)?;
    let sig = encoding::decode_array::<64>(sig, "sig")?;
    let payload = signing_payload(message)?;
    key.verify(&payload, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "v": 0,
            "msg_id": "01JB0000000000000000000001",
            "thread_id": "01JB0000000000000000000001",
            "kind": "request",
            "from": {"address": "dana@dev-relay/frontend", "author": "agent", "session_id": "cee3f37e-0000-0000-0000-000000000000", "device_id": "k1x"},
            "to": {"address": "bo@dev-relay/backend"},
            "grade": "question",
            "body": {"text": "안녕하세요 🙂\n줄바꿈"},
            "created_at": "2026-10-23T04:12:56.123Z",
            "expires_at": "2026-10-24T04:12:56.123Z",
            "state": "sent"
        })
    }

    #[test]
    fn payload_excludes_state_and_sig_and_is_canonical() {
        let mut m = sample();
        let p1 = signing_payload(&m).unwrap();
        m["state"] = json!("delivered_to_device");
        m["sig"] = json!("garbage");
        assert_eq!(signing_payload(&m).unwrap(), p1);
        assert!(p1.starts_with(b"lodelai-msg-v1\0{\"body\":{\"text\":"));
        let c = String::from_utf8(canonical_payload(&m).unwrap()).unwrap();
        assert!(c.starts_with("{\"body\":{\"text\":"));
        assert!(!c.contains("\"state\""));
        assert_eq!(&p1[DOMAIN.len() + 1..], c.as_bytes());
    }

    /// 묶음 26 §5: 회신 머리 `need` 도 서명 대상 — 지우면 검증이 실패한다.
    #[test]
    fn top_level_need_is_signed() {
        let key = SigningKeyPair::from_seed(&[43u8; 32]);
        let mut m = sample();
        m["need"] = json!("task");
        sign_message(&mut m, &key).unwrap();
        verify_message(&m, &key.verifying_key()).unwrap();
        m.as_object_mut().unwrap().remove("need");
        assert!(verify_message(&m, &key.verifying_key()).is_err());
    }

    #[test]
    fn sign_then_verify_and_tamper() {
        let key = SigningKeyPair::from_seed(&[42u8; 32]);
        let mut m = sample();
        let sig = sign_message(&mut m, &key).unwrap();
        assert_eq!(m["sig"], sig);
        assert_eq!(sig.len(), 86);
        verify_message(&m, &key.verifying_key()).unwrap();

        // state 는 서버가 바꿔도 서명이 산다
        m["state"] = json!("delivered_to_device");
        verify_message(&m, &key.verifying_key()).unwrap();

        // grade·to·kind·body 변조는 깨진다
        for (field, v) in [
            ("grade", json!("task")),
            ("kind", json!("chat")),
            ("to", json!({"address": "eve@dev-relay"})),
            ("body", json!({"text": "다른 본문"})),
        ] {
            let mut t = m.clone();
            t[field] = v;
            assert!(
                matches!(
                    verify_message(&t, &key.verifying_key()),
                    Err(Error::BadSignature)
                ),
                "{field}"
            );
        }
        // 다른 키
        assert!(
            verify_message(&m, &SigningKeyPair::from_seed(&[1u8; 32]).verifying_key()).is_err()
        );
    }

    #[test]
    fn golden_signature() {
        // 시드 [9;32] + sample() → 고정 sig. 서명 입력(태그·JCS·제외 필드)이 조금이라도 바뀌면 깨진다.
        let key = SigningKeyPair::from_seed(&[9u8; 32]);
        let mut m = sample();
        let sig = sign_message(&mut m, &key).unwrap();
        assert_eq!(sig, "8toULTGZvpnnTj1c4H1jcJ-euWdQ85qoGuaziPG0ig88c_agEZ8xZh25D1qyGAnyNWXRSzxPYjE6rqilz66xBQ");
    }

    #[test]
    fn signature_is_deterministic() {
        // Ed25519 는 결정적 — 같은 키·같은 메시지면 같은 sig. fixtures 재현 시험의 전제.
        let key = SigningKeyPair::from_seed(&[9u8; 32]);
        let mut a = sample();
        let mut b = sample();
        assert_eq!(
            sign_message(&mut a, &key).unwrap(),
            sign_message(&mut b, &key).unwrap()
        );
    }

    #[test]
    fn missing_or_malformed_sig() {
        let key = SigningKeyPair::from_seed(&[42u8; 32]);
        let m = sample();
        assert!(matches!(
            verify_message(&m, &key.verifying_key()),
            Err(Error::MissingSignature)
        ));
        let mut m2 = m.clone();
        m2["sig"] = json!(123);
        assert!(matches!(
            verify_message(&m2, &key.verifying_key()),
            Err(Error::MissingSignature)
        ));
        m2["sig"] = json!("AAAA");
        assert!(matches!(
            verify_message(&m2, &key.verifying_key()),
            Err(Error::BadEncoding { .. })
        ));
        assert!(matches!(
            sign_message(&mut json!([1]), &key),
            Err(Error::NotAnObject)
        ));
    }
}
