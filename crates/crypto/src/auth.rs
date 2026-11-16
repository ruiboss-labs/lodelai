//! WebSocket 인증 challenge 서명 (protocol.md §7.1 · §3 와이어 인코딩, ADR 0006).
//!
//! 서명 입력:
//!
//! ```text
//! "lodelai-auth-v1" ‖ 0x00 ‖ server(UTF-8) ‖ 0x00 ‖ device_id(ASCII) ‖ 0x00 ‖ nonce 원시 32바이트
//! ```
//!
//! - 도메인 태그로 메시지 서명(`lodelai-msg-v1`)과 겹치지 않는다.
//! - `server`·`device_id` 에 0x00 이 있으면 거부(경계 이동 방지). nonce 는 base64url 로 받은 것을 디코드해 32바이트여야 한다.

use crate::keys::{SigningKeyPair, VerifyingKey};
use crate::{encoding, Error, Result};

/// 도메인 태그.
pub const DOMAIN: &str = "lodelai-auth-v1";

/// nonce 원시 길이(바이트). 서버가 base64url 43자로 보낸다.
pub const NONCE_LEN: usize = 32;

/// 서명 대상 바이트. `nonce_b64` 는 서버가 `challenge.nonce` 로 보낸 base64url 문자열.
///
/// # Errors
/// `server`·`device_id` 에 0x00 이 있거나 nonce 가 32바이트 base64url 이 아니면 오류.
pub fn challenge_bytes(server: &str, device_id: &str, nonce_b64: &str) -> Result<Vec<u8>> {
    for (what, v) in [("server", server), ("device_id", device_id)] {
        if v.contains('\0') {
            return Err(Error::ChallengeField { what });
        }
    }
    let nonce = encoding::decode_array::<NONCE_LEN>(nonce_b64, "nonce")?;
    let mut payload = Vec::with_capacity(server.len() + device_id.len() + NONCE_LEN + 2);
    payload.extend_from_slice(server.as_bytes());
    payload.push(encoding::DOMAIN_SEPARATOR);
    payload.extend_from_slice(device_id.as_bytes());
    payload.push(encoding::DOMAIN_SEPARATOR);
    payload.extend_from_slice(&nonce);
    Ok(encoding::domain_separated(DOMAIN, &payload))
}

/// challenge 에 서명해 base64url 문자열을 돌려준다(`auth.sig`).
pub fn sign_challenge(
    key: &SigningKeyPair,
    server: &str,
    device_id: &str,
    nonce_b64: &str,
) -> Result<String> {
    Ok(encoding::encode(
        &key.sign(&challenge_bytes(server, device_id, nonce_b64)?),
    ))
}

/// 서버 쪽 검증. `device_id` 가 `key` 의 지문인지는 호출자가 따로 확인한다.
pub fn verify_challenge(
    key: &VerifyingKey,
    server: &str,
    device_id: &str,
    nonce_b64: &str,
    sig: &str,
) -> Result<()> {
    let sig = encoding::decode_array::<64>(sig, "auth sig")?;
    key.verify(&challenge_bytes(server, device_id, nonce_b64)?, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce() -> String {
        encoding::encode(&[0xA5u8; 32])
    }

    #[test]
    fn round_trip_and_binding() {
        let key = SigningKeyPair::from_seed(&[3u8; 32]);
        let vk = key.verifying_key();
        let sig = sign_challenge(&key, "dev-relay", "k1_abc", &nonce()).unwrap();
        verify_challenge(&vk, "dev-relay", "k1_abc", &nonce(), &sig).unwrap();
        // nonce·server·device_id 어느 하나라도 다르면 실패 (재생·서버 바꿔치기 방지)
        let other_nonce = encoding::encode(&[0x5Au8; 32]);
        assert!(verify_challenge(&vk, "dev-relay", "k1_abc", &other_nonce, &sig).is_err());
        assert!(verify_challenge(&vk, "other", "k1_abc", &nonce(), &sig).is_err());
        assert!(verify_challenge(&vk, "dev-relay", "k1_xyz", &nonce(), &sig).is_err());
        // 다른 키
        let other = SigningKeyPair::from_seed(&[4u8; 32]).verifying_key();
        assert!(verify_challenge(&other, "dev-relay", "k1_abc", &nonce(), &sig).is_err());
    }

    #[test]
    fn bad_fields_are_rejected() {
        assert!(matches!(
            challenge_bytes("s\0", "d", &nonce()),
            Err(Error::ChallengeField { what: "server" })
        ));
        assert!(matches!(
            challenge_bytes("s", "d\0", &nonce()),
            Err(Error::ChallengeField { what: "device_id" })
        ));
        // nonce 길이·형식
        assert!(challenge_bytes("s", "d", &encoding::encode(&[1u8; 31])).is_err());
        assert!(challenge_bytes("s", "d", "not base64!").is_err());
    }

    #[test]
    fn bytes_layout() {
        let b = challenge_bytes("S", "D", &nonce()).unwrap();
        let mut expect = b"lodelai-auth-v1\0S\0D\0".to_vec();
        expect.extend_from_slice(&[0xA5u8; 32]);
        assert_eq!(b, expect);
    }

    #[test]
    fn golden_signature() {
        let key = SigningKeyPair::from_seed(&[3u8; 32]);
        let sig = sign_challenge(&key, "dev-relay", "k1_abc", &nonce()).unwrap();
        assert_eq!(sig, "QE_Gus-EwC3_vTjJlriSos4aAQ4QzXCeArdxCpLtW3D-n2NWFYECIuAADEYC54NCE-GS9B45URJtSZGr73l5Ag");
    }
}
