//! 기기 폐기 증명(묶음 22 §2c·§12-11 ⓐ, `lodelai-devrevoke-v1`).
//!
//! 같은 사용자의 폐기 안 된 기기(서명자 — 자기 폐기면 그 기기 자신)가 폐기되는 기기에 서명한다. 받는 기기는 **서명자가 자기가
//! 쥔 그 사람의 핀에서 devcert 사슬로 닿을 때만** 이 증명으로 핀을 옮긴다 — 서버가 지운 기기(관리자 폐기·이메일 복구)는 증명이
//! 없어 사람 확인으로 간다. `at` 은 받은 RFC 3339 문자열 그대로 서명 입력에 넣는다(다시 꼴을 맞추지 않음).

use crate::encoding::{decode_array, domain_separated, encode, DOMAIN_SEPARATOR};
use crate::keys::{SigningKeyPair, VerifyingKey};

/// 도메인 태그.
pub const TAG_DEVREVOKE: &str = "lodelai-devrevoke-v1";

/// 서명 대상. `server` 는 `ready.server` 와 같은 문자열.
#[derive(Debug, Clone, Copy)]
pub struct Revoke<'a> {
    pub server: &'a str,
    pub device_id: &'a str,
    pub at: &'a str,
}

/// 서명 입력: `lodelai-devrevoke-v1 ‖ 0 ‖ server ‖ 0 ‖ revoked_device_id ‖ 0 ‖ at`.
pub fn payload(r: &Revoke<'_>) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(r.server.as_bytes());
    p.push(DOMAIN_SEPARATOR);
    p.extend_from_slice(r.device_id.as_bytes());
    p.push(DOMAIN_SEPARATOR);
    p.extend_from_slice(r.at.as_bytes());
    domain_separated(TAG_DEVREVOKE, &p)
}

/// 서명자 기기의 서명(base64url 86자).
pub fn sign(signing: &SigningKeyPair, r: &Revoke<'_>) -> String {
    encode(&signing.sign(&payload(r)))
}

/// `sig` 가 서명자 키 `signer_ed25519` 로 `r` 에 한 서명인가. 서명자가 핀 사슬 위인지는 호출자가 본다.
pub fn verify(signer_ed25519: &VerifyingKey, r: &Revoke<'_>, sig: &str) -> bool {
    let Ok(bytes) = decode_array::<64>(sig, "devrevoke sig") else {
        return false;
    };
    signer_ed25519.verify(&payload(r), &bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKeys;

    #[test]
    fn sign_verify_and_every_field_is_bound() {
        let signer = DeviceKeys::generate(&[1; 64]);
        let r = Revoke {
            server: "lodelai.example",
            device_id: "k1_AAAAAAAAAAAAAAAAAAAAAA",
            at: "2026-10-27T01:02:03.004Z",
        };
        let sig = sign(&signer.signing, &r);
        assert_eq!(sig.len(), 86);
        let vk = signer.signing.verifying_key();
        assert!(verify(&vk, &r, &sig));
        for changed in [
            Revoke {
                server: "other",
                ..r
            },
            Revoke {
                device_id: "k1_BBBBBBBBBBBBBBBBBBBBBB",
                ..r
            },
            Revoke {
                at: "2026-10-27T01:02:03.005Z",
                ..r
            },
        ] {
            assert!(!verify(&vk, &changed, &sig));
        }
        assert!(!verify(
            &DeviceKeys::generate(&[2; 64]).signing.verifying_key(),
            &r,
            &sig
        ));
        assert!(!verify(&vk, &r, "A"));
    }

    /// 입력 바이트 고정(relay·다른 구현과 맞추는 기준).
    #[test]
    fn payload_bytes() {
        let r = Revoke {
            server: "s",
            device_id: "d",
            at: "t",
        };
        let mut want = b"lodelai-devrevoke-v1".to_vec();
        want.extend_from_slice(b"\0s\0d\0t");
        assert_eq!(payload(&r), want);
    }
}
