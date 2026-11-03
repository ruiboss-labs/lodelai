//! 내 기기 서명(`docs/design/e2e-envelope.md` §7a, protocol §3 `lodelai-devcert-v1`, #393).
//!
//! 같은 사용자의 기존 기기(서명자)가 새 기기의 (`device_id`, x25519)에 서명하면, 서명자를 이미 믿는 동료는 새 기기를 자동
//! 신뢰한다. `server` 가 들어가 다른 서버로 옮겨 쓰지 못한다(같은 기기 키를 여러 서버에 쓴다, #389). relay 는 저장 전에
//! 검증만 하고(정직한 서버에서 쓰레기 서명을 막음) **진짜 방어는 피어의 검증**이다.

use crate::encoding::{decode_array, domain_separated, encode, DOMAIN_SEPARATOR};
use crate::keys::{SigningKeyPair, VerifyingKey};

/// 도메인 태그.
pub const TAG_DEVCERT: &str = "lodelai-devcert-v1";

/// 서명 대상. `server` 는 `ready.server` 와 같은 문자열.
#[derive(Debug, Clone, Copy)]
pub struct Cert<'a> {
    pub server: &'a str,
    pub user: &'a str,
    pub device_id: &'a str,
    pub x25519: &'a [u8; 32],
    pub signer: &'a str,
}

/// 서명 입력: `lodelai-devcert-v1 ‖ 0 ‖ server ‖ 0 ‖ user ‖ 0 ‖ device_id ‖ 0 ‖ x25519 32B ‖ 0 ‖ signer`.
pub fn payload(c: &Cert<'_>) -> Vec<u8> {
    let mut p = Vec::new();
    for part in [c.server, c.user, c.device_id] {
        p.extend_from_slice(part.as_bytes());
        p.push(DOMAIN_SEPARATOR);
    }
    p.extend_from_slice(c.x25519);
    p.push(DOMAIN_SEPARATOR);
    p.extend_from_slice(c.signer.as_bytes());
    domain_separated(TAG_DEVCERT, &p)
}

/// 서명자 기기의 서명(base64url 86자).
pub fn sign(signing: &SigningKeyPair, c: &Cert<'_>) -> String {
    encode(&signing.sign(&payload(c)))
}

/// `sig` 가 서명자 키 `signer_ed25519` 로 `c` 에 한 서명인가. 서명자 `device_id` 가 그 키의 지문인지는 호출자가 이미
/// 아는 기기(디렉터리·신뢰 집합)에서 키를 꺼내므로 따로 보지 않는다.
pub fn verify(signer_ed25519: &VerifyingKey, c: &Cert<'_>, sig: &str) -> bool {
    let Ok(bytes) = decode_array::<64>(sig, "devcert sig") else {
        return false;
    };
    signer_ed25519.verify(&payload(c), &bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKeys;

    #[test]
    fn sign_verify_and_every_field_is_bound() {
        let signer = DeviceKeys::generate(&[1; 64]);
        let target = DeviceKeys::generate(&[2; 64]);
        let x = target.exchange.public_key();
        let other_x = DeviceKeys::generate(&[3; 64]).exchange.public_key();
        let (target_id, signer_id) = (target.device_id(), signer.device_id());
        let c = Cert {
            server: "lodelai.example",
            user: "alice",
            device_id: target_id.as_str(),
            x25519: &x,
            signer: signer_id.as_str(),
        };
        let sig = sign(&signer.signing, &c);
        assert_eq!(sig.len(), 86);
        let vk = signer.signing.verifying_key();
        assert!(verify(&vk, &c, &sig));
        // 서버·사용자·대상·x25519·서명자 하나라도 다르면 틀린다(다른 서버로 옮겨 쓸 수 없음, #389).
        for changed in [
            Cert {
                server: "other",
                ..c
            },
            Cert { user: "bob", ..c },
            Cert {
                device_id: "k1_AAAAAAAAAAAAAAAAAAAAAA",
                ..c
            },
            Cert {
                x25519: &other_x,
                ..c
            },
            Cert {
                signer: "k1_AAAAAAAAAAAAAAAAAAAAAA",
                ..c
            },
        ] {
            assert!(!verify(&vk, &changed, &sig));
        }
        // 다른 키·쓰레기 서명.
        assert!(!verify(&target.signing.verifying_key(), &c, &sig));
        assert!(!verify(&vk, &c, "A"));
    }
}
