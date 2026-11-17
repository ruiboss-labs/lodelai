//! x25519 공개키를 기기의 Ed25519 키로 묶는 서명(`docs/design/e2e-envelope.md` §2, `lodelai-xkey-v1`).
//!
//! `device_id` 는 Ed25519 지문뿐이라, 이 서명이 없으면 서버가 디렉터리의 x25519 를 바꿔 끼워도 아무도 모른다 — 지문을 사람이
//! 대조해도 본문이 서버 키로 감싸진다. 등록·기기 연결 코드·디렉터리에 `x25519_sig` 를 싣고, 피어를 배울 때 `device_id` 재계산과
//! 함께 검증한다. relay 의 등록 검증은 정직한 서버에서 쓰레기 키를 막는 용도이고 **진짜 방어는 클라이언트 검증**이다.

use crate::encoding::{decode_array, domain_separated, encode, DOMAIN_SEPARATOR};
use crate::keys::{SigningKeyPair, VerifyingKey};
use crate::DeviceId;

/// 도메인 태그.
pub const TAG_XKEY: &str = "lodelai-xkey-v1";

/// 서명 입력: `lodelai-xkey-v1 ‖ 0x00 ‖ device_id(ASCII) ‖ 0x00 ‖ x25519 공개키 32바이트`.
pub fn payload(device_id: &str, x25519: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(device_id.len() + 1 + 32);
    p.extend_from_slice(device_id.as_bytes());
    p.push(DOMAIN_SEPARATOR);
    p.extend_from_slice(x25519);
    domain_separated(TAG_XKEY, &p)
}

/// 기기가 자기 x25519 공개키에 하는 서명(base64url 86자). `device_id` 는 그 기기의 것.
pub fn sign(signing: &SigningKeyPair, device_id: &str, x25519: &[u8; 32]) -> String {
    encode(&signing.sign(&payload(device_id, x25519)))
}

/// 피어 기기 공개 정보 검증: `device_id` 가 `ed25519` 의 지문이고 `sig` 가 그 키로 `(device_id, x25519)` 에 한 서명인가.
/// 하나라도 틀리면 거짓 — 호출자는 그 기기를 배우지 않는다(`Learned::Mismatch`).
pub fn verify(ed25519: &VerifyingKey, device_id: &str, x25519: &[u8; 32], sig: &str) -> bool {
    let Some(id) = DeviceId::parse(device_id) else {
        return false;
    };
    if !id.matches(ed25519) {
        return false;
    }
    let Ok(bytes) = decode_array::<64>(sig, "x25519_sig") else {
        return false;
    };
    ed25519.verify(&payload(device_id, x25519), &bytes).is_ok()
}
