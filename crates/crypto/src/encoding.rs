//! 바이트 ↔ 문자열 표기 (protocol.md §3 "와이어 인코딩 확정", 설계 2026-10-23).
//!
//! 1. 바이트 열(공개키·nonce·서명·암호문)은 모두 **base64url, 패딩 없음**(RFC 4648 §5). `sig` 는 64바이트 → 86자.
//! 2. `device_id`: `k1_` + base64url(패딩 없음)(SHA-256(Ed25519 공개키 32바이트)[0..16)) → 25자. [`device_id`](crate::device_id).
//! 3. 서명 입력은 항상 `도메인 태그 ‖ 0x00 ‖ 페이로드`. 태그는 [`message::DOMAIN`](crate::message::DOMAIN)·[`auth::DOMAIN`](crate::auth::DOMAIN).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{Error, Result};

/// `device_id` 키 알고리즘 버전 접두(다음 알고리즘은 `k2_`).
pub const DEVICE_ID_PREFIX: &str = "k1_";

/// 도메인 태그와 페이로드 사이 구분 바이트.
pub const DOMAIN_SEPARATOR: u8 = 0x00;

/// `태그 ‖ 0x00 ‖ 페이로드`.
pub fn domain_separated(tag: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 1 + payload.len());
    out.extend_from_slice(tag.as_bytes());
    out.push(DOMAIN_SEPARATOR);
    out.extend_from_slice(payload);
    out
}

/// 바이트를 base64url(패딩 없음) 문자열로.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// base64url(패딩 없음) 문자열을 바이트로. `what` 은 오류 메시지용 이름.
pub fn decode(s: &str, what: &'static str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::BadEncoding { what })
}

/// 고정 길이로 디코딩. 길이가 다르면 오류.
pub fn decode_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N]> {
    let v = decode(s, what)?;
    v.try_into().map_err(|_| Error::BadEncoding { what })
}
