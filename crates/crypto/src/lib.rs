//! lodelai 암호 기본 요소 (U1b, #53).
//!
//! - [`jcs`]: JSON Canonicalization Scheme(RFC 8785) 직렬화
//! - [`keys`]: 기기 키쌍(Ed25519 서명 + X25519 교환). 생성은 32바이트 시드 입력 — 난수는 호출자가 주입
//! - [`device_id`]: Ed25519 공개키 지문(ADR 0006)
//! - [`message`]: 메시지 서명·검증(protocol.md §3 — `state`·`sig` 를 뺀 모든 필드를 JCS 로 직렬화해 서명)
//! - [`auth`]: WebSocket challenge 서명(protocol.md §7.1)
//! - [`keystore`]: 비밀키 저장 추상 + 메모리 구현 + macOS Keychain 구현
//! - [`blob`]: 첨부 파일 암호문 STREAM(ADR 0009 §2, 묶음 15)
//! - [`envelope`]: 받은 메시지 봉투를 열 때의 오류 [`EnvelopeError`](옛 `enc: box` seal/open 은 #560 에서 걷어냄)
//! - [`devcert`]: 내 기기 서명 `lodelai-devcert-v1`(§7a, #393)
//! - [`xkey`]: x25519 공개키를 Ed25519 로 묶는 서명 `x25519_sig`(§2)
//!
//! 이 크레이트는 `serde_json::Value` 위에서 동작하고 `crates/core`·`crates/protocol` 에 의존하지 않는다.
//! relay(U4)·코어↔relay 클라이언트(U5)가 이것만 의존한다.
//!
//! 와이어 표기(base64url 무패딩, `device_id` 형식, 서명 도메인 분리)는 protocol.md §3 "와이어 인코딩 확정"을 따르고 [`encoding`] 에 모여 있다.

pub mod auth;
pub mod blob;
pub mod devcert;
pub mod device_id;
pub mod devrevoke;
pub mod encoding;
pub mod envelope;
pub mod jcs;
pub mod keys;
pub mod keystore;
pub mod message;
pub mod xkey;

pub use auth::{sign_challenge, verify_challenge};
pub use device_id::DeviceId;
pub use envelope::EnvelopeError;
pub use keys::{
    DeviceKeys, DeviceSecret, ExchangeKeyPair, SignatureBytes, SigningKeyPair, VerifyingKey,
};
pub use keystore::{KeyStore, KeyStoreError, MemoryKeyStore};
pub use message::{canonical_payload, sign_message, signing_payload, verify_message};

/// 이 크레이트의 오류.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// JCS 직렬화 실패(I-JSON 밖 값: NaN·무한대·고립 서로게이트 등).
    #[error("JCS 직렬화 실패: {0}")]
    Jcs(#[from] serde_json::Error),
    /// 서명 대상이 JSON 객체가 아니다.
    #[error("서명 대상은 JSON 객체여야 한다")]
    NotAnObject,
    /// `sig` 필드가 없거나 문자열이 아니다.
    #[error("sig 필드가 없거나 문자열이 아니다")]
    MissingSignature,
    /// base64url 디코딩 실패 또는 길이 불일치.
    #[error("{what} 디코딩 실패")]
    BadEncoding { what: &'static str },
    /// 서명 검증 실패.
    #[error("서명 검증 실패")]
    BadSignature,
    /// challenge 구성 요소에 구분자(개행)가 들어 있다.
    #[error("challenge 구성 요소에 개행이 들어 있다: {what}")]
    ChallengeField { what: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
