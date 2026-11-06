//! 받은 메시지 봉투를 열 때의 오류(MLS 응용 메시지 — relay-client `mls_conn`).
//!
//! 묶음 22 전의 E2E 봉투 `enc: box`(#313, ephemeral-static X25519 + XChaCha20-Poly1305)는 v8 relay 가 거절하고 제품 코드가 쓰지
//! 않아 seal/open·시험 벡터와 함께 걷어냈다(#560). 오류 꼴은 수신 상태(`failed(bad_envelope)`·`unreadable`)와 묶여 그대로 둔다.

/// 봉투 오류.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// 봉투 형식 위반. 수신 relay-client 는 `failed(bad_envelope)`.
    #[error("봉투 형식: {0}")]
    BadEnvelope(&'static str),
    /// 이 기기가 열 수 없다(그 그룹 상태가 없음 등) — 수신 상태 `unreadable`. 실패가 아니다.
    #[error("이 기기가 열 수 없다")]
    Unreadable,
    /// 연 평문이 UTF-8 이 아님 등. 수신은 `failed(bad_envelope)`.
    #[error("복호화 실패: {0}")]
    Decrypt(&'static str),
}
