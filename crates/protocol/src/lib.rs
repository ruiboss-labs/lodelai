//! lodelai 프로토콜 타입.
//!
//! 원본은 `packages/protocol/schema` 의 JSON Schema 다. 손으로 쓴 타입은 두지 않는다(ADR 0002).
//! [`generated`] 는 `lodelai-protocol-gen` 생성물이다(`bun run protocol:gen`). 스키마 파일마다 모듈 하나라
//! 이름이 같은 정의(`ws::Hello` 와 `ipc::Hello` 등)가 충돌하지 않는다.
//!
//! - 판별 유니온(`message::Message`, `ws::Frame` …)은 `#[serde(untagged)]` 로 나오지만 각 가지의 판별 필드
//!   (`kind`·`t`·`enc`)가 값 하나짜리 enum 이라 다른 가지로 잘못 읽히지 않는다.
//! - 상태 enum([`generated::states`])은 `lodelai-statechart` 를 그대로 다시 내보낸다(정의는 한 곳).
//! - `pattern` 이 있는 문자열은 검사하는 newtype 이다(역직렬화 때 검사).

pub mod display_name;
pub mod email;
pub mod generated;

pub use generated::{constants, message, states, ws};

/// 메시지 `v`·WS `hello.v` 가 쓰는 버전(constants.json, 1 = E2E 봉투 #313). 기존 사용처(`u32`)와 맞춘다.
#[allow(clippy::cast_possible_truncation)]
pub const PROTOCOL_VERSION: u32 = constants::PROTOCOL_VERSION as u32;

/// relay 가 받는 가장 낮은 `hello.v`(constants.json, 묶음 22 §12-24). 범위 밖이면 relay 가 challenge 전에
/// `error{version_unsupported, min, max}` 로 닫는다.
#[allow(clippy::cast_possible_truncation)]
pub const PROTOCOL_MIN: u32 = constants::PROTOCOL_MIN as u32;
const _: () = assert!(
    PROTOCOL_MIN <= PROTOCOL_VERSION,
    "PROTOCOL_MIN 이 PROTOCOL_VERSION 보다 크다"
);
/// 메시지 `v` 의 가장 높은 값(#613 — 판 11 은 연결 판이라 메시지 칸이 없음, 12 는 #626 반응). 받는 메시지 v 는 `[PROTOCOL_MIN, MESSAGE_V_MAX]`.
pub const MESSAGE_V_MAX: u32 = constants::MESSAGE_V_MAX as u32;
const _: () = assert!(
    PROTOCOL_MIN <= MESSAGE_V_MAX && MESSAGE_V_MAX <= PROTOCOL_VERSION,
    "MESSAGE_V_MAX 가 [PROTOCOL_MIN, PROTOCOL_VERSION] 밖"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_fits_u32() {
        assert_eq!(u64::from(PROTOCOL_VERSION), constants::PROTOCOL_VERSION);
        assert_eq!(u64::from(PROTOCOL_MIN), constants::PROTOCOL_MIN);
    }

    #[test]
    fn version_matches_ts_package() {
        let ts = include_str!("../../../packages/protocol/src/generated/constants.ts");
        assert!(
            ts.contains(&format!("PROTOCOL_VERSION = {PROTOCOL_VERSION}")),
            "TS 생성 상수와 다르다"
        );
    }
}
