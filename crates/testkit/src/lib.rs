//! lodelai 공용 테스트 도구 (U13a, #36).
//!
//! `crates/statechart/machines/wire.yaml`(선 머신)을 읽어 상태 머신 시험의 원천으로 쓴다. 앱 머신 yaml 은 앱 쪽 시험이
//! [`machine::Machines::load`] 로 따로 읽고 [`machine::Machines::merge`] 로 합친다(#559).
//! - [`model`]: yaml 의 타입 모델(serde)
//! - [`machine`]: 행을 펼치고 가드로 매칭하는 참조 인터프리터
//! - [`coverage`]: (상태 × 이벤트 × 가드 입력) 전수 검사 — 한 입력에 정확히 한 행인지
//! - [`conformance`]: 구현(U2 의 core)이 같은 케이스를 통과하는지 확인하는 차분 시험
//! - [`props`]: yaml 의 property(P1·P2·P7·P8)와 보안 불변식을 위반 목록으로 돌려주는 검사
//! - [`effects`]: `lodelai-effects` 의 시험용 구현(고정 시계·시드 난수·난수 실패 주입·결정적 ID)
//! - [`rng`]: 시드 고정 난수(외부 의존 없이 재현 가능한 random walk 용)
//!
//! 이 크레이트는 시험 전용이며 제품 코드에서 import 하지 않는다.

pub mod conformance;
pub mod coverage;
pub mod effects;
pub mod machine;
pub mod model;
pub mod props;
pub mod rng;

use std::path::PathBuf;

/// 선 머신 yaml(`crates/statechart/machines/wire.yaml`) 절대 경로.
pub fn default_yaml_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../statechart/machines/wire.yaml")
}

/// 기본 yaml 을 읽어 컴파일한다.
///
/// # Errors
/// 파일을 못 읽거나 yaml 이 모델과 맞지 않으면 사람이 읽을 수 있는 메시지를 돌려준다.
pub fn load_default() -> Result<machine::Machines, String> {
    machine::Machines::load(&default_yaml_path())
}
