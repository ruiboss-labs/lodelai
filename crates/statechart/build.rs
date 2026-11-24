//! machines/wire.yaml(선 머신) → 머신별 State/Event/가드/Action enum 과 순수 전이 함수 `step()`.
//! yaml 이 legend 규칙을 어기면 빌드가 실패한다(검증은 src/model.rs, 생성은 src/gen.rs — 앱 머신 크레이트도 같은 gen 을 쓴다).

#[path = "src/gen.rs"]
mod gen;
#[path = "src/model.rs"]
mod model;

use std::path::PathBuf;

const YAML: &str = "machines/wire.yaml";

fn main() {
    println!("cargo:rerun-if-changed={YAML}");
    println!("cargo:rerun-if-changed=src/model.rs");
    println!("cargo:rerun-if-changed=src/gen.rs");
    let text =
        std::fs::read_to_string(YAML).unwrap_or_else(|e| panic!("{YAML} 를 읽지 못했다: {e}"));
    let out = match gen::generate(&text, "crate", YAML) {
        Ok(s) => s,
        Err(e) => panic!("\n\n{YAML} 검증 실패:\n  {e}\n\n"),
    };
    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("machines.rs");
    std::fs::write(dest, out).unwrap();
}
