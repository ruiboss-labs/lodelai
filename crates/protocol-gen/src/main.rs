//! lodelai-protocol-gen — 선 프로토콜 생성기 (U1, #52). 레포 루트에서 `cargo run -p lodelai-protocol-gen` 으로 돌린다.
//! 루트 스크립트 `bun run protocol:gen` 이 이것과 TS 생성(`packages/protocol/scripts/gen.ts`)·Biome 포맷을 함께 돌린다.
//!
//! 만드는 것(선 스키마만 — 부품은 이 크레이트의 라이브러리):
//! 1. `crates/protocol/src/generated/{message,ws}.rs` — typify(=0.8.0). 스키마 파일마다 모듈 하나.
//! 2. `crates/protocol/src/generated/states.rs` — 상태 enum 은 생성하지 않고 `lodelai-statechart`(machines/wire.yaml) 를
//!    다시 내보낸다(정의는 한 곳).
//! 3. `crates/protocol/src/generated/constants.rs` — `constants.json`.
//! 4. `packages/protocol/schema/states.schema.json` — 위 enum 값에서. TS 가 이걸로 생성한다.
//! 5. `packages/protocol/fixtures/*.json` 재서명 + `fixtures/keys.json` — 사용자별 결정적 기기 키(SHA-512("lodelai-fixture-v1:" + user)).
//!
//! 폴더는 인자로 바꿀 수 있다: `--schema-dir`·`--fixture-dir`·`--out-dir`(기본은 이 레포 자리). `--check` 는 쓰지 않고 대조만.

use std::process::ExitCode;

use lodelai_protocol_gen::{
    gen_constants_rs, gen_fixtures, gen_mod_rs, gen_rust, gen_states_rs, gen_states_schema,
    read_constants, wire_state_types, Dirs, Writer,
};

const NAME: &str = "lodelai-protocol-gen";
const GENERATOR: &str = "lodelai-protocol-gen (crates/protocol-gen)";
/// typify 로 Rust 를 만드는 선 스키마.
const TYPED: &[&str] = &["message", "ws"];
const WIRE_YAML: &str = "crates/statechart/machines/wire.yaml";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let dirs = Dirs::from_args(&args, "crates/protocol/src/generated");
    if !dirs.schema.is_dir() {
        eprintln!(
            "{NAME}: 레포 루트에서 실행하거나 --schema-dir 를 주세요 ({} 없음)",
            dirs.schema.display()
        );
        return ExitCode::from(2);
    }
    let mut w = Writer::new(args.iter().any(|a| a == "--check"));
    let out = dirs.out.as_path();
    std::fs::create_dir_all(out).expect("출력 폴더");
    for stem in TYPED {
        w.text(
            &out.join(format!("{stem}.rs")),
            &gen_rust(&dirs.schema, stem, GENERATOR),
        );
    }
    let wire = wire_state_types();
    w.text(
        &out.join("states.rs"),
        &gen_states_rs(&wire, "lodelai_statechart", "states", WIRE_YAML, GENERATOR),
    );
    let constants = read_constants(&dirs.schema, &["constants.json"]);
    w.text(
        &out.join("constants.rs"),
        &gen_constants_rs(
            &constants,
            "`packages/protocol/schema/constants.json`(선).",
            "",
            GENERATOR,
        ),
    );
    w.text(
        &out.join("mod.rs"),
        &gen_mod_rs(TYPED, &["constants", "states"], "", GENERATOR),
    );
    w.json(
        &dirs.schema.join("states.schema.json"),
        &gen_states_schema(&wire, "states", WIRE_YAML, "lodelai-statechart"),
    );
    gen_fixtures(&dirs, &mut w);
    w.finish(NAME)
}
