# fixtures

키 정렬된 골든 샘플(Biome 이 들여쓰기 포맷을 적용하므로 파일 바이트 자체는 JCS 가 아니다). 부동소수 없음, 비ASCII 그대로.

- **서명·기기**: `from.device_id`·`sig` 는 `bun run protocol:gen` 이 사용자별 결정적 기기 키
  (`DeviceKeys::generate(SHA-512("lodelai-fixture-v1:" + user))`, `crates/protocol-gen`)로 다시 채운다. 손으로 고치면 생성기가 되돌린다.
  `keys.json` 은 그 공개키·`device_id` 목록(시험용, 비밀 아님).
- **L1 시험**(U1 완료 기준):
  - Rust `crates/protocol/tests/fixtures.rs` — 생성 타입으로 역직렬화 → 직렬화한 JCS 바이트가 원본 JCS 와 같고, 올바른 `kind` 가지로 읽히고, `sig` 가 `keys.json` 공개키로 검증된다.
  - TS `packages/protocol/src/fixtures.test.ts` — 같은 `sig` 를 TS JCS(`src/jcs.ts`)로 만든 서명 입력으로 검증한다. 두 언어의 JCS 바이트가 같아야만 통과한다.
