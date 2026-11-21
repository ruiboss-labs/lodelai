# 프로토콜 스키마 (원본)

기준 문서는 `docs/design/protocol.md`. 여기서 TS(`json-schema-to-typescript`)·Rust(`typify`, `crates/protocol`) 타입을 생성한다. **예외**: 상태 enum 은 Rust 쪽에서 `crates/statechart`(`machines/wire.yaml`)가 build.rs 로 생성하고 `crates/protocol` 이 re-export 한다 — `states.schema.json` 은 TS 생성에만 쓰고 Rust typify 대상에서 뺀다.

**생성**: 레포 루트에서 `bun run protocol:gen`(#52). Rust 생성기 `crates/protocol-gen` → `crates/protocol/src/generated/` + `states.schema.json`(statechart enum 값에서) + fixtures 재서명, TS 생성기 `packages/protocol/scripts/gen.ts` → `packages/protocol/src/generated/`, 마지막에 Biome 포맷. 스키마를 고치면 이 명령을 돌리고 생성물을 같이 커밋한다(CI 가 diff 로 검사). 생성 규칙·주의는 `crates/protocol/README.md`.

| 파일 | 내용 |
|---|---|
| `message.schema.json` | `Message`(kind 판별 oneOf), `Body`(enc 판별: plain/box), `PermissionRequest`/`Verdict`, 주소·ID 패턴 |
| `states.schema.json` | **생성물**: `crates/statechart/machines/wire.yaml`(선 머신)의 `machines[*].states[*].name` → 머신별 enum(RecipientState 등), `abort_reasons`. 손으로 고치지 않는다. 생성기는 `states`·`abort_reasons`·`guard_inputs` 만 읽는다(이벤트 키 on/event 에 의존하지 않음) |
| `ws.schema.json` | 중계 서버 WebSocket 프레임(`t` 판별) |
| `constants.json` | 선 코드 상수 단일 출처(바이트·초·길이, 이름에 단위) — relay·relay-client 공용 |
| `../fixtures/*.json` | 키 정렬된 샘플(Biome 포맷, 들여쓰기 있음). L1 시험은 파싱 후 JCS 로 직렬화한 바이트를 TS·Rust 가 비교한다 |

## 규칙

- Draft 2020-12. 최상위는 `$defs` 만. 파일 간 참조는 상대 `$ref`. `$defs` 키 PascalCase, 속성 snake_case. 판별 유니온은 `oneOf` + 각 가지에 `"kind": {"const": …}`(Rust `#[serde(tag = …)]`).
- 쓰는 키워드: type, properties, required, additionalProperties, enum, const, oneOf, $ref, $defs, items, minItems, minLength/maxLength, minimum, pattern, format(uuid, date-time), description. 쓰지 않음: if/then/else, allOf 상속, patternProperties, unevaluatedProperties, 재귀 anyOf.
- 크기 상한: 본문은 **UTF-8 바이트**(`constants.json`, 코어·서버가 검사). JSON Schema `maxLength` 는 코드 포인트라 500자 사유 상한에만 쓴다.
- 버전: 메시지 `v` 와 WS `hello.v` 는 **하나의 `PROTOCOL_VERSION`**(`schema/constants.json` — 현재 9: 1 = E2E 봉투 #313, 2 = 묶음 5 조직·이메일 가입, 3 = 묶음 14 메시지 동작, 4 = 묶음 15 파일·이미지, 5 = 묶음 16 그룹, 6 = 묶음 20 세션 공개 범위, 7 = 묶음 23 프로젝트 보이기, 8 = 묶음 22 MLS, 9 = #571 단계 B 이름 바꾸기 — 암호 태그·HTTP 머리). 와이어가 호환되지 않게 바뀔 때만 올린다.
- 서명 대상: `state`·`sig` 를 뺀 모든 필드를 JCS 로 직렬화(protocol §3). 서명 입력은 도메인 태그 `lodelai-msg-v1` ‖ 0x00 ‖ JCS 바이트. 인증은 `lodelai-auth-v1` ‖ 0x00 ‖ server ‖ 0x00 ‖ device_id ‖ 0x00 ‖ nonce 바이트(protocol §3 "와이어 인코딩 확정").
- 바이트 열은 base64url 패딩 없음. `device_id` = `k1_` + base64url(SHA-256(pubkey)[0..16)) 25자. `sig` 86자.
- 시각(`created_at`·`expires_at`·`requested_at`·`at`·`now`): RFC 3339 UTC **밀리초 3자리 고정** `YYYY-MM-DDTHH:MM:SS.mmmZ`(`crates/effects` `UnixMillis::to_rfc3339` 정규형, PR #75). 파싱은 오프셋·초 단위도 받되 다시 내보낼 때는 정규형만. 서명이 문자열 바이트에 걸리므로 형식이 하나여야 한다.
- typify 가 못 받는 타입은 손으로 쓴 serde + `jsonschema` 적합성 시험으로 폴백하고 `crates/protocol/README` 에 목록을 둔다(ADR 0002 예외, m1-plan U1). 현재 폴백 없음.
- 생성기 전처리(`crates/protocol-gen`): `format` 은 Rust 생성에서 지운다(`date-time` 이 chrono 가 되면 서명이 걸린 시각 문자열 바이트가 보존되지 않음 — 정규형 검사는 `pattern`). `const` 는 값 하나짜리 `enum` 으로 바꿔 넣는다(typify 0.8 은 `const` 를 `Value` 로 만들어 판별이 사라진다). 스키마 작성 규칙은 그대로다.
