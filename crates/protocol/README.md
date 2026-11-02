# lodelai-protocol

프로토콜 타입. 원본은 `packages/protocol/schema/*.schema.json`, `src/generated/` 는 `crates/protocol-gen` 생성물이다(손으로 고치지 않는다). 다시 만들기: 레포 루트에서 `bun run protocol:gen`.

## 모듈

| 모듈 | 원본 | 비고 |
|---|---|---|
| `message` | `message.schema.json` | `Message`(kind), `Body`(enc), 주소·ID newtype |
| `ws` | `ws.schema.json` | `Frame`(t) |
| `states` | (re-export) | `lodelai-statechart` 의 enum. 정의는 statechart 한 곳 |
| `constants` | `constants.json` | `PROTOCOL_VERSION` 등 |

## 생성 결과의 성질 (typify =0.8.0)

- **판별 유니온은 `#[serde(untagged)]`** 로 나온다. 각 가지의 판별 필드(`kind`·`t`·`enc`)가 값 하나짜리 enum 이라 다른 가지로 잘못 읽히지 않는다(필드가 같은 `ReplyMessage`·`RejectedMessage` 도 `kind` 로 갈린다 — 시험 있음). 대신 실패 메시지가 "did not match any variant" 로 뭉뚱그려진다.
- `pattern`·길이 제약이 있는 문자열은 **검사하는 newtype**(`TryFrom<String>`, 역직렬화 때 검사). 같은 패턴이라도 속성마다 따로 생긴다(`ChatMessageCreatedAt` 등) — 스키마에서 공용 `$defs` 로 묶으면 하나가 된다.
- `additionalProperties: false` → `deny_unknown_fields`.
- 다른 파일 정의는 복제하지 않고 `super::<모듈>::X` 로 잇는다.
- 손으로 쓴 폴백 타입: **없음**.
