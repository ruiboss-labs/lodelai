/**
 * lodelai 프로토콜 타입.
 *
 * 원본은 `schema/` 의 JSON Schema 다(ADR 0002). `generated/` 는 `bun run protocol:gen` 생성물이고 손으로 고치지 않는다.
 * 스키마 파일마다 네임스페이스 하나 — 이름이 같은 정의가 파일끼리 충돌하지 않는다.
 * Rust 쪽은 `crates/protocol` 의 같은 이름 모듈이다.
 */
export * as constants from './generated/constants.ts'
export { PROTOCOL_VERSION } from './generated/constants.ts'
export * as message from './generated/message.ts'
export * as states from './generated/states.ts'
export * as ws from './generated/ws.ts'
export { canonicalize, signingPayload } from './jcs.ts'
