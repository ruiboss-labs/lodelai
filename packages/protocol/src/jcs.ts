/**
 * JSON Canonicalization Scheme (RFC 8785) — `crates/crypto` `jcs` 와 같은 바이트를 만든다.
 *
 * ECMAScript `JSON.stringify` 의 원시값 직렬화가 곧 JCS 규칙(RFC 8785 §3.2.2)이므로, 객체 키를 UTF-16 코드 유닛 순
 * (JS 기본 정렬)으로 정렬하는 것만 더하면 된다. NaN·무한대·고립 서로게이트는 거부한다.
 */

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

export function canonicalize(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: NaN·무한대는 직렬화할 수 없다')
    return JSON.stringify(value)
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) throw new Error('JCS: 고립 서로게이트')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort()
    return `{${keys.map((k) => `${canonicalize(k)}:${canonicalize(obj[k])}`).join(',')}}`
  }
  throw new Error(`JCS: 지원하지 않는 값 ${typeof value}`)
}

const MESSAGE_DOMAIN = 'lodelai-msg-v1'
const EXCLUDED = new Set(['state', 'sig'])

/** 메시지 서명 입력: `lodelai-msg-v1` ‖ 0x00 ‖ JCS(`state`·`sig` 를 뺀 객체). protocol §3. */
export function signingPayload(message: Record<string, unknown>): Uint8Array<ArrayBuffer> {
  const filtered = Object.fromEntries(Object.entries(message).filter(([k]) => !EXCLUDED.has(k)))
  const body = new TextEncoder().encode(canonicalize(filtered))
  const tag = new TextEncoder().encode(MESSAGE_DOMAIN)
  const out = new Uint8Array(tag.length + 1 + body.length)
  out.set(tag, 0)
  out[tag.length] = 0
  out.set(body, tag.length + 1)
  return out
}
