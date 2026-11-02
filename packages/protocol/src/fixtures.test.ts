/**
 * L1 (U1 완료 기준) TS 쪽. Rust(`crates/protocol/tests/fixtures.rs`)가 재서명한 fixtures 의 `sig` 를
 * 이 패키지의 JCS 로 만든 서명 입력으로 검증한다 — 두 언어의 JCS 바이트가 같아야만 통과한다.
 */
import { expect, test } from 'bun:test'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { canonicalize, PROTOCOL_VERSION, signingPayload } from './index.ts'

const dir = join(import.meta.dir, '..', 'fixtures')
const keys = JSON.parse(readFileSync(join(dir, 'keys.json'), 'utf8')) as Record<
  string,
  { device_id: string; ed25519: string }
>
const fixtures = readdirSync(dir)
  .filter((f) => f.endsWith('.json') && f !== 'keys.json')
  .sort()
  .map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8')) as Record<string, unknown>] as const)

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url')
}

test('프로토콜 버전은 생성 상수', () => {
  expect(PROTOCOL_VERSION).toBe(13)
})

test('JCS: RFC 8785 §3.2 예제', () => {
  const input = JSON.parse(
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
  )
  expect(canonicalize(input)).toBe(
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
  )
})

test('JCS: RFC 8785 §3.2.3 키 정렬(UTF-16 코드 유닛)', () => {
  const input = JSON.parse(
    '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
  )
  // 다시 JSON.parse 하면 JS 가 정수형 키("1")를 앞으로 옮기므로 문자열 그대로 비교한다.
  expect(canonicalize(input)).toBe(
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
  )
})

test('JCS: NaN·고립 서로게이트 거부', () => {
  expect(() => canonicalize(Number.NaN)).toThrow()
  expect(() => canonicalize('\ud800')).toThrow()
})

test('fixtures 가 비지 않았다', () => {
  expect(fixtures.length).toBeGreaterThanOrEqual(7)
})

for (const [name, m] of fixtures) {
  test(`fixture ${name}: device_id 지문과 sig 가 TS JCS 로 검증된다`, async () => {
    const from = m.from as { address: string; device_id: string }
    const user = from.address.split('@')[0] ?? ''
    const k = keys[user]
    expect(k).toBeDefined()
    if (!k) return
    const pk = b64urlDecode(k.ed25519)
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', pk))
    expect(from.device_id).toBe(`k1_${b64urlEncode(digest.slice(0, 16))}`)
    const key = await crypto.subtle.importKey('raw', pk, { name: 'Ed25519' }, false, ['verify'])
    const ok = await crypto.subtle.verify('Ed25519', key, b64urlDecode(m.sig as string), signingPayload(m))
    expect(ok).toBe(true)
    // 한 바이트라도 바뀌면 실패
    const tampered = { ...m, kind: m.kind === 'reply' ? 'rejected' : 'reply' }
    expect(await crypto.subtle.verify('Ed25519', key, b64urlDecode(m.sig as string), signingPayload(tampered))).toBe(
      false,
    )
  })
}
