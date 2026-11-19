/**
 * 첨부 blob 독립 구현 교차 검증(묶음 15 §1, ADR 0009 §2).
 *
 * Rust(`crates/crypto` blob — RustCrypto aead::stream EncryptorBE32)가 만든 `fixtures/e2e/blob-vectors.json` 을 libsodium
 * 조각 단위 XChaCha20-Poly1305 로 **같은 입력에서 다시 만들어** 길이·SHA-256(작은 경우는 바이트 전체)이 같은지, 그리고 여는지 본다.
 * nonce 식(prefix 19B ‖ BE32 조각 번호 ‖ last 플래그)과 도메인 태그는 Rust 와 따로 적는다 — 한쪽 오타가 실패로 드러나게.
 * 벡터를 다시 만들려면 `LODELAI_REGEN_E2E_VECTORS=1 cargo test -p lodelai-crypto --test blob`.
 */
import { beforeAll, expect, test } from 'bun:test'
import sodium from 'libsodium-wrappers'
import vectors from '../fixtures/e2e/blob-vectors.json'

const enc = new TextEncoder()
const CHUNK = 65536

beforeAll(async () => {
  await sodium.ready
})

const hex = (b: Uint8Array) => sodium.to_hex(b)
const unhex = (s: string) => sodium.from_hex(s)
const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(b)))

function plain(n: number): Uint8Array {
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i++) out[i] = i % 251
  return out
}

function nonce(prefix: Uint8Array, counter: number, last: boolean): Uint8Array {
  const n = new Uint8Array(24)
  n.set(prefix, 0)
  new DataView(n.buffer).setUint32(19, counter, false)
  n[23] = last ? 1 : 0
  return n
}

function aad(blobId: string): Uint8Array {
  const tag = enc.encode('lodelai-blob-v1')
  const id = enc.encode(blobId)
  const out = new Uint8Array(tag.length + 1 + id.length)
  out.set(tag, 0)
  out.set(id, tag.length + 1)
  return out
}

/** 평문을 64 KiB 조각으로 — 빈 평문은 빈 마지막 조각 하나. */
function seal(fk: Uint8Array, prefix: Uint8Array, blobId: string, pt: Uint8Array): Uint8Array {
  const count = Math.max(1, Math.ceil(pt.length / CHUNK))
  const parts: Uint8Array[] = []
  for (let i = 0; i < count; i++) {
    const chunk = pt.subarray(i * CHUNK, Math.min(pt.length, (i + 1) * CHUNK))
    parts.push(
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        chunk,
        aad(blobId),
        null,
        nonce(prefix, i, i === count - 1),
        fk,
      ),
    )
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function open(fk: Uint8Array, prefix: Uint8Array, blobId: string, ct: Uint8Array): Uint8Array {
  const size = CHUNK + 16
  const count = Math.max(1, Math.ceil(ct.length / size))
  const parts: Uint8Array[] = []
  for (let i = 0; i < count; i++) {
    const chunk = ct.subarray(i * size, Math.min(ct.length, (i + 1) * size))
    parts.push(
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        chunk,
        aad(blobId),
        nonce(prefix, i, i === count - 1),
        fk,
      ),
    )
  }
  return parts.reduce((acc, p) => {
    const out = new Uint8Array(acc.length + p.length)
    out.set(acc, 0)
    out.set(p, acc.length)
    return out
  }, new Uint8Array(0))
}

test('Rust blob 벡터를 libsodium 조각 암호화로 다시 만들고 연다', async () => {
  const fk = unhex(vectors.fk)
  const prefix = unhex(vectors.prefix)
  expect(vectors.chunk).toBe(CHUNK)
  expect(vectors.cases.length).toBeGreaterThan(4)
  for (const c of vectors.cases) {
    const pt = plain(c.n)
    const ct = seal(fk, prefix, vectors.blob_id, pt)
    expect(ct.length).toBe(c.ct_len)
    expect(hex(await sha256(ct))).toBe(c.ct_sha256)
    if ('ct' in c && c.ct) expect(hex(ct)).toBe(c.ct)
    expect(open(fk, prefix, vectors.blob_id, ct)).toEqual(pt)
  }
})

test('잘린 blob·다른 blob_id 는 열리지 않는다', () => {
  const fk = unhex(vectors.fk)
  const prefix = unhex(vectors.prefix)
  const ct = seal(fk, prefix, vectors.blob_id, plain(2 * CHUNK + 3))
  expect(() => open(fk, prefix, vectors.blob_id, ct.subarray(0, 2 * (CHUNK + 16)))).toThrow()
  expect(() => open(fk, prefix, 'b_other', ct)).toThrow()
})
