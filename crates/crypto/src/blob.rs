//! 첨부 파일 암호문(blob, ADR 0009 §2, 묶음 15 `docs/design/bundle-15-files.md` §1).
//!
//! 파일 하나를 무작위 파일 키(FK)로 STREAM 암호화한다. 파일 전체를 메모리에 올리지 않는다.
//!
//! ```text
//! 조각      = 평문 65 536 바이트씩(마지막 조각은 짧거나 비어도 된다 — 빈 파일은 빈 마지막 조각 하나)
//! nonce     = prefix(19B) ‖ BE32 조각 번호 ‖ last(0x00 | 0x01)      RustCrypto aead::stream EncryptorBE32
//! 조각 암호 = XChaCha20-Poly1305(FK, nonce, 조각, AAD)
//! AAD       = lodelai-blob-v1 ‖ 0x00 ‖ blob_id
//! 암호문    = 조각 암호를 이어 붙인 것. 길이 = n + 16 × ceil(max(n,1) / 65 536)
//! ```
//!
//! FK·prefix 는 호출자가 넣는다(이 크레이트는 난수를 만들지 않는다 — 시험 벡터가 결정적이어야 한다). 받는 쪽은 암호문의
//! SHA-256(보낸 쪽이 봉투 본문에 싣는 값)을 읽으면서 계산해 끝에서 상수 시간으로 비교한다. 실패하면 이미 쓴 출력은
//! 호출자가 버린다(임시 파일에 쓰고 맞을 때만 옮김).

use std::io::{Read, Write};

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::encoding::domain_separated;

/// AAD 도메인 태그.
pub const TAG_BLOB: &str = "lodelai-blob-v1";
/// 평문 조각 크기.
pub const CHUNK: usize = 65_536;
/// 조각마다 붙는 AEAD 태그.
pub const TAG_LEN: usize = 16;

/// blob 오류.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob 입출력: {0}")]
    Io(#[from] std::io::Error),
    /// 조각 인증 실패(변조·순서 바뀜·잘림·다른 blob_id·다른 키).
    #[error("blob 복호화 실패")]
    Decrypt,
    /// 암호문 SHA-256 이 기대와 다르다.
    #[error("blob 해시 불일치")]
    Hash,
    #[error("blob 암호화 실패")]
    Encrypt,
}

/// 평문 `n` 바이트의 암호문 길이(relay 예약 크기 검사·relay-client 공용).
#[must_use]
pub fn blob_ct_len(n: u64) -> u64 {
    let chunk = CHUNK as u64;
    n + TAG_LEN as u64 * n.max(1).div_ceil(chunk)
}

fn aad(blob_id: &str) -> Vec<u8> {
    domain_separated(TAG_BLOB, blob_id.as_bytes())
}

/// `r` 에서 `len` 바이트까지(끝이면 짧게) 읽는다.
fn read_up_to(r: &mut impl Read, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len);
    r.take(len as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// 평문을 읽어 암호문을 쓴다. 돌려주는 값: (암호문 길이, 암호문 SHA-256).
///
/// # Errors
/// 입출력 오류.
pub fn seal_blob(
    fk: &[u8; 32],
    prefix: &[u8; 19],
    blob_id: &str,
    mut plain: impl Read,
    mut out: impl Write,
) -> Result<(u64, [u8; 32]), BlobError> {
    let aead = XChaCha20Poly1305::new(fk.into());
    let mut enc = EncryptorBE32::from_aead(aead, prefix.into());
    let aad = aad(blob_id);
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut cur = read_up_to(&mut plain, CHUNK)?;
    loop {
        let next = if cur.len() == CHUNK {
            read_up_to(&mut plain, CHUNK)?
        } else {
            Vec::new()
        };
        // 이번 조각이 가득 찼고 뒤가 더 있으면 중간 조각, 아니면 마지막.
        if cur.len() == CHUNK && !next.is_empty() {
            let ct = enc
                .encrypt_next(Payload {
                    msg: &cur,
                    aad: &aad,
                })
                .map_err(|_| BlobError::Encrypt)?;
            hash.update(&ct);
            out.write_all(&ct)?;
            total += ct.len() as u64;
            cur = next;
        } else {
            let ct = enc
                .encrypt_last(Payload {
                    msg: &cur,
                    aad: &aad,
                })
                .map_err(|_| BlobError::Encrypt)?;
            hash.update(&ct);
            out.write_all(&ct)?;
            total += ct.len() as u64;
            out.flush()?;
            return Ok((total, hash.finalize().into()));
        }
    }
}

/// 암호문을 읽어 평문을 쓴다. 돌려주는 값: 평문 길이. 암호문 SHA-256 이 `expect_sha256` 과 다르거나 조각 인증이 실패하면
/// 오류 — 그때까지 쓴 출력은 호출자가 버린다.
///
/// # Errors
/// 입출력 오류, [`BlobError::Decrypt`], [`BlobError::Hash`].
pub fn open_blob(
    fk: &[u8; 32],
    prefix: &[u8; 19],
    blob_id: &str,
    mut ct: impl Read,
    expect_sha256: &[u8; 32],
    mut out: impl Write,
) -> Result<u64, BlobError> {
    let aead = XChaCha20Poly1305::new(fk.into());
    let mut dec = DecryptorBE32::from_aead(aead, prefix.into());
    let aad = aad(blob_id);
    let size = CHUNK + TAG_LEN;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut cur = read_up_to(&mut ct, size)?;
    hash.update(&cur);
    let result = loop {
        let next = if cur.len() == size {
            read_up_to(&mut ct, size)?
        } else {
            Vec::new()
        };
        hash.update(&next);
        if cur.len() == size && !next.is_empty() {
            match dec.decrypt_next(Payload {
                msg: &cur,
                aad: &aad,
            }) {
                Ok(pt) => {
                    out.write_all(&pt)?;
                    total += pt.len() as u64;
                    cur = next;
                }
                Err(_) => break Err(BlobError::Decrypt),
            }
        } else {
            break match dec.decrypt_last(Payload {
                msg: &cur,
                aad: &aad,
            }) {
                Ok(pt) => {
                    out.write_all(&pt)?;
                    Ok(total + pt.len() as u64)
                }
                Err(_) => Err(BlobError::Decrypt),
            };
        }
    };
    // 인증 실패여도 남은 암호문을 다 읽어 해시를 끝낸다 — 해시 불일치가 먼저 보이게(받은 바이트 자체가 틀렸다).
    std::io::copy(&mut ct, &mut HashWriter(&mut hash))?;
    let got: [u8; 32] = hash.finalize().into();
    if !bool::from(got.ct_eq(expect_sha256)) {
        return Err(BlobError::Hash);
    }
    let n = result?;
    out.flush()?;
    Ok(n)
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FK: [u8; 32] = [0x11; 32];
    const PREFIX: [u8; 19] = [0x22; 19];
    const ID: &str = "b_0123456789abcdefghij";

    fn seal(plain: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let mut out = Vec::new();
        let (n, h) = seal_blob(&FK, &PREFIX, ID, plain, &mut out).unwrap();
        assert_eq!(n as usize, out.len());
        assert_eq!(n, blob_ct_len(plain.len() as u64));
        (out, h)
    }

    fn open(ct: &[u8], h: &[u8; 32], id: &str) -> Result<Vec<u8>, BlobError> {
        let mut out = Vec::new();
        open_blob(&FK, &PREFIX, id, ct, h, &mut out)?;
        Ok(out)
    }

    fn rehash(ct: &[u8]) -> [u8; 32] {
        Sha256::digest(ct).into()
    }

    #[test]
    fn 조각_경계에서_왕복한다() {
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7] {
            let plain: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let (ct, h) = seal(&plain);
            assert_eq!(open(&ct, &h, ID).unwrap(), plain, "n={n}");
        }
        assert_eq!(blob_ct_len(0), 16);
        assert_eq!(blob_ct_len(CHUNK as u64), CHUNK as u64 + 16);
        assert_eq!(blob_ct_len(CHUNK as u64 + 1), CHUNK as u64 + 1 + 32);
    }

    #[test]
    fn 변조는_모두_실패한다() {
        let plain: Vec<u8> = (0..3 * CHUNK + 5).map(|i| (i % 253) as u8).collect();
        let (ct, h) = seal(&plain);
        let size = CHUNK + TAG_LEN;

        // 해시를 맞춰 줘도(공격자가 해시까지 바꿈) AEAD 가 막는다.
        let mut flipped = ct.clone();
        flipped[size + 3] ^= 1;
        assert!(matches!(
            open(&flipped, &rehash(&flipped), ID),
            Err(BlobError::Decrypt)
        ));
        // 해시를 안 바꾸면 해시 불일치가 먼저.
        assert!(matches!(open(&flipped, &h, ID), Err(BlobError::Hash)));

        let mut swapped = ct[size..2 * size].to_vec();
        swapped.extend_from_slice(&ct[..size]);
        swapped.extend_from_slice(&ct[2 * size..]);
        assert!(matches!(
            open(&swapped, &rehash(&swapped), ID),
            Err(BlobError::Decrypt)
        ));

        let cut = &ct[..3 * size];
        assert!(matches!(
            open(cut, &rehash(cut), ID),
            Err(BlobError::Decrypt)
        ));

        assert!(matches!(open(&ct, &h, "b_other"), Err(BlobError::Decrypt)));

        let (empty, eh) = seal(&[]);
        assert!(matches!(
            open(&empty[..15], &rehash(&empty[..15]), ID),
            Err(BlobError::Decrypt)
        ));
        assert_eq!(open(&empty, &eh, ID).unwrap(), Vec::<u8>::new());
    }
}
