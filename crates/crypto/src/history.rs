//! 새 기기에 지난 대화 옮기기(#881, ADR 0015)의 암호 조각 — 봉한 표·조각 키·offer 서명.
//!
//! - **봉한 표(ticket)**: 옮기기마다 뽑는 묶음 키 AK(32바이트)를 받을 기기의 X25519 공개키로만 열리게 봉한다. HPKE base
//!   모드(RFC 9180, DHKEM-X25519·HKDF-SHA256·ChaCha20Poly1305) — openmls 가 들여온 `hpke-rs` 를 그대로 쓴다(손으로 짜지
//!   않음). `info` 에 옮기기 id·보낸 기기·받을 기기를 묶어, 다른 옮기기·다른 기기 짝의 표로 바꿔 끼우면 안 열린다.
//!   꼴 = `enc(32) ‖ ct(32 + 16)`.
//! - **조각 키**: `HKDF-SHA256(AK, "lodelai-history-part-v1" ‖ idx(BE32))` — 조각마다 키가 달라 바꿔 끼우기·잘라 내기가
//!   인증에서 걸린다. 조각 본문 암호는 [`crate::blob`] (ADR 0009 STREAM) 그대로.
//! - **offer 서명**: HPKE base 는 보낸 쪽을 증명하지 않고, offer 가 오는 길(own_stream)의 '보낸 기기'는 relay 가 붙인
//!   값이다. 디스크에 남는 글을 들이는 길이라 보낸 기기의 Ed25519(ADR 0006)로 묶는다 — 받는 쪽은 **신뢰 사슬로 확인한**
//!   그 기기 키로 검증한다(relay 디렉터리가 준 키를 그대로 믿지 않는다).

use hkdf::Hkdf;
use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::encoding::{decode_array, encode};
use crate::keys::{ExchangeKeyPair, SigningKeyPair, VerifyingKey};

/// 표의 HPKE info 도메인 태그.
pub const TAG_TICKET: &str = "lodelai-history-v1";
/// 조각 키 HKDF info 앞머리.
pub const TAG_PART: &str = "lodelai-history-part-v1";
/// offer 서명 도메인 태그.
pub const TAG_OFFER: &str = "lodelai-history-offer-v1";
/// 묶음 키 길이.
pub const AK_LEN: usize = 32;
/// 표 길이 = enc 32 + 암호문 32 + 태그 16.
pub const TICKET_LEN: usize = 32 + AK_LEN + 16;

fn hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// 표의 HPKE info: `lodelai-history-v1 ‖ 0x00 ‖ transfer_id ‖ 0x00 ‖ from_device ‖ 0x00 ‖ to_device`.
/// 세 값은 ULID·device_id(ASCII, 0x00 없음)라 경계가 섞이지 않는다.
#[must_use]
pub fn ticket_info(transfer_id: &str, from_device: &str, to_device: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        TAG_TICKET.len() + transfer_id.len() + from_device.len() + to_device.len() + 3,
    );
    for (i, part) in [TAG_TICKET, transfer_id, from_device, to_device]
        .iter()
        .enumerate()
    {
        if i > 0 {
            v.push(0);
        }
        v.extend_from_slice(part.as_bytes());
    }
    v
}

/// AK 를 받을 기기의 X25519 공개키로 봉한다. 실패(공개키가 낮은 차수 점 등)면 `None`.
#[must_use]
pub fn seal_ticket(ak: &[u8; AK_LEN], to_x25519: &[u8; 32], info: &[u8]) -> Option<Vec<u8>> {
    let (enc, ct) = hpke()
        .seal(
            &HpkePublicKey::new(to_x25519.to_vec()),
            info,
            &[],
            ak,
            None,
            None,
            None,
        )
        .ok()?;
    let mut out = Vec::with_capacity(TICKET_LEN);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    (out.len() == TICKET_LEN).then_some(out)
}

/// 내 X25519 비밀키로 표를 연다. 길이·info·키가 하나라도 다르면 `None`.
#[must_use]
pub fn open_ticket(
    ticket: &[u8],
    mine: &ExchangeKeyPair,
    info: &[u8],
) -> Option<Zeroizing<[u8; AK_LEN]>> {
    if ticket.len() != TICKET_LEN {
        return None;
    }
    let (enc, ct) = ticket.split_at(32);
    let sk = HpkePrivateKey::new(mine.seed().to_vec());
    let pt = Zeroizing::new(
        hpke()
            .open(enc, &sk, info, &[], ct, None, None, None)
            .ok()?,
    );
    let mut ak = Zeroizing::new([0u8; AK_LEN]);
    if pt.len() != AK_LEN {
        return None;
    }
    ak.copy_from_slice(&pt);
    Some(ak)
}

/// 조각 `idx` 의 본문 키.
#[must_use]
pub fn part_key(ak: &[u8; AK_LEN], idx: u32) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(TAG_PART.len() + 4);
    info.extend_from_slice(TAG_PART.as_bytes());
    info.extend_from_slice(&idx.to_be_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    // 32바이트는 HKDF-SHA256 출력 상한(255 × 32) 안 — 실패할 수 없다.
    let _ = Hkdf::<Sha256>::new(None, ak).expand(&info, key.as_mut());
    key
}

/// offer 서명 입력: `lodelai-history-offer-v1` 뒤에 칸마다 `길이(BE32) ‖ 바이트` — transfer_id · 보낸 기기 · 받을 기기 ·
/// 표 · plan(보내는 쪽이 정한 바이트 그대로). 길이를 앞에 붙여 칸 경계가 섞이지 않는다.
#[must_use]
pub fn offer_payload(
    transfer_id: &str,
    from_device: &str,
    to_device: &str,
    ticket: &[u8],
    plan: &[u8],
) -> Vec<u8> {
    let fields: [&[u8]; 5] = [
        transfer_id.as_bytes(),
        from_device.as_bytes(),
        to_device.as_bytes(),
        ticket,
        plan,
    ];
    let mut v =
        Vec::with_capacity(TAG_OFFER.len() + fields.iter().map(|f| f.len() + 4).sum::<usize>());
    v.extend_from_slice(TAG_OFFER.as_bytes());
    for f in fields {
        // 칸은 모두 작다(표 80바이트, plan 수백 바이트) — u32 를 넘지 않는다.
        v.extend_from_slice(&u32::try_from(f.len()).unwrap_or(u32::MAX).to_be_bytes());
        v.extend_from_slice(f);
    }
    v
}

/// 보낸 기기가 offer 에 하는 서명(base64url).
#[must_use]
pub fn sign_offer(signing: &SigningKeyPair, payload: &[u8]) -> String {
    encode(&signing.sign(payload))
}

/// offer 서명 검증 — `signer` 는 호출자가 신뢰 사슬로 확인한 그 기기의 Ed25519.
#[must_use]
pub fn verify_offer(signer: &VerifyingKey, payload: &[u8], sig: &str) -> bool {
    let Ok(bytes) = decode_array::<64>(sig, "history_offer.sig") else {
        return false;
    };
    signer.verify(payload, &bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 9180 A.2.1(DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, base) — 봉함은 임시 키가 무작위라
    /// 공개 벡터와 맞출 수 없으니 **열기** 쪽으로 대조한다(같은 수트·같은 구현이 표를 연다).
    #[test]
    fn rfc_9180_a_2_1_열기_벡터() {
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let sk_r = h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let pk_r = h("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let enc = h("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let ct = h(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
        );
        let got = hpke()
            .open(
                &enc,
                &HpkePrivateKey::new(sk_r.clone()),
                &info,
                b"Count-0",
                &ct,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(got, pt);
        // 우리 키 꼴(ExchangeKeyPair 의 seed)이 HPKE 의 skR·pkR 과 같은 바이트다.
        let mine = ExchangeKeyPair::from_seed(&sk_r.try_into().unwrap());
        assert_eq!(mine.public_key().to_vec(), pk_r);
    }

    #[test]
    fn 표는_받을_기기만_같은_info_로만_연다() {
        let to = ExchangeKeyPair::from_seed(&[7u8; 32]);
        let other = ExchangeKeyPair::from_seed(&[8u8; 32]);
        let ak = [0x5au8; AK_LEN];
        let info = ticket_info("01JTRANSFER", "k1_from", "k1_to");
        let ticket = seal_ticket(&ak, &to.public_key(), &info).unwrap();
        assert_eq!(ticket.len(), TICKET_LEN);
        assert_eq!(*open_ticket(&ticket, &to, &info).unwrap(), ak);
        // 다른 내 기기는 못 연다.
        assert!(open_ticket(&ticket, &other, &info).is_none());
        // 옮기기 id·보낸 기기·받을 기기 중 하나라도 다르면 못 연다.
        for bad in [
            ticket_info("01JOTHER", "k1_from", "k1_to"),
            ticket_info("01JTRANSFER", "k1_evil", "k1_to"),
            ticket_info("01JTRANSFER", "k1_from", "k1_other"),
        ] {
            assert!(open_ticket(&ticket, &to, &bad).is_none());
        }
        // 한 바이트라도 바뀌면·길이가 다르면 못 연다.
        let mut t = ticket.clone();
        t[40] ^= 1;
        assert!(open_ticket(&t, &to, &info).is_none());
        assert!(open_ticket(&ticket[..TICKET_LEN - 1], &to, &info).is_none());
        // 봉할 때마다 다르다(임시 키).
        assert_ne!(seal_ticket(&ak, &to.public_key(), &info).unwrap(), ticket);
    }

    #[test]
    fn info_고정_꼴() {
        assert_eq!(
            ticket_info("T", "A", "B"),
            b"lodelai-history-v1\0T\0A\0B".to_vec()
        );
    }

    /// 조각 키 고정 벡터 — 따로 계산한 HKDF-SHA256(salt 없음, ikm = 00..1f, info = 태그 ‖ idx BE32).
    #[test]
    fn 조각_키_고정_벡터() {
        let ak: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        for (idx, want) in [
            (
                0u32,
                "9f0fa6c8aed02b9a2202f4de78231d1b7544693de8f3f2faefd5aea5e222a387",
            ),
            (
                1,
                "1ecb751bd201ff3fb0eacb940392dbb41ae2b8c00327a4d1b82075ac80223037",
            ),
            (
                7,
                "2133237e7c0aaf8dec20f7375be9c405bcadc927d011dbcb98a246e45c078e29",
            ),
        ] {
            assert_eq!(hex::encode(*part_key(&ak, idx)), want, "idx {idx}");
        }
    }

    #[test]
    fn offer_서명은_칸_하나라도_바뀌면_틀린다() {
        let signer = SigningKeyPair::from_seed(&[3u8; 32]);
        let other = SigningKeyPair::from_seed(&[4u8; 32]);
        let p = offer_payload("T1", "from", "to", b"ticket", b"plan");
        // 고정 꼴: 태그 뒤 길이 앞붙임.
        let mut want = TAG_OFFER.as_bytes().to_vec();
        for f in [&b"T1"[..], b"from", b"to", b"ticket", b"plan"] {
            want.extend_from_slice(&u32::try_from(f.len()).unwrap().to_be_bytes());
            want.extend_from_slice(f);
        }
        assert_eq!(p, want);
        let sig = sign_offer(&signer, &p);
        assert!(verify_offer(&signer.verifying_key(), &p, &sig));
        assert!(!verify_offer(&other.verifying_key(), &p, &sig));
        // 칸 경계를 옮겨도(같은 이은 바이트) 다른 입력이다.
        for bad in [
            offer_payload("T", "1from", "to", b"ticket", b"plan"),
            offer_payload("T1", "from", "to", b"ticketp", b"lan"),
            offer_payload("T1", "from", "to2", b"ticket", b"plan"),
        ] {
            assert!(!verify_offer(&signer.verifying_key(), &bad, &sig));
        }
        assert!(!verify_offer(&signer.verifying_key(), &p, "x"));
        assert!(!verify_offer(&signer.verifying_key(), &p, ""));
    }
}
