//! 기기 키쌍. Ed25519(서명·인증) + X25519(M2 E2E 봉투). ADR 0003·0006.
//!
//! 난수는 이 크레이트가 만들지 않는다. 호출자가 32바이트 시드를 넣는다(`effects::Rng::fill` 등).
//! 비밀 바이트는 drop 시 0 으로 지운다.

use ed25519_dalek::Signer;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding;
use crate::{Error, Result};

/// Ed25519 서명 64바이트.
pub type SignatureBytes = [u8; 64];

/// Ed25519 공개키(검증 전용). 상대 기기·서버가 보관하는 쪽.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// 32바이트 공개키에서. 곡선 위 점이 아니면 오류.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::BadEncoding {
                what: "verifying key",
            })
    }

    /// base64url(패딩 없음) 표기에서.
    pub fn from_b64(s: &str) -> Result<Self> {
        Self::from_bytes(&encoding::decode_array::<32>(s, "verifying key")?)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_b64(&self) -> String {
        encoding::encode(&self.to_bytes())
    }

    /// 서명 검증. `verify_strict` — 약한 키·비정규 S 를 거부(libsodium 과 같은 쪽으로 엄격).
    pub fn verify(&self, msg: &[u8], sig: &SignatureBytes) -> Result<()> {
        let sig = ed25519_dalek::Signature::from_bytes(sig);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| Error::BadSignature)
    }
}

/// Ed25519 서명 키쌍.
#[derive(Clone)]
pub struct SigningKeyPair(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKeyPair")
            .field(&self.verifying_key().to_b64())
            .finish()
    }
}

impl SigningKeyPair {
    /// RFC 8032 의 32바이트 비밀키(시드)에서.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        self.0.sign(msg).to_bytes()
    }
}

/// X25519 교환 키쌍(M2 E2E 봉투용. M1 에서는 생성·등록만).
#[derive(Clone)]
pub struct ExchangeKeyPair(x25519_dalek::StaticSecret);

impl std::fmt::Debug for ExchangeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ExchangeKeyPair")
            .field(&encoding::encode(&self.public_key()))
            .finish()
    }
}

impl ExchangeKeyPair {
    /// RFC 7748 의 32바이트 비밀키에서(클램핑은 내부에서).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(*seed))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }

    /// 공유 비밀 X25519(a, K_B). 전부 0 이면(소차수 점) `None`.
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = self
            .0
            .diffie_hellman(&x25519_dalek::PublicKey::from(*their_public));
        shared.was_contributory().then(|| shared.to_bytes())
    }
}

/// 기기 키 비밀 — 저장소에 들어가는 형태. 두 시드 64바이트.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DeviceSecret {
    pub signing_seed: [u8; 32],
    pub exchange_seed: [u8; 32],
}

impl DeviceSecret {
    pub const LEN: usize = 64;

    /// 호출자가 채운 64바이트 난수에서(앞 32 = 서명, 뒤 32 = 교환).
    pub fn from_random(random: &[u8; 64]) -> Self {
        let mut signing_seed = [0u8; 32];
        let mut exchange_seed = [0u8; 32];
        signing_seed.copy_from_slice(&random[..32]);
        exchange_seed.copy_from_slice(&random[32..]);
        Self {
            signing_seed,
            exchange_seed,
        }
    }

    /// 저장 바이트(64). Keychain·메모리 저장소가 이 형태로 보관한다. 복사본은 drop 시 지워진다.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.signing_seed);
        out[32..].copy_from_slice(&self.exchange_seed);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: &[u8; 64] = bytes.try_into().map_err(|_| Error::BadEncoding {
            what: "device secret",
        })?;
        Ok(Self::from_random(arr))
    }
}

impl std::fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceSecret(..)")
    }
}

/// 기기 키 전체(서명 + 교환 + 지문). 앱 코어가 들고 있는 형태.
#[derive(Clone, Debug)]
pub struct DeviceKeys {
    pub signing: SigningKeyPair,
    pub exchange: ExchangeKeyPair,
}

impl DeviceKeys {
    pub fn from_secret(secret: &DeviceSecret) -> Self {
        Self {
            signing: SigningKeyPair::from_seed(&secret.signing_seed),
            exchange: ExchangeKeyPair::from_seed(&secret.exchange_seed),
        }
    }

    /// 호출자가 채운 64바이트 난수에서 새 기기 키를 만든다.
    pub fn generate(random: &[u8; 64]) -> Self {
        Self::from_secret(&DeviceSecret::from_random(random))
    }

    pub fn to_secret(&self) -> DeviceSecret {
        DeviceSecret {
            signing_seed: self.signing.seed(),
            exchange_seed: self.exchange.seed(),
        }
    }

    pub fn device_id(&self) -> crate::DeviceId {
        crate::DeviceId::from_verifying_key(&self.signing.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn rfc8032_ed25519_vectors() {
        // RFC 8032 §7.1 TEST 1·2·3
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (sk, pk, msg, sig) in cases {
            let kp = SigningKeyPair::from_seed(&h32(sk));
            assert_eq!(hex::encode(kp.verifying_key().to_bytes()), pk);
            let msg = hex::decode(msg).unwrap();
            let s = kp.sign(&msg);
            assert_eq!(hex::encode(s), sig);
            kp.verifying_key().verify(&msg, &s).unwrap();
            let mut bad = s;
            bad[0] ^= 1;
            assert!(kp.verifying_key().verify(&msg, &bad).is_err());
        }
    }

    #[test]
    fn rfc7748_x25519_vector() {
        // RFC 7748 §6.1
        let alice = ExchangeKeyPair::from_seed(&h32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = ExchangeKeyPair::from_seed(&h32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            hex::encode(alice.public_key()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex::encode(bob.public_key()),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(
            hex::encode(alice.diffie_hellman(&bob.public_key()).unwrap()),
            k
        );
        assert_eq!(
            hex::encode(bob.diffie_hellman(&alice.public_key()).unwrap()),
            k
        );
        // 소차수 점(0) 은 거부
        assert!(alice.diffie_hellman(&[0u8; 32]).is_none());
    }

    #[test]
    fn device_secret_round_trip() {
        let mut random = [0u8; 64];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }
        let keys = DeviceKeys::generate(&random);
        let secret = keys.to_secret();
        assert_eq!(*secret.to_bytes(), random);
        let again =
            DeviceKeys::from_secret(&DeviceSecret::from_bytes(&*secret.to_bytes()).unwrap());
        assert_eq!(again.device_id(), keys.device_id());
        assert_eq!(again.exchange.public_key(), keys.exchange.public_key());
        assert!(DeviceSecret::from_bytes(&random[..63]).is_err());
    }

    #[test]
    fn verifying_key_b64_round_trip_and_rejects_bad() {
        let kp = SigningKeyPair::from_seed(&[7u8; 32]);
        let vk = kp.verifying_key();
        assert_eq!(VerifyingKey::from_b64(&vk.to_b64()).unwrap(), vk);
        assert!(VerifyingKey::from_b64("not base64!").is_err());
        assert!(VerifyingKey::from_b64(&encoding::encode(&[1u8; 31])).is_err());
    }
}
