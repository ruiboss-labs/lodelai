//! `device_id` = Ed25519 공개키 지문 (ADR 0006).
//!
//! 표기(protocol.md §3 와이어 인코딩): `k1_` + base64url(패딩 없음)(SHA-256(공개키 32바이트)[0..16)) — 25자.
//! 스키마 패턴 `^k1_[A-Za-z0-9_-]{22}$`. 서버는 등록된 공개키로 지문을 재계산해 대조한다.

use sha2::{Digest, Sha256};

use crate::encoding::{self, DEVICE_ID_PREFIX};
use crate::keys::VerifyingKey;

/// 기기 지문 문자열. 비교는 바이트 동일성.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(String);

impl DeviceId {
    /// 지문 전체 길이(접두 3 + base64url 22).
    pub const LEN: usize = 25;
    /// 해시에서 쓰는 앞 바이트 수.
    pub const DIGEST_BYTES: usize = 16;

    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let digest = Sha256::digest(vk.to_bytes());
        Self(format!(
            "{DEVICE_ID_PREFIX}{}",
            encoding::encode(&digest[..Self::DIGEST_BYTES])
        ))
    }

    /// 전송에서 받은 문자열을 검사해 받는다. 형식(접두·길이·base64url)이 맞아야 한다.
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix(DEVICE_ID_PREFIX)?;
        if s.len() != Self::LEN {
            return None;
        }
        let bytes = encoding::decode(rest, "device_id").ok()?;
        (bytes.len() == Self::DIGEST_BYTES).then(|| Self(s.to_owned()))
    }

    /// 공개키가 이 지문과 맞는지.
    pub fn matches(&self, vk: &VerifyingKey) -> bool {
        *self == Self::from_verifying_key(vk)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for DeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKeyPair;

    /// RFC 8032 TEST 1 공개키(d75a98…)의 지문. 바뀌면 안 된다.
    const GOLDEN_TEST1_DEVICE_ID: &str = "k1_If4x36FUomFia_hUBG_SJw";

    #[test]
    fn fingerprint_is_stable_and_prefixed() {
        // RFC 8032 TEST 1 공개키의 지문 — 바뀌면 등록된 기기 전부가 무효가 되므로 고정.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let vk = SigningKeyPair::from_seed(&seed).verifying_key();
        let id = DeviceId::from_verifying_key(&vk);
        assert_eq!(id.as_str().len(), DeviceId::LEN);
        assert!(id.as_str().starts_with("k1_"));
        // 골든: 이 값이 바뀌면 등록된 모든 기기의 device_id 가 달라진다
        assert_eq!(id.as_str(), GOLDEN_TEST1_DEVICE_ID);
        let expected_digest = sha2::Sha256::digest(vk.to_bytes());
        assert_eq!(
            id.as_str(),
            format!("k1_{}", encoding::encode(&expected_digest[..16]))
        );
        assert!(id.matches(&vk));
        assert_eq!(DeviceId::parse(id.as_str()), Some(id.clone()));
        assert!(!id.matches(&SigningKeyPair::from_seed(&[1u8; 32]).verifying_key()));
    }

    #[test]
    fn parse_rejects_bad_forms() {
        assert!(DeviceId::parse("").is_none());
        assert!(DeviceId::parse("k2_AAAAAAAAAAAAAAAAAAAAAA").is_none());
        assert!(DeviceId::parse("k1_AAAA").is_none());
        assert!(DeviceId::parse("k1_AAAAAAAAAAAAAAAAAAAA+/").is_none());
        assert!(DeviceId::parse("k1_AAAAAAAAAAAAAAAAAAAAAA=").is_none());
        assert!(DeviceId::parse("k1_AAAAAAAAAAAAAAAAAAAAAA").is_some());
    }
}
