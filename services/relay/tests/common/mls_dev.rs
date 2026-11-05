//! 시험 공용 MLS 기기(openmls) — mls.rs·relay.rs 가 같이 쓴다(#488).

use lodelai_crypto::{encoding, DeviceKeys};
use lodelai_relay_client::mls::{create_config, DeviceSigner, Kind, CIPHERSUITE, EXT_LODELAI};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{
    Capabilities, CredentialType, ExtensionType, GroupId, KeyPackage, Lifetime, MlsGroup,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider as _;
use serde_json::{json, Value};

pub const DAYS: u64 = 24 * 3600;

/// 프로필 capabilities(§2) — 마지막 수단 확장도 둔다(없으면 last_resort KeyPackage 가 openmls 검사에서 거절된다).
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[
            ExtensionType::Unknown(EXT_LODELAI),
            ExtensionType::LastResort,
        ]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// 한 기기의 MLS 쪽(비밀은 이 provider 안).
pub struct Dev {
    pub provider: OpenMlsRustCrypto,
    pub signer: DeviceSigner,
}

impl Dev {
    pub fn new(keys: &DeviceKeys) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: DeviceSigner::new(keys.signing.clone()),
        }
    }

    /// 이 기기의 KeyPackage(비밀은 provider 에 남음).
    pub fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .key_package_lifetime(Lifetime::new(60 * DAYS))
            .leaf_node_capabilities(capabilities())
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.signer.credential(),
            )
            .unwrap()
            .key_package()
            .clone()
    }

    pub fn create(&self, kind: Kind, gid: &[u8]) -> MlsGroup {
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &create_config(kind, &[]).unwrap(),
            GroupId::from_slice(gid),
            self.signer.credential(),
        )
        .unwrap()
    }

    pub fn group_info(&self, g: &MlsGroup) -> Vec<u8> {
        g.export_group_info(self.provider.crypto(), &self.signer, true)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }
}

pub fn data(b: &[u8]) -> Value {
    json!({"data": encoding::encode(b)})
}

/// `a`·`b` 의 pair 그룹을 세우는 Handshake 본문 둘(start, `b` 기기들을 넣는 Add Commit+welcome) — 보낸 뒤 epoch 1.
/// (gid, start, commit)
pub fn pair_bodies(
    a: &DeviceKeys,
    a_name: &str,
    b: &[&DeviceKeys],
    b_name: &str,
) -> (Vec<u8>, Value, Value) {
    let ad = Dev::new(a);
    let gid = lodelai_relay_client::mls::pair_group_id(a_name, b_name);
    let mut g = ad.create(Kind::Pair, &gid);
    let start = json!({"enc": "mls", "wire": "start", "group_info": data(&ad.group_info(&g))});
    let kps: Vec<KeyPackage> = b.iter().map(|k| Dev::new(k).key_package()).collect();
    let (commit, welcome, _) = g.add_members(&ad.provider, &ad.signer, &kps).unwrap();
    g.merge_pending_commit(&ad.provider).unwrap();
    let commit = json!({
        "enc": "mls", "wire": "commit",
        "payload": data(&commit.tls_serialize_detached().unwrap()),
        "group_info": data(&ad.group_info(&g)),
        "welcome": data(&welcome.tls_serialize_detached().unwrap()),
    });
    (gid.to_vec(), start, commit)
}

/// 응용 메시지 **모양**(묶음 22 — 1:1 도 enc mls, #488). relay 는 열지 않으므로 길이만 맞춘다: 페이로드 = 머리 고정분 + 오버헤드 +
/// 본문 바이트라 크기 검사가 평문 바이트로 정확히 잰다(옛 box 의 ct = 본문 + 16 과 같은 뜻).
pub fn fake_app(text: &[u8]) -> Value {
    use lodelai_relay::frames::{MLS_APP_OVERHEAD, MLS_PLAINTEXT_HEAD_BYTES};
    let mut p = vec![0u8; MLS_PLAINTEXT_HEAD_BYTES + MLS_APP_OVERHEAD];
    p.extend_from_slice(text);
    json!({"enc": "mls", "wire": "app", "payload": data(&p)})
}
