//! MLS 프로필(묶음 22 §2, ADR 0012): openmls 0.8.3 위에 이 앱이 정한 것만 고정한다.
//!
//! - ciphersuite **0x0003**(X25519·ChaCha20-Poly1305·SHA-256·Ed25519) 하나. crypto 는 `openmls_rust_crypto`.
//! - 잎 서명 키 = **기기 Ed25519 키**. [`DeviceSigner`] 가 Keychain 에서 읽은 기기 키로 서명만 빌려준다 — 저장(`mls_kv`)에는
//!   넣지 않는다. Credential = `BasicCredential(device_id)`.
//! - wire format `PURE_PLAINTEXT`(Handshake = PublicMessage, 응용 = PrivateMessage), 제안은 값으로만(`add_members`·
//!   `remove_members`·`self_update` — `propose_*` 를 부르는 길을 두지 않는다).
//! - `max_past_epochs` 3, 순서 어긋남 50, 앞질러 감 1 000, ratchet tree 확장 켬.
//! - GroupContext 확장 `0xF0A1` = `{kind, admins?}` JSON(relay 가 이미 아는 것만). 이름은 넣지 않는다(`group_meta` 응용 메시지).
//!   모든 잎의 capabilities 와 그룹의 required capabilities 에 `0xF0A1` 을 둔다(없으면 Add 가 거절된다).

use lodelai_crypto::keys::SigningKeyPair;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use sha2::{Digest, Sha256};

use crate::mls_rules::{self, device_of, RuleCtx, Verdict};
use crate::mls_store::{GroupState, MlsStore};

/// 쓰는 ciphersuite 하나(§2).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
/// 이 앱의 GroupContext 확장 번호(§2).
pub const EXT_LODELAI: u16 = 0xF0A1;
/// 지난 epoch 비밀을 남기는 수(§2 — 그 이상은 FS 를 위해 지운다).
pub const MAX_PAST_EPOCHS: usize = 3;
/// KeyPackage 수명(§3 — 90일 상한). openmls `Lifetime::new` 가 `not_before` 를 1시간 앞당기므로 1시간 빼서 전체 폭이 90일이
/// 되게 한다 — relay 는 `not_after − not_before` 가 90일을 넘으면 거절한다.
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 90 * 24 * 3600 - 3600;

/// openmls 에 넘기는 provider: crypto·난수는 RustCrypto, 저장은 [`MlsStore`].
pub struct Provider {
    crypto: RustCrypto,
    store: MlsStore,
}

impl Provider {
    #[must_use]
    pub fn new(store: MlsStore) -> Self {
        Self {
            crypto: RustCrypto::default(),
            store,
        }
    }
}

impl Provider {
    /// openmls 호출 하나를 트랜잭션으로 감싼다 — [`MlsStore::begin`]. 상태를 바꾸는 호출은 모두 이 안에서 한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn begin(&self) -> Result<crate::mls_store::Txn<'_>, crate::mls_store::MlsStoreError> {
        self.store.begin()
    }

    /// 저장 연결의 (secure_delete, journal_mode) — 시험용.
    #[doc(hidden)]
    #[must_use]
    pub fn pragmas(&self) -> (i64, String) {
        self.store.pragmas()
    }

    /// [`MlsStore::scrub`].
    pub fn scrub(&self) {
        self.store.scrub();
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MlsStore;

    fn storage(&self) -> &Self::StorageProvider {
        &self.store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// 기기 Ed25519 키로 서명하는 openmls `Signer`. 비밀은 이 값 안에만 있고 저장에 쓰이지 않는다.
pub struct DeviceSigner {
    key: SigningKeyPair,
}

impl DeviceSigner {
    #[must_use]
    pub fn new(key: SigningKeyPair) -> Self {
        Self { key }
    }

    /// 잎의 Credential·서명 공개키(device_id 는 그 공개키의 지문).
    #[must_use]
    pub fn credential(&self) -> CredentialWithKey {
        let vk = self.key.verifying_key();
        let id = lodelai_crypto::DeviceId::from_verifying_key(&vk);
        CredentialWithKey {
            credential: BasicCredential::new(id.as_str().as_bytes().to_vec()).into(),
            signature_key: vk.to_bytes().to_vec().into(),
        }
    }
}

impl Signer for DeviceSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// 그룹 종류(§2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 1:1 — 두 사람.
    Pair,
    /// 내 기기끼리.
    SelfDevices,
    /// 여러 사람(묶음 16).
    Group,
}

impl Kind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::SelfDevices => "self",
            Self::Group => "group",
        }
    }
}

/// pair 그룹 id: `SHA-256("lodelai-pair-v1" ‖ 0 ‖ min(a,b) ‖ 0 ‖ max(a,b))`(아이디 UTF-8, §2a).
#[must_use]
pub fn pair_group_id(a: &str, b: &str) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(b"lodelai-pair-v1");
    h.update([0]);
    h.update(lo.as_bytes());
    h.update([0]);
    h.update(hi.as_bytes());
    h.finalize().into()
}

/// 내 기기 그룹 id: `SHA-256("lodelai-self-v1" ‖ 0 ‖ user)`(§2a).
#[must_use]
pub fn self_group_id(user: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lodelai-self-v1");
    h.update([0]);
    h.update(user.as_bytes());
    h.finalize().into()
}

/// 잎 capabilities: 0x0003 하나 + 이 앱 확장.
#[must_use]
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        // 마지막 수단 KeyPackage(§3)의 확장도 적어야 KeyPackageIn::validate 가 받는다(10-27 지적).
        Some(&[
            ExtensionType::Unknown(EXT_LODELAI),
            ExtensionType::LastResort,
        ]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// GroupContext 확장 `0xF0A1` 값.
fn lodelai_extension(kind: Kind, admins: &[String]) -> Extension {
    let mut v = serde_json::json!({"kind": kind.as_str()});
    if !admins.is_empty() {
        v["admins"] = admins.into();
    }
    Extension::Unknown(EXT_LODELAI, UnknownExtension(v.to_string().into_bytes()))
}

fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(50, 1_000)
}

/// 만들기 설정(§2).
///
/// # Errors
/// 확장 묶음이 잘못됐을 때(코드 오류).
pub fn create_config(
    kind: Kind,
    admins: &[String],
) -> Result<MlsGroupCreateConfig, InvalidExtensionError> {
    let ext = Extensions::from_vec(vec![
        lodelai_extension(kind, admins),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(EXT_LODELAI)],
            &[],
            &[CredentialType::Basic],
        )),
    ])?;
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet())
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities())
        .with_group_context_extensions(ext)
        .build())
}

/// Welcome·external commit 으로 들어갈 때의 설정(§2).
#[must_use]
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .sender_ratchet_configuration(sender_ratchet())
        .use_ratchet_tree_extension(true)
        .build()
}

/// KeyPackage 하나(§3). 비밀(init·잎 암호 키)은 provider 저장에 들어간다. `last_resort` 면 마지막 수단 확장.
///
/// # Errors
/// openmls 오류.
pub fn key_package(
    provider: &Provider,
    signer: &DeviceSigner,
    last_resort: bool,
) -> Result<KeyPackageBundle, KeyPackageNewError> {
    let mut b = KeyPackage::builder()
        .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECS))
        .leaf_node_capabilities(capabilities());
    if last_resort {
        b = b.mark_as_last_resort();
    }
    b.build(CIPHERSUITE, provider, signer, signer.credential())
}

/// 그룹 만들기(나 혼자, epoch 0). pair·self 는 id 를 계산해서, group 은 ULID UTF-8 로.
///
/// # Errors
/// openmls 오류.
pub fn create_group(
    provider: &Provider,
    signer: &DeviceSigner,
    kind: Kind,
    group_id: &[u8],
    admins: &[String],
) -> Result<MlsGroup, Error> {
    let cfg = create_config(kind, admins).map_err(|e| Error::Mls(e.to_string()))?;
    MlsGroup::new_with_group_id(
        provider,
        signer,
        &cfg,
        GroupId::from_slice(group_id),
        signer.credential(),
    )
    .map_err(|e| Error::Mls(e.to_string()))
}

/// MLS 계층 오류(진단 글은 로그에만).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mls: {0}")]
    Mls(String),
    #[error("mls 메시지 꼴")]
    Codec,
    /// 이 앱 규칙에 어긋난 메시지·Commit·Welcome(무엇인지는 로그용 짧은 이름).
    #[error("규칙 밖: {0}")]
    Rejected(&'static str),
    /// 지난 epoch 의 Commit 인데 우리가 적용한 것이 아님(늦은·갈라진 Commit — 멈춤 판정은 위에서).
    #[error("지난 epoch Commit")]
    Stale,
    /// 디렉터리가 늦다(새 기기 직후 등) — 디렉터리를 갱신한 뒤 같은 메시지를 다시 처리한다(ADR 0012 §5a ①). epoch 그대로.
    #[error("디렉터리 갱신 뒤 다시: {0}")]
    Retry(&'static str),
    /// 규칙 밖 Commit — 그룹을 막았다(`stalled_device`, 사람 확인).
    #[error("멈춤: {0}")]
    Stalled(&'static str),
    /// 막힌 그룹 — 보내기·받기 안 함.
    #[error("막힌 그룹: {}", .0.as_str())]
    Blocked(crate::mls_store::GroupState),
    #[error("저장: {0}")]
    Store(#[from] crate::mls_store::MlsStoreError),
}

fn mls_err(e: impl std::fmt::Display) -> Error {
    Error::Mls(e.to_string())
}

/// 받은 MLS 메시지를 처리한 결과.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// 응용 메시지 평문과 보낸 잎의 device_id(봉투 `from` 과 같음을 확인함).
    App { text: Vec<u8>, sender: String },
    /// pair·self: Commit 을 바로 merge 했다.
    Merged { epoch: u64 },
    /// group: 확정 전(§4-7) — merge 하지 않고 원 바이트를 두었다. `commit_ack{epoch, hash}` 를 보낸다. `joiner` 는
    /// external commit 이면 스스로 든 기기(#577 — 같은 기기가 옛 잎을 갈아 끼울 수도 있어 잎 기기 비교로는 못 가른다).
    Staged {
        epoch: u64,
        hash: [u8; 32],
        joiner: Option<String>,
    },
    /// 이미 merge 한 같은 Commit 이 다시 옴(merge 뒤 ack 전에 죽음) — 조용히 넘긴다.
    Duplicate,
}

/// `commit_hash` = SHA-256(받은 TLS 원 바이트).
#[must_use]
pub fn commit_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// 디렉터리가 늦은 Commit 을 다시 보는 최대 시간 — 넘으면 멈춤(ADR §5a ① → ③, 설계 2b 리뷰).
pub const RETRY_MAX_MS: i64 = 60 * 60 * 1000;

/// openmls 가 KeyPackage 수명에 앞뒤로 두는 여유(1시간).
const LIFETIME_MARGIN_SECS: u64 = 3600;

/// 받은 Commit 의 이 앱 규칙(§3·§11 🟢⑧, 설계 리뷰 ③): Add 의 KeyPackage 는 0x0003·수명 90일 이하·지금 유효,
/// GroupContextExtensions 제안 없음(0xF0A1·ciphersuite 는 만든 뒤 바꾸지 않는다). openmls 기본 검사만 믿지 않는다.
/// ExternalInit 은 여기서 보지 않는다 — external commit 일 때만 허용하는 것은 [`mls_rules::check_staged`].
///
/// # Errors
/// 어긋나면 [`Error::Rejected`].
pub fn check_commit(staged: &StagedCommit, now_secs: u64, admin_op: bool) -> Result<(), Error> {
    for a in staged.add_proposals() {
        let kp = a.add_proposal().key_package();
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(Error::Rejected("add_ciphersuite"));
        }
        let lt = kp.life_time();
        let span = lt.not_after().saturating_sub(lt.not_before());
        if span > KEY_PACKAGE_LIFETIME_SECS + LIFETIME_MARGIN_SECS {
            return Err(Error::Rejected("add_lifetime_long"));
        }
        if now_secs < lt.not_before() || now_secs > lt.not_after() {
            return Err(Error::Rejected("add_lifetime_expired"));
        }
    }
    for q in staged.queued_proposals() {
        match q.proposal() {
            // group 의 `admin` 만 — 관리자·`admins` 만 바뀜은 [`mls_rules::check_staged`](§12-13 ①).
            Proposal::GroupContextExtensions(_) if !admin_op => {
                return Err(Error::Rejected("group_context_extensions"))
            }
            // ciphersuite·판을 바꿀 수 있다(설계 2a 리뷰 ②). openmls 0.8.3 은 보내는 쪽에서 ReInit 을 빼서 공개 API 로는
            // 이 Commit 을 못 만들고, PublicMessage 의 membership_tag 가 그룹 비밀이라 바이트로 짜는 시험도 못 둔다 — 악성
            // 클라이언트가 바이트로 보낸 것을 이 match 가 막는다.
            Proposal::ReInit(_) => return Err(Error::Rejected("reinit")),
            // 우리는 PSK 를 쓰지 않는다.
            Proposal::PreSharedKey(_) => return Err(Error::Rejected("psk")),
            _ => {}
        }
    }
    Ok(())
}

/// 관리자를 바꾼 GroupContext 확장(`admin` op, §12-13 ①): 0xF0A1 의 `admins` 만 새 값, 나머지 확장은 그대로.
#[must_use]
pub fn with_admins(group: &MlsGroup, admins: &[String]) -> Option<Extensions<GroupContext>> {
    let kind = group_kind(group)?;
    let exts = group
        .extensions()
        .iter()
        .map(|e| match e {
            Extension::Unknown(EXT_LODELAI, _) => lodelai_extension(kind, admins),
            other => other.clone(),
        })
        .collect();
    Extensions::from_vec(exts).ok()
}

/// 0xF0A1 `admins` 말고는 확장이 같은가(`kind` 도 그대로) — relay `only_admins_changed` 와 같은 계산.
#[must_use]
pub fn only_admins_changed(old: &Extensions<GroupContext>, new: &Extensions<GroupContext>) -> bool {
    let rest = |e: &Extensions<GroupContext>| -> Vec<Extension> {
        e.iter()
            .filter(|x| x.extension_type() != ExtensionType::Unknown(EXT_LODELAI))
            .cloned()
            .collect()
    };
    let kind = |e: &Extensions<GroupContext>| -> Option<String> {
        e.iter().find_map(|x| match x {
            Extension::Unknown(EXT_LODELAI, u) => serde_json::from_slice::<serde_json::Value>(&u.0)
                .ok()?
                .get("kind")?
                .as_str()
                .map(str::to_owned),
            _ => None,
        })
    };
    rest(old) == rest(new) && kind(old).is_some() && kind(old) == kind(new)
}

/// 그룹의 0xF0A1 `kind`.
#[must_use]
pub fn group_kind(group: &MlsGroup) -> Option<Kind> {
    let ext = group.extensions().unknown(EXT_LODELAI)?;
    let v: serde_json::Value = serde_json::from_slice(&ext.0).ok()?;
    match v.get("kind")?.as_str()? {
        "pair" => Some(Kind::Pair),
        "self" => Some(Kind::SelfDevices),
        "group" => Some(Kind::Group),
        _ => None,
    }
}

/// group 종류의 관리자(0xF0A1 `admins` — 사람 주소).
#[must_use]
pub fn group_admins(group: &MlsGroup) -> Vec<String> {
    group
        .extensions()
        .unknown(EXT_LODELAI)
        .and_then(|e| serde_json::from_slice::<serde_json::Value>(&e.0).ok())
        .and_then(|v| v.get("admins").cloned())
        .and_then(|a| serde_json::from_value(a).ok())
        .unwrap_or_default()
}

/// 유효 관리자(§12-25): 0xF0A1 `admins` ∩ 지금 잎 사용자, 비면 가장 작은 leaf index 잎의 사용자 한 명 — 나간·빠진 관리자는
/// 확장에 남아도 관리자가 아니다. `user_of` 는 잎 device_id → 사용자 아이디, `server` 는 사람 주소의 서버.
#[must_use]
pub fn effective_admins(
    group: &MlsGroup,
    server: &str,
    user_of: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut leaves: Vec<(u32, String)> = group
        .members()
        .filter_map(|m| {
            let d = mls_rules::device_of(&m.credential)?;
            Some((m.index.u32(), format!("{}@{server}", user_of(&d)?)))
        })
        .collect();
    leaves.sort();
    let listed: Vec<String> = group_admins(group)
        .into_iter()
        .filter(|a| leaves.iter().any(|(_, u)| u == a))
        .collect();
    if !listed.is_empty() {
        return listed;
    }
    leaves.into_iter().map(|(_, u)| u).take(1).collect()
}

/// Welcome 으로 들어간다(트랜잭션 하나). 트리의 모든 잎을 `ctx`(대화 사용자·디렉터리 잎 자격)로 먼저 보고, ciphersuite·그룹 id·
/// 0xF0A1 `kind` 를 연 뒤 대조하고 다르면 되돌린다(0.8.3 은
/// Welcome 의 ciphersuite 를 밖에 내주지 않는다 — 우리 KeyPackage 가 0x0003 뿐이라 다른 것은 열리지도 않지만 한 번 더 본다).
///
/// # Errors
/// 꼴·규칙·openmls 오류.
pub fn join_welcome(
    provider: &Provider,
    bytes: &[u8],
    kind: Kind,
    group_id: &[u8],
    ctx: &RuleCtx<'_>,
) -> Result<MlsGroup, Error> {
    let MlsMessageBodyIn::Welcome(w) = parse(bytes)?.extract() else {
        return Err(Error::Codec);
    };
    let t = provider.begin()?;
    let kps_before = provider.storage().key_package_count()?;
    let staged =
        StagedWelcome::new_from_welcome(provider, &join_config(), w, None).map_err(mls_err)?;
    // 들어가기 전에 트리의 모든 잎(나 포함)을 본다 — 대화 사용자의 자격 있는 기기·디렉터리 키여야(relay 를 믿지 않음,
    // 설계 리뷰 ②). 어긋나면 들어가지 않는다(Txn 이 되돌려 KeyPackage 도 남음).
    for mem in staged.members() {
        let dev = mls_rules::device_of(&mem.credential).ok_or(Error::Rejected("credential"))?;
        // 이미 트리에 있던 폐기 잎(키 일치)은 막지 않는다 — 든 뒤 스스로 Remove(#577 설계 결정).
        match ctx.existing_leaf_verdict(&dev, &mem.signature_key) {
            Verdict::Ok => {}
            Verdict::Retry(r) => return Err(Error::Retry(r)),
            Verdict::Stall(r) => return Err(Error::Stalled(r)),
        }
    }
    let g = staged.into_group(provider).map_err(mls_err)?;
    if g.ciphersuite() != CIPHERSUITE {
        return Err(Error::Rejected("welcome_ciphersuite"));
    }
    if g.group_id().as_slice() != group_id {
        return Err(Error::Rejected("welcome_group_id"));
    }
    if group_kind(&g) != Some(kind) {
        return Err(Error::Rejected("welcome_kind"));
    }
    // 마지막 수단 KeyPackage(여럿이 나눠 쓰는 init 키)로 들어왔다 — 첫 보내기 전에 Update 하도록 바로 때로(§7·ADR §4).
    if provider.storage().key_package_count()? == kps_before {
        provider.storage().update_reset(group_id, Some(0))?;
    }
    t.commit()?;
    Ok(g)
}

/// external commit 으로 다시 들어간다(§4-5·§5a `rejoin_needed`·§4-7 내 몫이 깨짐): GroupInfo(트리 포함)로 그룹을 만들고 Commit
/// 하나를 낸다 — 같은 서명 키(이 기기)의 옛 잎은 openmls 가 같은 Commit 으로 Remove 한다(§4-5 ⓒ). 들어가기 전에 트리의 모든 잎을
/// Welcome 과 같은 규칙으로 본다. openmls 는 만든 그룹을 바로 merge 해 저장한다 — relay 가 거절하면 호출자가 그룹을 지운다.
/// 이 기기의 옛 그룹(같은 id)은 호출자가 먼저 지운다. (그룹, Commit 바이트, GroupInfo 바이트).
///
/// # Errors
/// 꼴·규칙·openmls 오류.
pub fn join_external(
    provider: &Provider,
    signer: &DeviceSigner,
    group_info: &[u8],
    kind: Kind,
    group_id: &[u8],
    ctx: &RuleCtx<'_>,
) -> Result<(MlsGroup, Vec<u8>, Vec<u8>), Error> {
    let MlsMessageBodyIn::GroupInfo(vgi) = parse(group_info)?.extract() else {
        return Err(Error::Codec);
    };
    let t = provider.begin()?;
    let (g, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .build_group(provider, vgi, signer.credential())
        .map_err(mls_err)?
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(provider.storage())
        .map_err(mls_err)?
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .map_err(mls_err)?
        .finalize(provider)
        .map_err(mls_err)?;
    for mem in g.members() {
        let dev = mls_rules::device_of(&mem.credential).ok_or(Error::Rejected("credential"))?;
        // GroupInfo 트리에 이미 있던 폐기 잎(키 일치)은 막지 않는다 — 든 뒤 스스로 Remove(#577 설계 결정). 내 새 잎은
        // 폐기 기록에 없으니 그대로 검사된다.
        match ctx.existing_leaf_verdict(&dev, &mem.signature_key) {
            Verdict::Ok => {}
            Verdict::Retry(r) => return Err(Error::Retry(r)),
            Verdict::Stall(r) => return Err(Error::Stalled(r)),
        }
    }
    if g.ciphersuite() != CIPHERSUITE {
        return Err(Error::Rejected("external_ciphersuite"));
    }
    if g.group_id().as_slice() != group_id {
        return Err(Error::Rejected("external_group_id"));
    }
    if group_kind(&g) != Some(kind) {
        return Err(Error::Rejected("external_kind"));
    }
    let (commit, _, gi) = bundle.into_contents();
    let gi = gi.ok_or(Error::Codec)?;
    let commit = to_bytes(&commit)?;
    let gi = to_bytes(&MlsMessageOut::from(gi))?;
    t.commit()?;
    Ok((g, commit, gi))
}

/// 받은 응용·Commit 메시지 하나(트랜잭션 하나). 응용 메시지는 보낸 잎이 봉투 기기(`ctx.expect_sender`)와 같아야 한다.
/// Commit 은 이 앱 규칙([`check_commit`])과 받는 쪽 재검사([`mls_rules::check_staged`] — 핀·디렉터리, relay 를 믿지 않음)를 지나야
/// 하고, pair·self 는 바로 merge 하고 `mls_applied` 를 같은 트랜잭션에 남긴다. group 의 Commit 은 merge 하지 않고 원 바이트를
/// 둔다(§4-7). 이미 merge 한 같은 Commit 은 [`Received::Duplicate`]. 따로 온 Proposal 은 거절한다(제안은 Commit 안에 값으로만).
///
/// # Errors
/// 꼴·규칙·openmls 오류 — 실패하면 트랜잭션이 되돌려지고, `group` 도 저장에서 다시 읽는다(ROLLBACK 은 DB 만 되돌리고
/// 메모리의 `MlsGroup` 은 process·merge 로 앞서 있을 수 있다 — 설계 2a 리뷰 ①). [`Error::Stalled`] 면 그룹을
/// `stalled_device` 로, 다시 읽기도 실패하면 `syncing` 으로 막는다 — 그 뒤로는 [`Error::Blocked`]. [`Error::Retry`] 는 막지 않고
/// 호출자가 디렉터리 갱신마다·1분마다 같은 바이트로 다시 부른다 — 같은 Commit 이 처음 Retry 된 뒤 [`RETRY_MAX_MS`] 가 지나도
/// 그대로면 [`Error::Stalled`] 로 바꾼다.
pub fn receive(
    provider: &Provider,
    group: &mut MlsGroup,
    kind: Kind,
    bytes: &[u8],
    now_secs: u64,
    ctx: &RuleCtx<'_>,
) -> Result<Received, Error> {
    let gid = group.group_id().clone();
    if let Some((state, _, _)) = provider.storage().state(gid.as_slice())? {
        return Err(Error::Blocked(state));
    }
    let now_ms = i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let mut r = receive_in(provider, group, kind, bytes, now_secs, ctx);
    if let Err(Error::Retry(reason)) = r {
        let since = provider
            .storage()
            .retry_since(gid.as_slice(), &commit_hash(bytes), now_ms)?;
        if now_ms.saturating_sub(since) >= RETRY_MAX_MS {
            r = Err(Error::Stalled(reason));
        }
    }
    if matches!(r, Ok(_) | Err(Error::Stalled(_))) {
        provider.storage().clear_retry(gid.as_slice())?;
    }
    if let Err(e) = &r {
        // receive_in 이 끝나며 Txn 이 ROLLBACK 했다 — 저장 쪽이 기준.
        if let Ok(Some(g)) = MlsGroup::load(provider.storage(), &gid) {
            *group = g;
        } else {
            provider
                .storage()
                .set_state(gid.as_slice(), GroupState::Syncing, "reload", now_ms)?;
        }
        if let Error::Stalled(reason) = e {
            let state = if server_fault(reason) {
                GroupState::StalledServer
            } else {
                GroupState::StalledDevice
            };
            provider
                .storage()
                .set_state(gid.as_slice(), state, reason, now_ms)?;
        }
    }
    r
}

/// 디렉터리가 새로워져도 풀릴 수 없는 멈춤 이유인가(§12-23 ② — `stalled_server`): external commit 이 남의 잎을 빼거나 Add 를
/// 섞음(§4-5 ⓒ)·update path 없음·ExternalInit 을 멤버가 보냄, 사용자 단위 op 뒤 그 사용자 잎이 남음(§4-4)·relay 헤더에
/// subject 없음, create 가 epoch 0 이 아님, 보낸 쪽 종류가 멤버·새 멤버가 아님. 잎 자격(디렉터리·devcert·키)에 기대는 것은
/// `stalled_device`(§12-19 스스로 다시 봄).
#[must_use]
pub fn server_fault(reason: &str) -> bool {
    matches!(
        reason,
        "external_init"
            | "external_no_path"
            | "external_remove_other"
            | "external_add"
            | "sender_kind"
            | "user_leaves_left"
            | "subject"
            | "create_epoch"
    )
}

/// group 종류 확정(§4-7·§12-14): `commit_final{epoch N, commit_hash}` — 같은 해시로 쥔 남의 Commit 을 다시 처리해 merge 하고
/// 적용 기록을 남긴다(트랜잭션 하나, 규칙 재검사는 쥘 때 이미 함). 그 해시로 쥔 것이 없으면(다른 Commit 이 확정됨) 그 epoch 의
/// 쥔 것을 버리고 `Ok(false)` — 쌓인 것에서 group_seq 가 붙은 확정 Commit 이 온다. 내 Commit 의 확정은 `merge_pending_commit`.
///
/// # Errors
/// 꼴·openmls·저장 오류 — 실패하면 되돌리고 `group` 을 저장에서 다시 읽는다.
pub fn finalize(
    provider: &Provider,
    group: &mut MlsGroup,
    epoch: u64,
    hash: &[u8; 32],
) -> Result<bool, Error> {
    let gid = group.group_id().clone();
    let Some(bytes) = provider.storage().pending(gid.as_slice(), epoch, hash)? else {
        provider.storage().drop_pending(gid.as_slice(), epoch)?;
        return Ok(false);
    };
    let r = (|| {
        let pm = parse(&bytes)?
            .try_into_protocol_message()
            .map_err(|_| Error::Codec)?;
        let t = provider.begin()?;
        let p = group.process_message(provider, pm).map_err(mls_err)?;
        let ProcessedMessageContent::StagedCommitMessage(c) = p.into_content() else {
            return Err(Error::Codec);
        };
        group.merge_staged_commit(provider, *c).map_err(mls_err)?;
        provider
            .storage()
            .mark_applied(gid.as_slice(), epoch, hash)?;
        provider.storage().drop_pending(gid.as_slice(), epoch)?;
        t.commit()?;
        Ok(true)
    })();
    if r.is_err() {
        if let Ok(Some(g)) = MlsGroup::load(provider.storage(), &gid) {
            *group = g;
        }
    }
    r
}

/// group 종류 무효(§4-7): `commit_void` — 그 epoch 에 쥔 남의 Commit 을 버린다(epoch N 그대로).
///
/// # Errors
/// 저장 오류.
pub fn discard(provider: &Provider, gid: &[u8], epoch: u64) -> Result<(), Error> {
    provider.storage().drop_pending(gid, epoch)?;
    Ok(())
}

/// 보내기 전에: 막힌 그룹이면 [`Error::Blocked`].
///
/// # Errors
/// 막힘·저장 오류.
pub fn ensure_open(provider: &Provider, group: &MlsGroup) -> Result<(), Error> {
    match provider.storage().state(group.group_id().as_slice())? {
        Some((state, _, _)) => Err(Error::Blocked(state)),
        None => Ok(()),
    }
}

fn receive_in(
    provider: &Provider,
    group: &mut MlsGroup,
    kind: Kind,
    bytes: &[u8],
    now_secs: u64,
    ctx: &RuleCtx<'_>,
) -> Result<Received, Error> {
    let hash = commit_hash(bytes);
    let pm = parse(bytes)?
        .try_into_protocol_message()
        .map_err(|_| Error::Codec)?;
    let gid = group.group_id().as_slice().to_vec();
    if pm.group_id().as_slice() != gid.as_slice() {
        return Err(Error::Rejected("group_id"));
    }
    let epoch = pm.epoch().as_u64();
    let commit = pm.content_type() == ContentType::Commit;
    if commit && epoch < group.epoch().as_u64() {
        return if provider.storage().applied(&gid, epoch, &hash)? {
            Ok(Received::Duplicate)
        } else {
            Err(Error::Stale)
        };
    }
    let t = provider.begin()?;
    let p = group.process_message(provider, pm).map_err(mls_err)?;
    let sender = p.sender().clone();
    let sender_dev = device_of(p.credential());
    let out = match p.into_content() {
        ProcessedMessageContent::ApplicationMessage(a) => {
            let sender = sender_dev.ok_or(Error::Rejected("credential"))?;
            // 봉투의 보낸 기기와 다르면 버린다(§12-11 ⓔ) — Txn 안이라 ratchet 도 되돌린다.
            if ctx.expect_sender.is_some_and(|e| e != sender) {
                return Err(Error::Rejected("sender_mismatch"));
            }
            let text = a.into_bytes();
            if let Some(id) = ctx.keep_as {
                let now_ms = i64::try_from(now_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
                provider.storage().put_opened(id, &text, now_ms)?;
            }
            Received::App { text, sender }
        }
        ProcessedMessageContent::StagedCommitMessage(c) => {
            check_commit(&c, now_secs, ctx.group.is_some_and(|g| g.op == "admin"))?;
            match mls_rules::check_staged(ctx, group, &sender, &c) {
                Verdict::Ok => {}
                Verdict::Retry(r) => return Err(Error::Retry(r)),
                Verdict::Stall(r) => return Err(Error::Stalled(r)),
            }
            if kind == Kind::Group {
                provider.storage().put_pending(&gid, epoch, &hash, bytes)?;
                let joiner = matches!(sender, Sender::NewMemberCommit)
                    .then(|| sender_dev.clone())
                    .flatten();
                Received::Staged {
                    epoch,
                    hash,
                    joiner,
                }
            } else {
                group.merge_staged_commit(provider, *c).map_err(mls_err)?;
                provider.storage().mark_applied(&gid, epoch, &hash)?;
                Received::Merged {
                    epoch: group.epoch().as_u64(),
                }
            }
        }
        ProcessedMessageContent::ProposalMessage(_)
        | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            return Err(Error::Rejected("standalone_proposal"));
        }
    };
    t.commit()?;
    Ok(out)
}

/// 받은 바이트 → MLS 메시지.
///
/// # Errors
/// TLS 꼴이 아니면 [`Error::Codec`].
pub fn parse(bytes: &[u8]) -> Result<MlsMessageIn, Error> {
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::Codec)
}

/// 보낼 MLS 메시지 → 바이트.
///
/// # Errors
/// 직렬화 실패(코드 오류).
pub fn to_bytes(m: &MlsMessageOut) -> Result<Vec<u8>, Error> {
    m.tls_serialize_detached().map_err(|_| Error::Codec)
}
