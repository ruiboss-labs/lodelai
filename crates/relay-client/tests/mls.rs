//! 묶음 22 MLS 저장·프로필 왕복(§2·§8·§11): 두 기기가 각자 SQLite 저장으로 pair 그룹을 만들고 글을 주고받고, Update 하고,
//! DB 를 다시 열어도 이어지고, 지난 epoch 비밀이 사라지는지.

use std::path::Path;
use std::sync::Arc;

use lodelai_crypto::{devcert, DeviceKeys};
use lodelai_effects::OsRng;
use lodelai_relay_client::mls::{self, DeviceSigner, Kind, Provider};
use lodelai_relay_client::mls_rules::{DirDevice, Directory, Revocation, RuleCtx};
use lodelai_relay_client::mls_store::{GroupState, MlsStore, MlsStoreError};
use lodelai_relay_client::outbox::Store;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls::schedule::PreSharedKeyId;
use zeroize::Zeroizing;

struct Dev {
    provider: Provider,
    signer: DeviceSigner,
}

fn keys(seed: u8) -> DeviceKeys {
    DeviceKeys::generate(&[seed; 64])
}

fn store_key(seed: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([seed; 32])
}

fn open(path: &Path, seed: u8) -> Result<Dev, MlsStoreError> {
    // outbox 와 같은 파일(앱에서처럼 outbox 가 먼저 연다).
    let _outbox = Store::open(path).unwrap();
    let store = MlsStore::open(path, &store_key(seed), Arc::new(OsRng))?;
    Ok(Dev {
        provider: Provider::new(store),
        signer: DeviceSigner::new(keys(seed).signing),
    })
}

/// a 가 b 를 pair 그룹에 넣는다 → (a 그룹, b 그룹). openmls 호출마다 트랜잭션 하나.
fn pair(a: &Dev, b: &Dev) -> (MlsGroup, MlsGroup) {
    let gid = mls::pair_group_id("alice", "bob");
    let t = a.provider.begin().unwrap();
    let mut ga = mls::create_group(&a.provider, &a.signer, Kind::Pair, &gid, &[]).unwrap();
    t.commit().unwrap();
    let t = b.provider.begin().unwrap();
    let kp = mls::key_package(&b.provider, &b.signer, false).unwrap();
    t.commit().unwrap();
    let t = a.provider.begin().unwrap();
    let (commit, welcome, _) = ga
        .add_members(&a.provider, &a.signer, &[kp.key_package().clone()])
        .unwrap();
    // Handshake 는 평문 틀(PublicMessage), 응용은 PrivateMessage(§2).
    let wf = mls::parse(&mls::to_bytes(&commit).unwrap())
        .unwrap()
        .wire_format();
    assert_eq!(wf, WireFormat::PublicMessage);
    ga.merge_pending_commit(&a.provider).unwrap();
    t.commit().unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = mls::parse(&mls::to_bytes(&welcome).unwrap())
        .unwrap()
        .extract()
    else {
        panic!("Welcome 이 아님");
    };
    let t = b.provider.begin().unwrap();
    let gb = StagedWelcome::new_from_welcome(&b.provider, &mls::join_config(), welcome, None)
        .unwrap()
        .into_group(&b.provider)
        .unwrap();
    t.commit().unwrap();
    (ga, gb)
}

fn send(from: &Dev, g: &mut MlsGroup, text: &str) -> Vec<u8> {
    let t = from.provider.begin().unwrap();
    let m = g
        .create_message(&from.provider, &from.signer, text.as_bytes())
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&m).unwrap();
    assert_eq!(
        mls::parse(&bytes).unwrap().wire_format(),
        WireFormat::PrivateMessage
    );
    bytes
}

fn recv(to: &Dev, g: &mut MlsGroup, bytes: &[u8]) -> Result<Option<String>, String> {
    let m = mls::parse(bytes).unwrap();
    let pm = m.try_into_protocol_message().map_err(|e| e.to_string())?;
    // 실패하면 커밋하지 않고 버려져 ROLLBACK.
    let t = to.provider.begin().unwrap();
    let p = g
        .process_message(&to.provider, pm)
        .map_err(|e| e.to_string())?;
    let out = match p.into_content() {
        ProcessedMessageContent::ApplicationMessage(a) => {
            Some(String::from_utf8(a.into_bytes()).unwrap())
        }
        ProcessedMessageContent::StagedCommitMessage(c) => {
            g.merge_staged_commit(&to.provider, *c).unwrap();
            None
        }
        _ => None,
    };
    t.commit().unwrap();
    Ok(out)
}

fn update(from: &Dev, g: &mut MlsGroup) -> Vec<u8> {
    let t = from.provider.begin().unwrap();
    let b = g
        .self_update(&from.provider, &from.signer, LeafNodeParameters::default())
        .unwrap();
    let bytes = mls::to_bytes(b.commit()).unwrap();
    g.merge_pending_commit(&from.provider).unwrap();
    t.commit().unwrap();
    bytes
}

#[test]
fn pair_그룹_왕복_update_다시_열기() {
    let dir = tempfile::tempdir().unwrap();
    let (pa, pb) = (dir.path().join("a.db"), dir.path().join("b.db"));
    let a = open(&pa, 1).unwrap();
    let b = open(&pb, 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    assert_eq!(
        ga.group_id().as_slice(),
        mls::pair_group_id("bob", "alice"),
        "id 는 순서와 무관"
    );
    assert_eq!(
        recv(&b, &mut gb, &send(&a, &mut ga, "안녕"))
            .unwrap()
            .as_deref(),
        Some("안녕")
    );
    assert_eq!(
        recv(&a, &mut ga, &send(&b, &mut gb, "응"))
            .unwrap()
            .as_deref(),
        Some("응")
    );

    // Update(PCS) 뒤에도 양쪽이 이어진다.
    let c = update(&b, &mut gb);
    assert_eq!(recv(&a, &mut ga, &c).unwrap(), None);
    assert_eq!(ga.epoch(), gb.epoch());
    assert_eq!(
        recv(&b, &mut gb, &send(&a, &mut ga, "업데이트 뒤"))
            .unwrap()
            .as_deref(),
        Some("업데이트 뒤")
    );

    // b 를 닫고 DB 에서 다시 연다.
    let gid = gb.group_id().clone();
    drop(gb);
    drop(b);
    let b = open(&pb, 2).unwrap();
    let mut gb = MlsGroup::load(b.provider.storage(), &gid).unwrap().unwrap();
    assert_eq!(
        recv(&a, &mut ga, &send(&b, &mut gb, "다시 열고"))
            .unwrap()
            .as_deref(),
        Some("다시 열고")
    );
}

#[test]
fn 열쇠가_다르면_한_번에_알림() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.db");
    drop(open(&p, 1).unwrap());
    let err = MlsStore::open(&p, &store_key(9), Arc::new(OsRng)).unwrap_err();
    assert!(matches!(err, MlsStoreError::KeyMismatch));
    // 비우면 새 열쇠로 열린다.
    MlsStore::reset(&p, &store_key(9)).unwrap();
    assert!(MlsStore::open(&p, &store_key(9), Arc::new(OsRng)).is_ok());
}

/// MLS 연결도 secure_delete·WAL 을 켠다(연결마다 설정 — outbox 연결 것이 옮겨오지 않음, 설계 2a ①).
#[test]
fn mls_연결의_pragma() {
    let dir = tempfile::tempdir().unwrap();
    let d = open(&dir.path().join("a.db"), 1).unwrap();
    let (sd, jm) = d.provider.pragmas();
    assert_eq!((sd, jm.as_str()), (1, "wal"));
}

/// 커밋하지 않고 버려진 호출은 ROLLBACK — 다시 열어도 그 전 epoch 이고 이어서 연다(설계 ②).
#[test]
fn 실패한_호출은_되돌린다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, gb) = pair(&a, &b);
    let gid = gb.group_id().clone();
    let e = gb.epoch();
    let mut gb = gb;
    {
        let _t = b.provider.begin().unwrap();
        gb.self_update(&b.provider, &b.signer, LeafNodeParameters::default())
            .unwrap();
        gb.merge_pending_commit(&b.provider).unwrap();
        assert_ne!(gb.epoch(), e);
    }
    drop(gb);
    let mut gb = MlsGroup::load(b.provider.storage(), &gid).unwrap().unwrap();
    assert_eq!(gb.epoch(), e, "저장은 그 전 epoch");
    assert_eq!(
        recv(&b, &mut gb, &send(&a, &mut ga, "되돌린 뒤"))
            .unwrap()
            .as_deref(),
        Some("되돌린 뒤")
    );
}

#[test]
fn 지난_epoch_비밀은_3개까지만() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let old = send(&a, &mut ga, "옛 epoch");
    let mut late = Vec::new();
    for i in 0..5 {
        let c = update(&a, &mut ga);
        recv(&b, &mut gb, &c).unwrap();
        if i == 2 {
            late = send(&a, &mut ga, "조금 늦음");
        }
    }
    assert!(
        recv(&b, &mut gb, &old).is_err(),
        "5 epoch 지난 글은 못 연다"
    );
    assert_eq!(
        recv(&b, &mut gb, &late).unwrap().as_deref(),
        Some("조금 늦음")
    );
}

/// DB(+WAL) 파일 바이트. 시험은 체크포인트를 하지 않는다 — 저장이 스스로 WAL 을 잘라야 한다.
fn file_bytes(db: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(db).unwrap();
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    bytes.extend(std::fs::read(wal).unwrap_or_default());
    bytes
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// 지금 저장된 비밀 행(epoch 비밀·메시지 비밀)의 암호문 — 다른 연결로 읽고 바로 닫는다.
fn sealed_secret_rows(db: &Path) -> Vec<Vec<u8>> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut st = c.prepare("SELECT k, v FROM mls_kv").unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>)> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows.into_iter()
        .filter(|(k, _)| k.starts_with(b"EpochSecrets") || k.starts_with(b"MessageSecrets"))
        // 큰 값은 overflow 페이지로 나뉘어 파일에서 이어지지 않는다 — 앞 64 B(무작위 nonce 24 + 암호문 앞)를 지문으로.
        .map(|(_, v)| v[..v.len().min(64)].to_vec())
        .collect()
}

/// FS(§11, 설계 bc695ca3 ①): epoch 0 의 비밀 행 암호문이 몇 epoch 뒤 DB 에도 WAL 에도 없다(열쇠를 쥔 쪽도 못 연다).
#[test]
fn 지난_epoch_비밀의_암호문이_wal_에도_없다() {
    let dir = tempfile::tempdir().unwrap();
    let pb = dir.path().join("b.db");
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&pb, 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let old = sealed_secret_rows(&pb);
    assert!(!old.is_empty());
    assert!(
        old.iter().all(|v| contains(&file_bytes(&pb), v)),
        "지금은 있다"
    );
    for _ in 0..5 {
        let c = update(&a, &mut ga);
        recv(&b, &mut gb, &c).unwrap();
    }
    let now = file_bytes(&pb);
    for v in &old {
        assert!(!contains(&now, v), "지난 epoch 비밀 암호문이 남음");
    }
}

/// 저장 값은 암호화돼 있다 — DB·WAL 바이트에 응용 글·확장 JSON 이 없다(체크포인트 없이).
#[test]
fn 저장_바이트에_평문이_없다() {
    let dir = tempfile::tempdir().unwrap();
    let pb = dir.path().join("b.db");
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&pb, 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    recv(&b, &mut gb, &send(&a, &mut ga, "CANARY-평문-7f3a")).unwrap();
    let bytes = file_bytes(&pb);
    assert!(!contains(&bytes, "CANARY-평문-7f3a".as_bytes()));
    assert!(
        !contains(&bytes, b"\"kind\":\"pair\""),
        "GroupContext 확장도 값 안(암호화)"
    );
    assert!(!contains(&bytes, b"epoch_secrets"));
}

#[test]
fn group_id_는_계약_꼴() {
    use sha2::{Digest, Sha256};
    let want: [u8; 32] = Sha256::digest(b"lodelai-pair-v1\0alice\0bob").into();
    assert_eq!(mls::pair_group_id("bob", "alice"), want);
    let want: [u8; 32] = Sha256::digest(b"lodelai-self-v1\0alice").into();
    assert_eq!(mls::self_group_id("alice"), want);
}

/// 다른 연결이 읽는 중이라 못 자르면 표시가 남아 다음 scrub 이 다시 자른다(쓰기가 없어도).
#[test]
fn 못_자른_wal_은_다음_scrub_이_다시_자른다() {
    let dir = tempfile::tempdir().unwrap();
    let pb = dir.path().join("b.db");
    let wal = dir.path().join("b.db-wal");
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&pb, 2).unwrap();
    let reader = rusqlite::Connection::open(&pb).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM mls_kv", [], |r| r.get(0))
        .unwrap();
    let (_ga, _gb) = pair(&a, &b); // 안에서 scrub — 읽는 쪽 때문에 못 자름
    assert!(std::fs::metadata(&wal).unwrap().len() > 0);
    reader.execute_batch("COMMIT").unwrap();
    drop(reader);
    b.provider.scrub();
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 시험 디렉터리: 기기는 `keys(seed)`, 서버 이름은 고정.
#[derive(Default)]
struct World {
    live: Vec<DirDevice>,
    revs: Vec<(String, Revocation)>,
    members: Vec<String>,
}

impl Directory for World {
    fn server(&self) -> &str {
        "lodelai.example"
    }
    fn devices(&self, user: &str) -> Vec<DirDevice> {
        self.live
            .iter()
            .filter(|d| d.user == user)
            .cloned()
            .collect()
    }
    fn revocations(&self, user: &str) -> Vec<Revocation> {
        self.revs
            .iter()
            .filter(|(u, _)| u == user)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

fn id_of(seed: u8) -> String {
    keys(seed).device_id().as_str().to_owned()
}

impl World {
    /// alice = 1, bob = 2 — 각자 뿌리.
    fn pair() -> Self {
        let mut w = Self {
            members: vec!["alice".to_owned(), "bob".to_owned()],
            ..Self::default()
        };
        w.add("alice", 1, 1, &[]);
        w.add("bob", 2, 1, &[]);
        w
    }

    /// 디렉터리에 기기를 넣는다(`signed_by` = devcert 서명 기기 seed).
    fn add(&mut self, user: &str, seed: u8, added_ms: i64, signed_by: &[u8]) {
        let k = keys(seed);
        let id = id_of(seed);
        let x = k.exchange.public_key();
        let certs = signed_by
            .iter()
            .map(|&s| {
                let sig = devcert::sign(
                    &keys(s).signing,
                    &devcert::Cert {
                        server: "lodelai.example",
                        user,
                        device_id: &id,
                        x25519: &x,
                        signer: &id_of(s),
                    },
                );
                (id_of(s), sig)
            })
            .collect();
        let ed = k.signing.verifying_key().to_bytes();
        self.live.push(DirDevice {
            device_id: id,
            user: user.to_owned(),
            ed25519: ed,
            x25519: x,
            added_ms,
            certs,
        });
    }

    /// 자기 폐기 증명으로 끊는다(서명자 = 그 기기 자신).
    fn revoke_self(&mut self, user: &str, seed: u8) {
        let id = id_of(seed);
        let row = self
            .live
            .iter()
            .find(|d| d.device_id == id)
            .cloned()
            .unwrap();
        self.live.retain(|d| d.device_id != id);
        let at = "2026-10-27T00:00:00.000Z";
        let sig = lodelai_crypto::devrevoke::sign(
            &keys(seed).signing,
            &lodelai_crypto::devrevoke::Revoke {
                server: "lodelai.example",
                device_id: &id,
                at,
            },
        );
        self.revs.push((
            user.to_owned(),
            Revocation {
                device_id: id.clone(),
                added_ms: row.added_ms,
                ed25519: row.ed25519,
                x25519: row.x25519,
                certs: row.certs,
                at: at.to_owned(),
                signer: id,
                sig,
            },
        ));
    }

    fn ctx(&self) -> RuleCtx<'_> {
        self.ctx_from(None)
    }

    fn ctx_from<'a>(&'a self, sender: Option<&'a str>) -> RuleCtx<'a> {
        RuleCtx {
            dir: self,
            members: &self.members,
            expect_sender: sender,
            keep_as: None,
            group: None,
        }
    }
}

/// 마지막 수단 KeyPackage 도 받는 쪽 검사(KeyPackageIn::validate)를 지난다(10-27 — capabilities 에 LastResort).
#[test]
fn 마지막_수단_keypackage_가_검사를_지난다() {
    let dir = tempfile::tempdir().unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    for last in [false, true] {
        let t = b.provider.begin().unwrap();
        let kp = mls::key_package(&b.provider, &b.signer, last).unwrap();
        t.commit().unwrap();
        let bytes = kp.key_package().tls_serialize_detached().unwrap();
        let kin = KeyPackageIn::tls_deserialize_exact(&bytes).unwrap();
        kin.validate(b.provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
    }
}

/// pair 의 Commit 은 receive 가 바로 merge, 같은 Commit 이 다시 오면 Duplicate, 우리가 적용 안 한 지난 Commit 은 Stale.
/// 응용 메시지는 보낸 잎의 device_id 와 함께.
#[test]
fn receive_는_merge_중복_지난_epoch_를_가른다() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let c1 = update(&a, &mut ga);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &c1, now(), &w.ctx()).unwrap();
    assert_eq!(
        r,
        mls::Received::Merged {
            epoch: gb.epoch().as_u64()
        }
    );
    assert_eq!(
        mls::receive(&b.provider, &mut gb, Kind::Pair, &c1, now(), &w.ctx()).unwrap(),
        mls::Received::Duplicate
    );
    // 갈라진 지난 Commit(같은 epoch 에서 b 가 따로 만든 것이 아닌 다른 바이트) → Stale.
    let mut forged = c1.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        mls::receive(&b.provider, &mut gb, Kind::Pair, &forged, now(), &w.ctx()),
        Err(mls::Error::Stale)
    ));
    let m = send(&a, &mut ga, "누구");
    let want = lodelai_crypto::DeviceId::from_verifying_key(&keys(1).signing.verifying_key());
    assert_eq!(
        mls::receive(&b.provider, &mut gb, Kind::Pair, &m, now(), &w.ctx()).unwrap(),
        mls::Received::App {
            text: "누구".as_bytes().to_vec(),
            sender: want.as_str().to_owned()
        }
    );
}

/// group 종류의 Commit 은 merge 하지 않고 원 바이트를 둔다(§4-7).
#[test]
fn group_commit_은_확정_전_merge_하지_않는다() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch().as_u64();
    let c = update(&a, &mut ga);
    let r = mls::receive(&b.provider, &mut gb, Kind::Group, &c, now(), &w.ctx()).unwrap();
    assert_eq!(
        r,
        mls::Received::Staged {
            epoch: e,
            hash: mls::commit_hash(&c),
            joiner: None,
        }
    );
    assert_eq!(gb.epoch().as_u64(), e);
    let gid = gb.group_id().as_slice().to_vec();
    assert_eq!(
        b.provider
            .storage()
            .pending(&gid, e, &mls::commit_hash(&c))
            .unwrap(),
        Some(c)
    );
}

/// GroupContextExtensions(0xF0A1 바꾸기)를 담은 Commit 은 거절되고 epoch 그대로(§11 🟢⑧).
#[test]
fn 그룹_확장_바꾸는_commit_은_거절() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let pb = dir.path().join("b.db");
    let b = open(&pb, 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    let ext = mls::create_config(Kind::Group, &["mallory".to_owned()])
        .unwrap()
        .group_context_extensions()
        .clone();
    let t = a.provider.begin().unwrap();
    let (commit, _, _) = ga
        .update_group_context_extensions(&a.provider, ext, &a.signer)
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&commit).unwrap();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(
        matches!(r, Err(mls::Error::Rejected("group_context_extensions"))),
        "{r:?}"
    );
    let gid = gb.group_id().clone();
    drop(gb);
    let gb = MlsGroup::load(b.provider.storage(), &gid).unwrap().unwrap();
    assert_eq!(gb.epoch(), e);
}

/// 수명이 90일을 넘는 KeyPackage 를 Add 한 Commit 은 거절(§3 — openmls 기본만 믿지 않음).
#[test]
fn 수명이_긴_keypackage_add_는_거절() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let t = c.provider.begin().unwrap();
    let kp = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(now() - 10, now() + 200 * 24 * 3600))
        .leaf_node_capabilities(mls::capabilities())
        .build(
            mls::CIPHERSUITE,
            &c.provider,
            &c.signer,
            c.signer.credential(),
        )
        .unwrap();
    t.commit().unwrap();
    let t = a.provider.begin().unwrap();
    // openmls 는 보내는 쪽에서 막지 않는다 — 받는 쪽 이 앱 규칙이 막아야 한다.
    let (commit, _, _) = ga
        .add_members(&a.provider, &a.signer, &[kp.key_package().clone()])
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&commit).unwrap();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(
        matches!(r, Err(mls::Error::Rejected("add_lifetime_long"))),
        "{r:?}"
    );
    assert_eq!(
        gb.epoch(),
        ga.epoch(),
        "b 는 merge 하지 않음(a 도 자기 Commit 을 아직 merge 안 함)"
    );
}

/// Welcome 의 그룹 종류·id 가 기대와 다르면 들어가지 않고 되돌린다.
#[test]
fn welcome_종류가_다르면_되돌린다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let gid = mls::pair_group_id("alice", "bob");
    let t = a.provider.begin().unwrap();
    let mut ga = mls::create_group(&a.provider, &a.signer, Kind::Group, &gid, &[]).unwrap();
    t.commit().unwrap();
    let t = b.provider.begin().unwrap();
    let kp = mls::key_package(&b.provider, &b.signer, false).unwrap();
    t.commit().unwrap();
    let t = a.provider.begin().unwrap();
    let (_, welcome, _) = ga
        .add_members(&a.provider, &a.signer, &[kp.key_package().clone()])
        .unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    t.commit().unwrap();
    let w = mls::to_bytes(&welcome).unwrap();
    let r = mls::join_welcome(&b.provider, &w, Kind::Pair, &gid, &World::pair().ctx());
    assert!(
        matches!(r, Err(mls::Error::Rejected("welcome_kind"))),
        "{:?}",
        r.err()
    );
    assert!(
        MlsGroup::load(b.provider.storage(), &GroupId::from_slice(&gid))
            .unwrap()
            .is_none(),
        "되돌림"
    );
    // 기대가 맞으면 들어간다(KeyPackage 비밀도 되돌려져 그대로 있음).
    let g = mls::join_welcome(&b.provider, &w, Kind::Group, &gid, &World::pair().ctx()).unwrap();
    assert_eq!(mls::group_kind(&g), Some(Kind::Group));
}

/// merge 뒤 저장 오류가 나면 ROLLBACK 하고 메모리 그룹도 저장에서 다시 읽는다 — 같은 Commit 을 다시 처리하면 된다(설계 2a ①).
#[test]
fn merge_뒤_저장_오류면_그룹을_되돌리고_다시_처리된다() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    let c = update(&a, &mut ga);
    b.provider.storage().fail_next_mark_applied();
    assert!(mls::receive(&b.provider, &mut gb, Kind::Pair, &c, now(), &w.ctx()).is_err());
    assert_eq!(gb.epoch(), e, "메모리 그룹도 그 전 epoch");
    assert!(matches!(
        mls::receive(&b.provider, &mut gb, Kind::Pair, &c, now(), &w.ctx()).unwrap(),
        mls::Received::Merged { .. }
    ));
    assert_eq!(
        recv(&b, &mut gb, &send(&a, &mut ga, "다시 됨"))
            .unwrap()
            .as_deref(),
        Some("다시 됨")
    );
}

/// reset 은 적용·확정 전 기록도 비운다.
#[test]
fn reset_은_적용_기록도_비운다() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.db");
    let d = open(&p, 1).unwrap();
    d.provider
        .storage()
        .mark_applied(b"g", 5, &[7; 32])
        .unwrap();
    d.provider
        .storage()
        .put_pending(b"g", 5, &[7; 32], b"x")
        .unwrap();
    drop(d);
    MlsStore::reset(&p, &store_key(1)).unwrap();
    let d = open(&p, 1).unwrap();
    assert!(!d.provider.storage().applied(b"g", 5, &[7; 32]).unwrap());
    assert_eq!(
        d.provider.storage().pending(b"g", 5, &[7; 32]).unwrap(),
        None
    );
}

/// a 가 c(seed 3)의 KeyPackage 를 Add 한 Commit.
fn add_commit(a: &Dev, ga: &mut MlsGroup, c: &Dev) -> Vec<u8> {
    let t = c.provider.begin().unwrap();
    let kp = mls::key_package(&c.provider, &c.signer, false).unwrap();
    t.commit().unwrap();
    let t = a.provider.begin().unwrap();
    let (commit, _, _) = ga
        .add_members(&a.provider, &a.signer, &[kp.key_package().clone()])
        .unwrap();
    t.commit().unwrap();
    mls::to_bytes(&commit).unwrap()
}

/// 디렉터리에 아직 없는 기기의 Add → Retry(epoch 그대로·막지 않음), 디렉터리가 오면 같은 Commit 이 들어간다(ADR §5a ①).
#[test]
fn 디렉터리에_없는_기기_add_는_retry_뒤_들어간다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    let bytes = add_commit(&a, &mut ga, &c);
    let mut w = World::pair();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(
        matches!(r, Err(mls::Error::Retry("device_unknown"))),
        "{r:?}"
    );
    assert_eq!(gb.epoch(), e);
    // bob 의 두 번째 기기 — bob 뿌리(2)가 서명.
    w.add("bob", 3, 2, &[2]);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx()).unwrap();
    assert!(matches!(r, mls::Received::Merged { .. }), "{r:?}");
    assert_eq!(gb.epoch().as_u64(), e.as_u64() + 1);
}

/// 사슬이 없는 기기의 Add 는 처음엔 Retry(디렉터리가 늦을 수 있음), 같은 Commit 이 1시간 넘게 그대로면 멈춤 — 그 뒤로
/// 그 그룹은 받기·보내기 막힘(설계 2b 리뷰).
#[test]
fn 사슬_없는_기기_add_는_한_시간_뒤_멈추고_그룹을_막는다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    let bytes = add_commit(&a, &mut ga, &c);
    let mut w = World::pair();
    // devcert 없이 bob 아래, 늦게 등록 — 뿌리(2)에서 닿지 않는 이메일 기기(§2b 3).
    w.add("bob", 3, 5, &[]);
    let t0 = now();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, t0, &w.ctx());
    assert!(matches!(r, Err(mls::Error::Retry("no_chain"))), "{r:?}");
    let gid = gb.group_id().as_slice().to_vec();
    assert_eq!(b.provider.storage().state(&gid).unwrap(), None);
    let r = mls::receive(
        &b.provider,
        &mut gb,
        Kind::Pair,
        &bytes,
        t0 + 3599,
        &w.ctx(),
    );
    assert!(matches!(r, Err(mls::Error::Retry("no_chain"))), "{r:?}");
    let r = mls::receive(
        &b.provider,
        &mut gb,
        Kind::Pair,
        &bytes,
        t0 + 3600,
        &w.ctx(),
    );
    assert!(matches!(r, Err(mls::Error::Stalled("no_chain"))), "{r:?}");
    assert_eq!(gb.epoch(), e);
    let (state, reason, _) = b.provider.storage().state(&gid).unwrap().unwrap();
    assert_eq!(
        (state, reason.as_str()),
        (GroupState::StalledDevice, "no_chain")
    );
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(
        matches!(r, Err(mls::Error::Blocked(GroupState::StalledDevice))),
        "{r:?}"
    );
    assert!(matches!(
        mls::ensure_open(&b.provider, &gb),
        Err(mls::Error::Blocked(GroupState::StalledDevice))
    ));
    // 풀면(사람 확인) 다시 연다.
    b.provider.storage().clear_state(&gid).unwrap();
    mls::ensure_open(&b.provider, &gb).unwrap();
}

/// 멈춘 1:1 은 스스로 푼다(§12-19): 디렉터리가 늦어 1시간 넘게 멈춘 Add 가, 그 기기의 devcert 가 디렉터리에 오면 사람 손 없이
/// 들어가고 막음·행이 사라진다. 디렉터리에 와도 잎 키가 다르면 원래 멈춤(이유·처음 멈춘 때)을 그대로 둔다.
#[test]
fn 멈춘_1대1_은_디렉터리가_바뀌면_스스로_풀린다() {
    use lodelai_relay_client::conn::Mls;
    use lodelai_relay_client::mls_conn::{self, Handled, Retried};
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch().as_u64();
    let bytes = add_commit(&a, &mut ga, &c);
    let b = Mls {
        provider: b.provider,
        signer: b.signer,
    };
    let gid = gb.group_id().as_slice().to_vec();
    let mut late = World::pair();
    late.add("bob", 3, 5, &[]);
    let t0 = now();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, t0, &late.ctx());
    assert!(matches!(r, Err(mls::Error::Retry("no_chain"))), "{r:?}");
    let r = mls::receive(
        &b.provider,
        &mut gb,
        Kind::Pair,
        &bytes,
        t0 + 3600,
        &late.ctx(),
    );
    assert!(matches!(r, Err(mls::Error::Stalled("no_chain"))), "{r:?}");
    mls_conn::keep_stalled(&b, &gid, e, &bytes, &serde_json::json!({}), None, t0 + 3600);
    let stalled = b.provider.storage().state(&gid).unwrap().unwrap();
    let redo = |w: &World, at: u64| {
        let snap = mls_conn::stall_open(&b, &gid).unwrap();
        let mut g = mls_conn::load(&b, &gid).unwrap();
        let r = mls::receive(&b.provider, &mut g, Kind::Pair, &bytes, at, &w.ctx());
        assert!(!matches!(r, Err(mls::Error::Blocked(_))), "{r:?}");
        let h = if r.is_ok() {
            Handled::Done
        } else {
            Handled::Retry
        };
        mls_conn::stall_close(&b, &gid, snap, &h)
    };

    // 디렉터리에 왔는데 잎 키가 다르다(같은 device_id, 다른 서명 키) — 계속 멈춤, 처음 멈춘 때 그대로.
    let mut other = World::pair();
    other.add("bob", 3, 5, &[2]);
    other.live.last_mut().unwrap().ed25519 = keys(8).signing.verifying_key().to_bytes();
    assert_eq!(redo(&other, t0 + 7200), Retried::Still);
    assert_eq!(
        b.provider.storage().state(&gid).unwrap(),
        Some(stalled.clone())
    );
    assert_eq!(b.provider.storage().stalled().unwrap().len(), 1);
    assert_eq!(mls_conn::load(&b, &gid).unwrap().epoch().as_u64(), e);

    // bob 의 뿌리(2)가 서명한 devcert 가 디렉터리에 왔다(directory.update) — 풀림.
    let mut fresh = World::pair();
    fresh.add("bob", 3, 5, &[2]);
    assert_eq!(redo(&fresh, t0 + 7300), Retried::Freed);
    assert_eq!(b.provider.storage().state(&gid).unwrap(), None);
    assert!(b.provider.storage().stalled().unwrap().is_empty());
    assert_eq!(mls_conn::load(&b, &gid).unwrap().epoch().as_u64(), e + 1);
    // 풀린 뒤엔 다시 볼 것이 없다.
    assert!(mls_conn::stall_open(&b, &gid).is_none());
}

/// §12-23 ②: 디렉터리가 새로워져도 풀릴 수 없는 어긋남(여기선 relay 가 'bob 이 나감'이라 한 Commit 뒤 bob 잎이 남음, §4-4)은
/// `stalled_server` — 스스로 다시 볼 행을 남기지 않고, 다시 처리하려 열지도 않는다.
#[test]
fn 사용자_op_뒤_잎이_남으면_stalled_server_로_멈추고_스스로_보지_않는다() {
    use lodelai_relay_client::conn::Mls;
    use lodelai_relay_client::mls_conn;
    use lodelai_relay_client::mls_rules::GroupRule;
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch().as_u64();
    let bytes = update(&a, &mut ga);
    let b = Mls {
        provider: b.provider,
        signer: b.signer,
    };
    let gid = gb.group_id().as_slice().to_vec();
    let w = World::pair();
    let mut ctx = w.ctx();
    ctx.group = Some(GroupRule {
        op: "leave",
        subject: Some("bob"),
        subjects: &[],
    });
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &ctx);
    assert!(
        matches!(r, Err(mls::Error::Stalled("user_leaves_left"))),
        "{r:?}"
    );
    assert!(mls::server_fault("user_leaves_left") && !mls::server_fault("no_chain"));
    let (state, _, _) = b.provider.storage().state(&gid).unwrap().unwrap();
    assert_eq!(state, GroupState::StalledServer);
    assert_eq!(gb.epoch().as_u64(), e);
    mls_conn::keep_stalled(&b, &gid, e, &bytes, &serde_json::json!({}), None, now());
    assert!(b.provider.storage().stalled().unwrap().is_empty());
    assert!(mls_conn::stall_open(&b, &gid).is_none());
    assert_eq!(
        mls_conn::blocked(&b, &gid),
        Some(GroupState::StalledServer),
        "열지 않는다"
    );
}

/// 새 기기 직후: 내 다른 기기가 certify 하고 바로 Add — devcert 의 directory.update 가 Commit 보다 늦게 와도 멈추지 않고
/// 갱신 뒤 같은 Commit 이 들어간다(ADR §5a ①).
#[test]
fn devcert_보다_먼저_온_add_는_갱신_뒤_들어간다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    let bytes = add_commit(&a, &mut ga, &c);
    let mut w = World::pair();
    w.add("bob", 3, 5, &[]);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(matches!(r, Err(mls::Error::Retry("no_chain"))), "{r:?}");
    assert_eq!(gb.epoch(), e);
    // directory.update 로 devcert(bob 뿌리 2 의 서명)가 옴.
    w.live.retain(|d| d.device_id != id_of(3));
    w.add("bob", 3, 5, &[2]);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx()).unwrap();
    assert!(matches!(r, mls::Received::Merged { .. }), "{r:?}");
    let gid = gb.group_id().as_slice().to_vec();
    assert_eq!(b.provider.storage().state(&gid).unwrap(), None);
}

/// 막 폐기된 기기의 Update(폐기 전에 relay 가 순서를 줌)는 받는 쪽 디렉터리가 폐기를 먼저 봐도(증명 있든 없든) 들어간다. 그 기기를 잎으로
/// 넣는 것은 멈춤(설계 2b 리뷰).
#[test]
fn 막_폐기된_기기의_commit_은_받고_그_기기_add_는_멈춤() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let c = update(&a, &mut ga);
    let mut w = World::pair();
    w.revoke_self("alice", 1);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &c, now(), &w.ctx()).unwrap();
    assert!(matches!(r, mls::Received::Merged { .. }), "{r:?}");
    // 증명 없는 폐기(관리자 내보내기·복구) 직후의 Update 도 받는다 — 디렉터리에서 사라졌을 뿐 우리 트리의 잎.
    let c2 = update(&a, &mut ga);
    let mut gone = World::pair();
    gone.live.retain(|d| d.device_id != id_of(1));
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &c2, now(), &gone.ctx()).unwrap();
    assert!(matches!(r, mls::Received::Merged { .. }), "{r:?}");

    // 그 기기를 잎으로 넣는 것(Add·external commit)은 멈춤 — 훔친 기기 되살리기 막음.
    assert_eq!(
        lodelai_relay_client::mls_rules::leaf_ok(
            &w,
            "alice",
            &id_of(1),
            &keys(1).signing.verifying_key().to_bytes()
        ),
        lodelai_relay_client::mls_rules::Verdict::Stall("revoked")
    );
}

/// 디렉터리에 없는(막 폐기된) 잎이 update path 로 서명 키를 바꾸면 멈춤 — duty Remove 전에 키를 돌려 버티는 길(설계
/// 2b 리뷰 7ca1cab6).
#[test]
fn 막_폐기된_기기가_서명_키를_바꾸면_멈춤() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let e = gb.epoch();
    // 같은 credential(device_id) 에 새 서명 키.
    let new = DeviceSigner::new(keys(9).signing);
    let t = a.provider.begin().unwrap();
    let bundle = ga
        .self_update_with_new_signer(
            &a.provider,
            &a.signer,
            NewSignerBundle {
                signer: &new,
                credential_with_key: CredentialWithKey {
                    credential: a.signer.credential().credential,
                    signature_key: new.credential().signature_key,
                },
            },
            LeafNodeParameters::default(),
        )
        .unwrap();
    let c = mls::to_bytes(bundle.commit()).unwrap();
    t.commit().unwrap();
    let mut w = World::pair();
    w.revoke_self("alice", 1);
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &c, now(), &w.ctx());
    assert!(
        matches!(r, Err(mls::Error::Stalled("revoked_key_change"))),
        "{r:?}"
    );
    assert_eq!(gb.epoch(), e);
}

/// 응용 메시지의 보낸 잎이 봉투 기기와 다르면 버리고(ratchet 도 되돌림), 맞는 기기로 오면 같은 바이트가 열린다.
#[test]
fn 봉투_기기와_다른_응용은_버린다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let w = World::pair();
    let m = send(&a, &mut ga, "누구");
    let other = id_of(9);
    let r = mls::receive(
        &b.provider,
        &mut gb,
        Kind::Pair,
        &m,
        now(),
        &w.ctx_from(Some(&other)),
    );
    assert!(
        matches!(r, Err(mls::Error::Rejected("sender_mismatch"))),
        "{r:?}"
    );
    let gid = gb.group_id().as_slice().to_vec();
    assert_eq!(
        b.provider.storage().state(&gid).unwrap(),
        None,
        "버림은 막지 않음"
    );
    let me = id_of(1);
    assert_eq!(
        mls::receive(
            &b.provider,
            &mut gb,
            Kind::Pair,
            &m,
            now(),
            &w.ctx_from(Some(&me))
        )
        .unwrap(),
        mls::Received::App {
            text: "누구".as_bytes().to_vec(),
            sender: me.clone()
        }
    );
}

/// external commit(상태를 잃은 기기가 GroupInfo 로 다시 들어옴): 같은 기기의 옛 잎 Remove 와 ExternalInit 은 여기서만 허용.
/// 봉투 기기가 다르면 멈춤.
#[test]
fn external_commit_은_자기_옛_잎만_바꾼다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (ga, _gb) = pair(&a, &b);
    // b 가 상태를 잃음 — 새 저장, 같은 기기 키.
    let b2 = open(&dir.path().join("b2.db"), 2).unwrap();
    let gi = ga
        .export_group_info(a.provider.crypto(), &a.signer, true)
        .unwrap();
    let MlsMessageBodyIn::GroupInfo(vgi) =
        mls::parse(&mls::to_bytes(&gi).unwrap()).unwrap().extract()
    else {
        panic!("GroupInfo 가 아님");
    };
    let t = b2.provider.begin().unwrap();
    let (_g2, bundle) = MlsGroup::external_commit_builder()
        .with_config(mls::join_config())
        .build_group(&b2.provider, vgi, b2.signer.credential())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(mls::capabilities())
                .build(),
        )
        .load_psks(b2.provider.storage())
        .unwrap()
        .build(b2.provider.rand(), b2.provider.crypto(), &b2.signer, |_| {
            true
        })
        .unwrap()
        .finalize(&b2.provider)
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(bundle.commit()).unwrap();
    let w = World::pair();

    // 봉투가 다른 기기라 하면 멈춤(a 쪽 그룹을 따로 열어 본다).
    let gid = ga.group_id().clone();
    let a_db = dir.path().join("a.db");
    drop(ga);
    let mut ga = MlsGroup::load(a.provider.storage(), &gid).unwrap().unwrap();
    let e = ga.epoch();
    let other = id_of(9);
    let r = mls::receive(
        &a.provider,
        &mut ga,
        Kind::Pair,
        &bytes,
        now(),
        &w.ctx_from(Some(&other)),
    );
    assert!(
        matches!(r, Err(mls::Error::Stalled("sender_mismatch"))),
        "{r:?}"
    );
    assert_eq!(ga.epoch(), e);
    a.provider.storage().clear_state(gid.as_slice()).unwrap();
    let _ = a_db;

    let me = id_of(2);
    let r = mls::receive(
        &a.provider,
        &mut ga,
        Kind::Pair,
        &bytes,
        now(),
        &w.ctx_from(Some(&me)),
    )
    .unwrap();
    assert!(matches!(r, mls::Received::Merged { .. }), "{r:?}");
    assert_eq!(ga.members().count(), 2, "옛 잎을 빼고 새 잎");
}

/// PSK 제안을 담은 Commit 은 거절. ReInit 은 openmls 0.8.3 이 보내는 쪽에서 조용히 빼서(`filter_proposals` TODO #751) 공개 API 로는
/// 담을 수 없다 — 받는 쪽은 `check_commit` 의 match 가 덮는다. 빠지는 것을 여기서 확인해 둔다(판이 바뀌면 이 시험이 알린다).
#[test]
fn psk_commit_은_거절_reinit_은_보내는_쪽이_뺀다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let w = World::pair();

    // ReInit{group_id, version 1, ciphersuite 0x0003, extensions []} — 구조체 필드는 crate 밖에 닫혀 있어 TLS 바이트로.
    let mut raw = vec![32u8];
    raw.extend_from_slice(ga.group_id().as_slice());
    raw.extend_from_slice(&[0, 1, 0, 3, 0]);
    let reinit = ReInitProposal::tls_deserialize_exact(&raw).unwrap();
    let t = a.provider.begin().unwrap();
    let bundle = ga
        .commit_builder()
        .add_proposal(Proposal::ReInit(Box::new(reinit)))
        .load_psks(a.provider.storage())
        .unwrap()
        .build(a.provider.rand(), a.provider.crypto(), &a.signer, |_| true)
        .unwrap()
        .stage_commit(&a.provider)
        .unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(bundle.commit()).unwrap();
    // 받는 쪽에서 직접 열어 제안이 없는지 본다(되돌리고 receive 로 다시).
    {
        let pm = mls::parse(&bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let _t = b.provider.begin().unwrap();
        let p = gb.process_message(&b.provider, pm).unwrap();
        let ProcessedMessageContent::StagedCommitMessage(c) = p.into_content() else {
            panic!("Commit 이 아님");
        };
        assert_eq!(c.queued_proposals().count(), 0, "ReInit 이 빠진 빈 Commit");
    }
    let gid = gb.group_id().clone();
    gb = MlsGroup::load(b.provider.storage(), &gid).unwrap().unwrap();
    assert!(matches!(
        mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx()).unwrap(),
        mls::Received::Merged { .. }
    ));
    let e = gb.epoch();

    // 외부 PSK — 두 쪽에 같은 PSK 를 두어 openmls 가 열 수 있게 한 뒤에도 이 앱 규칙이 막는다.
    let psk = PreSharedKeyId::external(b"lodelai-test".to_vec(), vec![7; 32]);
    for d in [&a, &b] {
        let t = d.provider.begin().unwrap();
        psk.store(&d.provider, &[1; 32]).unwrap();
        t.commit().unwrap();
    }
    let t = a.provider.begin().unwrap();
    let bundle = ga
        .commit_builder()
        .add_proposal(Proposal::PreSharedKey(Box::new(PreSharedKeyProposal::new(
            psk,
        ))))
        .load_psks(a.provider.storage())
        .unwrap()
        .build(a.provider.rand(), a.provider.crypto(), &a.signer, |_| true)
        .unwrap()
        .stage_commit(&a.provider)
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(bundle.commit()).unwrap();
    let r = mls::receive(&b.provider, &mut gb, Kind::Pair, &bytes, now(), &w.ctx());
    assert!(matches!(r, Err(mls::Error::Rejected("psk"))), "{r:?}");
    assert_eq!(gb.epoch(), e);
}

/// 설계 리뷰 ①: relay 가 준 KeyPackage 의 서명 키가 디렉터리의 그 기기 키가 아니면 Add 하지 않는다(MITM 막기).
#[test]
fn 디렉터리와_키가_다른_keypackage_는_add_하지_않는다() {
    let dir = tempfile::tempdir().unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let evil = open(&dir.path().join("e.db"), 9).unwrap();
    let kp_b64 = |kp: &KeyPackage| {
        lodelai_crypto::encoding::encode(&mls::to_bytes(&MlsMessageOut::from(kp.clone())).unwrap())
    };
    let t = b.provider.begin().unwrap();
    let good = mls::key_package(&b.provider, &b.signer, false).unwrap();
    t.commit().unwrap();
    // 공격자 키로 서명하고 Credential 만 bob 의 device_id 로.
    let t = evil.provider.begin().unwrap();
    let forged = KeyPackage::builder()
        .leaf_node_capabilities(mls::capabilities())
        .build(
            mls::CIPHERSUITE,
            &evil.provider,
            &evil.signer,
            CredentialWithKey {
                credential: BasicCredential::new(id_of(2).into_bytes()).into(),
                signature_key: evil.signer.credential().signature_key,
            },
        )
        .unwrap();
    t.commit().unwrap();
    let w = World::pair();
    let frame = serde_json::json!({"t": "key_packages", "items": [
        {"device_id": id_of(2), "key_package": kp_b64(forged.key_package())},
        {"device_id": id_of(2), "key_package": kp_b64(good.key_package())},
    ]});
    let got = lodelai_relay_client::mls_conn::key_packages(&frame, &w.ctx());
    assert_eq!(got.len(), 1, "디렉터리 키와 같은 것만");
    assert_eq!(
        got[0].leaf_node().signature_key().as_slice(),
        keys(2).signing.verifying_key().to_bytes().as_slice()
    );
}

/// 설계 리뷰 ②: Welcome 트리에 대화 사용자가 아닌 잎이 섞여 있으면 들어가지 않는다.
#[test]
fn 남의_잎이_섞인_welcome_으로는_들어가지_않는다() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let gid = mls::pair_group_id("alice", "bob");
    let t = a.provider.begin().unwrap();
    let mut ga = mls::create_group(&a.provider, &a.signer, Kind::Pair, &gid, &[]).unwrap();
    t.commit().unwrap();
    let mut kps = Vec::new();
    for d in [&b, &c] {
        let t = d.provider.begin().unwrap();
        kps.push(
            mls::key_package(&d.provider, &d.signer, false)
                .unwrap()
                .key_package()
                .clone(),
        );
        t.commit().unwrap();
    }
    let t = a.provider.begin().unwrap();
    let (_, welcome, _) = ga.add_members(&a.provider, &a.signer, &kps).unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    t.commit().unwrap();
    let w = mls::to_bytes(&welcome).unwrap();
    // carol(3)은 디렉터리에 있지만 이 pair 의 사용자가 아니다.
    let mut world = World::pair();
    world.add("carol", 3, 1, &[]);
    let r = mls::join_welcome(&b.provider, &w, Kind::Pair, &gid, &world.ctx());
    assert!(r.is_err(), "들어가면 안 됨");
    assert!(
        MlsGroup::load(b.provider.storage(), &GroupId::from_slice(&gid))
            .unwrap()
            .is_none(),
        "join 0"
    );
}

/// §4-7·§12-14: 쥔 group Commit 은 commit_final 의 해시가 같을 때만 merge(epoch+1·쥔 것 지움), 다른 해시면 버리고 epoch 그대로.
/// commit_void 면 버린다.
#[test]
fn group_commit_은_같은_해시의_확정에만_merge() {
    let w = World::pair();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let (mut ga, mut gb) = pair(&a, &b);
    let gid = gb.group_id().as_slice().to_vec();
    let e = gb.epoch().as_u64();
    // 다른 해시의 확정 — 쥔 것을 버리고 그대로.
    let c = update(&a, &mut ga);
    mls::receive(&b.provider, &mut gb, Kind::Group, &c, now(), &w.ctx()).unwrap();
    assert!(!mls::finalize(&b.provider, &mut gb, e, &[9; 32]).unwrap());
    assert_eq!(gb.epoch().as_u64(), e);
    assert_eq!(
        b.provider
            .storage()
            .pending(&gid, e, &mls::commit_hash(&c))
            .unwrap(),
        None
    );
    // 같은 Commit 을 다시 쥐고 같은 해시의 확정 — merge.
    mls::receive(&b.provider, &mut gb, Kind::Group, &c, now(), &w.ctx()).unwrap();
    assert!(mls::finalize(&b.provider, &mut gb, e, &mls::commit_hash(&c)).unwrap());
    assert_eq!(gb.epoch().as_u64(), e + 1);
    assert_eq!(
        b.provider
            .storage()
            .pending(&gid, e, &mls::commit_hash(&c))
            .unwrap(),
        None
    );
    // 확정 뒤 a 의 응용 메시지가 열린다(같은 epoch).
    let m = send(&a, &mut ga, "확정 뒤");
    assert_eq!(recv(&b, &mut gb, &m).unwrap().as_deref(), Some("확정 뒤"));
    // 무효 — 쥔 것을 버리고 그대로.
    let c2 = update(&a, &mut ga);
    let e2 = gb.epoch().as_u64();
    mls::receive(&b.provider, &mut gb, Kind::Group, &c2, now(), &w.ctx()).unwrap();
    mls::discard(&b.provider, &gid, e2).unwrap();
    assert_eq!(
        b.provider
            .storage()
            .pending(&gid, e2, &mls::commit_hash(&c2))
            .unwrap(),
        None
    );
    assert_eq!(gb.epoch().as_u64(), e2);
}

/// alice(관리자) 가 bob·carol 을 group 종류에 넣는다 → (alice, bob, carol 그룹).
fn group3(a: &Dev, b: &Dev, c: &Dev) -> (MlsGroup, MlsGroup, MlsGroup) {
    let t = a.provider.begin().unwrap();
    let mut ga = mls::create_group(
        &a.provider,
        &a.signer,
        Kind::Group,
        b"01m5x5y8dfy5z700g66tt0zcse",
        &["alice@lodelai.example".to_owned()],
    )
    .unwrap();
    t.commit().unwrap();
    let kps: Vec<KeyPackage> = [b, c]
        .iter()
        .map(|d| {
            let t = d.provider.begin().unwrap();
            let kp = mls::key_package(&d.provider, &d.signer, false).unwrap();
            t.commit().unwrap();
            kp.key_package().clone()
        })
        .collect();
    let t = a.provider.begin().unwrap();
    let (_, welcome, _) = ga.add_members(&a.provider, &a.signer, &kps).unwrap();
    ga.merge_pending_commit(&a.provider).unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&welcome).unwrap();
    let join = |d: &Dev| {
        let MlsMessageBodyIn::Welcome(w) = mls::parse(&bytes).unwrap().extract() else {
            panic!("Welcome 이 아님");
        };
        let t = d.provider.begin().unwrap();
        let g = StagedWelcome::new_from_welcome(&d.provider, &mls::join_config(), w, None)
            .unwrap()
            .into_group(&d.provider)
            .unwrap();
        t.commit().unwrap();
        g
    };
    (ga, join(b), join(c))
}

fn world3() -> World {
    let mut w = World::pair();
    w.members.push("carol".to_owned());
    w.add("carol", 3, 1, &[]);
    w
}

fn rule<'a>(w: &'a World, op: &'a str, subject: Option<&'a str>) -> RuleCtx<'a> {
    let mut c = w.ctx();
    c.group = Some(lodelai_relay_client::mls_rules::GroupRule {
        op,
        subject,
        subjects: &[],
    });
    c
}

fn leaf_of(g: &MlsGroup, seed: u8) -> LeafNodeIndex {
    let id = id_of(seed);
    g.members()
        .find(|m| {
            lodelai_relay_client::mls_rules::device_of(&m.credential).as_deref()
                == Some(id.as_str())
        })
        .unwrap()
        .index
}

/// QA(16 qa_forged_remove 의 MLS 판, §4-4): 관리자 아닌 bob 이 carol 을 빼는 Commit 은 서버가 통과시켜도 받는 쪽이 멈춤 —
/// 관리자 alice 의 같은 Commit 은 받는다. GCE 로 관리자 바꾸기도 관리자만(§12-13 ①).
#[test]
fn 관리자_아닌_사람의_remove_와_admin_은_받는_쪽이_막는다() {
    let w = world3();
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("a.db"), 1).unwrap();
    let b = open(&dir.path().join("b.db"), 2).unwrap();
    let c = open(&dir.path().join("c.db"), 3).unwrap();
    let (mut ga, mut gb, mut gc) = group3(&a, &b, &c);
    let carol = leaf_of(&gb, 3);
    // bob 의 위조 remove.
    let t = b.provider.begin().unwrap();
    let (forged, _, _) = gb.remove_members(&b.provider, &b.signer, &[carol]).unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&forged).unwrap();
    let r = mls::receive(
        &a.provider,
        &mut ga,
        Kind::Group,
        &bytes,
        now(),
        &rule(&w, "remove", Some("carol")),
    );
    assert!(
        matches!(r, Err(mls::Error::Stalled("remove_live"))),
        "{r:?}"
    );
    // bob 의 위조 admin(GCE).
    let ext = mls::with_admins(&gb, &["bob@lodelai.example".to_owned()]).unwrap();
    let t = b.provider.begin().unwrap();
    gb.clear_pending_commit(b.provider.storage()).unwrap();
    let (gce, _, _) = gb
        .update_group_context_extensions(&b.provider, ext, &b.signer)
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&gce).unwrap();
    // 한 번 멈춘 그룹은 막히므로 다른 받는 기기(carol)로 본다.
    let r = mls::receive(
        &c.provider,
        &mut gc,
        Kind::Group,
        &bytes,
        now(),
        &rule(&w, "admin", Some("bob")),
    );
    assert!(matches!(r, Err(mls::Error::Stalled("admin_rule"))), "{r:?}");
    // 관리자 alice 의 remove 는 받는다.
    let carol_a = leaf_of(&ga, 3);
    let t = a.provider.begin().unwrap();
    let (ok, _, _) = ga
        .remove_members(&a.provider, &a.signer, &[carol_a])
        .unwrap();
    t.commit().unwrap();
    let bytes = mls::to_bytes(&ok).unwrap();
    // bob 이 받는다(자기 위조 Commit 은 버리고).
    let t = b.provider.begin().unwrap();
    gb.clear_pending_commit(b.provider.storage()).unwrap();
    t.commit().unwrap();
    let r = mls::receive(
        &b.provider,
        &mut gb,
        Kind::Group,
        &bytes,
        now(),
        &rule(&w, "remove", Some("carol")),
    );
    assert!(matches!(r, Ok(mls::Received::Staged { .. })), "{r:?}");
}

/// #819: 깨짐 무효 셈은 서로 다른 낸 기기를 세고, 다시 열어도 남고(재시작), 지우면 0 부터.
#[test]
fn 깨짐_무효_셈은_낸_기기를_세고_다시_열어도_남는다() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rc.db");
    let g = b"grp-1";
    {
        let d = open(&path, 1).unwrap();
        let st = d.provider.storage();
        assert_eq!(st.note_broken_void(g, "dev-a").unwrap(), (1, 1));
        assert_eq!(
            st.note_broken_void(g, "dev-a").unwrap(),
            (2, 1),
            "같은 기기는 한 번만 센다"
        );
    }
    let d = open(&path, 1).unwrap();
    let st = d.provider.storage();
    assert_eq!(
        st.note_broken_void(g, "dev-b").unwrap(),
        (3, 2),
        "다시 열어도 남는다"
    );
    assert_eq!(
        st.note_broken_void(b"grp-2", "dev-a").unwrap(),
        (1, 1),
        "그룹마다 따로"
    );
    st.clear_broken_voids(g).unwrap();
    assert_eq!(
        st.note_broken_void(g, "dev-a").unwrap(),
        (1, 1),
        "지우면 0 부터"
    );
}
