//! MLS 저장(묶음 22 §8, ADR 0012 §6): openmls `StorageProvider` 를 relay-client SQLite 의 `mls_kv` 표로 구현한다.
//!
//! - 꼴은 openmls 의 메모리 저장(`openmls_memory_storage` 0.5, MIT)을 따른다: 열 키 = 라벨 ‖ serde_json(키) ‖ 판(u16 BE),
//!   목록 값(내 잎·제안 줄)은 한 값 안에 JSON 배열로. 그 구현의 `clear_proposal_queue` 가 라벨 없는 키를 지우는 실수는 옮기지 않았다.
//! - **값은 Keychain 의 32 B 열쇠로 XChaCha20-Poly1305 암호화**한다(nonce 24 B 앞붙임, AAD = 열 키 — 다른 행으로 옮겨 끼우지
//!   못하게). DB 는 outbox 와 같은 파일이라 `secure_delete` 가 이미 켜져 있다 — 지운·덮어쓴 행이 본 DB free page 에 남지 않는다.
//! - **WAL**: `secure_delete` 는 `-wal` 의 옛 프레임을 덮지 않는다. 열쇠는 Keychain 에 그대로라, 나중에 기기를 턴 쪽이 `-wal` 의
//!   옛 암호문으로 지난 epoch 비밀을 열 수 있다(FS 구멍 — 설계 bc695ca3 리뷰 ①). 그래서 쓰기·지우기가 있었으면 표시해 두고,
//!   openmls 호출 하나(merge·KeyPackage 소비·그룹 지우기)가 끝날 때마다 [`MlsStore::scrub`] 로 WAL 을 본 DB 로 옮겨 0 으로 자른다
//!   (outbox 와 같은 `truncate_wal`). 닫힐 때도 한 번.
//! - `mls_meta.kid` = SHA-256(열쇠) 앞 8 B. 열쇠가 바뀌었으면(Keychain 항목을 잃음) 열 때 [`MlsStoreError::KeyMismatch`] 로
//!   한 번에 알린다 — 그룹마다 복호화 오류가 흩어지지 않게(그때는 저장을 비우고 다시 들어간다).
//! - 이 기기의 서명 키(기기 Ed25519)는 여기 넣지 않는다 — Keychain 에만 있고, openmls 에는 `Signer` 로만 빌려준다.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use lodelai_effects::Rng;
use openmls_traits::storage::{traits, Entity, Key, StorageProvider, CURRENT_VERSION};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// 저장 오류. 값·키 바이트는 넣지 않는다.
#[derive(Debug, thiserror::Error)]
pub enum MlsStoreError {
    #[error("sqlite: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("직렬화: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("MLS 저장 값을 풀지 못했다")]
    Crypto,
    #[error("난수: {0}")]
    Rng(String),
    /// 저장된 값을 만든 열쇠와 지금 열쇠가 다르다(Keychain 항목을 잃음).
    #[error("MLS 저장 열쇠가 바뀌었다")]
    KeyMismatch,
    #[error("I/O: {0}")]
    Io(String),
}

type R<T> = Result<T, MlsStoreError>;

/// MLS 표(outbox 와 같은 DB 파일, 이 저장의 연결만 쓴다).
fn opened_row(msg_id: &str) -> Vec<u8> {
    let mut r = b"opened\0".to_vec();
    r.extend_from_slice(msg_id.as_bytes());
    r
}

const SCHEMA: &str = r"
-- 열 키 = 라벨 ‖ 키 ‖ 판, 값 = XChaCha20-Poly1305(nonce ‖ 암호문).
CREATE TABLE IF NOT EXISTS mls_kv (
  k BLOB PRIMARY KEY,
  v BLOB NOT NULL
) WITHOUT ROWID;
-- 값을 만든 열쇠의 지문(SHA-256 앞 8 B) — 열쇠를 잃었는지 한 번에 안다.
CREATE TABLE IF NOT EXISTS mls_meta (
  id  INTEGER PRIMARY KEY CHECK (id = 0),
  kid BLOB NOT NULL
);
-- 적용(merge)한 Commit(묶음 22 리뷰 ④): merge 와 같은 트랜잭션에 남긴다. merge 뒤 relay ack 전에 죽어 같은 Commit 이 다시
-- 오면 '이미 그 epoch' 로 조용히 넘긴다(멈춤 판정에 넣지 않음). 그룹마다 최근 몇 개만. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_applied (
  grp   BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  hash  BLOB NOT NULL,
  PRIMARY KEY (grp, epoch)
) WITHOUT ROWID;
-- group 종류의 2단계 확정(§4-7): commit_final 까지 merge 하지 않는다. StagedCommit 은 메모리 값이라 앱이 그 사이 다시 켜질 수
-- 있어 원 Commit 바이트를 두고 final 때 다시 처리한다(공개 메시지 — 비밀 없음).
CREATE TABLE IF NOT EXISTS mls_pending (
  grp   BLOB NOT NULL,
  epoch INTEGER NOT NULL,
  hash  BLOB NOT NULL,
  bytes BLOB NOT NULL,
  PRIMARY KEY (grp, epoch, hash)
) WITHOUT ROWID;
-- 보내기·받기를 막은 그룹(2b): 'stalled_device'(규칙 밖 Commit — 사람 확인·relay 이상) · 'syncing'(실패 뒤 저장에서 다시 읽지
-- 못함 — 다시 들어가야 함). 행이 없으면 보통. 비밀 없음.
-- 디렉터리가 늦어 다시 볼 Commit(ADR §5a ①): 처음 본 때. 1시간 넘게 풀리지 않으면 멈춤(설계 2b 리뷰). 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_retry (
  grp   BLOB NOT NULL,
  hash  BLOB NOT NULL,
  since INTEGER NOT NULL,
  PRIMARY KEY (grp, hash)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mls_group_state (
  grp    BLOB PRIMARY KEY,
  state  TEXT NOT NULL,
  reason TEXT NOT NULL,
  since  INTEGER NOT NULL
) WITHOUT ROWID;
-- 연 응용 메시지 평문(암호화, 열 키 = 'opened' ‖ msg_id): 코어 ack 까지. MLS 는 같은 메시지를 두 번 못 연다(FS).
CREATE TABLE IF NOT EXISTS mls_opened (
  msg_id TEXT PRIMARY KEY,
  v      BLOB NOT NULL,
  at     INTEGER NOT NULL
) WITHOUT ROWID;
-- 그룹 → 대화 주소(EvConversationSync 의 conversation — pair 면 상대 사람 주소, self 면 내 주소). 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_conv (
  grp          BLOB PRIMARY KEY,
  conversation TEXT NOT NULL
) WITHOUT ROWID;
-- group 종류의 화면 값(묶음 16 GroupState): 이름(group_meta 응용 메시지)·확정 seq·이 기기가 들어온 seq. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_group_meta (
  grp        BLOB PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT '',
  seq        INTEGER NOT NULL DEFAULT 0,
  joined_seq INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
-- 확정을 기다리는 group Commit 의 헤더(내 것·남의 것) — commit_final 때 코어에 GroupUpdate{op, actor, subject} 로. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_commit_meta (
  grp     BLOB NOT NULL,
  epoch   INTEGER NOT NULL,
  hash    BLOB NOT NULL,
  op      TEXT NOT NULL,
  actor   TEXT NOT NULL,
  subject TEXT,
  PRIMARY KEY (grp, epoch, hash)
) WITHOUT ROWID;
-- 주기 Update(§7): 그룹마다 마지막 내 Update(또는 처음 본) 시각·그 뒤 보낸 내 응용 메시지 수. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_update (
  grp     BLOB PRIMARY KEY,
  last_ms INTEGER NOT NULL,
  sent    INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
-- 대화를 멈추게 한 Handshake(§12-19): 디렉터리를 받을 때·간격마다 같은 길로 다시 처리해 풀리면 지운다. 그룹마다 하나(처음 것 —
-- 그 뒤 것은 막혀 ack 하지 않고 relay 가 다시 준다). group 종류는 확정 seq 가 붙어야 다시 본다(쥔 채 멈췄으면 commit_final 이
-- 채움). since = 처음 멈춘 때(ms) — 30일 넘으면 그만 본다. 공개 메시지 — 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_stalled (
  grp       BLOB PRIMARY KEY,
  epoch     INTEGER NOT NULL,
  hash      BLOB NOT NULL,
  message   TEXT NOT NULL,
  group_seq INTEGER,
  since     INTEGER NOT NULL
) WITHOUT ROWID;
-- 막힌 동안 열지 못하고 버린 응용 메시지가 처음 온 때(§12-23 ③ — 화면 '이때부터 받지 못한 글' 줄, EvConversationSync.lost_since).
-- 풀리면 그 알림에 실어 보내고 지운다. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_lost (
  grp   BLOB PRIMARY KEY,
  since INTEGER NOT NULL
) WITHOUT ROWID;
-- 내가 낸 사람 op 그룹 Commit 의 변경 줄 키(§12-27 ⓒ — 처음 보낸 group 메시지 msg_id). epoch 마다 내 Commit 은 하나.
-- 확정·무효 결과에서 꺼내 코어에 GroupChangePending 으로. 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_change (
  grp       BLOB NOT NULL,
  epoch     INTEGER NOT NULL,
  change_id TEXT NOT NULL,
  PRIMARY KEY (grp, epoch)
) WITHOUT ROWID;
-- 그 대화에서 마지막으로 연 응용 메시지의 시각(§12-27 ⓐ — rejoin_needed 때 lost_since 의 시작). 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_recv (
  grp BLOB PRIMARY KEY,
  at  INTEGER NOT NULL
) WITHOUT ROWID;
-- 이 기기에 한 번 한 일(예 'kp_published' — 첫 KeyPackage 묶음을 relay 가 받았음, §3). 비밀 없음.
CREATE TABLE IF NOT EXISTS mls_flags (
  name TEXT PRIMARY KEY,
  at   INTEGER NOT NULL
) WITHOUT ROWID;
";

/// 대화를 멈추게 한 Handshake 한 행(§12-19).
#[derive(Debug, Clone)]
pub struct Stalled {
    pub group: Vec<u8>,
    pub message: String,
    pub group_seq: Option<u64>,
    pub since: i64,
}

/// 막힌 그룹의 상태(`EvConversationSync.state` 와 같은 이름).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupState {
    /// 잎 자격(디렉터리·devcert·키)에 기대는 규칙 밖 Commit 으로 멈춤 — 디렉터리가 바뀌면 스스로 다시 본다(§12-19).
    StalledDevice,
    /// 디렉터리가 새로워져도 풀릴 수 없는 어긋남(relay 이상 — §12-23 ②). 스스로 다시 보지 않고 '다시 받기'·'나가기'만.
    StalledServer,
    /// 실패 뒤 저장에서 그룹을 다시 읽지 못함 — 다시 들어가야 한다.
    Syncing,
}

impl GroupState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StalledDevice => "stalled_device",
            Self::StalledServer => "stalled_server",
            Self::Syncing => "syncing",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "syncing" => Self::Syncing,
            "stalled_server" => Self::StalledServer,
            // 모르는 값도 막는다.
            _ => Self::StalledDevice,
        }
    }
}

/// `mls_applied` 에 그룹마다 남기는 수(지난 epoch 비밀 수 + 지금).
const APPLIED_KEEP: i64 = crate::mls::MAX_PAST_EPOCHS as i64 + 1;

/// openmls 저장. outbox 와 **같은 DB 파일에 자기 연결**을 둔다 — openmls 호출 하나를 트랜잭션 하나로 묶을 때([`MlsStore::begin`])
/// 다른 스레드의 outbox 쓰기가 그 트랜잭션에 끼어 ROLLBACK 에 같이 지워지지 않게(WAL 이 두 연결의 쓰기를 차례로 세운다).
pub struct MlsStore {
    conn: Mutex<Connection>,
    /// MLS 동작 하나씩 — 두 동작이 한 연결의 트랜잭션에 섞이지 않게. [`Txn`] 이 쥔다.
    op: Mutex<()>,
    cipher: XChaCha20Poly1305,
    rng: Arc<dyn Rng>,
    /// 마지막 [`MlsStore::scrub`] 뒤 쓰기·지우기가 있었다(WAL 에 옛 프레임이 있을 수 있음).
    dirty: AtomicBool,
    /// 시험: 다음 [`MlsStore::mark_applied`] 를 실패시킨다(merge 뒤 저장 오류).
    fail_next: AtomicBool,
}

impl std::fmt::Debug for MlsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlsStore")
    }
}

/// rusqlite 기본과 같은 쓰기 대기(outbox 연결과 차례로 쓸 때).
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn kid(key: &Zeroizing<[u8; 32]>) -> Vec<u8> {
    Sha256::digest(key.as_slice())[..8].to_vec()
}

fn connect(path: &Path) -> R<Connection> {
    crate::outbox::create_private(path).map_err(|e| MlsStoreError::Io(e.to_string()))?;
    let c = Connection::open(path)?;
    crate::outbox::pragmas(&c)?;
    c.execute_batch(SCHEMA)?;
    Ok(c)
}

impl MlsStore {
    /// `path` 는 relay-client DB(outbox 와 같은 파일). `key` 는 Keychain 에서 읽은 32 B. 처음이면 그 지문을 남기고, 다르면
    /// [`MlsStoreError::KeyMismatch`].
    ///
    /// # Errors
    /// sqlite·I/O 오류·열쇠 바뀜.
    pub fn open(path: &Path, key: &Zeroizing<[u8; 32]>, rng: Arc<dyn Rng>) -> R<Self> {
        let c = connect(path)?;
        let want = kid(key);
        let had: Option<Vec<u8>> = c
            .query_row("SELECT kid FROM mls_meta WHERE id = 0", [], |r| r.get(0))
            .optional()?;
        match had {
            Some(k) if k != want => return Err(MlsStoreError::KeyMismatch),
            Some(_) => {}
            None => {
                c.execute(
                    "INSERT INTO mls_meta (id, kid) VALUES (0, ?1)",
                    params![want],
                )?;
            }
        }
        Ok(Self {
            conn: Mutex::new(c),
            op: Mutex::new(()),
            cipher: XChaCha20Poly1305::new(key.as_slice().into()),
            rng,
            dirty: AtomicBool::new(false),
            fail_next: AtomicBool::new(false),
        })
    }

    /// 시험용: 다음 `mark_applied` 를 실패시킨다.
    #[doc(hidden)]
    pub fn fail_next_mark_applied(&self) {
        self.fail_next.store(true, Ordering::Release);
    }

    /// 저장을 모두 비운다(열쇠를 잃은 뒤 — 그룹은 다시 들어간다). 새 열쇠의 지문을 남긴다.
    ///
    /// # Errors
    /// sqlite·I/O 오류.
    pub fn reset(path: &Path, key: &Zeroizing<[u8; 32]>) -> R<()> {
        let c = connect(path)?;
        // 다시 들어간 뒤 옛 행이 '이미 적용'으로 Commit 을 삼키지 않게 적용·확정 전 기록도 비운다(설계 2a 권고).
        c.execute_batch(
            "DELETE FROM mls_kv; DELETE FROM mls_applied; DELETE FROM mls_pending; DELETE FROM mls_group_state; \
             DELETE FROM mls_retry; DELETE FROM mls_flags; DELETE FROM mls_opened; DELETE FROM mls_conv; DELETE FROM mls_group_meta; DELETE FROM mls_commit_meta; \
             DELETE FROM mls_stalled; DELETE FROM mls_lost; DELETE FROM mls_recv; DELETE FROM mls_change;",
        )?;
        c.execute(
            "INSERT INTO mls_meta (id, kid) VALUES (0, ?1) ON CONFLICT (id) DO UPDATE SET kid = excluded.kid",
            params![kid(key)],
        )?;
        crate::outbox::truncate_wal(&c);
        Ok(())
    }

    /// group 종류의 (이름, 확정 seq, 들어온 seq).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn group_meta(&self, group: &[u8]) -> R<Option<(String, u64, u64)>> {
        Ok(self
            .c()
            .query_row(
                "SELECT name, seq, joined_seq FROM mls_group_meta WHERE grp = ?1",
                params![group],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                        u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    ))
                },
            )
            .optional()?)
    }

    /// group 종류의 화면 값을 바꾼다(`None` 은 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_group_meta(
        &self,
        group: &[u8],
        name: Option<&str>,
        seq: Option<u64>,
        joined_seq: Option<u64>,
    ) -> R<()> {
        let c = self.c();
        c.execute(
            "INSERT OR IGNORE INTO mls_group_meta (grp) VALUES (?1)",
            params![group],
        )?;
        if let Some(n) = name {
            c.execute(
                "UPDATE mls_group_meta SET name = ?2 WHERE grp = ?1",
                params![group, n],
            )?;
        }
        if let Some(v) = seq {
            c.execute(
                "UPDATE mls_group_meta SET seq = MAX(seq, ?2) WHERE grp = ?1",
                params![group, epoch_i64(v)],
            )?;
        }
        if let Some(v) = joined_seq {
            c.execute(
                "UPDATE mls_group_meta SET joined_seq = ?2 WHERE grp = ?1",
                params![group, epoch_i64(v)],
            )?;
        }
        Ok(())
    }

    /// 확정을 기다리는 group Commit 의 헤더를 남긴다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_commit_meta(
        &self,
        group: &[u8],
        epoch: u64,
        hash: &[u8; 32],
        op: &str,
        actor: &str,
        subject: Option<&str>,
    ) -> R<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO mls_commit_meta (grp, epoch, hash, op, actor, subject) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![group, epoch_i64(epoch), hash.as_slice(), op, actor, subject],
        )?;
        Ok(())
    }

    /// 그 Commit 의 (op, actor, subject) 를 꺼내 지운다. 그 epoch 의 다른 것도 지운다(확정·무효 뒤).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn take_commit_meta(
        &self,
        group: &[u8],
        epoch: u64,
        hash: &[u8; 32],
    ) -> R<Option<(String, String, Option<String>)>> {
        let c = self.c();
        let got = c
            .query_row(
                "SELECT op, actor, subject FROM mls_commit_meta WHERE grp = ?1 AND epoch = ?2 AND hash = ?3",
                params![group, epoch_i64(epoch), hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        // 같은 epoch 의 다른 해시는 남긴다 — 무효된 남의 Commit 결과가 뒤에 확정될 내 Commit 의 헤더를 지우지 않게. 다음
        // epoch 의 결과 때 지워진다.
        c.execute(
            "DELETE FROM mls_commit_meta WHERE grp = ?1 AND (epoch < ?2 OR (epoch = ?2 AND hash = ?3))",
            params![group, epoch_i64(epoch), hash.as_slice()],
        )?;
        Ok(got)
    }

    /// 이 기기(사람 주소 `actor`)가 그 epoch 에 낸 Commit 의 (op, subject) — 무효·다른 Commit 확정 때 같은 변경을 다시 내려고.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn own_commit_meta(
        &self,
        group: &[u8],
        epoch: u64,
        actor: &str,
    ) -> R<Option<(String, Option<String>)>> {
        Ok(self
            .c()
            .query_row(
                "SELECT op, subject FROM mls_commit_meta WHERE grp = ?1 AND epoch = ?2 AND actor = ?3",
                params![group, epoch_i64(epoch), actor],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// 그룹의 대화 주소를 남긴다(이미 있으면 바꿈).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_conv(&self, group: &[u8], conversation: &str) -> R<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO mls_conv (grp, conversation) VALUES (?1, ?2)",
            params![group, conversation],
        )?;
        Ok(())
    }

    /// 대화 주소를 남긴 그룹 전부(1:1·group).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn conv_groups(&self) -> R<Vec<Vec<u8>>> {
        let c = self.c();
        let mut st = c.prepare("SELECT grp FROM mls_conv")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 그룹의 대화 주소(남겨 둔 것).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn conv(&self, group: &[u8]) -> R<Option<String>> {
        Ok(self
            .c()
            .query_row(
                "SELECT conversation FROM mls_conv WHERE grp = ?1",
                params![group],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 막힌 대화들(대화 주소, 상태) — 접속 때 코어에 다시 알린다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn blocked_conversations(&self) -> R<Vec<(String, GroupState, Option<i64>)>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT v.conversation, s.state, l.since FROM mls_group_state s JOIN mls_conv v ON v.grp = s.grp
             LEFT JOIN mls_lost l ON l.grp = s.grp",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        Ok(rows
            .filter_map(std::result::Result::ok)
            .map(|(c, s, l)| (c, GroupState::parse(&s), l))
            .collect())
    }

    /// 막힌 동안 응용 메시지를 버렸다 — 처음 버린 때를 남긴다(이미 있으면 둔다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_lost(&self, group: &[u8], now_ms: i64) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_lost (grp, since) VALUES (?1, ?2)",
            params![group, now_ms],
        )?;
        Ok(())
    }

    /// 처음 버린 때(ms).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn lost(&self, group: &[u8]) -> R<Option<i64>> {
        Ok(self
            .c()
            .query_row(
                "SELECT since FROM mls_lost WHERE grp = ?1",
                params![group],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 버린 기록을 지우고 그 때를 돌려준다(풀림 알림에 싣는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn take_lost(&self, group: &[u8]) -> R<Option<i64>> {
        let at = self.lost(group)?;
        self.c()
            .execute("DELETE FROM mls_lost WHERE grp = ?1", params![group])?;
        Ok(at)
    }

    /// 그 epoch 에 낸 내 Commit 의 변경 줄 키(§12-27 ⓒ). 같은 epoch 로 다시 봉인하면 덮는다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_change(&self, group: &[u8], epoch: u64, change_id: &str) -> R<()> {
        self.c().execute(
            "INSERT OR REPLACE INTO mls_change (grp, epoch, change_id) VALUES (?1, ?2, ?3)",
            params![group, i64::try_from(epoch).unwrap_or(i64::MAX), change_id],
        )?;
        Ok(())
    }

    /// 그 epoch 의 내 Commit 변경 줄 키를 꺼낸다(지움).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn take_change(&self, group: &[u8], epoch: u64) -> R<Option<String>> {
        let e = i64::try_from(epoch).unwrap_or(i64::MAX);
        let id = self
            .c()
            .query_row(
                "SELECT change_id FROM mls_change WHERE grp = ?1 AND epoch = ?2",
                params![group, e],
                |r| r.get(0),
            )
            .optional()?;
        self.c().execute(
            "DELETE FROM mls_change WHERE grp = ?1 AND epoch = ?2",
            params![group, e],
        )?;
        Ok(id)
    }

    /// 그 대화에서 응용 메시지를 열었다 — 가장 늦은 시각을 남긴다(§12-27 ⓐ).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_recv(&self, group: &[u8], at_ms: i64) -> R<()> {
        self.c().execute(
            "INSERT INTO mls_recv (grp, at) VALUES (?1, ?2) ON CONFLICT (grp) DO UPDATE SET at = max(at, excluded.at)",
            params![group, at_ms],
        )?;
        Ok(())
    }

    /// 그 대화에서 마지막으로 연 응용 메시지의 시각(ms). 없으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn recv_at(&self, group: &[u8]) -> R<Option<i64>> {
        Ok(self
            .c()
            .query_row(
                "SELECT at FROM mls_recv WHERE grp = ?1",
                params![group],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 연 응용 메시지 평문을 남긴다(받기 트랜잭션 안에서).
    ///
    /// # Errors
    /// sqlite·암호화 오류.
    pub fn put_opened(&self, msg_id: &str, text: &[u8], now_ms: i64) -> R<()> {
        let v = self.seal(&opened_row(msg_id), text)?;
        self.c().execute(
            "INSERT OR REPLACE INTO mls_opened (msg_id, v, at) VALUES (?1, ?2, ?3)",
            params![msg_id, v, now_ms],
        )?;
        Ok(())
    }

    /// 남겨 둔 평문.
    ///
    /// # Errors
    /// sqlite·복호화 오류.
    pub fn opened(&self, msg_id: &str) -> R<Option<Zeroizing<Vec<u8>>>> {
        let v: Option<Vec<u8>> = self
            .c()
            .query_row(
                "SELECT v FROM mls_opened WHERE msg_id = ?1",
                params![msg_id],
                |r| r.get(0),
            )
            .optional()?;
        v.map(|v| self.open_value(&opened_row(msg_id), &v))
            .transpose()
    }

    /// 코어가 ack 했다 — 지운다. `older_than_ms` 를 주면 그보다 오래된 것도(앱이 ack 하지 못하고 버린 것).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_opened(&self, msg_id: &str, older_than_ms: Option<i64>) -> R<()> {
        let c = self.c();
        c.execute("DELETE FROM mls_opened WHERE msg_id = ?1", params![msg_id])?;
        if let Some(t) = older_than_ms {
            c.execute("DELETE FROM mls_opened WHERE at < ?1", params![t])?;
        }
        Ok(())
    }

    /// 한 번 한 일 표시가 있나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn flag(&self, name: &str) -> R<bool> {
        Ok(self
            .c()
            .query_row(
                "SELECT 1 FROM mls_flags WHERE name = ?1",
                params![name],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// 한 번 한 일을 표시한 시각(유닉스 밀리초). 없으면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn flag_at(&self, name: &str) -> R<Option<i64>> {
        Ok(self
            .c()
            .query_row(
                "SELECT at FROM mls_flags WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 한 번 한 일을 표시한다(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_flag(&self, name: &str, now_ms: i64) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_flags (name, at) VALUES (?1, ?2)",
            params![name, now_ms],
        )?;
        Ok(())
    }

    /// 저장된 내 KeyPackage 수(마지막 수단 포함) — Welcome 으로 들어간 뒤 줄지 않았으면 마지막 수단을 쓴 것이다(openmls 는
    /// 마지막 수단만 지우지 않는다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn key_package_count(&self) -> R<u64> {
        let n: i64 = self.c().query_row(
            "SELECT COUNT(*) FROM mls_kv WHERE substr(k, 1, ?1) = ?2",
            params![i64::try_from(KEY_PACKAGE.len()).unwrap_or(0), KEY_PACKAGE],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// 주기 Update 셈: 내 응용 메시지 하나를 보냈다(처음 보는 그룹이면 지금부터 센다). 지금까지 센 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn update_sent(&self, group: &[u8], now_ms: i64) -> R<u64> {
        let n: i64 = self.c().query_row(
            "INSERT INTO mls_update (grp, last_ms, sent) VALUES (?1, ?2, 1)
             ON CONFLICT(grp) DO UPDATE SET sent = sent + 1 RETURNING sent",
            params![group, now_ms],
            |r| r.get(0),
        )?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// 주기 Update 셈: 이 그룹을 처음 보면 지금부터 센다(받기만 하는 그룹도 7일마다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn update_seen(&self, group: &[u8], now_ms: i64) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_update (grp, last_ms, sent) VALUES (?1, ?2, 0)",
            params![group, now_ms],
        )?;
        Ok(())
    }

    /// 때가 된 그룹: 마지막 뒤 `every_ms` 가 지났거나 `every_n` 개 이상 보냈다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn update_due(&self, now_ms: i64, every_ms: i64, every_n: u64) -> R<Vec<Vec<u8>>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT grp FROM mls_update WHERE last_ms <= ?1 OR sent >= ?2 ORDER BY last_ms",
        )?;
        let rows = st.query_map(
            params![
                now_ms.saturating_sub(every_ms),
                i64::try_from(every_n).unwrap_or(i64::MAX)
            ],
            |r| r.get(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// 셈을 다시: 마지막 = `last_ms`, 보낸 수 0. `None` 이면 그 그룹 행을 지운다(그룹 없어짐).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn update_reset(&self, group: &[u8], last_ms: Option<i64>) -> R<()> {
        match last_ms {
            Some(t) => self.c().execute(
                "INSERT INTO mls_update (grp, last_ms, sent) VALUES (?1, ?2, 0)
                 ON CONFLICT(grp) DO UPDATE SET last_ms = ?2, sent = 0",
                params![group, t],
            )?,
            None => self
                .c()
                .execute("DELETE FROM mls_update WHERE grp = ?1", params![group])?,
        };
        Ok(())
    }

    /// 그 그룹의 그 epoch 에서 이 해시의 Commit 을 이미 merge 했나.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn applied(&self, group: &[u8], epoch: u64, hash: &[u8; 32]) -> R<bool> {
        let got: Option<Vec<u8>> = self
            .c()
            .query_row(
                "SELECT hash FROM mls_applied WHERE grp = ?1 AND epoch = ?2",
                params![group, epoch_i64(epoch)],
                |r| r.get(0),
            )
            .optional()?;
        Ok(got.as_deref() == Some(hash.as_slice()))
    }

    /// merge 한 Commit 을 남긴다 — [`Txn`] 안에서(merge 와 같이 커밋·되돌림). 오래된 것은 지운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn mark_applied(&self, group: &[u8], epoch: u64, hash: &[u8; 32]) -> R<()> {
        if self.fail_next.swap(false, Ordering::AcqRel) {
            return Err(MlsStoreError::Io("시험이 낸 실패".to_owned()));
        }
        let c = self.c();
        c.execute(
            "INSERT OR REPLACE INTO mls_applied (grp, epoch, hash) VALUES (?1, ?2, ?3)",
            params![group, epoch_i64(epoch), hash.as_slice()],
        )?;
        c.execute(
            "DELETE FROM mls_applied WHERE grp = ?1 AND epoch <= ?2",
            params![group, epoch_i64(epoch) - APPLIED_KEEP],
        )?;
        Ok(())
    }

    /// group 종류의 확정 전 Commit 바이트를 둔다(§4-7).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_pending(&self, group: &[u8], epoch: u64, hash: &[u8; 32], bytes: &[u8]) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_pending (grp, epoch, hash, bytes) VALUES (?1, ?2, ?3, ?4)",
            params![group, epoch_i64(epoch), hash.as_slice(), bytes],
        )?;
        Ok(())
    }

    /// 확정 전 Commit 바이트(있으면).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pending(&self, group: &[u8], epoch: u64, hash: &[u8; 32]) -> R<Option<Vec<u8>>> {
        Ok(self
            .c()
            .query_row(
                "SELECT bytes FROM mls_pending WHERE grp = ?1 AND epoch = ?2 AND hash = ?3",
                params![group, epoch_i64(epoch), hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 그 epoch 의 확정 전 Commit 을 모두 지운다(final·void 뒤).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_pending(&self, group: &[u8], epoch: u64) -> R<()> {
        self.c().execute(
            "DELETE FROM mls_pending WHERE grp = ?1 AND epoch <= ?2",
            params![group, epoch_i64(epoch)],
        )?;
        Ok(())
    }

    /// 그룹을 막는다(이미 막혀 있으면 처음 상태·시각을 둔다 — 멈춘 원인이 먼저다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_state(&self, group: &[u8], state: GroupState, reason: &str, now_ms: i64) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_group_state (grp, state, reason, since) VALUES (?1, ?2, ?3, ?4)",
            params![group, state.as_str(), reason, now_ms],
        )?;
        Ok(())
    }

    /// 막힌 그룹의 (상태, 이유, 시각 ms).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn state(&self, group: &[u8]) -> R<Option<(GroupState, String, i64)>> {
        Ok(self
            .c()
            .query_row(
                "SELECT state, reason, since FROM mls_group_state WHERE grp = ?1",
                params![group],
                |r| {
                    Ok((
                        GroupState::parse(&r.get::<_, String>(0)?),
                        r.get(1)?,
                        r.get(2)?,
                    ))
                },
            )
            .optional()?)
    }

    /// 다시 볼 Commit 을 처음 본 때(ms). 처음이면 `now_ms` 를 남기고 그것을 돌려준다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn retry_since(&self, group: &[u8], hash: &[u8; 32], now_ms: i64) -> R<i64> {
        let c = self.c();
        c.execute(
            "INSERT OR IGNORE INTO mls_retry (grp, hash, since) VALUES (?1, ?2, ?3)",
            params![group, hash.as_slice(), now_ms],
        )?;
        Ok(c.query_row(
            "SELECT since FROM mls_retry WHERE grp = ?1 AND hash = ?2",
            params![group, hash.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// 그 그룹의 다시 볼 기록을 지운다(Commit 이 들어갔거나 그룹을 막음).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn clear_retry(&self, group: &[u8]) -> R<()> {
        self.c()
            .execute("DELETE FROM mls_retry WHERE grp = ?1", params![group])?;
        Ok(())
    }

    /// 막음을 푼다(사람이 확인했거나 다시 들어감).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn clear_state(&self, group: &[u8]) -> R<()> {
        self.c()
            .execute("DELETE FROM mls_group_state WHERE grp = ?1", params![group])?;
        Ok(())
    }

    /// 대화를 멈추게 한 Handshake 를 남긴다(이미 있으면 처음 것을 둔다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn put_stalled(
        &self,
        group: &[u8],
        epoch: u64,
        hash: &[u8; 32],
        message: &str,
        group_seq: Option<u64>,
        now_ms: i64,
    ) -> R<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO mls_stalled (grp, epoch, hash, message, group_seq, since) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![group, epoch_i64(epoch), hash.as_slice(), message, group_seq.map(epoch_i64), now_ms],
        )?;
        Ok(())
    }

    /// 쥔 채 멈춘 group Commit 이 확정됐다 — 다시 볼 수 있게 seq 를 채운다. 그 Commit 이 아니면 아무것도 안 한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn stalled_final(&self, group: &[u8], epoch: u64, hash: &[u8; 32], seq: u64) -> R<bool> {
        Ok(self.c().execute(
            "UPDATE mls_stalled SET group_seq = ?4 WHERE grp = ?1 AND epoch = ?2 AND hash = ?3 AND group_seq IS NULL",
            params![group, epoch_i64(epoch), hash.as_slice(), epoch_i64(seq)],
        )? > 0)
    }

    /// 멈추게 한 그 Commit 인가.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn is_stalled_by(&self, group: &[u8], epoch: u64, hash: &[u8; 32]) -> R<bool> {
        Ok(self
            .c()
            .query_row(
                "SELECT 1 FROM mls_stalled WHERE grp = ?1 AND epoch = ?2 AND hash = ?3",
                params![group, epoch_i64(epoch), hash.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// 다시 볼 멈춘 Handshake 들: (그룹, 메시지 JSON, 확정 seq, 처음 멈춘 때 ms).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn stalled(&self) -> R<Vec<Stalled>> {
        let c = self.c();
        let mut st = c.prepare("SELECT grp, message, group_seq, since FROM mls_stalled")?;
        let rows = st.query_map([], |r| {
            Ok(Stalled {
                group: r.get(0)?,
                message: r.get(1)?,
                group_seq: r
                    .get::<_, Option<i64>>(2)?
                    .and_then(|v| u64::try_from(v).ok()),
                since: r.get(3)?,
            })
        })?;
        Ok(rows.filter_map(std::result::Result::ok).collect())
    }

    /// 멈춘 Handshake 를 지운다(풀렸거나 그룹을 버림).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_stalled(&self, group: &[u8]) -> R<()> {
        self.c()
            .execute("DELETE FROM mls_stalled WHERE grp = ?1", params![group])?;
        Ok(())
    }

    /// (secure_delete, journal_mode) — 시험이 이 연결의 설정을 본다.
    #[doc(hidden)]
    pub fn pragmas(&self) -> (i64, String) {
        let c = self.c();
        let sd = c
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap_or(-1);
        let jm = c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap_or_default();
        (sd, jm)
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// openmls 호출 하나(만들기·Add·Welcome·받기·merge·KeyPackage 만들기)를 감싼다: `BEGIN IMMEDIATE` 로 시작해
    /// [`Txn::commit`] 이면 COMMIT, 커밋 없이 버려지면(실패·early return) ROLLBACK — 어느 쪽이든 끝에 [`MlsStore::scrub`].
    /// 중간에 죽어도 그룹 상태가 반쯤 바뀐 채 남지 않는다.
    ///
    /// # Errors
    /// sqlite 오류(다른 쓰기가 5초 넘게 잡고 있음 등).
    pub fn begin(&self) -> R<Txn<'_>> {
        let op = self.op.lock().unwrap_or_else(PoisonError::into_inner);
        self.c().execute_batch("BEGIN IMMEDIATE")?;
        Ok(Txn {
            store: self,
            _op: op,
            done: false,
        })
    }

    /// 그 사이 쓰기·지우기가 있었으면 WAL 을 본 DB 로 옮기고 0 으로 자른다(지난 epoch 비밀·쓴 KeyPackage 의 옛 암호문이
    /// `-wal` 에 남지 않게). 다른 연결이 읽는 중이라 못 자르면 표시를 되돌려 다음 번에 다시 한다. 보통은 [`Txn`] 이 부른다.
    pub fn scrub(&self) {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        // 읽는 쪽이 있으면 기다리지 않는다(기본 5초 대기가 MLS 동작마다 붙지 않게) — 표시를 되돌려 다음에 다시.
        let c = self.c();
        let _ = c.busy_timeout(Duration::ZERO);
        let ok = crate::outbox::try_truncate_wal(&c);
        let _ = c.busy_timeout(BUSY_TIMEOUT);
        if !ok {
            self.dirty.store(true, Ordering::Release);
        }
    }

    fn seal(&self, row: &[u8], plain: &[u8]) -> R<Vec<u8>> {
        let mut nonce = [0u8; 24];
        self.rng
            .try_fill(&mut nonce)
            .map_err(|e| MlsStoreError::Rng(e.to_string()))?;
        let ct = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: row,
                },
            )
            .map_err(|_| MlsStoreError::Crypto)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open_value(&self, row: &[u8], sealed: &[u8]) -> R<Zeroizing<Vec<u8>>> {
        if sealed.len() < 24 {
            return Err(MlsStoreError::Crypto);
        }
        let (nonce, ct) = sealed.split_at(24);
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: row })
            .map(Zeroizing::new)
            .map_err(|_| MlsStoreError::Crypto)
    }

    fn get_raw(&self, c: &rusqlite::Connection, row: &[u8]) -> R<Option<Zeroizing<Vec<u8>>>> {
        let v: Option<Vec<u8>> = c
            .query_row("SELECT v FROM mls_kv WHERE k = ?1", params![row], |r| {
                r.get(0)
            })
            .optional()?;
        v.map(|v| self.open_value(row, &v)).transpose()
    }

    fn put_raw(&self, c: &rusqlite::Connection, row: &[u8], plain: &[u8]) -> R<()> {
        let v = self.seal(row, plain)?;
        c.execute(
            "INSERT INTO mls_kv (k, v) VALUES (?1, ?2) ON CONFLICT (k) DO UPDATE SET v = excluded.v",
            params![row, v],
        )?;
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn write(&self, label: &[u8], key: &[u8], value: &[u8]) -> R<()> {
        let row = row_key(label, key);
        self.put_raw(&self.c(), &row, value)
    }

    fn read<V: Entity<CURRENT_VERSION>>(&self, label: &[u8], key: &[u8]) -> R<Option<V>> {
        let row = row_key(label, key);
        let v = self.get_raw(&self.c(), &row)?;
        Ok(v.map(|v| serde_json::from_slice(&v)).transpose()?)
    }

    fn delete(&self, label: &[u8], key: &[u8]) -> R<()> {
        let row = row_key(label, key);
        self.c()
            .execute("DELETE FROM mls_kv WHERE k = ?1", params![row])?;
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }

    /// 목록 값 하나를 바꾼다(읽고 쓰기를 한 잠금 안에서).
    fn edit_list(&self, label: &[u8], key: &[u8], f: impl FnOnce(&mut Vec<Vec<u8>>)) -> R<()> {
        let row = row_key(label, key);
        let c = self.c();
        let mut list: Vec<Vec<u8>> = match self.get_raw(&c, &row)? {
            Some(v) => serde_json::from_slice(&v)?,
            None => Vec::new(),
        };
        f(&mut list);
        let bytes = Zeroizing::new(serde_json::to_vec(&list)?);
        self.put_raw(&c, &row, &bytes)
    }

    fn append(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> R<()> {
        self.edit_list(label, key, |l| l.push(value))
    }

    fn remove_item(&self, label: &[u8], key: &[u8], value: &[u8]) -> R<()> {
        self.edit_list(label, key, |l| {
            if let Some(i) = l.iter().position(|x| x == value) {
                l.remove(i);
            }
        })
    }

    fn read_list<V: Entity<CURRENT_VERSION>>(&self, label: &[u8], key: &[u8]) -> R<Vec<V>> {
        let row = row_key(label, key);
        let list: Vec<Vec<u8>> = match self.get_raw(&self.c(), &row)? {
            Some(v) => serde_json::from_slice(&v)?,
            None => Vec::new(),
        };
        list.iter()
            .map(|v| serde_json::from_slice(v).map_err(MlsStoreError::from))
            .collect()
    }

    fn put<K: Key<CURRENT_VERSION>, V: Serialize>(
        &self,
        label: &[u8],
        key: &K,
        value: &V,
    ) -> R<()> {
        let v = Zeroizing::new(serde_json::to_vec(value)?);
        self.write(label, &serde_json::to_vec(key)?, &v)
    }

    fn get<K: Key<CURRENT_VERSION>, V: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: &K,
    ) -> R<Option<V>> {
        self.read(label, &serde_json::to_vec(key)?)
    }

    fn del<K: Key<CURRENT_VERSION>>(&self, label: &[u8], key: &K) -> R<()> {
        self.delete(label, &serde_json::to_vec(key)?)
    }
}

/// [`MlsStore::begin`] 의 트랜잭션. 커밋하지 않고 버려지면 ROLLBACK. 어느 쪽이든 scrub.
pub struct Txn<'a> {
    store: &'a MlsStore,
    _op: MutexGuard<'a, ()>,
    done: bool,
}

impl Txn<'_> {
    /// COMMIT 하고 scrub.
    ///
    /// # Errors
    /// sqlite 오류(그때는 Drop 이 ROLLBACK).
    pub fn commit(mut self) -> R<()> {
        self.store.c().execute_batch("COMMIT")?;
        self.done = true;
        Ok(())
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.store.c().execute_batch("ROLLBACK");
            // ROLLBACK 한 쓰기도 WAL 에 넘친 프레임이 있을 수 있다.
            self.store.dirty.store(true, Ordering::Release);
        }
        self.store.scrub();
    }
}

impl Drop for MlsStore {
    fn drop(&mut self) {
        self.scrub();
    }
}

fn epoch_i64(e: u64) -> i64 {
    i64::try_from(e).unwrap_or(i64::MAX)
}

/// 열 키 = 라벨 ‖ 키 ‖ 판(u16 BE).
fn row_key(label: &[u8], key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(label.len() + key.len() + 2);
    k.extend_from_slice(label);
    k.extend_from_slice(key);
    k.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
    k
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> R<Vec<u8>> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

const KEY_PACKAGE: &[u8] = b"KeyPackage";
const PSK: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS: &[u8] = b"EpochKeyPairs";
const TREE: &[u8] = b"Tree";
const GROUP_CONTEXT: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG: &[u8] = b"ConfirmationTag";
const JOIN_CONFIG: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES: &[u8] = b"OwnLeafNodes";
const GROUP_STATE: &[u8] = b"GroupState";
const QUEUED_PROPOSAL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS: &[u8] = b"MessageSecrets";

impl StorageProvider<CURRENT_VERSION> for MlsStore {
    type Error = MlsStoreError;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> R<()> {
        self.put(JOIN_CONFIG, group_id, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> R<()> {
        self.append(
            OWN_LEAF_NODES,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(leaf_node)?,
        )
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> R<()> {
        self.write(
            QUEUED_PROPOSAL,
            &serde_json::to_vec(&(group_id, proposal_ref))?,
            &serde_json::to_vec(proposal)?,
        )?;
        self.append(
            PROPOSAL_QUEUE_REFS,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(proposal_ref)?,
        )
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> R<()> {
        self.put(TREE, group_id, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> R<()> {
        self.put(INTERIM_TRANSCRIPT_HASH, group_id, interim_transcript_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> R<()> {
        self.put(GROUP_CONTEXT, group_id, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> R<()> {
        self.put(CONFIRMATION_TAG, group_id, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> R<()> {
        self.put(GROUP_STATE, group_id, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> R<()> {
        self.put(MESSAGE_SECRETS, group_id, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> R<()> {
        self.put(RESUMPTION_PSK_STORE, group_id, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> R<()> {
        self.put(OWN_LEAF_NODE_INDEX, group_id, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> R<()> {
        self.put(EPOCH_SECRETS, group_id, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> R<()> {
        self.put(SIGNATURE_KEY_PAIR, public_key, signature_key_pair)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> R<()> {
        self.put(ENCRYPTION_KEY_PAIR, public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> R<()> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let v = Zeroizing::new(serde_json::to_vec(key_pairs)?);
        self.write(EPOCH_KEY_PAIRS, &key, &v)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> R<()> {
        self.put(KEY_PACKAGE, hash_ref, key_package)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> R<()> {
        self.put(PSK, psk_id, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<MlsGroupJoinConfig>> {
        self.get(JOIN_CONFIG, group_id)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Vec<LeafNode>> {
        self.read_list(OWN_LEAF_NODES, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Vec<ProposalRef>> {
        self.read_list(PROPOSAL_QUEUE_REFS, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Vec<(ProposalRef, QueuedProposal)>> {
        let refs: Vec<ProposalRef> = self.queued_proposal_refs(group_id)?;
        refs.into_iter()
            .filter_map(|r| {
                let key = match serde_json::to_vec(&(group_id, &r)) {
                    Ok(k) => k,
                    Err(e) => return Some(Err(e.into())),
                };
                // 줄에 있는데 본문이 없으면 건너뛴다(메모리 저장은 여기서 패닉).
                match self.read::<QueuedProposal>(QUEUED_PROPOSAL, &key) {
                    Ok(Some(p)) => Some(Ok((r, p))),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .collect()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<TreeSync>> {
        self.get(TREE, group_id)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<GroupContext>> {
        self.get(GROUP_CONTEXT, group_id)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<InterimTranscriptHash>> {
        self.get(INTERIM_TRANSCRIPT_HASH, group_id)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<ConfirmationTag>> {
        self.get(CONFIRMATION_TAG, group_id)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<GroupState>> {
        self.get(GROUP_STATE, group_id)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<MessageSecrets>> {
        self.get(MESSAGE_SECRETS, group_id)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<ResumptionPskStore>> {
        self.get(RESUMPTION_PSK_STORE, group_id)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<LeafNodeIndex>> {
        self.get(OWN_LEAF_NODE_INDEX, group_id)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<Option<GroupEpochSecrets>> {
        self.get(EPOCH_SECRETS, group_id)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> R<Option<SignatureKeyPair>> {
        self.get(SIGNATURE_KEY_PAIR, public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> R<Option<HpkeKeyPair>> {
        self.get(ENCRYPTION_KEY_PAIR, public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> R<Vec<HpkeKeyPair>> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let row = row_key(EPOCH_KEY_PAIRS, &key);
        match self.get_raw(&self.c(), &row)? {
            Some(v) => Ok(serde_json::from_slice(&v)?),
            None => Ok(Vec::new()),
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> R<Option<KeyPackage>> {
        self.get(KEY_PACKAGE, hash_ref)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> R<Option<PskBundle>> {
        self.get(PSK, psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> R<()> {
        self.remove_item(
            PROPOSAL_QUEUE_REFS,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(proposal_ref)?,
        )?;
        self.delete(
            QUEUED_PROPOSAL,
            &serde_json::to_vec(&(group_id, proposal_ref))?,
        )
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(OWN_LEAF_NODES, group_id)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(JOIN_CONFIG, group_id)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(&self, group_id: &GroupId) -> R<()> {
        self.del(TREE, group_id)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(CONFIRMATION_TAG, group_id)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(GROUP_STATE, group_id)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(GROUP_CONTEXT, group_id)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(INTERIM_TRANSCRIPT_HASH, group_id)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(MESSAGE_SECRETS, group_id)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(RESUMPTION_PSK_STORE, group_id)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(OWN_LEAF_NODE_INDEX, group_id)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        self.del(EPOCH_SECRETS, group_id)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> R<()> {
        let refs: Vec<ProposalRef> = self.queued_proposal_refs(group_id)?;
        for r in refs {
            self.delete(QUEUED_PROPOSAL, &serde_json::to_vec(&(group_id, r))?)?;
        }
        self.del(PROPOSAL_QUEUE_REFS, group_id)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> R<()> {
        self.del(SIGNATURE_KEY_PAIR, public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> R<()> {
        self.del(ENCRYPTION_KEY_PAIR, public_key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> R<()> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete(EPOCH_KEY_PAIRS, &key)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> R<()> {
        self.del(KEY_PACKAGE, hash_ref)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(&self, psk_id: &PskKey) -> R<()> {
        self.del(PSK, psk_id)
    }
}
