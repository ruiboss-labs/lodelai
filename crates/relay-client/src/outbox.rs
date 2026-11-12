//! 영속 저장소(SQLite, 프로필당 파일 하나).
//!
//! - `outbox`: 보낼 프레임(서명까지 끝난 JSON). `dedup` 키로 중복 제거. 접속 중 순서대로 꺼내 보낸다. `send` 행은 봉인 전 메시지
//!   (`plain`, 평문 본문 포함)를 같이 둔다 — 큐 맨 앞에서 MLS 로 봉인하고 `stale_epoch` 면 새 epoch 로 다시 봉인한다(묶음 22). 행이
//!   빠질 때 함께 지워지고 로그·감사에 싣지 않는다(`Item` 에 없다). `retried` 칸은 옛 봉투 재암호화(#313) 흔적이라 쓰지 않는다(#503).
//! - `sent`: 서버가 `ack` 한 내 메시지의 `msg_id`(받은 `reply`·`rejected`·`system` 의 `reply_to` 검사용).
//! - `peers`: TOFU 로 고정한 상대 기기(device_id → 사용자·공개키) + 신뢰 상태(`trusted`·`pending`·`revoked`, e2e-envelope §7).

use std::path::Path;
use std::sync::Mutex;

use lodelai_crypto::{sign_message, DeviceKeys};
use lodelai_effects::Clock;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::{Error, Outgoing, Result};

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS outbox (
  seq    INTEGER PRIMARY KEY AUTOINCREMENT,
  dedup  TEXT NOT NULL UNIQUE,
  kind   TEXT NOT NULL,
  msg_id TEXT,
  peer   TEXT,
  frame  TEXT NOT NULL,
  plain  TEXT,
  retried INTEGER NOT NULL DEFAULT 0
);
-- 받은 메시지의 첨부 받기(묶음 15 §3). 키·해시는 여기에만 — core 에는 넘기지 않는다. 받으면(또는 못 받는다고 정하면) 행을 지운다.
CREATE TABLE IF NOT EXISTS downloads (
  msg_id  TEXT NOT NULL,
  idx     INTEGER NOT NULL,
  blob_id TEXT NOT NULL,
  fk      TEXT NOT NULL,
  prefix  TEXT NOT NULL,
  sha256  TEXT NOT NULL,
  size    INTEGER NOT NULL,
  PRIMARY KEY (msg_id, idx)
);
-- 그룹 로컬 상태(묶음 16 §3) — 서명 검증한 group 메시지를 순서대로 적용한 결과. 감쌀 대상의 유일한 근거.
CREATE TABLE IF NOT EXISTS cgroups (
  gid   TEXT PRIMARY KEY,
  name  TEXT NOT NULL,
  seq   INTEGER NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0,
  since INTEGER NOT NULL DEFAULT 0,
  unconfirmed INTEGER NOT NULL DEFAULT 0
);
-- 이번 접속 디렉터리의 사람(묶음 16 §3a ④ — 조직 빠짐 힌트의 사람이 아직 여기 있으면 적용하지 않는다). 내가 든 목록일 때만 통째로
-- 갈고, 빈 주소 줄 = '이번 접속에서 안다'. 접속할 때 비운다(모름 — 힌트를 미루지 않는다).
CREATE TABLE IF NOT EXISTS cdir_now (
  address TEXT PRIMARY KEY
);
-- relay 가 알린 조직 빠짐(groups.items[].org_left) — 그 그룹 seq 를 적용한 바로 뒤에 left·승계(§3a ④ 고침).
CREATE TABLE IF NOT EXISTS cgroup_org_left (
  gid     TEXT NOT NULL,
  address TEXT NOT NULL,
  seq     INTEGER NOT NULL,
  applied INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (gid, address, seq)
);
CREATE TABLE IF NOT EXISTS cgroup_members (
  gid      TEXT NOT NULL,
  address  TEXT NOT NULL,
  joined   INTEGER NOT NULL,
  left_seq INTEGER,
  admin    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cgroup_members_gid ON cgroup_members(gid);
-- 순서를 기다리는 group 메시지(이미 ack 함 — 재시작 뒤에도 이어서 적용).
CREATE TABLE IF NOT EXISTS cgroup_pending (
  gid      TEXT NOT NULL,
  seq      INTEGER NOT NULL,
  message  TEXT NOT NULL,
  trusted  INTEGER NOT NULL,
  since_ms INTEGER NOT NULL,
  PRIMARY KEY (gid, seq)
);
CREATE TABLE IF NOT EXISTS sent (
  msg_id  TEXT PRIMARY KEY,
  to_user TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peers (
  device_id TEXT PRIMARY KEY,
  user      TEXT NOT NULL,
  ed25519   TEXT NOT NULL,
  x25519    TEXT NOT NULL,
  trust     TEXT NOT NULL DEFAULT 'trusted',
  first_contact INTEGER NOT NULL DEFAULT 0,
  basis     TEXT NOT NULL DEFAULT '',
  pending_since INTEGER
);
CREATE INDEX IF NOT EXISTS peers_user ON peers(user);
-- 사용자마다 마지막으로 본 뿌리 기기(묶음 22 §2c) — 바뀌면 기록 줄 하나(처음 본 것은 조용히).
CREATE TABLE IF NOT EXISTS roots (
  user      TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  since     INTEGER NOT NULL
);
-- 모바일 검증: 마지막으로 받아진 푸시 등록의 salt(push.ok — 대화 값 HMAC 열쇠, 비밀 아님). 푸시 키는 키 저장소에만.
CREATE TABLE IF NOT EXISTS push_reg (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  salt BLOB NOT NULL
);
-- #870 own_stream: 마지막으로 남긴 보낸 seq(keyframe 때) — 다시 켜도 seq 가 줄지 않게.
CREATE TABLE IF NOT EXISTS own_stream_seq (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  last INTEGER NOT NULL
);
";

/// 큐 순서 한 줄([`Store::order`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRow {
    pub seq: i64,
    pub kind: String,
    pub peer: Option<String>,
    pub msg_id: Option<String>,
}

/// 큐에서 꺼낸 항목.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub seq: i64,
    /// `send` 면 서버의 `ack`/`nack` 를 기다린다. 그 밖은 쓰면 끝.
    pub kind: String,
    pub msg_id: Option<String>,
    /// `send` 의 받는 사용자(`to.address` 의 user). 보낸 기록에 남겨 받은 회신의 발신자와 대조한다.
    pub peer: Option<String>,
    pub frame: String,
}

/// 첨부 올리기 사양(묶음 15) — `upload` 행의 `upload` 열(JSON). `message` 는 `from.device_id` 를 채운 서명 전 메시지.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UploadSpec {
    pub message: Value,
    pub files: Vec<UploadFile>,
    /// `blob_unavailable` 로 다시 올린 횟수(F8 — 한 번까지).
    #[serde(default)]
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UploadFile {
    pub path: std::path::PathBuf,
    pub name: String,
    pub mime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// 넣을 때의 평문 크기. 올릴 때 다르면(파일이 바뀜) 실패.
    pub size: u64,
    /// [`crate::OutFile::sha256`]. 올릴 때 다르면(파일이 바뀜) 실패.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// [`crate::OutFile::size_px`](#612).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_px: Option<(u32, u32)>,
}

/// 받을 첨부 하나(묶음 15). `fk`·`prefix`·`sha256` 은 base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    pub msg_id: String,
    pub idx: u32,
    pub blob_id: String,
    pub fk: String,
    pub prefix: String,
    pub sha256: String,
    pub size: u64,
}

/// 상대 기기 신뢰 상태(e2e-envelope §7, #313 결정 b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// 감쌀 대상이고, 이 기기가 보낸 것을 평소처럼 받는다.
    Trusted,
    /// 새 기기 — 사람이 확인하기 전. 감싸지 않고, 이 기기가 보낸 것은 보류한다.
    Pending,
    /// 디렉터리 전체 목록에서 사라졌다. 다시 나타나면 `Pending`.
    Revoked,
}

impl Trust {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Pending => "pending",
            Self::Revoked => "revoked",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "trusted" => Self::Trusted,
            "pending" => Self::Pending,
            // 모르는 값은 믿지 않는다.
            _ => Self::Revoked,
        }
    }
}

/// 고정된 상대 기기.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub device_id: String,
    pub user: String,
    pub ed25519: String,
    pub x25519: String,
    pub trust: Trust,
    /// 그 사용자의 첫 디렉터리에서 TOFU 로 `Trusted` 가 됐다(화면은 알림만, 확인 요구 없음 — §7-1).
    pub first_contact: bool,
}

const PEER_COLS: &str = "device_id, user, ed25519, x25519, trust, first_contact";

fn peer_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Peer> {
    Ok(Peer {
        device_id: r.get(0)?,
        user: r.get(1)?,
        ed25519: r.get(2)?,
        x25519: r.get(3)?,
        trust: Trust::parse(&r.get::<_, String>(4)?),
        first_contact: r.get::<_, i64>(5)? != 0,
    })
}

/// 프로필 사진 올리기·지우기의 큐 키(묶음 15 §2) — 둘이 한 줄로, 마지막 의도만.
pub const AVATAR_KEY: &str = "profile.avatar";
/// 조직 사진 올리기·지우기의 큐 키(#554) — 내 사진과 따로, 같은 규칙.
pub const ORG_AVATAR_KEY: &str = "org.avatar";

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// # Errors
    /// sqlite 오류.
    pub fn open(path: &Path) -> Result<Self> {
        create_private(path)?;
        Self::init(Connection::open(path)?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        pragmas(&conn)?;
        conn.execute_batch(SCHEMA)?;
        // #313 전 DB: 열이 없으면 더한다(그 전 피어는 trusted 로 본다 — 개발 데이터, e2e-envelope §8).
        for (table, col, ddl) in [
            (
                "peers",
                "trust",
                "ALTER TABLE peers ADD COLUMN trust TEXT NOT NULL DEFAULT 'trusted'",
            ),
            (
                "peers",
                "first_contact",
                "ALTER TABLE peers ADD COLUMN first_contact INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "peers",
                "basis",
                "ALTER TABLE peers ADD COLUMN basis TEXT NOT NULL DEFAULT ''",
            ),
            (
                "peers",
                "pending_since",
                "ALTER TABLE peers ADD COLUMN pending_since INTEGER",
            ),
            (
                "outbox",
                "plain",
                "ALTER TABLE outbox ADD COLUMN plain TEXT",
            ),
            (
                "outbox",
                "retried",
                "ALTER TABLE outbox ADD COLUMN retried INTEGER NOT NULL DEFAULT 0",
            ),
            // 묶음 15: 첨부 올리기 사양(UploadSpec JSON). `upload` 행이면 있고, 올린 뒤 `send` 로 바뀌어도 남긴다(blob_unavailable 재시도).
            (
                "outbox",
                "upload",
                "ALTER TABLE outbox ADD COLUMN upload TEXT",
            ),
            // 묶음 15 §4a(140b5849): 확인 안 한 기기에서 온(held) 메시지의 첨부는 믿을 때까지 받지 않는다 — '믿음 기다림'.
            (
                "downloads",
                "held",
                "ALTER TABLE downloads ADD COLUMN held INTEGER NOT NULL DEFAULT 0",
            ),
            // 묶음 16 §3a ⑤: 이 기기 상태가 시작된 seq·'확인 안 된 변경 n건'.
            (
                "cgroups",
                "since",
                "ALTER TABLE cgroups ADD COLUMN since INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "cgroups",
                "unconfirmed",
                "ALTER TABLE cgroups ADD COLUMN unconfirmed INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            let has: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
                params![table, col],
                |r| r.get(0),
            )?;
            if !has {
                conn.execute_batch(ddl)?;
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub(crate) fn c(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 넣는다. `replace` 면 같은 `dedup` 의 옛 항목을 지우고 맨 뒤에 넣는다(마지막 값이 이긴다), 아니면 이미 있으면 무시.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push(
        &self,
        dedup: &str,
        kind: &str,
        msg_id: Option<&str>,
        peer: Option<&str>,
        frame: &str,
        replace: bool,
    ) -> Result<()> {
        self.push_with_plain(dedup, kind, msg_id, peer, frame, None, replace)
    }

    /// [`Self::push`] + 봉인 전 메시지(`send` 의 MLS 봉인·다시 봉인용).
    ///
    /// # Errors
    /// sqlite 오류.
    #[allow(clippy::too_many_arguments)]
    pub fn push_with_plain(
        &self,
        dedup: &str,
        kind: &str,
        msg_id: Option<&str>,
        peer: Option<&str>,
        frame: &str,
        plain: Option<&str>,
        replace: bool,
    ) -> Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        if replace {
            tx.execute("DELETE FROM outbox WHERE dedup = ?1", params![dedup])?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO outbox(dedup, kind, msg_id, peer, frame, plain) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![dedup, kind, msg_id, peer, frame, plain],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// # Errors
    /// sqlite 오류.
    pub fn has_dedup(&self, dedup: &str) -> Result<bool> {
        Ok(self.c().query_row(
            "SELECT EXISTS(SELECT 1 FROM outbox WHERE dedup = ?1)",
            params![dedup],
            |r| r.get(0),
        )?)
    }

    /// `send` 행의 봉인 전 메시지(바깥 `None` = 행 없음, 안쪽 `None` = 평문 없는 행).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn plain_of(&self, seq: i64) -> Result<Option<Option<String>>> {
        Ok(self
            .c()
            .query_row(
                "SELECT plain FROM outbox WHERE seq = ?1",
                params![seq],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 행의 프레임을 새로 봉인한 바이트로 바꾼다(MLS 봉인·`stale_epoch` 뒤 다시 봉인).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn reseal(&self, seq: i64, frame: &str) -> Result<()> {
        self.c().execute(
            "UPDATE outbox SET frame = ?2 WHERE seq = ?1",
            params![seq, frame],
        )?;
        Ok(())
    }

    /// 첨부 올리기 항목(묶음 15). `frame` 은 비어 있고 올린 뒤 [`Self::promote_upload`] 가 채운다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_upload(&self, dedup: &str, msg_id: &str, peer: &str, spec: &str) -> Result<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO outbox(dedup, kind, msg_id, peer, frame, upload) VALUES (?1, 'upload', ?2, ?3, '', ?4)",
            params![dedup, msg_id, peer, spec],
        )?;
        Ok(())
    }

    /// 프로필 사진 올리기(묶음 15 B9): 큐 키 `profile.avatar` 를 이 PNG(base64url, `upload` 칸)로 바꾼다. 지우기 행
    /// (`profile.update{avatar: null}`)과 같은 키라 마지막 의도만 남는다(계약 856eb04c).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_avatar(&self, png_b64: &str) -> Result<()> {
        self.push_avatar_as(AVATAR_KEY, "avatar", png_b64)
    }

    /// 조직 사진 올리기(#554): 큐 키 `org.avatar`·kind `org_avatar`. 지우기 행(`org.update{avatar: null}`)과 같은 키.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_org_avatar(&self, png_b64: &str) -> Result<()> {
        self.push_avatar_as(ORG_AVATAR_KEY, "org_avatar", png_b64)
    }

    fn push_avatar_as(&self, key: &str, kind: &str, png_b64: &str) -> Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        tx.execute("DELETE FROM outbox WHERE dedup = ?1", params![key])?;
        tx.execute(
            "INSERT INTO outbox(dedup, kind, frame, upload) VALUES (?1, ?2, '', ?3)",
            params![key, kind, png_b64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 그 행의 올리기 사양.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn upload_spec(&self, seq: i64) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row(
                "SELECT upload FROM outbox WHERE seq = ?1",
                params![seq],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    /// 다 올렸다: `upload` → `send`(서명 프레임·재암호화용 평문). 그 사이 행이 없어졌으면(로그아웃 버림) `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn promote_upload(&self, seq: i64, frame: &str, plain: &str) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE outbox SET kind = 'send', frame = ?2, plain = ?3 WHERE seq = ?1 AND kind = 'upload'",
            params![seq, frame, plain],
        )?;
        Ok(n == 1)
    }

    /// 큰 group Handshake(§5c): `send` → `mls_blob`, 서명 전 메시지를 둔다(평문은 그대로 — 실패하면 다시 봉인).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn demote_to_mls_blob(&self, seq: i64, message: &str) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE outbox SET kind = 'mls_blob', frame = '', upload = ?2 WHERE seq = ?1 AND kind = 'send'",
            params![seq, message],
        )?;
        Ok(n == 1)
    }

    /// blob 을 다 올렸다(§5c): `mls_blob` → `send`(서명 프레임). `frame` 이 비면 실패 — 다시 봉인하게 빈 send 로.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn promote_mls_blob(&self, seq: i64, frame: &str) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE outbox SET kind = 'send', frame = ?2, upload = NULL WHERE seq = ?1 AND kind = 'mls_blob'",
            params![seq, frame],
        )?;
        Ok(n == 1)
    }

    /// `blob_unavailable` 한 번 더(F8): `send` → `upload`, 사양을 바꿔 둔다(시도 수).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn demote_to_upload(&self, seq: i64, spec: &str) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE outbox SET kind = 'upload', frame = '', plain = NULL, upload = ?2 WHERE seq = ?1 AND kind = 'send'",
            params![seq, spec],
        )?;
        Ok(n == 1)
    }

    /// 받을 첨부를 적는다(같은 (msg_id, idx) 는 한 번 — 같은 deliver 를 다시 받아도).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn add_download(&self, d: &Download, held: bool) -> Result<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO downloads(msg_id, idx, blob_id, fk, prefix, sha256, size, held) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![d.msg_id, d.idx, d.blob_id, d.fk, d.prefix, d.sha256, d.size as i64, held],
        )?;
        Ok(())
    }

    /// 그 메시지의 '믿음 기다림' 첨부를 받을 수 있게 푼다(보낸 기기를 믿음). 푼 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn release_downloads(&self, msg_id: &str) -> Result<usize> {
        Ok(self.c().execute(
            "UPDATE downloads SET held = 0 WHERE msg_id = ?1 AND held = 1",
            params![msg_id],
        )?)
    }

    /// 그 메시지의 받을 첨부를 모두 지운다(기기 거부·폐기, 메시지 만료·거두기). 지운 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_downloads(&self, msg_id: &str) -> Result<usize> {
        Ok(self
            .c()
            .execute("DELETE FROM downloads WHERE msg_id = ?1", params![msg_id])?)
    }

    /// 받을 첨부(오래된 것부터).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn downloads(&self) -> Result<Vec<Download>> {
        let c = self.c();
        let mut st = c.prepare(
            "SELECT msg_id, idx, blob_id, fk, prefix, sha256, size FROM downloads WHERE held = 0 ORDER BY rowid",
        )?;
        let rows = st.query_map([], |r| {
            Ok(Download {
                msg_id: r.get(0)?,
                idx: r.get(1)?,
                blob_id: r.get(2)?,
                fk: r.get(3)?,
                prefix: r.get(4)?,
                sha256: r.get(5)?,
                size: r.get::<_, i64>(6)?.max(0) as u64,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// 받았다(또는 못 받는다고 정했다) — 행을 지운다(키가 남지 않게). 행이 없었으면(그사이 [`Self::drop_downloads`]) `false`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn finish_download(&self, msg_id: &str, idx: u32) -> Result<bool> {
        let c = self.c();
        let n = c.execute(
            "DELETE FROM downloads WHERE msg_id = ?1 AND idx = ?2",
            params![msg_id, idx],
        )?;
        truncate_wal(&c);
        Ok(n == 1)
    }

    /// 가장 오래된 항목.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn peek(&self) -> Result<Option<Item>> {
        Ok(self
            .c()
            .query_row(
                "SELECT seq, kind, msg_id, peer, frame FROM outbox ORDER BY seq LIMIT 1",
                [],
                |r| {
                    Ok(Item {
                        seq: r.get(0)?,
                        kind: r.get(1)?,
                        msg_id: r.get(2)?,
                        peer: r.get(3)?,
                        frame: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn remove(&self, seq: i64) -> Result<()> {
        let c = self.c();
        c.execute("DELETE FROM outbox WHERE seq = ?1", params![seq])?;
        truncate_wal(&c);
        Ok(())
    }

    /// 큐에 남은 프로필 기본 이미지 프레임(`profile.update{look}`, #874)을 버린다 — 붙을 때마다 부른다(프로필 바꾸기는 붙어
    /// 있을 때만 하는 즉시 동작이라 끊기기 전 못 나간 것이 늦게 저절로 적용되지 않게, look 을 모르는 relay 는 그 칸을
    /// error{protocol} 로 거절하기도 한다). 사진 올리기 등 다른 profile 행은 남긴다. 버린 수.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn drop_look_frames(&self) -> Result<usize> {
        let mut n = 0;
        for it in self.items()? {
            let look = it.kind == "profile"
                && serde_json::from_str::<serde_json::Value>(&it.frame)
                    .is_ok_and(|f| f["t"] == "profile.update" && f.get("look").is_some());
            if look {
                self.remove(it.seq)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// 아직 나가지 못한 보낸 메시지(`send`) 수 — 로그아웃 미리보기(#325).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn unsent_sends(&self) -> Result<usize> {
        let n: i64 = self.c().query_row(
            "SELECT COUNT(*) FROM outbox WHERE kind IN ('send','upload')",
            [],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// 아직 나가지 못한 보낸 메시지(`send`)를 큐에서 지우고 그 msg_id 를 큐 순서로 돌려준다(로그아웃, #325).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn discard_sends(&self) -> Result<Vec<String>> {
        let c = self.c();
        let mut st =
            c.prepare("DELETE FROM outbox WHERE kind IN ('send','upload') RETURNING seq, msg_id")?;
        let mut rows: Vec<(i64, Option<String>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        rows.sort_by_key(|(seq, _)| *seq);
        drop(st);
        truncate_wal(&c);
        Ok(rows.into_iter().filter_map(|(_, id)| id).collect())
    }

    /// # Errors
    /// sqlite 오류.
    pub fn len(&self) -> Result<usize> {
        let n: i64 = self
            .c()
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// # Errors
    /// sqlite 오류.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// 한 행(없으면 `None`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn get(&self, seq: i64) -> Result<Option<Item>> {
        Ok(self
            .c()
            .query_row(
                "SELECT seq, kind, msg_id, peer, frame FROM outbox WHERE seq = ?1",
                params![seq],
                |r| {
                    Ok(Item {
                        seq: r.get(0)?,
                        kind: r.get(1)?,
                        msg_id: r.get(2)?,
                        peer: r.get(3)?,
                        frame: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// 큐 순서대로 frame 없이 가볍게(대상별 차례 고르기, hosted 11-04 C).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn order(&self) -> Result<Vec<QueueRow>> {
        let c = self.c();
        let mut st = c.prepare("SELECT seq, kind, peer, msg_id FROM outbox ORDER BY seq")?;
        let rows = st.query_map([], |r| {
            Ok(QueueRow {
                seq: r.get(0)?,
                kind: r.get(1)?,
                peer: r.get(2)?,
                msg_id: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// 모든 항목(시험·진단).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn items(&self) -> Result<Vec<Item>> {
        let c = self.c();
        let mut st = c.prepare("SELECT seq, kind, msg_id, peer, frame FROM outbox ORDER BY seq")?;
        let rows = st.query_map([], |r| {
            Ok(Item {
                seq: r.get(0)?,
                kind: r.get(1)?,
                msg_id: r.get(2)?,
                peer: r.get(3)?,
                frame: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn mark_sent(&self, msg_id: &str, to_user: &str) -> Result<()> {
        self.c().execute(
            "INSERT OR IGNORE INTO sent(msg_id, to_user) VALUES (?1, ?2)",
            params![msg_id, to_user],
        )?;
        Ok(())
    }

    /// 내가 보낸 메시지면 그 받는 사용자.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn sent_to(&self, msg_id: &str) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row(
                "SELECT to_user FROM sent WHERE msg_id = ?1",
                params![msg_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn peer(&self, device_id: &str) -> Result<Option<Peer>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {PEER_COLS} FROM peers WHERE device_id = ?1"),
                params![device_id],
                peer_row,
            )
            .optional()?)
    }

    /// 그 사용자의 기기 전부(폐기 포함, 등록 순서 없음 — device_id 순).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn peers_of(&self, user: &str) -> Result<Vec<Peer>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {PEER_COLS} FROM peers WHERE user = ?1 ORDER BY device_id"
        ))?;
        let rows = st.query_map(params![user], peer_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// 모든 피어(sync 재발행용, 사용자·device_id 순).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn peers(&self) -> Result<Vec<Peer>> {
        let c = self.c();
        let mut st = c.prepare(&format!(
            "SELECT {PEER_COLS} FROM peers ORDER BY user, device_id"
        ))?;
        let rows = st.query_map([], peer_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// # Errors
    /// sqlite 오류.
    pub fn set_trust(&self, device_id: &str, trust: Trust) -> Result<()> {
        self.c().execute(
            "UPDATE peers SET trust = ?2 WHERE device_id = ?1",
            params![device_id, trust.as_str()],
        )?;
        Ok(())
    }

    /// 신뢰 근거(#393 e2e §7a-2): `first_contact`·`human`·`cert:<서명자 device_id>`(여럿). 없으면 빈 목록(예전 피어 —
    /// 근거를 모른다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn basis(&self, device_id: &str) -> Result<Vec<String>> {
        let b: Option<String> = self
            .c()
            .query_row(
                "SELECT basis FROM peers WHERE device_id = ?1",
                params![device_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(b.unwrap_or_default()
            .split(',')
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// 신뢰 근거를 바꾼다(중복 없이, 넣은 순).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_basis(&self, device_id: &str, basis: &[String]) -> Result<()> {
        let mut uniq: Vec<&str> = Vec::new();
        for b in basis {
            if !uniq.contains(&b.as_str()) {
                uniq.push(b);
            }
        }
        self.c().execute(
            "UPDATE peers SET basis = ?2 WHERE device_id = ?1",
            params![device_id, uniq.join(",")],
        )?;
        Ok(())
    }

    /// 근거 하나를 더한다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn add_basis(&self, device_id: &str, b: &str) -> Result<()> {
        let mut all = self.basis(device_id)?;
        all.push(b.to_owned());
        self.set_basis(device_id, &all)
    }

    /// 이 기기가 `pending` 이 된 시각(ms, #393 §7a-3 서명 기다림의 시작). 아니면 `None`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn pending_since(&self, device_id: &str) -> Result<Option<i64>> {
        Ok(self
            .c()
            .query_row(
                "SELECT pending_since FROM peers WHERE device_id = ?1",
                params![device_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    /// 기다림 시작 시각을 둔다(`None` = 지운다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_pending_since(&self, device_id: &str, at: Option<i64>) -> Result<()> {
        self.c().execute(
            "UPDATE peers SET pending_since = ?2 WHERE device_id = ?1",
            params![device_id, at],
        )?;
        Ok(())
    }

    /// # Errors
    /// sqlite 오류.
    pub fn peer_count(&self, user: &str) -> Result<usize> {
        let n: i64 = self.c().query_row(
            "SELECT COUNT(*) FROM peers WHERE user = ?1",
            params![user],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// 그 사용자의 마지막으로 본 뿌리.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn last_root(&self, user: &str) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row(
                "SELECT device_id FROM roots WHERE user = ?1",
                params![user],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// 마지막으로 본 뿌리를 남긴다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_root(&self, user: &str, device_id: &str, now_ms: i64) -> Result<()> {
        self.c().execute(
            "INSERT INTO roots (user, device_id, since) VALUES (?1, ?2, ?3) \
             ON CONFLICT (user) DO UPDATE SET device_id = excluded.device_id, since = excluded.since",
            params![user, device_id, now_ms],
        )?;
        Ok(())
    }

    /// 받아진 푸시 등록의 salt 를 둔다(앞 것은 바꾼다 — relay 가 등록마다 새로 만든다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_push_salt(&self, salt: &[u8]) -> Result<()> {
        self.c().execute(
            "INSERT INTO push_reg (id, salt) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET salt = excluded.salt",
            params![salt],
        )?;
        Ok(())
    }

    /// own_stream 보낸 seq 를 남긴다(#870 — keyframe 때).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn set_own_stream_seq(&self, last: u64) -> Result<()> {
        self.c().execute(
            "INSERT INTO own_stream_seq (id, last) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET last = excluded.last",
            params![i64::try_from(last).unwrap_or(i64::MAX)],
        )?;
        Ok(())
    }

    /// 남긴 own_stream seq(없으면 `None`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn own_stream_seq(&self) -> Result<Option<u64>> {
        let v: Option<i64> = self
            .c()
            .query_row("SELECT last FROM own_stream_seq WHERE id = 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(v.and_then(|v| u64::try_from(v).ok()))
    }

    /// 마지막 푸시 등록의 salt(등록 전이면 `None`).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn push_salt(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .c()
            .query_row("SELECT salt FROM push_reg WHERE id = 1", [], |r| r.get(0))
            .optional()?)
    }

    /// 심어 둔(`trusted`) 피어 행을 지운다 — 기기 등록이 실패했을 때(#339). 다른 상태면 둔다.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn remove_trusted_peer(&self, device_id: &str) -> Result<()> {
        self.c().execute(
            "DELETE FROM peers WHERE device_id = ?1 AND trust = 'trusted'",
            params![device_id],
        )?;
        Ok(())
    }

    /// 없을 때만 넣는다(이미 있으면 그대로).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn add_peer(&self, p: &Peer) -> Result<()> {
        self.insert_peer(p).map(|_| ())
    }

    /// 근거와 함께 없을 때만 넣는다 — 한 문장이라 그 사이에 디렉터리 처리가 끼지 못한다(#468: 행만 있고 `planted` 표시가 아직
    /// 없을 때 디렉터리가 오면 '목록에 없음'으로 폐기됐다).
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn insert_peer_with_basis(&self, p: &Peer, basis: &[String]) -> Result<bool> {
        let n = self.c().execute(
            "INSERT OR IGNORE INTO peers(device_id, user, ed25519, x25519, trust, first_contact, basis) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                p.device_id,
                p.user,
                p.ed25519,
                p.x25519,
                p.trust.as_str(),
                i64::from(p.first_contact),
                basis.join(",")
            ],
        )?;
        Ok(n == 1)
    }

    /// [`Self::add_peer`] 와 같고, 새로 넣었으면 `true`.
    ///
    /// # Errors
    /// sqlite 오류.
    pub fn insert_peer(&self, p: &Peer) -> Result<bool> {
        self.insert_peer_with_basis(p, &[])
    }
}

/// outbox.frame 에 서명된 평문 본문이, mls_kv 에 MLS 비밀(암호화)이 들어간다 → umask(0644)에 맡기지 않고 0600 으로 먼저
/// 만든다(core Store 와 같다). SQLite 는 -wal·-shm 을 본 파일과 같은 모드로 만든다.
pub(crate) fn create_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// 이 DB 를 여는 연결마다(outbox·MLS 저장): 지운 행을 0 으로 덮는다 — send 행의 봉투 전 평문(`plain`)·지난 epoch 비밀이
/// free page 에 남지 않게(#313, 묶음 22 §8). WAL·FULL.
pub(crate) fn pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")
}

/// WAL 을 본 DB 로 옮기고 0 바이트로 자른다 — 지운 send 행의 평문(`plain`)이 `-wal` 에 남지 않게(#313, relay 와 같은 방법).
/// 본 DB 쪽은 `secure_delete` 가 덮는다. 다른 연결이 읽는 중이면 이번엔 못 자를 수 있다. 실패는 삭제를 막지 않는다.
pub(crate) fn truncate_wal(c: &Connection) {
    let _ = try_truncate_wal(c);
}

/// [`truncate_wal`] 이 실제로 잘랐나 — `wal_checkpoint` 첫 열(busy)이 0 이고 오류가 없을 때만 참.
pub(crate) fn try_truncate_wal(c: &Connection) -> bool {
    c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
        r.get::<_, i64>(0)
    })
    .is_ok_and(|busy| busy == 0)
}

/// `system` 메시지(봉투 없는 빈 평문, §3.4 — `from.device_id` 를 채우고 `state` 를 뺀 것)를 서명한 `send` 프레임으로. 1:1·그룹
/// 응용 메시지는 MLS 라 여기 오지 않는다(연결 루프가 큐 맨 앞에서 봉인).
///
/// # Errors
/// 형식 오류·system 아님·서명 실패·프레임 상한 초과.
pub fn seal_send(keys: &DeviceKeys, plain: &Value) -> Result<String> {
    let mut m = plain.clone();
    if m.get("kind").and_then(Value::as_str) != Some("system") {
        // 1:1·그룹은 MLS(묶음 22) — 연결 루프가 큐 맨 앞에서 봉인한다.
        return Err(Error::Message("system 밖은 MLS 로만(묶음 22)".into()));
    }
    if m.pointer("/body/enc").and_then(Value::as_str) != Some("plain")
        || m.pointer("/body/text").and_then(Value::as_str) != Some("")
    {
        return Err(Error::Message("system 본문은 빈 평문".into()));
    }
    sign_message(&mut m, &keys.signing)?;
    let frame = json!({"t": "send", "message": m}).to_string();
    let max = lodelai_protocol::constants::WS_MAX_FRAME_BYTES as usize;
    if frame.len() > max {
        return Err(Error::FrameTooLarge {
            bytes: frame.len(),
            max,
        });
    }
    Ok(frame)
}

/// 첨부 메시지를 올리기 항목으로 넣는다(묶음 15 §3). 실제 올리기·봉투는 연결 루프가 큐 맨 앞에서 한다(순서 유지).
/// 감쌀 대상이 없으면 올리기 전에 거절한다 — 올려 놓고 버리면 blob 이 1시간 떠다닌다.
fn enqueue_upload(
    store: &Store,
    keys: &DeviceKeys,
    message: &Value,
    attachments: &[crate::OutFile],
) -> Result<()> {
    use lodelai_protocol::constants as c;
    let kind = message
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(kind, "chat" | "request" | "reply") {
        return Err(Error::Message(format!(
            "첨부는 chat·request·reply 만({kind})"
        )));
    }
    if attachments.is_empty() || attachments.len() > c::FILES_PER_MESSAGE as usize {
        return Err(Error::Message("첨부 수".into()));
    }
    let mut m = message.clone();
    let msg_id = m
        .get("msg_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Message("msg_id 없음".into()))?
        .to_owned();
    m.get_mut("from")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::Message("from 없음".into()))?
        .insert(
            "device_id".into(),
            Value::String(keys.device_id().as_str().to_owned()),
        );
    if let Some(o) = m.as_object_mut() {
        o.remove("state");
    }
    let to_user = m
        .pointer("/to/address")
        .and_then(Value::as_str)
        .and_then(|a| a.split('@').next())
        .ok_or_else(|| Error::Message("to.address 없음".into()))?
        .to_owned();
    let mut files = Vec::with_capacity(attachments.len());
    for a in attachments {
        let meta =
            std::fs::metadata(&a.path).map_err(|e| Error::Message(format!("첨부 파일: {e}")))?;
        if !meta.is_file() || meta.len() > c::FILE_MAX_BYTES {
            return Err(Error::Message("첨부 파일 크기·종류".into()));
        }
        if a.name.is_empty() || a.name.len() > 255 {
            return Err(Error::Message("첨부 이름 길이".into()));
        }
        files.push(UploadFile {
            path: a.path.clone(),
            name: a.name.clone(),
            mime: a.mime.clone(),
            role: a.role.clone(),
            size: meta.len(),
            sha256: a.sha256.clone(),
            size_px: a.size_px,
        });
    }
    let spec = UploadSpec {
        message: m,
        files,
        attempts: 0,
    };
    let spec = serde_json::to_string(&spec).map_err(|e| Error::Message(e.to_string()))?;
    store.push_upload(&format!("send:{msg_id}"), &msg_id, &to_user, &spec)
}

/// [`Outgoing`] 을 큐에 넣는다. `system` 은 여기서 서명하고, 1:1·그룹 응용 메시지는 평문만 두어 연결 루프가 큐 맨 앞에서 MLS 로
/// 봉인한다(재전송은 같은 바이트).
///
/// # Errors
/// 형식 오류·서명·저장 실패.
pub fn enqueue(store: &Store, keys: &DeviceKeys, clock: &dyn Clock, out: &Outgoing) -> Result<()> {
    let now = || {
        clock
            .now()
            .to_rfc3339()
            .map_err(|e| Error::Message(e.to_string()))
    };
    match out {
        Outgoing::Send { message } => {
            let mut m = message.clone();
            let msg_id = m
                .get("msg_id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Message("msg_id 없음".into()))?
                .to_owned();
            let from = m
                .get_mut("from")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::Message("from 없음".into()))?;
            from.insert(
                "device_id".into(),
                Value::String(keys.device_id().as_str().to_owned()),
            );
            if let Some(o) = m.as_object_mut() {
                o.remove("state");
            }
            let to_user = m
                .pointer("/to/address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                .ok_or_else(|| Error::Message("to.address 없음".into()))?
                .to_owned();
            // 같은 msg_id 가 이미 큐에 있으면 다시 봉투로 만들지 않는다(같은 바이트 유지 — 난수를 새로 쓰지 않게).
            if store.has_dedup(&format!("send:{msg_id}"))? {
                return Ok(());
            }
            // 1:1 은 MLS(묶음 22): 평문만 두고 봉인은 연결 루프가 큐 맨 앞에서(그룹이 있어야 하고 epoch 가 그때 정해진다). 빈
            // frame = 아직 봉인 안 함. `system`(봉투 없는 빈 평문)·그룹 맥락(h 전까지 봉투)은 지금처럼.
            let system = m.get("kind").and_then(Value::as_str) == Some("system");
            let frame = if system {
                seal_send(keys, &m)?
            } else {
                String::new()
            };
            store.push_with_plain(
                &format!("send:{msg_id}"),
                "send",
                Some(&msg_id),
                Some(&to_user),
                &frame,
                Some(&m.to_string()),
                false,
            )
        }
        Outgoing::SendFiles {
            message,
            attachments,
        } => enqueue_upload(store, keys, message, attachments),
        Outgoing::GroupChange { message } => {
            let mut m = message.clone();
            let msg_id = m
                .get("msg_id")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Message("msg_id 없음".into()))?
                .to_owned();
            m.get_mut("from")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| Error::Message("from 없음".into()))?
                .insert(
                    "device_id".into(),
                    Value::String(keys.device_id().as_str().to_owned()),
                );
            if let Some(o) = m.as_object_mut() {
                o.remove("state");
            }
            if store.has_dedup(&format!("send:{msg_id}"))? {
                return Ok(());
            }
            // 묶음 22: 그룹 변경은 MLS Commit 으로 — 평문만 두고 연결 루프가 큐 맨 앞에서(KeyPackage·start·Commit).
            let frame = String::new();
            let to = m
                .pointer("/to/address")
                .and_then(Value::as_str)
                .and_then(|a| a.split('@').next())
                .unwrap_or_default()
                .to_owned();
            store.push_with_plain(
                &format!("send:{msg_id}"),
                "send",
                Some(&msg_id),
                Some(&to),
                &frame,
                Some(&m.to_string()),
                false,
            )
        }
        Outgoing::SenderStatus {
            msg_id,
            state,
            abort_reason,
            fail_reason,
        } => {
            let mut f =
                json!({"t": "status", "msg_id": msg_id, "state": state.as_str(), "at": now()?});
            if *state == lodelai_protocol::states::SenderViewState::Aborted {
                if let Some(a) = abort_reason {
                    f["abort_reason"] = json!(a.as_str());
                }
            }
            if *state == lodelai_protocol::states::SenderViewState::Failed {
                if let Some(r) = fail_reason {
                    f["fail_reason"] = json!(r);
                }
            }
            // 같은 msg_id 에 상태가 여러 번 정당하게 나간다(accepted → consumed → replied) → 상태까지 키에 넣는다.
            store.push(
                &format!("status:{msg_id}:{}", state.as_str()),
                "status",
                Some(msg_id),
                None,
                &f.to_string(),
                false,
            )
        }
        Outgoing::ChatRead { msg_id } => {
            let f = json!({"t": "status", "msg_id": msg_id, "state": "read", "at": now()?});
            // SenderStatus 와 같은 키 모양 — 같은 msg_id 의 read 는 한 번만 나간다.
            store.push(
                &format!("status:{msg_id}:read"),
                "status",
                Some(msg_id),
                None,
                &f.to_string(),
                false,
            )
        }
        Outgoing::ChatAcknowledged { msg_id } => {
            let f = json!({"t": "status", "msg_id": msg_id, "state": "acknowledged", "at": now()?});
            store.push(
                &format!("status:{msg_id}:acknowledged"),
                "status",
                Some(msg_id),
                None,
                &f.to_string(),
                false,
            )
        }
        Outgoing::PresenceSet { share } => {
            let f = json!({"t": "presence.set", "share": share});
            store.push("presence", "presence", None, None, &f.to_string(), true)
        }
        Outgoing::Rejected { msg_id } => {
            let f = json!({"t": "status", "msg_id": msg_id, "state": "rejected", "at": now()?});
            store.push(
                &format!("rejected:{msg_id}"),
                "status",
                Some(msg_id),
                None,
                &f.to_string(),
                false,
            )
        }
        Outgoing::Publish {
            slug,
            grade,
            liveness,
            display,
            title,
            folder,
            busy,
            audience,
            project,
            agent,
            no,
        } => {
            let mut f =
                json!({"t": "session.publish", "slug": slug, "grade": grade, "liveness": liveness});
            if let Some(users) = audience {
                // 빈 people 은 relay 가 프레임 전체를 거절한다(publish 가 사라짐) — 주인만은 코어가 범위 목록을 지켜 보낸다.
                // release 에서도 큐에 넣지 않고 오류로 돌려준다(QA 20 🟡 — 넣으면 다시 보낼 때마다 거절된다).
                if users.is_empty() {
                    return Err(Error::Message("빈 audience people".into()));
                }
                // #845 둘째 ①: `#<list_id>` 로 실린 것은 친구 목록 id([`crate::AUDIENCE_LIST_MARK`]) — `lists` 로 갈라 싣는다.
                let (lists, users): (Vec<&String>, Vec<&String>) = users
                    .iter()
                    .partition(|u| u.starts_with(crate::AUDIENCE_LIST_MARK));
                let mut a = json!({"kind": "people"});
                if !users.is_empty() {
                    a["users"] = json!(users);
                }
                if !lists.is_empty() {
                    a["lists"] = json!(lists
                        .iter()
                        .map(|l| l.trim_start_matches(crate::AUDIENCE_LIST_MARK))
                        .collect::<Vec<_>>());
                }
                f["audience"] = a;
            }
            for (k, v) in [
                ("display", display),
                ("title", title),
                ("folder", folder),
                ("agent", agent),
            ] {
                if let Some(v) = v {
                    f[k] = json!(v);
                }
            }
            if *busy {
                f["busy"] = json!(true);
            }
            if let Some(n) = no {
                f["no"] = json!(n);
            }
            if let Some(p) = project {
                f["project"] = json!({"id": p.id, "name": p.name});
            }
            store.push(
                &format!("session:{slug}"),
                "session",
                None,
                None,
                &f.to_string(),
                true,
            )
        }
        Outgoing::Unpublish { slug } => {
            let f = json!({"t": "session.unpublish", "slug": slug});
            store.push(
                &format!("session:{slug}"),
                "session",
                None,
                None,
                &f.to_string(),
                true,
            )
        }
        Outgoing::ProfileUpdate {
            display_name,
            teams,
        } => {
            // 필드마다 따로(#355) — 표시 이름과 팀이 서로의 마지막 값을 지우지 않게.
            if let Some(d) = display_name {
                let f = json!({"t": "profile.update", "display_name": d});
                store.push(
                    "profile.display",
                    "profile",
                    None,
                    None,
                    &f.to_string(),
                    true,
                )?;
            }
            if let Some(ts) = teams {
                let f = json!({"t": "profile.update", "teams": ts});
                store.push("profile.teams", "profile", None, None, &f.to_string(), true)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #874: look 을 모르는 relay 에 붙으면 큐의 look 프레임만 버리고 다른 profile 행(사진 지우기 등)은 남긴다.
    #[test]
    fn look_프레임만_버린다() {
        let s = Store::memory().unwrap();
        s.push(
            "a",
            "profile",
            None,
            None,
            r#"{"t":"profile.update","look":{"kind":"initial","tone":3}}"#,
            true,
        )
        .unwrap();
        s.push(
            "b",
            "profile",
            None,
            None,
            r#"{"t":"profile.update","avatar":null}"#,
            true,
        )
        .unwrap();
        s.push(
            "c",
            "profile",
            None,
            None,
            r#"{"t":"profile.update","look":null}"#,
            true,
        )
        .unwrap();
        assert_eq!(s.drop_look_frames().unwrap(), 2);
        let left: Vec<String> = s.items().unwrap().into_iter().map(|i| i.frame).collect();
        assert_eq!(
            left,
            vec![r#"{"t":"profile.update","avatar":null}"#.to_owned()]
        );
    }
    use lodelai_crypto::encoding;
    use lodelai_protocol::states::SenderViewState;
    use lodelai_testkit::effects::FixedClock;

    fn keys() -> DeviceKeys {
        DeviceKeys::generate(&[1u8; 64])
    }

    fn bob() -> DeviceKeys {
        DeviceKeys::generate(&[2u8; 64])
    }

    fn peer_of(k: &DeviceKeys, user: &str, trust: Trust) -> Peer {
        Peer {
            device_id: k.device_id().as_str().to_owned(),
            user: user.to_owned(),
            ed25519: k.signing.verifying_key().to_b64(),
            x25519: encoding::encode(&k.exchange.public_key()),
            trust,
            first_contact: false,
        }
    }

    /// bob 의 신뢰한 기기 하나가 있는 저장소.
    fn store_with_bob() -> Store {
        let s = Store::memory().unwrap();
        s.add_peer(&peer_of(&bob(), "bob", Trust::Trusted)).unwrap();
        s
    }

    fn message(id: &str) -> Value {
        json!({
            "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": id, "thread_id": id, "kind": "chat",
            "from": {"address": "alice@local", "author": "human", "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"},
            "to": {"address": "bob@local"}, "body": {"enc": "plain", "text": "hi"},
            "created_at": "2026-10-23T04:12:56.000Z", "expires_at": "2026-10-24T04:12:56.000Z", "state": "sent"
        })
    }

    #[test]
    fn send_is_signed_with_own_device_and_deduped() {
        let s = store_with_bob();
        let k = keys();
        let clock = FixedClock::new(1_792_728_776_000);
        let out = Outgoing::Send {
            message: message("01JB0000000000000000000001"),
        };
        enqueue(&s, &k, clock.as_ref(), &out).unwrap();
        enqueue(&s, &k, clock.as_ref(), &out).unwrap();
        let items = s.items().unwrap();
        assert_eq!(items.len(), 1, "같은 msg_id 의 send 는 하나");
        // 1:1 은 MLS(묶음 22) — 봉인은 연결 루프가 큐 맨 앞에서. 큐에는 평문만(frame 빔).
        assert!(items[0].frame.is_empty());
        // 봉인 전 메시지는 같은 행에, Item 에는 없다
        let plain = s.plain_of(items[0].seq).unwrap().unwrap();
        let plain: Value = serde_json::from_str(&plain.unwrap()).unwrap();
        assert_eq!(plain["body"], json!({"enc": "plain", "text": "hi"}));
        assert_eq!(plain["from"]["device_id"], k.device_id().as_str());
    }

    #[test]
    fn system_goes_as_empty_plain_and_nonempty_system_is_refused() {
        let s = Store::memory().unwrap(); // 받는 기기를 몰라도 system 은 봉투가 없다
        let k = keys();
        let clock = FixedClock::new(0);
        let mut m = message("01JB0000000000000000000003");
        m["kind"] = json!("system");
        m["body"]["text"] = json!("");
        enqueue(
            &s,
            &k,
            clock.as_ref(),
            &Outgoing::Send { message: m.clone() },
        )
        .unwrap();
        let f: Value = serde_json::from_str(&s.items().unwrap()[0].frame).unwrap();
        assert_eq!(f["message"]["body"], json!({"enc": "plain", "text": ""}));
        m["msg_id"] = json!("01JB0000000000000000000004");
        m["body"]["text"] = json!("사유");
        assert!(enqueue(&s, &k, clock.as_ref(), &Outgoing::Send { message: m }).is_err());
    }

    /// 큐에서 뺀 send 행의 평문이 DB·`-wal` 원시 바이트에 남지 않는다(secure_delete + WAL 잘라냄, QA 리뷰).
    #[cfg(unix)]
    #[test]
    fn 뺀_send_행의_평문은_파일에_남지_않는다() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("q.db");
        let s = Store::open(&path).unwrap();
        s.add_peer(&peer_of(&bob(), "bob", Trust::Trusted)).unwrap();
        let canary = "lodelai-canary-queue-01JB";
        let mut m = message("01JB0000000000000000000001");
        m["body"]["text"] = json!(canary);
        let clock = FixedClock::new(0);
        enqueue(&s, &keys(), clock.as_ref(), &Outgoing::Send { message: m }).unwrap();
        let raw = || {
            ["q.db", "q.db-wal"]
                .iter()
                .filter_map(|n| std::fs::read(d.path().join(n)).ok())
                .flatten()
                .collect::<Vec<u8>>()
        };
        let has = |b: &[u8]| b.windows(canary.len()).any(|w| w == canary.as_bytes());
        assert!(
            has(&raw()),
            "시험 전제: 큐에 있는 동안은 평문이 파일에 있다"
        );
        let seq = s.items().unwrap()[0].seq;
        s.remove(seq).unwrap();
        assert!(!has(&raw()), "뺀 뒤 DB·-wal 에 평문이 남았다");
    }

    #[test]
    fn status_dedup_keeps_each_state_in_order() {
        // 같은 msg_id 의 accepted → consumed → replied 가 모두 순서대로 남는다.
        let s = Store::memory().unwrap();
        let clock = FixedClock::new(1_792_728_776_000);
        for st in [
            SenderViewState::Accepted,
            SenderViewState::Consumed,
            SenderViewState::Replied,
            SenderViewState::Consumed,
        ] {
            let out = Outgoing::SenderStatus {
                msg_id: "m".into(),
                state: st,
                abort_reason: None,
                fail_reason: None,
            };
            enqueue(&s, &keys(), clock.as_ref(), &out).unwrap();
        }
        let states: Vec<String> = s
            .items()
            .unwrap()
            .iter()
            .map(|i| {
                serde_json::from_str::<Value>(&i.frame).unwrap()["state"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            states,
            ["accepted", "consumed", "replied"],
            "같은 (msg_id, state) 는 한 번"
        );
    }

    /// PROTOCOL 13: agent 없는 세션(claude_code)의 session.publish 는 12 때와 같은 칸만 싣고, codex
    /// 세션만 agent 를 싣는다.
    #[test]
    fn publish_carries_agent_only_when_set() {
        let s = Store::memory().unwrap();
        let clock = FixedClock::new(0);
        let k = keys();
        let p = |slug: &str, agent: Option<&str>| Outgoing::Publish {
            slug: slug.into(),
            grade: "task".into(),
            liveness: "live:pty".into(),
            display: Some("api".into()),
            title: Some("제목".into()),
            folder: Some("api".into()),
            busy: true,
            audience: Some(vec!["bob".into()]),
            project: Some(crate::PublishProject {
                id: "A".repeat(22),
                name: "회사/api".into(),
            }),
            agent: agent.map(str::to_owned),
            no: None,
        };
        enqueue(&s, &k, clock.as_ref(), &p("cc", None)).unwrap();
        enqueue(&s, &k, clock.as_ref(), &p("cx", Some("codex"))).unwrap();
        let items = s.items().unwrap();
        // 키 순서는 serde_json 기능(preserve_order)이 빌드 단위마다 달라 값으로 비교한다 — 12 때와 같은 칸 그대로, agent 없음.
        let f: Value = serde_json::from_str(&items[0].frame).unwrap();
        assert_eq!(
            f,
            json!({"t": "session.publish", "slug": "cc", "grade": "task", "liveness": "live:pty",
                "audience": {"kind": "people", "users": ["bob"]}, "display": "api", "title": "제목",
                "folder": "api", "busy": true,
                "project": {"id": "AAAAAAAAAAAAAAAAAAAAAA", "name": "회사/api"}})
        );
        assert!(!items[0].frame.contains("agent"));
        let f: Value = serde_json::from_str(&items[1].frame).unwrap();
        assert_eq!(f["agent"], "codex");
        // #845 둘째 ①: `#<list_id>` 는 audience.lists 로 — 사람 0명 + 목록만이면 users 칸 없이.
        let with = |slug: &str, a: &[&str]| match p(slug, None) {
            Outgoing::Publish {
                slug,
                grade,
                liveness,
                display,
                title,
                folder,
                busy,
                project,
                agent,
                no,
                ..
            } => Outgoing::Publish {
                slug,
                grade,
                liveness,
                display,
                title,
                folder,
                busy,
                audience: Some(a.iter().map(|x| (*x).to_owned()).collect()),
                project,
                agent,
                no,
            },
            _ => unreachable!(),
        };
        enqueue(&s, &k, clock.as_ref(), &with("l1", &["bob", "#list-aaaa1"])).unwrap();
        enqueue(
            &s,
            &k,
            clock.as_ref(),
            &with("l2", &["#list-aaaa1", "#list-bbbb2"]),
        )
        .unwrap();
        let items = s.items().unwrap();
        let f: Value = serde_json::from_str(&items[2].frame).unwrap();
        assert_eq!(
            f["audience"],
            json!({"kind": "people", "users": ["bob"], "lists": ["list-aaaa1"]})
        );
        let f: Value = serde_json::from_str(&items[3].frame).unwrap();
        assert_eq!(
            f["audience"],
            json!({"kind": "people", "lists": ["list-aaaa1", "list-bbbb2"]})
        );
        assert!(f.get("no").is_none(), "번호 없으면 싣지 않는다");
        // 관문 Y2: 번호는 있을 때만 정수로.
        let mut numbered = p("n2", None);
        if let Outgoing::Publish { no, .. } = &mut numbered {
            *no = Some(6);
        }
        enqueue(&s, &k, clock.as_ref(), &numbered).unwrap();
        let f: Value = serde_json::from_str(&s.items().unwrap()[4].frame).unwrap();
        assert_eq!(f["no"], 6);
    }

    #[test]
    fn publish_last_value_wins_and_codes_only_on_matching_state() {
        let s = Store::memory().unwrap();
        let clock = FixedClock::new(0);
        let k = keys();
        let p = |g: &str| Outgoing::Publish {
            slug: "be".into(),
            grade: g.into(),
            liveness: "live:pty".into(),
            display: None,
            title: None,
            folder: None,
            busy: false,
            audience: None,
            project: None,
            agent: None,
            no: None,
        };
        enqueue(&s, &k, clock.as_ref(), &p("question")).unwrap();
        enqueue(&s, &k, clock.as_ref(), &p("task")).unwrap();
        enqueue(
            &s,
            &k,
            clock.as_ref(),
            &Outgoing::Unpublish {
                slug: "other".into(),
            },
        )
        .unwrap();
        let items = s.items().unwrap();
        assert_eq!(items.len(), 2);
        let f: Value = serde_json::from_str(&items[0].frame).unwrap();
        assert_eq!(f["grade"], "task");
        // 순서: 마지막 publish 가 뒤로 간다
        enqueue(&s, &k, clock.as_ref(), &p("question")).unwrap();
        let last: Value = serde_json::from_str(&s.items().unwrap().last().unwrap().frame).unwrap();
        assert_eq!(
            (last["t"].as_str(), last["grade"].as_str()),
            (Some("session.publish"), Some("question"))
        );

        // fail_reason 은 failed 일 때만, abort_reason 은 aborted 일 때만
        let st = Outgoing::SenderStatus {
            msg_id: "x".into(),
            state: SenderViewState::Pending,
            abort_reason: Some(lodelai_protocol::states::AbortReason::TurnEnded),
            fail_reason: Some("bad_signature".into()),
        };
        enqueue(&s, &k, clock.as_ref(), &st).unwrap();
        let f: Value = serde_json::from_str(&s.items().unwrap().last().unwrap().frame).unwrap();
        assert!(f.get("abort_reason").is_none() && f.get("fail_reason").is_none());
        let st = Outgoing::SenderStatus {
            msg_id: "x".into(),
            state: SenderViewState::Failed,
            abort_reason: None,
            fail_reason: Some("bad_signature".into()),
        };
        enqueue(&s, &k, clock.as_ref(), &st).unwrap();
        let f: Value = serde_json::from_str(&s.items().unwrap().last().unwrap().frame).unwrap();
        assert_eq!(f["fail_reason"], "bad_signature");
        assert_eq!(f["at"], "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn chat_read_is_a_status_read_frame_once_per_msg() {
        let s = Store::memory().unwrap();
        let clock = FixedClock::new(0);
        let k = keys();
        let out = Outgoing::ChatRead { msg_id: "c".into() };
        enqueue(&s, &k, clock.as_ref(), &out).unwrap();
        enqueue(&s, &k, clock.as_ref(), &out).unwrap();
        let items = s.items().unwrap();
        assert_eq!(items.len(), 1, "같은 msg_id 의 read 는 하나");
        let f: Value = serde_json::from_str(&items[0].frame).unwrap();
        assert_eq!(
            f,
            json!({"t": "status", "msg_id": "c", "state": "read", "at": "1970-01-01T00:00:00.000Z"})
        );
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            json!({"type": "chat_read", "msg_id": "c"})
        );
    }

    #[test]
    fn outgoing_round_trips_as_json() {
        // core 가 트랜잭셔널 아웃박스에 JSON 으로 저장한다.
        let out = Outgoing::SenderStatus {
            msg_id: "m".into(),
            state: SenderViewState::Aborted,
            abort_reason: Some(lodelai_protocol::states::AbortReason::TurnEnded),
            fail_reason: None,
        };
        let j = serde_json::to_value(&out).unwrap();
        assert_eq!(
            j,
            json!({"type": "sender_status", "msg_id": "m", "state": "aborted", "abort_reason": "turn_ended"})
        );
        assert_eq!(serde_json::from_value::<Outgoing>(j).unwrap(), out);
    }

    #[test]
    fn bad_send_is_an_error_not_a_panic() {
        let s = Store::memory().unwrap();
        let clock = FixedClock::new(0);
        assert!(enqueue(
            &s,
            &keys(),
            clock.as_ref(),
            &Outgoing::Send {
                message: json!({"from": {}})
            }
        )
        .is_err());
        assert!(enqueue(
            &s,
            &keys(),
            clock.as_ref(),
            &Outgoing::Send {
                message: json!({"msg_id": "m"})
            }
        )
        .is_err());
        assert!(s.is_empty().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn db_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("q.db");
        // 이미 0644 로 있던 파일도 0600 으로 바꾼다
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let s = Store::open(&path).unwrap();
        s.add_peer(&peer_of(&bob(), "bob", Trust::Trusted)).unwrap();
        let k = keys();
        let clock = FixedClock::new(0);
        enqueue(
            &s,
            &k,
            clock.as_ref(),
            &Outgoing::Send {
                message: message("01JB0000000000000000000001"),
            },
        )
        .unwrap();
        for name in ["q.db", "q.db-wal", "q.db-shm"] {
            let p = d.path().join(name);
            if p.exists() {
                assert_eq!(
                    std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{name}"
                );
            }
        }
        assert!(d.path().join("q.db-wal").exists(), "WAL 파일도 확인 대상");
    }
}
