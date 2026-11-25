//! 모바일 검증 S2: 알림 하나를 relay 연결 없이 연다(iOS NSE·Android FCM 서비스 — 설계 mobile-코어·mobile-push 판정).
//!
//! - 알림 본문 `p` = base64(nonce 12 ‖ ChaCha20-Poly1305(push 키, nonce, aad `lodelai-push-v1`, 1 ‖ id_len u8 ‖ msg_id ‖
//!   msg_len u16 BE ‖ MLS 응용 메시지 ‖ 0 채움)) — relay `push::seal` 과 같은 꼴.
//! - MLS 응용 메시지를 풀면 그 키가 지워진다(전방 비밀성). 그래서 연 평문을 `mls_opened` 에 같은 트랜잭션으로 남기고, 봉투가
//!   없어 못 한 보낸 기기 대조(§12-11 ⓔ)는 MLS 자격의 보낸 기기를 같이 남겨 앱이 다시 받을 때 한다.
//! - Commit·Welcome 은 처리하지 않는다(그룹 상태를 앞으로 미는 일은 앱만). 응용 메시지가 아니면 [`OpenError::NotApp`].
//! - 앱과 같은 MLS 저장을 고치므로 호출자가 앱과 나눠 쓰는 파일 잠금을 쥔 채 부른다(mobile-host).

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use openmls::prelude::{GroupId, MlsGroup};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::mls::{self, Provider, Received};
use crate::mls_store::MlsStore;

const SEAL_AAD: &[u8] = b"lodelai-push-v1";
const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

/// 연 알림.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub msg_id: String,
    /// MLS 그룹 id(바이트).
    pub gid: Vec<u8>,
    /// 본문(§12-17 평문의 머리 뒤 원 바이트).
    pub body: String,
    /// 첨부가 있다(머리 `files`).
    pub has_files: bool,
    /// MLS 자격의 보낸 기기.
    pub sender: String,
    /// 그 기기의 주인(이 기기가 디렉터리로 고정한 피어 표).
    pub sender_user: String,
    /// 보낸 에이전트 slug(#1092 평문 머리 `agent`, 꼴만 본 값) — 사람 글·옛 판이 보낸 글이면 `None`. 주장 범위는 MLS 가 증명한
    /// 보낸 기기 주인([`Self::sender_user`])의 세션뿐(이름은 그 사람 주소 아래에서만 찾는다).
    pub agent: Option<String>,
    /// 에이전트가 물은 요청의 답·거절인가(#1598 평문 머리 `to_agent: true`, #1607 판정 7055693137) — 사람이 물은 것·옛 판이
    /// 보낸 글이면 거짓. 보낸 쪽이 적는 값이라 알림 가르기(에이전트 앞 답·거절은 조용한 줄)에만 쓴다.
    pub to_agent: bool,
    /// 답·거절의 받는 사람이 보낸 사람과 다른가(#1598 평문 머리 `to_peer: true`) — 내 기기가 보낸 내 에이전트의 답을 조용한 줄로
    /// 가르는 데만 쓴다(보낸 쪽이 적는 값).
    pub to_peer: bool,
    /// 글 종류(#1470 평문 머리 `kind`, 꼴만 본 값 — 바깥 머리와 같은 낱말). 옛 판이 보낸 글이면 `None`(여는 쪽이 본문 꼴로
    /// 좁게 짐작한다).
    pub kind: Option<String>,
    /// 반응이 달린 원글 작성자의 사람 주소(#1470 평문 머리 `target_author`, 꼴만 본 값). 옛 판이 보낸 반응이면 `None`.
    pub target_author: Option<String>,
    /// 대화 주소(pair 면 상대 사람 주소, 내 기기 대화면 내 주소, 그룹이면 `+gid@server` — 화면이 여는 값). 모르면 `None`.
    pub conversation: Option<String>,
}

/// 못 연 까닭(로그 이유 칸 — 대화·본문은 싣지 않는다).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// AEAD 가 안 맞음 — 등록이 바뀌어 키가 어긋남(`push key mismatch`).
    KeyMismatch,
    /// 꼴이 틀림(base64·길이·판·MLS 바이트).
    Codec,
    /// 이 기기에 그 그룹이 없다(아직 Welcome 전·다시 들기 중).
    NoGroup,
    /// 응용 메시지가 아니다.
    NotApp,
    /// MLS 가 못 엶(막힘·epoch 지남 등).
    Unreadable(String),
    /// 보낸 기기를 이 기기가 모른다(피어 표에 없음) — 평문은 남겼고(키를 썼다) 앱이 봉투와 다시 견준다.
    UnknownSender,
    /// 저장소 오류.
    Store(String),
}

impl OpenError {
    /// 로그 이유 한 마디.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::KeyMismatch => "push key mismatch",
            Self::Codec => "bad payload",
            Self::NoGroup => "no group",
            Self::NotApp => "not app message",
            Self::Unreadable(_) => "mls unreadable",
            Self::UnknownSender => "unknown sender",
            Self::Store(_) => "store",
        }
    }
}

/// `p` 를 푸시 키로 푼다 → (msg_id, MLS 바이트).
///
/// # Errors
/// [`OpenError::Codec`]·[`OpenError::KeyMismatch`].
pub fn open_sealed(key: &[u8; 32], p: &str) -> Result<(String, Vec<u8>), OpenError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(p)
        .map_err(|_| OpenError::Codec)?;
    if raw.len() < NONCE_LEN + 16 {
        return Err(OpenError::Codec);
    }
    let (n, ct) = raw.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        ChaCha20Poly1305::new(key.into())
            .decrypt(
                Nonce::from_slice(n),
                Payload {
                    msg: ct,
                    aad: SEAL_AAD,
                },
            )
            .map_err(|_| OpenError::KeyMismatch)?,
    );
    let parse = || -> Option<(String, Vec<u8>)> {
        if plain.first() != Some(&SEAL_VERSION) {
            return None;
        }
        let id_len = usize::from(*plain.get(1)?);
        let id = std::str::from_utf8(plain.get(2..2 + id_len)?)
            .ok()?
            .to_owned();
        let at = 2 + id_len;
        let msg_len = usize::from(u16::from_be_bytes([*plain.get(at)?, *plain.get(at + 1)?]));
        Some((id, plain.get(at + 2..at + 2 + msg_len)?.to_vec()))
    };
    parse().ok_or(OpenError::Codec)
}

/// 알림 하나를 연다. `db` 는 relay-client DB(앱과 같은 파일), `store_key` 는 MLS 저장 열쇠(키 저장소), `server` 는 내 relay
/// server 이름. 이미 연 글(같은 알림이 두 번 옴)이면 남긴 평문을 그대로.
///
/// # Errors
/// [`OpenError`].
pub fn open_push(
    db: &Path,
    store_key: &Zeroizing<[u8; 32]>,
    push_key: &[u8; 32],
    p: &str,
    now_secs: u64,
    server: &str,
) -> Result<Opened, OpenError> {
    let (msg_id, bytes) = open_sealed(push_key, p)?;
    let pm = mls::parse(&bytes)
        .map_err(|_| OpenError::Codec)?
        .try_into_protocol_message()
        .map_err(|_| OpenError::Codec)?;
    let gid = pm.group_id().as_slice().to_vec();
    let store = MlsStore::open(db, store_key, Arc::new(lodelai_effects::OsRng))
        .map_err(|e| OpenError::Store(e.to_string()))?;
    let provider = Provider::new(store);
    let st = openmls_traits::OpenMlsProvider::storage(&provider);
    if let Some(t) = st
        .opened(&msg_id)
        .map_err(|e| OpenError::Store(e.to_string()))?
    {
        let sender = st
            .opened_sender(&msg_id)
            .map_err(|e| OpenError::Store(e.to_string()))?
            .unwrap_or_default();
        let text = String::from_utf8(t.to_vec()).map_err(|_| OpenError::Codec)?;
        return checked(db, st.conv(&gid).ok().flatten(), msg_id, gid, &text, sender);
    }
    let mut g = MlsGroup::load(st, &GroupId::from_slice(&gid))
        .ok()
        .flatten()
        .ok_or(OpenError::NoGroup)?;
    let dir = crate::keys::DirView::new(&Value::Null, server);
    let ctx = crate::mls_rules::RuleCtx {
        views: Default::default(),
        dir: &dir,
        members: &[],
        expect_sender: None,
        keep_as: Some(&msg_id),
        push_opened: true,
        group: None,
    };
    // 응용 메시지 처리는 대화 종류를 보지 않는다(Commit 갈래에서만 씀).
    let r = mls::receive(&provider, &mut g, mls::Kind::Pair, &bytes, now_secs, &ctx);
    provider.scrub();
    match r {
        Ok(Received::App { text, sender }) => {
            let text = String::from_utf8(text).map_err(|_| OpenError::Codec)?;
            checked(db, st.conv(&gid).ok().flatten(), msg_id, gid, &text, sender)
        }
        Ok(_) => Err(OpenError::NotApp),
        Err(e) => Err(OpenError::Unreadable(e.to_string())),
    }
}

/// #1023 알림 답장 — `p` 를 푸시 키로만 풀어 (msg_id, MLS 그룹 id). MLS 는 풀지 않는다(키를 쓰지 않음). 둘 다 relay 가 고를
/// 수 있는 값이라 대상은 이 기기가 이미 확인해 둔 글로 정한다([`opened_parties`]·코어 저장소).
///
/// # Errors
/// [`OpenError::Codec`]·[`OpenError::KeyMismatch`].
pub fn sealed_target(push_key: &[u8; 32], p: &str) -> Result<(String, Vec<u8>), OpenError> {
    let (msg_id, bytes) = open_sealed(push_key, p)?;
    let pm = mls::parse(&bytes)
        .map_err(|_| OpenError::Codec)?
        .try_into_protocol_message()
        .map_err(|_| OpenError::Codec)?;
    Ok((msg_id, pm.group_id().as_slice().to_vec()))
}

/// #1023 알림이 이미 연 글(`mls_opened`)의 (대화 주소, 보낸 기기 주인) — 남긴 줄의 그룹이 `gid` 와 같을 때만(relay 가 다른
/// 그룹의 msg_id 를 섞지 못하게). 줄이 없거나(코어가 받아 지웠음·안 열었음) 그룹이 다르거나 대화·보낸 이를 모르면 `None`.
/// 새로 풀지 않는다.
///
/// # Errors
/// 저장소 오류([`OpenError::Store`]).
pub fn opened_parties(
    db: &Path,
    store_key: &Zeroizing<[u8; 32]>,
    msg_id: &str,
    gid: &[u8],
) -> Result<Option<(String, String)>, OpenError> {
    let store = |e: &dyn std::fmt::Display| OpenError::Store(e.to_string());
    let st =
        MlsStore::open(db, store_key, Arc::new(lodelai_effects::OsRng)).map_err(|e| store(&e))?;
    if st.opened(msg_id).map_err(|e| store(&e))?.is_none()
        || st.opened_gid(msg_id).map_err(|e| store(&e))?.as_deref() != Some(gid)
    {
        return Ok(None);
    }
    let Some(conversation) = st.conv(gid).map_err(|e| store(&e))? else {
        return Ok(None);
    };
    let Some(sender) = st.opened_sender(msg_id).map_err(|e| store(&e))? else {
        return Ok(None);
    };
    let user = crate::outbox::Store::open(db)
        .map_err(|e| store(&e))?
        .peer(&sender)
        .map_err(|e| store(&e))?
        .map(|p| p.user);
    Ok(user.map(|u| (conversation, u)))
}

/// 알림 tag 를 이 기기의 대화로 바꾼다(앱이 알림을 눌렀을 때, mobile-host `open_push`). tag 는 relay `push::conv_tag` 와 같은
/// HMAC-SHA256(푸시 등록 salt, 그룹 머리 [`crate::mls_conn::header_of`]) 앞 16 B 소문자 hex 다. 이 기기가 아는 대화 그룹을 다
/// 대어 본다. 등록 전(salt 없음)·맞는 그룹 없음이면 `None`.
///
/// # Errors
/// 큐 파일·MLS 저장을 못 엶([`OpenError::Store`]).
pub fn conversation_of_tag(
    db: &Path,
    store_key: &Zeroizing<[u8; 32]>,
    tag: &str,
) -> Result<Option<String>, OpenError> {
    let salt = crate::outbox::Store::open(db)
        .map_err(|e| OpenError::Store(e.to_string()))?
        .push_salt()
        .map_err(|e| OpenError::Store(e.to_string()))?;
    let Some(salt) = salt else {
        return Ok(None);
    };
    let st = MlsStore::open(db, store_key, Arc::new(lodelai_effects::OsRng))
        .map_err(|e| OpenError::Store(e.to_string()))?;
    let tag = tag.to_ascii_lowercase();
    for gid in st
        .conv_groups()
        .map_err(|e| OpenError::Store(e.to_string()))?
    {
        if conv_tag(&salt, &crate::mls_conn::header_of(&gid)) == tag {
            return st.conv(&gid).map_err(|e| OpenError::Store(e.to_string()));
        }
    }
    Ok(None)
}

/// #1546 [`conversation_of_tag`] 의 거꾸로 — 이 기기 대화들의 알림 tag(relay `push::conv_tag` 와 같은 값). 뒤에서 받은 글의 알림을
/// 푸시 길과 같은 tag 로 띄워(갈아 끼움) 한 대화 알림이 둘로 갈리지 않게. 등록 전(salt 없음)이면 빈 표, 모르는 대화는 빠진다.
///
/// # Errors
/// 큐 파일·MLS 저장을 못 엶([`OpenError::Store`]).
pub fn tags_of_conversations(
    db: &Path,
    store_key: &Zeroizing<[u8; 32]>,
    conversations: &[String],
) -> Result<std::collections::HashMap<String, String>, OpenError> {
    let mut out = std::collections::HashMap::new();
    if conversations.is_empty() {
        return Ok(out);
    }
    let salt = crate::outbox::Store::open(db)
        .map_err(|e| OpenError::Store(e.to_string()))?
        .push_salt()
        .map_err(|e| OpenError::Store(e.to_string()))?;
    let Some(salt) = salt else {
        return Ok(out);
    };
    let st = MlsStore::open(db, store_key, Arc::new(lodelai_effects::OsRng))
        .map_err(|e| OpenError::Store(e.to_string()))?;
    for gid in st
        .conv_groups()
        .map_err(|e| OpenError::Store(e.to_string()))?
    {
        let Some(c) = st.conv(&gid).map_err(|e| OpenError::Store(e.to_string()))? else {
            continue;
        };
        if conversations.contains(&c) {
            out.insert(c, conv_tag(&salt, &crate::mls_conn::header_of(&gid)));
        }
    }
    Ok(out)
}

/// #895 relay `push::account_tag` 의 라벨 — 메시지 푸시마다 실리는 계정 표(`a`) = [`conv_tag`]`(salt, 이 글자)`.
pub const ACCOUNT_LABEL: &str = "lodelai:push-account";

/// #895 이 기기(그 큐 파일)의 계정 표 — relay 가 메시지 푸시에 싣는 `a` 와 같은 값. 푸시 등록 전(salt 없음)이면 `None`.
/// 암호 키 없이 큐 파일의 salt 만 읽는다(알림 확장에서도 가볍게).
///
/// # Errors
/// 큐 파일을 못 엶([`OpenError::Store`]).
pub fn account_tag_of(db: &Path) -> Result<Option<String>, OpenError> {
    let salt = crate::outbox::Store::open(db)
        .map_err(|e| OpenError::Store(e.to_string()))?
        .push_salt()
        .map_err(|e| OpenError::Store(e.to_string()))?;
    Ok(salt.map(|s| conv_tag(&s, ACCOUNT_LABEL)))
}

/// #1546 알림(푸시 열기)이 이미 연 글들의 msg_id — 아직 코어가 받지 않아 남아 있는 줄만. 뒤에서 짧게 붙기 **전에** 떠 두면
/// 붙은 뒤 다시 배달된 글 가운데 「이미 알림이 뜬 글」을 가를 수 있다(코어가 받으면 줄이 지워진다). 암호 키 없이 읽는다
/// (msg_id 칸은 평문). 큐 파일·표가 없으면 빈 목록.
///
/// # Errors
/// 큐 파일을 못 읽음([`OpenError::Store`]).
pub fn opened_ids(db: &Path) -> Result<Vec<String>, OpenError> {
    if !db.exists() {
        return Ok(Vec::new());
    }
    crate::outbox::sqlite_ready();
    let store = |e: rusqlite::Error| OpenError::Store(e.to_string());
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(store)?;
    // 보낸 기기 칸이 있는 줄만 — 푸시가 연 것이다(코어 ack 전에 끊겨 남긴 평문은 그 칸이 비어 있다).
    let Ok(mut st) = c.prepare("SELECT msg_id FROM mls_opened WHERE sender IS NOT NULL") else {
        return Ok(Vec::new());
    };
    let ids = st
        .query_map([], |r| r.get(0))
        .map_err(store)?
        .collect::<rusqlite::Result<Vec<String>>>()
        .map_err(store)?;
    Ok(ids)
}

/// relay `push::conv_tag` 와 같은 값 — HMAC-SHA256(salt, 그룹 머리) 앞 16 B 소문자 hex.
#[must_use]
pub fn conv_tag(salt: &[u8], group: &str) -> String {
    use hmac::Mac as _;
    let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(salt)
        .expect("HMAC 는 어떤 길이의 키도 받는다");
    m.update(group.as_bytes());
    m.finalize().into_bytes()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 평문(§12-17)을 풀고 보낸 기기의 주인을 피어 표(같은 큐 파일)에서 찾는다. 평문에는 보낸 사람이 없고 MLS 자격이 보낸 기기를
/// 증명한다. 봉투 대조(§12-11 ⓔ)는 앱이 다시 받을 때 한다.
fn checked(
    db: &Path,
    conversation: Option<String>,
    msg_id: String,
    gid: Vec<u8>,
    text: &str,
    sender: String,
) -> Result<Opened, OpenError> {
    let (body, files, extra) = crate::mls_conn::split_plaintext(text).ok_or(OpenError::Codec)?;
    let agent = extra
        .get(crate::mls_conn::AGENT_KEY)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let to_agent = extra.get(crate::mls_conn::TO_AGENT_KEY) == Some(&serde_json::Value::Bool(true));
    let to_peer = extra.get(crate::mls_conn::TO_PEER_KEY) == Some(&serde_json::Value::Bool(true));
    let kind = extra
        .get(crate::mls_conn::KIND_KEY)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let target_author = extra
        .get(crate::mls_conn::TARGET_AUTHOR_KEY)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let sender_user = crate::outbox::Store::open(db)
        .map_err(|e| OpenError::Store(e.to_string()))?
        .peer(&sender)
        .map_err(|e| OpenError::Store(e.to_string()))?
        .map(|p| p.user)
        .ok_or(OpenError::UnknownSender)?;
    Ok(Opened {
        msg_id,
        gid,
        body,
        has_files: files.is_some(),
        sender,
        sender_user,
        agent,
        to_agent,
        to_peer,
        kind,
        target_author,
        conversation,
    })
}
