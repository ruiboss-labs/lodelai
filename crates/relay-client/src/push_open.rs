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
    let (body, files, _) = crate::mls_conn::split_plaintext(text).ok_or(OpenError::Codec)?;
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
        conversation,
    })
}
