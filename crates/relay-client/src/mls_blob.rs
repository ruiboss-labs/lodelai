//! 큰 Handshake 의 blob 길(묶음 22 §5c). group Handshake 메시지(JSON)가 `Config::mls_inline_max` 를 넘으면 칸(payload·
//! welcome·group_info) 중 큰 것부터 ADR 0009 blob 으로 옮기고(MLS 바이트 그대로 — 따로 암호화하지 않음) 다시 잰다. 받는 쪽은
//! `{blob_id, size, sha256}` 을 받아 크기·해시를 맞춘 뒤 `data` 로 채워 평소 길로 처리한다. pair·self 는 측정상 넘지 않아 이
//! 길을 쓰지 않는다(§5c 실측 — 잎 50 이하는 모두 프레임 안).

use lodelai_crypto::encoding;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::files::{ask, Ctx, Stop};

/// blob 으로 옮길 수 있는 칸.
const FIELDS: [&str; 3] = ["payload", "welcome", "group_info"];

/// 메시지(JSON)가 상한을 넘나.
#[must_use]
pub fn oversize(message: &Value, max: usize) -> bool {
    message.to_string().len() > max
}

/// 서명한 `send` 프레임의 메시지가 상한을 넘으면 서명을 뗀 메시지(JSON 글)를 돌려준다 — 행을 `mls_blob` 으로 바꿀 때.
#[must_use]
pub fn unsigned_if_oversize(frame: &str, max: usize) -> Option<String> {
    let v: Value = serde_json::from_str(frame).ok()?;
    let mut m = v.get("message")?.clone();
    if !oversize(&m, max) {
        return None;
    }
    if let Some(o) = m.as_object_mut() {
        o.remove("sig");
    }
    Some(m.to_string())
}

/// 메시지에 blob 칸이 있나(받는 쪽).
#[must_use]
pub fn has_blobs(message: &Value) -> bool {
    FIELDS
        .iter()
        .any(|f| message.pointer(&format!("/body/{f}/blob")).is_some())
}

fn sha_b64(bytes: &[u8]) -> String {
    encoding::encode(&Sha256::digest(bytes))
}

/// `mls_blob` 행 하나를 올린다: 큰 칸부터 blob 으로 옮기며 상한 아래가 될 때까지 → 서명 → `send` 로. 성공이면 `true`. 실패면
/// `false` — 행은 그대로 두고 호출자(연결 루프)가 쥔 Commit 을 버리고 다시 봉인한다.
pub async fn upload(c: Ctx, seq: i64, max: usize) -> bool {
    let Ok(Some(spec)) = c.store.upload_spec(seq) else {
        return false;
    };
    let Ok(mut m) = serde_json::from_str::<Value>(&spec) else {
        return false;
    };
    while oversize(&m, max) {
        // 아직 data 인 칸 중 가장 큰 것.
        let Some((field, data)) = FIELDS
            .iter()
            .filter_map(|f| {
                let d = m.pointer(&format!("/body/{f}/data"))?.as_str()?;
                Some((*f, d.to_owned()))
            })
            .max_by_key(|(_, d)| d.len())
        else {
            tracing::warn!(seq, "blob 으로 옮겨도 상한을 넘는다");
            return false;
        };
        let Ok(bytes) = encoding::decode(&data, "mls") else {
            return false;
        };
        let Ok((blob_id, token)) = ask(&c, 'u', |req| {
            json!({"t": "blob.reserve", "req": req, "ct_len": bytes.len(), "purpose": "message"})
        })
        .await
        else {
            return false;
        };
        match crate::blobio::put_bytes(&c.target, &blob_id, &token, &bytes).await {
            Ok(204) => {}
            other => {
                tracing::info!(?other, "Handshake blob PUT 실패");
                return false;
            }
        }
        m["body"][field] =
            json!({"blob": {"blob_id": blob_id, "size": bytes.len(), "sha256": sha_b64(&bytes)}});
    }
    let Some(frame) = crate::mls_conn::sign_frame(&c.keys, m) else {
        return false;
    };
    if frame.len() > lodelai_protocol::constants::WS_MAX_FRAME_BYTES as usize {
        return false;
    }
    c.store.promote_mls_blob(seq, &frame).unwrap_or(false)
}

/// 받은 메시지·프레임의 blob 칸을 받아 `data` 로 채운다(크기·SHA-256 을 맞춤). `root` 는 칸이 있는 곳(`/body` 또는 `""` —
/// `group_info` 프레임). 받지 못했거나 어긋나면 `None`.
pub async fn fill(c: Ctx, mut v: Value, root: &str) -> Option<Value> {
    for f in FIELDS {
        let Some(b) = v.pointer(&format!("{root}/{f}/blob")).cloned() else {
            continue;
        };
        let (Some(blob_id), Some(size), Some(sha)) = (
            b.get("blob_id").and_then(Value::as_str),
            b.get("size").and_then(Value::as_u64),
            b.get("sha256").and_then(Value::as_str),
        ) else {
            return None;
        };
        let token = match ask(
            &c,
            'd',
            |req| json!({"t": "blob.get", "req": req, "blob_id": blob_id}),
        )
        .await
        {
            Ok((_, t)) => t,
            Err(Stop::Refused(code)) => {
                tracing::info!(code, "Handshake blob 표 거절");
                return None;
            }
            Err(_) => return None,
        };
        let bytes = match crate::blobio::get_bytes(&c.target, blob_id, &token, size).await {
            Ok(Ok(b)) => b,
            other => {
                tracing::info!(ok = other.is_ok(), "Handshake blob GET 실패");
                return None;
            }
        };
        if bytes.len() as u64 != size || sha_b64(&bytes) != sha {
            tracing::warn!("Handshake blob 크기·해시가 다르다 — 버림");
            return None;
        }
        let at = if root.is_empty() {
            &mut v
        } else {
            v.pointer_mut(root)?
        };
        at[f] = json!({"data": encoding::encode(&bytes)});
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 상한을_넘을_때만_서명을_떼어_돌려준다() {
        let m = json!({"msg_id": "x", "sig": "s", "body": {"payload": {"data": "a".repeat(100)}}});
        let frame = json!({"t": "send", "message": m}).to_string();
        assert_eq!(unsigned_if_oversize(&frame, 10_000), None);
        let u: Value = serde_json::from_str(&unsigned_if_oversize(&frame, 50).unwrap()).unwrap();
        assert!(u.get("sig").is_none());
        assert_eq!(u["body"]["payload"]["data"], m["body"]["payload"]["data"]);
    }

    #[test]
    fn blob_payload_의_commit_hash_는_그_sha256() {
        let bytes = b"commit bytes";
        let frame = json!({"t": "send", "message": {"body": {"payload": {"blob": {
            "blob_id": "AAAAAAAAAAAAAAAAAAAAAA", "size": bytes.len(), "sha256": sha_b64(bytes)}}}}})
        .to_string();
        assert_eq!(
            crate::mls_conn::frame_commit_hash(&frame),
            Some(crate::mls::commit_hash(bytes))
        );
        assert!(has_blobs(
            &serde_json::from_str::<Value>(&frame).unwrap()["message"]
        ));
    }
}
