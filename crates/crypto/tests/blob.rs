//! 첨부 blob 교차 검증 벡터(묶음 15 §1, ADR 0009 §2).
//!
//! `packages/protocol/fixtures/e2e/blob-vectors.json` 과 같아야 한다. 다시 만들려면
//! `LODELAI_REGEN_E2E_VECTORS=1 cargo test -p lodelai-crypto --test blob` — TS 독립 구현(`packages/protocol/src/blob.test.ts`)이
//! libsodium 조각 단위 암호화로 같은 바이트를 만들고 연다. 큰 경우는 암호문 대신 길이·SHA-256 만 싣는다.

use lodelai_crypto::blob::{blob_ct_len, open_blob, seal_blob, CHUNK};
use serde_json::{json, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

/// 평문 n 바이트: i mod 251.
fn plain(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packages/protocol/fixtures/e2e/blob-vectors.json"
);

fn vectors() -> Value {
    let fk = seq::<32>(0x10);
    let prefix = seq::<19>(0x60);
    let blob_id = "b_AAECAwQFBgcICQoLDA0ODw";
    let cases: Vec<Value> = [0usize, 1, 100, CHUNK, CHUNK + 1, 3 * CHUNK + 7]
        .iter()
        .map(|&n| {
            let mut ct = Vec::new();
            let (len, sha) =
                seal_blob(&fk, &prefix, blob_id, plain(n).as_slice(), &mut ct).unwrap();
            assert_eq!(len, blob_ct_len(n as u64));
            let mut c = json!({"n": n, "ct_len": len, "ct_sha256": hex(&sha)});
            if n <= 100 {
                c["ct"] = json!(hex(&ct));
            }
            c
        })
        .collect();
    json!({
        "about": "첨부 blob 교차 검증 벡터(묶음 15 §1, ADR 0009 §2). crates/crypto tests/blob.rs 가 만든다(LODELAI_REGEN_E2E_VECTORS=1). 평문 n 바이트 = i mod 251. TS packages/protocol/src/blob.test.ts 가 같은 바이트를 다시 만든다.",
        "fk": hex(&fk),
        "prefix": hex(&prefix),
        "blob_id": blob_id,
        "chunk": CHUNK,
        "cases": cases,
    })
}

#[test]
fn 교차_검증_벡터는_픽스처와_같고_열린다() {
    let v = vectors();
    if std::env::var_os("LODELAI_REGEN_E2E_VECTORS").is_some() {
        std::fs::write(
            FIXTURE,
            format!("{}\n", serde_json::to_string_pretty(&v).unwrap()),
        )
        .unwrap();
    }
    let on_disk: Value = serde_json::from_str(
        &std::fs::read_to_string(FIXTURE)
            .expect("픽스처 없음 — LODELAI_REGEN_E2E_VECTORS=1 로 만든다"),
    )
    .unwrap();
    assert_eq!(
        on_disk, v,
        "blob 구성이 바뀌었다 — 의도했다면 다시 만들고 TS 교차 시험을 돌린다"
    );
    // 다른 FK 로는 열리지 않는다.
    let mut ct = Vec::new();
    let (_, sha) = seal_blob(&seq(0x10), &seq(0x60), "b_x", plain(10).as_slice(), &mut ct).unwrap();
    let mut out = Vec::new();
    assert!(open_blob(&seq(0x11), &seq(0x60), "b_x", ct.as_slice(), &sha, &mut out).is_err());
}
