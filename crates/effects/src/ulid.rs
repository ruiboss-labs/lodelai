//! ULID(Crockford base32, 26자) 인코딩. 48비트 밀리초 + 80비트 난수 = 128비트, 첫 글자는 상위 3비트(`0`–`7`).

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 128비트 값을 26자로. `ms` 는 48비트를 넘으면 잘린다.
pub fn encode_ulid(ms: u64, rand80: u128) -> String {
    let value = (u128::from(ms & 0xFFFF_FFFF_FFFF) << 80) | (rand80 & ((1u128 << 80) - 1));
    (0..26)
        .map(|i| {
            let shift = 5 * (25 - i);
            ALPHABET[usize::try_from((value >> shift) & 31).unwrap_or(0)] as char
        })
        .collect()
}

fn digit(c: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|a| *a == c)
        .and_then(|p| u8::try_from(p).ok())
}

/// 26자 ULID 의 상위 48비트(밀리초). 형식이 틀리면 `None`.
pub fn decode_ulid_millis(s: &str) -> Option<u64> {
    if !is_ulid(s) {
        return None;
    }
    let mut value: u128 = 0;
    for b in s.bytes() {
        value = (value << 5) | u128::from(digit(b)?);
    }
    u64::try_from(value >> 80).ok()
}

/// 26자이고 **대문자** Crockford 문자만이며 첫 글자가 `0`–`7` 인가(128비트를 넘지 않는다).
/// 소문자는 같은 ID 의 다른 문자열이 되어 DB 키·중복 검사·서명의 바이트 비교를 깨므로 와이어에서는 거부한다.
pub fn is_ulid(s: &str) -> bool {
    s.len() == 26
        && s.bytes().all(|b| digit(b).is_some())
        && s.as_bytes()
            .first()
            .is_some_and(|b| (b'0'..=b'7').contains(b))
}
