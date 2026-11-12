//! 이메일 주소 형식(#339 hosted 가입·#355 초대). relay 와 앱이 같은 규칙을 쓴다.

/// 이메일 정규화: 앞뒤 공백을 빼고 소문자. 3~254자, `@` 하나(앞뒤가 비지 않음). ASCII 만 — 앞부분은 영숫자와
/// RFC 5322 atext 기호(`/` 제외)·`.`, 도메인은 영숫자·`.`·`-`(점·하이픈으로 시작·끝나지 않음). `<`·`>`·`"`·공백·제어
/// 문자를 받지 않는다 — 메일 서비스가 `bob<evil@y.io>` 를 이름 붙은 주소로 읽어 다른 곳으로 보내지 않게(묶음 5 QA).
/// 앞부분 64자 이하, 도메인은 점 하나 이상·라벨마다 1~63자(RFC 5321) — 메일 서비스가 거절할 주소를 먼저 거른다
/// (그러지 않으면 `email_unavailable` 로 보이고 발송 상한을 쓴다, 설계 10-25).
/// 형식만 본다(주소가 실제로 있는지는 코드가 확인한다).
pub fn normalize(s: &str) -> Option<String> {
    let e = s.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    let local_ok = (1..=64).contains(&local.len())
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-=?^_`{|}~.".contains(c));
    let domain_ok = domain.contains('.')
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    ((3..=254).contains(&e.len()) && local_ok && domain_ok).then_some(e)
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn 형식만_본다() {
        assert_eq!(
            normalize("  Dana@Example.COM ").as_deref(),
            Some("dana@example.com")
        );
        assert!(normalize("nobody").is_none());
        assert!(normalize("a@b@c").is_none());
        assert!(normalize("a b@c").is_none());
        assert!(normalize("../x@y").is_none());
        assert_eq!(
            normalize("a.b+tag@mail.x-y.io").as_deref(),
            Some("a.b+tag@mail.x-y.io")
        );
        let l64 = "a".repeat(64);
        assert!(normalize(&format!("{l64}@x.io")).is_some());
        assert!(normalize(&format!("a{l64}@x.io")).is_none());
        let label63 = "b".repeat(63);
        assert!(normalize(&format!("a@{label63}.io")).is_some());
        assert!(normalize(&format!("a@b{label63}.io")).is_none());
        for bad in [
            "bob<evil@y.io>",
            "<evil@y.io>",
            "\"bob\"@y.io",
            "a@b\r\nbcc:c@d",
            "a@-x.io",
            "a@x.io.",
            "a,b@x.io",
            "민지@x.io",
            "a@x\0.io",
            "a@localhost",
            "a@x..io",
            "a@x.-y.io",
        ] {
            assert!(normalize(bad).is_none(), "{bad}");
        }
    }
}
