//! 표시 이름 규칙(#326). relay(등록·`profile.update`)와 코어(`CmdAccountSetup`·`CmdSetDisplayName`)가 같은 함수로 검사한다.
//!
//! 앞뒤 공백을 뺀 뒤 1~[`MAX_CHARS`]자(문자 = Unicode scalar), 제어·bidi·영폭 문자(일반 범주 Cc·Cf·Zl·Zp) 없음.
//! 표시 이름은 신원이 아니다(서명하지 않는 서버 메타데이터) — 이 검사는 화면을 속이는 문자를 막는 방어일 뿐이다.

use unicode_general_category::{get_general_category, GeneralCategory as G};

/// 문자 단위 상한.
pub const MAX_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNameError {
    /// 공백을 빼면 빈 문자열.
    Empty,
    /// [`MAX_CHARS`] 초과.
    TooLong,
    /// 제어·bidi·영폭·줄·문단 구분 문자.
    Forbidden,
}

/// 검사하고 앞뒤 공백을 뺀 값을 돌려준다. 저장·전송은 이 값으로 한다.
///
/// # Errors
/// 규칙 밖이면 [`DisplayNameError`].
pub fn normalize(raw: &str) -> Result<String, DisplayNameError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(DisplayNameError::Empty);
    }
    if s.chars().any(|c| {
        matches!(
            get_general_category(c),
            G::Control | G::Format | G::LineSeparator | G::ParagraphSeparator
        )
    }) {
        return Err(DisplayNameError::Forbidden);
    }
    if s.chars().count() > MAX_CHARS {
        return Err(DisplayNameError::TooLong);
    }
    Ok(s.to_owned())
}

/// 세션 폴더 이름(`session.publish.folder`, m1-spec §2) 검사. [`normalize`] 에 더해 경로 구분자(`/`·`\\`)가
/// 있으면 거부한다 — cwd 마지막 성분만 나가고 전체·홈 경로가 동료에게 새지 않게. relay 가 같은 함수로 검사하고
/// 어긋나면 `session.publish` 전체를 거부하므로, 코어는 보내기 전에 이 함수로 걸러 실패한 필드를 뺀다
/// (맥 폴더 이름엔 `\\` 가 들어갈 수 있다).
///
/// # Errors
/// 규칙 밖이면 [`DisplayNameError`] — 구분자는 [`DisplayNameError::Forbidden`].
pub fn normalize_folder(raw: &str) -> Result<String, DisplayNameError> {
    let s = normalize(raw)?;
    if s.contains(['/', '\\']) {
        return Err(DisplayNameError::Forbidden);
    }
    Ok(s)
}

/// 프로젝트 구분 이름(묶음 23 §5): 성분 하나 이상을 `/` 로 이은 것, 성분마다 [`normalize_folder`], 전체 1~64자. 전체 경로가
/// 아니라 주인 사이드바처럼 겹침을 가르는 데 필요한 부모 성분만 — 빈 성분(`a//b`·앞뒤 `/`)·`.`·`..` 은 거부한다. relay 가
/// 같은 함수로 검사하고 어기면 `session.publish` 전체를 거부한다. 64자를 넘을 때 줄이기(`…/`)는 코어 몫.
///
/// # Errors
/// 규칙 밖이면 [`DisplayNameError`].
pub fn normalize_project_name(raw: &str) -> Result<String, DisplayNameError> {
    let parts = raw
        .split('/')
        .map(|p| match normalize_folder(p)? {
            n if n == "." || n == ".." => Err(DisplayNameError::Forbidden),
            n => Ok(n),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let s = parts.join("/");
    if s.chars().count() > MAX_CHARS {
        return Err(DisplayNameError::TooLong);
    }
    Ok(s)
}

/// 기기 이름(#490 묶음 28 §4 — 그 맥의 컴퓨터 이름): NFC 로 맞춘 뒤 [`normalize`](앞뒤 공백 빼기·1~64자·Cc·Cf·Zl·Zp
/// 없음). 빈 값(공백뿐 포함)은 `Ok(None)` = 지우기. relay(`device.name`)와 앱(보내기 전)이 같은 함수로 검사한다.
///
/// # Errors
/// 규칙 밖이면 [`DisplayNameError`].
pub fn normalize_device_name(raw: &str) -> Result<Option<String>, DisplayNameError> {
    use unicode_normalization::UnicodeNormalization;
    let nfc: String = raw.nfc().collect();
    match normalize(&nfc) {
        Ok(s) => Ok(Some(s)),
        Err(DisplayNameError::Empty) => Ok(None),
        Err(e) => Err(e),
    }
}

/// 맥 컴퓨터 이름 → 보낼 기기 이름(#490 묶음 28 §4, 계약 8cd7072c). 거절하지 않고 다듬는다: NFC → Cc·Cf·Zl·Zp 빼기 →
/// 앞뒤 공백 빼기 → 64자로 자르기 → [`normalize_device_name`] 로 확인. 남는 것이 없으면 `None`(보내지 않음). 앱은 이 값을
/// 내 `DirectoryDevice.name` 과 견주어 다를 때만 보낸다 — relay 와 같은 규칙으로 다듬어야 연결마다 다시 보내지 않는다.
#[must_use]
pub fn device_name_to_send(raw: &str) -> Option<String> {
    use unicode_normalization::UnicodeNormalization;
    let kept: String = raw
        .nfc()
        .filter(|&c| {
            !matches!(
                get_general_category(c),
                G::Control | G::Format | G::LineSeparator | G::ParagraphSeparator
            )
        })
        .collect();
    let cut: String = kept.trim().chars().take(MAX_CHARS).collect();
    normalize_device_name(&cut).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_name_is_nfc_and_rejects_hidden_characters() {
        // 조합형 한글(ᄒ+ᅡ+ᆫ)은 완성형으로.
        assert_eq!(
            normalize_device_name("  \u{1112}\u{1161}\u{11ab} 맥북 ").unwrap(),
            Some("한 맥북".to_owned())
        );
        assert_eq!(normalize_device_name("   ").unwrap(), None, "지우기");
        assert_eq!(normalize_device_name("").unwrap(), None);
        for bad in ["a\u{202e}b", "a\u{200b}b", "a\nb", "a\u{2028}b"] {
            assert_eq!(
                normalize_device_name(bad),
                Err(DisplayNameError::Forbidden),
                "{bad:?}"
            );
        }
        assert_eq!(
            normalize_device_name(&"가".repeat(65)),
            Err(DisplayNameError::TooLong)
        );
        assert!(normalize_device_name(&"가".repeat(64)).is_ok());
    }

    #[test]
    fn device_name_to_send_cleans_instead_of_rejecting() {
        assert_eq!(
            device_name_to_send("  \u{1112}\u{1161}\u{11ab}\u{200b} 맥북\n "),
            Some("한 맥북".to_owned())
        );
        assert_eq!(device_name_to_send(" \u{200b} "), None);
        let long = "가".repeat(80);
        let sent = device_name_to_send(&long).unwrap();
        assert_eq!(sent.chars().count(), MAX_CHARS);
        assert_eq!(
            normalize_device_name(&sent),
            Ok(Some(sent.clone())),
            "relay 가 같은 값으로 받는다"
        );
    }

    #[test]
    fn trims_and_accepts() {
        assert_eq!(normalize("  다나 Kim  ").as_deref(), Ok("다나 Kim"));
        assert_eq!(
            normalize(&"가".repeat(64)).map(|s| s.chars().count()),
            Ok(64)
        );
    }

    #[test]
    fn project_name() {
        assert_eq!(normalize_project_name("api").as_deref(), Ok("api"));
        assert_eq!(
            normalize_project_name("회사/api").as_deref(),
            Ok("회사/api")
        );
        for bad in [
            "",
            "/api",
            "api/",
            "a//b",
            "../api",
            "a/./b",
            "a\\b",
            "a/\u{200b}",
        ] {
            assert!(normalize_project_name(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}/{}", "가".repeat(32), "나".repeat(32));
        assert_eq!(
            normalize_project_name(&long),
            Err(DisplayNameError::TooLong)
        );
        assert!(
            normalize_project_name(&format!("{}/{}", "가".repeat(31), "나".repeat(32))).is_ok()
        );
    }

    #[test]
    fn rejects() {
        assert_eq!(normalize(""), Err(DisplayNameError::Empty));
        assert_eq!(normalize(" \t "), Err(DisplayNameError::Empty));
        assert_eq!(normalize(&"가".repeat(65)), Err(DisplayNameError::TooLong));
        // 제어(줄바꿈은 가운데에 있을 때)·bidi 덮어쓰기·영폭 공백·줄 구분
        for bad in [
            "a\nb",
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{2028}b",
            "a\u{0007}",
        ] {
            assert_eq!(normalize(bad), Err(DisplayNameError::Forbidden), "{bad:?}");
        }
    }

    #[test]
    fn folder_is_one_component() {
        assert_eq!(normalize_folder(" lodelai ").as_deref(), Ok("lodelai"));
        assert_eq!(normalize_folder("a b.c-d").as_deref(), Ok("a b.c-d"));
        for bad in [
            "/home/dana/lodelai",
            "~/lodelai",
            "projects/lodelai",
            "C:\\work",
            "a\\b",
        ] {
            assert_eq!(
                normalize_folder(bad),
                Err(DisplayNameError::Forbidden),
                "{bad:?}"
            );
        }
        assert_eq!(normalize_folder("  "), Err(DisplayNameError::Empty));
    }
}
