//! Windows 감싸기 — DPAPI(`CryptProtectData`, 사용자 범위)로 기기 비밀을 감싼 파일(#1272).
//!
//! - 감싸는 키는 Windows 가 사용자 로그온 비밀에서 꺼낸 DPAPI 마스터 키다. `CRYPTPROTECT_LOCAL_MACHINE` 은 쓰지 않는다
//!   (그 기기의 누구나 푼다). 화면은 띄우지 않는다(`CRYPTPROTECT_UI_FORBIDDEN`).
//! - DPAPI 는 IV 를 받지 않는다 — 파일 꼴의 IV 자리에 난수 12 B 를 두고, 엔트로피 = AAD(슬롯 포함) ‖ IV 로 묶는다. 다른
//!   슬롯 파일로 바꿔치기하거나 IV 를 고치면 풀리지 않는다(→ `Corrupt`).
//! - **같은 사용자로 도는 프로세스는 이 파일을 풀 수 있다**(맥 Keychain 접근 그룹 같은 장치가 없다). 그 길은 정책(#1271 —
//!   키 파일·DPAPI 경로와 명령 거부)과 원격 셸의 주인 승인이 맡는다. 남는 위험은 #1272 판정에 적혀 있다.
//! - 키 폴더·키 파일은 만들 때 보안 설명자를 명시한다: 소유자 = 현재 사용자, DACL = 현재 사용자만 모든 권한, 상속 끊음.
//!   못 만들면 실패한다(Unix 의 0700·0600 대응).

#![allow(unsafe_code)] // Win32(DPAPI·토큰·보안 설명자·CreateFileW) 호출 — 각 블록에 SAFETY 를 적는다.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_INVALID_DATA, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, NTE_BAD_DATA,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroize;

use super::{WrapError, WrappedFileStore, Wrapper, IV_LEN};
use crate::keystore::KeyStoreError;

/// DPAPI 감싸기(사용자 범위).
#[derive(Debug, Default, Clone, Copy)]
pub struct Dpapi;

/// `dir`(앱 데이터 폴더 안의 키 폴더)에 DPAPI 로 감싼 키 파일 저장소를 연다.
///
/// # Errors
/// 키 폴더를 사용자 전용으로 만들 수 없거나, 그 자리가 폴더가 아니거나 재분석 지점이다.
pub fn dpapi_store(dir: impl Into<PathBuf>) -> Result<WrappedFileStore<Dpapi>, KeyStoreError> {
    WrappedFileStore::new(dir, Dpapi)
}

fn entropy(aad: &[u8], iv: &[u8; IV_LEN]) -> Vec<u8> {
    let mut e = Vec::with_capacity(aad.len() + IV_LEN);
    e.extend_from_slice(aad);
    e.extend_from_slice(iv);
    e
}

/// DPAPI 는 입력 블롭을 읽기만 한다(`*mut` 는 C 선언 꼴).
/// DPAPI 입력 블롭. 길이가 `u32` 를 넘으면(4GiB) 잘라 감싸지 않고 `Backend` 오류 — `Wrapper` 는 공용이라 키 크기 밖 입력도 막는다.
fn blob(b: &[u8]) -> Result<CRYPT_INTEGER_BLOB, WrapError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(b.len())
            .map_err(|_| WrapError::Backend("DPAPI 입력이 4GiB 를 넘음".into()))?,
        pbData: b.as_ptr().cast_mut(),
    })
}

/// DPAPI 가 준 버퍼를 복사하고, 지운 뒤 `LocalFree` 한다.
///
/// # Safety
/// `out` 은 성공한 `CryptProtectData`/`CryptUnprotectData` 의 출력이어야 한다.
unsafe fn take(out: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if out.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: 호출자가 보장 — DPAPI 가 `cbData` 바이트를 할당해 돌려줬다.
    let s = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
    let v = s.to_vec();
    s.zeroize();
    // SAFETY: DPAPI 출력은 LocalAlloc 으로 할당된다(문서) — LocalFree 로 놓는다.
    unsafe { LocalFree(out.pbData.cast()) };
    v
}

impl Wrapper for Dpapi {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<([u8; IV_LEN], Vec<u8>), WrapError> {
        let mut iv = [0u8; IV_LEN];
        // SAFETY: iv 는 IV_LEN 바이트 버퍼, 알고리즘 핸들은 시스템 기본 RNG 플래그와 함께 null.
        let st = unsafe {
            BCryptGenRandom(
                null_mut(),
                iv.as_mut_ptr(),
                IV_LEN as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if st < 0 {
            return Err(WrapError::Backend(format!("BCryptGenRandom {st:#x}")));
        }
        let ent = entropy(aad, &iv);
        let (input, ent_blob) = (blob(plain)?, blob(&ent)?);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: 입력·엔트로피 블롭은 살아 있는 슬라이스를 가리키고, out 은 DPAPI 가 채운다.
        let ok = unsafe {
            CryptProtectData(
                &input,
                null(),
                &ent_blob,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(WrapError::Backend(format!(
                "CryptProtectData: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: 위 호출이 성공했다.
        Ok((iv, unsafe { take(&out) }))
    }

    fn open(&self, aad: &[u8], iv: &[u8; IV_LEN], sealed: &[u8]) -> Result<Vec<u8>, WrapError> {
        let ent = entropy(aad, iv);
        let (input, ent_blob) = (blob(sealed)?, blob(&ent)?);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: 위와 같다. 설명 문자열은 받지 않는다(null).
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                &ent_blob,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            // 어느 쪽이든 load() 에서 Corrupt — 새 신원으로 넘어가지 않는다. 원인 코드는 진단용으로 남긴다(비밀 없음):
            // ERROR_INVALID_DATA(엔트로피 틀림 — 실측)·NTE_BAD_DATA(변조) → Open. 그 밖(NTE_BAD_KEY_STATE = 비밀번호 강제 변경으로 마스터 키를 잃음 —
            // 영구, 프로필 미로드 — 일시적 등) → KeyUnavailable(코드).
            let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            if code == ERROR_INVALID_DATA || code == NTE_BAD_DATA as u32 {
                return Err(WrapError::Open);
            }
            return Err(WrapError::KeyUnavailable(format!(
                "CryptUnprotectData {code:#010x}"
            )));
        }
        // SAFETY: 위 호출이 성공했다. 평문 복사본은 호출자가 Zeroizing 으로 든다.
        Ok(unsafe { take(&out) })
    }
}

// ── 사용자 전용 보안 설명자 ───────────────────────────────────────────────

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// 지금 프로세스 토큰의 사용자 SID 문자열(`S-1-5-21-…`).
pub(crate) fn user_sid_string() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: 현재 프로세스 의사 핸들, 성공하면 token 을 아래에서 닫는다.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let r = (|| {
        let mut len = 0u32;
        // SAFETY: 크기만 묻는다(버퍼 null).
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
        // TOKEN_USER 정렬을 맞추려고 u64 버퍼.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: buf 는 len 바이트 이상.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: 성공한 TokenUser 질의의 버퍼 앞머리는 TOKEN_USER 다.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut s: *mut u16 = null_mut();
        // SAFETY: sid 는 buf 안의 유효한 SID, s 는 LocalFree 로 놓는다.
        if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: s 는 0 으로 끝나는 UTF-16 문자열.
        let out = unsafe {
            let mut n = 0;
            while *s.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
        };
        // SAFETY: ConvertSidToStringSidW 의 출력은 LocalFree 로 놓는다.
        unsafe { LocalFree(s.cast()) };
        Ok(out)
    })();
    // SAFETY: 위에서 연 토큰 핸들.
    unsafe { CloseHandle(token) };
    r
}

/// 소유자 = 현재 사용자, DACL = 현재 사용자만 모든 권한, 상속 끊음(`P`). 폴더는 아래로 물려준다(`OICI`).
struct UserOnlySd(PSECURITY_DESCRIPTOR);

impl UserOnlySd {
    fn new(container: bool) -> io::Result<Self> {
        let sid = user_sid_string()?;
        let inherit = if container { "OICI" } else { "" };
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;{inherit};FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: sddl 은 0 으로 끝나고, sd 는 Drop 에서 LocalFree 한다.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for UserOnlySd {
    fn drop(&mut self) {
        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorW 의 출력.
        unsafe { LocalFree(self.0) };
    }
}

fn is_reparse(m: &std::fs::Metadata) -> bool {
    m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// 키 폴더를 사용자 전용 보안 설명자로 만든다(부모는 보통대로). 이미 있으면 그대로 두되, 폴더가 아니거나 재분석
/// 지점(junction·심볼릭 링크)이면 실패 — 다른 자리에 키를 쓰게 되지 않게.
pub(super) fn create_dir_user_only(dir: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if is_reparse(&m) || !m.is_dir() => {
            return Err(io::Error::other(format!(
                "키 폴더 자리가 폴더가 아니거나 재분석 지점이다: {}",
                dir.display()
            )))
        }
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let sd = UserOnlySd::new(true)?;
    let sa = sd.attributes();
    // SAFETY: 경로는 0 으로 끝나고 sa 는 sd 가 사는 동안 쓴다.
    if unsafe { CreateDirectoryW(wide(dir).as_ptr(), &sa) } == 0 {
        let e = io::Error::last_os_error();
        // 다른 쪽이 먼저 만들었다 — 위 검사로 다시 본다(이번엔 있으니 되돌아오지 않는다).
        if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            return match std::fs::symlink_metadata(dir) {
                Ok(m) if !is_reparse(&m) && m.is_dir() => Ok(()),
                _ => Err(e),
            };
        }
        return Err(e);
    }
    Ok(())
}

/// 새 파일을 사용자 전용 보안 설명자로 만든다(있으면 실패 — `O_EXCL` 대응). 공유 모드는 std 와 같다(쓰는 중 rename 가능).
pub(super) fn create_new_user_only(path: &Path) -> io::Result<File> {
    let sd = UserOnlySd::new(false)?;
    let sa = sd.attributes();
    // SAFETY: 경로는 0 으로 끝나고 sa 는 sd 가 사는 동안 쓴다. 성공한 핸들은 File 이 맡는다.
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &sa,
            CREATE_NEW,
            // 자리가 매달린 링크여도 따라가 대상 자리에 만들지 않는다(Unix O_EXCL|O_NOFOLLOW 와 같은 뜻).
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 방금 연 유효한 핸들 — 소유권을 File 로 넘긴다.
    Ok(unsafe { File::from_raw_handle(h) })
}

/// 열린 키 파일이 재분석 지점이면 거부(`FILE_FLAG_OPEN_REPARSE_POINT` 로 연 뒤 — Unix `O_NOFOLLOW` 대응).
pub(super) fn reject_reparse(f: &File) -> io::Result<()> {
    if is_reparse(&f.metadata()?) {
        return Err(io::Error::other("키 파일이 재분석 지점이다"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::windows::process::CommandExt;

    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};

    use super::*;
    use crate::keys::DeviceSecret;
    use crate::keystore::KeyStore;

    fn secret(b: u8) -> DeviceSecret {
        DeviceSecret::from_bytes(&[b; 64]).unwrap()
    }

    fn store() -> (tempfile::TempDir, WrappedFileStore<Dpapi>) {
        let d = tempfile::tempdir().unwrap();
        let s = dpapi_store(d.path().join("keys")).unwrap();
        (d, s)
    }

    /// 경로의 소유자·DACL 을 SDDL 로.
    fn sddl_of(p: &Path) -> String {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // SAFETY: 시험 — 출력 sd 는 LocalFree.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide(p).as_ptr(),
                SE_FILE_OBJECT,
                info,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetNamedSecurityInfoW");
        let mut s: *mut u16 = null_mut();
        // SAFETY: 위와 같다.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                info,
                &mut s,
                null_mut(),
            )
        };
        assert_ne!(ok, 0);
        // SAFETY: 0 으로 끝나는 문자열.
        let out = unsafe {
            let mut n = 0;
            while *s.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(s, n))
        };
        // SAFETY: 위 두 출력.
        unsafe {
            LocalFree(s.cast());
            LocalFree(sd);
        }
        out
    }

    /// 소유자가 사용자이고, DACL 이 상속을 끊고(P) 사용자 하나만 모든 권한인지.
    fn assert_user_only(p: &Path, ace: &str) {
        let sid = user_sid_string().unwrap();
        let s = sddl_of(p);
        assert!(s.starts_with(&format!("O:{sid}D:P")), "{s}");
        let dacl = &s[s.find("D:").unwrap()..];
        assert_eq!(dacl.matches('(').count(), 1, "ACE 는 하나: {s}");
        assert!(dacl.contains(&format!("({ace};FA;;;{sid})")), "{s}");
    }

    #[test]
    fn dpapi_로_쓰고_읽고_덮고_지운다_슬롯은_이름만() {
        let (_d, s) = store();
        assert!(s.load("p@a.test_443").unwrap().is_none());
        s.store("p@a.test_443", &secret(1)).unwrap();
        s.store("p@a.test_443.mls-store", &secret(2)).unwrap();
        assert_eq!(
            s.load("p@a.test_443").unwrap().unwrap().to_bytes()[..],
            [1u8; 64][..]
        );
        assert_eq!(
            s.load("p@a.test_443.mls-store")
                .unwrap()
                .unwrap()
                .to_bytes()[0],
            2
        );
        assert_eq!(
            s.slots().unwrap(),
            vec!["p@a.test_443", "p@a.test_443.mls-store"]
        );
        s.store("p@a.test_443", &secret(3)).unwrap();
        assert_eq!(s.load("p@a.test_443").unwrap().unwrap().to_bytes()[0], 3);
        s.delete("p@a.test_443").unwrap();
        s.delete("p@a.test_443").unwrap();
        assert!(s.load("p@a.test_443").unwrap().is_none());
        assert_eq!(s.slots().unwrap(), vec!["p@a.test_443.mls-store"]);
    }

    #[test]
    fn 파일에_평문이_없고_같은_비밀도_매번_다르게_감싼다() {
        let (d, s) = store();
        s.store("x", &secret(0xAB)).unwrap();
        let a = fs::read(s.path("x")).unwrap();
        assert_eq!(a[0], super::super::VERSION);
        assert!(!a.windows(8).any(|w| w == [0xAB; 8]), "평문 비밀이 없다");
        s.store("x", &secret(0xAB)).unwrap();
        let b = fs::read(s.path("x")).unwrap();
        assert_ne!(a[1..=IV_LEN], b[1..=IV_LEN], "IV 는 난수");
        assert_ne!(a, b);
        // 임시 파일이 남지 않는다.
        assert_eq!(fs::read_dir(d.path().join("keys")).unwrap().count(), 1);
    }

    /// 다른 슬롯 파일로 바꿔치기·IV 변조·몸 변조는 Corrupt 이고, load_or_create 가 새 키를 만들지 않는다.
    #[test]
    fn 바꿔치기_변조는_corrupt_이고_새로_만들지_않는다() {
        let (_d, s) = store();
        s.store("a", &secret(1)).unwrap();
        s.store("b", &secret(2)).unwrap();
        fs::copy(s.path("a"), s.path("b")).unwrap();
        assert!(matches!(s.load("b"), Err(KeyStoreError::Corrupt)));
        let mut made = false;
        let r = s.load_or_create("b", &mut || {
            made = true;
            secret(9)
        });
        assert!(matches!(r, Err(KeyStoreError::Corrupt)));
        assert!(!made, "새 키를 만들지 않는다");

        let good = fs::read(s.path("a")).unwrap();
        let mut iv = good.clone();
        iv[1] ^= 1;
        fs::write(s.path("a"), &iv).unwrap();
        assert!(matches!(s.load("a"), Err(KeyStoreError::Corrupt)));
        let mut body = good.clone();
        let last = body.len() - 1;
        body[last] ^= 1;
        fs::write(s.path("a"), &body).unwrap();
        assert!(matches!(s.load("a"), Err(KeyStoreError::Corrupt)));
        fs::write(s.path("a"), &good).unwrap();
        assert_eq!(s.load("a").unwrap().unwrap().to_bytes()[0], 1);
    }

    /// 판정 조건: 키 폴더·키 파일은 소유자·DACL 을 사용자 전용으로 명시한다(상속 ACE 없음).
    #[test]
    fn 키_폴더와_파일은_사용자_전용_보안_설명자다() {
        let (d, s) = store();
        s.store("x", &secret(1)).unwrap();
        assert_user_only(&d.path().join("keys"), "A;OICI");
        assert_user_only(&s.path("x"), "A;");
        // 덮어쓴 뒤에도(임시 파일 → 바꿔 끼우기) 그대로.
        s.store("x", &secret(2)).unwrap();
        assert_user_only(&s.path("x"), "A;");
    }

    fn junction(link: &Path, target: &Path) {
        let st = std::process::Command::new("cmd")
            .raw_arg(format!(
                "/c mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
    }

    /// 키 폴더 자리가 junction 이면 열지 않는다(다른 폴더에 키를 쓰게 되지 않게).
    #[test]
    fn 키_폴더가_재분석_지점이면_거부() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("elsewhere")).unwrap();
        junction(&d.path().join("keys"), &d.path().join("elsewhere"));
        assert!(matches!(
            dpapi_store(d.path().join("keys")),
            Err(KeyStoreError::Backend(_))
        ));
        // 폴더 자리에 파일이 있어도.
        fs::write(d.path().join("file"), "x").unwrap();
        assert!(dpapi_store(d.path().join("file")).is_err());
    }

    /// 슬롯 파일 자리에 재분석 지점이 있으면 따라가지 않는다(Backend — 없음도 Corrupt 도 아님).
    /// junction 은 폴더라 여기서는 「폴더를 파일로 열기 실패」로 먼저 Backend 가 난다 — 재분석 판정 자체는
    /// `reject_reparse_는_재분석_지점을_거부한다` 가 고정한다(파일 심볼릭 링크는 만들 권한(1314)이 없어 시험 못 함).
    #[test]
    fn 슬롯_파일_자리의_재분석_지점은_따라가지_않는다() {
        let (d, s) = store();
        fs::create_dir(d.path().join("outside")).unwrap();
        junction(&s.path("link"), &d.path().join("outside"));
        assert!(matches!(s.load("link"), Err(KeyStoreError::Backend(_))));
    }

    /// 재분석 지점 자체를 연 핸들이면 거부하고, 보통 파일이면 통과(권한 없이 junction 으로).
    #[test]
    fn reject_reparse_는_재분석_지점을_거부한다() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        let d = tempfile::tempdir().unwrap();
        fs::create_dir(d.path().join("target")).unwrap();
        junction(&d.path().join("j"), &d.path().join("target"));
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(d.path().join("j"))
            .unwrap();
        assert!(reject_reparse(&f).is_err());
        fs::write(d.path().join("plain"), "x").unwrap();
        let f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(d.path().join("plain"))
            .unwrap();
        assert!(reject_reparse(&f).is_ok());
    }

    /// 풀기 실패의 원인 코드: 엔트로피 틀림은 Open, 반쯤 잘린 블롭은 Open 이거나 코드를 담은 KeyUnavailable
    /// — 어느 쪽이든 load() 에선 Corrupt(위 시험). 비밀은 담지 않는다.
    #[test]
    fn 풀기_실패는_원인_코드를_남긴다() {
        let (iv, mut sealed) = Dpapi.seal(b"aad", b"secret").unwrap();
        assert!(matches!(
            Dpapi.open(b"other", &iv, &sealed),
            Err(WrapError::Open)
        ));
        let n = sealed.len();
        sealed.truncate(n / 2);
        match Dpapi.open(b"aad", &iv, &sealed) {
            Err(WrapError::Open) => {}
            Err(WrapError::KeyUnavailable(m)) => {
                assert!(m.starts_with("CryptUnprotectData 0x"), "{m}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// 엔트로피가 다르면(다른 슬롯 AAD) DPAPI 가 풀지 않는다 — 감싸기 단위.
    #[test]
    fn 엔트로피가_다르면_풀리지_않는다() {
        let (iv, sealed) = Dpapi.seal(b"aad-a", b"secret").unwrap();
        assert_eq!(Dpapi.open(b"aad-a", &iv, &sealed).unwrap(), b"secret");
        let r = Dpapi.open(b"aad-b", &iv, &sealed);
        assert!(matches!(r, Err(WrapError::Open)), "{r:?}");
    }
}
