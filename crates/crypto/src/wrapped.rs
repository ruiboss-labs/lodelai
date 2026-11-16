//! 감싼 파일 키 저장소 — 플랫폼 키 저장소가 임의 비밀을 직접 담지 못할 때(Android Keystore) 쓴다(모바일 검증, 설계
//! Android 기기 키 판정 (A)).
//!
//! - 기기 비밀(64 B)을 [`Wrapper`] 가 하드웨어 키로 감싸(AES-256-GCM) 앱 전용 폴더의 파일 하나에 둔다. 감싸는 키는 기기
//!   밖으로 나오지 않는다(Android: AndroidKeyStore, StrongBox 가 있으면 그것).
//! - 파일 꼴: 판 1 B ‖ IV 12 B ‖ 암호문(태그 포함). AAD = `"lodelai-key-file"` ‖ 판 ‖ 슬롯 — 다른 슬롯 파일로 바꿔치기해도
//!   풀리지 않는다.
//! - 쓰기는 임시 파일(0600·O_EXCL) → fsync → rename → 폴더 fsync. 반쯤 쓴 파일이 남지 않는다.
//! - 파일이 있는데 풀리지 않으면(감싸는 키를 잃음·키가 영구 무효·태그 틀림·꼴 틀림) [`KeyStoreError::Corrupt`] — `Ok(None)`
//!   이 아니다. `None` 이면 호출자가 새 키를 만들어 조용히 새 신원이 되기 때문이다.
//! - 파일 이름은 슬롯의 16진(슬롯에 `/`·`..` 가 있어도 폴더 밖으로 나가지 않게). 슬롯 목록은 파일 이름으로 — 비밀을 읽지
//!   않는다.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::keys::DeviceSecret;
use crate::keystore::{KeyStore, KeyStoreError};

/// 파일 꼴 판.
const VERSION: u8 = 1;
/// GCM IV 길이(플랫폼이 만든 IV — Android `Cipher.getIV()`).
const IV_LEN: usize = 12;
/// 파일 이름 끝.
const EXT: &str = ".key";

/// 감싸기 실패. 비밀 바이트는 싣지 않는다.
#[derive(Debug, thiserror::Error)]
pub enum WrapError {
    /// 감싸는 키가 없거나 쓸 수 없다(지워짐·영구 무효) — 저장된 파일은 다시 풀 수 없다.
    #[error("감싸는 키를 쓸 수 없다: {0}")]
    KeyUnavailable(String),
    /// 풀기 실패(태그 틀림 등).
    #[error("풀지 못했다")]
    Open,
    /// 플랫폼 호출 실패(일시적일 수 있다).
    #[error("플랫폼 키 저장소 호출 실패: {0}")]
    Backend(String),
}

/// 하드웨어 키로 감싸고 푸는 것. 이음매라 맥에서 흉내로 파일 꼴을 시험한다.
pub trait Wrapper: Send + Sync {
    /// 감싼다 — 플랫폼이 만든 IV 와 암호문(태그 포함).
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<([u8; IV_LEN], Vec<u8>), WrapError>;
    /// 푼다.
    fn open(&self, aad: &[u8], iv: &[u8; IV_LEN], sealed: &[u8]) -> Result<Vec<u8>, WrapError>;
}

/// 감싼 파일 키 저장소.
pub struct WrappedFileStore<W> {
    dir: PathBuf,
    wrapper: W,
}

impl<W: Wrapper> WrappedFileStore<W> {
    /// `dir` 은 앱 전용·백업 제외 폴더(Android `noBackupFilesDir/keys`). 없으면 0700 으로 만든다.
    ///
    /// # Errors
    /// 폴더를 만들 수 없음.
    pub fn new(dir: impl Into<PathBuf>, wrapper: W) -> Result<Self, KeyStoreError> {
        let dir = dir.into();
        create_dir_private(&dir)?;
        Ok(Self { dir, wrapper })
    }

    fn path(&self, slot: &str) -> PathBuf {
        self.dir
            .join(format!("{}{EXT}", hex_encode(slot.as_bytes())))
    }

    fn aad(slot: &str) -> Vec<u8> {
        let mut aad = b"lodelai-key-file".to_vec();
        aad.push(VERSION);
        aad.extend_from_slice(slot.as_bytes());
        aad
    }
}

impl<W: Wrapper> KeyStore for WrappedFileStore<W> {
    fn load(&self, slot: &str) -> Result<Option<DeviceSecret>, KeyStoreError> {
        let Some(bytes) = read_private(&self.path(slot))? else {
            return Ok(None);
        };
        if bytes.len() <= 1 + IV_LEN || bytes[0] != VERSION {
            return Err(KeyStoreError::Corrupt);
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&bytes[1..=IV_LEN]);
        let plain = match self
            .wrapper
            .open(&Self::aad(slot), &iv, &bytes[1 + IV_LEN..])
        {
            Ok(p) => zeroize::Zeroizing::new(p),
            // 파일은 있는데 못 푼다 — 감싸는 키를 잃었든 바뀌었든 새 신원으로 넘어가지 않는다.
            Err(WrapError::KeyUnavailable(_) | WrapError::Open) => {
                return Err(KeyStoreError::Corrupt)
            }
            Err(WrapError::Backend(e)) => return Err(KeyStoreError::Backend(e)),
        };
        DeviceSecret::from_bytes(&plain)
            .map(Some)
            .map_err(|_| KeyStoreError::Corrupt)
    }

    fn store(&self, slot: &str, secret: &DeviceSecret) -> Result<(), KeyStoreError> {
        let plain = secret.to_bytes();
        let (iv, sealed) = self
            .wrapper
            .seal(&Self::aad(slot), &*plain)
            .map_err(|e| KeyStoreError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(1 + IV_LEN + sealed.len());
        out.push(VERSION);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed);
        write_atomic(&self.dir, &self.path(slot), &out)
    }

    fn delete(&self, slot: &str) -> Result<(), KeyStoreError> {
        match fs::remove_file(self.path(slot)) {
            Ok(()) => sync_dir(&self.dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(backend(&e)),
        }
    }

    fn slots(&self) -> Result<Vec<String>, KeyStoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir).map_err(|e| backend(&e))? {
            let name = entry.map_err(|e| backend(&e))?.file_name();
            let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(EXT)) else {
                continue;
            };
            if let Some(slot) = hex_decode(stem).and_then(|b| String::from_utf8(b).ok()) {
                out.push(slot);
            }
        }
        out.sort();
        Ok(out)
    }
}

fn backend(e: &std::io::Error) -> KeyStoreError {
    KeyStoreError::Backend(e.to_string())
}

fn create_dir_private(dir: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| backend(&e))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(|e| backend(&e))
    }
}

/// 키 파일을 읽는다 — 심볼릭 링크는 따라가지 않는다. 없으면 `None`.
fn read_private(path: &Path) -> Result<Option<Vec<u8>>, KeyStoreError> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = match o.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(backend(&e)),
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| backend(&e))?;
    Ok(Some(buf))
}

/// 임시 파일(0600·O_EXCL) → fsync → rename → 폴더 fsync.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let written = (|| {
        let mut f: File = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(backend(&e));
    }
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| backend(&e))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn hex_encode(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(target_os = "android")]
pub mod android;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    use super::*;

    /// 흉내 감싸기: 메모리 키로 AEAD(맥 시험). `lost` 면 감싸는 키를 잃은 것처럼 군다.
    struct Fake {
        key: Mutex<[u8; 32]>,
        lost: AtomicBool,
        n: Mutex<u8>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                key: Mutex::new([7; 32]),
                lost: AtomicBool::new(false),
                n: Mutex::new(0),
            }
        }
    }

    impl Wrapper for Fake {
        fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<([u8; IV_LEN], Vec<u8>), WrapError> {
            let mut n = self.n.lock().unwrap();
            *n += 1;
            let iv = [*n; IV_LEN];
            let c = ChaCha20Poly1305::new(Key::from_slice(&*self.key.lock().unwrap()));
            let ct = c
                .encrypt(Nonce::from_slice(&iv), Payload { msg: plain, aad })
                .map_err(|_| WrapError::Backend("seal".into()))?;
            Ok((iv, ct))
        }

        fn open(&self, aad: &[u8], iv: &[u8; IV_LEN], sealed: &[u8]) -> Result<Vec<u8>, WrapError> {
            if self.lost.load(Ordering::SeqCst) {
                return Err(WrapError::KeyUnavailable("지워짐".into()));
            }
            let c = ChaCha20Poly1305::new(Key::from_slice(&*self.key.lock().unwrap()));
            c.decrypt(Nonce::from_slice(iv), Payload { msg: sealed, aad })
                .map_err(|_| WrapError::Open)
        }
    }

    fn secret(b: u8) -> DeviceSecret {
        DeviceSecret::from_bytes(&[b; 64]).unwrap()
    }

    fn store() -> (tempfile::TempDir, WrappedFileStore<Fake>) {
        let dir = tempfile::tempdir().unwrap();
        let s = WrappedFileStore::new(dir.path().join("keys"), Fake::new()).unwrap();
        (dir, s)
    }

    #[test]
    fn 쓰고_읽고_지운다_슬롯은_파일_이름으로() {
        let (_d, s) = store();
        assert!(s.load("phone@a.test_443").unwrap().is_none());
        s.store("phone@a.test_443", &secret(1)).unwrap();
        s.store("phone@a.test_443.mls-store", &secret(2)).unwrap();
        assert_eq!(
            s.load("phone@a.test_443").unwrap().unwrap().to_bytes()[..],
            [1u8; 64][..]
        );
        assert_eq!(
            s.slots().unwrap(),
            vec!["phone@a.test_443", "phone@a.test_443.mls-store"]
        );
        // 덮어쓰기.
        s.store("phone@a.test_443", &secret(3)).unwrap();
        assert_eq!(
            s.load("phone@a.test_443").unwrap().unwrap().to_bytes()[0],
            3
        );
        s.delete("phone@a.test_443").unwrap();
        s.delete("phone@a.test_443").unwrap();
        assert!(s.load("phone@a.test_443").unwrap().is_none());
        assert_eq!(s.slots().unwrap(), vec!["phone@a.test_443.mls-store"]);
    }

    #[test]
    fn 파일_꼴은_판_iv_암호문이고_비밀이_평문으로_없다() {
        let (d, s) = store();
        s.store("x", &secret(0xAB)).unwrap();
        let path = s.path("x");
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[0], VERSION);
        assert_eq!(bytes.len(), 1 + IV_LEN + 64 + 16);
        assert!(
            !bytes.windows(8).any(|w| w == [0xAB; 8]),
            "평문 비밀이 없다"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(d.path().join("keys"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        // 임시 파일이 남지 않는다.
        assert_eq!(fs::read_dir(d.path().join("keys")).unwrap().count(), 1);
    }

    /// 설계 ③: 파일은 있는데 못 풀면 Corrupt — load_or_create 가 새 키를 만들지 않는다(조용히 새 신원 금지).
    #[test]
    fn 못_풀면_corrupt_이고_새로_만들지_않는다() {
        let (_d, s) = store();
        s.store("x", &secret(1)).unwrap();
        let before = fs::read(s.path("x")).unwrap();
        s.wrapper.lost.store(true, Ordering::SeqCst);
        assert!(matches!(s.load("x"), Err(KeyStoreError::Corrupt)));
        let mut made = false;
        let r = s.load_or_create("x", &mut || {
            made = true;
            secret(9)
        });
        assert!(matches!(r, Err(KeyStoreError::Corrupt)));
        assert!(!made, "새 키를 만들지 않는다");
        assert_eq!(fs::read(s.path("x")).unwrap(), before, "파일을 덮지 않는다");
    }

    /// AAD 에 슬롯이 들어가 다른 슬롯 파일로 바꿔치기하면 풀리지 않는다. 태그·판·길이가 틀려도 Corrupt.
    #[test]
    fn 바꿔치기_변조_판_틀림은_corrupt() {
        let (_d, s) = store();
        s.store("a", &secret(1)).unwrap();
        s.store("b", &secret(2)).unwrap();
        fs::copy(s.path("a"), s.path("b")).unwrap();
        assert!(matches!(s.load("b"), Err(KeyStoreError::Corrupt)));
        let mut bytes = fs::read(s.path("a")).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(s.path("a"), &bytes).unwrap();
        assert!(matches!(s.load("a"), Err(KeyStoreError::Corrupt)));
        fs::write(s.path("a"), [2u8; 40]).unwrap();
        assert!(matches!(s.load("a"), Err(KeyStoreError::Corrupt)));
        fs::write(s.path("a"), [VERSION]).unwrap();
        assert!(matches!(s.load("a"), Err(KeyStoreError::Corrupt)));
    }

    #[cfg(unix)]
    #[test]
    fn 심볼릭_링크_키_파일은_따라가지_않는다() {
        let (d, s) = store();
        s.store("real", &secret(1)).unwrap();
        let outside = d.path().join("outside.key");
        fs::copy(s.path("real"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, s.path("link")).unwrap();
        assert!(matches!(s.load("link"), Err(KeyStoreError::Backend(_))));
    }
}
