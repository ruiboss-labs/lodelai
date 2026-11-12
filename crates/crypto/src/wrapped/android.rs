//! Android: AndroidKeyStore 의 내보낼 수 없는 AES-256-GCM 키로 감싼다(설계 Android 기기 키 판정 (A)). Kotlin 없이 JNI 로
//! `java.security.KeyStore`·`javax.crypto.Cipher` 를 직접 부른다. JavaVM 은 받은 것을 쥔다 — 앱은 ndk-context(Tauri·tao 가
//! 채움)에서([`AndroidKeystoreWrapper::from_ndk_context`]), 알림 받기(FCM 서비스)는 Tauri 없이 깨므로 JNI 진입의 JNIEnv 에서
//! ([`AndroidKeystoreWrapper::new`]) 받는다(설계 mobile-코어 판정 ④).
//!
//! - 키 별칭 하나([`ALIAS`]). 없으면 만든다 — StrongBox 가 있으면 그것, 없으면(StrongBoxUnavailableException) TEE.
//! - 사용자 인증을 걸지 않는다: 잠긴 화면에서도 알림 받기가 풀어야 한다. 첫 잠금 해제 전(Direct Boot)에는 키를 못 써 알림이
//!   '새 메시지'로만 뜨는 것을 받아들인다(설계 ⑤).
//! - 키가 영구 무효(KeyPermanentlyInvalidatedException)이거나 사라졌으면 [`WrapError::KeyUnavailable`] — 저장소가
//!   `Corrupt` 로 바꾼다(조용히 새 신원 금지).

#![allow(unsafe_code)] // ndk-context 의 원시 JavaVM·Context 포인터를 받는 두 곳뿐.

use jni::objects::{JByteArray, JObject, JValue};
use jni::JNIEnv;

use super::{WrapError, Wrapper, IV_LEN};

/// 감싸기 키 만들기를 한 번에 하나씩 — 처음 store 가 겹쳐 둘 다 '없음'을 보고 만들면 뒤 것이 별칭을 덮어 앞 파일이 영영 안
/// 풀린다(설계 조건). 알림 받기(FCM 서비스)는 같은 프로세스에서 풀기만 하므로 프로세스 안 잠금이면 된다.
static GENERATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// AndroidKeyStore 감싸기 키 별칭.
pub const ALIAS: &str = "lodelai.device-key-wrap";
const PROVIDER: &str = "AndroidKeyStore";
const TRANSFORM: &str = "AES/GCM/NoPadding";
/// `Cipher.ENCRYPT_MODE`·`DECRYPT_MODE`.
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;
/// `KeyProperties.PURPOSE_ENCRYPT | PURPOSE_DECRYPT`.
const PURPOSES: i32 = 1 | 2;

/// AndroidKeyStore 감싸기(쥔 JavaVM 으로 부른다).
pub struct AndroidKeystoreWrapper {
    vm: jni::JavaVM,
}

impl AndroidKeystoreWrapper {
    /// 받은 JavaVM 으로(JNI 진입에서 `env.get_java_vm()`).
    #[must_use]
    pub fn new(vm: jni::JavaVM) -> Self {
        Self { vm }
    }

    /// ndk-context 의 JavaVM 으로(Tauri 앱 안).
    ///
    /// # Errors
    /// JavaVM 을 못 받음.
    pub fn from_ndk_context() -> Result<Self, WrapError> {
        let ctx = ndk_context::android_context();
        // SAFETY: ndk-context 는 앱 기동 때 Tauri(tao)가 넣은 살아 있는 JavaVM 포인터를 준다. 프로세스 동안 유효하다.
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| WrapError::Backend(format!("JavaVM: {e}")))?;
        Ok(Self { vm })
    }

    fn with_env<T>(
        &self,
        f: impl FnOnce(&mut JNIEnv) -> Result<T, WrapError>,
    ) -> Result<T, WrapError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| WrapError::Backend(format!("JNI 붙기: {e}")))?;
        let r = f(&mut env);
        // 던져진 자바 예외가 남아 있으면 지운다(다음 JNI 호출이 막히지 않게). 내용은 이미 오류로 바꿨다.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        r
    }
}

/// 자바 예외를 꺼내 이름으로 가른다. 예외가 없으면 `None`.
fn take_exception(env: &mut JNIEnv) -> Option<String> {
    if !env.exception_check().unwrap_or(false) {
        return None;
    }
    let ex = env.exception_occurred().ok()?;
    let _ = env.exception_clear();
    let class = env
        .call_method(&ex, "getClass", "()Ljava/lang/Class;", &[])
        .and_then(|c| c.l())
        .and_then(|c| env.call_method(&c, "getName", "()Ljava/lang/String;", &[]))
        .and_then(|n| n.l())
        .ok()?;
    let name: String = env.get_string(&class.into()).ok()?.into();
    Some(name)
}

/// JNI 호출 결과를 오류로. 키가 사라졌거나 영구 무효면 [`WrapError::KeyUnavailable`], 태그 틀림은 [`WrapError::Open`].
fn check<T>(env: &mut JNIEnv, r: jni::errors::Result<T>, what: &str) -> Result<T, WrapError> {
    match r {
        Ok(v) if !env.exception_check().unwrap_or(false) => Ok(v),
        Ok(_) | Err(_) => {
            let name = take_exception(env).unwrap_or_else(|| "?".into());
            Err(
                if name.ends_with("KeyPermanentlyInvalidatedException")
                    || name.ends_with("UnrecoverableKeyException")
                {
                    WrapError::KeyUnavailable(name)
                } else if name.ends_with("AEADBadTagException") {
                    WrapError::Open
                } else {
                    WrapError::Backend(format!("{what}: {name}"))
                },
            )
        }
    }
}

fn jstr<'a>(env: &mut JNIEnv<'a>, s: &str) -> Result<JObject<'a>, WrapError> {
    env.new_string(s)
        .map(JObject::from)
        .map_err(|e| WrapError::Backend(e.to_string()))
}

fn bytes<'a>(env: &mut JNIEnv<'a>, b: &[u8]) -> Result<JObject<'a>, WrapError> {
    env.byte_array_from_slice(b)
        .map(JObject::from)
        .map_err(|e| WrapError::Backend(e.to_string()))
}

/// 감싸기 키(`SecretKey`). `create` 면 없을 때 만든다.
fn wrap_key<'a>(env: &mut JNIEnv<'a>, create: bool) -> Result<JObject<'a>, WrapError> {
    let provider = jstr(env, PROVIDER)?;
    let r = env.call_static_method(
        "java/security/KeyStore",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        &[JValue::Object(&provider)],
    );
    let ks = check(env, r.and_then(|v| v.l()), "KeyStore.getInstance")?;
    let r = env.call_method(
        &ks,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    );
    check(env, r, "KeyStore.load")?;
    let alias = jstr(env, ALIAS)?;
    if !contains(env, &ks, &alias)? {
        if !create {
            return Err(WrapError::KeyUnavailable("감싸기 키 없음".into()));
        }
        let _one = GENERATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 잠근 채 다시 본다 — 기다리는 동안 다른 쪽이 만들었으면 그 키를 쓴다.
        if !contains(env, &ks, &alias)? {
            // StrongBox 먼저, 없으면 TEE. 어느 쪽인지 logcat 에 한 줄(실기 판정).
            let at = if generate(env, true).is_ok() {
                "StrongBox"
            } else {
                generate(env, false)?;
                "TEE"
            };
            log_info(env, &format!("기기 키 감싸기 키를 만듦 — {at}"));
        }
    }
    let r = env.call_method(
        &ks,
        "getKey",
        "(Ljava/lang/String;[C)Ljava/security/Key;",
        &[JValue::Object(&alias), JValue::Object(&JObject::null())],
    );
    let key = check(env, r.and_then(|v| v.l()), "getKey")?;
    if key.is_null() {
        return Err(WrapError::KeyUnavailable("getKey null".into()));
    }
    Ok(key)
}

fn contains(env: &mut JNIEnv, ks: &JObject, alias: &JObject) -> Result<bool, WrapError> {
    let r = env.call_method(
        ks,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(alias)],
    );
    check(env, r.and_then(|v| v.z()), "containsAlias")
}

/// logcat 한 줄(`android.util.Log.i("lodelai", …)`) — Rust stderr 는 logcat 에 안 나온다. 실패해도 넘어간다.
fn log_info(env: &mut JNIEnv, msg: &str) {
    let (Ok(tag), Ok(m)) = (jstr(env, "lodelai"), jstr(env, msg)) else {
        return;
    };
    let r = env.call_static_method(
        "android/util/Log",
        "i",
        "(Ljava/lang/String;Ljava/lang/String;)I",
        &[JValue::Object(&tag), JValue::Object(&m)],
    );
    let _ = check(env, r, "Log.i");
}

/// `KeyGenParameterSpec`(GCM·NoPadding·256, 인증 없음, 무작위 IV 강제)로 AES 키를 만든다.
fn generate(env: &mut JNIEnv, strongbox: bool) -> Result<(), WrapError> {
    let alias = jstr(env, ALIAS)?;
    let r = env.new_object(
        "android/security/keystore/KeyGenParameterSpec$Builder",
        "(Ljava/lang/String;I)V",
        &[JValue::Object(&alias), JValue::Int(PURPOSES)],
    );
    let builder = check(env, r, "KeyGenParameterSpec.Builder")?;
    let gcm = jstr(env, "GCM")?;
    let modes = env
        .new_object_array(1, "java/lang/String", &gcm)
        .map_err(|e| WrapError::Backend(e.to_string()))?;
    let r = env.call_method(
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&modes)],
    );
    check(env, r, "setBlockModes")?;
    let none = jstr(env, "NoPadding")?;
    let paddings = env
        .new_object_array(1, "java/lang/String", &none)
        .map_err(|e| WrapError::Backend(e.to_string()))?;
    let r = env.call_method(
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&paddings)],
    );
    check(env, r, "setEncryptionPaddings")?;
    let r = env.call_method(
        &builder,
        "setKeySize",
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(256)],
    );
    check(env, r, "setKeySize")?;
    if strongbox {
        let r = env.call_method(
            &builder,
            "setIsStrongBoxBacked",
            "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
            &[JValue::Bool(1)],
        );
        check(env, r, "setIsStrongBoxBacked")?;
    }
    let r = env.call_method(
        &builder,
        "build",
        "()Landroid/security/keystore/KeyGenParameterSpec;",
        &[],
    );
    let spec = check(env, r.and_then(|v| v.l()), "build")?;
    let (aes, provider) = (jstr(env, "AES")?, jstr(env, PROVIDER)?);
    let r = env.call_static_method(
        "javax/crypto/KeyGenerator",
        "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
        &[JValue::Object(&aes), JValue::Object(&provider)],
    );
    let kg = check(env, r.and_then(|v| v.l()), "KeyGenerator.getInstance")?;
    let r = env.call_method(
        &kg,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    );
    check(env, r, "KeyGenerator.init")?;
    let r = env.call_method(&kg, "generateKey", "()Ljavax/crypto/SecretKey;", &[]);
    check(env, r, "generateKey").map(|_| ())
}

fn cipher<'a>(env: &mut JNIEnv<'a>) -> Result<JObject<'a>, WrapError> {
    let t = jstr(env, TRANSFORM)?;
    let r = env.call_static_method(
        "javax/crypto/Cipher",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&t)],
    );
    check(env, r.and_then(|v| v.l()), "Cipher.getInstance")
}

fn update_aad(env: &mut JNIEnv, c: &JObject, aad: &[u8]) -> Result<(), WrapError> {
    let a = bytes(env, aad)?;
    let r = env.call_method(c, "updateAAD", "([B)V", &[JValue::Object(&a)]);
    check(env, r, "updateAAD").map(|_| ())
}

fn do_final(env: &mut JNIEnv, c: &JObject, input: &[u8]) -> Result<Vec<u8>, WrapError> {
    let i = bytes(env, input)?;
    let r = env.call_method(c, "doFinal", "([B)[B", &[JValue::Object(&i)]);
    let out = check(env, r.and_then(|v| v.l()), "doFinal")?;
    env.convert_byte_array(JByteArray::from(out))
        .map_err(|e| WrapError::Backend(e.to_string()))
}

impl Wrapper for AndroidKeystoreWrapper {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<([u8; IV_LEN], Vec<u8>), WrapError> {
        self.with_env(|env| {
            let key = wrap_key(env, true)?;
            let c = cipher(env)?;
            // IV 는 플랫폼이 만든다(AndroidKeyStore 는 호출자 IV 를 거절 — 무작위 IV 강제).
            let r = env.call_method(
                &c,
                "init",
                "(ILjava/security/Key;)V",
                &[JValue::Int(ENCRYPT_MODE), JValue::Object(&key)],
            );
            check(env, r, "Cipher.init(ENCRYPT)")?;
            update_aad(env, &c, aad)?;
            let sealed = do_final(env, &c, plain)?;
            let r = env.call_method(&c, "getIV", "()[B", &[]);
            let iv = check(env, r.and_then(|v| v.l()), "getIV")?;
            let iv = env
                .convert_byte_array(JByteArray::from(iv))
                .map_err(|e| WrapError::Backend(e.to_string()))?;
            let iv: [u8; IV_LEN] = iv
                .try_into()
                .map_err(|_| WrapError::Backend("IV 길이".into()))?;
            Ok((iv, sealed))
        })
    }

    fn open(&self, aad: &[u8], iv: &[u8; IV_LEN], sealed: &[u8]) -> Result<Vec<u8>, WrapError> {
        self.with_env(|env| {
            // 키가 없으면 만들지 않는다 — 파일이 있는데 키가 사라졌다는 뜻이다.
            let key = wrap_key(env, false)?;
            let c = cipher(env)?;
            let ivb = bytes(env, iv)?;
            let r = env.new_object(
                "javax/crypto/spec/GCMParameterSpec",
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&ivb)],
            );
            let spec = check(env, r, "GCMParameterSpec")?;
            let r = env.call_method(
                &c,
                "init",
                "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
                &[
                    JValue::Int(DECRYPT_MODE),
                    JValue::Object(&key),
                    JValue::Object(&spec),
                ],
            );
            check(env, r, "Cipher.init(DECRYPT)")?;
            update_aad(env, &c, aad)?;
            do_final(env, &c, sealed)
        })
    }
}

/// 앱 전용·백업 제외 폴더(`Context.getNoBackupFilesDir()`) — 기기 키 파일·데이터 폴더를 둘 곳. 자동 백업·기기 이전에 실리지
/// 않는다(설계 mobile-코어 판정 ④ — 앱 데이터도 `<여기>/lodelai`).
///
/// # Errors
/// JNI 호출 실패.
pub fn no_backup_dir(env: &mut JNIEnv, context: &JObject) -> Result<std::path::PathBuf, WrapError> {
    let r = env.call_method(context, "getNoBackupFilesDir", "()Ljava/io/File;", &[]);
    let dir = check(env, r.and_then(|v| v.l()), "getNoBackupFilesDir")?;
    let r = env.call_method(&dir, "getAbsolutePath", "()Ljava/lang/String;", &[]);
    let path = check(env, r.and_then(|v| v.l()), "getAbsolutePath")?;
    let path: String = env
        .get_string(&path.into())
        .map_err(|e| WrapError::Backend(e.to_string()))?
        .into();
    Ok(std::path::PathBuf::from(path))
}

/// [`no_backup_dir`] 를 ndk-context 의 Context 로(Tauri 앱 안).
///
/// # Errors
/// JNI 호출 실패.
pub fn ndk_no_backup_dir() -> Result<std::path::PathBuf, WrapError> {
    AndroidKeystoreWrapper::from_ndk_context()?.with_env(|env| {
        let ctx = ndk_context::android_context();
        // SAFETY: ndk-context 의 Context 는 앱 기동 때 Tauri(tao)가 넣은 전역 참조다. 프로세스 동안 유효하다.
        let context = unsafe { JObject::from_raw(ctx.context().cast()) };
        // `JObject` 는 Drop 이 없어 이 래퍼가 끝나도 전역 참조는 그대로 남는다.
        no_backup_dir(env, &context)
    })
}

/// logcat 한 줄(태그 `lodelai`) — JNI 진입(알림 받기)이 못 연 이유를 남길 때.
pub fn log_line(env: &mut JNIEnv, msg: &str) {
    log_info(env, msg);
}
