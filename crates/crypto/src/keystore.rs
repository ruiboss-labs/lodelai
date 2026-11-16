//! 비밀키 저장 추상.
//!
//! - [`KeyStore`]: 슬롯 이름 → [`DeviceSecret`]. 슬롯은 호출자가 정한다(M1 은 한 맥에서 앱 프로필 2개를 띄우므로
//!   **프로필 이름이 슬롯**이 되어야 키가 섞이지 않는다. `LODELAI_CHANNEL=dev` 분리는 서비스 이름으로 — `crates/core/src/paths.rs` 와 같은 규칙).
//! - [`MemoryKeyStore`]: 시험·CI 용.
//! - [`macos::KeychainKeyStore`]: macOS Keychain generic password(service = 번들 ID 기반, account = 슬롯).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::keys::DeviceSecret;

/// 저장소 오류. 비밀 바이트는 메시지에 넣지 않는다.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("키 저장소 접근 실패: {0}")]
    Backend(String),
    #[error("저장된 키 형식이 잘못됐다")]
    Corrupt,
}

/// 기기 비밀키 저장소. 구현은 `Send + Sync` 여서 코어·relay 가 `Arc<dyn KeyStore>` 로 든다.
pub trait KeyStore: Send + Sync {
    /// 슬롯의 비밀을 읽는다. 없으면 `Ok(None)`.
    fn load(&self, slot: &str) -> Result<Option<DeviceSecret>, KeyStoreError>;
    /// 슬롯에 비밀을 쓴다(있으면 덮어쓴다).
    fn store(&self, slot: &str, secret: &DeviceSecret) -> Result<(), KeyStoreError>;
    /// 슬롯을 지운다. 없어도 `Ok`.
    fn delete(&self, slot: &str) -> Result<(), KeyStoreError>;
    /// 이 저장소의 슬롯 이름 전부(묶음 29 §4 — 로그아웃 때 목록 파일 밖 슬롯까지 지우려고). **비밀값은 읽지 않는다.**
    fn slots(&self) -> Result<Vec<String>, KeyStoreError>;

    /// 있으면 읽고, 없으면 `make` 가 준 비밀을 저장한 뒤 돌려준다. 첫 실행의 키 생성 경로.
    fn load_or_create(
        &self,
        slot: &str,
        make: &mut dyn FnMut() -> DeviceSecret,
    ) -> Result<DeviceSecret, KeyStoreError> {
        if let Some(s) = self.load(slot)? {
            return Ok(s);
        }
        let s = make();
        self.store(slot, &s)?;
        Ok(s)
    }
}

/// 메모리 저장소(시험·CI).
#[derive(Default)]
pub struct MemoryKeyStore {
    slots: Mutex<HashMap<String, DeviceSecret>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self, slot: &str) -> Result<Option<DeviceSecret>, KeyStoreError> {
        Ok(self.slots.lock().expect("poisoned").get(slot).cloned())
    }

    fn store(&self, slot: &str, secret: &DeviceSecret) -> Result<(), KeyStoreError> {
        self.slots
            .lock()
            .expect("poisoned")
            .insert(slot.to_owned(), secret.clone());
        Ok(())
    }

    fn delete(&self, slot: &str) -> Result<(), KeyStoreError> {
        self.slots.lock().expect("poisoned").remove(slot);
        Ok(())
    }

    fn slots(&self) -> Result<Vec<String>, KeyStoreError> {
        let mut v: Vec<String> = self
            .slots
            .lock()
            .expect("poisoned")
            .keys()
            .cloned()
            .collect();
        v.sort();
        Ok(v)
    }
}

/// 슬롯 열거 결과 한 줄(Keychain 검색 결과를 판정용으로 옮긴 것).
#[derive(Debug)]
pub enum ListedItem {
    /// 속성만(`kSecReturnAttributes`) — 키는 Keychain 속성 이름(`acct` = 슬롯).
    Attrs(HashMap<String, String>),
    /// 속성 사전이 아닌 결과(비밀값 바이트·참조 등). 열거에서는 오면 안 된다.
    NotAttrs,
}

/// Keychain 속성: 계정(= 슬롯 이름).
pub const ATTR_ACCOUNT: &str = "acct";
/// Keychain 값(비밀). 열거 결과에 이 키가 있으면 비밀값을 읽은 것이다.
pub const ATTR_VALUE_DATA: &str = "v_Data";

/// 열거 결과에서 슬롯 이름만 뽑는다. 비밀값이 섞여 오면(값 바이트·`v_Data` 속성) 쓰지 않고 오류 — 열거가 비밀을 읽지 않는
/// 것을 여기서 고정한다(질의를 바꿔 값을 읽게 되면 이 함수가 막는다).
pub fn slot_names(items: Vec<ListedItem>) -> Result<Vec<String>, KeyStoreError> {
    let mut out = Vec::new();
    for item in items {
        let ListedItem::Attrs(attrs) = item else {
            return Err(KeyStoreError::Backend(
                "슬롯 열거에 속성 아닌 결과가 왔다".into(),
            ));
        };
        if attrs.contains_key(ATTR_VALUE_DATA) {
            return Err(KeyStoreError::Backend(
                "슬롯 열거가 비밀값을 받았다 — 쓰지 않는다".into(),
            ));
        }
        if let Some(a) = attrs.get(ATTR_ACCOUNT) {
            out.push(a.clone());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos {
    //! Apple Keychain 구현(macOS·iOS). 앱 전용 접근 그룹·entitlement 는 번들 서명 쪽(U12)에서 붙인다. iOS 는 앱과 알림 확장(NSE)이
    //! 같은 기기 키를 읽어야 해서 [`KeychainKeyStore::with_access_group`] 으로 키체인 access group 을 준다(모바일 검증 — 기기
    //! 비밀키는 App Group 의 Store 파일이 아니라 여기에만 둔다).

    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::base::Error as SfError;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    use security_framework::passwords::{
        delete_generic_password, delete_generic_password_options, generic_password,
        get_generic_password, set_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    use super::{slot_names, KeyStore, KeyStoreError, ListedItem};
    use crate::keys::DeviceSecret;

    /// `errSecItemNotFound`
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    /// `errSecDuplicateItem`
    const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

    /// 기본 서비스 이름. `LODELAI_CHANNEL=dev` 빌드는 [`KeychainKeyStore::new`] 에 `.dev` 를 붙인 이름을 넘긴다.
    pub const DEFAULT_SERVICE: &str = "com.ruiboss.lodelai.device-key";

    pub struct KeychainKeyStore {
        service: String,
        /// 키체인 access group(iOS 앱·NSE 공유). 없으면 앱 기본 그룹.
        access_group: Option<String>,
    }

    impl KeychainKeyStore {
        /// `service` 는 Keychain 항목의 service 속성. 채널(dev/prod)마다 다르게 준다.
        pub fn new(service: impl Into<String>) -> Self {
            Self {
                service: service.into(),
                access_group: None,
            }
        }

        /// 항목을 이 access group 에 두고 거기서 찾는다(iOS 앱·알림 확장이 같은 키를 쓰게 — 그룹은 entitlement 와 짝).
        #[must_use]
        pub fn with_access_group(mut self, group: impl Into<String>) -> Self {
            self.access_group = Some(group.into());
            self
        }

        fn options(&self, slot: &str) -> PasswordOptions {
            let mut o = PasswordOptions::new_generic_password(&self.service, slot);
            if let Some(g) = &self.access_group {
                o.set_access_group(g);
            }
            o
        }

        /// 쓸 때 붙이는 접근 등급: 첫 잠금 해제 뒤에는 잠긴 휴대폰에서도 읽고(알림 확장이 미리보기를 풀 수 있게), 이 기기에만
        /// 둔다(백업·iCloud 키체인으로 기기 키가 복제되지 않게 — ThisDeviceOnly). 설계 조건 ①.
        fn write_options(&self, slot: &str) -> Result<PasswordOptions, KeyStoreError> {
            let mut o = self.options(slot);
            let ac = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                0,
            )
            .map_err(Self::backend)?;
            o.set_access_control(ac);
            Ok(o)
        }

        fn backend(e: SfError) -> KeyStoreError {
            KeyStoreError::Backend(format!("Keychain OSStatus {}", e.code()))
        }
    }

    impl KeyStore for KeychainKeyStore {
        fn load(&self, slot: &str) -> Result<Option<DeviceSecret>, KeyStoreError> {
            let got = if self.access_group.is_some() {
                generic_password(self.options(slot))
            } else {
                get_generic_password(&self.service, slot)
            };
            match got {
                Ok(bytes) => DeviceSecret::from_bytes(&bytes)
                    .map(Some)
                    .map_err(|_| KeyStoreError::Corrupt),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(Self::backend(e)),
            }
        }

        fn store(&self, slot: &str, secret: &DeviceSecret) -> Result<(), KeyStoreError> {
            // iOS 는 그룹을 안 줘도 접근 등급을 건다 — 그룹 없는 항목은 entitlement `keychain-access-groups` 첫 항목(앱·NSE 가
            // 같이 쓰는 공유 그룹)에 들어가고, 잠긴 휴대폰에서 NSE 가 읽으려면 AfterFirstUnlock 이어야 한다(팀 접두사를 앱이
            // 몰라도 되게).
            if self.access_group.is_some() || cfg!(target_os = "ios") {
                let write = |o| set_generic_password_options(&*secret.to_bytes(), o);
                // #849: iOS 는 앱을 지워도 키체인 항목이 남는다. 같은 자리에 접근 등급이 다른 옛 항목이 있으면 중복 갱신이 그
                // 항목을 못 찾아 실패한다(등급을 찾는 조건에 넣은 채 update — 중복·못 찾음). 그때만 옛 항목을 지우고 한 번 다시
                // 쓴다 — 등급도 새 값이 된다. 다른 실패(기기 잠김 -25308 등)는 지우지 않는다: 지우기는 되고 다시 쓰기는 또 실패해
                // 좋은 키를 잃는다(잠긴 휴대폰에서 뒤의 푸시 등록이 키를 쓴다). 처음부터 지우고 쓰지 않는 것은 사이에 끝나면 잃기 때문.
                match write(self.write_options(slot)?) {
                    Ok(()) => Ok(()),
                    Err(e)
                        if matches!(e.code(), ERR_SEC_DUPLICATE_ITEM | ERR_SEC_ITEM_NOT_FOUND) =>
                    {
                        self.delete(slot)?;
                        write(self.write_options(slot)?).map_err(Self::backend)
                    }
                    Err(e) => Err(Self::backend(e)),
                }
            } else {
                set_generic_password(&self.service, slot, &*secret.to_bytes())
                    .map_err(Self::backend)
            }
        }

        fn delete(&self, slot: &str) -> Result<(), KeyStoreError> {
            let gone = if self.access_group.is_some() {
                delete_generic_password_options(self.options(slot))
            } else {
                delete_generic_password(&self.service, slot)
            };
            match gone {
                Ok(()) => Ok(()),
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                Err(e) => Err(Self::backend(e)),
            }
        }

        /// 이 서비스의 generic password 항목을 **속성만** 찾는다(`kSecMatchLimitAll`·`kSecReturnAttributes`,
        /// `kSecReturnData` 없음 — 비밀값은 읽지 않아 키체인 허락 창도 뜨지 않는다). 결과 판정은 [`slot_names`].
        fn slots(&self) -> Result<Vec<String>, KeyStoreError> {
            let mut search = ItemSearchOptions::new();
            search
                .class(ItemClass::generic_password())
                .service(&self.service)
                .load_attributes(true)
                .load_data(false)
                .limit(Limit::All);
            if let Some(g) = &self.access_group {
                search.access_group(g);
            }
            let found = search.search();
            let results = match found {
                Ok(r) => r,
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
                Err(e) => return Err(Self::backend(e)),
            };
            slot_names(
                results
                    .iter()
                    .map(|r| match r {
                        SearchResult::Dict(_) => r
                            .simplify_dict()
                            .map_or(ListedItem::NotAttrs, ListedItem::Attrs),
                        _ => ListedItem::NotAttrs,
                    })
                    .collect(),
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// 실제 Keychain 을 건드린다(로그인 키체인에 항목 생성·삭제). CI(ubuntu)에서는 빌드도 안 되고,
        /// 맥에서도 키체인 프롬프트가 뜰 수 있어 기본은 ignore. `cargo test -p lodelai-crypto -- --ignored` 로.
        #[test]
        #[ignore = "실제 macOS Keychain 사용"]
        fn keychain_round_trip() {
            let store = KeychainKeyStore::new("com.ruiboss.lodelai.device-key.test");
            let slot = "lodelai-crypto-test";
            store.delete(slot).unwrap();
            assert!(store.load(slot).unwrap().is_none());
            let secret = DeviceSecret::from_random(&[5u8; 64]);
            store.store(slot, &secret).unwrap();
            assert_eq!(
                store.load(slot).unwrap().unwrap().to_bytes(),
                secret.to_bytes()
            );
            let secret2 = DeviceSecret::from_random(&[6u8; 64]);
            store.store(slot, &secret2).unwrap();
            assert_eq!(
                store.load(slot).unwrap().unwrap().to_bytes(),
                secret2.to_bytes()
            );
            store.delete(slot).unwrap();
            assert!(store.load(slot).unwrap().is_none());
        }

        /// 없는 항목 지우기는 성공(errSecItemNotFound) — 옮긴 프로필의 '계정 빼기'가 새 서비스에 없는 옛 슬롯을 지울 때(#571 단계 A).
        #[test]
        #[ignore = "실제 macOS Keychain 사용"]
        fn keychain_delete_missing_is_ok() {
            let store = KeychainKeyStore::new("com.ruiboss.lodelai.device-key.test-missing");
            store.delete("없는-슬롯@local").unwrap();
            store.delete("없는-슬롯@local").unwrap();
        }

        /// 실제 Keychain 열거: 슬롯 이름이 나오고(비밀값 없이 — slot_names 가 v_Data 를 막는다), 지우면 사라진다.
        #[test]
        #[ignore = "실제 macOS Keychain 사용"]
        fn keychain_slots_list_names_only() {
            let store = KeychainKeyStore::new("com.ruiboss.lodelai.device-key.test-slots");
            for s in store.slots().unwrap() {
                store.delete(&s).unwrap();
            }
            assert!(store.slots().unwrap().is_empty());
            let secret = DeviceSecret::from_random(&[7u8; 64]);
            store.store("p@a.example", &secret).unwrap();
            store.store("p@b.example:8443", &secret).unwrap();
            assert_eq!(
                store.slots().unwrap(),
                vec!["p@a.example", "p@b.example:8443"]
            );
            for s in store.slots().unwrap() {
                store.delete(&s).unwrap();
            }
            assert!(store.slots().unwrap().is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceKeys;

    #[test]
    fn memory_store_round_trip_and_slots_are_isolated() {
        let store = MemoryKeyStore::new();
        assert!(store.load("a").unwrap().is_none());
        let s = DeviceSecret::from_random(&[1u8; 64]);
        store.store("a", &s).unwrap();
        assert_eq!(store.load("a").unwrap().unwrap().to_bytes(), s.to_bytes());
        assert!(store.load("b").unwrap().is_none());
        store.delete("a").unwrap();
        store.delete("a").unwrap();
        assert!(store.load("a").unwrap().is_none());
    }

    #[test]
    fn load_or_create_creates_once() {
        let store = MemoryKeyStore::new();
        let calls = std::cell::Cell::new(0u8);
        let mut make = || {
            calls.set(calls.get() + 1);
            DeviceSecret::from_random(&[calls.get(); 64])
        };
        let first = store.load_or_create("p1", &mut make).unwrap();
        let second = store.load_or_create("p1", &mut make).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(calls.get(), 1);
        // 두 프로필은 다른 키
        let other = store.load_or_create("p2", &mut make).unwrap();
        assert_ne!(
            DeviceKeys::from_secret(&first).device_id(),
            DeviceKeys::from_secret(&other).device_id()
        );
    }

    #[test]
    fn memory_store_lists_slots() {
        let store = MemoryKeyStore::new();
        let s = DeviceSecret::from_random(&[2u8; 64]);
        store.store("p@b", &s).unwrap();
        store.store("p@a", &s).unwrap();
        assert_eq!(store.slots().unwrap(), vec!["p@a", "p@b"]);
    }

    /// 열거는 비밀값을 받지 않는다 — 값 바이트·`v_Data` 가 섞여 오면 쓰지 않고 오류(묶음 29 §4, 10-28 결정).
    #[test]
    fn slot_names_refuse_secret_values() {
        let attrs = |pairs: &[(&str, &str)]| {
            ListedItem::Attrs(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        };
        assert_eq!(
            slot_names(vec![
                attrs(&[(ATTR_ACCOUNT, "p@b"), ("svce", "x")]),
                attrs(&[(ATTR_ACCOUNT, "p@a")]),
                attrs(&[(ATTR_ACCOUNT, "p@a")]),
                attrs(&[("svce", "계정 없음")]),
            ])
            .unwrap(),
            vec!["p@a", "p@b"]
        );
        assert!(slot_names(vec![attrs(&[
            (ATTR_ACCOUNT, "p@a"),
            (ATTR_VALUE_DATA, "비밀")
        ])])
        .is_err());
        assert!(slot_names(vec![attrs(&[(ATTR_ACCOUNT, "p@a")]), ListedItem::NotAttrs]).is_err());
        assert!(slot_names(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn store_is_object_safe() {
        let _boxed: Box<dyn KeyStore> = Box::new(MemoryKeyStore::new());
    }
}
