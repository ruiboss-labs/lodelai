//! 원격 relay 연결(#364, m1-spec §17.1): URL 검사와 TLS 설정.
//!
//! - `wss://` 는 어느 호스트든 받는다. 인증서는 일반 검증(rustls + webpki 루트, 암호 공급자 ring).
//! - `ws://` 는 로컬(`127.0.0.1`·`localhost`·`[::1]`)만 — 같은 맥 relay 와 로컬 개발. 평문을 밖으로 보내지 않는다.

use std::sync::{Arc, OnceLock};

use tokio_tungstenite::tungstenite::http::Uri;

use crate::{Error, Result};

/// 연결 대상. `ws_url` 하나에서 HTTP 요청(설정 코드 등록)의 대상도 같이 뽑는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Target {
    /// `Host` 헤더 값. 기본 포트면 포트를 뺀다(relay 는 `<도메인>`·`<도메인>:443` 둘 다 받는다).
    pub fn host_header(&self) -> String {
        match (self.tls, self.port) {
            (true, 443) | (false, 80) => self.host.clone(),
            _ if self.host.contains(':') => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

/// `ws_url` 을 검사한다. `wss://` 는 아무 호스트, `ws://` 는 로컬만.
///
/// # Errors
/// 형식이 틀렸거나 `ws://` 가 로컬이 아니면 [`Error::Relay`].
pub fn target(ws_url: &str) -> Result<Target> {
    let uri: Uri = ws_url
        .parse()
        .map_err(|_| Error::Relay("서버 주소 형식".into()))?;
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => return Err(Error::Relay("서버 주소는 wss:// 만".into())),
    };
    let host = uri
        .host()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| Error::Relay("서버 주소에 호스트가 없다".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if !tls && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Err(Error::Relay("ws:// 는 로컬만 — 서버 주소는 wss://".into()));
    }
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    Ok(Target { tls, host, port })
}

/// 서버 하나를 가리키는 파일 이름 조각 `<호스트 소문자 [a-z0-9.-]>_<포트>`(IPv6 의 `:` 는 `-`)(묶음 4 relay-client 큐 파일, 29 §3 판 기록·§4 키
/// 슬롯이 같이 쓴다). 주소 꼴이 틀리면 `None`. 로컬 relay(원격 주소 없음)는 부르는 쪽이 가른다.
#[must_use]
pub fn server_key(ws_url: &str) -> Option<String> {
    let t = target(ws_url).ok()?;
    let host: String = t
        .host
        .to_ascii_lowercase()
        .chars()
        // IPv6 리터럴의 ':' 는 버리지 않고 '-' 로 — 다른 주소가 한 키로 겹치지 않게(설계 569d815a).
        .map(|c| if c == ':' { '-' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    Some(format!("{host}_{}", t.port))
}

/// rustls 클라이언트 설정(한 번 만들어 같이 쓴다).
pub fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring 은 기본 TLS 판을 지원한다")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

#[cfg(test)]
mod tests {

    #[test]
    fn server_key_is_lowercase_host_and_port() {
        assert_eq!(
            server_key("wss://lodelai-API.Example.com/v1/ws").as_deref(),
            Some("lodelai-api.example.com_443")
        );
        assert_eq!(
            server_key("wss://lodelai.example.com:8443/v1/ws").as_deref(),
            Some("lodelai.example.com_8443")
        );
        assert_eq!(
            server_key("wss://[fd00::1]:8443/v1/ws").as_deref(),
            Some("fd00--1_8443")
        );
        assert_eq!(server_key("http://x").as_deref(), None);
    }

    use super::*;

    #[test]
    fn accepts_wss_and_local_ws_only() {
        let t = target("wss://relay.example.com/v1/ws").unwrap();
        assert_eq!(
            (t.tls, t.host.as_str(), t.port, t.host_header().as_str()),
            (true, "relay.example.com", 443, "relay.example.com")
        );
        let t = target("ws://127.0.0.1:8787/v1/ws").unwrap();
        assert_eq!(
            (t.tls, t.port, t.host_header().as_str()),
            (false, 8787, "127.0.0.1:8787")
        );
        assert_eq!(
            target("ws://[::1]:9/v1/ws").unwrap().host_header(),
            "[::1]:9"
        );
        assert_eq!(
            target("wss://h:8443/v1/ws").unwrap().host_header(),
            "h:8443"
        );
        for bad in [
            "ws://relay.example.com/v1/ws",
            "ws://192.168.0.75:8787/v1/ws",
            "http://relay.example.com",
            "relay.example.com",
            "",
        ] {
            assert!(target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tls_config_builds() {
        let _ = client_config();
    }
}
