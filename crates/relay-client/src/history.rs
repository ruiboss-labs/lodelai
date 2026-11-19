//! #881 새 기기에 지난 대화 옮기기(ADR 0015) — offer 를 봉하고 여는 곳.
//!
//! 기기 비밀키(서명·X25519)와 신뢰 사슬(devcert·`roots_in`)이 여기 있어 코어가 아니라 relay-client 가 한다. 코어는 묶음
//! 키를 주고 봉한 표·서명을 받거나, 받은 offer 를 주고 묶음 키를 받는다.
//!
//! 상대 기기의 키는 **신뢰 사슬로 확인한 디렉터리 항목**에서만 꺼낸다([`RelayClient::own_confirmed`]) — relay 가 붙인
//! `from_device` 나 피어 표의 키를 그대로 믿지 않는다.

use lodelai_crypto::encoding::{decode, encode};
use lodelai_crypto::history as h;
use lodelai_crypto::{DeviceKeys, VerifyingKey};
use zeroize::Zeroizing;

use crate::mls_rules::{self, DirDevice, Directory};
use crate::{keys, RelayClient};

/// 봉한 offer — `history_offer` 의 `ticket`·`sig`(base64url).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferSeal {
    pub ticket: String,
    pub sig: String,
}

/// 묶음 키를 받을 기기의 X25519 로 봉하고 이 기기 키로 서명한다. 봉할 수 없는 공개키면 `None`.
#[must_use]
pub fn seal_offer(
    mine: &DeviceKeys,
    my_device: &str,
    to_device: &str,
    to_x25519: &[u8; 32],
    transfer_id: &str,
    ak: &[u8; h::AK_LEN],
    plan_json: &str,
) -> Option<OfferSeal> {
    let info = h::ticket_info(transfer_id, my_device, to_device);
    let ticket = h::seal_ticket(ak, to_x25519, &info)?;
    let payload = h::offer_payload(
        transfer_id,
        my_device,
        to_device,
        &ticket,
        plan_json.as_bytes(),
    );
    Some(OfferSeal {
        sig: h::sign_offer(&mine.signing, &payload),
        ticket: encode(&ticket),
    })
}

/// 받은 offer 의 서명을 보낸 기기 키(`from_ed25519` — 호출자가 신뢰 사슬로 확인한 것)로 검증한 뒤 표를 연다. 서명이
/// 틀리거나 표가 이 기기 것이 아니면 `None`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn open_offer(
    mine: &DeviceKeys,
    my_device: &str,
    from_device: &str,
    from_ed25519: &[u8; 32],
    transfer_id: &str,
    ticket: &str,
    plan_json: &str,
    sig: &str,
) -> Option<Zeroizing<[u8; h::AK_LEN]>> {
    let ticket = decode(ticket, "history_offer.ticket").ok()?;
    let signer = VerifyingKey::from_bytes(from_ed25519).ok()?;
    let payload = h::offer_payload(
        transfer_id,
        from_device,
        my_device,
        &ticket,
        plan_json.as_bytes(),
    );
    if !h::verify_offer(&signer, &payload, sig) {
        return None;
    }
    let info = h::ticket_info(transfer_id, from_device, my_device);
    h::open_ticket(&ticket, &mine.exchange, &info)
}

impl RelayClient {
    /// 신뢰 사슬(뿌리에서 devcert 로 닿음)로 확인된 내 다른 기기의 디렉터리 항목. 이 기기·모르는 기기·확인 안 된 기기면
    /// `None`. self 그룹 잎인지는 보지 않는다(승인 직후엔 아직 잎이 아니다 — [`Self::own_devices`]).
    fn own_confirmed_device(&self, device: &str) -> Option<DirDevice> {
        if device == self.me.device_id {
            return None;
        }
        let (user, server) = self
            .me
            .address
            .split_once('@')
            .unwrap_or((self.me.address.as_str(), ""));
        let d = self.directory();
        let dir = keys::DirView::new(&d, server).with_former(&self.store);
        if !mls_rules::roots_in(&dir, user).eligible.contains(device) {
            return None;
        }
        dir.devices(user)
            .into_iter()
            .find(|x| x.device_id == device)
    }

    /// #881 그 기기가 지금 확인된 내 다른 기기인가.
    #[must_use]
    pub fn own_confirmed(&self, device: &str) -> bool {
        self.own_confirmed_device(device).is_some()
    }

    /// #881 묶음 키를 `to_device`(확인된 내 다른 기기)만 열게 봉하고 서명한다. 확인된 내 기기가 아니면 `None`.
    #[must_use]
    pub fn history_seal(
        &self,
        to_device: &str,
        transfer_id: &str,
        ak: &[u8; h::AK_LEN],
        plan_json: &str,
    ) -> Option<OfferSeal> {
        let to = self.own_confirmed_device(to_device)?;
        seal_offer(
            &self.keys,
            &self.me.device_id,
            to_device,
            &to.x25519,
            transfer_id,
            ak,
            plan_json,
        )
    }

    /// #881 받은 offer 를 연다 — 보낸 기기가 확인된 내 다른 기기이고 서명이 그 기기 것일 때만 묶음 키를 돌려준다.
    #[must_use]
    pub fn history_open(
        &self,
        from_device: &str,
        transfer_id: &str,
        ticket: &str,
        plan_json: &str,
        sig: &str,
    ) -> Option<Zeroizing<[u8; h::AK_LEN]>> {
        let from = self.own_confirmed_device(from_device)?;
        open_offer(
            &self.keys,
            &self.me.device_id,
            from_device,
            &from.ed25519,
            transfer_id,
            ticket,
            plan_json,
            sig,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lodelai_crypto::DeviceSecret;

    fn keys(n: u8) -> DeviceKeys {
        DeviceKeys::from_secret(&DeviceSecret {
            signing_seed: [n; 32],
            exchange_seed: [n.wrapping_add(100); 32],
        })
    }

    #[test]
    fn 받을_기기만_열고_다른_기기_다른_서명자_바뀐_칸은_못_연다() {
        let (old, new, third) = (keys(1), keys(2), keys(3));
        let ak = [9u8; 32];
        let plan = r#"{"msgs":2,"files":0,"bytes":3}"#;
        let o = seal_offer(
            &old,
            "k1_old",
            "k1_new",
            &new.exchange.public_key(),
            "T1",
            &ak,
            plan,
        )
        .unwrap();
        let old_pub = old.signing.verifying_key().to_bytes();
        let open =
            |me: &DeviceKeys, me_id: &str, from: &str, signer: &[u8; 32], t: &str, p: &str| {
                open_offer(me, me_id, from, signer, t, &o.ticket, p, &o.sig)
            };
        assert_eq!(
            open(&new, "k1_new", "k1_old", &old_pub, "T1", plan).as_deref(),
            Some(&ak)
        );
        // 다른 내 기기는 표를 못 연다(서명은 맞아도 표가 그 기기 것이 아니다).
        assert!(open(&third, "k1_third", "k1_old", &old_pub, "T1", plan).is_none());
        assert!(open(&third, "k1_new", "k1_old", &old_pub, "T1", plan).is_none());
        // 서명한 기기가 다르다(신뢰 사슬이 준 키와 안 맞음).
        let third_pub = third.signing.verifying_key().to_bytes();
        assert!(open(&new, "k1_new", "k1_old", &third_pub, "T1", plan).is_none());
        // 보낸 기기·transfer_id·plan 가운데 하나라도 바뀌면 서명이 안 맞는다.
        assert!(open(&new, "k1_new", "k1_other", &old_pub, "T1", plan).is_none());
        assert!(open(&new, "k1_new", "k1_old", &old_pub, "T2", plan).is_none());
        assert!(open(&new, "k1_new", "k1_old", &old_pub, "T1", "{}").is_none());
    }
}
