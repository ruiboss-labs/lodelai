//! 받는 쪽 잎 자격(묶음 22 §2b·§2c·§4, ADR 0012 §5a). relay 와 **같은 디렉터리로 같은 계산**을 다시 해서 relay 가 자격 없는
//! 잎에 순서를 준 것(서버 이상)만 잡는다.
//!
//! - 뿌리(§2b 3, c53989c0·e73b25bd): 그래프 마디 = 그 사용자의 폐기 안 된 기기 + 증명 있는 폐기(`devrevoke`)로 끊긴 기기
//!   (고리로만 — 잎은 못 됨), 화살표 = 서명을 다시 검증한 devcert(서명자 → 대상, 대상은 두 마디 모두). 뿌리 후보 = 자기 또는 아래에 폐기 안 된 기기가
//!   있는 마디(들어오는 화살표 있어도 — #489), 뿌리 = 후보 중 등록이 가장 이른 것(같으면 device_id 순).
//! - 잎 자격 = 그 사용자의 폐기 안 된 디렉터리 기기 · 잎 서명 키 = 디렉터리 Ed25519 · 뿌리에서 화살표로 닿음.
//! - 뿌리가 바뀐 것은 어긋남이 아니다(§2c — 받고 기록 줄, `keys::learn_directory`). 결과는 셋: 통과 · `Retry`(디렉터리가
//!   늦음 — 새 기기 직후 디렉터리에 아직 없거나 devcert 가 아직 안 보임, 갱신 뒤 다시 보면 풀림, ADR §5a ①. 1시간 넘게
//!   그대로면 `mls::receive` 가 멈춤으로 바꾼다) · `Stall`(서버 이상 — ③⑤).

use std::collections::{HashMap, HashSet};

use lodelai_crypto::{devcert, devrevoke, VerifyingKey};
use openmls::prelude::{MlsGroup, Proposal, Sender, StagedCommit};

/// 디렉터리의 폐기 안 된 기기 하나.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirDevice {
    pub device_id: String,
    pub user: String,
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
    /// 서버 등록 시각(`added_at`) — 뿌리 계산.
    pub added_ms: i64,
    /// 내 기기 서명(`certs[{signer, sig}]`) — 검증은 여기서 다시.
    pub certs: Vec<(String, String)>,
}

/// 증명 있는 폐기(`DirectoryUser.revocations[]`, §12-11 ⓐ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub device_id: String,
    /// 그 기기의 등록 시각 — 뿌리 계산.
    pub added_ms: i64,
    /// 그 기기의 Ed25519 — 그 기기가 서명한 devcert 를 검증.
    pub ed25519: [u8; 32],
    /// 그 기기의 X25519 — 그 기기로 들어오는 devcert 의 서명 입력.
    pub x25519: [u8; 32],
    /// 그 기기로 들어오는 devcert(`{signer, sig}`) — 증명 폐기 뒤에도 남는다(e73b25bd).
    pub certs: Vec<(String, String)>,
    pub at: String,
    pub signer: String,
    pub sig: String,
}

/// 받는 쪽이 보는 디렉터리.
pub trait Directory {
    /// `ready.server`(서명 입력).
    fn server(&self) -> &str;
    /// 그 사용자의 폐기 안 된 기기.
    fn devices(&self, user: &str) -> Vec<DirDevice>;
    /// 그 사용자의 증명 있는 폐기.
    fn revocations(&self, user: &str) -> Vec<Revocation>;
    /// 디렉터리에서 사라진 기기(조직에서 빠짐·폐기)의 옛 사용자 — 잎 → 사용자를 relay(`device_user`, 폐기 기기도)와 같게
    /// 풀 때만(유효 관리자 §12-25). 잎 자격 판정에는 쓰지 않는다.
    fn former_user(&self, _device_id: &str) -> Option<String> {
        None
    }
}

/// 규칙 판정.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// 디렉터리가 늦다 — 갱신 뒤 다시 본다.
    Retry(&'static str),
    /// 멈춤 — relay 이상.
    Stall(&'static str),
}

fn vk(bytes: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).ok()
}

/// 한 사용자의 뿌리 계산 결과.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roots {
    /// 뿌리 device_id(살아 있는 기기가 없으면 없음).
    pub root: Option<String>,
    /// 잎 자격 = 뿌리에서 닿는 폐기 안 된 기기.
    pub eligible: HashSet<String>,
}

/// §2b 3 의 그래프로 뿌리와 잎 자격을 계산한다.
#[must_use]
pub fn roots(server: &str, user: &str, live: &[DirDevice], revoked: &[Revocation]) -> Roots {
    // 마디: id → (등록 시각, Ed25519, 살아 있나). 살아 있는 기기가 먼저(같은 id 의 폐기 항목은 무시).
    let mut nodes: HashMap<&str, (i64, [u8; 32], bool)> = live
        .iter()
        .map(|d| (d.device_id.as_str(), (d.added_ms, d.ed25519, true)))
        .collect();
    // 증명 폐기 기기: 서명자는 같은 사용자의 기기(산 것·증명 폐기된 것)이고 서명이 맞아야 마디가 된다.
    let keys: HashMap<&str, [u8; 32]> = live
        .iter()
        .map(|d| (d.device_id.as_str(), d.ed25519))
        .chain(revoked.iter().map(|r| (r.device_id.as_str(), r.ed25519)))
        .collect();
    for r in revoked {
        if nodes.contains_key(r.device_id.as_str()) {
            continue;
        }
        let proved = keys.get(r.signer.as_str()).and_then(vk).is_some_and(|k| {
            devrevoke::verify(
                &k,
                &devrevoke::Revoke {
                    server,
                    device_id: &r.device_id,
                    at: &r.at,
                },
                &r.sig,
            )
        });
        if proved {
            nodes.insert(r.device_id.as_str(), (r.added_ms, r.ed25519, false));
        }
    }
    // 화살표: 대상은 산 기기와 마디가 된 증명 폐기 기기. 서명자가 마디이고 서명이 맞아야.
    let targets = live
        .iter()
        .map(|d| (d.device_id.as_str(), &d.x25519, &d.certs))
        .chain(
            revoked
                .iter()
                .filter(|r| nodes.get(r.device_id.as_str()).is_some_and(|n| !n.2))
                .map(|r| (r.device_id.as_str(), &r.x25519, &r.certs)),
        );
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for (target, x25519, certs) in targets {
        for (signer, sig) in certs {
            if signer == target {
                continue;
            }
            let Some((_, key, _)) = nodes.get(signer.as_str()) else {
                continue;
            };
            let ok = vk(key).is_some_and(|k| {
                devcert::verify(
                    &k,
                    &devcert::Cert {
                        server,
                        user,
                        device_id: target,
                        x25519,
                        signer,
                    },
                    sig,
                )
            });
            if ok {
                edges.entry(signer.as_str()).or_default().push(target);
            }
        }
    }
    // 들어오는 화살표가 있어도 후보다(#489) — 자동 재서명으로 내 기기끼리 서로 서명해 순환이 보통이다.
    let mut best: Option<(i64, &str, HashSet<&str>)> = None;
    for (&id, &(added, _, _)) in &nodes {
        let reach = below(&edges, id);
        if !reach.iter().any(|n| nodes.get(n).is_some_and(|x| x.2)) {
            continue;
        }
        if best.as_ref().is_none_or(|(a, b, _)| (added, id) < (*a, *b)) {
            best = Some((added, id, reach));
        }
    }
    best.map_or_else(Roots::default, |(_, id, reach)| Roots {
        root: Some(id.to_owned()),
        eligible: reach
            .into_iter()
            .filter(|n| nodes.get(n).is_some_and(|x| x.2))
            .map(str::to_owned)
            .collect(),
    })
}

/// `from` 과 그 아래(화살표로 닿는) 마디.
fn below<'a>(edges: &HashMap<&'a str, Vec<&'a str>>, from: &'a str) -> HashSet<&'a str> {
    let mut seen = HashSet::from([from]);
    let mut stack = vec![from];
    while let Some(n) = stack.pop() {
        for &t in edges.get(n).into_iter().flatten() {
            if seen.insert(t) {
                stack.push(t);
            }
        }
    }
    seen
}

/// 디렉터리로 [`roots`].
#[must_use]
pub fn roots_in(dir: &dyn Directory, user: &str) -> Roots {
    roots(
        dir.server(),
        user,
        &dir.devices(user),
        &dir.revocations(user),
    )
}

/// 그 기기가 그 사용자의 잎이 될 수 있나(§2b).
#[must_use]
pub fn leaf_ok(dir: &dyn Directory, user: &str, device_id: &str, leaf_key: &[u8]) -> Verdict {
    let Some(d) = dir
        .devices(user)
        .into_iter()
        .find(|d| d.device_id == device_id)
    else {
        if dir
            .revocations(user)
            .iter()
            .any(|r| r.device_id == device_id)
        {
            return Verdict::Stall("revoked");
        }
        // 새 기기 직후 디렉터리가 아직 안 옴 — 갱신 뒤 다시.
        return Verdict::Retry("device_unknown");
    };
    if d.ed25519.as_slice() != leaf_key {
        return Verdict::Stall("leaf_key");
    }
    if roots_in(dir, user).eligible.contains(device_id) {
        Verdict::Ok
    } else {
        // 새 기기 직후 devcert 의 directory.update 가 Commit 보다 늦을 수 있다(ADR §5a ①) — 오래가면 receive 가 멈춤으로.
        Verdict::Retry("no_chain")
    }
}

/// 받은 Commit 을 볼 때 호출자가 주는 것.
pub struct RuleCtx<'a> {
    pub dir: &'a dyn Directory,
    /// 그룹의 멤버 사용자(pair 는 둘, self 는 나) — 호출자가 봉투·그룹 종류에서 한 곳에서 정한다.
    pub members: &'a [String],
    /// 봉투 `from.device_id`(그 메시지를 보낸 기기, §12-11 ⓔ).
    pub expect_sender: Option<&'a str>,
    /// 응용 메시지를 열면 그 평문을 이 msg_id 로 같은 트랜잭션에 남긴다 — MLS 는 같은 메시지를 두 번 못 연다(FS). 코어가
    /// ack 하기 전에 끊겨 다시 배달되면 남긴 것을 쓴다.
    pub keep_as: Option<&'a str>,
    /// 알림(push_open)이 봉투 없이 연다 — `keep_as` 로 남길 때 MLS 자격의 보낸 기기도 같이 남겨, 앱이 다시 받을 때 봉투와
    /// 견주게 한다(§12-11 ⓔ, 모바일 검증 S2).
    pub push_opened: bool,
    /// group 종류 Commit 의 봉투 헤더(`group_op`·`subject`·`subjects`) — 사람 op 규칙(§4-3·4·§12-13·15·22). pair·self 는 `None`.
    pub group: Option<GroupRule<'a>>,
}

/// group Commit 의 사람 op(봉투 헤더, 사람 주소는 아이디로).
#[derive(Clone, Copy)]
pub struct GroupRule<'a> {
    pub op: &'a str,
    pub subject: Option<&'a str>,
    pub subjects: &'a [String],
}

impl GroupRule<'_> {
    /// 사용자 단위 Remove 를 하는 op(그 사람 잎 전부).
    fn user_op(&self) -> bool {
        matches!(self.op, "remove" | "leave" | "org_left")
    }
}

impl<'a> RuleCtx<'a> {
    /// 그 기기를 가진 멤버 사용자.
    fn user_of(&self, device_id: &str) -> Option<&'a str> {
        self.members
            .iter()
            .find(|u| self.dir.devices(u).iter().any(|d| d.device_id == device_id))
            .map(String::as_str)
    }

    fn eligible(&self, device_id: &str, leaf_key: &[u8]) -> Result<(), Verdict> {
        let Some(user) = self.user_of(device_id) else {
            let revoked = self.members.iter().any(|u| {
                self.dir
                    .revocations(u)
                    .iter()
                    .any(|r| r.device_id == device_id)
            });
            return Err(if revoked {
                Verdict::Stall("revoked")
            } else {
                Verdict::Retry("device_unknown")
            });
        };
        match leaf_ok(self.dir, user, device_id, leaf_key) {
            Verdict::Ok => Ok(()),
            v => Err(v),
        }
    }

    /// 그 기기가 이 그룹 멤버 사용자의 잎이 될 수 있나 — Add 할 KeyPackage·Welcome 트리의 잎(relay 를 믿지 않음, §2b).
    #[must_use]
    pub fn leaf_verdict(&self, device_id: &str, leaf_key: &[u8]) -> Verdict {
        match self.eligible(device_id, leaf_key) {
            Ok(()) => Verdict::Ok,
            Err(v) => v,
        }
    }

    /// 들어가려는 트리(Welcome·external 의 GroupInfo)에 **이미 있는** 잎 하나(#577 설계 결정 — '지금 끊기'): 멤버 사용자의
    /// 폐기 기록에 있고 잎 키가 그 기록의 Ed25519 와 같으면 통과다(남은 멤버·든 뒤의 나가 Remove 한다). 키가 다르거나 멤버의
    /// 기록이 아니면 [`Self::leaf_verdict`] 그대로(Stall). Commit 이 새로 넣거나 바꾸는 잎은 이것을 쓰지 않는다(check_staged).
    #[must_use]
    pub fn existing_leaf_verdict(&self, device_id: &str, leaf_key: &[u8]) -> Verdict {
        if self.revoked_same_key(device_id, leaf_key) {
            Verdict::Ok
        } else {
            self.leaf_verdict(device_id, leaf_key)
        }
    }

    /// 디렉터리 기기 목록엔 없고 멤버 사용자의 폐기 기록에 있으며, 잎 키가 그 기록의 Ed25519 와 같은 기기인가.
    fn revoked_same_key(&self, device_id: &str, leaf_key: &[u8]) -> bool {
        self.user_of(device_id).is_none()
            && self.members.iter().any(|u| {
                self.dir
                    .revocations(u)
                    .iter()
                    .any(|r| r.device_id == device_id && r.ed25519.as_slice() == leaf_key)
            })
    }

    /// 트리의 잎 기기 중 멤버 사용자의 폐기 기록에 있는(디렉터리 기기 목록엔 없는) 것.
    #[must_use]
    /// 그 잎 기기의 주인 — 폐기된 기기도(폐기 목록에서). 모르면 `None`.
    pub fn leaf_user(&self, device_id: &str) -> Option<&'a str> {
        self.user_of(device_id).or_else(|| {
            self.members
                .iter()
                .find(|u| {
                    self.dir
                        .revocations(u)
                        .iter()
                        .any(|r| r.device_id == device_id)
                })
                .map(String::as_str)
        })
    }

    pub fn is_revoked_leaf(&self, device_id: &str) -> bool {
        self.user_of(device_id).is_none()
            && self.members.iter().any(|u| {
                self.dir
                    .revocations(u)
                    .iter()
                    .any(|r| r.device_id == device_id)
            })
    }

    fn is_live(&self, device_id: &str) -> bool {
        self.user_of(device_id).is_some()
    }
}

/// `BasicCredential` 의 device_id.
#[must_use]
pub fn device_of(c: &openmls::prelude::Credential) -> Option<String> {
    let b = openmls::prelude::BasicCredential::try_from(c.clone()).ok()?;
    String::from_utf8(b.identity().to_vec()).ok()
}

/// 받은 Commit 을 merge 전에 다시 본다(§4 1~5, relay 를 믿지 않음). `group` 은 merge 전 그룹.
/// - 보낸 잎(멤버): 봉투 기기와 같고, 잎 키(새 경로면 새 잎) = 디렉터리 Ed25519, 뿌리에서 닿음. Remove 는 디렉터리에서 사라진
///   (폐기된) 기기만(사용자 단위 op 는 group 종류 — 16 뒤). ExternalInit 없음.
/// - external commit: 들어오는 잎이 멤버 사용자의 자격 있는 기기, Remove 는 같은 device_id 의 옛 잎뿐, Add 없음.
/// - Add 마다 KeyPackage 기기의 잎 자격(멤버 사용자).
#[must_use]
pub fn check_staged(
    ctx: &RuleCtx<'_>,
    group: &MlsGroup,
    sender: &Sender,
    staged: &StagedCommit,
) -> Verdict {
    match check(ctx, group, sender, staged) {
        Ok(()) => Verdict::Ok,
        Err(v) => v,
    }
}

fn check(
    ctx: &RuleCtx<'_>,
    group: &MlsGroup,
    sender: &Sender,
    staged: &StagedCommit,
) -> Result<(), Verdict> {
    let external_init = staged
        .queued_proposals()
        .any(|q| matches!(q.proposal(), Proposal::ExternalInit(_)));
    let new_leaf = staged.update_path_leaf_node();
    match sender {
        Sender::Member(i) => {
            if external_init {
                return Err(Verdict::Stall("external_init"));
            }
            let m = group.member_at(*i).ok_or(Verdict::Stall("sender_leaf"))?;
            let dev = device_of(&m.credential).ok_or(Verdict::Stall("credential"))?;
            if ctx.expect_sender.is_some_and(|e| e != dev) {
                return Err(Verdict::Stall("sender_mismatch"));
            }
            let key = new_leaf.map_or(m.signature_key.as_slice(), |l| l.signature_key().as_slice());
            // 보낸 잎은 이미 우리 트리 안의 잎이다. 디렉터리에 없으면(증명 있든 없든 막 폐기 — relay 는 폐기 전에 순서를 준
            // Commit 을 배달하고 폐기 뒤엔 그 기기 것을 받지 않음, §12-11 ⓒ) 받아들인다 — duty 로 곧 Remove 된다(설계 2b
            // 리뷰). 디렉터리에 있으면 잎 규칙 그대로. 디렉터리 늦음(Retry)·폐기 기기 넣기 거절은 Add·external commit 에만.
            if ctx.user_of(&dev).is_some() {
                ctx.eligible(&dev, key)?;
            } else if key != m.signature_key.as_slice() {
                // 디렉터리에 없는 잎이 update path 로 서명 키를 바꾸면 멈춤 — 폐기된 기기가 duty Remove 전에 키를 돌려
                // 버티는 길을 좁힌다(설계 2b 리뷰 7ca1cab6).
                return Err(Verdict::Stall("revoked_key_change"));
            }
            let actor = ctx.user_of(&dev);
            let mut removed = HashSet::new();
            for r in staged.remove_proposals() {
                let t = group
                    .member_at(r.remove_proposal().removed())
                    .ok_or(Verdict::Stall("remove_leaf"))?;
                let tdev = device_of(&t.credential).ok_or(Verdict::Stall("credential"))?;
                // 폐기된 기기 잎은 언제나. 사용자 단위 op 는 subject 의 잎(remove 는 관리자만, leave·org_left 는 relay 기록이
                // 근거 — 받는 쪽은 그 사람 잎인지만 본다, §12-13 ②).
                let by_rule = ctx.group.is_some_and(|g| {
                    g.user_op()
                        && ctx.user_of(&tdev).is_some()
                        && ctx.user_of(&tdev) == g.subject
                        && (g.op != "remove" || actor.is_some_and(|a| is_admin(ctx, group, a)))
                });
                if ctx.is_live(&tdev) && !by_rule {
                    return Err(Verdict::Stall("remove_live"));
                }
                removed.insert(tdev);
            }
            if let Some(g) = ctx.group {
                group_rules(ctx, group, staged, g, actor, &removed)?;
            }
        }
        Sender::NewMemberCommit => {
            let leaf = new_leaf.ok_or(Verdict::Stall("external_no_path"))?;
            let dev = device_of(leaf.credential()).ok_or(Verdict::Stall("credential"))?;
            if ctx.expect_sender.is_some_and(|e| e != dev) {
                return Err(Verdict::Stall("sender_mismatch"));
            }
            ctx.eligible(&dev, leaf.signature_key().as_slice())?;
            for r in staged.remove_proposals() {
                let t = group
                    .member_at(r.remove_proposal().removed())
                    .ok_or(Verdict::Stall("remove_leaf"))?;
                // 자기 옛 잎만(QA 🟢⑧ — 다른 멤버 Remove 섞기 거절).
                if device_of(&t.credential).as_deref() != Some(dev.as_str()) {
                    return Err(Verdict::Stall("external_remove_other"));
                }
            }
            if staged.add_proposals().next().is_some() {
                return Err(Verdict::Stall("external_add"));
            }
        }
        _ => return Err(Verdict::Stall("sender_kind")),
    }
    for a in staged.add_proposals() {
        let leaf = a.add_proposal().key_package().leaf_node();
        let dev = device_of(leaf.credential()).ok_or(Verdict::Stall("credential"))?;
        // 넣은 뒤 폐기된 기기(0.3.0 관문 B18): 멤버는 자기 디렉터리에서 자격 있는 기기만 넣으므로, 폐기 기록과 잎 키가 같은
        // 기기를 넣는 Commit 은 '폐기를 알기 전'에 순서를 받은 것이다 — 꺼져 있다 늦게 받는 쪽이 멈추지 않게 받아들인다
        // (보낸 잎이 폐기된 경우와 같은 사정). 그 잎은 폐기 잎 Remove 일감으로 곧 빠진다. 키가 다르면 지금처럼 멈춤.
        let revoked = ctx.revoked_same_key(&dev, leaf.signature_key().as_slice());
        if !revoked {
            ctx.eligible(&dev, leaf.signature_key().as_slice())?;
        }
        if let Some(g) = ctx.group {
            let user = if revoked {
                ctx.leaf_user(&dev)
            } else {
                ctx.user_of(&dev)
            };
            let ok = match g.op {
                "add" => user.is_some() && user == g.subject,
                // 처음 멤버 + 만든 사람의 다른 기기(§12-22, 97fea6e6 — epoch 0 의 잎은 만든 사람뿐).
                "create" => user
                    .is_some_and(|u| g.subjects.iter().any(|s| s == u) || has_leaf(ctx, group, u)),
                // 새 기기 Add(§12-15 ⓑ): 이미 잎이 있는 사용자만.
                "update" => user.is_some_and(|u| has_leaf(ctx, group, u)),
                _ => false,
            };
            if !ok {
                return Err(Verdict::Stall("add_rule"));
            }
        }
    }
    Ok(())
}

/// 사람 주소(`아이디@서버`)로 본 관리자인가 — merge 전 그룹의 유효 관리자(§12-25).
fn is_admin(ctx: &RuleCtx<'_>, group: &MlsGroup, user: &str) -> bool {
    let me = format!("{user}@{}", ctx.dir.server());
    crate::mls::effective_admins(group, ctx.dir.server(), |d| {
        ctx.user_of(d)
            .map(str::to_owned)
            .or_else(|| ctx.dir.former_user(d))
    })
    .contains(&me)
}

/// 그 사용자의 잎이 그룹에 있나.
fn has_leaf(ctx: &RuleCtx<'_>, group: &MlsGroup, user: &str) -> bool {
    group
        .members()
        .any(|m| device_of(&m.credential).is_some_and(|d| ctx.user_of(&d) == Some(user)))
}

/// group 종류 Commit 의 사람 op 규칙(보낸 잎이 멤버일 때): 사용자 단위 op 뒤 그 사람 잎 0(§4-4), GroupContextExtensions 는
/// `admin` 에서 관리자만·0xF0A1 `admins` 만 바뀜(§12-13 ①), create 는 epoch 0 에서만(§12-22).
fn group_rules(
    ctx: &RuleCtx<'_>,
    group: &MlsGroup,
    staged: &StagedCommit,
    g: GroupRule<'_>,
    actor: Option<&str>,
    removed: &HashSet<String>,
) -> Result<(), Verdict> {
    if g.user_op() {
        let subject = g.subject.ok_or(Verdict::Stall("subject"))?;
        let left = group.members().any(|m| {
            device_of(&m.credential)
                .is_some_and(|d| !removed.contains(&d) && ctx.user_of(&d) == Some(subject))
        });
        if left {
            return Err(Verdict::Stall("user_leaves_left"));
        }
    }
    if g.op == "create" && group.epoch().as_u64() != 0 {
        return Err(Verdict::Stall("create_epoch"));
    }
    let gce = staged
        .queued_proposals()
        .any(|q| matches!(q.proposal(), Proposal::GroupContextExtensions(_)));
    if gce || g.op == "admin" {
        let admin = actor.is_some_and(|a| is_admin(ctx, group, a));
        let new = staged.group_context().extensions();
        if !(gce
            && g.op == "admin"
            && admin
            && crate::mls::only_admins_changed(group.extensions(), new))
        {
            return Err(Verdict::Stall("admin_rule"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lodelai_crypto::DeviceKeys;

    use super::*;

    const SERVER: &str = "lodelai.example";

    /// 시험용 디렉터리(한 사용자 alice).
    #[derive(Default)]
    struct Dir {
        live: Vec<DirDevice>,
        revs: Vec<Revocation>,
    }

    impl Directory for Dir {
        fn server(&self) -> &str {
            SERVER
        }
        fn devices(&self, user: &str) -> Vec<DirDevice> {
            self.live
                .iter()
                .filter(|d| d.user == user)
                .cloned()
                .collect()
        }
        fn revocations(&self, user: &str) -> Vec<Revocation> {
            if user == "alice" {
                self.revs.clone()
            } else {
                Vec::new()
            }
        }
    }

    struct Dev {
        keys: DeviceKeys,
        id: String,
    }

    fn dev(seed: u8) -> Dev {
        let keys = DeviceKeys::generate(&[seed; 64]);
        let id = keys.device_id().as_str().to_owned();
        Dev { keys, id }
    }

    fn ed(d: &Dev) -> [u8; 32] {
        d.keys.signing.verifying_key().to_bytes()
    }

    impl Dir {
        fn add(&mut self, d: &Dev, added_ms: i64, signed_by: &[&Dev]) {
            let x = d.keys.exchange.public_key();
            let certs = signed_by
                .iter()
                .map(|s| {
                    let sig = devcert::sign(
                        &s.keys.signing,
                        &devcert::Cert {
                            server: SERVER,
                            user: "alice",
                            device_id: &d.id,
                            x25519: &x,
                            signer: &s.id,
                        },
                    );
                    (s.id.clone(), sig)
                })
                .collect();
            self.live.push(DirDevice {
                device_id: d.id.clone(),
                user: "alice".to_owned(),
                ed25519: ed(d),
                x25519: x,
                added_ms,
                certs,
            });
        }

        /// 폐기: 증명이 있으면 revocations 에 남고 그 기기로 들어오는·나가는 devcert 가 남는다(e73b25bd). 없으면 그 기기의
        /// 행과 그 기기가 서명한 devcert 가 사라진다.
        fn revoke(&mut self, d: &Dev, proof_by: Option<&Dev>) {
            let row = self
                .live
                .iter()
                .find(|x| x.device_id == d.id)
                .cloned()
                .unwrap();
            self.live.retain(|x| x.device_id != d.id);
            if let Some(s) = proof_by {
                let at = "2026-10-27T00:00:00.000Z";
                let sig = devrevoke::sign(
                    &s.keys.signing,
                    &devrevoke::Revoke {
                        server: SERVER,
                        device_id: &d.id,
                        at,
                    },
                );
                self.revs.push(Revocation {
                    device_id: d.id.clone(),
                    added_ms: row.added_ms,
                    ed25519: ed(d),
                    x25519: row.x25519,
                    certs: row.certs,
                    at: at.to_owned(),
                    signer: s.id.clone(),
                    sig,
                });
            } else {
                for x in &mut self.live {
                    x.certs.retain(|(signer, _)| *signer != d.id);
                }
            }
        }

        fn root(&self) -> Option<String> {
            roots_in(self, "alice").root
        }

        /// 이미 있는 기기에 devcert 하나 더(자동 재서명).
        fn sign(&mut self, target: &Dev, signer: &Dev) {
            let row = self
                .live
                .iter_mut()
                .find(|x| x.device_id == target.id)
                .unwrap();
            let sig = devcert::sign(
                &signer.keys.signing,
                &devcert::Cert {
                    server: SERVER,
                    user: "alice",
                    device_id: &target.id,
                    x25519: &row.x25519,
                    signer: &signer.id,
                },
            );
            row.certs.push((signer.id.clone(), sig));
        }
    }

    /// #489: 자동 재서명으로 a1↔a2 가 서로 서명해도 이른 a1 이 뿌리, 둘 다 잎.
    #[test]
    fn 서로_서명한_순환도_뿌리가_있다() {
        let (a1, a2) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        dir.add(&a2, 2, &[&a1]);
        dir.sign(&a1, &a2);
        assert_eq!(dir.root(), Some(a1.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &a1.id, &ed(&a1)), Verdict::Ok);
        assert_eq!(leaf_ok(&dir, "alice", &a2.id, &ed(&a2)), Verdict::Ok);
    }

    /// #489: A→C, C→B(B 가 C 보다 이른 등록) — 순방향만 세면 B 가 잎을 잃는다. B 도 잎.
    #[test]
    fn 늦은_기기가_이른_기기를_확인해도_잎() {
        let (a, b, c) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[]);
        dir.add(&c, 3, &[&a]);
        dir.sign(&b, &c);
        assert_eq!(dir.root(), Some(a.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &b.id, &ed(&b)), Verdict::Ok);
    }

    /// #489: A↔B 순환에서 A 를 증명으로 끊은 뒤 devcert 없는 D2 — 뿌리 A 그대로, D2 잎 아님.
    #[test]
    fn 순환에서_증명_폐기_뒤_d2_는_잎_아님() {
        let (a, b, d2) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.sign(&a, &b);
        dir.revoke(&a, Some(&b));
        dir.add(&d2, 3, &[]);
        assert_eq!(dir.root(), Some(a.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &b.id, &ed(&b)), Verdict::Ok);
        assert_eq!(
            leaf_ok(&dir, "alice", &d2.id, &ed(&d2)),
            Verdict::Retry("no_chain")
        );
    }

    /// #489: 서버가 증명 없이 A 를 폐기, B↔C 가 남음 — 이른 B 가 뿌리, C 도 잎.
    #[test]
    fn 증명_없는_폐기_뒤_순환은_이른_쪽이_뿌리() {
        let (a, b, c) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.add(&c, 3, &[&a, &b]);
        dir.sign(&b, &c);
        dir.revoke(&a, None);
        assert_eq!(dir.root(), Some(b.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &c.id, &ed(&c)), Verdict::Ok);
    }

    /// #489: 늦게 붙은 X 가 X→A 로 서명해도 X 는 뿌리에서 닿지 않는다.
    #[test]
    fn 늦은_기기의_역서명은_아무것도_열지_않는다() {
        let (a, x) = (dev(1), dev(9));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&x, 4, &[]);
        dir.sign(&a, &x);
        assert_eq!(dir.root(), Some(a.id.clone()));
        assert_eq!(
            leaf_ok(&dir, "alice", &x.id, &ed(&x)),
            Verdict::Retry("no_chain")
        );
    }

    #[test]
    fn 사슬로_닿는_기기만_잎() {
        let (a, b, c, x) = (dev(1), dev(2), dev(3), dev(9));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.add(&c, 3, &[&b]);
        // 이메일로 붙인 기기: devcert 없음, 늦게 등록 — 뿌리도 잎도 아님.
        dir.add(&x, 4, &[]);
        assert_eq!(dir.root(), Some(a.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &c.id, &ed(&c)), Verdict::Ok);
        assert_eq!(
            leaf_ok(&dir, "alice", &x.id, &ed(&x)),
            Verdict::Retry("no_chain")
        );
        assert_eq!(
            leaf_ok(&dir, "alice", &b.id, &ed(&c)),
            Verdict::Stall("leaf_key")
        );
        assert_eq!(
            leaf_ok(&dir, "alice", &dev(7).id, &ed(&c)),
            Verdict::Retry("device_unknown")
        );
    }

    #[test]
    fn 위조한_devcert_고리는_잇지_않는다() {
        let (a, b) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.live[1].certs[0].1 = devcert::sign(
            &dev(5).keys.signing,
            &devcert::Cert {
                server: SERVER,
                user: "alice",
                device_id: &b.id,
                x25519: &b.keys.exchange.public_key(),
                signer: &a.id,
            },
        );
        assert_eq!(
            leaf_ok(&dir, "alice", &b.id, &ed(&b)),
            Verdict::Retry("no_chain")
        );
    }

    /// QA 🔴(c53989c0): 옛 뿌리 A 를 B 가 증명으로 끊어도 A 가 뿌리로 남고 B 는 잎, 그 뒤 devcert 없는 D2 는 잎 아님.
    #[test]
    fn 증명_폐기_뒤에도_뿌리는_그대로() {
        let (a, b, d2) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.revoke(&a, Some(&b));
        dir.add(&d2, 3, &[]);
        assert_eq!(dir.root(), Some(a.id.clone()), "증명 폐기 마디가 고리");
        assert_eq!(leaf_ok(&dir, "alice", &b.id, &ed(&b)), Verdict::Ok);
        assert_eq!(
            leaf_ok(&dir, "alice", &d2.id, &ed(&d2)),
            Verdict::Retry("no_chain")
        );
        // 자기 폐기 증명(A 자신이 서명)도 같다.
        let mut own = Dir::default();
        own.add(&a, 1, &[]);
        own.add(&b, 2, &[&a]);
        own.revoke(&a, Some(&a));
        assert_eq!(own.root(), Some(a.id.clone()));
        assert_eq!(leaf_ok(&own, "alice", &b.id, &ed(&b)), Verdict::Ok);
    }

    /// A→B→C 에서 가운데 B 를 증명으로 끊어도 B 로 들어오는 devcert 가 남아 뿌리 A·C 잎(e73b25bd).
    #[test]
    fn 가운데_기기를_증명으로_끊어도_사슬이_남는다() {
        let (a, b, c) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.add(&c, 3, &[&b]);
        dir.revoke(&b, Some(&a));
        assert_eq!(dir.root(), Some(a.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &c.id, &ed(&c)), Verdict::Ok);
        assert_eq!(
            leaf_ok(&dir, "alice", &b.id, &ed(&b)),
            Verdict::Stall("revoked"),
            "폐기된 기기는 잎이 못 됨"
        );
    }

    /// 서버가 증명 없이 A 를 폐기하면 사슬이 끊겨 B 가 뿌리(§2c — 바뀜은 받고 기록 줄).
    #[test]
    fn 증명_없는_폐기는_뿌리가_바뀐다() {
        let (a, b) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.revoke(&a, None);
        assert_eq!(dir.root(), Some(b.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &b.id, &ed(&b)), Verdict::Ok);
    }

    /// 사슬 밖 기기(서버가 끼움)가 서명한 '증명'은 마디를 만들지 못한다 — 서명자가 그 사용자의 기기여도 서명이 틀리면 무시.
    #[test]
    fn 틀린_폐기_증명은_마디가_아니다() {
        let (a, b) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.revoke(&a, Some(&b));
        dir.revs[0].sig = devrevoke::sign(
            &dev(9).keys.signing,
            &devrevoke::Revoke {
                server: SERVER,
                device_id: &a.id,
                at: &dir.revs[0].at.clone(),
            },
        );
        assert_eq!(dir.root(), Some(b.id.clone()));
    }

    /// 더 이른 등록 시각의 devcert 없는 기기가 끼면(서버 바꿔치기) 그것이 뿌리 — 받고 기록 줄(§2c, 받아들인 약점).
    #[test]
    fn 더_이른_기기가_끼면_뿌리가_된다() {
        let (a, b, x) = (dev(1), dev(2), dev(9));
        let mut dir = Dir::default();
        dir.add(&a, 5, &[]);
        dir.add(&b, 6, &[&a]);
        dir.add(&x, 0, &[]);
        assert_eq!(dir.root(), Some(x.id.clone()));
        assert_eq!(
            leaf_ok(&dir, "alice", &b.id, &ed(&b)),
            Verdict::Retry("no_chain"),
            "옛 사슬은 새 뿌리 아래가 아니다"
        );
    }

    /// #577 설계 결정('지금 끊기'): 들어가려는 트리에 이미 있는 폐기 잎은 키가 폐기 기록과 같으면 통과, 키가 다르거나
    /// 멤버의 기록이 아니면 멈춤. 새로 넣는 잎 판정(leaf_verdict — Add·KeyPackage)은 그대로 멈춤.
    #[test]
    fn 트리에_남은_폐기_잎은_들기를_막지_않는다() {
        let (a, b, x) = (dev(1), dev(2), dev(9));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        dir.add(&b, 2, &[&a]);
        dir.revoke(&a, Some(&b));
        let members = ["alice".to_owned()];
        let ctx = RuleCtx {
            dir: &dir,
            members: &members,
            expect_sender: None,
            keep_as: None,
            push_opened: false,
            group: None,
        };
        // 재현: 끊긴 a 의 잎이 트리에 남아 있다 — 들기는 통과, 지운 뒤 빼야 할 잎으로 보인다.
        assert_eq!(ctx.existing_leaf_verdict(&a.id, &ed(&a)), Verdict::Ok);
        assert!(ctx.is_revoked_leaf(&a.id));
        assert!(!ctx.is_revoked_leaf(&b.id));
        // 폐기 기기를 새로 넣는 것(Add·KeyPackage)은 그대로 멈춤.
        assert_eq!(ctx.leaf_verdict(&a.id, &ed(&a)), Verdict::Stall("revoked"));
        // 키가 다른 폐기 잎은 멈춤.
        assert_eq!(
            ctx.existing_leaf_verdict(&a.id, &ed(&x)),
            Verdict::Stall("revoked")
        );
        // 멤버 아닌 사용자의 기록이면(이 그룹 멤버가 bob 뿐) 통과가 아니다.
        let others = ["bob".to_owned()];
        let ctx = RuleCtx {
            members: &others,
            ..ctx
        };
        assert_ne!(ctx.existing_leaf_verdict(&a.id, &ed(&a)), Verdict::Ok);
    }
}
