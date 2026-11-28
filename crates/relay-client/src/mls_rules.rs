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

/// 그 Retry 까닭이 「트리의 잎이 디렉터리에 산 기기로 없다」인가(`device_unknown`·`revoke_unproved`) — 디렉터리가 늦은 것일
/// 수도, 그 기기가 증명 없이 끊긴 것일 수도 있다. 뒤쪽이면 그 트리는 기다려도 통과하지 못한다(#1479).
#[must_use]
pub fn gone_leaf(why: &str) -> bool {
    matches!(why, "device_unknown" | "revoke_unproved")
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

/// 한 사용자의 디렉터리를 한 번 판정한 것: 뿌리·잎 자격과 **증명된** 폐기 기록([`proved_set`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserView {
    pub roots: Roots,
    /// 증명된 폐기 기록(기기마다 하나).
    pub proved: Vec<Revocation>,
}

/// §2b 3 의 그래프로 뿌리와 잎 자격을 계산한다. 폐기 기록은 [`proved_set`] 이 증명됐다고 본 것만 마디가 된다.
#[must_use]
pub fn roots(server: &str, user: &str, live: &[DirDevice], revoked: &[Revocation]) -> Roots {
    user_view(server, user, live, revoked).roots
}

/// 뿌리·잎 자격·증명된 폐기 기록을 한 번에([`roots`]·[`proved_set`] 이 같은 계산을 본다).
#[must_use]
pub fn user_view(server: &str, user: &str, live: &[DirDevice], revoked: &[Revocation]) -> UserView {
    let (nodes, proved) = judge(server, user, live, revoked);
    UserView {
        roots: roots_over(server, user, live, &nodes).0,
        proved: proved.into_iter().cloned().collect(),
    }
}

/// 디렉터리에 실린 폐기 기록 중 **증명된** 것(#1479·#1511). relay 가 실은 기록을 그대로 믿지 않는다 — 폐기 증명을 지어내는
/// 값이 잎 자격을 지어내는 값보다 싸지 않게, 서명이 맞고 서명자가 다음 중 하나일 때만이다:
/// - 산 기기이고 뿌리 아래에 있다(잎 자격과 같은 집합), 또는
/// - 폐기 기록 기기이고 그 기록이 같은 규칙으로 증명됐다(끊기기 전에 서명한 사슬), 또는
/// - 그 기기 자신(자기 폐기 증명 — 아래).
///
/// 뿌리는 증명된 기록에 기대고 증명은 뿌리에 기대므로 두 걸음으로 푼다. ① 서명자가 「산 기기 아무거나 또는 이미 든 기록의
/// 기기」인 가장 작은 고정점 — 폐기 기록끼리만 서로 증명하는 고리는 못 든다. ② 그 기록들로 뿌리를 구해, 서명자가 「뿌리 아래
/// 산 기기 또는 남은 기록의 기기」인 것만 남기기를 줄지 않을 때까지 되풀이한다(줄기만 하므로 끝난다). 한 바퀴에 전부를 같이
/// 판정하고 같은 기기의 기록은 정해진 순서로 하나를 고르므로, 디렉터리가 내준 순서와 무관하다.
///
/// `at` 으로 「끊긴 뒤에 한 서명」을 가르지는 않는다 — 서명자가 적는 값이라 막는 힘이 없다.
///
/// 자기 폐기 증명(그 기기가 스스로 서명)은 둘로 가른다. 그 기기의 **잎을 폐기 잎으로 보는 데**는 그것만으로 충분하다 — 기기
/// 아이디가 키의 해시라 그 키를 쥔 쪽만 서명할 수 있고, 하나뿐인 기기를 스스로 끊은 사람은 그 기록밖에 없다(#1201). 하지만
/// **다른 기록의 서명자·뿌리 계산의 마디**로는 그 기기가 뿌리이거나 뿌리 아래일 때만 쓴다(사슬에 닿지 않는 자기 서명 기록은
/// relay 가 지어낼 수 있다).
#[must_use]
pub fn proved_set(
    server: &str,
    user: &str,
    live: &[DirDevice],
    revoked: &[Revocation],
) -> Vec<Revocation> {
    judge(server, user, live, revoked)
        .1
        .into_iter()
        .cloned()
        .collect()
}

/// [`proved_set`] 의 본체 — (뿌리 계산의 마디·서명자로 쓰는 기록, 증명된 기록 전부). 앞이 뒤에 든다.
fn judge<'a>(
    server: &str,
    user: &str,
    live: &[DirDevice],
    revoked: &'a [Revocation],
) -> (Vec<&'a Revocation>, Vec<&'a Revocation>) {
    let live_key: HashMap<&str, [u8; 32]> = live
        .iter()
        .map(|d| (d.device_id.as_str(), d.ed25519))
        .collect();
    // 후보: 산 기기와 같은 id 는 뺀다(산 기기가 먼저). 순서를 정해 둔다.
    let mut cands: Vec<&Revocation> = revoked
        .iter()
        .filter(|r| !live_key.contains_key(r.device_id.as_str()))
        .collect();
    cands.sort_by(|a, b| {
        (
            &a.device_id,
            &a.at,
            &a.signer,
            &a.sig,
            a.added_ms,
            a.ed25519,
        )
            .cmp(&(
                &b.device_id,
                &b.at,
                &b.signer,
                &b.sig,
                b.added_ms,
                b.ed25519,
            ))
    });
    cands.dedup();
    // 서명자 키: 산 기기, 없으면 폐기 기록의 키(기기 아이디가 키의 해시라 같은 id 의 키는 하나다 — 디렉터리를 읽는 쪽이 본다).
    let key_of = |id: &str| {
        live_key
            .get(id)
            .copied()
            .or_else(|| cands.iter().find(|r| r.device_id == id).map(|r| r.ed25519))
    };
    let sig_ok: Vec<bool> = cands
        .iter()
        .map(|r| {
            key_of(&r.signer).as_ref().and_then(vk).is_some_and(|k| {
                devrevoke::verify(
                    &k,
                    &devrevoke::Revoke {
                        server,
                        device_id: &r.device_id,
                        at: &r.at,
                    },
                    &r.sig,
                )
            })
        })
        .collect();
    // `within` 안에서, `base` 가 받거나 서명자가 (자기 아닌) 이미 든 기록의 기기인 가장 작은 고정점.
    let grow = |within: &[bool], base: &dyn Fn(&Revocation) -> bool| {
        let mut inn = vec![false; cands.len()];
        loop {
            let ids: HashSet<&str> = cands
                .iter()
                .zip(&inn)
                .filter(|(_, x)| **x)
                .map(|(r, _)| r.device_id.as_str())
                .collect();
            let mut grew = false;
            for (i, r) in cands.iter().enumerate() {
                if !inn[i]
                    && within[i]
                    && sig_ok[i]
                    && (base(r) || (r.signer != r.device_id && ids.contains(r.signer.as_str())))
                {
                    inn[i] = true;
                    grew = true;
                }
            }
            if !grew {
                return inn;
            }
        }
    };
    // 기기마다 하나(정해 둔 순서의 첫 기록).
    let picked = |inn: &[bool]| {
        let mut seen = HashSet::new();
        cands
            .iter()
            .zip(inn)
            .filter(|(r, x)| **x && seen.insert(r.device_id.as_str()))
            .map(|(r, _)| *r)
            .collect::<Vec<&'a Revocation>>()
    };
    let own = |r: &Revocation| r.signer == r.device_id;
    let mut inn = grow(&vec![true; cands.len()], &|r| {
        own(r) || live_key.contains_key(r.signer.as_str())
    });
    loop {
        let (roots, under) = roots_over(server, user, live, &picked(&inn));
        // 자기 폐기 증명(그 기기가 스스로 서명)은 그 기기가 뿌리이거나 뿌리 아래일 때만 — 사슬에 닿지 않는 자기 서명 기록은
        // relay 가 지어낼 수 있다.
        let next = grow(&inn, &|r| {
            if own(r) {
                under.contains(&r.device_id)
            } else {
                roots.eligible.contains(&r.signer)
            }
        });
        if next == inn {
            break;
        }
        inn = next;
    }
    let all: Vec<bool> = cands
        .iter()
        .enumerate()
        .map(|(i, r)| inn[i] || (own(r) && sig_ok[i]))
        .collect();
    (picked(&inn), picked(&all))
}

/// 뿌리 계산 본체: `revoked` 는 이미 증명됐다고 본 폐기 기록(마디).
/// 돌려주는 둘째는 뿌리와 그 아래 마디 전부(폐기 기기도).
fn roots_over(
    server: &str,
    user: &str,
    live: &[DirDevice],
    revoked: &[&Revocation],
) -> (Roots, HashSet<String>) {
    // 마디: id → (등록 시각, Ed25519, 살아 있나). 살아 있는 기기가 먼저(같은 id 의 폐기 항목은 무시).
    let mut nodes: HashMap<&str, (i64, [u8; 32], bool)> = live
        .iter()
        .map(|d| (d.device_id.as_str(), (d.added_ms, d.ed25519, true)))
        .collect();
    for r in revoked {
        nodes
            .entry(r.device_id.as_str())
            .or_insert((r.added_ms, r.ed25519, false));
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
    best.map_or_else(Default::default, |(_, id, reach)| {
        (
            Roots {
                root: Some(id.to_owned()),
                eligible: reach
                    .iter()
                    .filter(|n| nodes.get(*n).is_some_and(|x| x.2))
                    .map(|n| (*n).to_owned())
                    .collect(),
            },
            reach.into_iter().map(str::to_owned).collect(),
        )
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

/// 디렉터리로 [`user_view`].
#[must_use]
pub fn user_view_in(dir: &dyn Directory, user: &str) -> UserView {
    user_view(
        dir.server(),
        user,
        &dir.devices(user),
        &dir.revocations(user),
    )
}

/// 디렉터리로 [`roots`].
#[must_use]
pub fn roots_in(dir: &dyn Directory, user: &str) -> Roots {
    user_view_in(dir, user).roots
}

/// 그 기기가 그 사용자의 잎이 될 수 있나(§2b).
#[must_use]
pub fn leaf_ok(dir: &dyn Directory, user: &str, device_id: &str, leaf_key: &[u8]) -> Verdict {
    leaf_ok_with(dir, user, device_id, leaf_key, &roots_in(dir, user))
}

fn leaf_ok_with(
    dir: &dyn Directory,
    user: &str,
    device_id: &str,
    leaf_key: &[u8],
    roots: &Roots,
) -> Verdict {
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
    if roots.eligible.contains(device_id) {
        Verdict::Ok
    } else {
        // 새 기기 직후 devcert 의 directory.update 가 Commit 보다 늦을 수 있다(ADR §5a ①) — 오래가면 receive 가 멈춤으로.
        Verdict::Retry("no_chain")
    }
}

/// [`RuleCtx`] 가 사용자마다 한 번 계산해 두는 판정.
pub type ViewCache = std::sync::Mutex<HashMap<String, std::sync::Arc<UserView>>>;

/// 받은 Commit 을 볼 때 호출자가 주는 것.
pub struct RuleCtx<'a> {
    /// 사용자마다 한 번 계산한 [`UserView`] — 한 판정 안에서 잎마다 다시 계산하지 않는다(`Default::default()` 로 만든다).
    pub views: ViewCache,
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
    /// 그 사용자의 판정(이 ctx 에서 한 번만 계산).
    fn view(&self, user: &str) -> std::sync::Arc<UserView> {
        let mut views = self
            .views
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(v) = views.get(user) {
            return v.clone();
        }
        let v = std::sync::Arc::new(user_view_in(self.dir, user));
        views.insert(user.to_owned(), v.clone());
        v
    }

    /// 그 기기의 **증명된** 폐기 기록이 있는 멤버 사용자와 그 기록의 Ed25519.
    fn proved_owner(&self, device_id: &str) -> Option<(&'a str, [u8; 32])> {
        self.members.iter().find_map(|u| {
            self.view(u)
                .proved
                .iter()
                .find(|r| r.device_id == device_id)
                .map(|r| (u.as_str(), r.ed25519))
        })
    }

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
        match leaf_ok_with(self.dir, user, device_id, leaf_key, &self.view(user).roots) {
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
    /// **증명된** 폐기 기록에 있고 잎 키가 그 기록의 Ed25519 와 같으면 통과다(남은 멤버·든 뒤의 나가 Remove 한다). 기록은 있는데
    /// 증명이 안 됐으면 다시 보기(`revoke_unproved`), 키가 다르거나 멤버의 기록이 아니면 [`Self::leaf_verdict`] 그대로(Stall). Commit 이 새로 넣거나 바꾸는 잎은 이것을 쓰지 않는다(check_staged).
    #[must_use]
    pub fn existing_leaf_verdict(&self, device_id: &str, leaf_key: &[u8]) -> Verdict {
        if self.revoked_same_key(device_id, leaf_key) {
            Verdict::Ok
        } else if self.user_of(device_id).is_none()
            && self.proved_owner(device_id).is_none()
            && self.members.iter().any(|u| {
                self.dir
                    .revocations(u)
                    .iter()
                    .any(|r| r.device_id == device_id)
            })
        {
            // 폐기 기록은 실렸는데 아직 증명되지 않았다(#1511) — 서명 못 받은 내 기기가 낸 끊기는 그 기기가 서명을 받으면
            // 풀린다. 멈추지 않고 디렉터리 갱신 뒤 다시 본다. 새로 넣는 잎(Add)은 지금처럼 멈춤이다.
            Verdict::Retry("revoke_unproved")
        } else {
            self.leaf_verdict(device_id, leaf_key)
        }
    }

    /// 디렉터리 기기 목록엔 없고 멤버 사용자의 **증명된** 폐기 기록([`proved_set`])에 있으며, 잎 키가 그 기록의 Ed25519 와
    /// 같은 기기인가. 증명 안 된 기록은 통과시키지 않는다(#1479 — 전에는 키 일치만 봤다).
    fn revoked_same_key(&self, device_id: &str, leaf_key: &[u8]) -> bool {
        self.user_of(device_id).is_none()
            && self
                .proved_owner(device_id)
                .is_some_and(|(_, ed)| ed.as_slice() == leaf_key)
    }

    /// 그 잎 기기의 주인 — 폐기된 기기도(**증명된** 폐기 기록에서, #1511: 확인 안 된 기록으로 주인을 짚지 않는다). 모르면 `None`.
    #[must_use]
    pub fn leaf_user(&self, device_id: &str) -> Option<&'a str> {
        self.user_of(device_id)
            .or_else(|| self.proved_owner(device_id).map(|(u, _)| u))
    }

    /// 트리의 잎 기기 중 멤버 사용자의 증명된 폐기 기록에 있는(디렉터리 기기 목록엔 없는) 것.
    #[must_use]
    pub fn is_revoked_leaf(&self, device_id: &str) -> bool {
        self.user_of(device_id).is_none() && self.proved_owner(device_id).is_some()
    }

    fn is_live(&self, device_id: &str) -> bool {
        self.user_of(device_id).is_some()
    }

    /// 그 잎의 Remove 가 「산 기기 빼기」로 막히는가 — 받는 쪽 Commit 재검사([`check`])와 만드는 쪽(relay 가 시킨
    /// `remove_device`, #1517)이 같이 부른다. `by_rule` 은 사용자 단위 op(remove·leave·org_left)의 예외 — 기기 단위 일에는 없다.
    /// 디렉터리를 아직 못 받았으면 모든 기기가 「산 기기 아님」으로 읽힌다 — 만드는 쪽은 이번 접속에서 받은 뒤에만 부른다
    /// ([`crate::duty_guard`]).
    #[must_use]
    pub fn remove_blocked(&self, device_id: &str, by_rule: bool) -> bool {
        self.is_live(device_id) && !by_rule
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
                if ctx.remove_blocked(&tdev, by_rule) {
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

    impl Dir {
        /// 산 목록에 없는 기기의 폐기 기록을 그대로 싣는다(relay 가 내주는 대로) — 증명 서명은 `signer` 의 키로.
        fn push_rev(&mut self, d: &Dev, added_ms: i64, signer: &Dev) {
            let at = "2026-10-27T00:00:00.000Z";
            self.revs.push(Revocation {
                device_id: d.id.clone(),
                added_ms,
                ed25519: ed(d),
                x25519: d.keys.exchange.public_key(),
                certs: Vec::new(),
                at: at.to_owned(),
                signer: signer.id.clone(),
                sig: devrevoke::sign(
                    &signer.keys.signing,
                    &devrevoke::Revoke {
                        server: SERVER,
                        device_id: &d.id,
                        at,
                    },
                ),
            });
        }

        /// 증명됐다고 본 폐기 기기(정렬).
        fn proved(&self) -> Vec<String> {
            let mut v: Vec<String> = user_view_in(self, "alice")
                .proved
                .into_iter()
                .map(|r| r.device_id)
                .collect();
            v.sort();
            v
        }
    }

    fn sorted(ids: &[&Dev]) -> Vec<String> {
        let mut v: Vec<String> = ids.iter().map(|d| d.id.clone()).collect();
        v.sort();
        v
    }

    /// #1511: relay 가 지어 넣은 폐기 기록 y 의 키로 서명한 x 의 폐기는 증명이 아니다 — 사슬에 닿지 않는 y 의 자기 서명은 y
    /// 자신의 잎에만 통하고 서명자로는 못 쓴다. 서로 서명한 고리도 못 든다.
    #[test]
    fn 지어낸_폐기_기록의_키로_한_증명은_통하지_않는다() {
        let (a1, x, y) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        // y 는 자기 서명, x 는 y 가 서명.
        dir.push_rev(&y, 0, &y);
        dir.push_rev(&x, 2, &y);
        assert_eq!(dir.proved(), sorted(&[&y]));
        assert_eq!(dir.root(), Some(a1.id.clone()), "y 는 마디가 아니다");
        // 둘이 서로 서명해도 같다.
        dir.revs.clear();
        dir.push_rev(&y, 0, &x);
        dir.push_rev(&x, 2, &y);
        assert!(dir.proved().is_empty());
        assert_eq!(dir.root(), Some(a1.id.clone()));
        // 뿌리 아래 산 기기가 y 를 증명하면 사슬이 풀린다.
        dir.revs.clear();
        dir.push_rev(&y, 3, &a1);
        dir.push_rev(&x, 2, &y);
        assert_eq!(dir.proved(), sorted(&[&x, &y]));
    }

    /// #1511: 끼워 넣은 산 기기 l 의 서명으로 진짜 뿌리 a1 을 폐기로 꾸미지 못한다 — a1 이 마디가 되면 뿌리가 a1 로 가고 l 은 그
    /// 아래가 아니다. 끝 상태는 「a1 증명 안 됨」이고 진짜 a3 은 사슬 없음으로 드러난다(조용히 통과하지 않는다).
    #[test]
    fn 뿌리_아래가_아닌_산_기기의_증명은_통하지_않는다() {
        let (a1, l, a3) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        dir.add(&a3, 3, &[&a1]);
        dir.live.retain(|d| d.device_id != a1.id);
        dir.add(&l, 2, &[]);
        dir.push_rev(&a1, 1, &l);
        assert!(dir.proved().is_empty());
        assert_eq!(dir.root(), Some(l.id.clone()));
        assert_eq!(
            leaf_ok(&dir, "alice", &a3.id, &ed(&a3)),
            Verdict::Retry("no_chain")
        );
    }

    /// #1479 (나): 메일 확인으로 새 뿌리가 된 a2 가 뒤늦게 서명한 옛 기기 a1 의 증명은 통한다 — 뿌리는 그대로 a2.
    #[test]
    fn 새_뿌리_기기가_서명한_뒤늦은_증명은_통한다() {
        let (a1, a2) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a2, 5, &[]);
        dir.push_rev(&a1, 1, &a2);
        assert_eq!(dir.proved(), sorted(&[&a1]));
        assert_eq!(dir.root(), Some(a2.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &a2.id, &ed(&a2)), Verdict::Ok);
    }

    /// 서명한 기기가 나중에 (증명으로) 끊겨도 그 기기가 끊기 전에 한 증명은 남는다. 기록 순서를 뒤섞어도 같다.
    #[test]
    fn 서명자가_나중에_끊긴_증명_사슬은_순서와_무관하게_풀린다() {
        let (a1, a2, a3, a4) = (dev(1), dev(2), dev(3), dev(4));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        dir.add(&a2, 2, &[&a1]);
        dir.add(&a3, 3, &[&a2]);
        dir.add(&a4, 4, &[&a3]);
        dir.revoke(&a4, Some(&a3));
        dir.revoke(&a3, Some(&a2));
        dir.revoke(&a2, Some(&a1));
        let view = user_view_in(&dir, "alice");
        assert_eq!(dir.proved(), sorted(&[&a2, &a3, &a4]));
        assert_eq!(view.roots.root, Some(a1.id.clone()));
        dir.revs.reverse();
        assert_eq!(dir.proved(), sorted(&[&a2, &a3, &a4]));
        assert_eq!(user_view_in(&dir, "alice").roots, view.roots);
        dir.revs.rotate_left(1);
        assert_eq!(dir.proved(), sorted(&[&a2, &a3, &a4]));
        // 같은 기록이 두 번 실려도 기기마다 하나.
        let dup = dir.revs[0].clone();
        dir.revs.push(dup);
        assert_eq!(dir.proved(), sorted(&[&a2, &a3, &a4]));
    }

    /// 서명 못 받은 산 기기 a3 이, 사슬 있는 a2 가 남아 있는데 뿌리 a1 을 끊은 경우(relay 는 받는다 — 신뢰 상태와 무관하게
    /// 보낸다): a3 은 뿌리 아래가 아니라 그 증명은 아직 통하지 않고, a2 가 a3 에 서명하면 통한다.
    #[test]
    fn 사슬_없는_산_기기의_증명은_서명을_받은_뒤에_통한다() {
        let (a1, a2, a3) = (dev(1), dev(2), dev(3));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        dir.add(&a2, 2, &[&a1]);
        dir.add(&a3, 3, &[]);
        dir.revoke(&a1, Some(&a3));
        assert!(dir.proved().is_empty());
        assert_eq!(dir.root(), Some(a2.id.clone()));
        let members = ["alice".to_owned()];
        let ctx = |dir: &Dir| {
            let c = RuleCtx {
                views: Default::default(),
                dir,
                members: &members,
                expect_sender: None,
                keep_as: None,
                push_opened: false,
                group: None,
            };
            (
                c.existing_leaf_verdict(&a1.id, &ed(&a1)),
                c.leaf_verdict(&a1.id, &ed(&a1)),
            )
        };
        // 그 사이 트리에 남은 a1 잎은 다시 보기, 새로 넣는 것은 멈춤.
        assert_eq!(
            ctx(&dir),
            (Verdict::Retry("revoke_unproved"), Verdict::Stall("revoked"))
        );
        dir.sign(&a3, &a2);
        assert_eq!(ctx(&dir).0, Verdict::Ok);
        assert_eq!(dir.proved(), sorted(&[&a1]));
        assert_eq!(dir.root(), Some(a1.id.clone()));
        assert_eq!(leaf_ok(&dir, "alice", &a3.id, &ed(&a3)), Verdict::Ok);
    }

    /// #1201: 하나뿐인 기기 a1 을 스스로 끊고 새 기기 a2 가 붙으면, a1 의 자기 폐기 증명은 a1 의 잎을 폐기 잎으로 보는 데 통한다
    /// (뿌리는 a2 — a1 은 마디가 아니다).
    #[test]
    fn 하나뿐인_기기의_자기_폐기_증명은_그_잎에_통한다() {
        let (a1, a2) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a2, 5, &[]);
        dir.push_rev(&a1, 1, &a1);
        assert_eq!(dir.proved(), sorted(&[&a1]));
        assert_eq!(dir.root(), Some(a2.id.clone()));
        let members = ["alice".to_owned()];
        let ctx = RuleCtx {
            views: Default::default(),
            dir: &dir,
            members: &members,
            expect_sender: None,
            keep_as: None,
            push_opened: false,
            group: None,
        };
        assert!(ctx.is_revoked_leaf(&a1.id));
        assert_eq!(ctx.existing_leaf_verdict(&a1.id, &ed(&a1)), Verdict::Ok);
    }

    /// 서명 못 받은 산 기기 a2 가 뿌리 a1 을 증명으로 끊으면: a1 에서 a2 로 화살표가 없어 뿌리는 a2, 증명은 통한다.
    #[test]
    fn 사슬_없는_산_기기가_뿌리를_증명으로_끊으면_그_기기가_뿌리다() {
        let (a1, a2) = (dev(1), dev(2));
        let mut dir = Dir::default();
        dir.add(&a1, 1, &[]);
        dir.add(&a2, 2, &[]);
        dir.revoke(&a1, Some(&a2));
        assert_eq!(dir.proved(), sorted(&[&a1]));
        assert_eq!(dir.root(), Some(a2.id.clone()));
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
            views: Default::default(),
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
            views: Default::default(),
            members: &others,
            ..ctx
        };
        assert_ne!(ctx.existing_leaf_verdict(&a.id, &ed(&a)), Verdict::Ok);
    }

    /// #1479: 폐기 기록의 증명(서명)이 틀리면 트리에 남은 그 잎을 통과시키지도, 빼야 할 폐기 잎으로 보지도 않는다 — relay 가
    /// 실은 기록의 키 일치만으로는 안 된다. 사슬 없는 새 기기가 서명한 맞는 증명은 통과다(메일 확인 끊기를 건 기기).
    #[test]
    fn 증명이_틀린_폐기_기록은_남은_잎을_통과시키지_않는다() {
        let (a, b, x) = (dev(1), dev(2), dev(9));
        let mut dir = Dir::default();
        dir.add(&a, 1, &[]);
        // b 는 a 의 서명 없이 붙은 새 기기(사슬 없음).
        dir.add(&b, 2, &[]);
        dir.revoke(&a, Some(&b));
        let members = ["alice".to_owned()];
        let ok = RuleCtx {
            views: Default::default(),
            dir: &dir,
            members: &members,
            expect_sender: None,
            keep_as: None,
            push_opened: false,
            group: None,
        };
        assert_eq!(ok.existing_leaf_verdict(&a.id, &ed(&a)), Verdict::Ok);
        assert!(ok.is_revoked_leaf(&a.id));
        // 같은 기록인데 서명이 그 사용자 기기 것이 아니다.
        let mut forged = Dir::default();
        forged.add(&a, 1, &[]);
        forged.add(&b, 2, &[]);
        forged.revoke(&a, Some(&b));
        forged.revs[0].sig = devrevoke::sign(
            &x.keys.signing,
            &devrevoke::Revoke {
                server: SERVER,
                device_id: &a.id,
                at: &forged.revs[0].at.clone(),
            },
        );
        let bad = RuleCtx {
            views: Default::default(),
            dir: &forged,
            members: &members,
            expect_sender: None,
            keep_as: None,
            push_opened: false,
            group: None,
        };
        assert_ne!(bad.existing_leaf_verdict(&a.id, &ed(&a)), Verdict::Ok);
        assert!(!bad.is_revoked_leaf(&a.id));
    }
}
